#!/bin/sh
# Explicit operator-only local review packaging. Never install or enable live trust.
set -eu
umask 077
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import pwd
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile

IDENTIFIER = 'dev.tailgate.local-review'
APP = 'TailgateLocalReview.app'
BINARY = APP + '/Contents/MacOS/TailgateReview'
PLIST = APP + '/Contents/Info.plist'
MANIFEST = 'local-review.json'
# Deliberately reviewed, dependency/plugin-free manifest. Changes need code review.
PACKAGE_SHA256 = '9b4416a96a9ac6511a234a49ef3e9c2e49c60162e7baa0dd72f9aca9eb1f5d90'
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
INFO = {
    'CFBundleIdentifier': IDENTIFIER, 'CFBundleExecutable': 'TailgateReview',
    'CFBundleName': 'Tailgate Local Review', 'CFBundleDisplayName': 'Tailgate Local Review',
    'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '0.1.0',
    'CFBundleVersion': '1', 'LSMinimumSystemVersion': '13.0',
    'NSHighResolutionCapable': True,
}

class Rejected(Exception):
    pass

def require(value):
    if not value:
        raise Rejected()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def ordinary_caller():
    require(os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid())
    require(not any(name in os.environ for name in ('SUDO_UID', 'SUDO_USER', 'SUDO_COMMAND')))

def no_acl(path, fd=None):
    if sys.platform != 'darwin':
        return
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    if fd is None:
        acl = libc.acl_get_file(os.fsencode(path), 0x100)
    else:
        libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.acl_get_fd_np.restype = ctypes.c_void_p
        acl = libc.acl_get_fd_np(fd, 0x100)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT)
        return
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        require(libc.acl_get_entry(acl, 0, ctypes.byref(entry)) == -1 and ctypes.get_errno() == errno.EINVAL)
    finally:
        libc.acl_free(acl)

def protected(path, *, directory=False, private=True):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and str(path) == str(path.resolve()))
    # Never accept privileged deployment/configuration inputs, even when readable.
    require(not any(path == p or p in path.parents for p in
                    map(Path, ('/Applications', '/Library', '/System', '/private/etc', '/private/var/root'))))
    for part in [path] + list(path.parents):
        s = os.lstat(part)
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, os.getuid()))
        no_acl(part)
        sticky = part == Path('/private/tmp') and s.st_uid == 0 and s.st_mode & stat.S_ISVTX
        require(not s.st_mode & 0o022 or sticky)
    s = os.lstat(path)
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
    require(s.st_uid == os.getuid() and (not private or not s.st_mode & 0o077))
    return path

def read_file(path, limit, *, private=True):
    path = protected(path, private=private)
    # Resolve every component using directory descriptors, so a substituted ancestor
    # symlink cannot redirect a validated input read into a privileged/secret tree.
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walked = Path('/')
        for component in path.parts[1:-1]:
            walked /= component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            s = os.fstat(parent)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid()))
            sticky = walked == Path('/private/tmp') and s.st_uid == 0 and s.st_mode & stat.S_ISVTX
            require(not s.st_mode & 0o022 or sticky)
            no_acl(walked, fd=parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit)
        require(before.st_uid == os.getuid() and not before.st_mode & (0o077 if private else 0o022))
        no_acl(path, fd=fd)
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        require(len(data) == before.st_size and len(data) <= limit)
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return bytes(data)
    finally:
        os.close(fd)

def write_file(path, data, executable=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(0o700 if executable else 0o600)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'

def pin(value, length=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None)
    return value

def invocation(argv):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, 'Rejected: explicit local-review arguments required; see --help.\n')
    p = Parser(description='Operator-only, no-install local TailgateReview packaging; never enables live trust.')
    mode = p.add_mutually_exclusive_group(required=True)
    for name in ('stage', 'sign', 'verify'):
        mode.add_argument('--' + name, action='store_true')
    p.add_argument('--archive', help='reviewed uncompressed git archive tar, private regular file')
    p.add_argument('--archive-sha256')
    p.add_argument('--commit', help='full git archive commit ID')
    p.add_argument('--artifact', help='existing stage (sign) or signed package (verify)')
    p.add_argument('--artifact-sha256', help='independently retained package tree pin')
    p.add_argument('--identity', help='exact lowercase 40-hex certificate SHA-1 selector')
    p.add_argument('--certificate', help='public DER ONLY, private regular file')
    p.add_argument('--certificate-sha256', help='independently reviewed public DER pin')
    p.add_argument('--output', help='NEW output directory under private existing parent')
    a = p.parse_args(argv)
    ordinary_caller()  # Before opening any input, including a public certificate.
    source = (a.archive, a.archive_sha256, a.commit)
    signer = (a.identity, a.certificate, a.certificate_sha256)
    if a.stage:
        require(all(source) and not any(signer) and not a.artifact and not a.artifact_sha256 and a.output)
        pin(a.archive_sha256)
        require(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', a.commit) is not None)
    else:
        require(not any(source) and all(signer) and a.artifact and a.artifact_sha256)
        require(bool(a.output) == a.sign)
        pin(a.identity, 40); pin(a.certificate_sha256); pin(a.artifact_sha256)
    if a.output:
        output = Path(a.output)
        require(output.is_absolute() and '..' not in output.parts and output.name not in ('', '.', '..'))
        protected(output.parent, directory=True)
        require(not os.path.lexists(output))
    return a

def archive_sources(data, commit):
    files = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        require(archive.pax_headers.get('comment') == commit)
        total = 0
        for member in archive:
            name = member.name.rstrip('/')
            parts = PurePosixPath(name).parts
            require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))
            require(str(PurePosixPath(name)) == name and name not in seen and len(seen) < 20000)
            seen.add(name)
            require(member.isdir() or member.isreg())
            require(not member.pax_headers.get('linkpath') and not member.issparse())
            total += member.size
            require(0 <= member.size <= 8 * 1024 * 1024 and total <= MAX_ARCHIVE)
            test_source = len(parts) >= 3 and parts[:2] in (
                ('Tests', 'TailgateCoreTests'), ('Tests', 'TailgateLiveTests'))
            if member.isreg() and (name == 'Package.swift' or parts[0] == 'Sources' or test_source):
                require(name == 'Package.swift' or (len(parts) >= 3 and name.endswith('.swift')))
                files[name] = archive.extractfile(member).read()
        require(digest(files.get('Package.swift', b'')) == PACKAGE_SHA256)
        require('Sources/TailgateReview/App.swift' in files)
        # SwiftPM validates every declared target even when building one product.
        for target in ('TailgateCoreTests', 'TailgateLiveTests'):
            require(any(name.startswith('Tests/' + target + '/') for name in files))
    return files

def command(args, *, cwd, timeout=120, accepted=(0,)):
    # No inherited shell, Swift/SDK overrides, git config, proxy or loader variables.
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(cwd),
           'TMPDIR': str(cwd) + '/', 'LANG': 'C', 'LC_ALL': 'C',
           'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        run = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                             stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout, check=False)
        require(run.returncode in accepted)
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(1024 * 1024 + 1), err.read(1024 * 1024 + 1)
        require(len(stdout) <= 1024 * 1024 and len(stderr) <= 1024 * 1024)
        return run.returncode, stdout, stderr

def macho_payload(data):
    # Hash everything except the signature and fields codesign must update. Accept
    # only thin, little-endian 64-bit macOS executables from the native CLT build.
    require(len(data) >= 32)
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    require(magic == 0xfeedfacf and cpu in (0x1000007, 0x100000c) and kind == 2 and count < 512)
    end = 32 + size
    require(end <= len(data))
    pos, commands, signature, first_content = 32, [], None, len(data)
    linkedit = None
    for _ in range(count):
        require(pos + 8 <= end)
        cmd, length = struct.unpack_from('<II', data, pos)
        require(length >= 8 and length % 8 == 0 and pos + length <= end)
        block = bytearray(data[pos:pos + length])
        if cmd == 0x1d:  # LC_CODE_SIGNATURE: excluded, never code or other linkedit data.
            require(length == 16 and signature is None)
            signature = struct.unpack_from('<II', block, 8)
        else:
            if cmd == 0x19:  # LC_SEGMENT_64
                require(length >= 72)
                nsects = struct.unpack_from('<I', block, 64)[0]
                require(length == 72 + 80 * nsects)
                if block[8:24].rstrip(b'\0') == b'__LINKEDIT':
                    require(linkedit is None)
                    linkedit = struct.unpack_from('<QQ', block, 40)
                    block[32:40] = b'\0' * 8  # vmsize
                    block[48:56] = b'\0' * 8  # filesize
                for n in range(nsects):
                    offset = struct.unpack_from('<I', block, 72 + n * 80 + 48)[0]
                    if offset:
                        first_content = min(first_content, offset)
            commands.append(bytes(block))
        pos += length
    require(pos == end and end <= first_content <= len(data) and linkedit is not None)
    require(not any(data[end:first_content]))  # only zero load-command padding
    sigstart = len(data)
    if signature:
        sigstart, sigsize = signature
        require(sigstart >= first_content and sigsize > 0 and sigstart + sigsize == len(data))
    require(linkedit[0] <= sigstart and sum(linkedit) == len(data))
    header = struct.pack('<6I', magic, cpu, subtype, kind, flags, reserved)
    # Signing can append up to 15 zero alignment bytes before a new signature.
    # Preserve length in 16-byte units: do not discard arbitrary trailing zeros.
    payload = data[first_content:sigstart]
    aligned = payload.ljust((len(payload) + 15) // 16 * 16, b'\0')
    return digest(header + b''.join(commands) + aligned)

def package_files(root, signed):
    root = protected(root, directory=True)
    expected = {BINARY, PLIST, MANIFEST}
    if signed:
        expected.add(APP + '/Contents/_CodeSignature/CodeResources')
    found = set()
    directories = {APP, APP + '/Contents', APP + '/Contents/MacOS'}
    if signed:
        directories.add(APP + '/Contents/_CodeSignature')
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            require(path.relative_to(root).as_posix() in directories)
            protected(path, directory=True, private=False)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            require(relative in expected)
            found.add(relative)
    require(found == expected)
    return {name: read_file(root / name, MAX_BINARY if name == BINARY else 1024 * 1024, private=False) for name in sorted(found)}

def tree_pin(files):
    return digest(canonical({name: digest(data) for name, data in files.items()}))

def check_record(files, signed):
    record = json.loads(files[MANIFEST])
    base = {'format', 'mode', 'bundle_id', 'live_enabled', 'archive_sha256', 'commit',
            'package_manifest_sha256', 'toolchain', 'unsigned_executable_sha256', 'payload_sha256'}
    extra = {'certificate_sha256', 'identity', 'designated_requirement', 'stage_sha256', 'signed_executable_sha256'}
    require(set(record) == (base | extra if signed else base))
    require(record['format'] == 1 and record['mode'] == ('signed-local-review' if signed else 'staged-local-review'))
    require(record['bundle_id'] == IDENTIFIER and record['live_enabled'] is False)
    require(record['package_manifest_sha256'] == PACKAGE_SHA256)
    pin(record['archive_sha256']); pin(record['unsigned_executable_sha256']); pin(record['payload_sha256'])
    require(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', record['commit']) is not None)
    require(isinstance(record['toolchain'], str) and 0 < len(record['toolchain']) < 4096)
    require(plistlib.loads(files[PLIST]) == INFO)
    require(macho_payload(files[BINARY]) == record['payload_sha256'])
    require(digest(files[BINARY]) == record['signed_executable_sha256' if signed else 'unsigned_executable_sha256'])
    return record

def requirement(identity):
    return 'identifier "' + IDENTIFIER + '" and certificate leaf = H"' + identity + '"'

def public_certificate(a, work):
    cert = read_file(a.certificate, 16384)
    require(digest(cert) == a.certificate_sha256 and hashlib.sha1(cert).hexdigest() == a.identity)
    # One complete DER SEQUENCE, not PEM, a private-key export or concatenated input.
    require(len(cert) > 4 and cert[0] == 0x30)
    length, header = cert[1], 2
    if length & 0x80:
        count = length & 0x7f
        require(0 < count <= 3 and len(cert) > 2 + count and cert[2] != 0)
        length, header = int.from_bytes(cert[2:2 + count], 'big'), 2 + count
        require(length >= 128)
    require(header + length == len(cert))
    # Only public DER is accepted. Never import, enumerate identities or read a key.
    path = work / 'public.der'
    write_file(path, cert)
    _, out, err = command(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-in', path, '-noout', '-text'], cwd=work)
    text = (out + err).decode('utf-8', 'strict')
    require('Certificate:' in text and 'Code Signing' in text)
    require(not re.search(r'Apple|Developer ID|1\.2\.840\.113635', text, re.I))
    return cert

def verify_signature(app, a, cert, work):
    dr = requirement(a.identity)
    command(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '--test-requirement', '=' + dr, app], cwd=work)
    _, out, err = command(['/usr/bin/codesign', '--display', '--verbose=4', app], cwd=work)
    text = (out + err).decode('utf-8', 'strict')
    require(re.search(r'^Identifier=' + re.escape(IDENTIFIER) + '$', text, re.M))
    flags = re.search(r'flags=0x([0-9a-fA-F]+)', text)
    require(flags and int(flags[1], 16) & 0x10000 and not int(flags[1], 16) & 2)
    require(re.search(r'^TeamIdentifier=not set$', text, re.M))
    _, out, err = command(['/usr/bin/codesign', '--display', '-r-', app], cwd=work)
    text = (out + err).decode('utf-8', 'strict')
    require(re.search(r'^designated => identifier "' + re.escape(IDENTIFIER) +
                      r'" and certificate leaf = H"' + a.identity + r'"$', text, re.M | re.I))
    prefix = work / ('leaf-' + os.urandom(8).hex())
    command(['/usr/bin/codesign', '--display', '--extract-certificates', prefix, app], cwd=work)
    require(read_file(Path(str(prefix) + '0'), 16384, private=False) == cert)
    # No entitlement blob at all, including no application/team/private-group claim.
    _, out, _ = command(['/usr/bin/codesign', '--display', '--entitlements', '-', '--xml', app], cwd=work)
    require(not out.strip() or plistlib.loads(out) == {})
    return dr

def publish(work, output, signed):
    files = package_files(work, signed)
    check_record(files, signed)
    result_pin = tree_pin(files)
    # Atomic no-replace directory reservation; failures never claim completion.
    os.mkdir(output, 0o700)
    for name, data in files.items():
        write_file(output / name, data, executable=(name == BINARY))
    require(tree_pin(package_files(output, signed)) == result_pin)
    return {'format': 1, 'status': 'signed-local-review' if signed else 'staged-local-review',
            'artifact_sha256': result_pin, 'live_enabled': False, 'installed': False}

def stage(a):
    data = read_file(a.archive, MAX_ARCHIVE)
    require(digest(data) == a.archive_sha256)
    files = archive_sources(data, a.commit)
    output = Path(a.output)
    with tempfile.TemporaryDirectory(prefix='.tailgate-local-build-', dir=output.parent) as directory:
        work = Path(directory)
        source, scratch, product = work / 'source', work / 'scratch', work / 'package'
        source.mkdir(mode=0o700); product.mkdir(mode=0o700)
        for name, content in files.items():
            write_file(source / name, content)
        _, version, _ = command(['/usr/bin/swift', '--version'], cwd=work)
        command(['/usr/bin/swift', 'build', '--disable-automatic-resolution', '--scratch-path', scratch,
                 '-c', 'release', '--product', 'TailgateReview'], cwd=source, timeout=900)
        _, out, _ = command(['/usr/bin/swift', 'build', '--disable-automatic-resolution', '--scratch-path', scratch,
                             '-c', 'release', '--show-bin-path'], cwd=source)
        binary_dir = Path(out.decode('utf-8', 'strict').strip())
        require(binary_dir.is_absolute() and scratch in binary_dir.parents)
        # SwiftPM's native build path may be a symlink: resolve ONLY inside this private scratch.
        binary_dir = binary_dir.resolve()
        require(scratch in binary_dir.parents)
        executable = read_file(binary_dir / 'TailgateReview', MAX_BINARY, private=False)
        write_file(product / BINARY, executable, executable=True)
        write_file(product / PLIST, plistlib.dumps(INFO, sort_keys=True))
        record = {'format': 1, 'mode': 'staged-local-review', 'bundle_id': IDENTIFIER, 'live_enabled': False,
                  'archive_sha256': a.archive_sha256, 'commit': a.commit, 'package_manifest_sha256': PACKAGE_SHA256,
                  'toolchain': version.decode('utf-8', 'strict').strip(),
                  'unsigned_executable_sha256': digest(executable), 'payload_sha256': macho_payload(executable)}
        write_file(product / MANIFEST, canonical(record))
        return publish(product, output, False)

def sign_or_verify(a):
    artifact = protected(a.artifact, directory=True)
    files = package_files(artifact, a.verify)
    require(tree_pin(files) == a.artifact_sha256)
    record = check_record(files, a.verify)
    parent = Path(a.output).parent if a.sign else artifact.parent
    protected(parent, directory=True)
    with tempfile.TemporaryDirectory(prefix='.tailgate-local-sign-', dir=parent) as directory:
        work = Path(directory)
        cert = public_certificate(a, work)
        product = work / 'package'
        product.mkdir(mode=0o700)
        for name, content in files.items():
            write_file(product / name, content, executable=(name == BINARY))
        app = product / APP
        dr = requirement(a.identity)
        if a.sign:
            # This path is fixed, never inferred from environment/search-list/default identity.
            keychain = Path(pwd.getpwuid(os.getuid()).pw_dir) / 'Library/Keychains/Tailgate Signing.keychain-db'
            protected(keychain)  # metadata only; codesign alone may access the explicit key.
            # Cross-check that staging did not smuggle a certificate-backed signature.
            rc, out, err = command(['/usr/bin/codesign', '--display', '--verbose=4', app], cwd=work, accepted=(0, 1))
            if rc == 0:
                text = (out + err).decode('utf-8', 'strict')
                flags = re.search(r'flags=0x([0-9a-fA-F]+)', text)
                require(flags and int(flags[1], 16) & 2 and not re.search(r'^Authority=', text, re.M))
            command(['/usr/bin/codesign', '--force', '--sign', a.identity, '--keychain', keychain,
                     '--identifier', IDENTIFIER, '--requirements', '=designated => ' + dr, '--options', 'runtime',
                     '--timestamp=none', '--digest-algorithm=sha256', app], cwd=work)
        actual_dr = verify_signature(app, a, cert, work)
        if a.verify:
            require(record['identity'] == a.identity and record['certificate_sha256'] == a.certificate_sha256)
            require(record['designated_requirement'] == actual_dr)
            pin(record['stage_sha256'])
            require(package_files(product, True) == files)
        else:
            # codesign is allowed to change ONLY signature storage and its Mach-O bookkeeping.
            signed_binary = read_file(product / BINARY, MAX_BINARY)
            require(macho_payload(signed_binary) == record['payload_sha256'])
            require(read_file(product / PLIST, 16384) == files[PLIST])
            record.update(mode='signed-local-review', identity=a.identity, certificate_sha256=a.certificate_sha256,
                          designated_requirement=actual_dr, stage_sha256=a.artifact_sha256,
                          signed_executable_sha256=digest(signed_binary))
            (product / MANIFEST).write_bytes(canonical(record))
        # Re-read the original pinned tree after tool activity; no mutable-path trust.
        require(package_files(artifact, a.verify) == files)
        if a.verify:
            return {'format': 1, 'status': 'verified-local-review', 'artifact_sha256': a.artifact_sha256,
                    'live_enabled': False, 'installed': False}
        return publish(product, Path(a.output), True)

def main(argv):
    a = invocation(argv)
    require(sys.platform == 'darwin')
    return stage(a) if a.stage else sign_or_verify(a)

if __name__ == '__main__':
    try:
        result = main(sys.argv[1:])
    except (Exception, KeyboardInterrupt):
        result = {'format': 1, 'status': 'rejected', 'live_enabled': False, 'installed': False}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    raise SystemExit(3 if result['status'] == 'rejected' else 0)
PY
