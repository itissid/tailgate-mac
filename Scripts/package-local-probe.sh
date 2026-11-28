#!/bin/sh
# Operator-run, dummy-only packaging. No certificate generation, trust changes or install.
set -eu
umask 077
exec /usr/bin/python3 -I -B - "$@" <<'PY'
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile

IDENTIFIER = 'dev.tailgate.local-keychain-probe'
APP = 'KeychainProbe.app'
MAX_SOURCE = 262144

class Rejected(Exception):
    pass

def require(condition):
    if not condition:
        raise Rejected()

def no_extended_acl(path):
    if sys.platform != 'darwin':
        return
    # POSIX mode bits alone miss ACL grants. Reject all extended ACL entries,
    # including benign ones, instead of guessing which grants are acceptable.
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_file.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    acl = libc.acl_get_file(os.fsencode(path), 0x100)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT)
        return
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        require(libc.acl_get_entry(acl, 0, ctypes.byref(entry)) == -1 and ctypes.get_errno() == errno.EINVAL)
    finally:
        libc.acl_free(acl)

def safe_chain(path, *, directory=False, private=False):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and str(p) == str(p.resolve()))
    for part in [p] + list(p.parents):
        s = os.lstat(part)
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, os.getuid()))
        no_extended_acl(part)
        # Only a root-owned sticky temporary parent is exempt from write-bit checks.
        sticky_temp = part in (Path('/private/tmp'), Path('/tmp')) and s.st_uid == 0 and s.st_mode & stat.S_ISVTX
        require(not s.st_mode & 0o022 or sticky_temp)
    s = os.lstat(p)
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
    if private:
        require(s.st_uid == os.getuid() and not s.st_mode & 0o077)
    return p

def read_regular(path, maximum):
    p = safe_chain(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= maximum)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        require(len(data) == s.st_size and len(data) <= maximum and (s.st_size, s.st_mtime_ns, s.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return bytes(data)
    finally:
        os.close(fd)

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def invocation(arguments):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, 'Rejected: provide explicit dummy-package arguments; see --help.\n')
    p = Parser(description='Package ONLY the reviewed synthetic Keychain probe. --check never signs or reads Keychain.')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--sign-reviewed-dummy', action='store_true')
    p.add_argument('--identity', required=True, help='explicit 40-hex codesign identity selector')
    p.add_argument('--certificate', required=True, help='public DER certificate for that identity')
    p.add_argument('--source-root', required=True, help='reviewed experiment snapshot directory')
    p.add_argument('--probe-sha256', required=True, help='independently reviewed Probe.swift hash')
    p.add_argument('--output', required=True, help='new package directory under an existing private parent')
    p.add_argument('--version', required=True, choices=['1', '2'])
    p.add_argument('--previous', help='previous verified package; required for version 2')
    return p.parse_args(arguments)

def preflight(args):
    require(os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid())
    require(re.fullmatch('[0-9a-fA-F]{40}', args.identity) is not None)
    require(re.fullmatch('[0-9a-f]{64}', args.probe_sha256) is not None)
    source = safe_chain(args.source_root, directory=True, private=True)
    code = read_regular(source / 'Probe.swift', MAX_SOURCE)
    info_data = read_regular(source / 'Info.plist', 16384)
    info = plistlib.loads(info_data)
    require(set(info).issubset({'CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleName', 'CFBundlePackageType', 'CFBundleVersion'}))
    require(info.get('CFBundleIdentifier') == IDENTIFIER and info.get('CFBundleExecutable') == 'KeychainProbe' and info.get('CFBundlePackageType') == 'APPL')
    require(info.get('CFBundleName', 'KeychainProbe') == 'KeychainProbe' and info.get('CFBundleVersion', '1') == '1')
    require(sha256(code) == args.probe_sha256)
    cert = read_regular(args.certificate, 16384)
    # This SHA-1 is ONLY codesign's identity selector, not a content signature.
    require(hashlib.sha1(cert).hexdigest() == args.identity.lower())
    output = Path(args.output)
    require(output.is_absolute() and '..' not in output.parts)
    parent = safe_chain(output.parent, directory=True, private=True)
    require(output.name not in ('', '.', '..') and not os.path.lexists(output))
    require((args.version == '2') == bool(args.previous))
    previous = safe_chain(args.previous, directory=True, private=True) if args.previous else None
    if previous:
        require(previous != output)
    return code, info, cert, parent, output, previous

def command(args, *, cwd, limit=65536):
    # Never echo codesign diagnostics or captured identities/certificate subjects.
    user = pwd.getpwuid(os.getuid())
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': user.pw_dir, 'USER': user.pw_name, 'LANG': 'C', 'LC_ALL': 'C'}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        run = subprocess.run([str(a) for a in args], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             cwd=cwd, env=env, timeout=120, check=False)
        require(run.returncode == 0)
        out.seek(0); err.seek(0)
        a, b = out.read(limit + 1), err.read(limit + 1)
        require(len(a) <= limit and len(b) <= limit)
        return a, b

def verify(app, cert, work):
    require(app.name == APP)
    command(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', app], cwd=work)
    a, b = command(['/usr/bin/codesign', '--display', '--verbose=4', app], cwd=work)
    meta = (a + b).decode('utf-8', 'strict')
    require(re.search(r'^Identifier=' + re.escape(IDENTIFIER) + '$', meta, re.M) is not None)
    flags = re.search(r'flags=0x([0-9a-fA-F]+)', meta)
    require(flags is not None and int(flags.group(1), 16) & 0x10000 and not int(flags.group(1), 16) & 2)
    # Verify exact leaf bytes with SHA-256, independently of the identity selector.
    prefix = work / ('cert-' + os.urandom(8).hex())
    command(['/usr/bin/codesign', '--display', '--extract-certificates', prefix, app], cwd=work)
    leaf = read_regular(Path(str(prefix) + '0'), 16384)
    require(sha256(leaf) == sha256(cert))
    a, b = command(['/usr/bin/codesign', '--display', '-r-', app], cwd=work)
    requirements = (a + b).decode('utf-8', 'strict')
    match = re.search(r'^designated => (.+)$', requirements, re.M)
    require(match is not None)
    dr = match.group(1)
    require(('certificate ' in dr or 'anchor ' in dr) and 'cdhash' not in dr)
    # Verify the declared requirement too, rather than merely displaying it.
    command(['/usr/bin/codesign', '--verify', '--strict', '--test-requirement', '=' + dr, app], cwd=work)
    plist = plistlib.loads(read_regular(app / 'Contents/Info.plist', 16384))
    require(plist.get('CFBundleIdentifier') == IDENTIFIER and plist.get('CFBundleExecutable') == 'KeychainProbe')
    binary = read_regular(app / 'Contents/MacOS/KeychainProbe', 32 * 1024 * 1024)
    return dr, sha256(binary), plist

def package(args, inputs):
    code, info, cert, parent, output, previous = inputs
    require(sys.platform == 'darwin')
    # A private temporary build is under the chosen protected output parent, never .build.
    with tempfile.TemporaryDirectory(prefix='.tailgate-probe-build-', dir=parent) as directory:
        work = Path(directory)
        source = work / 'Probe.swift'
        # Public C entry point is deliberately emitted, so v1/v2 have different code.
        marker = ('\n@_cdecl("tailgate_probe_build_version") public func tailgateProbeBuildVersion() -> Int32 { return ' + args.version + ' }\n').encode()
        source.write_bytes(code + marker)
        app = work / APP
        binary = app / 'Contents/MacOS/KeychainProbe'
        binary.parent.mkdir(parents=True, mode=0o700)
        info = dict(info, CFBundleVersion=args.version)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        command(['/usr/bin/swiftc', '-O', '-suppress-warnings', '-framework', 'Security', source, '-o', binary], cwd=work)
        command(['/usr/bin/codesign', '--sign', args.identity, '--options', 'runtime', '--timestamp=none', '--digest-algorithm=sha256', app], cwd=work)
        dr, binary_hash, actual = verify(app, cert, work)
        require(actual.get('CFBundleVersion') == args.version)
        if previous:
            old_app = previous / APP
            old_dr, old_hash, old_info = verify(old_app, cert, work)
            require(old_info.get('CFBundleVersion') == '1' and old_dr == dr and old_hash != binary_hash)
        record = {'version': 1, 'dummy_only': True, 'build_version': args.version,
                  'bundle_id': IDENTIFIER, 'certificate_sha256': sha256(cert),
                  'probe_source_sha256': sha256(code), 'executable_sha256': binary_hash,
                  'designated_requirement': dr}
        # Atomically reserve a NEW destination; never replace or merge an old app.
        os.mkdir(output, 0o700)
        try:
            os.rename(app, output / APP)
            with (output / 'verified-dummy-package.json').open('x') as stream:
                json.dump(record, stream, sort_keys=True)
                stream.write('\n')
        except BaseException:
            # Leave evidence, not a false complete package, if publication failed.
            raise Rejected() from None
    return {'version': 1, 'status': 'packaged-dummy-only', 'live_enabled': False,
            'build_version': args.version, 'upgrade_control_verified': bool(previous)}

def main(arguments):
    args = invocation(arguments)
    inputs = preflight(args)
    if args.check:
        return {'version': 1, 'status': 'inputs-checked-only', 'signed': False, 'live_enabled': False}
    return package(args, inputs)

if __name__ == '__main__':
    try:
        value = main(sys.argv[1:])
    except (Exception, KeyboardInterrupt):
        value = {'version': 1, 'status': 'rejected', 'live_enabled': False}
    print(json.dumps(value, separators=(',', ':'), sort_keys=True))
    raise SystemExit(0 if value['status'] in ('inputs-checked-only', 'packaged-dummy-only') else 3)
PY
