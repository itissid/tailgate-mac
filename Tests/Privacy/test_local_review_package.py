"""Synthetic packaging boundaries only: never compile, sign, read Keychain or launch UI."""
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Scripts/package-local-review.sh'
source = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
package = types.ModuleType('local_review_package')
exec(compile(source, str(SCRIPT), 'exec'), package.__dict__)


def macho(code=b'CODE-REVIEW-ONLY', signature=b'ADHOC---', include_signature=True):
    """Small structural Mach-O fixture, NOT an executable or valid signature."""
    content = code.ljust(16, b'\0') + b'LINKDATA'
    signature = signature if include_signature else b''
    commands = []
    commands.append(struct.pack('<II16sQQQQIIII', 0x19, 152, b'__TEXT', 0x100000000, 4096,
                                0, 4112, 7, 5, 1, 0) +
                    struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0x100001000, 16,
                                4096, 2, 0, 0, 0, 0, 0, 0))
    commands.append(struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', 0x100002000,
                                4096 + len(signature), 4112, 8 + len(signature), 7, 1, 0, 0))
    if include_signature:
        commands.append(struct.pack('<IIII', 0x1d, 16, 4120, len(signature)))
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, len(commands),
                         sum(map(len, commands)), 0x200085, 0)
    return (header + b''.join(commands)).ljust(4096, b'\0') + content + signature


class LocalReviewPackageTests(unittest.TestCase):
    def setUp(self):
        if os.getuid() == 0:
            self.skipTest('Private filesystem fixtures require an ordinary caller')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        # No real certificate and no real keychain are used. x509/code signing is mocked.
        self.cert_bytes = b'\x30\x06PUBLIC'
        self.cert = self.root / 'public.der'
        package.write_file(self.cert, self.cert_bytes)
        self.identity = hashlib.sha1(self.cert_bytes).hexdigest()
        self.cert_hash = package.digest(self.cert_bytes)
        self.archive = self.root / 'source.tar'
        self.commit = 'a' * 40
        self.stage = self.root / 'stage'
        self.signed = self.root / 'signed'
        self.calls = []
        self.make_archive()
        self.stage_args = ['--stage', '--archive', str(self.archive), '--archive-sha256',
                           package.digest(self.archive.read_bytes()), '--commit', self.commit,
                           '--output', str(self.stage)]
        self.signer_args = ['--identity', self.identity, '--certificate', str(self.cert),
                            '--certificate-sha256', self.cert_hash]

    def make_archive(self, changes=None, extra=None, commit=None, omit=()):
        files = {'Package.swift': (ROOT / 'Package.swift').read_bytes(),
                 'Sources/TailgateReview/App.swift': b'// synthetic reviewed source\n',
                 'Tests/TailgateCoreTests/Fixture.swift': b'// synthetic test target\n',
                 'Tests/TailgateLiveTests/Fixture.swift': b'// synthetic test target\n',
                 'Scripts/never-run.sh': b'exit 99\n'}
        files.update(changes or {})
        with tarfile.open(self.archive, 'w', format=tarfile.PAX_FORMAT,
                          pax_headers={'comment': commit or self.commit}) as archive:
            for name, content in files.items():
                if name in omit:
                    continue
                item = tarfile.TarInfo(name)
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            if extra:
                archive.addfile(extra)
        self.archive.chmod(0o600)

    def fake_command(self, args, *, cwd, **kwargs):
        args = [str(a) for a in args]
        self.calls.append(args)
        if args[0] == '/usr/bin/swift':
            if '--version' in args:
                return 0, b'Apple Swift synthetic offline fixture\n', b''
            scratch = Path(args[args.index('--scratch-path') + 1])
            binary_dir = scratch / 'arm64-apple-macosx/release'
            if '--show-bin-path' in args:
                return 0, str(binary_dir).encode() + b'\n', b''
            self.assertTrue((Path(cwd) / 'Tests/TailgateCoreTests/Fixture.swift').is_file())
            self.assertTrue((Path(cwd) / 'Tests/TailgateLiveTests/Fixture.swift').is_file())
            self.assertFalse((Path(cwd) / 'Scripts').exists())
            package.write_file(binary_dir / 'TailgateReview', macho(), executable=True)
            # Match normal compiler output modes; private scratch parent is the boundary.
            (binary_dir / 'TailgateReview').chmod(0o755)
            return 0, b'', b''
        if args[0] == '/usr/bin/openssl':
            return 0, b'Certificate:\n X509v3 Extended Key Usage: Code Signing\n', b''
        if '--sign' in args:
            app = Path(args[-1])
            binary = app / 'Contents/MacOS/TailgateReview'
            binary.write_bytes(macho(signature=b'CERTIFICATE-SIGNATURE-FIXTURE'))
            package.write_file(app / 'Contents/_CodeSignature/CodeResources', b'synthetic resource seal')
            (app / 'Contents/_CodeSignature').chmod(0o755)
            (app / 'Contents/_CodeSignature/CodeResources').chmod(0o644)
        elif '--verbose=4' in args:
            signed = (Path(args[-1]) / 'Contents/_CodeSignature').exists()
            text = ('Identifier=' + package.IDENTIFIER + '\nflags=' +
                    ('0x10000(runtime)\nTeamIdentifier=not set\n' if signed else '0x2(adhoc)\n'))
            return 0, b'', text.encode()
        elif '-r-' in args:
            return 0, b'', ('designated => ' + package.requirement(self.identity) + '\n').encode()
        elif '--extract-certificates' in args:
            prefix = args[args.index('--extract-certificates') + 1]
            package.write_file(Path(prefix + '0'), self.cert_bytes)
            Path(prefix + '0').chmod(0o644)
        return 0, b'', b''

    def stage_fixture(self):
        with mock.patch.object(package, 'command', self.fake_command):
            return package.stage(package.invocation(self.stage_args))

    def sign_args(self):
        stage_pin = package.tree_pin(package.package_files(self.stage, False))
        return ['--sign', '--artifact', str(self.stage), '--artifact-sha256', stage_pin,
                '--output', str(self.signed)] + self.signer_args

    def fake_keychain_boundary(self, path, **kwargs):
        if str(path).endswith('/Library/Keychains/Tailgate Signing.keychain-db'):
            # Do not even stat the real fixed keychain in tests.
            return Path(path)
        return self.real_protected(path, **kwargs)

    def run_sign(self, command=None):
        args = package.invocation(self.sign_args())
        self.real_protected = package.protected
        with mock.patch.object(package, 'protected', self.fake_keychain_boundary), \
                mock.patch.object(package, 'command', command or self.fake_command):
            return package.sign_or_verify(args)

    def test_stage_builds_only_pinned_sources_and_never_uses_signer_tools(self):
        value = self.stage_fixture()
        self.assertEqual(value['status'], 'staged-local-review')
        self.assertFalse(value['live_enabled'])
        self.assertFalse(value['installed'])
        self.assertTrue(all(c[0] == '/usr/bin/swift' for c in self.calls))
        build = next(c for c in self.calls if '--product' in c)
        self.assertEqual(build[:4], ['/usr/bin/swift', 'build', '--disable-automatic-resolution', '--scratch-path'])
        self.assertEqual(build[5:], ['-c', 'release', '--product', 'TailgateReview'])
        self.assertIn('.tailgate-local-build-', build[4])
        files = package.package_files(self.stage, False)
        self.assertEqual(value['artifact_sha256'], package.tree_pin(files))
        self.assertEqual(plistlib.loads(files[package.PLIST]), package.INFO)
        self.assertNotIn('TailgateTeamIdentifier', package.INFO)
        self.assertFalse(list(self.root.glob('.tailgate-local-build-*')))

    def test_modes_reject_crossed_or_implicit_inputs_before_file_reads(self):
        invalid = [[], ['--stage', '--sign'], self.stage_args + self.signer_args,
                   self.stage_args + ['--artifact', '/not/read'],
                   ['--sign', '--artifact', '/not/read', '--artifact-sha256', 'a' * 64],
                   ['--verify', '--artifact', '/not/read', '--artifact-sha256', 'a' * 64,
                    '--output', '/not/written'] + self.signer_args,
                   self.stage_args + ['--keychain', '/not/read'],
                   self.stage_args + ['--install'], self.stage_args + ['--team', 'NO']]
        for args in invalid:
            with self.subTest(args=args), mock.patch.object(package, 'read_file', side_effect=AssertionError('read')), \
                    mock.patch.object(package, 'command', side_effect=AssertionError('tool')), mock.patch('sys.stderr'):
                with self.assertRaises((package.Rejected, SystemExit)):
                    package.invocation(args)

    def test_privileged_callers_rejected_before_input_reads(self):
        for uid, euid, gid, egid in [(0, 0, 1, 1), (501, 0, 1, 1), (501, 501, 1, 0)]:
            with mock.patch.object(package.os, 'getuid', return_value=uid), \
                    mock.patch.object(package.os, 'geteuid', return_value=euid), \
                    mock.patch.object(package.os, 'getgid', return_value=gid), \
                    mock.patch.object(package.os, 'getegid', return_value=egid), \
                    mock.patch.object(package, 'read_file', side_effect=AssertionError('read')), \
                    self.assertRaises(package.Rejected):
                package.invocation(self.stage_args)
        with mock.patch.dict(os.environ, {'SUDO_USER': 'synthetic'}), self.assertRaises(package.Rejected):
            package.invocation(self.stage_args)

    def test_archive_pin_and_commit_must_match_before_compilation(self):
        for field, value in [('archive_sha256', 'f' * 64), ('commit', 'b' * 40)]:
            args = package.invocation(self.stage_args)
            setattr(args, field, value)
            with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
                package.stage(args)
            self.assertFalse(self.stage.exists())

    def test_unreviewed_manifest_cannot_run_even_in_pinned_archive(self):
        self.make_archive(changes={'Package.swift': b'// arbitrary manifest, never executed\n'})
        args = package.invocation(self.stage_args)
        args.archive_sha256 = package.digest(self.archive.read_bytes())
        with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
            package.stage(args)

    def test_archive_rejects_links_special_entries_duplicates_and_traversal(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('a/./b', tarfile.REGTYPE), ('a//b', tarfile.REGTYPE),
                           ('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE),
                           ('fifo', tarfile.FIFOTYPE), ('Package.swift', tarfile.REGTYPE)]:
            with self.subTest(name=name):
                item = tarfile.TarInfo(name); item.type = kind; item.linkname = '/not/read'
                self.make_archive(extra=item)
                with self.assertRaises(package.Rejected):
                    package.archive_sources(self.archive.read_bytes(), self.commit)

    def test_missing_declared_test_target_fails_before_build(self):
        self.make_archive(omit=('Tests/TailgateLiveTests/Fixture.swift',))
        with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
            package.archive_sources(self.archive.read_bytes(), self.commit)

    def test_ancestor_symlink_swap_cannot_redirect_input_read(self):
        parent = self.root / 'input-parent'
        parent.mkdir(mode=0o700)
        package.write_file(parent / 'source', b'public fixture')
        other = self.root / 'unrelated-fixture'
        other.mkdir(mode=0o700)
        package.write_file(other / 'source', b'must not be read')
        moved = self.root / 'original-parent'
        real_open = os.open
        def swap(path, flags, **kwargs):
            if str(path) == 'input-parent' and 'dir_fd' in kwargs:
                parent.rename(moved)
                parent.symlink_to(other, target_is_directory=True)
            return real_open(path, flags, **kwargs)
        with mock.patch.object(package.os, 'open', swap), \
                mock.patch.object(package.os, 'read', side_effect=AssertionError('redirected read')), \
                self.assertRaises(OSError):
            package.read_file(parent / 'source', 1024)
        parent.unlink()
        moved.rename(parent)

    def test_private_paths_refuse_links_hardlinks_fifo_writes_and_acl(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            path = self.root / kind
            if kind == 'symlink': path.symlink_to(self.cert)
            elif kind == 'hardlink': os.link(self.cert, path)
            else: os.mkfifo(path, 0o600)
            with self.assertRaises(package.Rejected): package.read_file(path, 16384)
            path.unlink()
        self.cert.chmod(0o644)
        with self.assertRaises(package.Rejected): package.read_file(self.cert, 16384)
        self.cert.chmod(0o600)
        with mock.patch.object(package, 'no_acl', side_effect=package.Rejected()), self.assertRaises(package.Rejected):
            package.read_file(self.cert, 16384)
        self.root.chmod(0o777)
        with self.assertRaises(package.Rejected): package.read_file(self.cert, 16384)
        self.root.chmod(0o700)

    def test_privileged_paths_rejected_before_any_open(self):
        for path in ('/Library/Tailgate/configuration', '/Applications/Tailgate.app/Contents/Info.plist',
                     '/private/etc/secret', '/private/var/root/secret'):
            with mock.patch.object(package.os, 'open', side_effect=AssertionError('open')), self.assertRaises(package.Rejected):
                package.read_file(path, 16384)

    def test_existing_or_nonprivate_output_parent_is_rejected(self):
        self.stage.mkdir(mode=0o700)
        with self.assertRaises(package.Rejected): package.invocation(self.stage_args)
        self.stage.rmdir()
        self.stage.symlink_to(self.root / 'missing')
        with self.assertRaises(package.Rejected): package.invocation(self.stage_args)
        self.stage.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(package.Rejected): package.invocation(self.stage_args)
        self.root.chmod(0o700)

    def test_signing_and_verify_exact_cert_requirement_and_no_keychain_discovery(self):
        self.stage_fixture()
        value = self.run_sign()
        self.assertEqual(value['status'], 'signed-local-review')
        signs = [c for c in self.calls if '--sign' in c]
        self.assertEqual(len(signs), 1)
        self.assertEqual(signs[0][signs[0].index('--sign') + 1], self.identity)
        self.assertTrue(signs[0][signs[0].index('--keychain') + 1].endswith('/Library/Keychains/Tailgate Signing.keychain-db'))
        self.assertIn('--timestamp=none', signs[0]); self.assertIn('--digest-algorithm=sha256', signs[0])
        self.assertEqual(signs[0][signs[0].index('--requirements') + 1],
                         '=designated => ' + package.requirement(self.identity))
        self.assertNotIn('--entitlements', signs[0])
        self.assertTrue(all(c[0] != '/usr/bin/security' for c in self.calls))
        before = len(self.calls)
        args = package.invocation(['--verify', '--artifact', str(self.signed), '--artifact-sha256',
                                   value['artifact_sha256']] + self.signer_args)
        real_protected = package.protected
        def no_keychain_metadata(path, **kwargs):
            self.assertNotIn('/Library/Keychains/', str(path))
            return real_protected(path, **kwargs)
        with mock.patch.object(package, 'command', self.fake_command), \
                mock.patch.object(package, 'protected', no_keychain_metadata):
            result = package.sign_or_verify(args)
        self.assertEqual(result['status'], 'verified-local-review')
        self.assertFalse(any('--sign' in c or '--keychain' in c for c in self.calls[before:]))
        checks = [c for c in self.calls if '--test-requirement' in c]
        self.assertTrue(all(c[c.index('--test-requirement') + 1] == '=' + package.requirement(self.identity) for c in checks))

    def test_tampered_stage_or_manifest_pin_cannot_reach_any_tool(self):
        self.stage_fixture()
        args = package.invocation(self.sign_args())
        for name in (package.BINARY, package.PLIST, package.MANIFEST):
            path = self.stage / name
            original = path.read_bytes()
            path.write_bytes(original + b'tampering')
            with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
                package.sign_or_verify(args)
            path.write_bytes(original)
        self.assertFalse(self.signed.exists())

    def test_unexpected_artifact_entries_and_symlinks_rejected(self):
        self.stage_fixture()
        for name in ('Contents/embedded.provisionprofile', 'Contents/extra', 'Contents/Resources/secret'):
            path = self.stage / package.APP / name
            package.write_file(path, b'not allowed')
            with self.assertRaises(package.Rejected): package.package_files(self.stage, False)
            path.unlink()
            if name.startswith('Contents/Resources/'): path.parent.rmdir()
        binary = self.stage / package.BINARY
        binary.unlink(); binary.symlink_to(self.cert)
        with self.assertRaises(package.Rejected): package.package_files(self.stage, False)

    def test_certificate_pins_and_der_shape_checked_before_openssl_or_key_use(self):
        self.stage_fixture()
        for attribute, value in [('identity', 'f' * 40), ('certificate_sha256', 'e' * 64)]:
            args = package.invocation(self.sign_args()); setattr(args, attribute, value)
            with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
                package.sign_or_verify(args)
        for data in (b'not DER', self.cert_bytes + b'trailing', b'\x30\x80indefinite'):
            self.cert.write_bytes(data)
            args = package.invocation(self.sign_args())
            args.identity = hashlib.sha1(data).hexdigest(); args.certificate_sha256 = package.digest(data)
            with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
                package.sign_or_verify(args)

    def test_certificate_backed_stage_and_sign_failure_never_fall_back(self):
        self.stage_fixture()
        for failure in ('already-signed', 'key-unavailable'):
            with self.subTest(failure=failure):
                def unavailable(cmd, **kwargs):
                    if '--sign' in cmd:
                        raise package.Rejected()
                    if failure == 'already-signed' and '--verbose=4' in cmd:
                        return 0, b'', b'flags=0x10000(runtime)\nAuthority=synthetic\n'
                    return self.fake_command(cmd, **kwargs)
                with self.assertRaises(package.Rejected): self.run_sign(unavailable)
                self.assertFalse(self.signed.exists())
        self.assertFalse(any('--sign' in c for c in self.calls))

    def test_signed_pin_mismatch_refused_before_verification_tools(self):
        self.stage_fixture()
        result = self.run_sign()
        args = package.invocation(['--verify', '--artifact', str(self.signed), '--artifact-sha256',
                                   result['artifact_sha256']] + self.signer_args)
        (self.signed / package.BINARY).write_bytes(macho(signature=b'other signature'))
        with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
            package.sign_or_verify(args)

    def test_developer_id_certificate_rejected_before_keychain_or_signing(self):
        self.stage_fixture()
        def apple_cert(cmd, **kw):
            result = self.fake_command(cmd, **kw)
            if str(cmd[0]) == '/usr/bin/openssl':
                return 0, b'Certificate:\nCode Signing\nDeveloper ID Application\n', b''
            return result
        with self.assertRaises(package.Rejected): self.run_sign(apple_cert)
        self.assertFalse(any('--sign' in c for c in self.calls))
        self.assertFalse(self.signed.exists())

    def test_signer_flags_dr_entitlements_and_payload_mismatch_fail_without_publish(self):
        self.stage_fixture()
        for failure in ('leaf', 'adhoc', 'runtime', 'team', 'requirement', 'entitlements', 'code', 'plist'):
            with self.subTest(failure=failure):
                def corrupt(cmd, **kw):
                    result = self.fake_command(cmd, **kw)
                    cmd = [str(x) for x in cmd]
                    if failure == 'leaf' and '--extract-certificates' in cmd:
                        Path(cmd[cmd.index('--extract-certificates') + 1] + '0').write_bytes(b'other public cert')
                    if '--verbose=4' in cmd and 'runtime' in result[2].decode():
                        if failure == 'adhoc': return 0, b'', result[2].replace(b'0x10000', b'0x10002')
                        if failure == 'runtime': return 0, b'', result[2].replace(b'0x10000', b'0x0')
                        if failure == 'team': return 0, b'', result[2].replace(b'not set', b'WRONGTEAM')
                    if failure == 'requirement' and '-r-' in cmd:
                        return 0, b'', b'designated => anchor trusted\n'
                    if failure == 'entitlements' and '--entitlements' in cmd:
                        return 0, plistlib.dumps({'keychain-access-groups': ['synthetic']}), b''
                    if '--sign' in cmd:
                        app = Path(cmd[-1])
                        if failure == 'code': (app / 'Contents/MacOS/TailgateReview').write_bytes(macho(code=b'CHANGED-CODE', signature=b'NEW-SIGNATURE'))
                        if failure == 'plist': (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'wrong'}))
                    return result
                with self.assertRaises(package.Rejected): self.run_sign(corrupt)
                self.assertFalse(self.signed.exists())

    def test_original_stage_rechecked_after_signing(self):
        self.stage_fixture()
        def mutate_source(cmd, **kw):
            result = self.fake_command(cmd, **kw)
            if '--sign' in cmd:
                (self.stage / package.PLIST).write_bytes(b'tampered during signing')
            return result
        with self.assertRaises(package.Rejected): self.run_sign(mutate_source)
        self.assertFalse(self.signed.exists())

    def test_payload_comparison_allows_only_signature_bookkeeping_not_code_or_commands(self):
        original = macho()
        self.assertEqual(package.macho_payload(original), package.macho_payload(macho(signature=b'other signature size')))
        self.assertEqual(package.macho_payload(original), package.macho_payload(macho(include_signature=False)))
        self.assertNotEqual(package.macho_payload(original), package.macho_payload(macho(code=b'OTHER CODE')))
        changed = bytearray(original); changed[12:16] = struct.pack('<I', 6)
        with self.assertRaises(package.Rejected): package.macho_payload(changed)
        for data in (b'not a Mach-O', original[:-1], original + b'junk'):
            with self.assertRaises(package.Rejected): package.macho_payload(data)

    def test_command_uses_absolute_tools_clean_environment_and_null_stdin(self):
        def fake_run(argv, **kwargs):
            self.assertEqual(argv, ['/usr/bin/swift', '--version'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            env = kwargs['env']
            self.assertNotIn('DYLD_INSERT_LIBRARIES', env)
            self.assertNotIn('SWIFT_EXEC', env)
            self.assertEqual(env['DEVELOPER_DIR'], '/Library/Developer/CommandLineTools')
            self.assertEqual(env['HOME'], str(self.root))
            return types.SimpleNamespace(returncode=0)
        with mock.patch.dict(os.environ, {'DYLD_INSERT_LIBRARIES': 'never-read', 'SWIFT_EXEC': 'never-run'}), \
                mock.patch.object(package.subprocess, 'run', fake_run):
            self.assertEqual(package.command(['/usr/bin/swift', '--version'], cwd=self.root), (0, b'', b''))

    def test_empty_real_cli_is_rejected_without_tools_or_user_data(self):
        result = subprocess.run(['/bin/sh', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(str(self.root).encode(), result.stderr)


if __name__ == '__main__':
    unittest.main()
