"""Offline packaging checks. No Security/keychain/signing/GUI subprocess is executed."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Scripts/package-local-probe.sh'
source = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
package = types.ModuleType('tailgate_dummy_package')
package.__name__ = 'tailgate_dummy_package'
exec(compile(source, str(SCRIPT), 'exec'), package.__dict__)


class LocalPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fixture = self.root / 'reviewed'
        self.fixture.mkdir(mode=0o700)
        self.code = b'import Foundation\nprint("dummy only")\n'
        (self.fixture / 'Probe.swift').write_bytes(self.code)
        (self.fixture / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': package.IDENTIFIER,
            'CFBundleExecutable': 'KeychainProbe', 'CFBundlePackageType': 'APPL',
        }))
        self.cert = self.root / 'public.der'
        self.cert.write_bytes(b'synthetic-public-certificate-input')
        self.selector = hashlib.sha1(self.cert.read_bytes()).hexdigest()
        self.output = self.root / 'version-one'
        self.args = ['--check', '--identity', self.selector, '--certificate', str(self.cert),
                     '--source-root', str(self.fixture), '--probe-sha256', hashlib.sha256(self.code).hexdigest(),
                     '--output', str(self.output), '--version', '1']
        # Real filesystem fixtures need an ordinary, unprivileged process.
        if os.getuid() == 0:
            self.skipTest('Requires an unprivileged test process for private filesystem fixtures')

    def test_check_never_runs_any_tool_or_reads_keychain(self):
        with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), \
                mock.patch.object(package, 'package', side_effect=AssertionError('signing')):
            value = package.main(self.args)
        self.assertEqual(value, {'version': 1, 'status': 'inputs-checked-only', 'signed': False, 'live_enabled': False})
        self.assertFalse(self.output.exists())

    def test_missing_or_invalid_identity_and_missing_required_options(self):
        for selector in ('-', '', 'default', 'A' * 39, 'z' * 40):
            args = list(self.args)
            args[args.index('--identity') + 1] = selector
            with self.assertRaises(package.Rejected):
                package.preflight(package.invocation(args))
        for name in ('--identity', '--certificate', '--probe-sha256'):
            args = list(self.args)
            index = args.index(name)
            del args[index:index + 2]
            with mock.patch('sys.stderr'), self.assertRaises(SystemExit):
                package.invocation(args)

    def test_unmatched_certificate_selector_rejects_without_tools(self):
        args = package.invocation(self.args)
        args.identity = 'f' * 40
        with mock.patch.object(package, 'command', side_effect=AssertionError('tool')), self.assertRaises(package.Rejected):
            package.preflight(args)

    def test_source_pin_and_bundle_name_are_mandatory(self):
        args = package.invocation(self.args)
        (self.fixture / 'Probe.swift').write_bytes(self.code + b'// modified')
        with self.assertRaises(package.Rejected): package.preflight(args)
        (self.fixture / 'Probe.swift').write_bytes(self.code)
        (self.fixture / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'other'}))
        with self.assertRaises(package.Rejected): package.preflight(args)

    def test_refuses_link_hardlink_fifo_and_writable_snapshot(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                path = self.fixture / 'Probe.swift'
                path.unlink()
                if kind == 'symlink': path.symlink_to(self.cert)
                elif kind == 'hardlink': os.link(self.cert, path)
                else: os.mkfifo(path, 0o600)
                with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))
        (self.fixture / 'Probe.swift').unlink()
        (self.fixture / 'Probe.swift').write_bytes(self.code)
        self.fixture.chmod(0o777)
        with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))

    def test_output_requires_private_existing_parent_and_no_existing_destination(self):
        self.output.mkdir(mode=0o700)
        with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))
        self.output.rmdir()
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))
        self.output.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))

    def test_extended_acl_rejection_is_not_bypassed_by_mode_bits(self):
        with mock.patch.object(package, 'no_extended_acl', side_effect=package.Rejected()), self.assertRaises(package.Rejected):
            package.preflight(package.invocation(self.args))

    def test_unknown_plist_environment_configuration_is_rejected(self):
        path = self.fixture / 'Info.plist'
        info = plistlib.loads(path.read_bytes())
        info['LSEnvironment'] = {'DYLD_INSERT_LIBRARIES': 'fixture'}
        path.write_bytes(plistlib.dumps(info))
        with self.assertRaises(package.Rejected): package.preflight(package.invocation(self.args))

    def test_privileged_or_mismatched_identity_refused(self):
        for uid, euid, gid, egid in [(0, 0, 1, 1), (501, 0, 1, 1), (501, 501, 1, 0)]:
            with mock.patch.object(package.os, 'getuid', return_value=uid), \
                    mock.patch.object(package.os, 'geteuid', return_value=euid), \
                    mock.patch.object(package.os, 'getgid', return_value=gid), \
                    mock.patch.object(package.os, 'getegid', return_value=egid), self.assertRaises(package.Rejected):
                package.preflight(package.invocation(self.args))

    def test_version_two_requires_previous_and_first_version_refuses_it(self):
        args = package.invocation(self.args)
        args.version = '2'
        with self.assertRaises(package.Rejected): package.preflight(args)
        args.version = '1'; args.previous = str(self.root)
        with self.assertRaises(package.Rejected): package.preflight(args)

    def fake_command(self, args, *, cwd, limit=65536):
        args = [str(a) for a in args]
        self.calls.append(args)
        if args[0] == '/usr/bin/swiftc':
            executable = Path(args[-1])
            executable.write_bytes(Path(args[-3]).read_bytes())
            executable.chmod(0o700)
        elif '--extract-certificates' in args:
            prefix = args[args.index('--extract-certificates') + 1]
            Path(prefix + '0').write_bytes(self.cert.read_bytes())
        elif '--verbose=4' in args:
            return b'', ('Identifier=' + package.IDENTIFIER + '\nflags=0x10000(runtime)\n').encode()
        elif '-r-' in args:
            return b'', ('designated => identifier "' + package.IDENTIFIER + '" and anchor trusted\n').encode()
        return b'', b''

    def test_simulated_upgrade_keeps_designated_requirement_and_changes_code(self):
        self.calls = []
        args = package.invocation(self.args)
        with mock.patch.object(package.sys, 'platform', 'darwin'), mock.patch.object(package, 'command', self.fake_command):
            first = package.package(args, package.preflight(args))
            previous = self.output
            args.output = str(self.root / 'version-two')
            args.version = '2'; args.previous = str(previous)
            second = package.package(args, package.preflight(args))
        self.assertFalse(first['upgrade_control_verified'])
        self.assertTrue(second['upgrade_control_verified'])
        a = json.loads((previous / 'verified-dummy-package.json').read_text())
        b = json.loads((Path(args.output) / 'verified-dummy-package.json').read_text())
        self.assertNotEqual(a['executable_sha256'], b['executable_sha256'])
        self.assertEqual(a['designated_requirement'], b['designated_requirement'])
        signs = [c for c in self.calls if '--sign' in c]
        self.assertEqual(len(signs), 2)
        self.assertTrue(all('--timestamp=none' in c and '--digest-algorithm=sha256' in c for c in signs))
        self.assertTrue(all(c[c.index('--sign') + 1] == self.selector for c in signs))
        self.assertTrue(all(c[0] != '/usr/bin/security' for c in self.calls))
        dr_checks = [c for c in self.calls if '--test-requirement' in c]
        self.assertTrue(dr_checks)
        self.assertTrue(all(c[c.index('--test-requirement') + 1].startswith('=identifier ') for c in dr_checks))

    def test_upgrade_requires_stable_requirement_and_different_executable(self):
        for changed in ('requirement', 'same-code'):
            with self.subTest(changed=changed):
                self.calls = []
                args = package.invocation(self.args)
                args.output = str(self.root / ('initial-' + changed))
                with mock.patch.object(package.sys, 'platform', 'darwin'), mock.patch.object(package, 'command', self.fake_command):
                    package.package(args, package.preflight(args))
                old = Path(args.output)
                args.output = str(self.root / ('update-' + changed)); args.version = '2'; args.previous = str(old)
                def changed_tool(cmd, **kw):
                    result = self.fake_command(cmd, **kw)
                    if changed == 'requirement' and '-r-' in cmd and str(old) not in str(cmd[-1]):
                        return b'', ('designated => identifier "' + package.IDENTIFIER + '" and certificate leaf trusted\\n').encode()
                    if changed == 'same-code' and cmd[0] == '/usr/bin/swiftc':
                        Path(cmd[-1]).write_bytes((old / package.APP / 'Contents/MacOS/KeychainProbe').read_bytes())
                    return result
                with mock.patch.object(package.sys, 'platform', 'darwin'), mock.patch.object(package, 'command', changed_tool), self.assertRaises(package.Rejected):
                    package.package(args, package.preflight(args))
                self.assertFalse(Path(args.output).exists())

    def test_actual_signer_mismatch_is_rejected_without_publish(self):
        self.calls = []
        def different_cert(args, **kw):
            result = self.fake_command(args, **kw)
            if '--extract-certificates' in args:
                Path(str(args[list(args).index('--extract-certificates') + 1]) + '0').write_bytes(b'other fixture cert')
            return result
        args = package.invocation(self.args)
        with mock.patch.object(package.sys, 'platform', 'darwin'), mock.patch.object(package, 'command', different_cert), self.assertRaises(package.Rejected):
            package.package(args, package.preflight(args))
        self.assertFalse(self.output.exists())

    def test_wrong_hardening_or_ad_hoc_flag_is_rejected(self):
        for flags in ('0x0', '0x10002'):
            self.calls = []
            def metadata(args, **kw):
                result = self.fake_command(args, **kw)
                if '--verbose=4' in args:
                    return b'', ('Identifier=' + package.IDENTIFIER + '\nflags=' + flags + '\n').encode()
                return result
            args = package.invocation(self.args)
            with mock.patch.object(package.sys, 'platform', 'darwin'), mock.patch.object(package, 'command', metadata), self.assertRaises(package.Rejected):
                package.package(args, package.preflight(args))
            self.assertFalse(self.output.exists())

    def test_empty_command_cli_does_not_sign(self):
        result = subprocess.run(['/bin/sh', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'certificate subject', result.stderr)


if __name__ == '__main__':
    unittest.main()
