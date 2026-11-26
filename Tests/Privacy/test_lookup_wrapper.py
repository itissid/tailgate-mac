"""Synthetic exact-name lookup wrapper tests; no app, network or Keychain access."""
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('lookup_adapter_tests', str(ROOT / 'Scripts/tailgate-lookup'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lookup = importlib.util.module_from_spec(spec)
loader.exec_module(lookup)


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def output(device=None):
    return {'version': 1, 'status': 'disclosed', 'device': device if device is not None else {'name': 'demo-runner'}}


class LookupWrapperTests(unittest.TestCase):
    def test_strict_exact_name_and_canonical_fields_frame(self):
        for fields in lookup.FIELDS:
            name, selected, frame = lookup.query(['--name', 'demo-runner', '--fields', fields])
            self.assertEqual(name, 'demo-runner')
            self.assertEqual(selected, fields)
            self.assertEqual(frame, ('TAILGATE-LOOKUP/1\ndemo-runner\n' + fields + '\n').encode())
            self.assertLessEqual(len(frame), 104)

    def test_reject_invalid_names_and_modes(self):
        for name in ['', '1runner', '-runner', 'runner-', 'Demo', 'demo.example', '*', '../demo', 'https://demo', 'demo\nname', 'a' * 64, 'démø']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                lookup.query(['--name', name, '--fields', 'name'])
        for fields in ['all', 'ips', 'name,name', 'ips,name', 'name, tags', 'name,keys', 'name\n']:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                lookup.query(['--name', 'demo-runner', '--fields', fields])
        for args in [[], ['--wait'], ['--fields', 'name', '--name', 'demo-runner'], ['--name', 'demo-runner', '--fields', 'name', '--url', 'invalid']]:
            with self.assertRaises(ValueError):
                lookup.query(args)

    def test_success_includes_only_requested_fields_and_no_extra_identity(self):
        self.assertEqual(lookup.parse_result(encode(output()), 0, 'demo-runner', 'name'), output())
        value = output({'name': 'demo-runner', 'tags': ['tag:demo-client'], 'ips': ['100.' + '64.0.42', 'fd7a:' + '115c:a1e0::42']})
        self.assertEqual(lookup.parse_result(encode(value), 0, 'demo-runner', 'name,tags,ips'), value)
        for key in ['nodeKey', 'hostname', 'id', 'owner', 'extra']:
            value = output({'name': 'demo-runner', key: 'unrequested'})
            self.assertEqual(lookup.parse_result(encode(value), 0, 'demo-runner', 'name'), lookup.failure('unknown'))

    def test_missing_requested_field_or_wrong_name_is_not_forwarded(self):
        for value in [output({'name': 'other'}), output({}), output({'name': 'demo-runner', 'tags': []})]:
            self.assertEqual(lookup.parse_result(encode(value), 0, 'demo-runner', 'name,ips'), lookup.failure('unknown'))

    def test_every_failure_has_no_device_match_or_count(self):
        for status in lookup.FAILURES:
            value = lookup.failure(status)
            code = 3 if status == 'unknown' else 2
            self.assertEqual(lookup.parse_result(encode(value), code, 'demo-runner', 'name'), value)
            for key in ['device', 'name', 'found', 'count', 'message']:
                bad = dict(value, **{key: 'forbidden'})
                self.assertEqual(lookup.parse_result(encode(bad), code, 'demo-runner', 'name'), lookup.failure('unknown'))

    def test_malformed_duplicate_truncated_excess_output_is_unknown(self):
        for raw in [b'', b'no', b'{', b'[' * 1500 + b']' * 1500, b'{}\n{}', b' ' * (lookup.MAX_RESULT + 1), b'{"version":1,"version":1,"status":"rejected"}', b'{"version":true,"status":"rejected"}', b'[]', b'null']:
            self.assertEqual(lookup.parse_result(raw, 2, 'demo-runner', 'name'), lookup.failure('unknown'))
        nested = b'{"version":1,"status":"disclosed","device":{"name":"demo-runner","name":"demo-runner"}}'
        self.assertEqual(lookup.parse_result(nested, 0, 'demo-runner', 'name'), lookup.failure('unknown'))

    def test_exit_codes_must_match_status(self):
        for code in [1, 2, 3, -15]:
            self.assertEqual(lookup.parse_result(encode(output()), code, 'demo-runner', 'name'), lookup.failure('unknown'))
        self.assertEqual(lookup.parse_result(encode(lookup.failure('rejected')), 0, 'demo-runner', 'name'), lookup.failure('unknown'))

    def test_reject_tag_duplicates_bad_types_and_unbounded_arrays(self):
        for tags in [['tag:demo', 'tag:demo'], ['*'], ['tag:Demo'], ['tag:x\n'], [{}], 'tag:demo', ['tag:demo'] * 65]:
            value = output({'name': 'demo-runner', 'tags': tags})
            self.assertEqual(lookup.parse_result(encode(value), 0, 'demo-runner', 'name,tags'), lookup.failure('unknown'))

    def test_reject_non_tailnet_ip_zone_duplicates_and_wrong_types(self):
        for ips in [[], ['127.' + '0.0.1'], ['192.' + '0.2.1'], ['::1'], ['fd7a:' + '115c:a1e0::1%en0'], [{}], '100.' + '64.0.1', ['100.' + '64.0.1'] * 2, ['100.' + '64.0.1'] * 17]:
            value = output({'name': 'demo-runner', 'ips': ips})
            self.assertEqual(lookup.parse_result(encode(value), 0, 'demo-runner', 'name,ips'), lookup.failure('unknown'))

    def test_parse_errors_do_not_echo_input(self):
        raw = b'{"status":"rejected","message":"synthetic-private-context"}'
        result = encode(lookup.parse_result(raw, 2, 'demo-runner', 'name'))
        self.assertNotIn(b'synthetic-private-context', result)
        self.assertNotIn(b'demo-runner', result)

    def test_invalid_cli_does_not_load_verifier_or_launch(self):
        with mock.patch.object(lookup.sys, 'argv', ['tailgate-lookup', '--list-all']), mock.patch.object(lookup, 'common') as shared:
            self.assertEqual(lookup.main(), lookup.failure())
        shared.assert_not_called()

    def test_reuse_existing_installation_verifier_and_safe_environment(self):
        shared = lookup.common()
        self.assertEqual(shared.EXECUTABLE, '/Applications/Tailgate.app/Contents/MacOS/TailgateReview')
        self.assertTrue(callable(shared.verify_installation))
        with mock.patch.dict(os.environ, {'DYLD_INSERT_LIBRARIES': 'not-used', 'PYTHONPATH': 'not-used', 'HTTPS_PROXY': 'not-used'}):
            env = shared.safe_environment()
        self.assertNotIn('DYLD_INSERT_LIBRARIES', env)
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('HTTPS_PROXY', env)

    def test_verifier_failure_never_launches_and_reveals_no_name(self):
        fake = types.SimpleNamespace(acquire_lock=lambda: os.open(os.devnull, os.O_RDONLY), verify_installation=mock.Mock(side_effect=ValueError('synthetic-sensitive')))
        with mock.patch.object(lookup.sys, 'argv', ['tailgate-lookup', '--name', 'demo-runner', '--fields', 'name']), mock.patch.object(lookup, 'common', return_value=fake), mock.patch.object(lookup.subprocess, 'Popen') as launch:
            self.assertEqual(lookup.main(), lookup.failure())
        launch.assert_not_called()

    def test_launch_uses_fixed_binary_query_and_no_ambient_secrets(self):
        class Input(io.BytesIO):
            def close(self):
                self.sent = self.getvalue()
                super().close()
        child = types.SimpleNamespace(stdin=Input())
        fake = types.SimpleNamespace(EXECUTABLE='/Applications/Tailgate.app/Contents/MacOS/TailgateReview', acquire_lock=lambda: os.open(os.devnull, os.O_RDONLY), verify_installation=mock.Mock(), safe_environment=lambda: {'PATH': '/usr/bin:/bin'}, stop=mock.Mock())
        with mock.patch.object(lookup.sys, 'argv', ['tailgate-lookup', '--name', 'demo-runner', '--fields', 'name']), mock.patch.object(lookup, 'common', return_value=fake), mock.patch.object(lookup.subprocess, 'Popen', return_value=child) as launch, mock.patch.object(lookup, 'wait_once', return_value=lookup.failure('declined')):
            self.assertEqual(lookup.main(), lookup.failure('declined'))
        args, kwargs = launch.call_args
        self.assertEqual(args[0], [fake.EXECUTABLE, '--lookup-and-wait'])
        self.assertEqual(child.stdin.sent, b'TAILGATE-LOOKUP/1\ndemo-runner\nname\n')
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(kwargs['cwd'], '/')

    def test_output_cap_or_disconnect_is_unknown_not_a_disclosure(self):
        for raw, parent in [(b'x' * (lookup.MAX_RESULT + 1), 5), (encode(output()), 1)]:
            readfd, writefd = os.pipe()
            self.addCleanup(os.close, readfd)
            # Use cap+1 in a compact chunk with a fake selector; avoids a pipe-size block.
            child = types.SimpleNamespace(stdout=readfd)
            adapter = types.SimpleNamespace(stop=mock.Mock())
            select = mock.MagicMock()
            select.__enter__.return_value = select
            select.select.return_value = [(types.SimpleNamespace(fd=readfd), None)]
            chunks = [raw[:1024]] * 9 if len(raw) > lookup.MAX_RESULT else [raw]
            with mock.patch.object(lookup.selectors, 'DefaultSelector', return_value=select), mock.patch.object(lookup.os, 'read', side_effect=chunks), mock.patch.object(lookup.os, 'getppid', return_value=parent):
                self.assertEqual(lookup.wait_once(child, parent, adapter, 'demo-runner', 'name'), lookup.failure('unknown'))
            os.close(writefd)
            adapter.stop.assert_called_once()


if __name__ == '__main__':
    unittest.main()
