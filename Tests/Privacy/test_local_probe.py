"""Offline checks for the dummy-only, explicitly inconclusive local-signing probe."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "Experiments/LocalKeychain"
spec = importlib.util.spec_from_file_location("tailgate_local_probe", EXPERIMENT / "runner.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def observation(status, code):
    return {"version": 1, "status": status, "osstatus": code}


class LocalProbeTests(unittest.TestCase):
    def controls(self):
        return [observation("ok", 0), observation("ok", 0), observation("denied", -25308),
                observation("denied", -25293), observation("ok", 0), observation("ok", 0)]

    def test_both_signers_need_positive_controls_before_and_after(self):
        self.assertEqual(probe.classify_case(self.controls()), "passed")
        for index in (0, 1, 4, 5):
            values = self.controls()
            values[index] = observation("denied", -25308)
            self.assertEqual(probe.classify_case(values), "inconclusive")

    def test_unauthorized_read_is_failure_not_pass(self):
        for index in (2, 3):
            values = self.controls()
            values[index] = observation("ok", 0)
            self.assertEqual(probe.classify_case(values), "failed")

    def test_missing_item_bad_keychain_setup_or_bad_status_is_not_denial(self):
        for result in [observation("inconclusive", -25300), observation("inconclusive", -25295),
                       observation("denied", -25300), observation("ok", -25308),
                       {"status": "denied"}, None]:
            values = self.controls()
            values[2] = result
            self.assertEqual(probe.classify_case(values), "inconclusive")
        self.assertEqual(probe.classify_case([]), "inconclusive")

    def test_preflight_never_runs_compiler_or_process(self):
        with mock.patch.object(probe, "command", side_effect=AssertionError("process")), \
                mock.patch.object(probe, "compile_probe", side_effect=AssertionError("compiler")):
            for args in ([], ["--preflight"]):
                result = probe.main(args)
                self.assertEqual(result["status"], "blocked")
                self.assertIs(result["signer_isolation_observed"], False)

    def test_cli_preflight_has_bounded_redacted_output_and_honest_exit(self):
        run = subprocess.run(["/bin/bash", str(EXPERIMENT / "run.sh"), "--preflight"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        self.assertEqual(run.returncode, 3)
        self.assertEqual(run.stderr, b"")
        self.assertLess(len(run.stdout), 256)
        value = json.loads(run.stdout)
        self.assertEqual(value["status"], "blocked")
        self.assertIs(value["signer_isolation_observed"], False)

    def test_result_parser_rejects_dynamic_fields_and_duplicates(self):
        for raw in [b'{"version":1,"status":"ok","path":"ignored"}',
                    b'{"version":1,"status":"ok","status":"denied"}',
                    b'{"version":true,"status":"ok"}', b"x" * 513, b"null"]:
            with self.assertRaises((ValueError, TypeError)):
                probe.strict_result(raw)

    def test_known_result_parser_roundtrips(self):
        value = observation("denied", -25308)
        self.assertEqual(probe.strict_result(json.dumps(value).encode()), value)

    def test_fixture_mode_requires_explicit_isolated_lab_attestation(self):
        with mock.patch.dict(probe.os.environ, {}, clear=True), \
                mock.patch.object(probe, "command", side_effect=AssertionError("process")):
            result = probe.fixture_test(["a", "b", "c", "d"], "unused")
            self.assertEqual(result["status"], "blocked")
            self.assertIs(result["signer_isolation_observed"], False)

    def test_fixture_paths_are_private_and_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(probe.safe_root(str(root)), root)
            child = root / "child"
            child.touch(mode=0o600)
            self.assertEqual(probe.in_root(root, str(child)), child)
            child.chmod(0o666)
            with self.assertRaises(ValueError):
                probe.in_root(root, str(child))
            with self.assertRaises(ValueError):
                probe.in_root(root, str(root.parent))
            link = root / "link"
            link.symlink_to(child)
            with self.assertRaises(ValueError):
                probe.in_root(root, str(link))

    def test_safety_surface_contains_no_default_or_mutation_operations(self):
        swift = (EXPERIMENT / "Probe.swift").read_text()
        runner = (EXPERIMENT / "runner.py").read_text()
        for forbidden in ("SecKeychainCreate(", "SecKeychainDelete(", "SecKeychainSetSearchList(",
                          "SecKeychainSetDefault(", "SecKeychainCopyDefault(",
                          "SecKeychainSetDomainSearchList(", "SecPKCS12Import("):
            self.assertNotIn(forbidden, swift)
        self.assertIn("kSecMatchSearchList as String: [keychain]", swift)
        self.assertIn("try check(SecKeychainSetUserInteractionAllowed(false))", swift)
        self.assertNotIn("/usr/bin/security", runner)
        self.assertNotIn("/usr/bin/codesign", runner)


if __name__ == "__main__":
    unittest.main()
