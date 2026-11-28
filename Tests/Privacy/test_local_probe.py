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

    def update_controls(self):
        return [observation("ok", 0) if i not in (3, 4, 5) else observation("denied", -25308)
                for i in range(9)]

    def test_update_requires_old_new_and_unrelated_positive_controls(self):
        self.assertEqual(probe.classify_update(self.update_controls()), "passed")
        for index in (0, 1, 2, 6, 7, 8):
            rows = self.update_controls()
            rows[index] = observation("denied", -25308)
            self.assertEqual(probe.classify_update(rows), "inconclusive")
        for index in (3, 4, 5):
            rows = self.update_controls()
            rows[index] = observation("ok", 0)
            self.assertEqual(probe.classify_update(rows), "failed")
            rows[index] = observation("inconclusive", -25300)
            self.assertEqual(probe.classify_update(rows), "inconclusive")
        self.assertEqual(probe.classify_update(self.update_controls()[:-1]), "inconclusive")

    def update_fixture(self, root):
        apps = []
        for label in ("a1", "a2", "b"):
            app = root / label / "KeychainProbe.app"
            binary = app / "Contents/MacOS/KeychainProbe"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"test-only-not-a-signed-app")
            binary.chmod(0o700)
            apps.append(app)
        keychain = root / "dummy.keychain-db"
        keychain.touch(mode=0o600)
        return [str(root), *(str(a) for a in apps), str(keychain), "a" * 64, "b" * 64]

    def test_update_mode_requires_opt_in_and_distinguishes_missing_fixtures(self):
        with mock.patch.dict(probe.os.environ, {}, clear=True), \
                mock.patch.object(probe, "command", side_effect=AssertionError("process")):
            self.assertEqual(probe.update_test(["x"] * 7, "unused")["stage"], "isolated-fixtures-required")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(probe.os.environ, {"TAILGATE_DISPOSABLE_LAB": "1"}), \
                mock.patch.object(probe, "command", side_effect=AssertionError("process")):
            args = self.update_fixture(Path(directory).resolve())
            Path(args[2], "Contents/MacOS/KeychainProbe").unlink()
            result = probe.update_test(args, "verifier")
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["stage"], "update-fixtures-missing")
            self.assertFalse(result["update_access_observed"])

    def test_update_rejects_alias_paths_hardlinks_and_malformed_pins_before_execution(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(probe.os.environ, {"TAILGATE_DISPOSABLE_LAB": "1"}), \
                mock.patch.object(probe, "command", side_effect=AssertionError("process")):
            args = self.update_fixture(Path(directory).resolve())
            for index, value in ((2, args[1]), (5, "x" * 64), (6, args[5])):
                changed = args[:]; changed[index] = value
                self.assertEqual(probe.update_test(changed, "verifier")["stage"], "update-fixtures-invalid")
            binary = Path(args[2], "Contents/MacOS/KeychainProbe")
            binary.unlink(); probe.os.link(Path(args[1], "Contents/MacOS/KeychainProbe"), binary)
            self.assertEqual(probe.update_test(args, "verifier")["stage"], "update-fixtures-invalid")

    def test_update_driver_orders_controls_and_never_seeds_updated_app_acl(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(probe.os.environ, {"TAILGATE_DISPOSABLE_LAB": "1"}):
            args = self.update_fixture(Path(directory).resolve())
            rows = iter(self.update_controls())
            calls = []
            def fake_command(argv, **kwargs):
                calls.append(argv)
                value = next(rows) if argv[1] == "--read" else observation("ok", 0)
                return 0, json.dumps(value).encode()
            with mock.patch.object(probe, "command", side_effect=fake_command):
                result = probe.update_test(args, "verifier")
            self.assertEqual(result["status"], "passed")  # Driver sequencing only; not OS evidence.
            self.assertEqual([c[1] for c in calls], ["--verify-update", "--seed-update"] + ["--read"]*9 + ["--verify-update"])
            self.assertEqual(calls[1][0], str(Path(args[1], "Contents/MacOS/KeychainProbe")))
            self.assertEqual(calls[3][0], str(Path(args[2], "Contents/MacOS/KeychainProbe")))
            self.assertEqual(calls[3][-1], "a")
            self.assertLess(len(json.dumps(result)), 512)
            for value in args:
                self.assertNotIn(value, json.dumps(result))

    def test_update_invalid_signatures_setup_or_final_mutation_are_not_pass(self):
        for failed_call, expected in ((0, "update-signature-controls"), (1, "update-item-setup"), (11, "update-signature-controls")):
            with tempfile.TemporaryDirectory() as directory, \
                    mock.patch.dict(probe.os.environ, {"TAILGATE_DISPOSABLE_LAB": "1"}):
                args = self.update_fixture(Path(directory).resolve())
                outcomes = [(0, json.dumps(observation("ok", 0)).encode())] * 12
                # Expected cross-denials, not arbitrary all-success mock receipts.
                for i, row in enumerate(self.update_controls(), start=2):
                    outcomes[i] = (0, json.dumps(row).encode())
                outcomes[failed_call] = (3, json.dumps(observation("inconclusive", -25300)).encode())
                with mock.patch.object(probe, "command", side_effect=outcomes):
                    result = probe.update_test(args, "verifier")
                self.assertEqual(result["stage"], expected)
                self.assertFalse(result["update_access_observed"])

    def test_update_read_process_failure_cannot_be_a_denial_pass(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(probe.os.environ, {"TAILGATE_DISPOSABLE_LAB": "1"}):
            args = self.update_fixture(Path(directory).resolve())
            ok = (0, json.dumps(observation("ok", 0)).encode())
            responses = [ok] * 5 + [(1, json.dumps(observation("denied", -25308)).encode())]
            with mock.patch.object(probe, "command", side_effect=responses):
                result = probe.update_test(args, "verifier")
            self.assertEqual(result["stage"], "update-reader-process")
            self.assertFalse(result["update_access_observed"])

    def test_update_signature_controls_require_both_code_and_instruction_changes(self):
        swift = (EXPERIMENT / "Probe.swift").read_text()
        for invariant in ("a1.certificate == a2.certificate", "certificatePin(a1) == pinA",
                          "certificatePin(a2) == pinA", "certificatePin(b) == pinB",
                          "a1.codeHash != a2.codeHash", "a1.instructionsHash != a2.instructionsHash",
                          "a1.requirement == a2.requirement", "SecCodeCopyDesignatedRequirement",
                          "a1.architecture == a2.architecture"):
            self.assertIn(invariant, swift)

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
