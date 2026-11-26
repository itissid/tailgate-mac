"""Synthetic-only privacy regressions. No network and no real credentials."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "Scripts" / "check-public.py"
spec = importlib.util.spec_from_file_location("check_public", SCRIPT)
privacy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = privacy
spec.loader.exec_module(privacy)


def fake_private_email():
    return "fixture-person" + "@" + "fixture-internal.testcorp.tld"


def fake_token():
    return "tskey-" + "client-" + "syntheticvalue" * 3


def private_path():
    return "/" + "Users/" + "fixture-person/secret.json"


def synthetic_ip(last=1):
    return ".".join(map(str, (100, 64, 0, last)))


class ContentTests(unittest.TestCase):
    def check(self, value, category):
        self.assertIn(category, privacy.content_categories(value.encode(), set()))

    def test_private_email_and_absolute_paths(self):
        self.check(fake_private_email(), "private-email")
        self.check(private_path(), "absolute-user-path")
        self.check("/" + "home/fixture-person/project", "absolute-user-path")
        self.check("C:" + "\\Users\\fixture-person\\app", "absolute-user-path")

    def test_public_handle_noreply_and_synthetic_docs(self):
        safe = "dev@" + "users.noreply.github.com alice@example.com host.example.ts.net"
        self.assertEqual(privacy.content_categories(safe.encode(), set()), set())

    def test_tailnet_addresses_and_real_local_hostname(self):
        self.check(synthetic_ip(), "tailnet-address")
        self.check("fd7a:" + "115c:a1e0:1234::1", "tailnet-address")
        self.check("fixture-node.production-tail" + ".ts.net", "tailnet-hostname")
        name = "fixture-machine" + ".local"
        self.assertIn("local-hostname", privacy.content_categories(name.encode(), {name}))
        self.assertNotIn("local-hostname", privacy.content_categories(("prefix" + name + "suffix").encode(), {name}))

    def test_secrets_signing_material_and_bearer_values(self):
        for value, category in [
            (fake_token(), "oauth-token"),
            ("ghp_" + "x" * 30, "github-token"),
            ("-----BEGIN " + "PRIVATE KEY-----", "private-key"),
            ("-----BEGIN " + "CERTIFICATE-----", "certificate"),
            ("AKIA" + "X" * 16, "cloud-access-key"),
            ("Bearer " + "x" * 32, "bearer-token"),
            ('client_secret = "' + "x" * 28 + '"', "assigned-secret"),
            ("https://" + "fixture:privatevalue@api.example.com", "credential-url"),
        ]:
            with self.subTest(category=category):
                self.check(value, category)

    def test_signing_build_and_sensitive_config_paths(self):
        for path in ["Release/profile.mobileprovision", "signer.p12", ".env.production", "credentials.json", ".build/output", "dist/Tailgate.app/Contents/MacOS/Tailgate", "payload/private.key"]:
            with self.subTest(path=path):
                self.assertTrue(privacy.path_categories(path, set()))
        for path in ["Release/Info.plist", "Release/Tailgate.entitlements", "Docs/signing.md", "Examples/browser.json", ".env.example"]:
            with self.subTest(path=path):
                self.assertEqual(privacy.path_categories(path, set()), set())

    def test_only_reviewed_selector_fixture_is_exempt(self):
        path = "Tests/TailgateCoreTests/PolicyTests.swift"
        data = ('        for src in ["*", "' + synthetic_ip() + '"] {\n').encode()
        result = privacy.reviewed_fixture_bytes(path, data)
        self.assertNotIn("tailnet-address", privacy.content_categories(result, set()))
        self.assertEqual(privacy.reviewed_fixture_bytes("Tests/Other.swift", data), data)
        self.assertEqual(privacy.reviewed_fixture_bytes(path, synthetic_ip(2).encode()), synthetic_ip(2).encode())
        self.assertEqual(privacy.reviewed_fixture_bytes(path, ('let node = "' + synthetic_ip() + '"').encode()), ('let node = "' + synthetic_ip() + '"').encode())

    def test_metadata_display_name_must_be_neutral_or_public_handle(self):
        safe = "author fixture <fixture@users.noreply.github.com> 0 +0000\n"
        self.assertEqual(privacy.metadata_categories(safe.encode()), set())
        private = "author Synthetic Person <fixture@users.noreply.github.com> 0 +0000\n"
        self.assertIn("unreviewed-display-name", privacy.metadata_categories(private.encode()))
        trailer = "Co-authored-by: Synthetic Person <fixture@users.noreply.github.com>\n"
        self.assertIn("unreviewed-display-name", privacy.metadata_categories(trailer.encode()))

    def test_non_utf8_cannot_silently_pass(self):
        self.assertFalse(privacy.is_text(bytes((255, 254, 253))))
        self.assertTrue(privacy.is_text("Public documentation.".encode()))

    def test_dangerous_path_labels_never_echo_values(self):
        path = "Docs/" + fake_private_email() + ".txt"
        label = privacy.path_label(path, set())
        self.assertTrue(label.startswith("path-sha256:"))
        self.assertNotIn(fake_private_email(), label)


class HostnameTests(unittest.TestCase):
    def test_discovery_uses_only_local_sources_without_any_resolver(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"fixture-machine.local\n", stderr=b"")
        with mock.patch.object(privacy.socket, "gethostname", return_value="fixture-kernel-host"), \
             mock.patch.object(privacy.socket, "getfqdn", side_effect=AssertionError("Resolver forbidden")), \
             mock.patch.object(privacy.socket, "gethostbyname", side_effect=AssertionError("Resolver forbidden")), \
             mock.patch.object(privacy.socket, "gethostbyaddr", side_effect=AssertionError("Resolver forbidden")), \
             mock.patch.object(privacy.socket, "getaddrinfo", side_effect=AssertionError("Resolver forbidden")), \
             mock.patch.object(privacy.sys, "platform", "darwin"), \
             mock.patch.object(privacy.subprocess, "run", return_value=completed) as local_query:
            names = privacy.local_hostnames()
        self.assertIn("fixture-kernel-host", names)
        self.assertIn("fixture-machine.local", names)
        self.assertIn("fixture-machine", names)
        self.assertEqual(local_query.call_count, 3)
        for call in local_query.call_args_list:
            self.assertEqual(call.args[0][:2], ["/usr/sbin/scutil", "--get"])


class GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="publication-privacy-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ,
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                        GIT_AUTHOR_EMAIL="fixture@users.noreply.github.com",
                        GIT_COMMITTER_EMAIL="fixture@users.noreply.github.com")
        self.git("init", "-q", "-b", "main")
        self.file("README.md", "Synthetic fixture.\n")
        self.commit("Initial fixture")

    def git(self, *args, env=None):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=env or self.env, stderr=subprocess.DEVNULL)

    def file(self, name, data):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        self.git("add", "--", name)

    def commit(self, message, env=None):
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "-m", message, env=env)

    def scanner(self):
        return privacy.Scanner(self.repo, hosts=set())

    def test_worktree_does_not_reopen_a_prechecked_path_to_read(self):
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Path-based read forbidden")):
            self.scanner().worktree()

    def test_clean_history_index_and_worktree(self):
        scanner = self.scanner()
        scanner.history(); scanner.index(); scanner.worktree()
        self.assertEqual(scanner.findings, set())

    def test_deleted_historical_secret_is_still_rejected(self):
        self.file("old.txt", fake_token()); self.commit("Synthetic secret fixture")
        self.git("rm", "-q", "old.txt"); self.commit("Delete fixture")
        scanner = self.scanner(); scanner.history()
        self.assertTrue(any(f.category == "oauth-token" and f.location == "old.txt" for f in scanner.findings))

    def test_staged_index_is_scanned_even_if_worktree_is_clean(self):
        self.file("staged.txt", fake_token())
        (self.repo / "staged.txt").write_text("No secret in worktree.\n")
        scanner = self.scanner(); scanner.index()
        self.assertTrue(any(f.category == "oauth-token" and f.scope == "index" for f in scanner.findings))

    def test_untracked_nonignored_file_is_scanned(self):
        (self.repo / "draft.txt").write_text(fake_private_email())
        scanner = self.scanner(); scanner.worktree()
        self.assertTrue(any(f.category == "private-email" and f.scope == "worktree" for f in scanner.findings))

    def test_author_committer_and_message_metadata(self):
        env = dict(self.env, GIT_AUTHOR_EMAIL=fake_private_email(), GIT_COMMITTER_EMAIL=fake_private_email())
        self.file("safe.txt", "No private text.\n"); self.commit("Move from " + private_path(), env=env)
        scanner = self.scanner(); scanner.history()
        self.assertTrue(any(f.category == "private-email" and f.location.startswith("commit:") for f in scanner.findings))
        self.assertTrue(any(f.category == "absolute-user-path" and f.location.startswith("commit:") for f in scanner.findings))

    def test_annotated_tag_metadata_is_scanned(self):
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "fixture-tag", "-m", fake_private_email())
        scanner = self.scanner(); scanner.history()
        self.assertTrue(any(f.category == "private-email" and f.location.startswith("tag:") for f in scanner.findings))

    def test_historic_private_filename_is_reported_without_echo(self):
        self.file("old/" + fake_private_email(), "Safe contents.\n"); self.commit("Synthetic filename")
        scanner = self.scanner(); scanner.history()
        self.assertTrue(any(f.category == "private-email" and f.location.startswith("path-sha256:") for f in scanner.findings))
        self.assertFalse(any(fake_private_email() in f.location for f in scanner.findings))

    def test_public_ref_snapshot_excludes_unpublished_commit(self):
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.file("future.txt", fake_token()); self.commit("Unpublished fixture")
        scanner = self.scanner(); scanner.history("refs/remotes/origin/main")
        self.assertEqual(scanner.findings, set())
        scanner = self.scanner(); scanner.history()
        self.assertTrue(any(f.category == "oauth-token" for f in scanner.findings))

    def test_binary_and_lfs_cannot_silently_pass(self):
        path = self.repo / "binary.bin"; path.write_bytes(b"\x00\x01")
        self.git("add", "binary.bin")
        self.file("large.txt", "version https://git-lfs.github.com/spec/v1\n")
        scanner = self.scanner(); scanner.index()
        categories = {f.category for f in scanner.findings}
        self.assertIn("binary-or-symlink-not-reviewed", categories)
        self.assertIn("lfs-content-not-scanned", categories)

    def test_shallow_history_fails_closed(self):
        head = self.git("rev-parse", "HEAD").strip()
        (self.repo / ".git" / "shallow").write_bytes(head + b"\n")
        with self.assertRaises(privacy.ScanFailure):
            self.scanner().history()

    def test_limits_fail_closed_and_output_never_echoes_private_text(self):
        self.file("future.txt", fake_token())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = privacy.main(["--repo", str(self.repo)])
        self.assertEqual(code, 1)
        self.assertNotIn(fake_token(), output.getvalue())
        self.assertNotIn(str(self.repo), output.getvalue())
        old = privacy.MAX_BLOB
        try:
            privacy.MAX_BLOB = 4
            with self.assertRaises(privacy.ScanFailure):
                self.scanner().index()
        finally:
            privacy.MAX_BLOB = old


if __name__ == "__main__":
    unittest.main()
