"""Bounded descriptor-only worktree reads; synthetic temporary filesystem data."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_check_public import privacy


class WorktreeDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="publication-fd-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, self.root_fd)
        self.path = self.root / "sample.txt"
        self.path.write_bytes(b"safe")

    def read(self, path="sample.txt", limit=64):
        return privacy.read_worktree_file(self.root_fd, path, limit)

    def test_regular_file_at_exact_budget_and_empty_zero_budget(self):
        self.assertEqual(self.read(limit=4), b"safe")
        self.path.write_bytes(b"")
        self.assertEqual(self.read(limit=0), b"")

    def test_existing_file_and_total_budget_limits_are_checked_before_read(self):
        with mock.patch.object(privacy.os, "read", side_effect=AssertionError("Must not read")) as read:
            with self.assertRaises(privacy.ScanFailure):
                self.read(limit=3)
            with mock.patch.object(privacy, "MAX_BLOB", 3):
                with self.assertRaises(privacy.ScanFailure):
                    self.read(limit=64)
        read.assert_not_called()

    def test_growth_after_fstat_is_rejected_with_hard_read_bound(self):
        real_read = os.read
        requested = []
        grown = False

        def grow_before_read(fd, count):
            nonlocal grown
            requested.append(count)
            if not grown:
                grown = True
                with self.path.open("ab") as writer:
                    writer.write(b"x" * 1024)
            return real_read(fd, count)

        with mock.patch.object(privacy.os, "read", side_effect=grow_before_read):
            with self.assertRaises(privacy.ScanFailure):
                self.read(limit=8)
        self.assertEqual(sum(requested), 5)  # Original four bytes plus one sentinel.

    def test_growth_after_eof_is_rejected_by_same_fd_poststat(self):
        real_read = os.read

        def grow_after_eof(fd, count):
            chunk = real_read(fd, count)
            if not chunk:
                with self.path.open("ab") as writer:
                    writer.write(b"x")
            return chunk

        with mock.patch.object(privacy.os, "read", side_effect=grow_after_eof):
            with self.assertRaises(privacy.ScanFailure):
                self.read(limit=64)

    def test_truncation_after_validation_is_rejected(self):
        real_read = os.read
        truncated = False

        def truncate_before_read(fd, count):
            nonlocal truncated
            if not truncated:
                truncated = True
                self.path.write_bytes(b"")
            return real_read(fd, count)

        with mock.patch.object(privacy.os, "read", side_effect=truncate_before_read):
            with self.assertRaises(privacy.ScanFailure):
                self.read()

    def test_replacement_after_open_does_not_reopen_or_read_symlink_target(self):
        target = self.root / "other.txt"
        target.write_bytes(b"not-the-opened-file")
        real_open = os.open
        final_fds = []
        stat_fds = []
        read_fds = []
        real_stat = os.fstat
        real_read = os.read

        def replace_after_open(path, flags, **kwargs):
            fd = real_open(path, flags, **kwargs)
            if path == "sample.txt":
                final_fds.append(fd)
                self.path.unlink()
                self.path.symlink_to(target)
            return fd

        def record_stat(fd):
            stat_fds.append(fd)
            return real_stat(fd)

        def record_read(fd, count):
            read_fds.append(fd)
            return real_read(fd, count)

        with mock.patch.object(privacy.os, "open", side_effect=replace_after_open), \
             mock.patch.object(privacy.os, "fstat", side_effect=record_stat), \
             mock.patch.object(privacy.os, "read", side_effect=record_read):
            self.assertEqual(self.read(), b"safe")
        self.assertEqual(stat_fds, final_fds * 2)
        self.assertTrue(read_fds)
        self.assertTrue(all(fd == final_fds[0] for fd in read_fds))

    def test_symlink_swap_before_open_is_rejected(self):
        target = self.root / "other.txt"
        target.write_bytes(b"not-a-candidate")
        real_open = os.open

        def replace_before_open(path, flags, **kwargs):
            if path == "sample.txt":
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.path.unlink()
                self.path.symlink_to(target)
            return real_open(path, flags, **kwargs)

        with mock.patch.object(privacy.os, "open", side_effect=replace_before_open), \
             mock.patch.object(privacy.os, "read", side_effect=AssertionError("Must not read")) as read:
            with self.assertRaises(privacy.ScanFailure):
                self.read()
        read.assert_not_called()

    def test_intermediate_directory_symlink_is_rejected(self):
        (self.root / "actual").mkdir()
        (self.root / "actual" / "nested.txt").write_bytes(b"not-followed")
        (self.root / "alias").symlink_to(self.root / "actual", target_is_directory=True)
        with mock.patch.object(privacy.os, "read", side_effect=AssertionError("Must not read")) as read:
            with self.assertRaises(privacy.ScanFailure):
                self.read("alias/nested.txt")
        read.assert_not_called()

    def test_fifo_open_is_nonblocking_and_rejected_before_read(self):
        os.mkfifo(self.root / "fifo")
        real_open = os.open

        def require_nonblocking(path, flags, **kwargs):
            if path == "fifo":
                # Assert BEFORE the real open so this regression cannot hang.
                self.assertTrue(flags & os.O_NONBLOCK)
                self.assertTrue(flags & os.O_NOFOLLOW)
            return real_open(path, flags, **kwargs)

        with mock.patch.object(privacy.os, "open", side_effect=require_nonblocking), \
             mock.patch.object(privacy.os, "read", side_effect=AssertionError("Must not read")) as read:
            with self.assertRaises(privacy.ScanFailure):
                self.read("fifo")
        read.assert_not_called()

    def test_directory_is_not_read_as_regular_file(self):
        (self.root / "folder").mkdir()
        with mock.patch.object(privacy.os, "read", side_effect=AssertionError("Must not read")) as read:
            with self.assertRaises(privacy.ScanFailure):
                self.read("folder")
        read.assert_not_called()

    def test_deleted_file_is_omitted_and_unsafe_paths_fail_closed(self):
        self.assertIsNone(self.read("missing.txt"))
        for path in ("", "../sample.txt", "/sample.txt", "folder/../sample.txt", "./sample.txt", "folder//sample.txt"):
            with self.subTest(path=path):
                with self.assertRaises(privacy.ScanFailure):
                    self.read(path)
        with self.assertRaises(privacy.ScanFailure):
            self.read(limit=-1)


if __name__ == "__main__":
    unittest.main()
