#!/usr/bin/env python3
"""Local, stdlib-only publication gate. Findings never contain matched text.

Default scope: all refs' complete commit history, annotated tags, staged index,
and nonignored worktree files. This is a bounded heuristic gate, not proof of the
absence of personal data or secrets. It makes no network requests. Run before
publishing; historical findings require history remediation, not a new deletion.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import sys
from dataclasses import dataclass

MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_COMMITS = 10_000
MAX_ITEMS = 100_000
MAX_COMMAND = 32 * 1024 * 1024
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")
PUBLIC_MAIL = re.compile(r"(?:[0-9]+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com\Z", re.I)
EXAMPLE_DOMAINS = {"example.com", "example.org", "example.net", "example.invalid", "localhost.invalid"}
HOME_PATH = re.compile(r"(?:/(?:Users|home)/[^\s/\"'<>]+|[A-Za-z]:[\\/](?:Users)[\\/][^\s\\/\"'<>]+)", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TAILNET_DNS = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*)\.ts\.net\b", re.I)
SYNTHETIC_DNS_LABELS = {"example", "demo", "sample", "test", "fixture"}
SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("certificate", re.compile(r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----")),
    ("oauth-token", re.compile(r"\btskey-(?:api|auth|client|oauth)-[A-Za-z0-9_-]{12,}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("cloud-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9_~+/.=-]{24,}", re.I)),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b")),
    ("credential-url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.I)),
    ("assigned-secret", re.compile(r"(?i)\b(?:client_secret|oauth_secret|access_token|refresh_token|password)\b[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_+./=-]{20,}[\"']")),
)
FORBIDDEN_SUFFIXES = {".p12", ".pfx", ".p8", ".pem", ".key", ".cer", ".crt", ".der", ".mobileprovision", ".provisionprofile", ".keychain", ".keychain-db", ".ipa", ".dmg", ".pkg", ".dSYM", ".app"}
FORBIDDEN_COMPONENTS = {".build", ".swiftpm", ".pi", "DerivedData", "node_modules", ".env", ".aws", ".ssh", ".gnupg", "Secrets", "secrets", "credentials", "__pycache__", "xcuserdata"}
FORBIDDEN_NAMES = {"credentials.json", "credentials.yaml", "credentials.yml", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_ed25519", "id_ecdsa", ".DS_Store", ".gitconfig", ".netrc", ".npmrc", ".pypirc", ".authinfo"}
NEUTRAL_IDENTITIES = {"github", "tailgate", "tailgate contributors", "tailgate automation", "fixture", "github-actions[bot]", "dependabot[bot]"}


class ScanFailure(Exception):
    """Intentionally carries only static, non-sensitive error categories."""


def git(repo: Path, *args: str, limit: int = MAX_COMMAND) -> bytes:
    # Never inherit credential helpers for a network operation: there are no network
    # commands. Disable optional locks and replacement objects for consistent history.
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
    with subprocess.Popen(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=env) as proc:
        assert proc.stdout is not None
        data = proc.stdout.read(limit + 1)
        if len(data) > limit:
            proc.kill()
            proc.wait()
            raise ScanFailure("command-output-limit")
        try:
            status = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise ScanFailure("git-timeout") from None
        if status:
            raise ScanFailure("git-command-failed")
        return data


def local_hostnames() -> set[str]:
    """Use runtime observations, never commit a user's hostname as a search needle."""
    names = {socket.gethostname(), socket.getfqdn()}
    if sys.platform == "darwin":
        for key in ("ComputerName", "LocalHostName", "HostName"):
            try:
                value = subprocess.run(["/usr/sbin/scutil", "--get", key], capture_output=True,
                                       timeout=3, check=False).stdout.decode("utf-8", "replace").strip()
                if value:
                    names.add(value)
            except (OSError, subprocess.TimeoutExpired):
                pass
    result = set()
    for name in names:
        if name and name.casefold() not in {"localhost", "localhost.localdomain"}:
            result.add(name.casefold())
            if name.endswith(".local"):
                result.add(name[:-6].casefold())
    return {n for n in result if len(n) >= 5}


def content_categories(data: bytes, hosts: set[str]) -> set[str]:
    text = data.decode("utf-8", "replace")
    categories = set()
    for match in EMAIL.finditer(text):
        email = match.group(0)
        domain = email.rsplit("@", 1)[1].casefold()
        if not PUBLIC_MAIL.fullmatch(email) and not any(domain == d or domain.endswith("." + d) for d in EXAMPLE_DOMAINS) and not domain.endswith(".invalid"):
            categories.add("private-email")
    if HOME_PATH.search(text):
        categories.add("absolute-user-path")
    for match in IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if ip in ipaddress.ip_network((0x64400000, 10)) and str(ip) != "100.100.100.100":
            categories.add("tailnet-address")
    if re.search(r"(?i)\bfd7a:115c:a1e0:[0-9a-f:]", text):
        categories.add("tailnet-address")
    for match in TAILNET_DNS.finditer(text):
        if match.group(1).casefold().split(".")[-1] not in SYNTHETIC_DNS_LABELS:
            categories.add("tailnet-hostname")
    folded = text.casefold()
    if any(re.search(r"(?<![a-z0-9_-])" + re.escape(host) + r"(?![a-z0-9_-])", folded) for host in hosts):
        categories.add("local-hostname")
    for category, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            categories.add(category)
    return categories


def metadata_categories(data: bytes) -> set[str]:
    # A GitHub handle plus its noreply address is an intentional public identity.
    # Other display names require review rather than guessing whether they are PII.
    text = data.decode("utf-8", "replace")
    identities = re.findall(r"(?mi)^(?:author|committer|tagger|co-authored-by:|signed-off-by:)\s+([^\r\n<>]+)\s+<([^\r\n<>]+)>", text)
    for name, email in identities:
        public_handle = email.split("@", 1)[0].split("+", 1)[-1].casefold() if PUBLIC_MAIL.fullmatch(email) else None
        neutral_project = re.fullmatch(r"tailgate (?:maintainers?|contributors?|authors?|automation|team|project)", name.strip(), re.I)
        if name.strip().casefold() not in NEUTRAL_IDENTITIES and not neutral_project and name.strip().casefold() != public_handle:
            return {"unreviewed-display-name"}
    return set()


def is_text(data: bytes) -> bool:
    try:
        data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    return 0 not in data


def reviewed_fixture_bytes(path: str, data: bytes) -> bytes:
    # Existing rejection tests deliberately exercise one synthetic CGNAT address.
    # This exception applies only to the selector-list line in these two files,
    # not arbitrary test files, other addresses, metadata, paths, or secrets.
    if path not in {"Tests/TailgateCoreTests/PolicyTests.swift", "Tests/TailgateCoreTests/LiveCompilerTests.swift"}:
        return data
    ip = re.escape(".".join(map(str, (100, 64, 0, 1))).encode("ascii"))
    return re.sub(rb'(?m)^(\s*for src in \[[^\r\n]*)"' + ip + rb'"', rb'\1"synthetic-selector"', data)


def path_categories(path: str, hosts: set[str]) -> set[str]:
    parts = PurePosixPath(path).parts
    categories = content_categories(path.encode("utf-8", "surrogateescape"), hosts)
    if any(part in FORBIDDEN_COMPONENTS or part.endswith(".app") for part in parts):
        categories.add("sensitive-or-build-path")
    name = parts[-1] if parts else ""
    if name in FORBIDDEN_NAMES or name.endswith((".local.json", ".local.plist", ".log", ".xcuserstate")) or (name.startswith(".env.") and name not in {".env.example", ".env.sample"}):
        categories.add("sensitive-config-path")
    if PurePosixPath(name).suffix.casefold() in {x.casefold() for x in FORBIDDEN_SUFFIXES}:
        categories.add("signing-or-binary-path")
    if any(ord(c) < 32 or ord(c) > 126 for c in path) or "\\" in path:
        categories.add("ambiguous-path")
    return categories


def path_label(path: str, hosts: set[str]) -> str:
    if path_categories(path, hosts) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,180}", path):
        return "path-sha256:" + hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()[:16]
    return path


@dataclass(frozen=True, order=True)
class Finding:
    scope: str
    location: str
    category: str


class Scanner:
    def __init__(self, repo: Path, hosts: set[str] | None = None):
        self.repo = repo
        self.hosts = local_hostnames() if hosts is None else hosts
        self.findings: set[Finding] = set()
        self.total = 0
        self.objects: dict[str, bytes] = {}
        self.items = 0
        self.commits = 0
        self._seen: set[tuple[str, str, str]] = set()

    def inspect(self, data: bytes, scope: str, location: str) -> None:
        for category in content_categories(data, self.hosts):
            self.findings.add(Finding(scope, location, category))

    def blob(self, oid: str) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{40,64}", oid):
            raise ScanFailure("invalid-object-id")
        if oid not in self.objects:
            size = int(git(self.repo, "cat-file", "-s", oid, limit=64))
            if size > MAX_BLOB or self.total + size > MAX_TOTAL:
                raise ScanFailure("object-size-limit")
            data = git(self.repo, "cat-file", "blob", oid, limit=MAX_BLOB)
            self.total += len(data)
            self.objects[oid] = data
        return self.objects[oid]

    def file(self, oid: str, raw_path: bytes, scope: str, mode: bytes) -> None:
        path = raw_path.decode("utf-8", "surrogateescape")
        identity = (oid, path, scope)
        if identity in self._seen:
            return
        self._seen.add(identity)
        self.items += 1
        if self.items > MAX_ITEMS:
            raise ScanFailure("file-count-limit")
        label = path_label(path, self.hosts)
        for category in path_categories(path, self.hosts):
            self.findings.add(Finding(scope, label, category))
        if mode == b"160000":
            self.findings.add(Finding(scope, label, "submodule-not-scanned"))
            return
        data = self.blob(oid)
        if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
            self.findings.add(Finding(scope, label, "lfs-content-not-scanned"))
        if not is_text(data) or mode == b"120000":
            self.findings.add(Finding(scope, label, "binary-or-symlink-not-reviewed"))
        self.inspect(reviewed_fixture_bytes(path, data), scope, label)

    def history(self, ref: str | None = None) -> None:
        if git(self.repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ScanFailure("shallow-history")
        if ref:
            # Resolve to an object ID so even caller-controlled ref text cannot be a flag.
            tip = git(self.repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip().decode("ascii")
            rev_args = [tip]
        else:
            rev_args = ["--all"]
        commits = git(self.repo, "rev-list", *rev_args).splitlines()
        if len(commits) > MAX_COMMITS:
            raise ScanFailure("commit-count-limit")
        self.commits = len(commits)
        for raw_oid in commits:
            oid = raw_oid.decode("ascii")
            raw = git(self.repo, "cat-file", "commit", oid, limit=MAX_BLOB)
            self.inspect(raw, "history", "commit:" + oid[:12])
            for category in metadata_categories(raw):
                self.findings.add(Finding("history", "commit:" + oid[:12], category))
            for entry in git(self.repo, "ls-tree", "-r", "-z", oid).split(b"\0"):
                if not entry:
                    continue
                head, path = entry.split(b"\t", 1)
                mode, kind, blob_oid = head.split(b" ")
                self.file(blob_oid.decode("ascii"), path, "history", mode)
        # Lightweight tags' names and annotated tags' messages/taggers are covered too.
        tag_refs = git(self.repo, "for-each-ref", "--format=%(refname)", "refs/tags/").splitlines()
        for raw_ref in tag_refs:
            tag_ref = raw_ref.decode("utf-8", "surrogateescape")
            if ref is not None and tag_ref != ref:
                continue
            label = "tag-ref-sha256:" + hashlib.sha256(raw_ref).hexdigest()[:16]
            self.inspect(raw_ref, "history", label)
            oid = git(self.repo, "rev-parse", "--verify", "--end-of-options", tag_ref).strip().decode("ascii")
            while git(self.repo, "cat-file", "-t", oid).strip() == b"tag":
                raw = git(self.repo, "cat-file", "tag", oid, limit=MAX_BLOB)
                self.inspect(raw, "history", "tag:" + oid[:12])
                for category in metadata_categories(raw):
                    self.findings.add(Finding("history", "tag:" + oid[:12], category))
                first = raw.split(b"\n", 1)[0]
                if not first.startswith(b"object "):
                    raise ScanFailure("invalid-tag-object")
                oid = first[7:].decode("ascii")

    def index(self) -> None:
        for entry in git(self.repo, "ls-files", "--stage", "-z").split(b"\0"):
            if not entry:
                continue
            head, path = entry.split(b"\t", 1)
            mode, oid, stage = head.split(b" ")
            if stage != b"0":
                raise ScanFailure("unmerged-index")
            self.file(oid.decode("ascii"), path, "index", mode)

    def worktree(self) -> None:
        root = self.repo.resolve()
        paths = git(self.repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
        for raw_path in set(paths) - {b""}:
            path = raw_path.decode("utf-8", "surrogateescape")
            absolute = root / path
            if not absolute.exists() and not absolute.is_symlink():
                continue  # Deleted files remain covered by history/index.
            label = path_label(path, self.hosts)
            for category in path_categories(path, self.hosts):
                self.findings.add(Finding("worktree", label, category))
            if absolute.is_symlink() or not absolute.is_file():
                self.findings.add(Finding("worktree", label, "nonregular-file-not-scanned"))
                continue
            if not absolute.resolve().is_relative_to(root):
                raise ScanFailure("worktree-outside-root")
            size = absolute.stat().st_size
            if size > MAX_BLOB or self.total + size > MAX_TOTAL:
                raise ScanFailure("worktree-size-limit")
            data = absolute.read_bytes()
            self.total += len(data)
            if not is_text(data):
                self.findings.add(Finding("worktree", label, "binary-not-reviewed"))
            self.inspect(reviewed_fixture_bytes(path, data), "worktree", label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="local Git working tree (never printed)")
    parser.add_argument("--ref", help="limit historical scan to one local ref; no fetch")
    parser.add_argument("--history-only", action="store_true", help="omit index/worktree; useful for auditing a published ref snapshot")
    args = parser.parse_args(argv)
    try:
        root = Path(git(Path(args.repo), "rev-parse", "--show-toplevel").decode("utf-8", "surrogateescape").strip())
        scanner = Scanner(root)
        scanner.history(args.ref)
        if not args.history_only:
            scanner.index()
            scanner.worktree()
        for finding in sorted(scanner.findings):
            print(f"FAIL {finding.scope} {finding.location} [{finding.category}]")
        print(f"Privacy scan: {len(scanner.findings)} finding(s); {scanner.commits} commit(s); "
              f"{len(scanner.objects)} unique historical/index blob(s). Local refs only; no network.")
        return 1 if scanner.findings else 0
    except (ScanFailure, OSError, ValueError, UnicodeError):
        # Library exceptions can contain credential-bearing paths or raw subprocess data.
        print("Privacy scan incomplete; refusing publication (repository error or bounded scan limit).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
