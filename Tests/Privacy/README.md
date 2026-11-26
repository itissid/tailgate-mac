# Publication privacy gate

Run from the repository root before every publication:

```sh
python3 -B -m unittest discover -s Tests/Privacy -v
python3 -B Scripts/check-public.py
```

The default scan covers **every commit reachable from all local Git refs**, including author/committer identities and messages, historic and deleted versions of tracked files, tracked filenames, annotated tag identities/messages and tag names, the full staged index, and nonignored working-tree files. The GitHub workflow checks out full history before scanning. No source or matches are uploaded to an external scanning service.

To audit the locally known published snapshot separately:

```sh
python3 -B Scripts/check-public.py --ref refs/remotes/origin/main --history-only
```

This command does not fetch. An up-to-date remote-tracking ref is required to make claims about the current public branch. It cannot inspect previously downloaded forks, third-party caches, or unknown remote refs. A new commit deleting a file does not remove it from history; any real published credential must be revoked and the repository history remediated separately.

## What is rejected

- Private email addresses; reviewed synthetic example domains and public GitHub noreply identities are allowed. Commit/tag display names must be the corresponding public GitHub handle or a neutral project identity. Use a neutral project identity for future commits.
- Absolute user-home paths, the scanning host's observed hostname, tailnet IP ranges and nonexample Tailscale DNS names.
- Recognizable private keys, certificates, Tailscale OAuth/auth/API credentials, common GitHub/cloud tokens, long bearer values, and credential-bearing URLs or assignments.
- Sensitive local configuration, signing/profile files, build artifacts, nontext blobs, symlinks, Git LFS pointers and submodules. LFS/submodule contents are not silently treated as scanned.

Findings contain a category and a safe relative path or a hashed path label, **never the matched value**. Exit code `0` means no findings in the scanned scope, `1` means findings, and `2` means the scan was incomplete and publication must stop. Shallow history, unresolved index entries, unsupported repository input and size limits fail closed.

The gate uses Python's standard library. Default limits are 8 MiB per object/file, 256 MiB of scanned blob/worktree bytes, 10,000 commits and 100,000 unique historical/index file entries. Historical/index contents are deduplicated by Git object identity.

Hostname discovery reads only the kernel hostname and local macOS configuration, never forward/reverse DNS or mDNS resolution. Worktree reads walk descriptor-relative directories with no-follow opens, then validate and read the same regular-file descriptor. The final open is nonblocking so a substituted FIFO cannot hang the scan. Each read is capped at the validated size plus one sentinel byte; growth, truncation, or changed file metadata makes publication fail closed. This is per-file defensive reading, not an atomic snapshot of the entire repository: freeze changes and rerun the scan immediately before publication.

## Synthetic data and limitations

There is one narrow source exception: the existing compiler rejection-test selector-list line in `PolicyTests.swift` and `LiveCompilerTests.swift` uses a single reviewed synthetic CGNAT input. That exception does not apply to metadata, arbitrary test files, other addresses or other lines. New negative tests should construct token-shaped inputs from clearly synthetic fragments rather than embedding credential-shaped literals. Tests never contain real secrets or personal identifiers.

This is a bounded heuristic publication check, **not a guarantee that arbitrary PII or secrets cannot be present**. It does not recognize every human name, hostname of another machine, provider token format, encoded secret or sensitive configuration schema. The local hostname check is a runtime observation, not a personal hostname committed as a scanner needle; CI knows only the CI host. It does not scan ignored, untracked local files because they are not publication candidates; forced staged files are still scanned. Freeze the index and run again immediately before pushing, review the diff, and keep the repository free of real configuration. No CI run provisions credentials, touches Keychain, invokes Touch ID, or changes a tailnet.
