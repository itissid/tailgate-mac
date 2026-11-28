# No-fee local Tailgate review packages

`Scripts/package-local-review.sh` packages the **real `TailgateReview` executable**, not the synthetic Keychain probe. Its stable local identity is **`dev.tailgate.local-review`**, its bundle is `TailgateLocalReview.app`, and its display name is **Tailgate Local Review**. Command Line Tools are sufficient; this path needs neither paid Apple membership nor full Xcode, provisioning, notarization or a timestamp service.

This is **not a Developer ID release mode**. There is no team setting, provisioning profile, entitlement blob, private Keychain access group or installation step. The script generates a minimal local Info.plist rather than copying the production release plist. It does not modify `LiveController`, `MacTrust` or the UI. The offline fixture/review workflow remains in the executable; live windows remain present but their production controller must fail closed. `MacTrust` requires the different `dev.tailgate.mac` identifier, team, profile, Developer ID signature and root-owned `/Applications` deployment **before credential access**. A local signature cannot satisfy that contract. Do not enter real credentials into a review build or mistake offline Touch ID simulation approval for authorization of a live operation.

## Trust boundary and prerequisites

A human operator reviews and supplies all pins. Neither an archive's embedded commit comment nor a JSON record authenticates its origin. Obtain the **full commit ID and SHA-256 of the exact archive independently**, review that repository snapshot, and retain the pins separately from the artifact. Do not calculate a new pin merely to silence a mismatch. Never run this script from an unreviewed archive: invoke the separately reviewed packaging script.

Use an **ordinary non-sudo caller**. Setuid/setgid mismatches, root and sudo-origin environments are rejected before input reads. Use absolute canonical paths, private existing parents (mode 0700), and user-owned input files (mode 0600). Input files must be bounded, regular and single-link. Symlink components, writable ancestors and extended ACL entries are rejected; input reads walk directory descriptors with no-follow opens and validate the final file descriptor before reading; only root-owned sticky `/private/tmp` is an exception for parent write bits. Privileged application/system configuration paths are not accepted. The tool checks ACL metadata but never changes ACLs, trust, ownership, an installation or a Keychain search list.

Prepare these inputs **outside agent access**:

- For staging: a reviewed **uncompressed `git archive --format=tar`** with its full commit comment, without a path prefix; the independently retained SHA-256 and full commit ID. No working-tree files, `.build` products, git hooks or archive shell scripts are executed. All archive entries are checked for traversal, duplicates, links and special files. Only `Package.swift` and Swift files under `Sources/`, `Tests/TailgateCoreTests/` and `Tests/TailgateLiveTests/` are extracted into a fresh private directory. SwiftPM requires the test-target sources to validate the manifest, but this script never runs `swift test`. The current dependency/plugin-free `Package.swift` has a fixed SHA-256 allowlist in the script. A changed manifest needs a packaging-code review, not an override flag. This also prevents dependency resolution/fetching or plugin execution from being introduced through a changed manifest. The Swift package manifest is executable Swift; its exact allowlisted bytes are part of the reviewed trust boundary.
- Only for explicit signing or verification: the selected identity's exported **public DER certificate**, its independently reviewed SHA-256, and its exact lowercase 40-hex certificate SHA-1 identity selector. Never pass a private key/export, password, token, provisioning file or credential path. One complete DER certificate is required, with code-signing usage; Apple/Developer ID certificates are rejected. SHA-1 is used only for macOS identity selection and its certificate requirement syntax; artifact and public-certificate content pins use SHA-256.
- Only for signing: an existing compatible local code-signing identity held in the **fixed dedicated** `$HOME/Library/Keychains/Tailgate Signing.keychain-db`, where HOME means the caller's account-database home, not an environment override. The script has no alternate keychain flag, identity enumeration, default identity, automatic key selection or ad-hoc fallback. The keychain file must be user-owned/private with protected ancestors. Human setup/unlocking, certificate compatibility and any authorization prompt are outside this tool. Never grant an agent key access or choose **Always Allow** merely to make packaging succeed.

There is deliberately no certificate creation/import/unlock, password input, `security` invocation, trust-store adjustment, key export, ACL/partition-list adjustment or keychain discovery. The script reads only the explicitly supplied public DER; it checks the fixed keychain's **metadata**, not its file contents. On `--sign`, `/usr/bin/codesign` necessarily uses the selected private key through macOS. As documented by `codesign --keychain`, macOS still consults the normal Keychain search path when constructing the embedded public certificate chain, even though identity selection is restricted to the dedicated file. It may also consult normal trust infrastructure; this tool is not a sandbox or an assertion that the OS reads no other keychains/trust stores. `--verify` never selects or accesses the signing keychain and never signs. Missing/locked/unusable identity or a denied authorization is failure, not permission to try another identity.

## 1. Stage: build only, no certificate or signing

Prepare a private directory and the archive in the trusted operator context. Example archive preparation uses the reviewed repository and an explicit commit, not the mutable checkout:

```sh
git -C /path/to/reviewed-repository archive --format=tar \
  --output=/private/path/review/source.tar REVIEWED_FULL_COMMIT
chmod 600 /private/path/review/source.tar
# Independently review/retain the archive pin and full commit before proceeding.
```

The following is an actual build, **not a dry run**. Replace uppercase placeholders with independently reviewed pins:

```sh
/bin/sh Scripts/package-local-review.sh --stage \
  --archive /private/path/review/source.tar \
  --archive-sha256 REVIEWED_ARCHIVE_SHA256 \
  --commit REVIEWED_FULL_COMMIT \
  --output /private/path/review/stage-one
```

`--stage` rejects *all* signer/certificate/artifact options. It does not open a certificate/keychain, invoke codesign, install or launch an app. Compilation may emit a normal linker ad-hoc Mach-O seal; this is **not certificate-backed signing**. Source, scratch, caches, temporary home and output assembly are private and fresh. The build uses the standard CLT command:

```text
/usr/bin/swift build --disable-automatic-resolution --scratch-path <private> -c release --product TailgateReview
```

A separate matching `--show-bin-path` query finds that same scratch build, never the checkout's `.build`. Absolute tool paths and a minimal environment select `/Library/Developer/CommandLineTools`; inherited compiler, loader, proxy and SDK overrides are not passed through. The allowlisted manifest has no external dependencies. There is no dependency install, fetch, timestamp, notarization or service call in this workflow. This is not OS-level network containment for arbitrary malicious source: only review and the archive/manifest pins authorize the compiler inputs.

On success stdout is bounded JSON with `status: staged-local-review`, `artifact_sha256`, `installed: false`, `live_enabled: false`. **Retain `artifact_sha256` independently**. The new private directory contains exactly the app and `local-review.json` (archive/commit/manifest pins, toolchain version, executable and immutable-payload hashes). It is not installed, launched or approved for live use.

## 2. Sign: separate explicit human key use

Review the staged artifact and retain its pin before authorizing the signing action:

```sh
/bin/sh Scripts/package-local-review.sh --sign \
  --artifact /private/path/review/stage-one \
  --artifact-sha256 RETAINED_STAGE_TREE_SHA256 \
  --identity EXACT_LOWERCASE_CERTIFICATE_SHA1 \
  --certificate /private/path/review/public.der \
  --certificate-sha256 REVIEWED_PUBLIC_CERTIFICATE_SHA256 \
  --output /private/path/review/signed-one
```

Staging and signed outputs must be different, **new** destinations. There is no automatic transition from staging to signing. Before any key use, the script checks the exact staged tree pin, closed bundle layout, local plist, record, full unsigned executable hash, immutable Mach-O payload hash, public certificate content pin and identity selector. It refuses a preexisting certificate-backed stage signature. Only then does an explicit codesign operation use the fixed dedicated keychain, exact identity, hardened runtime, SHA-256 digests and `--timestamp=none`. `--force` replaces only the reviewed unsigned/linker-ad-hoc input; it is not fallback authorization.

The independently constructed designated requirement is:

```text
identifier "dev.tailgate.local-review" and certificate leaf = H"EXACT_LOWERCASE_CERTIFICATE_SHA1"
```

After signing, strict all-architecture signature validation tests this requirement, and the displayed DR must match it. The extracted leaf certificate must match the exact public DER bytes. Hardened/non-ad-hoc flags, absent team, local identifier, no entitlements, and the closed bundle layout are checked. The plist must be byte-identical; the executable's non-signature payload must be unchanged. The Mach-O comparison supports thin native arm64/x86_64 executables, normalizing only signature storage/load-command bookkeeping, `__LINKEDIT` file/VM sizes and up to 15 zero alignment bytes. Unsupported formats or unexpected layout changes fail closed. It is not a disassembler or a general-purpose Mach-O verifier; the native strict signature check is also required.

The original staged tree is read and checked **again** after signing. Publication reserves a new directory, writes only allowed files, and rechecks its complete content tree pin. Success is `signed-local-review` with a **new signed-artifact pin**, never a statement that Gatekeeper, live credentials or Keychain continuity passed. Failure returns `rejected` without raw diagnostics, paths or certificate subjects. A partially written output is incomplete evidence, not a release; do not run it or reuse the destination.

## 3. Verify without signing

Use the retained **signed**, not stage, tree pin and the same independently reviewed public signer inputs:

```sh
/bin/sh Scripts/package-local-review.sh --verify \
  --artifact /private/path/review/signed-one \
  --artifact-sha256 RETAINED_SIGNED_TREE_SHA256 \
  --identity EXACT_LOWERCASE_CERTIFICATE_SHA1 \
  --certificate /private/path/review/public.der \
  --certificate-sha256 REVIEWED_PUBLIC_CERTIFICATE_SHA256
```

Verification accepts no output or source options, performs no build or signing, and never opens/selects the dedicated keychain. It validates a private copy and rechecks the original. It requires the signed manifest's signer/DR to match the explicit public inputs and verifies the full binary and package pin. No mode installs or launches anything. A new process that needs a key operation always requires a fresh explicit `--sign` invocation.

## Reproduction, checks and limits

This makes the **procedure and provenance reproducible**, not a bit-for-bit reproducible compiler/signature claim. Retain the exact archive/pins, script revision, manifest pin, CLT/SDK/macOS versions and architecture. Fresh Swift builds can embed different private paths or compiler metadata, and signatures can differ. Do not expect a rebuild to inherit a previous artifact pin: review, stage and verify each new artifact. A same-signer DR does not prove Keychain continuity or grant a production unlock.

The tree pin is SHA-256 of canonical compact JSON (sorted keys plus newline) mapping each relative filename to its SHA-256. It includes the app binary, plist, record and, for signed packages, CodeResources. Filesystem metadata is validated separately, not included in this content pin. A self-contained manifest is not an external trust root. Same-user processes can replace private files; mode/ACL checks do not isolate an agent running as the operator. Keep source review, public-pin custody and signing in the trusted operator context, away from agents and concurrent mutators.

Offline boundary tests:

```sh
/usr/bin/python3 -B -m unittest discover -s Tests/Privacy -p test_local_review_package.py -v
/bin/sh -n Scripts/package-local-review.sh
```

Tests use synthetic archives and structural Mach-O fixtures with **mocked** compiler, x509 and signing responses. They test mode separation, privileged-caller refusal, no-tool early rejection, source/manifest/certificate/artifact pins, protected paths, no keychain discovery, signer/DR/entitlement mismatch, tampering, post-sign immutable-payload checks and publication refusal. They never access a real keychain, key, trust configuration or credential; they never build or launch the app. These tests cannot establish actual CLT build compatibility, certificate usability, real signature/DR encoding, Gatekeeper acceptance, offline UI rendering/Touch ID behavior or MacTrust runtime denial. Those require separate human-controlled acceptance. Packaging alone must not be reported as any of those passes. The app is visually unverified by these checks.

No mode offers Developer ID, provisioning, live enablement, installation, app launch, trust changes or notarization. Use the separate reviewed production process for production releases; do not convert a local review artifact into one by copying it into `/Applications`.
