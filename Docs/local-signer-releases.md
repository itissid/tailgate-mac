# Reuse one operator-controlled identity across dummy builds

Certificate Assistant is a **one-time identity setup**, not a step for every refactor. A release build whose code changed must be signed again, using the existing identity. A stable signer and designated requirement can let Keychain recognize an approved update; this still needs the same-signer upgrade control, not an assumption that every build inherits access.

This page and `Scripts/package-local-probe.sh` package **only the synthetic Keychain probe**, not a live Tailgate release. They neither disable Developer ID checks nor provision real API credentials. The current app remains gated pending separate credential, signing-key, journal, update and biometric acceptance. Do not enter OAuth secrets into a dummy app.

## What the operator supplies

- An existing **macOS-compatible code-signing identity**, chosen by its explicit 40-hex certificate fingerprint, and that identity's exported **public DER certificate**. Never supply a private-key export or its password. The selector is the SHA-1 value macOS uses to select an identity; executable signatures and content verification use SHA-256. No default identity, display-name lookup or ad-hoc fallback is accepted.
- A frozen, reviewed copy of `Experiments/LocalKeychain/Probe.swift` and `Info.plist`. The script requires an independently reviewed SHA-256 of the source, not just a path supplied by an agent.
- A private, operator-controlled directory to hold build inputs and outputs. The directory must be mode 0700, with no symlink components or group/world-writable ancestors (a root-owned sticky temporary parent is the sole exception). Input files must be bounded, regular, single-link files; extended filesystem ACL entries are rejected rather than interpreted. Even a benign inherited ACL can require choosing a different protected staging directory. Ordinary POSIX ownership does **not** isolate files from another process with that same user ID; keep the agent away from the signing identity and perform release review in the trusted operator context.

The operator must control whether and when the signing identity is used. Never teach an agent to authorize arbitrary code with that identity. Do not blindly choose **Always Allow** for a signing-key dialog: permission to use a release key has consequences beyond this experiment. The script does not grant `/usr/bin/codesign` permanent access or adjust any item ACL.

## Dry input check, then explicit signing

Run as the ordinary operator in the dedicated disposable account used for dummy acceptance, not under `sudo`. Prepare a private directory containing `reviewed/Probe.swift`, `reviewed/Info.plist` and an exported public `signer.der`; create the private output parent separately. Use actual absolute paths in place of the uppercase placeholders:

```sh
/bin/sh Scripts/package-local-probe.sh --check \
  --identity CERTIFICATE_SELECTOR_40_HEX \
  --certificate /private/path/signer.der \
  --source-root /private/path/reviewed \
  --probe-sha256 REVIEWED_SOURCE_SHA256 \
  --output /private/path/outputs/version-one --version 1
```

`--check` only reads those explicitly selected source/certificate files, checks their shapes, hashes and path protections, and refuses an existing destination. It does **not** verify that the public bytes form a usable signing identity or that a private key exists. It does not run a compiler, Keychain command, signature operation, GUI, network call or test app. Its success says `inputs-checked-only`, not signed or accepted.

After independently reviewing those exact inputs, replace **only** `--check` with **`--sign-reviewed-dummy`** to compile and sign. That command is an explicit human signing action and can require macOS authorization. It builds a private clean source snapshot; it never consumes cached `.build` output. It uses `codesign --timestamp=none` with SHA-256 content digests, no entitlements or trust modifications, and no notarization or install step.

`codesign` necessarily consults the selected user's signing identities, and may consult the normal Keychain search list while building a chain. This script makes **no promise of signing without Keychain reads**, and has deliberately not been run against an operator's real signing identity by an agent. Missing private key, unsupported certificate, invalid trust or a denied prompt is a setup failure—not evidence of credential isolation. The tool never creates certificates, trusts roots, changes search lists, asks for a keychain password on stdin, or installs software.

## High-signal update control

Build version two using the **same** identity, certificate and reviewed source, with these replacements:

```text
--output /private/path/outputs/version-two
--version 2
--previous /private/path/outputs/version-one
```

The two bundles deliberately have different `CFBundleVersion` values **and different executable code**: an exported dummy-only `tailgate_probe_build_version` function returns 1 or 2. The second package is accepted only when independently verifying both signed apps finds the same exact certificate, bundle identifier and designated requirement, a hardened non-ad-hoc signature, previous version 1, and a different authenticated executable hash. The prior JSON manifest is not trusted as evidence of those facts.

The script uses `codesign`'s native designated requirement, verifies it, and compares its exact text across versions. It rejects a requirement tied to `cdhash` (one binary), or one with no certificate/anchor clause. The native requirement may contain macOS certificate hashes; the script does not treat the supplied 40-hex identity selector as the content-integrity proof. It extracts the signed leaf certificate and matches its **SHA-256** against the operator-supplied public certificate.

Outputs are new private directories containing `KeychainProbe.app` and a local `verified-dummy-package.json`. The record contains public signer and executable hashes, the designated requirement, and build version; do not commit actual operator identities or build artifacts. Failures yield only a bounded `rejected` result. A partially published directory has no completion claim and must not be run or silently reused.

**This proves packaging consistency only, not Keychain continuity.** The decisive test still provisions a dummy item for version one, proves version two can read it without altering the access rule, then proves a valid differently signed app cannot. Both positive controls must succeed; missing items or signing failures are inconclusive. Coordinate these packages with the [dummy Keychain experiment](../Experiments/LocalKeychain/README.md). Use its opt-in `--update-fixtures` mode for the same-signer update control; a successful packaging check by itself cannot pass that test.

## Verification boundary

Offline tests exercise input protections, no-tool dry checks, redacted failure, exact signer comparison, hardened flags and simulated update requirements. Compiling two synthetic probe versions verifies that the version marker changes executable bytes; no operator private key, Keychain item, certificate-signing action, app launch, Touch ID or network is needed for that compilation. A compiler-generated ad-hoc Mach-O seal is not a certificate-backed signing result or acceptance evidence. Real code signing, same-signer Keychain continuity, alternate-signer denial and any production use require human-run acceptance. No test grants a production unlock.
