# Local signer / legacy Keychain learning test

This is a **dummy-only experiment**, not a new Tailgate authority implementation.

## Hypothesis and falsifier (before execution)

Hypothesis: a legacy, file-based Keychain item whose secret-read ACL names one valid,
self-signed app identity can be read without UI by that identity, while an app with
**the same name and bundle ID but a different valid signer** cannot read it without
UI. A second item authorizing the second signer is the positive control.

The hypothesis is falsified by an unauthorized successful read, or by failure of
an intended reader. Invalid signatures, failed setup, locked stores, missing
items, and inability to sign are **inconclusive**, not a successful denial test.
An `errSecInteractionNotAllowed` result means noninteractive access was denied;
it is not a claim that a person cannot subsequently override a legacy ACL.

## What was and was not run

The default command is safe to run in a developer account:

```sh
Experiments/LocalKeychain/run.sh --offline
```

It compiles the helper into a private temporary directory, checks the deterministic
result classifier, and performs no Keychain or certificate operation. It does not
prove the hypothesis. Temporary files are cleaned up.

The certificate-backed signer experiment has **not** been run in the operator's
normal account. On the installed macOS, `man codesign` explicitly states that
`--keychain` restricts signing-identity lookup but still consults the user's normal
Keychain search list while constructing the certificate chain. Therefore using
that option alone cannot meet the task's prohibition on reading login/system
Keychains. Creating a file Keychain may also affect that account's search-list
state; this experiment does not assume creation is side-effect-free.

The default preflight:

```sh
Experiments/LocalKeychain/run.sh --preflight
```

reports `blocked` and exits 3 before generating signer material or touching
Keychain. This is the expected honest result under the current strict constraints.
There is no ad-hoc-signature fallback and no conversion of a setup error into PASS.

## Human-only next step: isolated dummy fixture preparation

Use a disposable macOS VM or a dedicated throwaway macOS user with **no personal
Keychain items, credentials, identities or Apple account**. Do not use the normal
operator account. Preparing fixtures there is a separate explicitly human-approved
activity: standard signing tools may consult that isolated account's Keychain
search list. Do not add certificates to trusted roots or change trust settings.
Do not enroll in Apple's paid program for this experiment.

1. Run `--offline` first. Read the helper source and freeze its revision.
2. In that isolated environment, create a private temporary directory (mode 0700).
   Use the manual commands below to compile one helper and copy it into two
   identical app structures, `a/KeychainProbe.app` and `b/KeychainProbe.app`.
   Both must have executable `KeychainProbe` and bundle identifier
   `dev.tailgate.local-keychain-probe`.
3. Generate two **throwaway lab** RSA signing keys and self-signed certificates,
   with synthetic random common names, code-signing extended key usage, and no
   personal subject fields. Keep their private material only in the isolated
   temporary directory. Create/import into explicit temporary **file Keychains**;
   do not import into login/System, change trusted roots, or permit all apps to
   use a key. Only the installed `/usr/bin/codesign` should be authorized to use
   each lab signing key. If signing requires changing personal/system state,
   an unrestricted key ACL, interactive authorization, a trusted-root setting,
   or weakening signature validity, **stop**. Do not call that a denial PASS.
4. Sign A and B with different lab certificates using explicit certificate hashes,
   the respective explicit lab signer Keychain, `--timestamp=none`, and hardened
   runtime. Do not use `--sign -` or the same certificate twice. Never export or
   reuse a real signing identity. This fixture setup is intentionally manual;
   the repository supplies no command which imports a key into the normal user's
   Keychain or changes trust/search lists.
5. Prepare a third explicit private temporary **file Keychain** for the dummy
   items, unlocked with a random lab-only password. Put the lab password in a
   mode-0600 file in the temporary root, `password.bin`; place 32 random dummy bytes
   in `dummy.bin`. Neither value is an OAuth secret. The test runner never asks
   for a password, reads a login Keychain, or makes a network request.
6. Run the fixture driver, giving that directory and the two signed app paths:

   ```sh
   TAILGATE_DISPOSABLE_LAB=1 Experiments/LocalKeychain/run.sh \
     --fixtures LAB_ROOT A_APP B_APP DUMMY_KEYCHAIN
   ```

   The driver verifies both signatures with explicit leaf-certificate requirements
   and network disabled, verifies matching app/bundle names and different leaf
   fingerprints, provisions two items with single-app secret-read ACLs, then runs
   both positive controls and both cross-identity reads. Each helper disables UI
   for its own process and supplies the explicit file Keychain on every operation.
   A missing/corrupt/malformed item or failed signature/control is not a denial.
7. After recording only the redacted result, remove the entire disposable user/VM.
   Destroy all lab keys, private Keychain files and dummy material. The driver does
   not delete or reset any real Keychain. Nothing from the temporary fixture root
   belongs in Git, a ticket, CI artifacts or chat.

Helper compilation and app layout (from the repository root; `LAB_ROOT` below
stands for your new private, canonical absolute temporary directory):

```sh
swiftc -O -suppress-warnings -framework Security \
  Experiments/LocalKeychain/Probe.swift -o LAB_ROOT/KeychainProbe
mkdir -p LAB_ROOT/a/KeychainProbe.app/Contents/MacOS \
  LAB_ROOT/b/KeychainProbe.app/Contents/MacOS
cp LAB_ROOT/KeychainProbe LAB_ROOT/a/KeychainProbe.app/Contents/MacOS/KeychainProbe
cp LAB_ROOT/KeychainProbe LAB_ROOT/b/KeychainProbe.app/Contents/MacOS/KeychainProbe
cp Experiments/LocalKeychain/Info.plist LAB_ROOT/a/KeychainProbe.app/Contents/Info.plist
cp Experiments/LocalKeychain/Info.plist LAB_ROOT/b/KeychainProbe.app/Contents/Info.plist
```

Use `A_APP=LAB_ROOT/a/KeychainProbe.app` and
`B_APP=LAB_ROOT/b/KeychainProbe.app` after replacing all placeholders. Setting
`TAILGATE_DISPOSABLE_LAB=1` is an operator attestation, **not isolation** and not a
way to make fixture preparation safe in the normal account.

The helper's `--self-test` exercises result classification only. `--fixtures`
requires the complete, already prepared fixture; it does not silently generate or
trust replacement certificates. All dynamic error payloads, paths, certificate
names, fingerprints and dummy bytes are withheld from stdout/stderr. It returns a
small JSON summary with numeric OSStatus where relevant, never the credential.

## Opt-in: does a same-identity code update retain access?

This is an additional **unexecuted acceptance procedure**, not a conclusion that
Tailgate's no-fee deployment works. Certificate Assistant creates a signing
identity once; each changed build still needs its own signature. This test asks
whether keeping that identity and designated requirement stable lets a new build
read the existing dummy item without recreating an identity, changing its ACL,
or reprovisioning OAuth. No real OAuth credentials participate.

Supply **already signed** fixtures in an isolated lab account/VM:

- `A1_APP`: the original `KeychainProbe.app` containing this helper.
- `A2_APP`: a genuinely recompiled version of the helper with a meaningful code
  change (for example, an extra executed self-test assertion), signed with the
  **same exact certificate** as A1. Merely changing a plist, resource, timestamp,
  signature options or executable filename is not sufficient. Both builds must
  support the same `--read` protocol; A1 must support `--seed-update`.
- `B_APP`: the helper signed by a different valid certificate and public key,
  with the same app name and bundle identifier as A1/A2.
- An existing, empty private dummy Keychain, plus private `password.bin` and
  `dummy.bin` as described above. Use fresh dummy items for this run; duplicate
  setup is inconclusive, not an update of existing items.
- Independently reviewed SHA-256 fingerprints of the exact leaf certificate for
  A and B: 64 lowercase hexadecimal digits, obtained from the lab certificates,
  not derived automatically from whichever app happens to be at the path.

Run, after substituting the fixture paths and fingerprints:

```sh
TAILGATE_DISPOSABLE_LAB=1 Experiments/LocalKeychain/run.sh \
  --update-fixtures LAB_ROOT A1_APP A2_APP B_APP DUMMY_KEYCHAIN PIN_A PIN_B
```

All three apps must live at **different private paths** beneath `LAB_ROOT`, with
separate regular executable files (no hardlinks) and final name
`KeychainProbe.app`. Executables must be user-only readable/executable (mode 0700),
like the mode-0600 dummy files. Neither a same-path overwrite nor an ACL amendment
is performed by this driver. A2 reading an item seeded for A1 **at a different
pathname** is the stronger control against success attributable only to retaining
a previously trusted path. A failure at a different path is inconclusive for an
in-place update; this test does not claim to cover atomic installation, app
replacement, all macOS releases or code-requirement migration.

Before touching the dummy items, the verifier requires valid explicit
certificate-pinned signatures for all apps, the common bundle identifier, the
same pinned certificate/public key for A1/A2, a distinct pinned B identity,
different executable **CDHashes** and different compiled `__TEXT,__text`
instruction-section SHA-256 hashes for A1/A2, and identical serialized designated
requirements. Byte-identical requirements are a conservative sufficient condition
for equivalence; logically equivalent requirements encoded differently are
rejected as inconclusive. The code parser supports only bounded thin 64-bit,
same-architecture Mach-O executables. Fat/unrecognized executables or
resource-only changes are invalid fixture setup, not an access-denial PASS.
Different instruction bytes are evidence of a code change, not proof that the
operator chose a useful change or that an updated app is safe.

The driver seeds A's item using **A1 only** and B's using B, never adds A2 to an
ACL, then performs these noninteractive reads against the same explicit store:

| Order | Read | Required result |
|---|---|---|
| 1–3 | A1 → A item; A2 → A item; B → B item | All return the exact dummy bytes |
| 4–6 | B → A item; A1 → B item; A2 → B item | Each is denied with a recognized authorization status |
| 7–9 | Repeat all three positive reads | All still return the exact dummy bytes |

Signature/code/requirement controls are rechecked afterward. The helper never
prints dummy bytes or dynamically trusts a new identity. A passing redacted
summary has `stage: "update-identity-acl"` and
`update_access_observed: true`. `update-fixtures-missing` is **blocked** (supply the
existing signed fixtures; the driver never creates an identity);
`update-fixtures-invalid`, signature failures and broken positive controls are
**inconclusive**. An unexpected successful cross-read is **failed**. No failure
is solved by broadening the ACL, changing trust settings or switching to ad-hoc
signing. Fixture source and paths must remain frozen during the run.

The offline self-test also checks the instruction-section parser with synthetic
bytes (instruction change differs, header-only change does not, invalid bounds
reject). Those checks and mocked Python sequencing tests are **not** observations
of real signed-app or Keychain enforcement. Even a real PASS establishes only
this dummy credential/update experiment, not fresh biometrics, the enclave key,
journal freshness or a secure installation/signing-key custody process. Keep the
signing key out of the untrusted agent's control; a stable identity intentionally
extends trust to future builds signed by that identity.

## Limits

- The legacy APIs are deprecated; availability and behavior must be observed on
  the target macOS, not inferred from headers or this successful compilation.
- This experiment tests app-identity ACL behavior, **not Touch ID**. A legacy item
  ACL is not the same thing as biometric protection. Separate acceptance must
  prove the Secure Enclave signature operation requires a fresh touch, cancel
  prevents the protected operation, and public-key pinning survives restart.
- Same-user software able to read a file-Keychain's password can override its
  protection. A trusted app may also be compromised in-process. Do not weaken
  code integrity or substitute a mutable app-name check for signature identity.
- There is no Gatekeeper/notarization claim, no deployment, no real OAuth data,
  no real Tailscale operation, and no claim that the production app now supports
  self-signing. The Developer ID release path remains unchanged.
