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
