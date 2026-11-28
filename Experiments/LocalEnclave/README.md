# Local Secure Enclave acceptance probe — human only, dummy only

**Not a Tailgate authority implementation. NEVER unlocks production.** This
standalone experiment is not a package target, does not import TailgateLive, and
changes no existing live gate. No OAuth, Tailscale, network, credential provisioning,
Keychain item APIs, certificate imports, trust settings, or code-signing operations are
implemented. Do not provision real credentials based on its output.

## Hypothesis and falsifier

On **one physical Mac** (Apple Silicon or supported T2, enrolled Touch ID), can an
app signed with an existing **private self-signed code-signing certificate**, with
**zero entitlements and no provisioning profile**, create a Secure Enclave P-256
signing key, save its enclave-wrapped representation in a local file, restore the
same public key, and sign the exact dummy challenge using a fresh touch?

The access control is explicitly `WhenUnlockedThisDeviceOnly` plus
`[.privateKeyUsage, .biometryCurrentSet]`. No Apple private access group, Data
Protection Keychain access group, `userPresence`, passcode, companion/watch, software
key, legacy-Keychain key alternative, or automatic key replacement is supplied.

A create/restore/sign error is **blocked/inconclusive**, not successful denial or
proof that paid enrollment is necessary. A valid signature without a new touch,
a password-authorized signature, a changed-message verification success, or a
changed key accepted under the old pin falsifies the intended behavior. Stop; do
not weaken flags/entitlements or substitute a software key to obtain green output.

## Actual SDK investigation (offline)

Inspected the installed **macOS 15.5 SDK** from Command Line Tools, with Swift
6.1.2, on arm64. These are declarations/documented contracts, not observations of
real enclave enforcement:

- `CryptoKit.framework/Modules/CryptoKit.swiftmodule/arm64e-apple-macos.swiftinterface`,
  `SecureEnclave.P256.Signing.PrivateKey` (available macOS 10.15):
  ```swift
  public let publicKey: P256.Signing.PublicKey
  public let dataRepresentation: Data
  public init(dataRepresentation: Data, authenticationContext: LAContext? = nil) throws
  public init(compactRepresentable: Bool = true,
              accessControl: SecAccessControl = /* default */,
              authenticationContext: LAContext? = nil) throws
  ```
  The default access control is **not biometric**; this probe never uses it.
  Creation and restore support a supplied context; neither initializer accepts
  an access group. This is the supported CryptoKit wrapped-key path, not a
  `SecKeyCopyExternalRepresentation` export of an enclave private scalar. The
  opaque representation is device-bound encrypted/wrapped key material, **not
  plaintext private-key bytes**. Keep it private nonetheless. There is no attempt
  to parse the blob or assert its binary format.
- `Security.framework/Headers/SecAccessControl.h`: `privateKeyUsage` applies the
  control to private-key operations (including signing); `biometryCurrentSet`
  requires enrollment and invalidates access when fingers are added/removed.
  `userPresence` explicitly permits passcode, so is not an equivalent substitute.
- `LocalAuthentication.framework/Headers/LAContext.h`: the biometrics-only policy
  fails on unavailable/unenrolled/locked-out Touch ID; the broader
  `deviceOwnerAuthentication` permits password and is **not used**. An empty
  `localizedFallbackTitle` hides the fallback button; **that UI setting alone
  does not enforce the access-control policy**. Reuse duration zero disallows
  reuse of a previous lock-screen biometric unlock. That property specifically
  concerns lock-screen reuse, not all possible framework caching. A new context
  per operation and `invalidate()` afterward are also required here; fresh-touch
  enforcement still needs human observation, especially on immediate repeats.

Canonical Apple references (links for operator review; not fetched in this
network-free session):
[Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[CryptoKit SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave),
[Signing PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey).
SDK availability and the absence of an access-group parameter do **not** establish
that a self-signed app will succeed on the target OS. In particular, any
`errSecMissingEntitlement` (`-34018`) or other creation failure must be recorded,
not worked around. There is no observed entitlement impossibility yet: **the
signed real-device probe has not been run**.

## Offline build and checks (safe for an agent)

From the repository root, build outside the tree. These commands do not run any
Secure Enclave API, inspect its availability, create `LAContext`, access Keychain,
or prompt for Touch ID. The compiler/linker may apply normal platform ad-hoc
linker signing; no operator identity is used and the resulting CLI is deliberately
ineligible for hardware commands.

```sh
CHECK_DIR=$(mktemp -d /private/tmp/tailgate-enclave-offline.XXXXXX)
xcrun swiftc -typecheck -warnings-as-errors Experiments/LocalEnclave/main.swift
xcrun swiftc -O -warnings-as-errors -target "$(uname -m)-apple-macos12.0" \
  -framework CryptoKit -framework LocalAuthentication -framework Security \
  Experiments/LocalEnclave/main.swift -o "$CHECK_DIR/LocalEnclaveProbe"
"$CHECK_DIR/LocalEnclaveProbe" --self-test
plutil -lint Experiments/LocalEnclave/Info.plist
```

`--self-test` is deterministic and filesystem-free: exact 111-byte challenge and
SHA-256, static public ECDSA test vector, correct/changed-message verification,
wrong/substituted/malformed pin, corrupted/malformed signature, all eight
acceptance boolean combinations, and state round-trip/version/size/shape failures.
The vector uses the intentionally public scalar/nonce 1; it is **only a public-key
verification fixture**, never a signing key in the probe. No key generation,
randomness, or Secure Enclave call occurs in this path. It is not a mock hardware
PASS.

## Human preparation — not performed by the agent

Freeze/review these three source files first. Use only dummy local state. Have an
existing private self-signed code-signing identity ready; protect its private key
from agents. If it does not exist, stop and arrange a separately approved human
signer-setup procedure. This experiment supplies no import/create/trust commands.
Never add the certificate to trusted roots, change Keychain search lists, or grant
an unrestricted signing-key ACL to make this work.

Build an app with the executable above at
`LocalEnclaveProbe.app/Contents/MacOS/LocalEnclaveProbe` and this `Info.plist` at
`Contents/Info.plist`. Example layout, **operator only**, for a new private staging
directory (`LAB` is an existing private absolute directory):

```sh
APP="$LAB/LocalEnclaveProbe.app"
mkdir -p "$APP/Contents/MacOS"
cp "$CHECK_DIR/LocalEnclaveProbe" "$APP/Contents/MacOS/LocalEnclaveProbe"
cp Experiments/LocalEnclave/Info.plist "$APP/Contents/Info.plist"
# HUMAN ONLY, later: existing exact identity, hardened runtime, no entitlements.
# SIGNER_SHA1 is the independently known existing signing identity fingerprint.
codesign --sign "$SIGNER_SHA1" --options runtime --timestamp=none "$APP"
codesign --verify --strict --verbose=2 "$APP"
```

No ad-hoc fallback, `--deep`, custom entitlements, sandbox/group entitlement, or
embedded profile. Signing may consult the human account's Keychains and request
approval to use its signing identity; that is a **separate human prerequisite**,
not something the probe or agent performs. No notarization/Gatekeeper claim is
made; do not disable Gatekeeper or other security settings. If normal launch is
blocked, record the blocker.

Obtain `CERT_SHA256` independently from the DER bytes of the known certificate
(e.g. `shasum -a 256 operator-reviewed-certificate.der`), not by automatically
trusting whatever certificate a candidate app embeds. It is exactly 64 lowercase
hex digits, with no separators/newline. The app checks its bundle ID, full code
seal, running-code requirement, hardened/non-ad-hoc signature, one pinned leaf
certificate, absence of a profile and absence of **all** entitlements. It uses an
explicit certificate requirement, not an Apple trust-root requirement, and does
not enable signature-verification network access. Pinning the signer is a local
fixture guard, not proof of app isolation or a trusted installation.

## Minimal first acceptance: one fresh touch

Operator, from Terminal in the foreground, after reviewing the signed artifact:

```sh
# NEW_STATE_DIR must NOT exist. Use a canonical absolute path, no symlinks,
# e.g. a new enclave-run-1 beneath your canonical private LAB (not /tmp).
TAILGATE_LOCAL_ENCLAVE_HUMAN=1 \
  "$APP/Contents/MacOS/LocalEnclaveProbe" --probe "$NEW_STATE_DIR" "$CERT_SHA256"
```

This is the single opt-in probe invocation, with **one expected biometric action**:

1. Verify the independently pinned signed app before any enclave/context call.
2. Require `SecureEnclave.isAvailable` and enrolled Touch ID. Create a new 0700
   directory; no existing directory/state is reused by `--probe`.
3. With a no-UI creation context, create the enclave key with the explicit flags;
   persist only wrapped bytes and X9.63 public bytes in create-only, fsynced
   `state.json` (0600). Creation must not ask for authentication. If it does need
   UI, the command stops rather than adding a second prompt/weakening protection.
4. Release the original key/context, read the actual saved file, restore with a
   **new** context, compare restored public bytes to saved bytes and pin, and call
   `signature(for:)` on exactly the fixed challenge. No `evaluatePolicy` pre-auth,
   no reuse of the creation context, no password credential or fallback call.
5. **You observe a new Touch ID prompt and touch once.** The restored key must sign;
   public-key verification must succeed for the challenge and fail for the same
   bytes with an appended `00` byte. No signature/blob is printed.

Exact challenge, UTF-8/ASCII, LF after **every** line, no NUL:

```text
TAILGATE / LOCAL ENCLAVE ACCEPTANCE / v1
DUMMY ONLY; NEVER AUTHORIZE PRODUCTION
operation=sign-fixed-challenge
```

Length 111; SHA-256
`52abaf62434899ebfa422f63d77bd6e174b2030344db1be24fd9a60156404dce`.
There is no caller-supplied message/file/production plan interface.

A successful run emits one JSON line with `status: "signature-observed"`,
`stage: "restore-sign-fresh-touch"`, and `public_key_sha256` (SHA-256 over the
65-byte X9.63 public key), exits 0. Record that public pin separately for subsequent
runs. First-run pinning is explicit first-use trust, **not hardware attestation**.
The JSON cannot know that a person saw/touched a prompt. If no fresh touch occurred,
record acceptance as **failed** even if the signature verified.

## Exact CLI and failure interface

```text
--self-test
--probe   NEW_STATE_DIR CERT_SHA256
--restore STATE_DIR     CERT_SHA256 PUBLIC_KEY_SHA256
--no-ui   STATE_DIR     CERT_SHA256 PUBLIC_KEY_SHA256
```

All except `--self-test` require `TAILGATE_LOCAL_ENCLAVE_HUMAN=1` and the signed app.
The environment flag is an operator attestation, **not a security boundary**. No
arguments, unknown/malformed arguments, or absent opt-in exit 3 before any signer,
hardware, context or filesystem work. Paths must be canonical absolute paths with
no symlink aliases. Existing state must remain an owned 0700 directory, containing
an owned, single-link, regular 0600 `state.json`, bounded to 64 KiB. State JSON has
`version: 1`, `wrapped` and `publicKey` (Foundation Codable base64 Data). Treat this
schema as experiment-only, not a supported production storage format.

`--restore` reads only: no creation/replacement/write, compares the operator's
independently retained public pin **before** trying to restore/sign, and requires a
new context/touch. It works in a new process, allowing a restart acceptance test.
`--no-ui` is the same operation with `interactionNotAllowed = true`; **never run it
from an agent**, even though it requests no UI. It must fail to produce a signature.
An unexpected successful verified signature emits
`failed-unexpected-no-ui-signature`, exits 3. A `blocked` result alone is not a
passing denial control: a missing file, corrupt blob, bad pin, unavailable device,
or broken positive control proves nothing about authorization.

All thrown errors emit `status: "blocked"`, the last fixed `stage`, fixed
`error_kind`, and numeric `error_code`, exit 3. `error_code` is an OSStatus only
when `error_kind == "osstatus"`, an LAError code only for `local-authentication`;
CryptoKit/other NSError bridging codes must not be interpreted as OSStatus.
No dynamic error description, credential, path, certificate subject, wrapped blob
or signature is logged. The public pin is included if already known, even on a
later failure, so cancellation does not require recreation. A partial create/save
failure may leave an unusable private directory/file; it is retained, never
repaired/overwritten automatically. Stop and inspect privately. No delete/reset
command is provided. Invalidate contexts on exit; no retries, software/password
fallback, automatic pin changes, or automatic key replacement.

Every JSON result has `production_unlocked: false` and
`hardware_acceptance_complete: false`, even after a valid signature. There is no
result file/flag consumed by Tailgate. Nothing in this experiment broadens the
Developer ID/access-group/install/journal/live-write gates.

## Operator acceptance still required

Keep only redacted result/status, source revision, macOS/hardware version, signer
and public-pin provenance, and human observations; never attach `state.json` or
signer private material to Git/tickets/chat. In order:

- First `--probe`: create without entitlement/profile, save/read/restore same key,
  one visibly fresh Touch ID, no password, exact-message success/changed-message
  failure. Failure at creation/restore may be an actual entitlement/platform
  limitation; capture stage/code and stop. Do not label it a hardware denial PASS.
- **Process restart**: run `--restore` with the retained pin, and again immediately;
  each must require a fresh touch, including just after lock-screen Touch ID.
  Same pin must survive process and Mac restart. No-touch signature is a failure.
- **Cancellation**: run `--restore`, click Cancel (do not touch). Must return blocked
  with no signature-observed result; immediately repeat the positive control with
  a fresh touch. Do not enter a password if the OS unexpectedly offers one.
- **No-UI denial**: bracket `--no-ui` with successful `--restore` positive controls
  on unchanged state/pins. Confirm an authorization/interaction denial, not merely
  a generic error. No signature, no fallback, and the same pin must remain usable.
- **Pin/blob tamper**: a wrong external public pin must fail before restore; a
  deliberately corrupted *copy* of the wrapped state with the original external
  pin must fail, never generate a replacement. Preserve the original privately
  for the positive control; this probe does not edit it for you.
- **Enrollment change** (separate, explicitly approved human activity; potentially
  disruptive): changing enrolled fingerprints must make the original key unusable
  under its existing pin, not create a new key. The SDK contract is not a performed
  invalidation test. No enrollment/system-state change is part of the minimal run.

The first invocation intentionally does not automate this multi-step human matrix
or claim a completed acceptance based on a single touch. Test the actual signed
build/OS; a VM/CI/mock is not a replacement for biometric hardware. CLI prompt
presentation and no-UI creation are themselves unverified until the operator run.

## Checks actually run in this change / residual gaps

- `xcrun swiftc -typecheck -warnings-as-errors Experiments/LocalEnclave/main.swift`:
  passed on CLT/macOS 15.5 SDK.
- Optimized `swiftc` command above: built successfully; built CLI `--self-test`:
  `offline-checks-passed`, exit 0.
- Built CLI exercised with no arguments, unknown option, and each hardware command
  **without** the human opt-in, plus three malformed opted-in invocations: all
  eight blocked at `arguments`, exit 3, no stderr.
- `plutil -lint Experiments/LocalEnclave/Info.plist`: OK.
- `python3 Scripts/check-public.py`: zero findings after replacing a synthetic
  home-directory example rejected by the repository's absolute-user-path rule.
- `git diff --no-index --check /dev/null FILE` for each of these three new files:
  no whitespace findings (exit 1 denotes the new-file diff; checked with a wrapper
  accepting that status only with empty output). Project-wide integration/production
  tests were not run; this standalone experiment has no production linkage.

No enclave API (even `isAvailable`), Touch ID prompt, Keychain/trust operation,
operator signing, live OAuth/Tailscale operation, or commit was performed by the
agent. No app was rendered; prompt/UI behavior is **visually unverified**.

Even a completed operator matrix would show only this local dummy key experiment.
The wrapped file has no demonstrated app-identity ACL/access-group isolation:
same-user software might copy it and request its own biometric operation. POSIX
permissions and self-signer pin checks are not an agent-resistant credential store,
rollback protection, enclave attestation, policy-review UI, replay journal, secure
installation/signing-key custody, or production authorization. The existing
LocalKeychain experiment addresses a different ACL question and supplies no proof
of these biometric properties. Production no-fee support remains blocked pending
separately reviewed authority/storage/isolation and complete acceptance work.
