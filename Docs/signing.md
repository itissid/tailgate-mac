# Building the trusted Mac app

The development executable is intentionally **not** a trusted credential holder. `MacTrust()` fails before using Keychain unless the process is an installed, root-owned, Developer ID–signed, hardened, non-debug app with the exact private Keychain entitlements below. Code signing can be performed with Command Line Tools; full Xcode is not required for the build.

## Human prerequisites

1. Use your Apple Developer account to register the explicit App ID `dev.tailgate.mac`. Prepare a **Developer ID Application** signing certificate and a matching **Developer ID distribution provisioning profile** that authorizes the app's private Keychain access group. Protect the signing key from agents; do not let an agent arbitrarily sign replacement builds. A personal ad-hoc identity or a development profile is not accepted for live mode.
2. The machine needs Apple Silicon/T2 Secure Enclave and enrolled Touch ID. The signature key is P-256, nonexportable, device-only, and protected with `privateKeyUsage` plus `biometryCurrentSet`. Adding/removing enrolled fingerprints invalidates its authorization. There is no automatic key replacement or password fallback.
3. Obtain the team ID and the profile from Apple yourself. These are build inputs, **not OAuth credentials**. The profile and signing certificate are not committed here. The packaging command will request access to the selected signing identity through macOS. Timestamping contacts Apple's service.

## Package, notarize, install

From the repository root, substitute your own signing identity, team ID and profile path:

```sh
Scripts/package-app.sh \
  'Developer ID Application: Your Name (YOURTEAMID)' \
  YOURTEAMID /path/to/distribution.provisionprofile dist
```

The script checks the profile's explicit app ID, team, distribution type, keychain authorization and expiration; builds the release executable; embeds the profile; substitutes team values into the tracked plist templates; signs with hardened runtime; and checks the code seal. It refuses to overwrite an existing output bundle. It never reads OAuth credentials, installs, or launches the app. Profile decoding and a successful local signature check are not a substitute for Apple's runtime profile validation or notarization.

Use your independently configured Apple notarization credential profile (never an OAuth secret):

```sh
ditto -c -k --keepParent dist/Tailgate.app dist/Tailgate.zip
xcrun notarytool submit dist/Tailgate.zip --keychain-profile YOUR_NOTARY_PROFILE --wait
xcrun stapler staple dist/Tailgate.app
spctl --assess --type execute --verbose=2 dist/Tailgate.app
```

Have an administrator install the reviewed app, without merging an older bundle. Quit any existing instance first. The following is a **human-run** example for a fresh installation (it deliberately refuses an existing destination):

```sh
sudo test ! -e /Applications/Tailgate.app && \
  sudo ditto dist/Tailgate.app /Applications/Tailgate.app
sudo chown -R root:wheel /Applications/Tailgate.app
sudo chmod -RN /Applications/Tailgate.app
sudo chmod -R a+rX,go-w /Applications/Tailgate.app
codesign --verify --deep --strict --verbose=2 /Applications/Tailgate.app
open /Applications/Tailgate.app
```

Do not execute these commands blindly if another Tailgate app already exists. Root ownership, absence of writable group/world permissions and ACLs, and no symlinks are checked recursively on launch. Developer ID signature requirement, exact private access-group entitlement, app sandbox, network-client entitlement, user-selected-read-only entitlement and debugger absence are also checked. The only file-access entitlement is `com.apple.security.files.user-selected.read-only`: the human chooses a local `.tailgate` proposal using `NSOpenPanel`. There are no ambient-home reads, automatic imports, file-write entitlements or broad filesystem permissions. The app accepts no extra signing entitlements, including debugger access, disabled library validation, shared application groups or unsigned executable memory. The normal sandbox container remains writable for UI state, but it cannot replace root-owned code or grant another process the private access group.

## What Keychain stores

All items use the **Data Protection Keychain**, `WhenUnlockedThisDeviceOnly`, no synchronization, and access group `TEAMID.dev.tailgate.mac`. The service is `TEAMID.dev.tailgate.mac.authority-v1`.

| Account | Purpose and update rule |
|---|---|
| `configuration` | One atomic UI-provisioned configuration document including the OAuth credentials. **Create-only**. A second setup cannot substitute a credential under an existing process or approved plan. |
| `receipt` | Mutable sanitized reconciliation receipt; callers must keep tokens, bearer keys and raw HTTP payloads out of this slot. |
| `signing-public-key-v1` | First-use pin for the Secure Enclave public key. Never silently updated. Existing key without pin, or pin without key, fails closed. |
| `intent-active-v1` | One fixed **atomic cross-process lock** containing request UUID and digest. `SecItemAdd` permits only one holder. |
| `intent-UUID` | Immutable digest history prevents reuse of the same request ID, including after restart. |
| `intent-result-UUID` | Immutable `applied`, `rejected` or `unknown` outcome. Unknown does not release the active lock. |

Only `configuration` and `receipt` are exposed by `store`/`load`. Missing items throw `MacTrustError.missing`; inaccessible/corrupt store is an error, not “not configured.” Reserve a write intent **before any write-capable network call**. On a definite `applied` or definite no-write `rejected` result, record the outcome then release the active lock; a crash or unknown result remains blocked. `unresolvedDigest()` permits read-only reconciliation but grants no lock-clearing operation. Never classify a timeout or an ambiguous server response as rejected. Merely restarting the app or reprovisioning cannot unlock the journal.

The credential-bearing app verifies the plan signature against the pinned public key and checks deadline, exact target, operation, policy version and single-use identifier before using a token. Touch ID authenticates a user for the local enclave operation. Tailscale sees an OAuth token, **not** the enclave public key or biometric proof. A stolen OAuth credential bypasses this local gate; Keychain access isolation, signed code integrity and the release process remain trusted assumptions.

## Credential rotation and recovery

There is deliberately **no generic delete/reset API** and no hidden “clear journal” switch. The current configuration slot cannot be overwritten.

If credentials need rotation, first revoke the old OAuth client in Tailscale's admin console; this stops its future token issuance, though already-issued tokens must also be accounted for according to Tailscale's revocation behavior. Do not assume revocation repaired an uncertain write. Check the authoritative tailnet state using read-only access and compare the retained receipt/digest. An unknown intent continues to block writes.

Rotation then requires a separately reviewed, signed maintenance release under the same app identity that (a) refuses any active unresolved intent, (b) replaces only the `configuration` item under explicit human approval, and (c) preserves the signing pin, per-ID history and outcome journal. That maintenance flow is **not provided by this release**. Never instruct an agent to delete all app Keychain items, create a different app identity to escape a lock, or replace the pin to make recovery appear successful. An unresolved write requires explicit human reconciliation and a separately reviewed recovery procedure; this release intentionally stops rather than guessing.

## Verification limits

The source and release plist templates can be checked with Command Line Tools. A development-process rejection can be tested without any Keychain mutation. Success on actual Developer ID provisioning, signed installation, sandbox permissions, biometric hardware, durable Keychain concurrency and key invalidation requires a human-controlled signed deployment. These have not been claimed as verified by unit tests or a source build.
