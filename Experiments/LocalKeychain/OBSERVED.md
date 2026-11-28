# Observed result

## On-device follow-up — locally signed, dummy data only

Using the probe from revision `71a51e4`, two real builds (v1 and v2) were signed with the same operator-controlled certificate. Both had the same bundle ID and explicit certificate-pinned designated requirement, different signed code hashes, and different machine instructions. All reader processes had Keychain UI disabled. No live OAuth credentials or Tailscale API were involved.

- **Initial read:** A fresh file-based Keychain held one random dummy item with its read rule naming v1. The signed v1 app returned success only after comparing all retrieved bytes with the test oracle.
- **Update:** In a new temporary store, the fixture added one item for v1, then ran v1 → v2 → v1 against the unchanged item. All three reads returned success without a prompt, at distinct bundle paths for the two versions.
- **Negative control:** A different, ad-hoc-signed build with the same name and bundle ID had a separate item in the same fresh fixture. Both apps read their own item before and after the cross-reads. Neither app read the other’s item (`errSecAuthFailed`, −25293). This specifically tests an ad-hoc copy, not a copy signed using the operator’s release key, and not a second trusted certificate.
- **Cleanup:** The fixture Keychains and dummy values were removed; the user Keychain search-list snapshot matched the original after testing.

These observations are evidence for *noninteractive access to these file-based dummy items*, not proof of Secure Enclave behavior, resistance to journal rollback, protection against misuse of the signing key, or authenticated live Tailscale operations. A separate clean build of the review app was signed and verified for local offline review only; it was not given the production app identity or a Keychain entitlement.

## Earlier offline-only run

Run in the development account, without signing identities, certificate imports,
Keychain creation/opening/reads/writes, trust settings, search-list changes, GUI
prompts, administrator privileges, or network access.

## Commands actually run

```text
bash -n Experiments/LocalKeychain/run.sh
# exit 0

plutil -lint Experiments/LocalKeychain/Info.plist
# Info.plist: OK

Experiments/LocalKeychain/run.sh --offline
# {"signer_isolation_observed":false,"stage":"compile-and-classifier","status":"offline-checks-passed","version":1}
# exit 0

Experiments/LocalKeychain/run.sh --preflight
# {"signer_isolation_observed":false,"stage":"codesign-may-consult-user-search-list","status":"blocked","version":1}
# exit 3

python3 -B -m unittest discover -s Tests/Privacy -p test_local_probe.py -v
# Ran 10 tests ... OK

python3 Scripts/check-public.py
# 0 findings

git diff --check
# exit 0
```

The offline command compiled the actual Swift helper and ran its deterministic
error classifier. The Python tests exercise the control/denial matrix, malformed
results, safe fixture paths, preflight no-I/O behavior, and redacted CLI output.
An initial classifier test failed because an inconsistent success/error pair was
labeled a failure instead of inconclusive; ordering was fixed and the complete
focused suite then passed. This is a harness correction, not evidence about
Keychain enforcement.

## Limits of the earlier offline-only run

**Signer isolation was not observed in that earlier run.** No certificate-backed A/B binaries were signed
or exercised. No actual dummy-item read/write was done, because no existing
isolated fixture was supplied and search-list-neutral creation was not established.
The installed `codesign` man page says its explicit `--keychain` still consults
the normal search list during certificate-chain construction. Running it in the
normal account would exceed the agreed no-personal-Keychain-read scope.

The fixture driver is therefore an unexercised human-run procedure for an
explicitly isolated dummy account/VM, not a green production acceptance result.
It cannot enable self-signing in Tailgate, certify per-use biometrics, or establish
that a legacy file Keychain is equivalent to a provisioned Data Protection group.
No live credential should be provisioned based on these offline results alone.
