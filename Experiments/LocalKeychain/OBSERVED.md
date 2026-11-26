# Observed result

## Scope

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

## What remains unobserved

**Signer isolation: NOT OBSERVED.** No certificate-backed A/B binaries were signed
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
