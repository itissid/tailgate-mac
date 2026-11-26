# Operator acceptance: from source to a live pilot

Do not treat a green test run as a signed release, a successful Touch ID operation, or a live tailnet check. Record observations privately. Do not open public issues with device names, node keys, account IDs, ETags, provisioning profiles, OAuth data, or policy dumps.

## Before credentials

- Review the source and dependency manifest at a fixed Git commit. Build and run the offline tests and demo. Try an invalid file and an expired/discarded review. Neither may perform a real operation.
- Use an independent trusted operator account/build path for release signing. Follow [signing.md](signing.md) to obtain a Developer ID Application identity and the matching Developer ID provisioning profile for this exact app ID and private Keychain group. If that identity/profile is missing, stop here: an ad hoc signature is not a substitute.
- Verify bundle signature, entitlements, Gatekeeper acceptance and root-controlled installation. Launch the workspace build and check that Live activation is rejected. Never enter live credentials in an untrusted build.

## Pilot in a dedicated tailnet only

- Separately authorize the target, one destination tag, source, exact TCP/UDP ports and VM. Verify that the existing policy fits the supported subset; **do not overwrite or weaken production policy to fit this app**. Provision narrowly scoped, distinct OAuth clients according to [api-contract.md](api-contract.md). The approval app is an additional local guard, not a Tailscale server-side restriction.
- Obtain the VM's public node-key pin over an independently authenticated operator channel. Check that this VM can supply a pin before completing browser enrollment; if it cannot, stop. Setup is a one-time local action in the verified app; do not paste credentials into a terminal or chat with an agent.
- Import a synthetic `.tailgate` file. Verify that import alone did not call Tailscale or prompt Touch ID. Press Review. Verify the target, stated untrusted purpose, full diff, tests, method, path, ETag and exact candidate. Check in the admin console that validation alone made no change.
- On a fresh plan, cancel the biometric prompt; confirm the policy was not written and the cancelled review cannot be replayed. With separate authorization, change the test policy between review and apply; confirm the stale review cannot overwrite it. Be prepared for an unresolved lock on any ambiguous response. Never test crashes/timeouts on a production tailnet.
- For a separately approved pilot write, approve one review. Compare the applied policy and authoritative audit record. Verify an unchanged review cannot be used again. Confirm the policy approval did not mint a key or enroll a machine.
- Complete the browser sign-in on the independently pinned VM, then explicitly check enrollment. A different device with the same name or tag must never count. Network policy tests do not prove application-level connectivity. Confirm expected connectivity separately, within the authorized pilot.
- Test read-only reconciliation. A matching policy hash indicates **observed state**, not who applied it. Unknown outcomes require authoritative investigation. Never delete an active lock, blindly resend or automatically roll back. If trust, credential scope, receipt state or enrollment proof cannot be established, stop and retire/revoke the pilot clients through an independently authenticated admin session.

## Evidence labels

- **Offline-tested:** automated tests with generated examples/fake transport and signer.
- **Operator-verified:** only the steps actually observed with the installed signed app and intended pilot tailnet.
- **Not supported:** generic tailnet policies, unrestricted endpoint execution, live key issuance, automatic remediation or unlocking ambiguous writes.
