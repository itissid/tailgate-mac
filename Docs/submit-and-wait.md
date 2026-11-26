# Agent-initiated submit and wait

A local agent can request a human review without manually browsing for a file:

```sh
Scripts/tailgate-submit --wait < Examples/browser.tailgate
```

Use a **previously configured, Developer ID–signed, root-installed** `/Applications/Tailgate.app`. The wrapper never selects a development executable, accepts a caller's executable path, or falls back to `swift run`. Before launch it checks root ownership, no symlinks, restrictive permissions, the exact bundle/executable names and Developer ID code-sign requirement. The installed app repeats its stricter trust checks before Keychain use. Signing, protected access-group configuration, and OAuth provisioning remain human-controlled prerequisites in [signing.md](signing.md).

## Flow

1. The wrapper starts exactly `/Applications/Tailgate.app/Contents/MacOS/TailgateReview --submit-and-wait`, with a minimal fixed environment and the proposal on stdin. No secret is put in argv, a file, an environment variable, or a local server.
2. A dedicated native window reads one frame with a five-second input deadline and a strict size cap. It shows the purpose as **unverified agent text** and the proposal as plain text. This stage has no Keychain, OAuth, validation request or biometric prompt. No normal workbench or setup window is available in this mode.
3. A human clicks **Review with my existing setup…**. Only then can the verified app read its existing local configuration, retrieve the policy and inventory, and validate the compiled full candidate. Missing configuration is rejected; this agent-launched window never asks for credentials.
4. The human inspects the full request and separately clicks **Approve this exact write with Touch ID…**. The same signed, short-lived, single-use approval and durable journal as the normal live window guard the write.
5. The app emits one bounded JSON receipt and exits. The wrapper validates the schema and exit status before forwarding a newly generated sanitized JSON record. It never forwards arbitrary stdout, stderr, HTTP diagnostics, policies, device names, hashes or identifiers.

The wrapper serializes normal submissions with a per-user nonblocking local lock. The UI refuses another running Tailgate instance; quit the regular operator app before invoking it. This is launch coordination, not an authorization token: an untrusted same-user agent can interfere with availability, but cannot bypass the app's trusted biometric gate or atomic write journal.

## Machine-readable result

Example confirmed policy application:

```json
{"version":1,"status":"applied","write_outcome":"applied","enrollment":"not_confirmed"}
```

| Status | `write_outcome` | Meaning |
|---|---|---|
| `declined` | `not_attempted` | Human closed/declined before execution, or biometric signing was declined. |
| `rejected` | `not_attempted` | Invalid input, unavailable verified installation/configuration, failed read/validation, unsupported operation, or a definite pre-write refusal. |
| `expired` | `not_attempted` | Five-minute human session limit elapsed before execution started. |
| `stale` | `not_applied` | The reviewed policy/inventory changed, or Tailscale rejected the conditional write with 412. |
| `applied` | `applied` | Controller confirmed the exact policy application. No key issuance or enrollment is implied. |
| `unknown` | `unknown` | Execution may have started; outcome is not confirmed. Stop and reconcile; do not retry automatically. |

Exit codes: **0** for `applied`, **2** for declined/rejected/expired/stale, **3** for unknown. `enrollment` is always `not_confirmed`. Waiting for VM enrollment is deliberately not bundled into this command; policy application is not device enrollment or connectivity proof.

**No receipt means UNKNOWN, never “nothing happened.”** SIGKILL, crashes, caller disconnect, output pipe closure or wrapper failure may prevent any receipt. Malformed/multiple/oversized stdout or an inconsistent exit status becomes `unknown`. Closing or timing out after the execution stage begins also returns `unknown`, even if the write had not yet reached Tailscale. The wrapper has a six-minute outer bound, detects parent termination, and never retries; cancellation cannot undo a request that the remote service may already have received. During an ambiguous submitted write the durable journal remains the authority for later read-only reconciliation.

The agent should report `unknown` to the human and stop. It must not re-run the command, manufacture a fresh approval ID, change the requested operation, or invoke a fallback API. Any legitimate later attempt requires a fresh human review after reconciliation.

## Limits and verification

The receipt helps the local agent coordinate; it is not an attested remote credential or a trusted audit proof. The agent controls its own displayed output. Trust the signed app's UI and the authoritative Tailscale state, not text a caller claims the app produced.

Offline tests cover the lifecycle, interruption semantics, one terminal receipt, bounded framing, JSON schema, wrapper parsing and environment filtering without launching the installed app. Native rendering, command-line launch of the signed sandbox app, Keychain access, Touch ID, UI-close behavior during a real POST, and live policy outcomes still need the human-controlled [acceptance checks](acceptance.md). No secret-bearing or hardware path is certified by these tests.
