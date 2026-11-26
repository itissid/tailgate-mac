# Tailgate for Mac

**Let an agent propose a Tailscale policy change. Keep the credentials, the diff, and the decision on your Mac.**

An agent can call Tailgate and wait: it submits a bounded `.tailgate` proposal on stdin and receives a status receipt. You don't run the command or locate a file. A manual file picker is also available. Submission alone does not contact Tailscale. When you choose **Review**, the trusted app compiles an allowed change, asks Tailscale to validate the full candidate, and displays the exact bytes it would send. Touch ID authorizes **that one request**, not a session in which the agent can make additional changes.

**Release status:** buildable source with an offline demo and a guarded live policy/browser-enrollment path. No pre-signed binary is distributed here. A regular `swift run` build cannot access the live credential store. Live deployment requires a Developer ID–signed, provisioned installation and human acceptance checks. **Live auth-key minting is disabled**, not silently substituted for browser enrollment.

## Try it without an account

Requires macOS 13+ and Swift 6.1+ (Apple Command Line Tools work; the full Xcode app is not needed to build or test). No external Swift package dependencies.

```sh
git clone https://github.com/itissid/tailgate-mac.git
cd tailgate-mac
swift build -c release
swift test --disable-xctest
swift run tailgate-preview --stdin < Examples/browser.json  # read-only, no prompt
swift run TailgateReview                                   # starts in offline mode
```

The offline example allows `tag:demo-client` → `tag:workload-demo-api` on **TCP 443** and tests that **TCP 22 and 80 remain denied**. The offline demo also models a separately approved key request and delivery failure without creating a bearer key. None of the demo, preview or automated tests needs OAuth or writes to a tailnet.

## Agent → human → Tailscale

```mermaid
sequenceDiagram
    participant Agent
    participant Mac as Signed Tailgate app
    actor You
    participant SE as Secure Enclave
    participant TS as Tailscale
    Agent->>Mac: Submit local .tailgate on stdin and wait
    Mac-->>You: Pending request (no automatic authentication)
    You->>Mac: Review this proposal
    Mac->>TS: Read policy + inventory; validate candidate (no policy write)
    Mac-->>You: Agent's unverified purpose, compiled diff, exact request
    You->>SE: Approve this review with Touch ID
    SE-->>Mac: Signature over the immutable review
    Mac->>Mac: Verify signature, freshness and single-use journal
    Mac->>TS: OAuth-authenticated POST with original If-Match
    TS-->>Mac: Applied, stale, or unconfirmed
    Mac-->>Agent: Redacted receipt; enrollment is separate
```

Once a trusted release is installed and provisioned, the **agent** runs:

```sh
Scripts/tailgate-submit --wait < Examples/browser.tailgate
```

If the conversation names a machine but doesn't include its selectors, the agent can run `Scripts/tailgate-lookup --name demo-runner --fields name,tags`. You see the exact response and approve its release with Touch ID; request `name,tags,ips` only if the agent also needs overlay addresses. An approved result goes to the requesting agent/session and may reach its model provider. No inventory dump, fuzzy match or policy write is available from lookup. The compiler accepts tag selectors, not raw IP grants. See the [device lookup contract](Docs/device-lookup.md).

See the [submission and receipt contract](Docs/submit-and-wait.md). A missing or `unknown` receipt is **not permission to retry**.

The **agent's words aren't policy**. Tailgate displays them as unverified context and signs the context together with the compiled operation. Never put a transcript, password, token, real device inventory, or personal information in the file. Start with [`Examples/browser.tailgate`](Examples/browser.tailgate) or the [agent handoff format](Docs/agent-handoff.md). No agent socket, chat integration, clipboard watcher, automatic file opener, or shell executor is required.

## What the live path will and won't do

| Situation | Result |
|---|---|
| Missing or overly broad policy, unknown fields, wildcard selector, existing destination tag | Refuses. Only a narrow [policy subset](Docs/policy-subset.md) is supported. It never replaces an incompatible policy with the demo baseline. |
| Candidate fails validation or a negative assertion | No write. Validation tests policy semantics, not packet delivery or VM health. |
| Review edited, discarded, expired, replayed, or policy ETag changed | Requires a new review. The writer uses the exact validated bytes with `If-Match`, never an unconditional POST. |
| POST times out, returns an unfamiliar success format, or the app crashes mid-write | Stops. A durable local lock blocks new writes. Reconcile is read-only, not “try again.” No automatic rollback. |
| Browser enrollment | A human signs in on the intended VM. The app checks the pinned node key, exact tag, authorization, and applied policy. It never logs in, retags, or enrolls another machine on your behalf. |
| Proposal requests an auth key | **Refused before applying policy in live mode.** Tailscale's policy ETag does not guard key issuance, a bearer key isn't VM-bound, and this project has no provisioned private receiver or verified 300-second API lifetime. No key-creation endpoint is implemented. |

**Trust model:** Tailscale authenticates an OAuth token; it does **not** verify the biometric signature. Locally the signed app verifies the signature against its pinned Secure Enclave public key. macOS restricts the Data Protection Keychain items to the signed application's private access group. The installed code, signing process, host and administrator remain trusted. A stolen token or compromised signed release can bypass this local gate. Tag freshness is checked against inventory, not guaranteed by a distributed lock against other administrators.

## Provisioning and verification

1. [Build, sign, notarize and install](Docs/signing.md) the trusted app. Keep signing and provisioning materials outside the repo and unavailable to untrusted agents. Do not loosen the runtime checks to get a development build working.
2. Use distinct, narrowly scoped reader/writer OAuth clients and an independent VM node-key pin. See the [API contract and scope table](Docs/api-contract.md) and [browser enrollment contract](Docs/enrollment.md). Enter credentials into the installed app's secure setup fields, **never** chat, shell, CI, a proposal, or GitHub.
3. In a dedicated test tailnet, use the [operator acceptance checklist](Docs/acceptance.md). Hardware authentication, production signing, actual server behavior, and successful enrollment are **not** certified by mock tests.

| Code | Responsibility |
|---|---|
| `Sources/TailgateCore` | Strict proposal compiler, handoff format, offline simulator |
| `Sources/TailgateLive` | Code identity, Keychain, biometric signing, pinned API origin, transactions and enrollment checks |
| `Sources/TailgateReview` | Operator-controlled native offline/live windows |
| `Sources/TailgatePreview` | Read-only fixture preview; no dependency on the live module |

Before publishing changes, run `python3 Scripts/check-public.py` and `python3 -m unittest discover -s Tests/Privacy`. The [local privacy checks](Tests/Privacy/README.md) are heuristic. The scan covers reachable history, staged files and nonignored working files. It is a guardrail, not proof that no identifying detail exists. Only fictional examples belong in this repository.
