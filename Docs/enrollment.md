# Enrollment: browser wait, not agent-directed device administration

The policy write and device enrollment are distinct operations. A successful policy POST does not mean a VM joined, and a new device with the expected hostname does not prove it is the intended VM. The live browser path is a **read-only observation** of a previously human-pinned node after the reviewed policy has been applied.

## Human binding and browser sign-in

1. A human uses an independently trusted VM console or pre-provisioned management channel to obtain that VM's full Tailscale **node public key**, encoded as `nodekey:` plus 64 lowercase hexadecimal characters. This public value is not the private node key. Do not copy private state files, credentials, or an auth key into the app.
2. The human enters the public-key pin in the Mac setup UI along with a descriptive VM label. If a server device identifier is already known, it may be pinned too. It must consistently use the API field selected by the caller, preferably the current `nodeId` field. The label is display text, not an identity check. **Do not populate this binding from the agent proposal, a login URL, hostname, IP, or latest-device match.** If no independently verified pin is available, stop; this build does not offer automatic trust-on-first-use.
3. The review must include this binding, exact tag, explicit tailnet, enrollment mode, full policy bytes/hash, original ETag, review ID and expiry. The signed plan hash must cover the binding itself, not just the policy bytes.
4. After a successful, reconciled policy write, start the monitor with its candidate hash and the **post-write** ETag. A failed/unknown write cannot start an enrollment monitor as if it succeeded.
5. A human completes the official interactive sign-in flow on the intended VM. This module does not invoke Tailscale, launch supplied URLs, sign in, apply tags, or approve a device. Browser sign-in commonly creates user identity rather than tag identity; success requires exactly the reviewed tag to be present through a separately authorized human procedure. No automatic retagging or key fallback is permitted.
6. The Mac performs read-only policy GET → device inventory GET → policy GET. Both policy reads must match the exact target, post-write ETag and applied policy hash. Fresh inventory must contain **one** node matching the full pin; if a device ID was pinned it must match too. The device must be authorized and have exactly the one reviewed tag. The receipt records what was observed, not a permanent connectivity guarantee.

A fresh node public key can require initialization by the VM's Tailscale client. This module deliberately supplies no shell command or automatic bootstrap. If the human cannot obtain and authenticate that public identity before approving, the deployment is not ready for this path. Rotation of a pinned key requires a new trusted binding and review, never silent repinning.

## Swift interface

```swift
let binding = try EnrollmentVMBinding(
    label: humanLabel,
    nodeKey: humanVerifiedNodePublicKey,
    expectedDeviceID: knownDeviceID  // optional; never hostname
)
let plan = try BrowserEnrollmentPlan(
    reviewID: approvedID,
    tailnet: explicitTailnet,
    reviewedPlanSHA256: signedPlanHash,
    appliedPolicySHA256: reconciledPolicyHash,
    postApplyETag: reconciledPostWriteETag,
    binding: binding,
    expectedTag: reviewedTag,
    startedAt: appliedAt,
    timeoutSeconds: 300
)
var monitor = BrowserEnrollmentMonitor(plan: plan)
let state = monitor.inspect(freshBracketedSnapshot, now: Date())
```

The structs validate shape, not the source of trust. They are not approval tokens; only the signed-app broker decides when the approved write was successfully reconciled and constructs the monitor. The monitor owns no credentials or transport. `inspect` only updates its in-memory observation state. Missing node keys never fall back to another field. Inventory with duplicated pins/IDs, wrong IDs or extra tags cannot verify.

Waiting reasons distinguish absent node, missing authorization, missing reviewed tag, and stale inventory. Cancellation, timeout, identity conflict or policy conflict is terminal. A historical verified receipt also stays terminal; it cannot be rebound to a new policy or node. Fresh checks require a new monitor for the same trusted approved context. The caller must stop monitoring on application/session cancellation and enforce its own monotonic deadline across asynchronous network requests; caller-provided wall-clock timestamps are not an approval-expiry security primitive. No timeout or cancellation automatically removes policy or revokes a device: cleanup is another write requiring its own reviewed approval.

## Why key enrollment is disabled in the live build

`KeyEnrollmentAvailability.isEnabled` is a constant `false`; `requireAvailable()` always throws before token access or network activity. There is no caller-supplied `trusted: true` switch, generic recipient URL, or receiver executable in this build. The existing memory-only demo may still model a one-use 300-second issuance, but it cannot make real keys and establishes no live API guarantee.

The requested live key mode needs all of these independently established guarantees:

- The exact reviewed short expiry is supported by the service. The public [auth-key documentation](https://tailscale.com/docs/features/access-control/auth-keys#key-expiry) says expiry can be specified in days from **1 to 90 inclusive**. The official [Go client key model](https://github.com/tailscale/tailscale-client-go-v2/blob/main/keys.go) exposes `expirySeconds`, `reusable`, `ephemeral`, `preauthorized`, and tag fields, but that schema alone does **not** prove a 300-second key is accepted. The build must not silently round the approved lifetime up to a day.
- A pre-provisioned VM-local receiver has an independently verified identity and private authenticated channel. The endpoint, pin and destination helper must not be chosen by the proposing agent. A hostname or TLS certificate for an agent-controlled receiver is insufficient.
- The enrollment helper and its memory/OS are outside agent control. A bearer key delivered to a VM controlled by the agent cannot honestly be called inaccessible to the agent. Pinned delivery authenticates the recipient; it does not cryptographically restrict a stolen Tailscale bearer key to that VM.
- Policy and issuance cannot race in a way that violates the approval. Policy `If-Match` protects the policy POST; it does not create a transaction around `/keys`. A preflight GET is not an atomic policy-to-key condition.
- The exact tag is available to a narrowly scoped issuer without automatically expanding `tagOwners` or OAuth privileges, and issuance/delivery/redeem receipts can be reconciled across unknown outcomes without reminting.

No real API calls were made to prove these service guarantees. Reading public official docs/source establishes the exposed contract, not observed live behavior. With those capabilities absent, the safe useful path is an explicit browser wait. Any future key mode needs a separate reviewed implementation, receiver provisioning and verification, and per-issuance human approval. Failure, uncertainty, or browser inconvenience never enables it implicitly.

## Offline verification

`Tests/TailgateLiveTests/EnrollmentTests.swift` uses Swift Testing and public fake node keys. It covers successful exact pinned enrollment; missing/wrong keys; missing authorization/tag; extra and duplicated tags; unexpected or duplicated device IDs; concurrent policy version/body/target changes; stale/future observations; expiry; cancellation; terminal receipts; and permanently disabled key issuance. It neither uses hardware nor contacts a tailnet.
