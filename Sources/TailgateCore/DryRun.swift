import CryptoKit
import Foundation

private func digest(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}

// Render complete JSON as a line diff. No agent-provided summary or HTML is displayed.
private func policyDiff(_ old: Data, _ new: Data) throws -> String {
    func lines(_ data: Data) throws -> [Substring] {
        let object = try JSONSerialization.jsonObject(with: data)
        let pretty = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes])
        return String(decoding: pretty, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
    }
    let a = try lines(old), b = try lines(new), changes = b.difference(from: a)
    var removed = Set<Int>(), inserted = Set<Int>()
    for change in changes {
        switch change {
        case .remove(let n, _, _): removed.insert(n)
        case .insert(let n, _, _): inserted.insert(n)
        }
    }
    var i = 0, j = 0, out = ["--- fixture policy", "+++ proposed policy"]
    while i < a.count || j < b.count {
        if removed.contains(i) { out.append("-" + a[i]); i += 1 }
        else if inserted.contains(j) { out.append("+" + b[j]); j += 1 }
        else { out.append(" " + b[j]); i += 1; j += 1 }
    }
    return out.joined(separator: "\n")
}

public enum ReviewError: String, LocalizedError {
    case obsolete = "The review is no longer current. Nothing executed for this approval."
    case expired = "The review expired. A new review and Touch ID are required."
    case notApproved = "Touch ID was unavailable, cancelled, or denied. Nothing executed for this approval."
    case stale = "Policy ETag changed. This operation was not applied. Reconcile before retrying."
    case wrongPhase = "This operation is not available at this stage."
    public var errorDescription: String? { rawValue }
}

public struct Review: Identifiable, Sendable {
    public let id: UUID
    public let text: String
    public let fingerprint: String
    public let title: String
    fileprivate init(title: String, details: String) {
        self.title = title
        id = UUID()
        text = "OFFLINE • fixture-tailnet • NO REAL WRITES\n\(title)\nReview ID: \(id.uuidString) (single use, valid 120 seconds)\n\n" + details
        fingerprint = digest(Data(text.utf8))
    }
}

/// This boundary gates a *simulator*. It is not an authentication API for other processes.
@MainActor public protocol ReviewGate {
    func confirm(_ review: Review) async -> Bool
}

public enum Stage: Equatable {
    case initial, browserWait, keyReview, keyWait, complete, stopped
}

/// Independent fixture identity pins, not values supplied by the proposal. No network address or key material.
enum Fixture {
    static let vm = "demo-vm"
    static let recipient = "fixture-vm-receiver-01"  // stands in for an authenticated SPKI pin
    static let node = "fixture-node-identity-01"     // stands in for attested node public identity
}

struct Observation {
    let node: String
    let tags: [String]
    let authorized: Bool
}

// An isolated, memory-only model of three different systems. No networking, credentials,
// secrets, shell, persistent receipts, or environment-based switch to a real backend.
@MainActor final class MemoryLab {
    private(set) var policy = Compiler.fixturePolicy
    private var revision = 1
    var etag: String { "\"fixture-rev-\(revision)\"" }
    private(set) var writes = 0
    private(set) var issued = 0
    private(set) var issuedPayload: String?
    private(set) var delivered = false
    private(set) var redeemed = false
    var onlineRecipient = Fixture.recipient
    var failDelivery = false
    var losePolicyReply = false
    var loseIssueReply = false
    private var keyDeadline: ContinuousClock.Instant?
    var observation: Observation?

    func rotateETag() { revision += 1 }
    func replace(_ candidate: Data, ifMatch: String) throws {
        guard etag == ifMatch else { throw ReviewError.stale }
        policy = candidate; writes += 1; revision += 1
        if losePolicyReply { throw LabFault.unknown }
    }
    fileprivate func issueAndDeliver(_ request: KeyRequest, now: ContinuousClock.Instant) throws {
        let pin = request.recipient
        guard pin == Fixture.recipient, pin == onlineRecipient, !request.policy.tag.isEmpty, issued == 0 else { throw LabFault.preflight }
        issued += 1; issuedPayload = request.payload; keyDeadline = now.advanced(by: .seconds(KeyRequest.ttl))
        if loseIssueReply { throw LabFault.unknown }
        guard !failDelivery, onlineRecipient == pin else { throw LabFault.delivery }
        delivered = true // receipt only: there is never a bearer value
    }
    func simulateUse(from pin: String, now: ContinuousClock.Instant) -> Bool {
        guard delivered, !redeemed, pin == Fixture.recipient, let deadline = keyDeadline, now < deadline else { return false }
        redeemed = true; return true
    }
}
private enum LabFault: Error { case unknown, preflight, delivery }
private struct KeyRequest {
    static let ttl = 300 // simulation requirement, not a verified live API minimum
    let policy: CompiledPolicy
    let etag: String
    let recipient: String
    var payload: String {
        // `tag` is generated by the strict compiler and is safe ASCII.
        "{\"capabilities\":{\"devices\":{\"create\":{\"ephemeral\":false,\"preauthorized\":false,\"reusable\":false,\"tags\":[\"\(policy.tag)\"]}}},\"expirySeconds\":\(Self.ttl)}"
    }
}

@MainActor public final class DryRunSession {
    public private(set) var stage: Stage = .initial
    public private(set) var receipt = "No operations attempted."
    private let lab: MemoryLab
    private let now: () -> ContinuousClock.Instant
    private var generation = UUID()
    private var pending: (Review, Operation, ContinuousClock.Instant)?
    private var applied: (CompiledPolicy, String)?
    private enum Operation {
        case policy(CompiledPolicy, String)
        case key(KeyRequest)
    }
    public convenience init() { self.init(lab: MemoryLab(), now: { .now }) }
    init(lab: MemoryLab, now: @escaping () -> ContinuousClock.Instant) {
        self.lab = lab; self.now = now
    }
    public func invalidateReview() {
        generation = UUID(); pending = nil
    }
    private func install(_ review: Review, _ op: Operation) -> Review {
        pending = (review, op, now().advanced(by: .seconds(120))); return review
    }
    public func reviewPolicy(proposal: Data) throws -> Review {
        invalidateReview() // even an invalid replacement invalidates the prior plan
        guard stage == .initial else { throw ReviewError.wrongPhase }
        let base = lab.policy, etag = lab.etag
        let policy = try Compiler.compile(proposal: proposal, base: base)
        let next = policy.mode == "browser" ? "Wait for human browser enrollment and a read-only identity check. No key." : "Separate key review required. No key is authorized by this plan."
        let review = Review(title: "Replace fixture policy (one write)", details: """
        POST /api/v2/tailnet/fixture-tailnet/acl
        If-Match: \(etag)
        Base SHA-256: \(digest(base))
        Candidate body SHA-256: \(digest(policy.candidate))
        Enrollment mode: \(policy.mode); intended VM: \(policy.vm); expected node: \(Fixture.node); exact tag: \(policy.tag)
        Next: \(next)

        \(try policyDiff(base, policy.candidate))

        Exact request body (UTF-8):
        \(String(decoding: policy.candidate, as: UTF8.self))
        """)
        return install(review, .policy(policy, etag))
    }
    public func reviewKey() throws -> Review {
        invalidateReview()
        guard stage == .keyReview, let (policy, etag) = applied, policy.mode == "key" else { throw ReviewError.wrongPhase }
        guard lab.etag == etag else { throw ReviewError.stale }
        let key = KeyRequest(policy: policy, etag: etag, recipient: Fixture.recipient)
        let review = Review(title: "Issue and deliver one fixture key", details: """
        POST /api/v2/tailnet/fixture-tailnet/keys (one mint; no policy write)
        Verify policy ETag before mint: \(etag) (not a transactional If-Match on /keys)
        Applied policy SHA-256: \(digest(policy.candidate))
        Intended VM: \(policy.vm); only deliver to fixture receiver pin: \(key.recipient)
        Expected node: \(Fixture.node); exactly one tag: \(policy.tag)
        Single use; requested TTL \(KeyRequest.ttl)s; no preauthorization; no reusable key.
        Delivery: private in-memory receipt only. Never return a key to the agent.
        If any outcome is uncertain, stop; do not issue a replacement or undo the policy.

        Exact simulated request body (UTF-8):
        \(key.payload)
        """)
        return install(review, .key(key))
    }
    /// Consume the slot BEFORE suspending. A refusal/expiry/unknown response cannot be replayed.
    /// No caller-supplied body, URL, pin or ETag is accepted at execution time.
    public func execute(_ review: Review, gate: ReviewGate) async throws {
        guard let (saved, op, deadline) = pending, saved.id == review.id, saved.fingerprint == review.fingerprint else { throw ReviewError.obsolete }
        pending = nil
        let epoch = generation
        guard now() < deadline else { throw ReviewError.expired }
        guard await gate.confirm(saved) else { throw ReviewError.notApproved }
        guard epoch == generation else { throw ReviewError.obsolete }
        guard now() < deadline else { throw ReviewError.expired }
        switch op {
        case let .policy(policy, etag):
            do { try lab.replace(policy.candidate, ifMatch: etag) }
            catch LabFault.unknown {
                stage = .stopped; receipt = "Policy outcome unknown. No key attempted; reconcile before any new write."; return
            }
            applied = (policy, lab.etag)
            stage = policy.mode == "browser" ? .browserWait : .keyReview
            receipt = "Policy applied (fixture \(lab.etag)). No key issued. Enrollment not confirmed."
        case let .key(key):
            guard lab.etag == key.etag else { throw ReviewError.stale }
            do { try lab.issueAndDeliver(key, now: now()) }
            catch LabFault.preflight {
                stage = .stopped; receipt = "Policy applied. Recipient preflight failed; no key issued. Enrollment not confirmed."; return
            } catch LabFault.delivery {
                stage = .stopped; receipt = "Policy applied. One fixture key issued; delivery failed. No retry. Enrollment not confirmed."; return
            } catch {
                stage = .stopped; receipt = "Policy applied. Key issuance outcome unknown. No retry. Enrollment not confirmed."; return
            }
            stage = .keyWait; receipt = "Policy applied. One fixture issuance delivered only to the pinned fixture receiver. Enrollment not confirmed."
        }
    }
    /// Simulate an observation from trusted inventory; never accepts identity data from a proposal.
    /// Real browser login would happen on the intended VM, outside this app.
    public func simulateFixtureJoin() throws {
        guard let (policy, _) = applied, stage == .browserWait || stage == .keyWait else { throw ReviewError.wrongPhase }
        if stage == .keyWait, !lab.simulateUse(from: Fixture.recipient, now: now()) {
            receipt = "Policy applied; key delivery recorded but fixture redemption failed. Enrollment not confirmed. No retry."; stage = .stopped; return
        }
        lab.observation = Observation(node: Fixture.node, tags: [policy.tag], authorized: true)
    }
    public func checkEnrollment() throws {
        guard let (policy, etag) = applied, stage == .browserWait || stage == .keyWait else { throw ReviewError.wrongPhase }
        guard lab.etag == etag else { stage = .stopped; receipt += " Policy changed; enrollment check stopped."; throw ReviewError.stale }
        guard let node = lab.observation, node.node == Fixture.node, node.tags == [policy.tag], node.authorized else { return }
        if stage == .keyWait, !lab.redeemed { return }
        receipt += " Verified authorized pinned fixture node and exact tag. Enrollment confirmed (simulation)."
        stage = .complete
    }
}
