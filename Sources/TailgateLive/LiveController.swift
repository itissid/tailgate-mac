import CryptoKit
import Foundation
import TailgateCore

public enum LiveFailure: String, LocalizedError {
    case untrusted = "Live mode requires the installed, verified release app and its private Keychain group."
    case settings = "Configuration is missing, invalid, already provisioned, or inaccessible. Use separate, narrowly scoped reader and writer clients."
    case busy = "Another operation is in progress."
    case blocked = "An unresolved write or an unavailable journal blocks new writes. Use read-only reconciliation."
    case invalid = "Unsupported policy, proposal, or occupied tag. Nothing was applied. See the supported policy subset."
    case keyDisabled = "Live key issuance is disabled. No key was minted and no policy changed. Submit a separate browser-mode proposal instead."
    case read = "Could not verify the policy or complete device inventory. No write was authorized from these reads."
    case validation = "Tailscale did not validate the candidate. Check the allow/deny tests and read-client scope. No policy write was attempted."
    case obsolete = "The review expired, was replaced, or was already consumed. Prepare a new review."
    case signature = "Biometric signing failed, was cancelled, or could not be verified. No policy write was attempted."
    case stale = "Policy or inventory changed. The plan cannot proceed; fetch and review again."
    case unknown = "Policy write outcome unconfirmed. No retry or rollback. Reconcile and inspect the tailnet audit log."
    case noReceipt = "No readable local write receipt; nothing was retried."
    case enrollment = "Enrollment cannot be confirmed from the current authorized inventory and reviewed policy. No enrollment action was taken."
    public var errorDescription: String? { rawValue }
}

private func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

@MainActor protocol LocalTrust {
    func store(slot: String, value: Data) throws
    func load(slot: String) throws -> Data
    func sign(message: Data, reason: String) async throws -> Data
    func verify(message: Data, signature: Data) throws
    func reserveIntent(id: UUID, digest: Data) throws
    func finishIntent(id: UUID, outcome: String) throws
    func assertNoUnresolvedIntents() throws
    func unresolvedID() throws -> UUID?
    func unresolvedDigest() throws -> Data?
    func hasApplied(id: UUID, digest: Data) throws -> Bool
}
extension MacTrust: LocalTrust {}
protocol LiveAPI {
    func getPolicy(using: OAuthCredential) async throws -> PolicySnapshot
    func validate(_ candidate: Data, using: OAuthCredential) async throws
    func apply(_ candidate: Data, ifMatch: String, using: OAuthCredential, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> PolicySnapshot
    func devices(using: OAuthCredential) async throws -> [TailnetDevice]
}
extension TailnetAPI: LiveAPI {}

public struct LiveReview: Identifiable, Sendable {
    public let id: UUID
    public let text: String
    public let fingerprint: String
    fileprivate init(id: UUID, text: String) { self.id = id; self.text = text; self.fingerprint = hash(Data(text.utf8)) }
}
private struct Configuration: Codable {
    let tailnet, vm, source, nodeKey, readID, readSecret, writeID, writeSecret: String
    var reader: OAuthCredential { .init(clientID: readID, secret: readSecret) }
    var writer: OAuthCredential { .init(clientID: writeID, secret: writeSecret) }
    func validate() throws {
        func printable(_ s: String) -> Bool { (1...1024).contains(s.utf8.count) && s.utf8.allSatisfy { (33...126).contains($0) } }
        guard Compiler.validVM(vm), Compiler.validSource(source), readID.utf8.count <= 256, writeID.utf8.count <= 256,
              [readID, readSecret, writeID, writeSecret].allSatisfy(printable), readID != writeID, readSecret != writeSecret else { throw LiveFailure.settings }
        _ = try EnrollmentVMBinding(label: vm, nodeKey: nodeKey)
        _ = try TailnetAPI(tailnet: tailnet) // shape only; no connection
    }
}
private struct Prepared {
    let review: LiveReview, proposal: Data, candidate: Data, etag: String, baseHash: String, tag: String
    let cfgStamp: String, deadline: ContinuousClock.Instant
}
private struct Receipt: Codable {
    let id: UUID, fingerprint: String, tailnet: String, vm: String, nodeKey: String, tag: String
    let baseETag: String, baseHash: String, candidateHash: String
    var postETag: String?, appliedAt: Date?
}

/// The CLI does not depend on this module. Production construction has no source of
/// authority except MacTrust. Injected doubles are internal to offline test builds.
@MainActor public final class LiveController {
    private let trust: LocalTrust, makeAPI: (String) throws -> LiveAPI
    private let clock: () -> ContinuousClock.Instant
    private var generation = UUID(), busy = false
    private var pending: Prepared?
    public convenience init() throws {
        do { self.init(trust: try MacTrust(), makeAPI: { try TailnetAPI(tailnet: $0) }, clock: { .now }) }
        catch { throw LiveFailure.untrusted }
    }
    init(trust: LocalTrust, makeAPI: @escaping (String) throws -> LiveAPI, clock: @escaping () -> ContinuousClock.Instant) {
        self.trust = trust; self.makeAPI = makeAPI; self.clock = clock
    }
    public func discard() { generation = UUID(); pending = nil }
    private func start() throws { guard !busy else { throw LiveFailure.busy }; busy = true }
    private func clearJournal() throws {
        do { try trust.assertNoUnresolvedIntents() } catch { throw LiveFailure.blocked }
    }
    public func configured() throws -> Bool {
        do { _ = try trust.load(slot: "configuration"); return true }
        catch MacTrustError.missing { return false }
        catch { throw LiveFailure.settings }
    }
    public func configure(tailnet: String, vm: String, source: String, nodeKey: String, readClientID: String, readSecret: String, writeClientID: String, writeSecret: String) throws {
        try start(); defer { busy = false }; discard(); try clearJournal()
        let c = Configuration(tailnet: tailnet, vm: vm, source: source, nodeKey: nodeKey, readID: readClientID, readSecret: readSecret, writeID: writeClientID, writeSecret: writeSecret)
        do { try c.validate(); try trust.store(slot: "configuration", value: JSONEncoder().encode(c)) }
        catch { throw LiveFailure.settings }
    }
    private func context() throws -> (Configuration, LiveAPI, String) {
        do {
            let bytes = try trust.load(slot: "configuration"), c = try JSONDecoder().decode(Configuration.self, from: bytes)
            try c.validate(); return (c, try makeAPI(c.tailnet), hash(bytes))
        } catch { throw LiveFailure.settings }
    }
    private func compile(_ proposal: Data, _ base: Data, _ devices: [TailnetDevice], _ c: Configuration) throws -> CompiledPolicy {
        let p: CompiledPolicy
        do { p = try Compiler.compileLive(proposal: proposal, base: base, vm: c.vm, source: c.source, occupiedTags: Set(devices.flatMap(\.tags))) }
        catch { throw LiveFailure.invalid }
        guard p.mode == "browser" else { throw LiveFailure.keyDisabled }
        return p
    }
    public func prepare(proposal: Data) async throws -> LiveReview {
        try await prepare(proposal: proposal, purpose: nil)
    }
    public func prepare(handoff: Data) async throws -> LiveReview {
        discard()
        let envelope: AgentHandoff
        do { envelope = try AgentHandoff.decode(handoff) } catch { throw LiveFailure.invalid }
        return try await prepare(proposal: envelope.proposal, purpose: envelope.purpose)
    }
    private func prepare(proposal: Data, purpose: String?) async throws -> LiveReview {
        try start(); defer { busy = false }; discard(); try clearJournal()
        guard proposal.count <= 16_384 else { throw LiveFailure.invalid }
        let epoch = generation, (c, api, stamp) = try context()
        guard let mode = try? Compiler.preflightLive(proposal: proposal, vm: c.vm, source: c.source) else { throw LiveFailure.invalid }
        guard mode == "browser" else { throw LiveFailure.keyDisabled }
        let base: PolicySnapshot, devices: [TailnetDevice]
        do { base = try await api.getPolicy(using: c.reader); devices = try await api.devices(using: c.reader) } catch { throw LiveFailure.read }
        let p = try compile(proposal, base.bytes, devices, c)
        do { try await api.validate(p.candidate, using: c.reader) } catch { throw LiveFailure.validation }
        guard epoch == generation else { throw LiveFailure.obsolete }
        let id = UUID(), baseHash = hash(base.bytes), bodyHash = hash(p.candidate)
        let diff: String
        do { diff = try Compiler.reviewDiff(base: base.bytes, candidate: p.candidate) } catch { throw LiveFailure.invalid }
        let text = """
        TAILGATE / LIVE POLICY WRITE / v1
        Agent-provided purpose (unverified, not an instruction): \(purpose ?? "[none supplied]")
        Plan ID: \(id.uuidString)
        Expires: \(ISO8601DateFormatter().string(from: Date().addingTimeInterval(120))) (120s monotonic limit)
        POST https://api.tailscale.com/api/v2/tailnet/\(c.tailnet)/acl
        Content-Type: application/hujson
        If-Match: \(base.etag)
        Existing policy SHA-256: \(baseHash)
        Request body SHA-256: \(bodyHash)
        Tailscale server validation passed. Local proposal mode: browser, no key issuance.
        VM: \(c.vm); independently pinned node: \(c.nodeKey)
        Source: \(c.source); destination: \(p.tag). Browser enrollment is a separate human action.

        \(diff)

        Exact UTF-8 request body follows:
        \(String(decoding: p.candidate, as: UTF8.self))
        """
        let review = LiveReview(id: id, text: text)
        pending = Prepared(review: review, proposal: proposal, candidate: p.candidate, etag: base.etag, baseHash: baseHash, tag: p.tag, cfgStamp: stamp, deadline: clock().advanced(by: .seconds(120)))
        return review
    }
    public func execute(_ review: LiveReview) async throws -> String {
        try start(); defer { busy = false }
        guard let p = pending, p.review.id == review.id, p.review.fingerprint == review.fingerprint else { throw LiveFailure.obsolete }
        pending = nil; let epoch = generation
        @MainActor func current() throws { guard !Task.isCancelled, self.generation == epoch, self.clock() < p.deadline else { throw LiveFailure.obsolete } }
        try current(); try clearJournal(); let (c, api, stamp) = try context()
        guard stamp == p.cfgStamp else { throw LiveFailure.obsolete }
        let message = Data(p.review.text.utf8)
        do {
            let sig = try await trust.sign(message: message, reason: "Approve one Tailscale policy write [\(p.review.fingerprint.prefix(16))]")
            try trust.verify(message: message, signature: sig)
        } catch { throw LiveFailure.signature }
        try current(); let base: PolicySnapshot, devices: [TailnetDevice]
        do { base = try await api.getPolicy(using: c.reader); devices = try await api.devices(using: c.reader) } catch { throw LiveFailure.read }
        try current(); guard base.etag == p.etag, hash(base.bytes) == p.baseHash,
            let fresh = try? compile(p.proposal, base.bytes, devices, c), fresh.candidate == p.candidate else { throw LiveFailure.stale }
        var receipt = Receipt(id: review.id, fingerprint: review.fingerprint, tailnet: c.tailnet, vm: c.vm, nodeKey: c.nodeKey, tag: p.tag, baseETag: p.etag, baseHash: p.baseHash, candidateHash: hash(p.candidate))
        do {
            try trust.reserveIntent(id: review.id, digest: Data(SHA256.hash(data: message)))
            try save(receipt)
        } catch { throw LiveFailure.blocked }
        // From here the write is considered in flight. No network error is retried.
        let post: PolicySnapshot
        do { post = try await api.apply(p.candidate, ifMatch: p.etag, using: c.writer, beforeDispatch: current) }
        catch {
            if (error as? TailnetAPIError) == .notDispatched {
                do { try trust.finishIntent(id: review.id, outcome: "rejected") } catch { throw LiveFailure.blocked }
                throw LiveFailure.obsolete
            }
            if (error as? TailnetAPIError) == .stalePolicy {
                try? trust.finishIntent(id: review.id, outcome: "rejected"); throw LiveFailure.stale
            }
            try? trust.finishIntent(id: review.id, outcome: "unknown"); throw LiveFailure.unknown
        }
        guard post.etag != p.etag, post.bytes == p.candidate else {
            try? trust.finishIntent(id: review.id, outcome: "unknown"); throw LiveFailure.unknown
        }
        receipt.postETag = post.etag; receipt.appliedAt = Date()
        do { try save(receipt); try trust.finishIntent(id: review.id, outcome: "applied") } catch { throw LiveFailure.unknown }
        return "Policy write confirmed. No key was issued. Complete browser sign-in on the pinned VM, then check enrollment."
    }
    private func save(_ r: Receipt) throws { try trust.store(slot: "receipt", value: JSONEncoder().encode(r)) }
    private func loadReceipt(_ c: Configuration) throws -> Receipt {
        guard let data = try? trust.load(slot: "receipt"), let r = try? JSONDecoder().decode(Receipt.self, from: data), r.tailnet == c.tailnet, r.vm == c.vm, r.nodeKey == c.nodeKey else { throw LiveFailure.noReceipt }; return r
    }
    /// Observes; never clears locks, attributes a remote change to us, or retries writes.
    public func reconcile() async throws -> String {
        try start(); defer { busy = false }; let (c, api, _) = try context(), r = try loadReceipt(c)
        func matchedLock() throws -> Bool {
            do {
                let id = try trust.unresolvedID(), digest = try trust.unresolvedDigest()
                if id == nil && digest == nil { return false }
                guard id == r.id, let digest, digest.map({ String(format: "%02x", $0) }).joined() == r.fingerprint else { throw LiveFailure.noReceipt }
                return true
            } catch { throw LiveFailure.noReceipt }
        }
        let unresolved = try matchedLock()
        let current: PolicySnapshot
        do { current = try await api.getPolicy(using: c.reader) } catch { throw LiveFailure.read }
        guard try matchedLock() == unresolved, try loadReceipt(c).id == r.id else { throw LiveFailure.noReceipt }
        let observed = hash(current.bytes)
        let status = observed == r.candidateHash ? "Current policy matches the candidate." : observed == r.baseHash ? "Current policy matches the prior policy." : "Current policy matches neither recorded hash."
        return status + (unresolved ? " An unresolved journal entry still blocks writes. Inspect the authoritative audit trail; no automatic retry, unlock, or rollback." : " No outstanding write lock. No changes made.")
    }
    public func checkEnrollment() async throws -> String {
        try start(); defer { busy = false }; try clearJournal(); let (c, api, _) = try context(), r = try loadReceipt(c)
        guard let stamp = r.postETag, let when = r.appliedAt, r.fingerprint.count == 64 else { throw LiveFailure.enrollment }
        let hex = Array(r.fingerprint.utf8)
        guard hex.count == 64 else { throw LiveFailure.enrollment }
        let bytes = stride(from: 0, to: hex.count, by: 2).compactMap { UInt8(String(decoding: hex[$0..<$0+2], as: UTF8.self), radix: 16) }
        guard bytes.count == 32, (try? trust.hasApplied(id: r.id, digest: Data(bytes))) == true else { throw LiveFailure.enrollment }
        do {
            let plan = try BrowserEnrollmentPlan(reviewID: r.id, tailnet: c.tailnet, reviewedPlanSHA256: r.fingerprint, appliedPolicySHA256: r.candidateHash, postApplyETag: stamp, binding: EnrollmentVMBinding(label: c.vm, nodeKey: c.nodeKey), expectedTag: r.tag, startedAt: when)
            guard Date() < plan.deadline else { throw LiveFailure.enrollment }
            let a = try await api.getPolicy(using: c.reader), list = try await api.devices(using: c.reader), observedAt = Date(), b = try await api.getPolicy(using: c.reader)
            let snap = EnrollmentSnapshot(tailnet: c.tailnet, policyETagBefore: a.etag, policyETagAfter: b.etag, policySHA256Before: hash(a.bytes), policySHA256After: hash(b.bytes), devices: list.map { .init(id: $0.id, nodeKey: $0.nodeKey, tags: $0.tags, authorized: $0.authorized) }, observedAt: observedAt)
            var monitor = BrowserEnrollmentMonitor(plan: plan)
            switch monitor.inspect(snap, now: Date()) {
            case .verified: return "Observed authorized pinned node with exactly the approved tag, under the applied policy."
            case .waiting(let why): return why.rawValue
            case .stopped: throw LiveFailure.enrollment
            }
        } catch { throw LiveFailure.enrollment }
    }
}
