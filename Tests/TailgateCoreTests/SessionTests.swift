import Foundation
import Testing
@testable import TailgateCore

@MainActor private struct Gate: ReviewGate {
    let action: (Review) -> Bool
    init(_ action: @escaping (Review) -> Bool = { _ in true }) { self.action = action }
    func confirm(_ review: Review) async -> Bool { action(review) }
}

@MainActor struct SessionTests {
    private let lab = MemoryLab()
    private func setup() -> DryRunSession { DryRunSession(lab: lab, now: { .now }) }
    private var keyInput: Data { Data(String(decoding: Compiler.example, as: UTF8.self).replacingOccurrences(of: "\"browser\"", with: "\"key\"").utf8) }
    private func keyReady(_ s: DryRunSession) async throws {
        let policy = try s.reviewPolicy(proposal: keyInput)
        try await s.execute(policy, gate: Gate()); #expect(s.stage == .keyReview); #expect(lab.issued == 0)
    }
    @Test func browserReviewBindsExactBodyAndNeverMints() async throws {
        let s = setup(), plan = try s.reviewPolicy(proposal: Compiler.example)
        let expected = try Compiler.compile(proposal: Compiler.example, base: Compiler.fixturePolicy)
        #expect(plan.text.contains(String(decoding: expected.candidate, as: UTF8.self))); #expect(plan.text.contains("If-Match: \(lab.etag)"))
        #expect(plan.text.contains("No key.")); #expect(plan.fingerprint.count == 64); #expect(lab.writes == 0)
        try await s.execute(plan, gate: Gate { $0.fingerprint == plan.fingerprint })
        #expect(lab.policy == expected.candidate); #expect(lab.writes == 1); #expect(s.stage == .browserWait)
        #expect(throws: ReviewError.wrongPhase) { try s.reviewKey() }
        try s.checkEnrollment(); #expect(s.stage == .browserWait)
        lab.observation = Observation(node: "different", tags: [expected.tag], authorized: true)
        try s.checkEnrollment(); #expect(s.stage == .browserWait)
        lab.observation = Observation(node: Fixture.node, tags: [expected.tag,"tag:extra"], authorized: true)
        try s.checkEnrollment(); #expect(s.stage == .browserWait)
        lab.observation = Observation(node: Fixture.node, tags: [expected.tag], authorized: false)
        try s.checkEnrollment(); #expect(s.stage == .browserWait)
        try s.simulateFixtureJoin(); try s.checkEnrollment(); #expect(s.stage == .complete); #expect(lab.issued == 0)
        await #expect(throws: ReviewError.obsolete) { try await s.execute(plan, gate: Gate()) }
    }
    @Test func denyBurnsReview() async throws {
        let s = setup(), plan = try s.reviewPolicy(proposal: Compiler.example)
        await #expect(throws: ReviewError.notApproved) { try await s.execute(plan, gate: Gate { _ in false }) }
        await #expect(throws: ReviewError.obsolete) { try await s.execute(plan, gate: Gate()) }; #expect(lab.writes == 0)
    }
    @Test func reviewIsSessionLocalAndEditsInvalidateEvenIfInvalid() async throws {
        let s = setup(), other = setup(), plan = try s.reviewPolicy(proposal: Compiler.example)
        await #expect(throws: ReviewError.obsolete) { try await other.execute(plan, gate: Gate()) }
        #expect(throws: (any Error).self) { try s.reviewPolicy(proposal: Data()) }
        await #expect(throws: ReviewError.obsolete) { try await s.execute(plan, gate: Gate()) }; #expect(lab.writes == 0)
    }
    @Test func invalidationDuringAuthentication() async throws {
        let s = setup(), plan = try s.reviewPolicy(proposal: Compiler.example)
        await #expect(throws: ReviewError.obsolete) { try await s.execute(plan, gate: Gate { _ in s.invalidateReview(); return true }) }
        #expect(lab.writes == 0)
    }
    @Test func expiryDuringAuthentication() async throws {
        var t = ContinuousClock.now
        let s = DryRunSession(lab: lab, now: { t }), plan = try s.reviewPolicy(proposal: Compiler.example)
        await #expect(throws: ReviewError.expired) { try await s.execute(plan, gate: Gate { _ in t = t.advanced(by: .seconds(120)); return true }) }
        #expect(lab.writes == 0)
    }
    @Test func compareAndSwapRejectsStaleWrite() async throws {
        let s = setup(), plan = try s.reviewPolicy(proposal: keyInput)
        await #expect(throws: ReviewError.stale) { try await s.execute(plan, gate: Gate { _ in lab.rotateETag(); return true }) }
        #expect(lab.writes == 0); #expect(lab.issued == 0)
        await #expect(throws: ReviewError.obsolete) { try await s.execute(plan, gate: Gate()) }
    }
    @Test func unknownPolicyOutcomeNeverMints() async throws {
        let s = setup(); lab.losePolicyReply = true
        try await s.execute(s.reviewPolicy(proposal: keyInput), gate: Gate()); #expect(s.stage == .stopped)
        #expect(s.receipt.contains("unknown")); #expect(lab.issued == 0); #expect(throws: ReviewError.wrongPhase) { try s.reviewKey() }
    }
    @Test func separateKeyReviewAndSingleUse() async throws {
        let s = setup(); try await keyReady(s); let key = try s.reviewKey()
        #expect(key.text.contains("\"reusable\":false")); #expect(key.text.contains(Fixture.recipient)); #expect(key.text.contains("\"expirySeconds\":300"))
        try await s.execute(key, gate: Gate()); #expect(s.stage == .keyWait); #expect(lab.issued == 1)
        let issuedPayload = try #require(lab.issuedPayload); #expect(key.text.hasSuffix(issuedPayload))
        #expect(!lab.simulateUse(from: "other", now: .now)); try s.checkEnrollment(); #expect(s.stage == .keyWait)
        try s.simulateFixtureJoin(); try s.checkEnrollment(); #expect(s.stage == .complete); #expect(!lab.simulateUse(from: Fixture.recipient, now: .now))
        await #expect(throws: ReviewError.obsolete) { try await s.execute(key, gate: Gate()) }; #expect(lab.issued == 1)
    }
    @Test func expiredKeyIsNotReissued() async throws {
        var t = ContinuousClock.now; let s = DryRunSession(lab: lab, now: { t }); try await keyReady(s)
        try await s.execute(s.reviewKey(), gate: Gate()); t = t.advanced(by: .seconds(300)); try s.simulateFixtureJoin()
        #expect(s.stage == .stopped); #expect(!lab.redeemed); #expect(lab.issued == 1)
    }
    @Test func changedPolicyBeforeMint() async throws {
        let s = setup(); try await keyReady(s); let key = try s.reviewKey()
        await #expect(throws: ReviewError.stale) { try await s.execute(key, gate: Gate { _ in lab.rotateETag(); return true }) }
        #expect(lab.writes == 1); #expect(lab.issued == 0)
    }
    @Test func wrongRecipientBlocksMint() async throws {
        let s = setup(); try await keyReady(s); lab.onlineRecipient = "name-matches-but-pin-does-not"
        try await s.execute(s.reviewKey(), gate: Gate()); #expect(s.stage == .stopped); #expect(lab.issued == 0)
        #expect(s.receipt.contains("Policy applied")); #expect(s.receipt.contains("no key issued"))
    }
    @Test func deliveryFailureIsNotRolledBackOrRetried() async throws {
        let s = setup(); try await keyReady(s); lab.failDelivery = true
        try await s.execute(s.reviewKey(), gate: Gate()); #expect(s.stage == .stopped); #expect(lab.issued == 1); #expect(!lab.delivered)
        #expect(s.receipt.contains("delivery failed")); #expect(lab.writes == 1); #expect(throws: ReviewError.wrongPhase) { try s.reviewKey() }
    }
    @Test func unknownMintNeverRetries() async throws {
        let s = setup(); try await keyReady(s); lab.loseIssueReply = true
        try await s.execute(s.reviewKey(), gate: Gate()); #expect(s.stage == .stopped); #expect(s.receipt.contains("outcome unknown"))
        #expect(lab.issued == 1); #expect(!lab.delivered); #expect(throws: ReviewError.wrongPhase) { try s.reviewKey() }
    }
}
