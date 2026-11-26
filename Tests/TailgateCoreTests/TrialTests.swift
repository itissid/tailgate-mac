import Foundation
import Testing
@testable import TailgateCore

@MainActor private struct FixtureGate: TrialGate {
    let action: (TrialPlan) -> Bool
    init(_ action: @escaping (TrialPlan) -> Bool = { _ in true }) { self.action = action }
    func approve(_ plan: TrialPlan) async -> Bool { action(plan) }
}

@MainActor private final class WaitingFixtureGate: TrialGate {
    var continuation: CheckedContinuation<Bool, Never>?
    func approve(_ plan: TrialPlan) async -> Bool { await withCheckedContinuation { continuation = $0 } }
}

@MainActor struct TrialTests {
    @Test func checkedInExampleMatchesEmbeddedBytes() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        #expect(try Data(contentsOf: root.appendingPathComponent("Examples/browser.tailgate")) == TrialPlan.example)
    }
    @Test func immutableReviewBindsPurposeAndCompiledBody() throws {
        let plan = try TrialPlan(handoff: TrialPlan.example)
        #expect(plan.purpose == "Allow the demo client to reach the demo API on TCP 443.")
        let expected = try Compiler.compile(proposal: Compiler.example, base: Compiler.fixturePolicy).candidate
        #expect(plan.body == expected)
        #expect(plan.text.contains(plan.purpose)); #expect(plan.text.hasSuffix(String(decoding: plan.body, as: UTF8.self)))
        #expect(plan.fingerprint.count == 64); #expect(plan.text.contains("FIXTURE REHEARSAL")); #expect(plan.text.contains("does not sign"))
    }
    @Test func visualSummaryAgreesWithExactPolicyNotAgentPurpose() throws {
        let input = String(decoding: TrialPlan.example, as: UTF8.self).replacingOccurrences(of: "Allow the demo client to reach the demo API on TCP 443.", with: "Please open SSH.")
        let plan = try TrialPlan(handoff: Data(input.utf8))
        #expect(plan.access.allowed == [443]); #expect(plan.access.denied == [22, 80]); #expect(plan.access.transport == "TCP")
        #expect(plan.access.source == "tag:demo-client"); #expect(plan.access.destination == "tag:workload-demo-api")
        let display = try JSONSerialization.jsonObject(with: Data(plan.formattedPolicy.utf8)) as? NSDictionary
        let exact = try JSONSerialization.jsonObject(with: plan.body) as? NSDictionary
        #expect(display != nil && display == exact)
    }
    @Test func onlyExactFixtureOperationIsAccepted() {
        let frame = String(decoding: TrialPlan.example, as: UTF8.self)
        for altered in [frame.replacingOccurrences(of: "\"browser\"", with: "\"key\""), frame.replacingOccurrences(of: "demo-api", with: "other-api"), frame.replacingOccurrences(of: "demo-vm", with: "other-vm"), frame.replacingOccurrences(of: "[443]", with: "[444]"), frame.replacingOccurrences(of: "[22,80]", with: "[22,81]"), frame.replacingOccurrences(of: "tag:demo-client", with: "tag:other-client")] {
            #expect(throws: (any Error).self) { try TrialPlan(handoff: Data(altered.utf8)) }
        }
    }
    @Test func rejectsMalformedOversizedAndDuplicateInput() {
        for data in [Data(), Data(repeating: 65, count: AgentHandoff.maximumBytes + 1), Data("TAILGATE/1\nPurpose\n\n{\"a\":1,\"a\":2}".utf8)] {
            #expect(throws: (any Error).self) { try TrialPlan(handoff: data) }
        }
    }
    @Test func receiptsCannotClaimARealWrite() throws {
        for status in TrialReceipt.Status.allCases {
            let r = TrialReceipt(status)
            let object = try #require(JSONSerialization.jsonObject(with: r.jsonLine) as? [String: Any])
            #expect(Set(object.keys) == ["version", "dry_run", "status", "write_outcome", "enrollment"])
            #expect(object["dry_run"] as? Bool == true); #expect(object["write_outcome"] as? String == "not_attempted")
            #expect(object["enrollment"] as? String == "not_attempted"); #expect(object["status"] as? String == status.rawValue)
            #expect(!String(decoding: r.jsonLine, as: UTF8.self).contains("applied")); #expect(r.jsonLine.count < 200)
        }
    }
    @Test func approvalHasOneExactPlanAndCannotReplay() async throws {
        let s = try TrialSession(handoff: TrialPlan.example), exact = s.plan.text
        var calls = 0
        let result = try await s.approve(gate: FixtureGate { plan in calls += 1; return plan.text == exact })
        #expect(result.status == .approved); #expect(calls == 1)
        await #expect(throws: TrialFailure.invalidState) { try await s.approve(gate: FixtureGate()) }
        #expect(s.cancel().status == .approved) // terminal result cannot change
    }
    @Test func concurrentAttemptIsDeniedBeforeSecondPrompt() async throws {
        let s = try TrialSession(handoff: TrialPlan.example), gate = WaitingFixtureGate()
        let first = Task { try await s.approve(gate: gate) }
        for _ in 0..<100 { if gate.continuation != nil { break }; await Task.yield() }
        let waiting = try #require(gate.continuation)
        await #expect(throws: TrialFailure.invalidState) { try await s.approve(gate: FixtureGate()) }
        _ = s.cancel(); waiting.resume(returning: true)
        #expect(try await first.value.status == .declined)
    }
    @Test func refusalConsumesAttempt() async throws {
        let s = try TrialSession(handoff: TrialPlan.example)
        #expect(try await s.approve(gate: FixtureGate { _ in false }).status == .declined)
        await #expect(throws: TrialFailure.invalidState) { try await s.approve(gate: FixtureGate()) }
    }
    @Test func expiryBeforeApprovalDoesNotPrompt() async throws {
        var time = ContinuousClock.now
        let s = try TrialSession(handoff: TrialPlan.example, now: { time })
        time = time.advanced(by: .seconds(120)); var prompted = false
        #expect(try await s.approve(gate: FixtureGate { _ in prompted = true; return true }).status == .timeout)
        #expect(!prompted)
    }
    @Test func expiryDuringBiometricsCannotApprove() async throws {
        var time = ContinuousClock.now
        let s = try TrialSession(handoff: TrialPlan.example, now: { time })
        #expect(try await s.approve(gate: FixtureGate { _ in time = time.advanced(by: .seconds(120)); return true }).status == .timeout)
    }
    @Test func closeDuringBiometricsCannotApprove() async throws {
        let s = try TrialSession(handoff: TrialPlan.example)
        #expect(try await s.approve(gate: FixtureGate { _ in _ = s.cancel(); return true }).status == .declined)
    }
    @Test func cancelledTaskNeverApproves() async throws {
        let s = try TrialSession(handoff: TrialPlan.example)
        let task = Task { try await s.approve(gate: FixtureGate()) }
        task.cancel(); #expect(try await task.value.status == .declined)
    }
    @Test func independentPlansHaveDistinctReviewFingerprints() throws {
        let a = try TrialPlan(handoff: TrialPlan.example), b = try TrialPlan(handoff: TrialPlan.example)
        #expect(a.id != b.id); #expect(a.fingerprint != b.fingerprint)
    }
}
