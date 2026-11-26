import Foundation
import Testing
@testable import TailgateCore

struct SubmissionTests {
    private func reviewed() -> SubmissionLifecycle {
        var life = SubmissionLifecycle()
        #expect(life.received() == true); #expect(life.beginReview() == true); #expect(life.reviewed() == true)
        return life
    }
    @Test func receivingAndReviewAreNotApproval() {
        var life = SubmissionLifecycle()
        #expect(life.beginExecution() == false); #expect(life.beginReview() == false); #expect(life.finish(.applied) == nil)
        #expect(life.received() == true); #expect(life.received() == false); #expect(life.beginReview() == true); #expect(life.beginExecution() == false)
        #expect(life.finish(.applied) == nil); #expect(life.reviewed() == true); #expect(life.beginExecution() == true); #expect(life.beginExecution() == false)
    }
    @Test func interruptionBeforeExecutionProvesNoWrite() {
        for phase in 0...3 {
            var life = SubmissionLifecycle()
            if phase >= 1 { life.received() }; if phase >= 2 { life.beginReview() }; if phase >= 3 { life.reviewed() }
            #expect(life.interrupt()?.status == .declined); #expect(life.phase == .finished)
            #expect(life.finish(.applied) == nil); #expect(life.interrupt() == nil)
        }
    }
    @Test func interruptedOrExpiredExecutionIsUnknown() {
        for expired in [false, true] {
            var life = reviewed(); #expect(life.beginExecution() == true)
            #expect(life.interrupt(expired: expired)?.status == .unknown)
            #expect(life.finish(.applied) == nil); #expect(life.beginReview() == false)
        }
        var waiting = reviewed(); #expect(waiting.interrupt(expired: true)?.status == .expired)
    }
    @Test func onlyFirstTerminalReceiptWins() {
        for status in SubmissionReceipt.Status.allCases {
            var life = reviewed(); life.beginExecution()
            #expect(life.finish(status)?.status == status)
            for replacement in SubmissionReceipt.Status.allCases { #expect(life.finish(replacement) == nil) }
        }
    }
    @Test func receiptIsBoundedConstantSchemaWithoutPolicyOrIdentity() throws {
        let statuses = Set(SubmissionReceipt.Status.allCases.map(\.rawValue))
        #expect(statuses == ["declined", "rejected", "expired", "stale", "applied", "unknown"])
        for status in SubmissionReceipt.Status.allCases {
            let r = SubmissionReceipt(status: status), data = r.jsonLine
            #expect(data.count < 256); #expect(data.last == 10)
            let obj = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
            #expect(Set(obj.keys) == ["version", "status", "write_outcome", "enrollment"])
            #expect(obj["status"] as? String == status.rawValue); #expect(obj["version"] as? Int == 1)
            #expect(obj["enrollment"] as? String == "not_confirmed")
            let expected = status == .applied ? "applied" : status == .unknown ? "unknown" : status == .stale ? "not_applied" : "not_attempted"
            #expect(obj["write_outcome"] as? String == expected)
            #expect(r.exitCode == (status == .applied ? 0 : status == .unknown ? 3 : 2))
        }
    }
    @Test func incrementalInputIsBoundedAndDecodedWithoutIO() throws {
        let frame = Data("TAILGATE/1\nReview an HTTPS-only test proposal\n\n".utf8) + Compiler.example
        var input = SubmissionInput()
        for byte in frame { try input.append(Data([byte])) }
        let result = try input.finish(); #expect(result.bytes == frame)
        #expect(result.handoff.proposal == Compiler.example)
        #expect(result.handoff.purpose == "Review an HTTPS-only test proposal")
        var large = SubmissionInput()
        try large.append(Data(repeating: 32, count: AgentHandoff.maximumBytes))
        #expect(throws: AgentHandoffError.invalid) { try large.append(Data([32])) }
        #expect(throws: AgentHandoffError.invalid) { try large.finish() }
        #expect(throws: AgentHandoffError.invalid) { try SubmissionInput().finish() }
    }
    @Test func wrapperParsesReceiptsWithoutLaunchingApp() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let script = root.appendingPathComponent("Scripts/tailgate-submit").path
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-B", "-c", #"""
import json, runpy, sys
m = runpy.run_path(sys.argv[1], run_name='submission_test')
r, parse = m['receipt'], m['parse_result']
for status in m['STATUSES']:
    expected = r(status)
    code = 0 if status == 'applied' else 3 if status == 'unknown' else 2
    assert parse(json.dumps(expected).encode(), code) == expected
    assert parse(json.dumps(expected).encode(), -9) == r('unknown')
for raw in [b'', b'not json', b'{}', b'x'*1025,
            b'{"version":1,"version":1}', b'{}\n{}',
            b'{"status":[]}', b'{"version":true}',
            json.dumps(dict(r('applied'), detail='untrusted')).encode()]:
    assert parse(raw, 0) == r('unknown')
env = m['safe_environment']()
assert set(env) == {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL'}
assert env['PATH'] == '/usr/bin:/bin:/usr/sbin:/sbin'
assert m['EXECUTABLE'] == '/Applications/Tailgate.app/Contents/MacOS/TailgateReview'
"""#, script]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit(); #expect(process.terminationStatus == 0)
    }
}
