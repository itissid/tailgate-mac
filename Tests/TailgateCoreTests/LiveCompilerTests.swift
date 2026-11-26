import Foundation
import Testing
@testable import TailgateCore

struct LiveCompilerTests {
    private let vm = "api-vm-01"
    private let source = "tag:trusted-client"
    private let target = "tag:workload-api-01"

    private func json(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func object(_ data: Data) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
    private func proposal(_ change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var value: [String: Any] = [
            "version": 1, "tag": target, "mode": "browser", "vm": vm,
            "grants": [["src": source, "dst": target, "protocol": "tcp", "ports": [443]]],
            "tests": [["src": source, "dst": target, "protocol": "tcp", "allow": [443], "deny": [22, 80]]]
        ]
        change(&value)
        return try json(value)
    }
    private func baseline(_ change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var value: [String: Any] = ["acls": [Any](), "ssh": [Any](), "grants": [Any](), "tests": [Any](),
                                    "tagOwners": [source: ["autogroup:admin"], "tag:old-service": ["autogroup:admin"]]]
        change(&value)
        return try json(value)
    }
    private func existing(_ change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        try baseline { root in
            root["grants"] = [["src": [source], "dst": ["tag:old-service"], "ip": ["tcp:8443", "tcp:443"]]]
            root["tests"] = [["src": source, "proto": "tcp", "accept": ["tag:old-service:443", "tag:old-service:8443"], "deny": ["tag:old-service:22"]]]
            change(&root)
        }
    }
    private func compile(_ input: Data? = nil, base: Data? = nil, occupied: Set<String> = []) throws -> CompiledPolicy {
        try Compiler.compileLive(proposal: input ?? proposal(), base: base ?? baseline(), vm: vm, source: source, occupiedTags: occupied)
    }
    private func rejected(_ input: Data? = nil, base: Data? = nil, occupied: Set<String> = [], sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(throws: (any Error).self, sourceLocation: sourceLocation) { try compile(input, base: base, occupied: occupied) }
    }

    @Test func locallyPinnedVMAndSourceAreUsedWithoutFixtureIdentity() throws {
        let result = try compile()
        #expect(result.vm == vm); #expect(result.tag == target); #expect(result.mode == "browser")
        let output = try object(result.candidate)
        #expect((output["grants"] as? [[String: [String]]]) == [["src": [source], "dst": [target], "ip": ["tcp:443"]]])
        #expect(!(String(decoding: result.candidate, as: UTF8.self).contains("demo-client")))
        #expect((output["tagOwners"] as? [String: [String]])?[target] == ["autogroup:admin"])
    }
    @Test func oldOwnersGrantsAndTestsArePreservedExactlyAsValues() throws {
        let base = try existing(), output = try object(compile(base: base).candidate), prior = try object(base)
        let oldGrants = try #require(prior["grants"] as? [Any]), oldTests = try #require(prior["tests"] as? [Any])
        #expect(try json(Array((output["grants"] as! [Any]).prefix(oldGrants.count))) == json(oldGrants))
        #expect(try json(Array((output["tests"] as! [Any]).prefix(oldTests.count))) == json(oldTests))
        let oldOwners = prior["tagOwners"] as! [String: [String]], newOwners = output["tagOwners"] as! [String: [String]]
        for (tag, owner) in oldOwners { #expect(newOwners[tag] == owner) }
        #expect(newOwners.count == oldOwners.count + 1)
        #expect(try json(output["acls"]!) == json(prior["acls"]!)); #expect(try json(output["ssh"]!) == json(prior["ssh"]!))
    }
    @Test func nextFreshProposalCanAppendWithoutLosingFirstOperation() throws {
        let first = try compile(), secondInput = try proposal { root in
            root["tag"] = "tag:workload-api-02"
            var grants = root["grants"] as! [[String: Any]], tests = root["tests"] as! [[String: Any]]
            grants[0]["dst"] = "tag:workload-api-02"; tests[0]["dst"] = "tag:workload-api-02"
            root["grants"] = grants; root["tests"] = tests
        }
        let second = try compile(secondInput, base: first.candidate, occupied: [first.tag])
        #expect((try object(second.candidate)["grants"] as? [Any])?.count == 2)
        rejected(base: first.candidate)
    }
    @Test func occupiedInventoryAndPolicyTagsRejectReuse() throws {
        rejected(occupied: [target])
        rejected(base: try baseline { $0["tagOwners"] = [source: ["autogroup:admin"], target: ["autogroup:admin"]] })
        rejected(try proposal { $0["tag"] = "tag:prod" })
    }
    @Test func humanPinMismatchAndUntrustedSelectorsReject() throws {
        rejected(try proposal { $0["vm"] = "another-vm" })
        rejected(try proposal { root in var rows = root["grants"] as! [[String: Any]]; rows[0]["src"] = "tag:other"; root["grants"] = rows })
        rejected(base: try baseline { $0["tagOwners"] = ["tag:another": ["autogroup:admin"]] })
        #expect(throws: (any Error).self) {
            try Compiler.compileLive(proposal: proposal(), base: baseline(), vm: "$(cmd)", source: source, occupiedTags: [])
        }
        rejected(occupied: ["tag:unsafe\u{202E}"])
    }
    @Test func sourceEqualTargetRejectsRatherThanCrashingOnDuplicateOwnerKeys() throws {
        let data = try proposal { root in
            root["tag"] = "tag:workload-trusted-client"
            var rows = root["grants"] as! [[String: Any]], tests = root["tests"] as! [[String: Any]]
            rows[0]["src"] = "tag:workload-trusted-client"; rows[0]["dst"] = "tag:workload-trusted-client"
            tests[0]["src"] = "tag:workload-trusted-client"; tests[0]["dst"] = "tag:workload-trusted-client"
            root["grants"] = rows; root["tests"] = tests
        }
        let base = try baseline { $0["tagOwners"] = ["tag:workload-trusted-client": ["autogroup:admin"]] }
        #expect(throws: (any Error).self) { try Compiler.compileLive(proposal: data, base: base, vm: vm, source: "tag:workload-trusted-client", occupiedTags: []) }
    }
    @Test func broadACLsMissingClosedSectionsAndUnsupportedFieldsReject() throws {
        for key in ["acls", "ssh", "tagOwners", "grants", "tests"] {
            rejected(base: try baseline { $0.removeValue(forKey: key) })
        }
        rejected(base: try baseline { $0["acls"] = [["action": "accept", "src": ["*"], "dst": ["*:*"]]] })
        rejected(base: try baseline { $0["ssh"] = [["action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"]]] })
        for key in ["groups", "hosts", "nodeAttrs", "autoApprovers", "postures", "ipsets"] {
            rejected(base: try baseline { $0[key] = [:] })
        }
    }
    @Test func transitiveUserWildcardAndExtraTagOwnersReject() throws {
        for owner in [["tag:old-service"], ["user@example.com"], ["*"], ["autogroup:admin", "tag:old-service"], []] {
            rejected(base: try baseline { $0["tagOwners"] = [source: owner] })
        }
        rejected(base: try baseline { $0["tagOwners"] = ["tag:*": ["autogroup:admin"], source: ["autogroup:admin"]] })
    }
    @Test func grantsRejectUnknownBroadOrMultipleSelectorsAndFields() throws {
        for src in [["*"], ["group:dev"], ["autogroup:member"], ["100.64.0.1"], [source, "tag:old-service"], ["tag:missing"]] {
            rejected(base: try existing { $0["grants"] = [["src": src, "dst": ["tag:old-service"], "ip": ["tcp:443", "tcp:8443"]]] })
        }
        for dst in [["*"], ["0.0.0.0/0"], ["tag:old-service", source]] {
            rejected(base: try existing { $0["grants"] = [["src": [source], "dst": dst, "ip": ["tcp:443", "tcp:8443"]]] })
        }
        rejected(base: try existing { root in var rows = root["grants"] as! [[String: Any]]; rows[0]["app"] = [:]; root["grants"] = rows })
    }
    @Test func grantsRejectAmbiguousDuplicateAndUnsupportedPortSyntax() throws {
        for ip in [["*"], ["tcp:*"], ["tcp:22-443"], ["tcp:00443"], ["tcp:443", "udp:8443"], ["tcp:443", "tcp:443"], ["icmp:0"], ["tcp:65536"]] {
            rejected(base: try existing { $0["grants"] = [["src": [source], "dst": ["tag:old-service"], "ip": ip]] })
        }
        rejected(base: try existing { $0["grants"] = ($0["grants"] as! [Any]) + ($0["grants"] as! [Any]) })
    }
    @Test func priorTestsCannotBeSilentlyDroppedOrMadeContradictory() throws {
        rejected(base: try existing { $0["tests"] = [] })
        for deny in [["tag:old-service:443"], ["tag:missing:22"], ["tag:old-service:22", "tag:old-service:22"], ["*:22"]] {
            rejected(base: try existing { root in var tests = root["tests"] as! [[String: Any]]; tests[0]["deny"] = deny; root["tests"] = tests })
        }
        rejected(base: try existing { root in var tests = root["tests"] as! [[String: Any]]; tests[0]["accept"] = ["tag:old-service:443"]; root["tests"] = tests })
    }
    @Test func commentsTrailingCommasDuplicatesAndSpoofedBytesAreRejectedNotStripped() throws {
        let text = String(decoding: try baseline(), as: UTF8.self)
        rejected(base: Data(("// preserve this comment\n" + text).utf8))
        rejected(base: Data(text.replacingOccurrences(of: "\"acls\":[]", with: "\"acls\":[],\"acls\":[]").utf8))
        rejected(base: Data(text.replacingOccurrences(of: "\"acls\":[]", with: "\"acls\":[,]").utf8))
        for unsafe in ["tag:old-\u{202E}service", "tag:old-\u{7F}service", "tag:old-\u{1B}service", "tag:old-νservice"] {
            rejected(base: Data(text.replacingOccurrences(of: "tag:old-service", with: unsafe).utf8))
        }
        rejected(base: Data(text.replacingOccurrences(of: "tagOwners", with: #"tag\u004fwners"#).utf8))
    }
    @Test func exactSemanticDiffReconstructsBothPoliciesAndOmitsNoChangedValues() throws {
        let base = try existing(), candidate = try compile(base: base).candidate
        let diff = try Compiler.reviewDiff(base: base, candidate: candidate)
        #expect(diff.contains("+")); #expect(diff.contains(target)); #expect(diff.contains("tag:old-service"))
        #expect(!diff.unicodeScalars.contains { $0.value < 32 && $0.value != 10 })
        let body = diff.components(separatedBy: "\n").dropFirst(2)
        let old = body.filter { $0.first != "+" }.map { String($0.dropFirst()) }.joined(separator: "\n")
        let new = body.filter { $0.first != "-" }.map { String($0.dropFirst()) }.joined(separator: "\n")
        #expect(try json(object(Data(old.utf8))) == json(object(base)))
        #expect(try json(object(Data(new.utf8))) == json(object(candidate)))
        #expect(diff.utf8.count <= 131_072)
    }
    @Test func diffNormalizesOnlyFormattingAndRejectsUnsafeDocuments() throws {
        let base = try baseline(), normalized = try json(object(base))
        let spaced = try JSONSerialization.data(withJSONObject: object(base), options: [.prettyPrinted])
        let diff = try Compiler.reviewDiff(base: spaced, candidate: normalized)
        #expect(!diff.components(separatedBy: "\n").dropFirst(2).contains { $0.first == "+" || $0.first == "-" })
        #expect(throws: (any Error).self) { try Compiler.reviewDiff(base: Data("{}".utf8), candidate: normalized) }
        #expect(throws: (any Error).self) { try Compiler.reviewDiff(base: normalized, candidate: Data("//comment".utf8)) }
    }
    @Test func inputAndInventoryBoundsFailClosedAndDoNotEchoSecrets() throws {
        rejected(base: Data(repeating: 32, count: 16_385))
        #expect(throws: (any Error).self) {
            try Compiler.compileLive(proposal: proposal(), base: baseline(), vm: vm, source: source,
                                     occupiedTags: Set((0...4_096).map { "tag:a\($0)" }))
        }
        do { _ = try compile(Data("PRIVATE-SECRET-DO-NOT-ECHO".utf8)); Issue.record("Unexpected acceptance") }
        catch { #expect(!error.localizedDescription.contains("PRIVATE-SECRET")) }
    }
    @Test func preflightReturnsOnlyExplicitValidatedModeWithoutPolicyOrInventory() throws {
        #expect(try Compiler.preflightLive(proposal: proposal(), vm: vm, source: source) == "browser")
        let key = try proposal { $0["mode"] = "key" }
        #expect(try Compiler.preflightLive(proposal: key, vm: vm, source: source) == "key")
        // Freshness belongs to compileLive, not this structural-only preflight.
        #expect(try Compiler.preflightLive(proposal: key, vm: vm, source: source) == compile(key).mode)
        rejected(key, occupied: [target])
    }
    @Test func preflightRejectsEveryMalformedShapeAndMismatchedLocalPin() throws {
        var malformed: [Data] = [Data(), Data("{}".utf8), Data("//comment".utf8), Data(repeating: 32, count: 16_385)]
        for key in ["mode", "version", "vm", "grants", "tests", "tag"] {
            malformed.append(try proposal { $0.removeValue(forKey: key) })
        }
        malformed.append(try proposal { $0["vm"] = "other-vm" })
        malformed.append(try proposal { $0["mode"] = "browser+key" })
        malformed.append(try proposal { $0["extra"] = "private-secret" })
        malformed.append(try proposal { $0["tag"] = "tag:prod" })
        malformed.append(try proposal { root in
            var tests = root["tests"] as! [[String: Any]]; tests[0]["allow"] = [22]; root["tests"] = tests
        })
        malformed.append(try proposal { root in
            var grants = root["grants"] as! [[String: Any]]; grants[0]["src"] = "tag:other"; root["grants"] = grants
        })
        malformed.append(Data(String(decoding: try proposal(), as: UTF8.self).replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1").utf8))
        for input in malformed {
            #expect(throws: (any Error).self) { try Compiler.preflightLive(proposal: input, vm: vm, source: source) }
        }
    }
    @Test func onboardingValidatorsMatchExactASCIIBoundsAndNeverAcceptControlText() throws {
        for value in ["a", "a0", "vm-01", String(repeating: "a", count: 64)] { #expect(Compiler.validVM(value)) }
        for value in ["", "A", "0vm", "-vm", "vm-", "vm_01", "vm.01", "vm ", "vm\n", "vm\u{202E}", "νm", String(repeating: "a", count: 65)] {
            #expect(!Compiler.validVM(value))
            #expect(throws: (any Error).self) { try Compiler.preflightLive(proposal: proposal(), vm: value, source: source) }
        }
        for value in ["tag:a", source, "tag:" + String(repeating: "a", count: 48)] { #expect(Compiler.validSource(value)) }
        for value in ["", "a", "tag:", "tag:A", "tag:0a", "tag:a-", "tag:a_b", "tag:a:b", "tag:*", "tag:a\u{7F}", "tag:a\u{202E}", "tag:" + String(repeating: "a", count: 49)] {
            #expect(!Compiler.validSource(value))
            #expect(throws: (any Error).self) { try Compiler.preflightLive(proposal: proposal(), vm: vm, source: value) }
        }
    }
}
