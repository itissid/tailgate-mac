import Foundation
import Testing
@testable import TailgateCore

struct PolicyTests {
    private func compile(_ data: Data = Compiler.example, base: Data = Compiler.fixturePolicy) throws -> CompiledPolicy {
        try Compiler.compile(proposal: data, base: base)
    }

    private func proposal(_ change: (inout [String: Any]) -> Void) throws -> Data {
        var object = try #require(JSONSerialization.jsonObject(with: Compiler.example) as? [String: Any])
        change(&object)
        return try JSONSerialization.data(withJSONObject: object, options: .sortedKeys)
    }

    private func changedRow(_ section: String, _ change: (inout [String: Any]) -> Void) throws -> Data {
        try proposal { root in
            var rows = root[section] as! [[String: Any]]
            change(&rows[0])
            root[section] = rows
        }
    }

    private func rejected(_ data: Data, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(throws: (any Error).self, sourceLocation: sourceLocation) {
            try compile(data)
        }
    }

    @Test func testExampleCompilesIntoFullRestrictivePolicy() throws {
        let result = try compile()
        #expect((result.tag) == ("tag:workload-demo-api"))
        #expect((result.mode) == ("browser"))
        #expect((result.vm) == ("demo-vm"))
        let policy = try #require(JSONSerialization.jsonObject(with: result.candidate) as? [String: Any])
        #expect((Set(policy.keys)) == (["acls", "ssh", "tagOwners", "grants", "tests"]))
        #expect(((policy["acls"] as? [Any])?.count) == (0))
        #expect(((policy["ssh"] as? [Any])?.count) == (0))
        #expect((policy["tagOwners"] as? [String: [String]]) == ([
            "tag:demo-client": ["autogroup:admin"],
            "tag:workload-demo-api": ["autogroup:admin"]
        ]))
        let grant = try #require((policy["grants"] as? [[String: [String]]])?.first)
        #expect((grant) == (["src": ["tag:demo-client"], "dst": [result.tag], "ip": ["tcp:443"]]))
        let test = try #require((policy["tests"] as? [[String: Any]])?.first)
        #expect((Set(test.keys)) == (["src", "proto", "accept", "deny"]))
        #expect((test["src"] as? String) == ("tag:demo-client"))
        #expect((test["proto"] as? String) == ("tcp"))
        #expect((test["accept"] as? [String]) == (["tag:workload-demo-api:443"]))
        #expect((test["deny"] as? [String]) == (["tag:workload-demo-api:22", "tag:workload-demo-api:80"]))
    }

    @Test func testFixtureIsExplicitClosedJSON() throws {
        let fixture = try #require(JSONSerialization.jsonObject(with: Compiler.fixturePolicy) as? [String: Any])
        for field in ["acls", "grants", "ssh", "tests"] {
            #expect(((fixture[field] as? [Any])?.count) == (0))
        }
        #expect((fixture["tagOwners"] as? [String: [String]]) == (["tag:demo-client": ["autogroup:admin"]]))
    }

    @Test func testKeyModeIsExplicitAndDoesNotChangeNetworkPolicy() throws {
        let key = try compile(proposal { $0["mode"] = "key" })
        #expect((key.mode) == ("key"))
        #expect((key.candidate) == (try compile().candidate))
    }

    @Test func testSupportsExactTCPAndUDPWithoutConflatingAssertions() throws {
        let data = try proposal { root in
            var grants = root["grants"] as! [[String: Any]]
            var tests = root["tests"] as! [[String: Any]]
            var udp = grants[0]
            udp["protocol"] = "udp"
            udp["ports"] = [53]
            grants.append(udp)
            var udpTest = tests[0]
            udpTest["protocol"] = "udp"
            udpTest["allow"] = [53]
            udpTest["deny"] = [22]
            tests.append(udpTest)
            root["grants"] = grants
            root["tests"] = tests
        }
        let result = try compile(data)
        let policy = try #require(JSONSerialization.jsonObject(with: result.candidate) as? [String: Any])
        #expect(((policy["grants"] as? [[String: [String]]])?.map { $0["ip"]! }) == ([["tcp:443"], ["udp:53"]]))
    }

    @Test func testOutputCanonicalizesPortOrder() throws {
        let first = try proposal { root in
            var grants = root["grants"] as! [[String: Any]]
            var tests = root["tests"] as! [[String: Any]]
            grants[0]["ports"] = [8443, 443]
            tests[0]["allow"] = [443, 8443]
            tests[0]["deny"] = [80, 22]
            root["grants"] = grants
            root["tests"] = tests
        }
        var object = try #require(JSONSerialization.jsonObject(with: first) as? [String: Any])
        var grants = object["grants"] as! [[String: Any]]
        grants[0]["ports"] = [443, 8443]
        object["grants"] = grants
        #expect((try compile(first).candidate) == (try compile(JSONSerialization.data(withJSONObject: object)).candidate))
        let canonical = try compile(first).candidate
        let reparsed = try JSONSerialization.jsonObject(with: canonical)
        #expect((canonical) == (try JSONSerialization.data(withJSONObject: reparsed, options: [.sortedKeys, .withoutEscapingSlashes])))
    }

    @Test func testOnlyTheClosedBaselineIsAccepted() throws {
        var base = try #require(JSONSerialization.jsonObject(with: Compiler.fixturePolicy) as? [String: Any])
        base["acls"] = [["action": "accept", "src": ["*"], "dst": ["*:*"]]]
        #expect(throws: (any Error).self) { try compile(base: JSONSerialization.data(withJSONObject: base)) }
        base["acls"] = []
        base["grants"] = [["src": ["*"], "dst": ["*"], "ip": ["*"]]]
        #expect(throws: (any Error).self) { try compile(base: JSONSerialization.data(withJSONObject: base)) }
        #expect(throws: (any Error).self) { try compile(base: try compile().candidate) }
        #expect(throws: (any Error).self) { try compile(base: Data("{}".utf8)) }
    }

    @Test func testRejectsUnrelatedBaseFieldsAndOmittedClosedFields() throws {
        var base = try #require(JSONSerialization.jsonObject(with: Compiler.fixturePolicy) as? [String: Any])
        base["autoApprovers"] = ["routes": ["0.0.0.0/0": ["tag:demo-client"]]]
        #expect(throws: (any Error).self) { try compile(base: JSONSerialization.data(withJSONObject: base)) }
        base.removeValue(forKey: "autoApprovers")
        base.removeValue(forKey: "acls")
        #expect(throws: (any Error).self) { try compile(base: JSONSerialization.data(withJSONObject: base)) }
    }

    @Test func testBaseWhitespaceAndObjectKeyOrderAreNotSignificant() throws {
        let base = Data(#" { "tests": [], "tagOwners": {"tag:demo-client":["autogroup:admin"]}, "ssh":[], "grants":[], "acls":[] } "#.utf8)
        #expect((try compile(base: base).candidate) == (try compile().candidate))
    }

    @Test func testRejectsDuplicateObjectKeysAtEveryLevel() throws {
        let text = String(decoding: Compiler.example, as: UTF8.self)
        rejected(Data(text.replacingOccurrences(of: "\"version\": 1", with: "\"version\":1,\"version\":1").utf8))
        rejected(Data(text.replacingOccurrences(of: "\"ports\":[443]", with: "\"ports\":[443],\"ports\":[443]").utf8))
        let duplicateBase = Data(#"{"acls":[],"acls":[],"grants":[],"ssh":[],"tagOwners":{"tag:demo-client":["autogroup:admin"]},"tests":[]}"#.utf8)
        #expect(throws: (any Error).self) { try compile(base: duplicateBase) }
    }

    @Test func testRejectsUnknownFieldsAndOperations() throws {
        rejected(try proposal { $0["execute"] = "tailscale up" })
        rejected(try proposal { $0["tagOwners"] = ["tag:workload-demo-api": ["*"]] })
        rejected(try changedRow("grants") { $0["app"] = ["capability": [:]] })
        rejected(try changedRow("tests") { $0["accept"] = ["*:*"] })
        rejected(try changedRow("grants") { $0.removeValue(forKey: "ports") })
    }

    @Test func testRejectsExistingTagsAndOutsideNamespace() throws {
        for tag in ["tag:demo-client", "tag:prod", "tag:workload-", "tag:workload-A", "tag:workload-a-", "tag:workload-a_b", "tag:workload-" + String(repeating: "a", count: 33)] {
            rejected(try proposal { $0["tag"] = tag })
        }
    }

    @Test func testRejectsWildcardsAndReversedGrantDirection() throws {
        for src in ["*", "autogroup:member", "100.64.0.1", "tag:workload-demo-api"] {
            rejected(try changedRow("grants") { $0["src"] = src })
        }
        for dst in ["*", "tag:demo-client", "tag:other", "0.0.0.0/0"] {
            rejected(try changedRow("grants") { $0["dst"] = dst })
        }
        rejected(try changedRow("grants") { $0["src"] = ["tag:demo-client"] })
    }

    @Test func testRejectsUnsupportedProtocolAndPortTypes() throws {
        for proto in ["*", "icmp", "TCP", "tcp:*"] {
            rejected(try changedRow("grants") { $0["protocol"] = proto })
        }
        for ports: Any in [[0], [-1], [65536], [443, 443], [], ["443"], ["*"], ["1-65535"], [true], [443.5], "443", Array(1...17)] {
            rejected(try changedRow("grants") { $0["ports"] = ports })
        }
    }

    @Test func testRejectsFalseOrIncompleteAllowAssertions() throws {
        for allowed in [[22], [], [443, 8443]] {
            rejected(try changedRow("tests") { $0["allow"] = allowed })
        }
        rejected(try changedRow("tests") { $0["protocol"] = "udp" })
        rejected(try changedRow("tests") { $0["src"] = "*" })
        rejected(try changedRow("tests") { $0["dst"] = "tag:other" })
        rejected(try proposal { $0["tests"] = [] })
    }

    @Test func testRequiresNonemptyDistinctDeniedPortsDisjointFromAllow() throws {
        for denied in [[], [443], [22, 443], [22, 22]] {
            rejected(try changedRow("tests") { $0["deny"] = denied })
        }
        rejected(try changedRow("tests") { $0.removeValue(forKey: "deny") })
    }

    @Test func testRejectsDuplicateGrantOrAssertionRows() throws {
        rejected(try proposal { root in
            root["grants"] = (root["grants"] as! [[String: Any]]) + (root["grants"] as! [[String: Any]])
            root["tests"] = (root["tests"] as! [[String: Any]]) + (root["tests"] as! [[String: Any]])
        })
        rejected(try proposal { $0["grants"] = [] })
    }

    @Test func testRejectsUntrustedVMAndUnknownEnrollmentModes() throws {
        for vm in ["other-vm", "demo-vm ", "https://demo-vm", "$(whoami)"] {
            rejected(try proposal { $0["vm"] = vm })
        }
        for mode in ["auto", "browser+key", "KEY", ""] {
            rejected(try proposal { $0["mode"] = mode })
        }
    }

    @Test func testRejectsEscapesUnicodeAndControlCharacters() throws {
        let text = String(decoding: Compiler.example, as: UTF8.self)
        rejected(Data(text.replacingOccurrences(of: "version", with: #"\u0076ersion"#).utf8))
        rejected(Data(text.replacingOccurrences(of: "demo-vm", with: "demo-vm\u{202E}").utf8))
        rejected(Data(text.replacingOccurrences(of: "demo-vm", with: "demo-νm").utf8))
        rejected(Data(text.replacingOccurrences(of: "demo-vm", with: "demo\nvm").utf8))
        rejected(Data([0xEF, 0xBB, 0xBF]) + Compiler.example)
    }

    @Test func testRejectsNonStrictJSONAndMalformedTokens() {
        let text = String(decoding: Compiler.example, as: UTF8.self)
        for version in ["1.0", "1e0", "01", "true", "null", "-0", "9999999999999999999999"] {
            rejected(Data(text.replacingOccurrences(of: "\"version\": 1", with: "\"version\": " + version).utf8))
        }
        for document in [text + "{}", text + "// comment", text.replacingOccurrences(of: "[443]", with: "[443,]"), "null", "[]", "{", "", "{\"a\":tru}", "{\"a\":nul}", "{\"a\":fal}"] {
            rejected(Data(document.utf8))
        }
    }

    @Test func testInputBoundsRejectOversizeDepthAndLongStrings() throws {
        rejected(Data(repeating: 32, count: 16_385))
        rejected(Data((String(repeating: "[", count: 14) + "0" + String(repeating: "]", count: 14)).utf8))
        rejected(try proposal { $0["vm"] = String(repeating: "a", count: 129) })
        rejected(Data(("[" + Array(repeating: "0", count: 1_024).joined(separator: ",") + "]").utf8))
    }

    @Test func testErrorsDoNotEchoProposalText() throws {
        let secretLikeText = "do-not-log-untrusted-content"
        let data = try proposal { $0["execute"] = secretLikeText }
        #expect(throws: PolicyError.invalidProposal) {
            try compile(data)
        }
        do {
            _ = try compile(data)
            Issue.record("Expected invalid proposal to throw")
        } catch {
            #expect(!error.localizedDescription.contains(secretLikeText))
        }
    }

    @Test func testCheckedInExamplesMatchCompilerContract() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let browser = try Data(contentsOf: root.appendingPathComponent("Examples/browser.json"))
        let key = try Data(contentsOf: root.appendingPathComponent("Examples/key.json"))
        #expect((try compile(browser).candidate) == (try compile().candidate))
        #expect((try compile(key).mode) == ("key"))
    }
}
