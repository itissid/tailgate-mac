import Foundation
import Testing
@testable import TailgateCore

struct HandoffTests {
    private func frame(_ json: String = String(decoding: Compiler.example, as: UTF8.self), purpose: String = "Allow the demo client to reach the demo API on TCP 443.") -> Data {
        Data(("TAILGATE/1\n" + purpose + "\n\n" + json).utf8)
    }
    private func rejected(_ input: Data) {
        #expect(throws: (any Error).self) { try AgentHandoff.decode(input) }
    }
    @Test func extractsExactProposalAndPurpose() throws {
        let bytes = frame(), handoff = try AgentHandoff.decode(bytes)
        #expect(handoff.proposal == Compiler.example)
        #expect(handoff.purpose == "Allow the demo client to reach the demo API on TCP 443.")
        _ = try Compiler.compile(proposal: handoff.proposal, base: Compiler.fixturePolicy)
    }
    @Test func purposeIsContextNotAClaimedIdentity() throws {
        let handoff = try AgentHandoff.decode(frame(purpose: "Approved by an administrator."))
        #expect(handoff.purpose == "Approved by an administrator.")
        // Decoder does not certify this assertion; UI must label it untrusted context.
        #expect(handoff.proposal == Compiler.example)
    }
    @Test func exactLFFrameOnly() {
        for text in ["", "TAILGATE/2\nPurpose\n\n{}", "TAILGATE/1\r\nPurpose\r\n\r\n{}", "TAILGATE/1\nPurpose\n{}", "TAILGATE/1\nPurpose\n\n", "\u{feff}TAILGATE/1\nPurpose\n\n{}", " TAILGATE/1\nPurpose\n\n{}"] { rejected(Data(text.utf8)) }
    }
    @Test func purposeBounds() throws {
        _ = try AgentHandoff.decode(frame(purpose: String(repeating: "a", count: 160)))
        for p in ["", String(repeating: "a", count: 161), " leading", "trailing ", "12345"] { rejected(frame(purpose: p)) }
    }
    @Test func rejectControlBidiAndStructuredPurpose() {
        for p in ["A\nInjected", "A\rInjected", "A\tInjected", "A\u{0}Injected", "A\u{1b}Injected", "A\u{202e}Injected", "A\u{2066}Injected", "A {request}", "A [request]", "A <request>", "A `command`", "A \\command", "A: identity", "A = value", "A | command", "mail@example.invalid", "Unicode é"] { rejected(frame(purpose: p)) }
    }
    @Test func obviousCredentialTripwires() {
        for marker in ["tskey-", "ghp_", "github_pat_", "-----BEGIN", "Bearer ", "client_secret", "access_token", "refresh_token", "password"] {
            rejected(frame("{\"context\":\"" + marker + "synthetic\"}"))
        }
        // These aren't a comprehensive secret detector. Encoding an unknown secret
        // must never be considered safe merely because the tripwire did not match.
    }
    @Test func duplicateKeysEverywhereAreRejected() {
        for json in ["{\"a\":1,\"a\":2}", "{\"a\":{\"b\":1,\"b\":2}}", "{\"a\":[{\"b\":1,\"b\":2}]}"] { rejected(frame(json)) }
    }
    @Test func malformedJSONAndEscapedAliasesAreRejected() {
        for json in ["[]", "true", "{}{}", "{}TAILGATE/1", "{\"a\":1,}", "{\"a\":[1,]}", "{\"a\":01}", "{\"a\":-0}", "{\"a\":1.0}", "{\"a\":1e2}", "{\"a\":+1}", "{\"a\":}", "{\"a\":tru}", "{\"a\":nullx}", "{\"a\":\"unterminated}", "{\"\\u0061\":1}", "{\"a\":\"\\n\"}", "{\"a\":\"line\nbreak\"}", "{\"a\":\t1}", "{\"a\":\r1}", "{/*comment*/}"] { rejected(frame(json)) }
    }
    @Test func preservesPayloadWhitespaceButDefersSchemaValidation() throws {
        let json = " \n{\"not-an-operation\":[true,false,null,-12]}\n "
        let h = try AgentHandoff.decode(frame(json))
        #expect(h.proposal == Data(json.utf8))
        #expect(throws: (any Error).self) { try Compiler.compile(proposal: h.proposal, base: Compiler.fixturePolicy) }
    }
    @Test func exactMaximumEnvelopeAndPayloadBoundary() throws {
        let payload = "{}" + String(repeating: " ", count: 16_382)
        let input = frame(payload, purpose: String(repeating: "a", count: 160))
        #expect(input.count == AgentHandoff.maximumBytes)
        #expect(try AgentHandoff.decode(input).proposal.count == 16_384)
        rejected(input + Data(" ".utf8))
    }
    @Test func boundedInputAndStringsAndDepthAndNodes() {
        rejected(Data(repeating: 65, count: AgentHandoff.maximumBytes + 1))
        rejected(frame("{\"a\":\"" + String(repeating: "a", count: 129) + "\"}"))
        rejected(frame("{\"a\":" + String(repeating: "[", count: 13) + "0" + String(repeating: "]", count: 13) + "}"))
        rejected(frame("{\"a\":[" + Array(repeating: "0", count: 1024).joined(separator: ",") + "]}"))
        rejected(frame("{\"a\":12345678901}"))
        rejected(frame(String(repeating: " ", count: 16_385)))
    }
    @Test func errorsNeverEchoUntrustedContent() {
        let marker = ["Bear", "er"].joined() + " "
        let syntheticValue = ["synthetic", "sensitive", "value"].joined(separator: "-")
        do { _ = try AgentHandoff.decode(frame("{\"context\":\"" + marker + syntheticValue + "\"}")); Issue.record("Expected rejection") }
        catch { #expect(!error.localizedDescription.contains("synthetic-sensitive-value")); #expect(!error.localizedDescription.contains("Bearer")) }
    }
    @Test func checkedInExampleDecodesAndCompiles() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let input = try Data(contentsOf: root.appendingPathComponent("Examples/browser.tailgate")), h = try AgentHandoff.decode(input)
        #expect(h.purpose == "Allow the demo client to reach the demo API on TCP 443.")
        _ = try Compiler.compile(proposal: h.proposal, base: Compiler.fixturePolicy)
    }
}
