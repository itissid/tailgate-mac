import Foundation
import Testing
@testable import TailgateLive

private actor ScriptedWire: HTTPTransport {
    private var results: [Result<HTTPResult,Error>]
    private(set) var requests = [URLRequest]()
    private let beforeTokenReturn: (@MainActor @Sendable () -> Void)?
    init(_ results: [Result<HTTPResult,Error>], beforeTokenReturn: (@MainActor @Sendable () -> Void)? = nil) { self.results = results; self.beforeTokenReturn = beforeTokenReturn }
    @MainActor func sendWrite(_ request: URLRequest, limit: Int, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> HTTPResult {
        do { try beforeDispatch() } catch { throw TailnetAPIError.notDispatched }
        return try await send(request, limit: limit)
    }
    func send(_ request: URLRequest, limit: Int) async throws -> HTTPResult {
        requests.append(request)
        guard !results.isEmpty else { throw TestFault.offline }
        let response = try results.removeFirst().get()
        if request.url?.path == "/api/v2/oauth/token", let hook = beforeTokenReturn { await hook() }
        return response
    }
}
private enum TestFault: Error { case offline, invalidated }
@MainActor private final class ApprovalState { var current = true; var guardCalls = 0 }
private func reply(_ body: String = "", status: Int = 200, headers: [String:String] = [:]) -> Result<HTTPResult,Error> {
    .success(HTTPResult(status: status, headers: headers, body: Data(body.utf8)))
}
private let token = reply(#"{"access_token":"fake-token","token_type":"Bearer","expires_in":3600}"#)
private let credential = OAuthCredential(clientID: "demo-client", secret: "fake-secret-never-live")
private let candidate = Data(#"{"acls":[],"grants":[],"tests":[]}"#.utf8)
private let policyHeaders = ["etag":"\"v1\"", "content-type":"application/hujson; charset=utf-8"]

struct TransportTests {
    @Test func rejectUnpinnedTailnetIdentifiers() {
        for input in ["-", "", "a", "https://other.example", "foo/bar", "foo%2fbar", "foo?x=1", "foo#x", "foo\r\nx:y", "a..b", " foo", "éxample.com", String(repeating:"a",count:254)] {
            #expect(throws: TailnetAPIError.invalidConfiguration) { try TailnetAPI(tailnet: input) }
        }
        #expect(throws: Never.self) { _ = try TailnetAPI(tailnet: "example.com") }
    }
    @Test func strictStrongETags() {
        for etag in ["", "*", "W/\"v1\"", "v1", "\"\"", "\"v1\", \"v2\"", "\"x\r\ny\"", "\"a b\"", String(repeating:"x",count:300)] { #expect(!TailnetAPI.isStrongETag(etag)) }
        #expect(TailnetAPI.isStrongETag("\"opaque-v1\""))
    }
    @Test func getPreservesRawBytesAndPinsOrigin() async throws {
        let hujson = "{ // preserve comment\n \"acls\": [], }"
        let wire = ScriptedWire([token, reply(hujson, headers: policyHeaders)])
        let snapshot = try await TailnetAPI(tailnet:"example.com",transport:wire).getPolicy(using:credential)
        #expect(snapshot.bytes == Data(hujson.utf8)); #expect(snapshot.etag == "\"v1\"")
        let requests = await wire.requests
        #expect(requests.count == 2)
        #expect(requests[0].url?.absoluteString == "https://api.tailscale.com/api/v2/oauth/token")
        let form = String(decoding: try #require(requests[0].httpBody), as:UTF8.self)
        #expect(form.contains("scope=policy_file%3Aread%20devices%3Acore%3Aread%20devices%3Aposture_attributes%3Aread"))
        #expect(requests[1].url?.absoluteString == "https://api.tailscale.com/api/v2/tailnet/example.com/acl")
        #expect(requests[1].value(forHTTPHeaderField:"Authorization") == "Bearer fake-token")
        #expect(requests[1].value(forHTTPHeaderField:"Accept") == "application/hujson")
    }
    @Test func readRejectsWeakMissingETagWrongMediaOrEmptyBody() async throws {
        for (body,headers) in [("{}",["etag":"W/\"v1\"","content-type":"application/hujson"]),("{}",["content-type":"application/hujson"]),("{}",["etag":"\"v1\"","content-type":"text/html"]),("",policyHeaders)] {
            let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply(body,headers:headers)]))
            await #expect(throws:TailnetAPIError.invalidResponse) { try await api.getPolicy(using:credential) }
        }
    }
    @Test func validationSubmitsCompleteExactCandidate() async throws {
        for body in ["", "{}", #"{"message":"","data":[]}"#] {
            let wire = ScriptedWire([token,reply(body)])
            try await TailnetAPI(tailnet:"example.com",transport:wire).validate(candidate,using:credential)
            let request = try #require(await wire.requests.last)
            #expect(request.url?.path.hasSuffix("/acl/validate") == true); #expect(request.httpMethod == "POST")
            #expect(request.httpBody == candidate); #expect(request.value(forHTTPHeaderField:"Content-Type") == "application/hujson")
        }
    }
    @Test func validationFailsClosedOnDiagnosticsEvenHTTP200() async throws {
        for body in [#"{"message":"secret","data":[]}"#, #"{"data":[{"errors":["secret"]}]}"#, #"{"warnings":[]}"#, "null", "[]", "false", #"{"data":null}"#, #"{"message":"bad","message":""}"#, #"{"m\u0065ssage":"bad","message":""}"#, " ", "<html>secret</html>"] {
            let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply(body)]))
            await #expect(throws:TailnetAPIError.validationFailed) { try await api.validate(candidate,using:credential) }
        }
    }
    @Test func applySendsExactIfMatchAndWriteScope() async throws {
        let wire = ScriptedWire([token,reply(String(decoding:candidate,as:UTF8.self),headers:policyHeaders)])
        let result = try await TailnetAPI(tailnet:"example.com",transport:wire).apply(candidate,ifMatch:"\"old\"",using:credential,beforeDispatch: {})
        #expect(result.etag == "\"v1\"")
        let requests = await wire.requests
        #expect(requests[1].httpBody == candidate); #expect(requests[1].value(forHTTPHeaderField:"If-Match") == "\"old\"")
        #expect(String(decoding:try #require(requests[0].httpBody),as:UTF8.self).contains("scope=policy_file%20devices%3Acore%3Aread%20devices%3Aposture_attributes"))
    }
    @Test func invalidWriteNeverFetchesToken() async throws {
        let wire = ScriptedWire([]), api = try TailnetAPI(tailnet:"example.com",transport:wire)
        await #expect(throws:TailnetAPIError.invalidInput) { try await api.apply(candidate,ifMatch:"*",using:credential,beforeDispatch: {}) }
        await #expect(throws:TailnetAPIError.invalidInput) { try await api.validate(Data("[]".utf8),using:credential) }
        await #expect(throws:TailnetAPIError.invalidInput) { try await api.apply(Data(repeating:123,count:1_048_577),ifMatch:"\"x\"",using:credential,beforeDispatch: {}) }
        #expect(await wire.requests.isEmpty)
    }
    @MainActor @Test func tokenAcquisitionInvalidationPreventsDispatch() async throws {
        let state = ApprovalState()
        let wire = ScriptedWire([token,reply("{}",headers:policyHeaders)],beforeTokenReturn: { state.current = false })
        let api = try TailnetAPI(tailnet:"example.com",transport:wire)
        await #expect(throws:TailnetAPIError.notDispatched) {
            try await api.apply(candidate,ifMatch:"\"old\"",using:credential,beforeDispatch: {
                state.guardCalls += 1
                guard state.current else { throw TestFault.invalidated }
            })
        }
        #expect(state.guardCalls == 1)
        let requests = await wire.requests
        #expect(requests.count == 1)
        #expect(requests[0].url?.path == "/api/v2/oauth/token")
        #expect(!requests.contains(where: { $0.url?.path.hasSuffix("/acl") == true && $0.httpMethod == "POST" }))
    }
    @MainActor @Test func productionDispatchGuardFailureNeverResumesPolicyTask() async throws {
        let request = URLRequest(url:URL(string:"https://api.tailscale.com/api/v2/tailnet/example.com/acl")!)
        let operation = BoundedRequest(request:request,limit:4096)
        await #expect(throws:TailnetAPIError.notDispatched) {
            try await operation.runWrite(beforeDispatch: { throw TestFault.invalidated })
        }
    }
    @Test func inventoryContinuationHeadersAndPartialStatusAreRejected() async throws {
        for headers in [["link":"<https://api.tailscale.com/page2>; rel=next"],["content-range":"items 0-9/100"],["x-next-page":"2"],["x-continuation-token":"opaque"],["x-pagination-total":"100"],["Link":"anything"]] {
            let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply("{\"devices\":[]}",headers:headers)]))
            await #expect(throws:TailnetAPIError.invalidResponse) { try await api.devices(using:credential) }
        }
        let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply("{\"devices\":[]}",status:206)]))
        await #expect(throws:TailnetAPIError.rejected(206)) { try await api.devices(using:credential) }
    }
    @Test func staleWriteIsNeverRetried() async throws {
        let wire = ScriptedWire([token,reply("secret",status:412)])
        await #expect(throws:TailnetAPIError.stalePolicy) { try await TailnetAPI(tailnet:"example.com",transport:wire).apply(candidate,ifMatch:"\"v0\"",using:credential,beforeDispatch: {}) }
        #expect(await wire.requests.count == 2)
    }
    @Test func ambiguousWritesAreUnknownAndNeverRetried() async throws {
        let outcomes: [Result<HTTPResult,Error>] = [.failure(TestFault.offline),reply("error-secret",status:500),reply("",status:200),reply("{}",status:200,headers:["etag":"W/\"weak\"","content-type":"application/hujson"]),reply("",status:302),reply("",status:429)]
        for outcome in outcomes {
            let wire = ScriptedWire([token,outcome])
            await #expect(throws:TailnetAPIError.outcomeUnknown) { try await TailnetAPI(tailnet:"example.com",transport:wire).apply(candidate,ifMatch:"\"old\"",using:credential,beforeDispatch: {}) }
            #expect(await wire.requests.count == 2)
        }
    }
    @Test func rejectedWriteDoesNotEchoBody() async throws {
        let wire = ScriptedWire([token,reply("fake-secret-never-live",status:400)])
        do { _ = try await TailnetAPI(tailnet:"example.com",transport:wire).apply(candidate,ifMatch:"\"old\"",using:credential,beforeDispatch: {}); Issue.record("Expected rejection") }
        catch { #expect(error as? TailnetAPIError == .rejected(400)); #expect(!error.localizedDescription.contains("fake-secret")) }
    }
    @Test func oauthIsRedactedAndMalformedCredentialsNeverSend() async throws {
        #expect(!String(describing:credential).contains("fake-secret")); #expect(!String(reflecting:credential).contains("fake-secret"))
        #expect(!String(describing:Mirror(reflecting:credential).children.map{String(describing:$0.value)}).contains("fake-secret"))
        let wire = ScriptedWire([]), api = try TailnetAPI(tailnet:"example.com",transport:wire)
        await #expect(throws:TailnetAPIError.invalidInput) { try await api.getPolicy(using:OAuthCredential(clientID:"id",secret:"bad\nsecret")) }
        #expect(await wire.requests.isEmpty)
    }
    @Test func rejectUnsupportedTokensBeforePolicyRequest() async throws {
        for body in [#"{"access_token":"unsafe\nheader","token_type":"Bearer","expires_in":3600}"#,#"{"access_token":"x","token_type":"Basic","expires_in":3600}"#,#"{"access_token":"x","token_type":"Bearer","expires_in":true}"#,#"{"access_token":"x","token_type":"Bearer","expires_in":3601}"#,#"{"access_token":"x","token_type":"Bearer","expires_in":3600,"scope":"all"}"#,#"{"access_token":"x","access_token":"y","token_type":"Bearer","expires_in":3600}"#] {
            let wire = ScriptedWire([reply(body)]), api = try TailnetAPI(tailnet:"example.com",transport:wire)
            await #expect(throws:TailnetAPIError.invalidResponse) { try await api.getPolicy(using:credential) }
            #expect(await wire.requests.count == 1)
        }
    }
    @Test func inventoryIsCompleteOrRejected() async throws {
        let key = String(repeating:"a",count:64)
        let row = #"{"id":"123","nodeId":"n123CNTRL","nodeKey":"nodekey:\#(key)","authorized":true,"tags":["tag:api"],"name":"api.example.ts.net","hostname":"api"}"#
        let wire = ScriptedWire([token,reply("{\"devices\":[\(row)]}")])
        let devices = try await TailnetAPI(tailnet:"example.com",transport:wire).devices(using:credential)
        #expect(devices.count == 1); #expect(devices[0].nodeKey == "nodekey:" + key); #expect(devices[0].authorized); #expect(devices[0].tags == ["tag:api"])
        let requests = await wire.requests
        #expect(requests[1].url?.query == "fields=all"); #expect(requests[1].value(forHTTPHeaderField:"Accept") == "application/json")
        #expect(String(decoding:try #require(requests[0].httpBody),as:UTF8.self).hasSuffix("scope=devices%3Acore%3Aread"))
        let untaggedBare = row.replacingOccurrences(of: "\"tags\":[\"tag:api\"],", with: "").replacingOccurrences(of: "nodekey:", with: "")
        let untagged = try await TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply("{\"devices\":[\(untaggedBare)]}")])).devices(using:credential)
        #expect(untagged[0].tags.isEmpty); #expect(untagged[0].nodeKey == "nodekey:" + key)
        for bad in ["{\"devices\":[\(row.replacingOccurrences(of: "[\"tag:api\"]", with: "null"))]}", "{}", "{\"devices\":[],\"next\":\"page2\"}","{\"devices\":[],\"devices\":[\(row)]}","{\"devices\":[\(row),\(row)]}","{\"devices\":[{}]}","{\"devices\":[\(row.replacingOccurrences(of:"true",with:"1"))]}","{\"devices\":[\(row.replacingOccurrences(of:"nodekey:" + key,with:""))]}"] {
            let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,reply(bad)]))
            await #expect(throws:TailnetAPIError.invalidResponse) { try await api.devices(using:credential) }
        }
    }
    @Test func oversizedResponsesFailClosed() async throws {
        let response = HTTPResult(status:200,headers:policyHeaders,body:Data(repeating:123,count:TailnetAPI.maxResponse + 1))
        let api = try TailnetAPI(tailnet:"example.com",transport:ScriptedWire([token,.success(response)]))
        await #expect(throws:TailnetAPIError.unavailable) { try await api.getPolicy(using:credential) }
    }
    @Test func ephemeralSessionDisablesAmbientState() {
        let cfg = BoundedRequest.configuration()
        #expect(cfg.urlCache == nil); #expect(cfg.urlCredentialStorage == nil); #expect(cfg.httpCookieStorage == nil)
        #expect(!cfg.httpShouldSetCookies); #expect(!cfg.waitsForConnectivity)
        #expect(cfg.connectionProxyDictionary?.isEmpty == true); #expect(cfg.timeoutIntervalForResource == 35)
    }
}
