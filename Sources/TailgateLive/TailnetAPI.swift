import Foundation
import Security

/// Provisioned only through the trusted Mac UI; never serialize or return this to a proposer.
public final class OAuthCredential: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    fileprivate let clientID: String
    fileprivate let secret: String
    public init(clientID: String, secret: String) { self.clientID = clientID; self.secret = secret }
    public var description: String { "OAuthCredential(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["credential": "<redacted>"]) }
}

public struct PolicySnapshot: Sendable {
    public let bytes: Data
    public let etag: String
    public init(bytes: Data, etag: String) { self.bytes = bytes; self.etag = etag }
}

public struct TailnetDevice: Sendable, Equatable {
    public let id: String
    public let nodeID: String
    public let nodeKey: String
    public let authorized: Bool
    public let tags: [String]
    public let name: String
    public let hostname: String
}

public enum TailnetAPIError: Error, Equatable, LocalizedError {
    case invalidConfiguration, invalidInput, credentialRejected, unavailable, invalidResponse
    case validationFailed, stalePolicy, rejected(Int), outcomeUnknown, notDispatched
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Use an explicit tailnet identifier, not an alias or URL."
        case .invalidInput: return "The request is outside the supported bounds."
        case .credentialRejected: return "The scoped OAuth credential was rejected."
        case .unavailable: return "The Tailscale request did not complete. No automatic retry was made."
        case .invalidResponse: return "Tailscale returned an unsupported or incomplete response."
        case .validationFailed: return "Tailscale did not validate the candidate policy and tests."
        case .stalePolicy: return "The policy changed. Re-fetch and review; do not retry this approval."
        case .rejected(let status): return "Tailscale rejected the request (HTTP \(status))."
        case .outcomeUnknown: return "Policy write outcome unknown. Reconcile with a read; never automatically repeat the write."
        case .notDispatched: return "The final approval guard failed. The policy POST was not dispatched."
        }
    }
}

/// Fixed-origin Tailscale operations only. This is not an agent-callable executor.
/// The caller must enforce the signed, consumed, durable per-plan approval before `apply`.
public struct TailnetAPI: Sendable {
    public let tailnet: String
    private let transport: any HTTPTransport
    static let origin = "https://api.tailscale.com"
    static let maxBody = 1_048_576
    static let maxResponse = 8_388_608
    public init(tailnet: String) throws { try self.init(tailnet: tailnet, transport: PinnedHTTPS()) }
    init(tailnet: String, transport: any HTTPTransport) throws {
        let bytes = Array(tailnet.utf8)
        guard (3...253).contains(bytes.count), tailnet != "-", !tailnet.hasPrefix("."), !tailnet.hasSuffix("."),
              bytes.allSatisfy({ (97...122).contains($0) || (65...90).contains($0) || (48...57).contains($0) || [45,46,64].contains($0) }),
              !tailnet.contains(".."), tailnet.filter({ $0 == "@" }).count <= 1 else { throw TailnetAPIError.invalidConfiguration }
        self.tailnet = tailnet; self.transport = transport
    }
    public func getPolicy(using credential: OAuthCredential) async throws -> PolicySnapshot {
        let response = try await authorized(method: "GET", suffix: "acl", body: nil, credential: credential)
        try checkReadStatus(response.status)
        return try snapshot(response)
    }
    /// Sends the exact complete candidate policy, not the diff or a tests-only array.
    public func validate(_ candidate: Data, using credential: OAuthCredential) async throws {
        try checkCandidate(candidate)
        let response = try await authorized(method: "POST", suffix: "acl/validate", body: candidate, credential: credential)
        guard response.status == 200 else {
            if [401,403].contains(response.status) { throw TailnetAPIError.credentialRejected }
            throw TailnetAPIError.validationFailed
        }
        if response.body.isEmpty { return }
        // Different official clients document empty bytes or an empty error envelope.
        // Reject unknown fields, populated diagnostics, nulls, malformed JSON, and nonempty data.
        guard let obj = try? Self.object(response.body),
              Set(obj.keys).isSubset(of: ["message", "data"]),
              obj["message"] == nil || (obj["message"] as? String) == "",
              obj["data"] == nil || (obj["data"] as? [Any])?.isEmpty == true else { throw TailnetAPIError.validationFailed }
    }
    public func apply(_ candidate: Data, ifMatch etag: String, using credential: OAuthCredential, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> PolicySnapshot {
        try checkCandidate(candidate)
        guard Self.isStrongETag(etag) else { throw TailnetAPIError.invalidInput }
        let token = try await accessToken(credential, scope: "policy_file devices:core:read devices:posture_attributes")
        let request = makeRequest(method: "POST", suffix: "acl", body: candidate, etag: etag, token: token)
        let response: HTTPResult
        do {
            // The production transport runs the final guard on MainActor immediately
            // before URLSessionDataTask.resume(), after all token acquisition/hops.
            response = try await transport.sendWrite(request, limit: Self.maxResponse, beforeDispatch: beforeDispatch)
            guard response.body.count <= Self.maxResponse else { throw TailnetAPIError.outcomeUnknown }
        } catch TailnetAPIError.notDispatched { throw TailnetAPIError.notDispatched }
        catch { throw TailnetAPIError.outcomeUnknown }
        if response.status == 412 { throw TailnetAPIError.stalePolicy }
        if [400,401,403,404,405,409,422].contains(response.status) { throw TailnetAPIError.rejected(response.status) }
        guard response.status == 200 else { throw TailnetAPIError.outcomeUnknown }
        do { return try snapshot(response) }
        catch { throw TailnetAPIError.outcomeUnknown }
    }
    private func inventoryRows(using credential: OAuthCredential) async throws -> [[String: Any]] {
        let response = try await authorized(method: "GET", suffix: "devices?fields=all", body: nil, credential: credential, inventory: true)
        try checkReadStatus(response.status)
        guard !response.headers.keys.contains(where: Self.continuationHeader) else { throw TailnetAPIError.invalidResponse }
        guard let root = try? Self.object(response.body),
              Set(root.keys) == ["devices"], let rows = root["devices"] as? [[String: Any]], rows.count <= 10_000 else { throw TailnetAPIError.invalidResponse }
        return rows
    }
    /// Private read-only inventory for the operator-gated point disclosure. Never
    /// exposes this whole inventory to a caller or requests a writer OAuth scope.
    func lookupInventory(using credential: OAuthCredential) async throws -> [LookupDevice] {
        let rows = try await inventoryRows(using: credential)
        var result = [LookupDevice](), ids = Set<String>(), keys = Set<String>()
        for row in rows {
            let tagValue: Any = row["tags"] ?? [String]()
            guard let id = row["id"] as? String, Self.asciiID(id),
                  let rawKey = row["nodeKey"] as? String, let key = Self.normalizedNodeKey(rawKey),
                  let auth = row["authorized"] as? NSNumber, CFGetTypeID(auth) == CFBooleanGetTypeID(),
                  let hostname = row["hostname"] as? String, Self.safeText(hostname),
                  let tags = tagValue as? [String], tags.count <= 64, Set(tags).count == tags.count, tags.allSatisfy(Self.tag),
                  ids.insert(id).inserted, keys.insert(key).inserted else { throw TailnetAPIError.invalidResponse }
            let addresses = row["addresses"] as? [String]
            // Missing or malformed addresses cannot be disclosed when requested.
            // Do not fail a name-only lookup because an unselected device has no IP.
            result.append(LookupDevice(id: id, nodeKey: key, hostname: hostname, authorized: auth.boolValue, tags: tags, addresses: addresses))
        }
        return result
    }
    public func devices(using credential: OAuthCredential) async throws -> [TailnetDevice] {
        let rows = try await inventoryRows(using: credential)
        var result = [TailnetDevice](), ids = Set<String>(), nodes = Set<String>(), keys = Set<String>()
        for row in rows {
            // Official device fixtures omit `tags` for user-owned/untagged nodes.
            // Absence means [], but explicit null or a wrong type is never accepted.
            let tagValue: Any = row["tags"] ?? [String]()
            guard let id = row["id"] as? String, Self.asciiID(id),
                  let nodeID = row["nodeId"] as? String, Self.asciiID(nodeID),
                  let rawKey = row["nodeKey"] as? String, let nodeKey = Self.normalizedNodeKey(rawKey),
                  let rawAuth = row["authorized"] as? NSNumber, CFGetTypeID(rawAuth) == CFBooleanGetTypeID(),
                  let tags = tagValue as? [String], tags.count <= 64, Set(tags).count == tags.count, tags.allSatisfy(Self.tag),
                  let name = row["name"] as? String, Self.safeText(name),
                  let hostname = row["hostname"] as? String, Self.safeText(hostname),
                  ids.insert(id).inserted, nodes.insert(nodeID).inserted, keys.insert(nodeKey).inserted else { throw TailnetAPIError.invalidResponse }
            result.append(TailnetDevice(id: id, nodeID: nodeID, nodeKey: nodeKey, authorized: rawAuth.boolValue, tags: tags.sorted(), name: name, hostname: hostname))
        }
        return result
    }
    private static func continuationHeader(_ name: String) -> Bool {
        let key = name.lowercased()
        return ["link", "content-range", "x-next-page", "x-next-cursor", "x-continuation-token", "continuation-token", "next-page", "next-cursor", "x-total-count", "x-total-pages", "x-page", "x-page-size", "x-per-page"].contains(key)
            || key.contains("pagination") || key.contains("continuation") || key.hasPrefix("x-next-")
    }
    private static func object(_ bytes: Data) throws -> [String:Any] {
        var scan = UniqueJSON(bytes: Array(bytes)); try scan.parse()
        guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String:Any] else { throw TailnetAPIError.invalidResponse }
        return object
    }
    static func isStrongETag(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (3...258).contains(bytes.count), bytes.first == 34, bytes.last == 34 else { return false }
        return bytes.dropFirst().dropLast().allSatisfy { $0 == 33 || (35...126).contains($0) }
    }
    private static func asciiID(_ value: String) -> Bool {
        (1...128).contains(value.utf8.count) && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,95].contains($0) }
    }
    private static func normalizedNodeKey(_ value: String) -> String? {
        let suffix = value.hasPrefix("nodekey:") ? String(value.dropFirst(8)) : value
        guard suffix.utf8.count == 64 && suffix.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        return "nodekey:" + suffix
    }
    private static func tag(_ value: String) -> Bool {
        value.hasPrefix("tag:") && (5...100).contains(value.utf8.count) && value.dropFirst(4).utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
    private static func safeText(_ value: String) -> Bool {
        (1...253).contains(value.utf8.count) && value.utf8.allSatisfy { (33...126).contains($0) }
    }
    private func checkCandidate(_ candidate: Data) throws {
        guard (2...Self.maxBody).contains(candidate.count), String(data: candidate, encoding: .utf8) != nil,
              candidate.first(where: { ![9,10,13,32].contains($0) }) == 123 else { throw TailnetAPIError.invalidInput }
    }
    private func snapshot(_ response: HTTPResult) throws -> PolicySnapshot {
        guard response.body.count <= Self.maxBody, !response.body.isEmpty,
              String(data: response.body, encoding: .utf8) != nil,
              let etag = response.headers["etag"], Self.isStrongETag(etag),
              let type = response.headers["content-type"]?.split(separator: ";").first?.lowercased(),
              ["application/hujson", "application/json"].contains(type) else { throw TailnetAPIError.invalidResponse }
        return PolicySnapshot(bytes: response.body, etag: etag)
    }
    private func checkReadStatus(_ status: Int) throws {
        guard status == 200 else {
            if [401,403].contains(status) { throw TailnetAPIError.credentialRejected }
            throw TailnetAPIError.rejected(status)
        }
    }
    private func authorized(method: String, suffix: String, body: Data?, credential: OAuthCredential, inventory: Bool = false) async throws -> HTTPResult {
        let scope = inventory ? "devices:core:read" : "policy_file:read devices:core:read devices:posture_attributes:read"
        let token = try await accessToken(credential, scope: scope)
        let request = makeRequest(method: method, suffix: suffix, body: body, token: token, inventory: inventory)
        do {
            let response = try await transport.send(request, limit: Self.maxResponse)
            guard response.body.count <= Self.maxResponse else { throw TailnetAPIError.invalidResponse }
            return response
        } catch { throw TailnetAPIError.unavailable }
    }
    private func makeRequest(method: String, suffix: String, body: Data?, etag: String? = nil, token: String, inventory: Bool = false) -> URLRequest {
        let url = URL(string: Self.origin + "/api/v2/tailnet/" + tailnet + "/" + suffix)!
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 25)
        request.httpMethod = method; request.httpBody = body
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue(inventory ? "application/json" : "application/hujson", forHTTPHeaderField: "Accept")
        if body != nil { request.setValue("application/hujson", forHTTPHeaderField: "Content-Type") }
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-Match") }
        return request
    }
    private func accessToken(_ credential: OAuthCredential, scope: String) async throws -> String {
        guard (1...256).contains(credential.clientID.utf8.count), (1...4096).contains(credential.secret.utf8.count),
              [credential.clientID,credential.secret].allSatisfy({ $0.utf8.allSatisfy { (33...126).contains($0) } }) else { throw TailnetAPIError.invalidInput }
        var request = URLRequest(url: URL(string: Self.origin + "/api/v2/oauth/token")!, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 25)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let fields = [("grant_type","client_credentials"),("client_id",credential.clientID),("client_secret",credential.secret),("scope",scope)]
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        request.httpBody = Data(fields.map { $0.0 + "=" + $0.1.addingPercentEncoding(withAllowedCharacters: allowed)! }.joined(separator: "&").utf8)
        let response: HTTPResult
        do { response = try await transport.send(request, limit: 16_384) }
        catch { throw TailnetAPIError.unavailable }
        guard response.status == 200 else { throw TailnetAPIError.credentialRejected }
        guard response.body.count <= 16_384, let value = try? Self.object(response.body),
              let token = value["access_token"] as? String, (1...8192).contains(token.utf8.count),
              token.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95,126,43,47,61].contains($0) }),
              let type = value["token_type"] as? String, type.lowercased() == "bearer",
              let ttl = value["expires_in"] as? NSNumber, CFGetTypeID(ttl) != CFBooleanGetTypeID(),
              ttl.doubleValue.rounded(.towardZero) == ttl.doubleValue, (1...3600).contains(ttl.intValue) else { throw TailnetAPIError.invalidResponse }
        if let granted = value["scope"] {
            guard let granted = granted as? String, Set(granted.split(separator: " ")).isSubset(of: Set(scope.split(separator: " "))) else { throw TailnetAPIError.invalidResponse }
        }
        return token
    }
}

// Internal seams for deterministic no-network tests; not exported as a general request API.
struct HTTPResult: Sendable {
    let status: Int
    let headers: [String:String]
    let body: Data
}
protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest, limit: Int) async throws -> HTTPResult
    @MainActor func sendWrite(_ request: URLRequest, limit: Int, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> HTTPResult
}
private enum WireError: Error { case transport, oversized, response, redirect }

private struct PinnedHTTPS: HTTPTransport {
    @MainActor func sendWrite(_ request: URLRequest, limit: Int, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> HTTPResult {
        guard request.url?.scheme == "https", request.url?.host == "api.tailscale.com", request.url?.port == nil,
              request.url?.user == nil, request.url?.password == nil else { throw TailnetAPIError.notDispatched }
        let operation = BoundedRequest(request: request, limit: limit)
        return try await withTaskCancellationHandler(operation: {
            try await operation.runWrite(beforeDispatch: beforeDispatch)
        }, onCancel: { operation.cancel() })
    }
    func send(_ request: URLRequest, limit: Int) async throws -> HTTPResult {
        guard request.url?.scheme == "https", request.url?.host == "api.tailscale.com", request.url?.port == nil,
              request.url?.user == nil, request.url?.password == nil else { throw WireError.response }
        let operation = BoundedRequest(request: request, limit: limit)
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await operation.run()
        }, onCancel: { operation.cancel() })
    }
}

/// One ephemeral session/request, serial callbacks, bounded streaming. No application retry loop.
final class BoundedRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let request: URLRequest
    private let limit: Int
    private let lock = NSLock()
    private var task: URLSessionDataTask?
    private var cancelled = false
    private var writeRequest = false
    private var dispatched = false
    private var continuation: CheckedContinuation<HTTPResult, Error>?
    private var bytes = Data()
    private var response: HTTPURLResponse?
    private var failure: Error?
    private var session: URLSession?
    init(request: URLRequest, limit: Int) { self.request = request; self.limit = limit }
    static func configuration() -> URLSessionConfiguration {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil; cfg.urlCredentialStorage = nil; cfg.httpCookieStorage = nil
        cfg.httpShouldSetCookies = false; cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.connectionProxyDictionary = [:]; cfg.waitsForConnectivity = false
        cfg.timeoutIntervalForRequest = 25; cfg.timeoutIntervalForResource = 35
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        cfg.httpMaximumConnectionsPerHost = 1
        return cfg
    }
    func run() async throws -> HTTPResult {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); defer { lock.unlock() }
            guard !cancelled else { continuation.resume(throwing: WireError.transport); return }
            self.continuation = continuation
            let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
            let session = URLSession(configuration: Self.configuration(), delegate: self, delegateQueue: queue)
            self.session = session; let task = session.dataTask(with: request); self.task = task; task.resume()
        }
    }
    @MainActor func runWrite(beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> HTTPResult {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            guard !cancelled else { lock.unlock(); continuation.resume(throwing: TailnetAPIError.notDispatched); return }
            self.continuation = continuation; self.writeRequest = true
            let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
            let session = URLSession(configuration: Self.configuration(), delegate: self, delegateQueue: queue)
            self.session = session
            let task = session.dataTask(with: request); self.task = task
            lock.unlock()
            do {
                try Task.checkCancellation()
                try beforeDispatch()
                // No await, executor/actor hop or user callback between the guard
                // and resume. MainActor edits cannot interleave in this section.
                lock.lock()
                guard !cancelled, self.continuation != nil else { lock.unlock(); throw TailnetAPIError.notDispatched }
                dispatched = true; task.resume(); lock.unlock()
            } catch {
                lock.lock(); let pending = self.continuation; self.continuation = nil; self.task = nil; self.session = nil; lock.unlock()
                pending?.resume(throwing: TailnetAPIError.notDispatched)
                session.invalidateAndCancel()
            }
        }
    }
    func cancel() { lock.lock(); cancelled = true; let task = task; lock.unlock(); task?.cancel() }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        failure = WireError.redirect; completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil) // system TLS hostname and certificate validation
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.url == request.url else { failure = WireError.response; completionHandler(.cancel); return }
        guard response.expectedContentLength <= limit else { failure = WireError.oversized; completionHandler(.cancel); return }
        self.response = http; completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard data.count <= limit - bytes.count else { failure = WireError.oversized; dataTask.cancel(); return }
        bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock(); let neverDispatched = writeRequest && !dispatched; lock.unlock()
        let result: Result<HTTPResult, Error>
        if neverDispatched { result = .failure(TailnetAPIError.notDispatched) }
        else if error != nil || failure != nil { result = .failure(failure ?? WireError.transport) }
        else if let response {
            var headers = [String:String]()
            for (key,value) in response.allHeaderFields { headers[String(describing: key).lowercased()] = String(describing: value) }
            result = .success(HTTPResult(status: response.statusCode, headers: headers, body: bytes))
        } else { result = .failure(WireError.response) }
        lock.lock(); let continuation = continuation; self.continuation = nil; self.task = nil; self.session = nil; lock.unlock()
        continuation?.resume(with: result); session.finishTasksAndInvalidate()
    }
}

// JSONSerialization validates grammar, this bounded preflight rejects duplicate keys
// (including escaped aliases) rather than silently losing part of an inventory.
private struct UniqueJSON {
    let bytes: [UInt8]
    private var i = 0
    private var nodes = 0
    init(bytes: [UInt8]) { self.bytes = bytes }
    mutating func parse() throws {
        try value(depth: 0); whitespace()
        guard i == bytes.count else { throw TailnetAPIError.invalidResponse }
    }
    private mutating func whitespace() { while i < bytes.count, [9,10,13,32].contains(bytes[i]) { i += 1 } }
    private mutating func string() throws -> String {
        let start = i; guard take(34) else { throw TailnetAPIError.invalidResponse }
        while i < bytes.count {
            if take(34) {
                guard let result = try? JSONDecoder().decode(String.self, from: Data(bytes[start..<i])) else { throw TailnetAPIError.invalidResponse }
                return result
            }
            if take(92) { guard i < bytes.count else { throw TailnetAPIError.invalidResponse }; i += 1 }
            else { i += 1 }
        }
        throw TailnetAPIError.invalidResponse
    }
    private mutating func take(_ byte: UInt8) -> Bool {
        guard i < bytes.count, bytes[i] == byte else { return false }; i += 1; return true
    }
    private mutating func value(depth: Int) throws {
        nodes += 1; guard nodes <= 200_000, depth <= 32 else { throw TailnetAPIError.invalidResponse }
        whitespace(); guard i < bytes.count else { throw TailnetAPIError.invalidResponse }
        if take(123) {
            whitespace(); if take(125) { return }; var keys = Set<String>()
            while true {
                whitespace(); let key = try string()
                guard keys.insert(key).inserted else { throw TailnetAPIError.invalidResponse }
                whitespace(); guard take(58) else { throw TailnetAPIError.invalidResponse }
                try value(depth: depth + 1); whitespace(); if take(125) { return }
                guard take(44) else { throw TailnetAPIError.invalidResponse }
            }
        } else if take(91) {
            whitespace(); if take(93) { return }
            while true {
                try value(depth: depth + 1); whitespace(); if take(93) { return }
                guard take(44) else { throw TailnetAPIError.invalidResponse }
            }
        } else if bytes[i] == 34 { _ = try string() }
        else {
            let start = i
            while i < bytes.count, ![9,10,13,32,44,93,125].contains(bytes[i]) { i += 1 }
            guard i > start else { throw TailnetAPIError.invalidResponse }
        }
    }
}
