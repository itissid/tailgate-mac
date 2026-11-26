import CryptoKit
import Darwin
import Foundation

/// All failures are deliberately non-enumerating and contain no caller/server text.
public enum LookupFailure: String, Error, LocalizedError {
    case rejected = "Lookup unavailable or unsupported. No device information was disclosed."
    case untrusted = "Lookup requires the installed, verified Tailgate app."
    case obsolete = "The disclosure review expired, changed, or was already consumed."
    case declined = "Fresh biometric approval was not verified. No device information was disclosed."
    case busy = "A lookup is already in progress."
    public var errorDescription: String? { rawValue }
}

/// Separate from the write configuration: lookup must never deserialize a writer secret.
/// Provision only through the installed app's explicit operator setup.
public struct LookupConfiguration: Codable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let tailnet: String
    private let clientID: String
    private let secret: String
    public init(tailnet: String, clientID: String, secret: String) throws {
        self.tailnet = tailnet; self.clientID = clientID; self.secret = secret
        try validate()
    }
    func validate() throws {
        guard (1...256).contains(clientID.utf8.count), (1...4096).contains(secret.utf8.count),
              [clientID, secret].allSatisfy({ $0.utf8.allSatisfy { (33...126).contains($0) } }) else { throw LookupFailure.rejected }
        _ = try TailnetAPI(tailnet: tailnet)
    }
    public func encoded() throws -> Data { try validate(); return try JSONEncoder().encode(self) }
    var credential: OAuthCredential { .init(clientID: clientID, secret: secret) }
    public var description: String { "LookupConfiguration(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["configuration": "<redacted>"]) }
}

struct LookupQuery: Equatable {
    let bytes: Data
    let hostname: String
    let tags: Bool
    let ips: Bool
    init(_ bytes: Data) throws {
        guard (1...160).contains(bytes.count), let text = String(data: bytes, encoding: .ascii) else { throw LookupFailure.rejected }
        let parts = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == "TAILGATE-LOOKUP/1", parts[3].isEmpty,
              Self.validHostname(String(parts[1])), ["name", "name,tags", "name,ips", "name,tags,ips"].contains(String(parts[2])) else { throw LookupFailure.rejected }
        self.bytes = bytes; hostname = String(parts[1]); tags = parts[2].split(separator: ",").contains("tags"); ips = parts[2].split(separator: ",").contains("ips")
    }
    static func validHostname(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...63).contains(bytes.count), let first = bytes.first, let last = bytes.last,
              (97...122).contains(first), (97...122).contains(last) || (48...57).contains(last) else { return false }
        return bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
}

// Private inventory, not an agent-facing DTO. No custom URL, policy operation, or token getter.
struct LookupDevice: Equatable, Sendable {
    let id: String
    let nodeKey: String
    let hostname: String
    let authorized: Bool
    let tags: [String]
    let addresses: [String]?
}
protocol LookupService {
    func lookupInventory(using credential: OAuthCredential) async throws -> [LookupDevice]
}
extension TailnetAPI: LookupService {}
@MainActor protocol LookupTrust {
    func load(slot: String) throws -> Data
    func sign(message: Data, reason: String) async throws -> Data
    func verify(message: Data, signature: Data) throws
}
extension MacTrust: LookupTrust {}

public struct LookupReview: Identifiable, Sendable {
    public let id: UUID
    public let text: String
    public let fingerprint: String
    fileprivate init(id: UUID, text: String) {
        self.id = id; self.text = text
        fingerprint = SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

private struct LookupResult: Equatable {
    let id: String
    let nodeKey: String
    let response: Data
}
private struct LookupPending {
    let review: LookupReview
    let query: LookupQuery
    let result: LookupResult
    let configurationHash: Data
    let deadline: ContinuousClock.Instant
}

@MainActor public final class DeviceLookupController {
    private let trust: LookupTrust
    private let makeService: (String) throws -> LookupService
    private let clock: () -> ContinuousClock.Instant
    private var busy = false
    private var generation = UUID()
    private var pending: LookupPending?

    public convenience init() throws {
        do { self.init(trust: try MacTrust(), makeService: { try TailnetAPI(tailnet: $0) }, clock: { .now }) }
        catch { throw LookupFailure.untrusted }
    }
    init(trust: LookupTrust, makeService: @escaping (String) throws -> LookupService, clock: @escaping () -> ContinuousClock.Instant) {
        self.trust = trust; self.makeService = makeService; self.clock = clock
    }
    public func discard() { pending = nil; generation = UUID() }
    private func configuration() throws -> (LookupConfiguration, Data) {
        do {
            let bytes = try trust.load(slot: "lookup-reader")
            guard bytes.count <= 8192 else { throw LookupFailure.rejected }
            let config = try JSONDecoder().decode(LookupConfiguration.self, from: bytes)
            try config.validate()
            return (config, Data(SHA256.hash(data: bytes)))
        } catch { throw LookupFailure.rejected }
    }
    /// Called only when the operator explicitly chooses Fetch. Fetch is read-only;
    /// its results are displayed to that operator, never yet released to the caller.
    public func prepare(query: Data) async throws -> LookupReview {
        discard()
        guard !busy else { throw LookupFailure.busy }; busy = true; defer { busy = false }
        let q = try LookupQuery(query), epoch = generation
        let (config, stamp) = try configuration()
        let result: LookupResult
        do { result = try Self.select(q, devices: await makeService(config.tailnet).lookupInventory(using: config.credential)) }
        catch { throw LookupFailure.rejected }
        guard epoch == generation, !Task.isCancelled else { throw LookupFailure.obsolete }
        let id = UUID()
        let review = LookupReview(id: id, text: """
        TAILGATE / READ-ONLY DISCLOSURE / v1
        This approves disclosure to the waiting local caller, NOT a policy write.
        Plan ID: \(id.uuidString)
        Tailnet: \(config.tailnet)
        Expires: \(ISO8601DateFormatter().string(from: Date().addingTimeInterval(120))) (120s monotonic limit)
        Exact caller query:
        \(String(decoding: query, as: UTF8.self))
        Exact response JSON (only these fields will be disclosed):
        \(String(decoding: result.response, as: UTF8.self))
        """)
        pending = LookupPending(review: review, query: q, result: result, configurationHash: stamp, deadline: clock().advanced(by: .seconds(120)))
        return review
    }
    public func disclose(_ review: LookupReview) async throws -> Data {
        guard !busy else { throw LookupFailure.busy }
        guard let p = pending, p.review.id == review.id, p.review.fingerprint == review.fingerprint else { throw LookupFailure.obsolete }
        pending = nil; busy = true; defer { busy = false }
        let epoch = generation
        func current() throws {
            guard generation == epoch, clock() < p.deadline, !Task.isCancelled else { throw LookupFailure.obsolete }
        }
        try current()
        let (config, stamp) = try configuration()
        guard stamp == p.configurationHash else { throw LookupFailure.obsolete }
        let message = Data(p.review.text.utf8)
        do {
            let signature = try await trust.sign(message: message, reason: "Disclose one device lookup [\(p.review.fingerprint.prefix(16))]")
            try trust.verify(message: message, signature: signature)
        } catch { throw LookupFailure.declined }
        try current()
        let result: LookupResult
        do { result = try Self.select(p.query, devices: await makeService(config.tailnet).lookupInventory(using: config.credential)) }
        catch { throw LookupFailure.rejected }
        try current()
        guard try configuration().1 == stamp, result == p.result else { throw LookupFailure.obsolete }
        return p.result.response
    }
    private static func select(_ q: LookupQuery, devices: [LookupDevice]) throws -> LookupResult {
        guard devices.count <= 10_000 else { throw LookupFailure.rejected }
        let matches = devices.filter { $0.hostname == q.hostname }
        guard matches.count == 1, let device = matches.first, device.authorized, !device.id.isEmpty, !device.nodeKey.isEmpty else { throw LookupFailure.rejected }
        var fields: [String: Any] = ["name": q.hostname]
        if q.tags {
            guard device.tags.count <= 64, Set(device.tags).count == device.tags.count,
                  device.tags.allSatisfy({ tag in
                      tag.hasPrefix("tag:") && (5...100).contains(tag.utf8.count) && tag.dropFirst(4).utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
                  }) else { throw LookupFailure.rejected }
            fields["tags"] = device.tags.sorted()
        }
        if q.ips {
            guard let input = device.addresses, (1...8).contains(input.count) else { throw LookupFailure.rejected }
            let ips = try input.map(overlayAddress)
            guard Set(ips).count == ips.count else { throw LookupFailure.rejected }
            fields["ips"] = ips.sorted()
        }
        let body = try JSONSerialization.data(withJSONObject: ["version": 1, "status": "disclosed", "device": fields], options: [.sortedKeys, .withoutEscapingSlashes])
        return LookupResult(id: device.id, nodeKey: device.nodeKey, response: body)
    }
    private static func overlayAddress(_ text: String) throws -> String {
        guard (1...45).contains(text.utf8.count), !text.contains("%"), !text.contains("/"), !text.contains("\0") else { throw LookupFailure.rejected }
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let bytes = withUnsafeBytes(of: v4) { Array($0) }
            guard bytes[0] == 100, (64...127).contains(bytes[1]) else { throw LookupFailure.rejected }
            return try canonical(AF_INET, &v4, INET_ADDRSTRLEN)
        }
        var v6 = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { throw LookupFailure.rejected }
        let bytes = withUnsafeBytes(of: v6) { Array($0) }
        guard Array(bytes.prefix(6)) == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0] else { throw LookupFailure.rejected }
        return try canonical(AF_INET6, &v6, INET6_ADDRSTRLEN)
    }
    private static func canonical<T>(_ family: Int32, _ address: inout T, _ capacity: Int32) throws -> String {
        var output = [CChar](repeating: 0, count: Int(capacity))
        let ok = withUnsafePointer(to: &address) { inet_ntop(family, $0, &output, socklen_t(capacity)) }
        guard ok != nil else { throw LookupFailure.rejected }
        return String(cString: output)
    }
}
