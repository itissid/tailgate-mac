import Foundation

/// A compiler-owned plan. Raw proposal bytes must never be used as display text or requests.
public struct CompiledPolicy: Sendable {
    public let candidate: Data
    public let tag: String
    public let mode: String
    public let vm: String
}

public enum PolicyError: Error, Equatable, LocalizedError {
    case invalidDocument
    case unsupportedBase
    case invalidProposal
    case assertionMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidDocument: return "Input is not bounded, unambiguous strict JSON."
        case .unsupportedBase: return "Only the closed demo policy baseline is supported."
        case .invalidProposal: return "Proposal is outside the narrow demo contract."
        case .assertionMismatch: return "Allow and deny assertions do not match the exact grants."
        }
    }
}

/// Offline, deliberately non-general policy compiler. It accepts only the closed fixture
/// baseline, never arbitrary live policies. It grants access TO a fresh workload tag,
/// never FROM that tag, so it cannot activate existing source grants by tagging a device.
public enum Compiler {
    public static let fixturePolicy = Data(#"{"acls":[],"grants":[],"ssh":[],"tagOwners":{"tag:demo-client":["autogroup:admin"]},"tests":[]}"#.utf8)

    public static let example = Data(#"""
    {
      "version": 1,
      "tag": "tag:workload-demo-api",
      "mode": "browser",
      "vm": "demo-vm",
      "grants": [
        {"src":"tag:demo-client","dst":"tag:workload-demo-api","protocol":"tcp","ports":[443]}
      ],
      "tests": [
        {"src":"tag:demo-client","dst":"tag:workload-demo-api","protocol":"tcp","allow":[443],"deny":[22,80]}
      ]
    }
    """#.utf8)

    public static func compile(proposal: Data, base: Data) throws -> CompiledPolicy {
        var baseParser = try StrictJSON(base)
        let parsedBase = try baseParser.parse()
        var fixtureParser = try StrictJSON(fixturePolicy)
        guard parsedBase == (try fixtureParser.parse()) else { throw PolicyError.unsupportedBase }

        var parser = try StrictJSON(proposal)
        let root = try object(try parser.parse(), keys: ["version", "tag", "mode", "vm", "grants", "tests"])
        guard root["version"] == .integer(1),
              case let .string(tag)? = root["tag"], validTag(tag),
              case let .string(mode)? = root["mode"], ["browser", "key"].contains(mode),
              root["vm"] == .string("demo-vm"),
              case let .array(grants)? = root["grants"], (1...2).contains(grants.count),
              case let .array(tests)? = root["tests"], tests.count == grants.count else {
            throw PolicyError.invalidProposal
        }

        var allowed: [String: [Int]] = [:]
        for value in grants {
            let row = try object(value, keys: ["src", "dst", "protocol", "ports"])
            let proto = try selectors(row, tag: tag)
            guard allowed[proto] == nil else { throw PolicyError.invalidProposal }
            allowed[proto] = try ports(row["ports"])
        }

        var denied: [String: [Int]] = [:]
        for value in tests {
            let row = try object(value, keys: ["src", "dst", "protocol", "allow", "deny"])
            let proto = try selectors(row, tag: tag)
            let accept = try ports(row["allow"])
            let deny = try ports(row["deny"])
            guard denied[proto] == nil, allowed[proto] == accept,
                  Set(accept).isDisjoint(with: deny) else { throw PolicyError.assertionMismatch }
            denied[proto] = deny
        }
        guard Set(denied.keys) == Set(allowed.keys) else { throw PolicyError.assertionMismatch }

        // Reconstruct only known-safe output. No proposal field is copied as raw JSON.
        let protocols = allowed.keys.sorted()
        let compiledGrants: [[String: Any]] = protocols.map { proto in
            ["src": ["tag:demo-client"], "dst": [tag],
             "ip": allowed[proto]!.map { "\(proto):\($0)" }]
        }
        let compiledTests: [[String: Any]] = protocols.map { proto in
            ["src": "tag:demo-client", "proto": proto,
             "accept": allowed[proto]!.map { "\(tag):\($0)" },
             "deny": denied[proto]!.map { "\(tag):\($0)" }]
        }
        let policy: [String: Any] = [
            "acls": [Any](), "ssh": [Any](),
            "tagOwners": ["tag:demo-client": ["autogroup:admin"], tag: ["autogroup:admin"]],
            "grants": compiledGrants, "tests": compiledTests
        ]
        let candidate = try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys, .withoutEscapingSlashes])
        return CompiledPolicy(candidate: candidate, tag: tag, mode: mode, vm: "demo-vm")
    }

    private static func object(_ value: JSONValue, keys: Set<String>) throws -> [String: JSONValue] {
        guard case let .object(fields) = value, Set(fields.keys) == keys else { throw PolicyError.invalidProposal }
        return fields
    }

    private static func selectors(_ row: [String: JSONValue], tag: String) throws -> String {
        guard row["src"] == .string("tag:demo-client"), row["dst"] == .string(tag),
              case let .string(proto)? = row["protocol"], ["tcp", "udp"].contains(proto) else {
            throw PolicyError.invalidProposal
        }
        return proto
    }

    private static func ports(_ value: JSONValue?) throws -> [Int] {
        guard case let .array(values)? = value, (1...16).contains(values.count) else {
            throw PolicyError.invalidProposal
        }
        let result: [Int] = try values.map {
            guard case let .integer(port) = $0, (1...65535).contains(port) else { throw PolicyError.invalidProposal }
            return port
        }
        guard Set(result).count == result.count else { throw PolicyError.invalidProposal }
        return result.sorted()
    }

    private static func validTag(_ value: String) -> Bool {
        let prefix = "tag:workload-"
        guard value.hasPrefix(prefix) else { return false }
        let name = Array(value.dropFirst(prefix.count).utf8)
        guard (1...32).contains(name.count), let first = name.first, (97...122).contains(first),
              let last = name.last, (97...122).contains(last) || (48...57).contains(last) else { return false }
        return name.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
}

private indirect enum JSONValue: Equatable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case integer(Int)
    case boolean(Bool)
    case null
}

/// JSONDecoder/JSONSerialization silently accept duplicate object names. This small
/// parser rejects them before schema checking. Deliberately supports an ASCII subset:
/// no string escapes (including escaped key aliases), floats, exponents, or comments.
private struct StrictJSON {
    private let bytes: [UInt8]
    private var index = 0
    private var nodes = 0

    init(_ data: Data) throws {
        guard (1...16_384).contains(data.count), data.allSatisfy({ $0 < 128 }) else {
            throw PolicyError.invalidDocument
        }
        bytes = Array(data)
    }

    mutating func parse() throws -> JSONValue {
        let result = try value(depth: 0)
        whitespace()
        guard index == bytes.count else { throw PolicyError.invalidDocument }
        return result
    }

    private mutating func value(depth: Int) throws -> JSONValue {
        nodes += 1
        guard depth <= 12, nodes <= 1_024 else { throw PolicyError.invalidDocument }
        whitespace()
        guard index < bytes.count else { throw PolicyError.invalidDocument }
        switch bytes[index] {
        case 123:
            index += 1
            whitespace()
            var fields: [String: JSONValue] = [:]
            if consume(125) { return .object(fields) }
            while true {
                whitespace()
                let key = try string()
                guard fields[key] == nil else { throw PolicyError.invalidDocument }
                whitespace()
                guard consume(58) else { throw PolicyError.invalidDocument }
                fields[key] = try value(depth: depth + 1)
                whitespace()
                if consume(125) { return .object(fields) }
                guard consume(44) else { throw PolicyError.invalidDocument }
            }
        case 91:
            index += 1
            whitespace()
            var values: [JSONValue] = []
            if consume(93) { return .array(values) }
            while true {
                values.append(try value(depth: depth + 1))
                whitespace()
                if consume(93) { return .array(values) }
                guard consume(44) else { throw PolicyError.invalidDocument }
            }
        case 34: return .string(try string())
        case 116: try literal("true"); return .boolean(true)
        case 102: try literal("false"); return .boolean(false)
        case 110: try literal("null"); return .null
        case 45, 48...57:
            let start = index
            _ = consume(45)
            let digitStart = index
            guard index < bytes.count, (48...57).contains(bytes[index]) else { throw PolicyError.invalidDocument }
            if consume(48) {
                guard index == bytes.count || !(48...57).contains(bytes[index]) else { throw PolicyError.invalidDocument }
            } else {
                while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            }
            guard index - digitStart <= 10,
                  let number = Int(String(decoding: bytes[start..<index], as: UTF8.self)),
                  !(number == 0 && bytes[start] == 45) else { throw PolicyError.invalidDocument }
            return .integer(number)
        default: throw PolicyError.invalidDocument
        }
    }

    private mutating func string() throws -> String {
        guard consume(34) else { throw PolicyError.invalidDocument }
        let start = index
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 34 {
                guard index - start <= 128 else { throw PolicyError.invalidDocument }
                let result = String(decoding: bytes[start..<index], as: UTF8.self)
                index += 1
                return result
            }
            guard byte >= 32, byte != 92 else { throw PolicyError.invalidDocument }
            index += 1
        }
        throw PolicyError.invalidDocument
    }

    private mutating func literal(_ text: String) throws {
        for byte in text.utf8 {
            guard consume(byte) else { throw PolicyError.invalidDocument }
        }
    }

    private mutating func whitespace() {
        while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }
}
