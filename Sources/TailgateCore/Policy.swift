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
        case .unsupportedBase: return "Policy is outside the supported closed, explicit tag-only subset."
        case .invalidProposal: return "Proposal is outside the narrow demo contract."
        case .assertionMismatch: return "Allow and deny assertions do not match the exact grants."
        }
    }
}

/// Deliberately non-general policy compiler. `compile` accepts the closed demo fixture;
/// `compileLive` preserves a validated restricted policy. Both grant access TO a fresh
/// workload tag, never FROM it, so tagging cannot activate old source grants.
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

        return try compileProposal(proposal, vm: "demo-vm", source: "tag:demo-client")
    }

    private static func compileProposal(_ proposal: Data, vm: String, source: String) throws -> CompiledPolicy {
        var parser = try StrictJSON(proposal)
        let root = try object(try parser.parse(), keys: ["version", "tag", "mode", "vm", "grants", "tests"])
        guard root["version"] == .integer(1),
              case let .string(tag)? = root["tag"], validTag(tag), tag != source,
              case let .string(mode)? = root["mode"], ["browser", "key"].contains(mode),
              root["vm"] == .string(vm),
              case let .array(grants)? = root["grants"], (1...2).contains(grants.count),
              case let .array(tests)? = root["tests"], tests.count == grants.count else {
            throw PolicyError.invalidProposal
        }

        var allowed: [String: [Int]] = [:]
        for value in grants {
            let row = try object(value, keys: ["src", "dst", "protocol", "ports"])
            let proto = try selectors(row, tag: tag, source: source)
            guard allowed[proto] == nil else { throw PolicyError.invalidProposal }
            allowed[proto] = try ports(row["ports"])
        }

        var denied: [String: [Int]] = [:]
        for value in tests {
            let row = try object(value, keys: ["src", "dst", "protocol", "allow", "deny"])
            let proto = try selectors(row, tag: tag, source: source)
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
            ["src": [source], "dst": [tag],
             "ip": allowed[proto]!.map { "\(proto):\($0)" }]
        }
        let compiledTests: [[String: Any]] = protocols.map { proto in
            ["src": source, "proto": proto,
             "accept": allowed[proto]!.map { "\(tag):\($0)" },
             "deny": denied[proto]!.map { "\(tag):\($0)" }]
        }
        let policy: [String: Any] = [
            "acls": [Any](), "ssh": [Any](),
            "tagOwners": [source: ["autogroup:admin"], tag: ["autogroup:admin"]],
            "grants": compiledGrants, "tests": compiledTests
        ]
        let candidate = try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys, .withoutEscapingSlashes])
        return CompiledPolicy(candidate: candidate, tag: tag, mode: mode, vm: vm)
    }

    /// Live requests are append-only within a deliberately small, closed-world subset.
    /// `vm`, `source`, and occupied inventory tags must come from trusted local configuration,
    /// never from the proposal. This method does not fetch inventory or run server validation.
    public static func compileLive(proposal: Data, base: Data, vm: String, source: String,
                                   occupiedTags: Set<String>) throws -> CompiledPolicy {
        guard validName(vm, max: 64), validExistingTag(source), occupiedTags.count <= 4_096,
              occupiedTags.allSatisfy(validExistingTag) else { throw PolicyError.invalidProposal }
        var parser = try StrictJSON(base)
        var existing = try validateLivePolicy(try parser.parse())
        guard case var .object(owners)? = existing["tagOwners"], owners[source] != nil,
              owners.count < 32,
              case let .array(grants)? = existing["grants"], grants.count <= 30,
              case let .array(tests)? = existing["tests"] else { throw PolicyError.unsupportedBase }
        let addition = try compileProposal(proposal, vm: vm, source: source)
        guard owners[addition.tag] == nil, !occupiedTags.contains(addition.tag), addition.tag != source else {
            throw PolicyError.invalidProposal
        }
        var additionParser = try StrictJSON(addition.candidate)
        let parts = try object(try additionParser.parse(), keys: ["acls", "ssh", "tagOwners", "grants", "tests"])
        guard case let .array(newGrants)? = parts["grants"], case let .array(newTests)? = parts["tests"] else {
            throw PolicyError.invalidProposal
        }
        owners[addition.tag] = .array([.string("autogroup:admin")])
        existing["tagOwners"] = .object(owners)
        existing["grants"] = .array(grants + newGrants)
        existing["tests"] = .array(tests + newTests)
        let candidate = try encode(.object(existing))
        // Reparse to enforce the byte/node bounds on the result, not only its inputs.
        var resultParser = try StrictJSON(candidate)
        _ = try validateLivePolicy(try resultParser.parse())
        return CompiledPolicy(candidate: candidate, tag: addition.tag, mode: addition.mode, vm: vm)
    }

    /// Full semantic line diff, with unchanged context. Whitespace/key order are normalized;
    /// array order and all values remain visible. Comments/escapes/Unicode are rejected, not stripped.
    public static func reviewDiff(base: Data, candidate: Data) throws -> String {
        func lines(_ data: Data) throws -> [String] {
            var parser = try StrictJSON(data)
            let policy = try parser.parse()
            _ = try validateLivePolicy(policy)
            let pretty = try encode(policy, pretty: true)
            return String(decoding: pretty, as: UTF8.self).components(separatedBy: "\n")
        }
        let old = try lines(base), new = try lines(candidate)
        let changes = new.difference(from: old)
        var removed = Set<Int>(), inserted = Set<Int>()
        for change in changes {
            switch change {
            case let .remove(offset, _, _): removed.insert(offset)
            case let .insert(offset, _, _): inserted.insert(offset)
            }
        }
        var i = 0, j = 0, output = ["--- current policy (normalized)", "+++ proposed policy (normalized)"]
        while i < old.count || j < new.count {
            if i < old.count, removed.contains(i) { output.append("-" + old[i]); i += 1 }
            else if j < new.count, inserted.contains(j) { output.append("+" + new[j]); j += 1 }
            else {
                guard i < old.count, j < new.count, old[i] == new[j] else { throw PolicyError.invalidDocument }
                output.append(" " + old[i]); i += 1; j += 1
            }
        }
        let text = output.joined(separator: "\n")
        guard text.utf8.count <= 131_072 else { throw PolicyError.invalidDocument }
        return text
    }

    private struct Edge: Hashable {
        let source: String
        let destination: String
        let proto: String
    }

    /// Require every existing grant to have complete positive coverage and nonempty
    /// negative assertions. No tests/owners/rows are rewritten or dropped by the caller.
    private static func validateLivePolicy(_ value: JSONValue) throws -> [String: JSONValue] {
        do {
            let root = try object(value, keys: ["acls", "ssh", "tagOwners", "grants", "tests"])
            guard root["acls"] == .array([]), root["ssh"] == .array([]),
                  case let .object(owners)? = root["tagOwners"], (1...32).contains(owners.count),
                  owners.allSatisfy({ validExistingTag($0.key) && $0.value == .array([.string("autogroup:admin")]) }),
                  case let .array(grants)? = root["grants"], grants.count <= 32,
                  case let .array(tests)? = root["tests"], tests.count == grants.count else {
                throw PolicyError.unsupportedBase
            }
            func tag(_ value: JSONValue?) throws -> String {
                guard case let .string(text)? = value, owners[text] != nil else { throw PolicyError.unsupportedBase }
                return text
            }
            func singletonTag(_ value: JSONValue?) throws -> String {
                guard case let .array(values)? = value, values.count == 1 else { throw PolicyError.unsupportedBase }
                return try tag(values[0])
            }
            func wirePort(_ value: String) throws -> Int {
                guard let number = Int(value), (1...65535).contains(number), String(number) == value else {
                    throw PolicyError.unsupportedBase
                }
                return number
            }
            var edges: [Edge: Set<Int>] = [:]
            for grant in grants {
                let row = try object(grant, keys: ["src", "dst", "ip"])
                let src = try singletonTag(row["src"]), dst = try singletonTag(row["dst"])
                guard src != dst, case let .array(ip)? = row["ip"], (1...16).contains(ip.count) else {
                    throw PolicyError.unsupportedBase
                }
                var proto: String?, allowed = Set<Int>()
                for entry in ip {
                    guard case let .string(text) = entry else { throw PolicyError.unsupportedBase }
                    let parts = text.components(separatedBy: ":")
                    guard parts.count == 2, ["tcp", "udp"].contains(parts[0]), proto == nil || proto == parts[0] else {
                        throw PolicyError.unsupportedBase
                    }
                    proto = parts[0]
                    guard allowed.insert(try wirePort(parts[1])).inserted else { throw PolicyError.unsupportedBase }
                }
                let edge = Edge(source: src, destination: dst, proto: proto!)
                guard edges.updateValue(allowed, forKey: edge) == nil else { throw PolicyError.unsupportedBase }
            }
            var covered = Set<Edge>()
            for test in tests {
                let row = try object(test, keys: ["src", "proto", "accept", "deny"])
                let src = try tag(row["src"])
                guard case let .string(proto)? = row["proto"], ["tcp", "udp"].contains(proto) else {
                    throw PolicyError.unsupportedBase
                }
                var destination: String?
                func endpoints(_ value: JSONValue?) throws -> Set<Int> {
                    guard case let .array(values)? = value, (1...16).contains(values.count) else { throw PolicyError.unsupportedBase }
                    var ports = Set<Int>()
                    for entry in values {
                        guard case let .string(text) = entry, let colon = text.lastIndex(of: ":") else {
                            throw PolicyError.unsupportedBase
                        }
                        let dst = String(text[..<colon])
                        guard owners[dst] != nil, destination == nil || destination == dst else { throw PolicyError.unsupportedBase }
                        destination = dst
                        let port = try wirePort(String(text[text.index(after: colon)...]))
                        guard ports.insert(port).inserted else { throw PolicyError.unsupportedBase }
                    }
                    return ports
                }
                let accept = try endpoints(row["accept"]), deny = try endpoints(row["deny"])
                let edge = Edge(source: src, destination: destination!, proto: proto)
                guard edges[edge] == accept, accept.isDisjoint(with: deny), covered.insert(edge).inserted else {
                    throw PolicyError.unsupportedBase
                }
            }
            guard Set(edges.keys) == covered else { throw PolicyError.unsupportedBase }
            return root
        } catch { throw PolicyError.unsupportedBase }
    }

    private static func validExistingTag(_ value: String) -> Bool {
        value.hasPrefix("tag:") && validName(String(value.dropFirst(4)), max: 48)
    }

    private static func validName(_ value: String, max: Int) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...max).contains(bytes.count), let first = bytes.first, (97...122).contains(first),
              let last = bytes.last, (97...122).contains(last) || (48...57).contains(last) else { return false }
        return bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }

    private static func encode(_ value: JSONValue, pretty: Bool = false) throws -> Data {
        func foundation(_ value: JSONValue) -> Any {
            switch value {
            case let .object(fields): return fields.mapValues(foundation)
            case let .array(values): return values.map(foundation)
            case let .string(text): return text
            case let .integer(number): return number
            case let .boolean(flag): return flag
            case .null: return NSNull()
            }
        }
        var options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        if pretty { options.insert(.prettyPrinted) }
        return try JSONSerialization.data(withJSONObject: foundation(value), options: options)
    }

    private static func object(_ value: JSONValue, keys: Set<String>) throws -> [String: JSONValue] {
        guard case let .object(fields) = value, Set(fields.keys) == keys else { throw PolicyError.invalidProposal }
        return fields
    }

    private static func selectors(_ row: [String: JSONValue], tag: String, source: String) throws -> String {
        guard row["src"] == .string(source), row["dst"] == .string(tag),
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
