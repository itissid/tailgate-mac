import Foundation

public enum AgentHandoffError: String, Error, Equatable, LocalizedError, Sendable {
    case invalid = "The proposal file is not a supported bounded Tailgate handoff."
    case sensitive = "The proposal file contains an obvious credential marker. Do not submit secrets or transcripts."
    public var errorDescription: String? { rawValue }
}

/// Untrusted context plus exact proposal bytes, not an approval or claimed caller identity.
/// Decoding is pure: it never opens a file, starts a request, or displays a prompt.
public struct AgentHandoff: Sendable {
    public let proposal: Data
    public let purpose: String
    public static let maximumBytes = 11 + 160 + 2 + 16_384

    private init(proposal: Data, purpose: String) {
        self.proposal = proposal; self.purpose = purpose
    }

    /// LF-only framing: TAILGATE/1, one bounded prose line, a blank line, then JSON.
    /// The compiler must still validate the proposal against trusted local configuration.
    public static func decode(_ bytes: Data) throws -> AgentHandoff {
        guard (1...maximumBytes).contains(bytes.count), bytes.allSatisfy({ $0 < 128 }) else { throw AgentHandoffError.invalid }
        let input = Array(bytes), magic = Array("TAILGATE/1\n".utf8)
        guard input.starts(with: magic), let end = input[magic.count...].firstIndex(of: 10),
              (1...160).contains(end - magic.count), end + 1 < input.count, input[end + 1] == 10 else { throw AgentHandoffError.invalid }
        let purposeBytes = input[magic.count..<end]
        let punctuation: Set<UInt8> = [32, 40, 41, 44, 45, 46, 47]
        guard purposeBytes.first != 32, purposeBytes.last != 32,
              purposeBytes.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || punctuation.contains($0) }),
              purposeBytes.contains(where: { (65...90).contains($0) || (97...122).contains($0) }) else { throw AgentHandoffError.invalid }
        let proposal = Data(input[(end + 2)...])
        guard (1...16_384).contains(proposal.count) else { throw AgentHandoffError.invalid }
        // A conservative tripwire, not redaction or a promise to recognize every secret.
        let lower = String(decoding: bytes, as: UTF8.self).lowercased()
        let markers = ["tskey-", "ghp_", "github_pat_", "-----begin", "bearer ", "client_secret", "access_token", "refresh_token", "password"]
        guard !markers.contains(where: lower.contains) else { throw AgentHandoffError.sensitive }
        var scan = HandoffJSON(proposal)
        try scan.parse()
        return AgentHandoff(proposal: proposal, purpose: String(decoding: purposeBytes, as: UTF8.self))
    }
}

/// Independent structural guard because Foundation JSON parsers silently collapse
/// duplicate keys. Matches the compiler's intentionally small ASCII JSON dialect;
/// it does not infer VM identity, ownership, policy permissions, or proposal validity.
private struct HandoffJSON {
    let bytes: [UInt8]
    var index = 0
    var nodes = 0
    init(_ data: Data) { bytes = Array(data) }

    mutating func parse() throws {
        whitespace()
        guard peek == 123 else { throw AgentHandoffError.invalid }
        try value(depth: 0)
        whitespace()
        guard index == bytes.count else { throw AgentHandoffError.invalid }
    }
    private var peek: UInt8? { index < bytes.count ? bytes[index] : nil }
    private mutating func take(_ byte: UInt8) -> Bool {
        guard peek == byte else { return false }; index += 1; return true
    }
    private mutating func whitespace() {
        while peek == 32 || peek == 10 { index += 1 }
    }
    private mutating func value(depth: Int) throws {
        nodes += 1
        guard depth <= 12, nodes <= 1_024 else { throw AgentHandoffError.invalid }
        whitespace()
        guard let next = peek else { throw AgentHandoffError.invalid }
        switch next {
        case 123:
            index += 1; whitespace(); var keys = Set<String>()
            if take(125) { return }
            while true {
                whitespace(); let key = try string()
                guard keys.insert(key).inserted else { throw AgentHandoffError.invalid }
                whitespace(); guard take(58) else { throw AgentHandoffError.invalid }
                try value(depth: depth + 1); whitespace()
                if take(125) { return }
                guard take(44) else { throw AgentHandoffError.invalid }
            }
        case 91:
            index += 1; whitespace()
            if take(93) { return }
            while true {
                try value(depth: depth + 1); whitespace()
                if take(93) { return }
                guard take(44) else { throw AgentHandoffError.invalid }
            }
        case 34: _ = try string()
        case 116: try literal("true")
        case 102: try literal("false")
        case 110: try literal("null")
        case 45, 48...57:
            let start = index; _ = take(45); let digits = index
            guard let first = peek, (48...57).contains(first) else { throw AgentHandoffError.invalid }
            if take(48) {
                if let next = peek, (48...57).contains(next) { throw AgentHandoffError.invalid }
            } else {
                while let next = peek, (48...57).contains(next) { index += 1 }
            }
            guard index - digits <= 10,
                  let integer = Int(String(decoding: bytes[start..<index], as: UTF8.self)),
                  !(integer == 0 && bytes[start] == 45) else { throw AgentHandoffError.invalid }
        default: throw AgentHandoffError.invalid
        }
    }
    private mutating func string() throws -> String {
        guard take(34) else { throw AgentHandoffError.invalid }
        let start = index
        while let byte = peek {
            if byte == 34 {
                guard index - start <= 128 else { throw AgentHandoffError.invalid }
                let text = String(decoding: bytes[start..<index], as: UTF8.self); index += 1; return text
            }
            guard (32...126).contains(byte), byte != 92 else { throw AgentHandoffError.invalid }
            index += 1
        }
        throw AgentHandoffError.invalid
    }
    private mutating func literal(_ text: String) throws {
        for byte in text.utf8 { guard take(byte) else { throw AgentHandoffError.invalid } }
    }
}
