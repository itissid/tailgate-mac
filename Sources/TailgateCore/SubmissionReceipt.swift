import Foundation

/// The only data returned to an untrusted submitter. No dynamic error text, policy,
/// account/device identifier, credentials, or bearer material can be encoded here.
public struct SubmissionReceipt: Equatable, Sendable {
    public enum Status: String, CaseIterable, Sendable {
        case declined, rejected, expired, stale, applied, unknown
    }
    public let status: Status
    public init(status: Status) { self.status = status }
    public var jsonLine: Data {
        let outcome: String
        switch status {
        case .applied: outcome = "applied"
        case .unknown: outcome = "unknown"
        case .stale: outcome = "not_applied"
        default: outcome = "not_attempted"
        }
        return Data("{\"version\":1,\"status\":\"\(status.rawValue)\",\"write_outcome\":\"\(outcome)\",\"enrollment\":\"not_confirmed\"}\n".utf8)
    }
    public var exitCode: Int32 { status == .applied ? 0 : status == .unknown ? 3 : 2 }
}

/// Pure lifecycle shared by the UI and deterministic offline tests. An interruption
/// after execution begins is UNKNOWN unless the controller returned a definite result.
/// Receipt absence is always unknown to the caller, irrespective of this local state.
public struct SubmissionLifecycle: Equatable, Sendable {
    public enum Phase: Equatable, Sendable { case receiving, waiting, reviewing, reviewed, executing, finished }
    public private(set) var phase: Phase = .receiving
    public private(set) var receipt: SubmissionReceipt?
    public init() {}
    @discardableResult public mutating func received() -> Bool {
        guard phase == .receiving else { return false }; phase = .waiting; return true
    }
    @discardableResult public mutating func beginReview() -> Bool {
        guard phase == .waiting else { return false }; phase = .reviewing; return true
    }
    @discardableResult public mutating func reviewed() -> Bool {
        guard phase == .reviewing else { return false }; phase = .reviewed; return true
    }
    @discardableResult public mutating func beginExecution() -> Bool {
        guard phase == .reviewed else { return false }; phase = .executing; return true
    }
    @discardableResult public mutating func finish(_ status: SubmissionReceipt.Status) -> SubmissionReceipt? {
        guard receipt == nil, status != .applied || phase == .executing else { return nil }
        let final = SubmissionReceipt(status: status); receipt = final; phase = .finished; return final
    }
    @discardableResult public mutating func interrupt(expired: Bool = false) -> SubmissionReceipt? {
        finish(phase == .executing ? .unknown : expired ? .expired : .declined)
    }
}

/// No file paths or I/O authority: a small incremental input cap, then pure decoding.
public struct SubmissionInput: Sendable {
    private var data = Data()
    public init() {}
    public mutating func append(_ chunk: Data) throws {
        guard chunk.count <= AgentHandoff.maximumBytes - data.count else { throw AgentHandoffError.invalid }
        data.append(chunk)
    }
    public func finish() throws -> (bytes: Data, handoff: AgentHandoff) { (data, try AgentHandoff.decode(data)) }
}
