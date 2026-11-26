import CryptoKit
import Foundation

public enum TrialFailure: Error { case invalidInput, invalidState }

/// Presentation reads the compiled policy, never the agent's reason for asking.
public struct TrialAccessSummary: Sendable {
    public let source, destination, transport: String
    public let allowed, denied: [UInt16]
    fileprivate init(body: Data) throws {
        struct Policy: Decodable {
            struct Grant: Decodable { let src, dst, ip: [String] }
            struct Check: Decodable { let src, proto: String; let accept, deny: [String] }
            let grants: [Grant]; let tests: [Check]
        }
        let p = try JSONDecoder().decode(Policy.self, from: body)
        guard p.grants.count == 1, p.tests.count == 1, let g = p.grants.first, let t = p.tests.first,
              g.src == [t.src], g.dst.count == 1, let dest = g.dst.first else { throw TrialFailure.invalidInput }
        func ports(_ entries: [String], prefix: String) throws -> [UInt16] {
            try entries.map { entry in
                guard entry.hasPrefix(prefix), let port = UInt16(entry.dropFirst(prefix.count)) else { throw TrialFailure.invalidInput }
                return port
            }.sorted()
        }
        source = t.src; destination = dest; transport = t.proto.uppercased()
        allowed = try ports(t.accept, prefix: dest + ":"); denied = try ports(t.deny, prefix: dest + ":")
        guard try ports(g.ip, prefix: t.proto + ":") == allowed else { throw TrialFailure.invalidInput }
    }
}

/// Fixed synthetic operation only. This does not confer production authority.
public struct TrialPlan: Sendable {
    public let id: UUID
    public let purpose: String
    public let body: Data
    public let access: TrialAccessSummary
    public let formattedPolicy: String
    public let text: String
    public let fingerprint: String
    public static let example = Data(("TAILGATE/1\nAllow the demo client to reach the demo API on TCP 443.\n\n" + String(decoding: Compiler.example, as: UTF8.self) + "\n").utf8)

    public init(handoff bytes: Data) throws {
        let handoff = try AgentHandoff.decode(bytes)
        let compiled = try Compiler.compile(proposal: handoff.proposal, base: Compiler.fixturePolicy)
        let fixture = try Compiler.compile(proposal: Compiler.example, base: Compiler.fixturePolicy)
        guard compiled.candidate == fixture.candidate, compiled.mode == "browser", compiled.vm == "demo-vm", compiled.tag == fixture.tag else { throw TrialFailure.invalidInput }
        id = UUID(); purpose = handoff.purpose; body = compiled.candidate
        access = try TrialAccessSummary(body: body)
        let json = try JSONSerialization.jsonObject(with: body)
        formattedPolicy = String(decoding: try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        text = """
        TAILGATE / FIXTURE REHEARSAL / NO REAL WRITE
        Trial ID: \(id.uuidString)
        Untrusted agent purpose (not an authorization): \(purpose)
        Operation: simulate one policy approval, demo-client to demo-api, TCP 443 only.
        Synthetic source: tag:demo-client
        Synthetic destination: tag:workload-demo-api
        Tests: allow TCP 443; deny TCP 22 and 80.
        No network, credentials, Keychain, signing, device enrollment or policy mutation.
        Touch ID here authenticates locally; it does not sign a plan or secure a production credential.

        Exact compiled synthetic policy body:
        \(String(decoding: body, as: UTF8.self))
        """
        fingerprint = SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public struct TrialReceipt: Equatable, Sendable {
    public enum Status: String, CaseIterable, Sendable { case approved, declined, timeout, error }
    public let status: Status
    public init(_ status: Status) { self.status = status }
    public var jsonLine: Data {
        Data("{\"version\":1,\"dry_run\":true,\"status\":\"\(status.rawValue)\",\"write_outcome\":\"not_attempted\",\"enrollment\":\"not_attempted\"}\n".utf8)
    }
    public var exitCode: Int32 {
        switch status { case .approved: return 0; case .declined: return 2; case .timeout: return 3; case .error: return 4 }
    }
}

@MainActor public protocol TrialGate {
    func approve(_ plan: TrialPlan) async -> Bool
}

/// In-memory rehearsal state; no executor, persistence or live dependency.
@MainActor public final class TrialSession {
    public let plan: TrialPlan
    public private(set) var receipt: TrialReceipt?
    public private(set) var approving = false
    private let deadline: ContinuousClock.Instant
    private let now: () -> ContinuousClock.Instant
    public convenience init(handoff: Data) throws { try self.init(handoff: handoff, now: { .now }) }
    init(handoff: Data, now: @escaping () -> ContinuousClock.Instant) throws {
        plan = try TrialPlan(handoff: handoff); self.now = now
        deadline = now().advanced(by: .seconds(120))
    }
    public var hasExpired: Bool { now() >= deadline }
    @discardableResult public func cancel() -> TrialReceipt { finish(.declined) }
    public func checkTimeout() -> TrialReceipt? { hasExpired ? finish(.timeout) : receipt }
    private func finish(_ status: TrialReceipt.Status) -> TrialReceipt {
        if let receipt { return receipt }
        let final = TrialReceipt(hasExpired ? .timeout : status)
        receipt = final; return final
    }
    /// Consume before suspension: one attempt only. Interrupted callbacks cannot approve.
    public func approve(gate: TrialGate) async throws -> TrialReceipt {
        guard receipt == nil, !approving else { throw TrialFailure.invalidState }
        if hasExpired { return finish(.timeout) }
        if Task.isCancelled { return finish(.declined) }
        approving = true
        let ok = await gate.approve(plan)
        if let receipt { return receipt }
        if Task.isCancelled { return finish(.declined) }
        return finish(ok ? .approved : .declined)
    }
}
