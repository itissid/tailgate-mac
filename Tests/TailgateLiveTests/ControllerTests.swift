import CryptoKit
import Foundation
import Testing
import TailgateCore
@testable import TailgateLive

// Wholly synthetic fixtures. No network, credentials, Secure Enclave or Keychain access.
private enum ControllerFixture {
    static let tailnet = "example.invalid"
    static let node = "nodekey:" + String(repeating: "a", count: 64)
    static let otherNode = "nodekey:" + String(repeating: "b", count: 64)
    static let target = "tag:workload-demo-api"
    static func sha(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func device(node: String = node, tags: [String] = [], authorized: Bool = true) -> TailnetDevice {
        TailnetDevice(id: "fixture-device", nodeID: "fixture-node", nodeKey: node, authorized: authorized,
                      tags: tags, name: "fixture.invalid", hostname: "fixture")
    }
}
private enum ControllerFault: Error { case denied, duplicate, missing, disk, interrupted }

@MainActor private final class ControllerTrust: LocalTrust {
    var slots: [String: Data] = [:]
    var reservations: [UUID: Data] = [:]
    var unresolved: UUID?
    var outcomes: [UUID: String] = [:]
    var signed: [Data] = []
    var verified: [Data] = []
    var onSign: (() throws -> Void)?
    var denyVerification = false
    var denyReceipt = false
    var denyFinish = false
    func store(slot: String, value: Data) throws {
        if slot == "configuration", slots[slot] != nil { throw ControllerFault.duplicate }
        if slot == "receipt", denyReceipt { throw ControllerFault.disk }
        slots[slot] = value
    }
    func load(slot: String) throws -> Data {
        guard let result = slots[slot] else { throw ControllerFault.missing }; return result
    }
    func sign(message: Data, reason: String) async throws -> Data {
        signed.append(message); try onSign?(); return message
    }
    func verify(message: Data, signature: Data) throws {
        guard !denyVerification, message == signature else { throw ControllerFault.denied }; verified.append(message)
    }
    func reserveIntent(id: UUID, digest: Data) throws {
        guard unresolved == nil, reservations[id] == nil else { throw ControllerFault.duplicate }
        unresolved = id; reservations[id] = digest
    }
    func finishIntent(id: UUID, outcome: String) throws {
        if denyFinish { throw ControllerFault.disk }
        outcomes[id] = outcome
        if outcome == "applied" || outcome == "rejected" { unresolved = nil }
    }
    func assertNoUnresolvedIntents() throws {
        guard unresolved == nil else { throw ControllerFault.interrupted }
    }
    func unresolvedID() throws -> UUID? { unresolved }
    func unresolvedDigest() throws -> Data? { unresolved.flatMap { reservations[$0] } }
    func hasApplied(id: UUID, digest: Data) throws -> Bool {
        outcomes[id] == "applied" && reservations[id] == digest
    }
}

private final class ControllerAPI: LiveAPI, @unchecked Sendable {
    enum ApplyMode { case success, stale, unknown, wrongBody, unchangedETag }
    var snapshot = PolicySnapshot(bytes: Compiler.fixturePolicy, etag: "\"fixture-1\"")
    var inventory: [TailnetDevice] = []
    var validateFails = false
    var readFails = false
    var applyMode = ApplyMode.success
    var policiesRead = 0
    var inventoriesRead = 0
    var validated: [Data] = []
    var submitted: [(Data, String)] = []
    var onApply: (() -> Void)?
    var onWriterToken: (@MainActor () -> Void)?
    func getPolicy(using: OAuthCredential) async throws -> PolicySnapshot {
        policiesRead += 1; if readFails { throw ControllerFault.interrupted }; return snapshot
    }
    func validate(_ candidate: Data, using: OAuthCredential) async throws {
        validated.append(candidate); if validateFails { throw TailnetAPIError.validationFailed }
    }
    func apply(_ candidate: Data, ifMatch: String, using: OAuthCredential, beforeDispatch: @escaping @MainActor () throws -> Void) async throws -> PolicySnapshot {
        if let action = onWriterToken { await action() }
        do { try await beforeDispatch() } catch { throw TailnetAPIError.notDispatched }
        submitted.append((candidate, ifMatch)); onApply?()
        switch applyMode {
        case .stale: throw TailnetAPIError.stalePolicy
        case .unknown:
            snapshot = PolicySnapshot(bytes: candidate, etag: "\"fixture-2\"")
            throw TailnetAPIError.outcomeUnknown
        case .wrongBody: return PolicySnapshot(bytes: Compiler.fixturePolicy, etag: "\"fixture-2\"")
        case .unchangedETag: return PolicySnapshot(bytes: candidate, etag: ifMatch)
        case .success:
            guard ifMatch == snapshot.etag else { throw TailnetAPIError.stalePolicy }
            snapshot = PolicySnapshot(bytes: candidate, etag: "\"fixture-2\""); return snapshot
        }
    }
    func devices(using: OAuthCredential) async throws -> [TailnetDevice] {
        inventoriesRead += 1; if readFails { throw ControllerFault.interrupted }; return inventory
    }
}

@MainActor struct ControllerTests {
    private let trust = ControllerTrust()
    private let api = ControllerAPI()
    private func controller(clock: @escaping () -> ContinuousClock.Instant = { .now }) -> LiveController {
        LiveController(trust: trust, makeAPI: { target in
            #expect(target == ControllerFixture.tailnet); return api
        }, clock: clock)
    }
    private func configured(clock: @escaping () -> ContinuousClock.Instant = { .now }) throws -> LiveController {
        let c = controller(clock: clock)
        try c.configure(tailnet: ControllerFixture.tailnet, vm: "demo-vm", source: "tag:demo-client", nodeKey: ControllerFixture.node,
                        readClientID: "fixture-reader", readSecret: "fixture-reader-material",
                        writeClientID: "fixture-writer", writeSecret: "fixture-writer-material")
        return c
    }
    private var keyProposal: Data {
        Data(String(decoding: Compiler.example, as: UTF8.self).replacingOccurrences(of: "\"browser\"", with: "\"key\"").utf8)
    }
    @Test func noImplicitRequestsAndConfigureIsCreateOnly() throws {
        let c = try configured()
        #expect(api.policiesRead == 0); #expect(api.inventoriesRead == 0); #expect(trust.signed.isEmpty)
        #expect(throws: LiveFailure.settings) {
            try c.configure(tailnet: ControllerFixture.tailnet, vm: "demo-vm", source: "tag:demo-client", nodeKey: ControllerFixture.node,
                            readClientID: "second-reader", readSecret: "second-reader-material",
                            writeClientID: "second-writer", writeSecret: "second-writer-material")
        }
    }
    @Test func exactDisplayedReviewIsSignedAndOnlyReviewedBodyPostedOnce() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        let candidate = try #require(api.validated.last)
        #expect(review.text.hasSuffix(String(decoding: candidate, as: UTF8.self)))
        #expect(review.fingerprint == ControllerFixture.sha(Data(review.text.utf8)))
        #expect(review.text.contains(ControllerFixture.node)); #expect(review.text.contains("If-Match: \"fixture-1\""))
        #expect(api.submitted.isEmpty); #expect(trust.signed.isEmpty)
        let result = try await c.execute(review)
        #expect(result.contains("No key was issued")); #expect(trust.signed == [Data(review.text.utf8)])
        #expect(trust.verified == trust.signed); #expect(api.submitted.count == 1)
        #expect(api.submitted.first?.0 == candidate); #expect(api.submitted.first?.1 == "\"fixture-1\"")
        #expect(trust.reservations[review.id] == Data(SHA256.hash(data: Data(review.text.utf8))))
        #expect(trust.outcomes[review.id] == "applied"); #expect(trust.unresolved == nil)
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }
        #expect(api.submitted.count == 1)
    }
    @Test func serverValidationFailureNeverSignsOrPosts() async throws {
        let c = try configured(); api.validateFails = true
        await #expect(throws: LiveFailure.validation) { try await c.prepare(proposal: Compiler.example) }
        #expect(api.validated.count == 1); #expect(trust.signed.isEmpty); #expect(api.submitted.isEmpty)
    }
    @Test func keyProposalFailsClosedBeforeValidationOrApproval() async throws {
        let c = try configured()
        await #expect(throws: LiveFailure.keyDisabled) { try await c.prepare(proposal: keyProposal) }
        #expect(api.validated.isEmpty); #expect(trust.signed.isEmpty); #expect(api.submitted.isEmpty)
        #expect(api.policiesRead == 0); #expect(api.inventoriesRead == 0)
    }
    @Test func stalePolicyBeforePOSTConsumesApprovalWithoutWriting() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        api.snapshot = PolicySnapshot(bytes: Compiler.fixturePolicy, etag: "\"fixture-new\"")
        await #expect(throws: LiveFailure.stale) { try await c.execute(review) }
        #expect(api.submitted.isEmpty); #expect(trust.reservations.isEmpty)
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }
    }
    @Test func sameETagWithChangedPolicyBytesStillRejects() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        api.snapshot = PolicySnapshot(bytes: Compiler.fixturePolicy + Data(" ".utf8), etag: "\"fixture-1\"")
        await #expect(throws: LiveFailure.stale) { try await c.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func stalePolicyOnPOSTIsRejectedWithoutRetry() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example); api.applyMode = .stale
        await #expect(throws: LiveFailure.stale) { try await c.execute(review) }
        #expect(api.submitted.count == 1); #expect(trust.outcomes[review.id] == "rejected"); #expect(trust.unresolved == nil)
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }; #expect(api.submitted.count == 1)
    }
    @Test func changedInventoryOccupyingNewTagBlocksWriteAfterTap() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        trust.onSign = { api.inventory = [ControllerFixture.device(node: ControllerFixture.otherNode, tags: [ControllerFixture.target])] }
        await #expect(throws: LiveFailure.stale) { try await c.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func expiryBeforeTapDoesNotSignAndExpiryDuringTapDoesNotPost() async throws {
        var t = ContinuousClock.now; let c = try configured(clock: { t })
        let first = try await c.prepare(proposal: Compiler.example); t = t.advanced(by: .seconds(120))
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(first) }; #expect(trust.signed.isEmpty)
        let second = try await c.prepare(proposal: Compiler.example)
        trust.onSign = { t = t.advanced(by: .seconds(120)) }
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(second) }; #expect(api.submitted.isEmpty)
    }
    @Test func cancellationDuringBiometricsDoesNotPostAndCannotReplay() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        trust.onSign = { throw ControllerFault.denied }
        await #expect(throws: LiveFailure.signature) { try await c.execute(review) }
        trust.onSign = nil
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func discardDuringBiometricsInvalidatesPlan() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        trust.onSign = { c.discard() }
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func signatureVerificationFailureBlocksWrite() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example); trust.denyVerification = true
        await #expect(throws: LiveFailure.signature) { try await c.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func reviewReplacementAndInvalidReplacementPreventOldApproval() async throws {
        let c = try configured(), first = try await c.prepare(proposal: Compiler.example)
        let second = try await c.prepare(proposal: Compiler.example)
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(first) }
        await #expect(throws: LiveFailure.invalid) { try await c.prepare(proposal: Data()) }
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(second) }; #expect(api.submitted.isEmpty)
    }
    @Test func reviewCannotCrossControllerEvenWithSameConfiguration() async throws {
        let c = try configured(), other = controller(), review = try await c.prepare(proposal: Compiler.example)
        await #expect(throws: LiveFailure.obsolete) { try await other.execute(review) }; #expect(api.submitted.isEmpty)
    }
    @Test func unknownOutcomeBlocksSecondControllerAndReadOnlyReconciliationDoesNotUnlock() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example); api.applyMode = .unknown
        await #expect(throws: LiveFailure.unknown) { try await c.execute(review) }
        #expect(trust.unresolved == review.id); #expect(trust.outcomes[review.id] == "unknown")
        let restarted = controller()
        await #expect(throws: LiveFailure.blocked) { try await restarted.prepare(proposal: Compiler.example) }
        let before = api.submitted.count, result = try await restarted.reconcile()
        #expect(result.contains("matches the candidate")); #expect(result.contains("still blocks writes"))
        #expect(api.submitted.count == before); #expect(trust.unresolved == review.id)
        await #expect(throws: LiveFailure.blocked) { try await restarted.checkEnrollment() }
    }
    @Test func crashAfterReservationBeforePOSTBlocksRestart() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example); trust.denyReceipt = true
        await #expect(throws: LiveFailure.blocked) { try await c.execute(review) }
        #expect(trust.unresolved == review.id); #expect(api.submitted.isEmpty)
        let restarted = controller()
        await #expect(throws: LiveFailure.blocked) { try await restarted.prepare(proposal: Compiler.example) }
        await #expect(throws: LiveFailure.noReceipt) { try await restarted.reconcile() }; #expect(api.submitted.isEmpty)
    }
    @Test func anotherControllerReservationBlocksPreviouslyPreparedApproval() async throws {
        let c = try configured(), first = try await c.prepare(proposal: Compiler.example), second = controller()
        let other = try await second.prepare(proposal: Compiler.example)
        try trust.reserveIntent(id: first.id, digest: Data(repeating: 0, count: 32))
        await #expect(throws: LiveFailure.blocked) { try await second.execute(other) }; #expect(api.submitted.isEmpty)
    }
    @Test func malformedSuccessNeverClearsDurableLock() async throws {
        for mode in [ControllerAPI.ApplyMode.wrongBody, .unchangedETag] {
            let localTrust = ControllerTrust(), localAPI = ControllerAPI()
            let c = LiveController(trust: localTrust, makeAPI: { _ in localAPI }, clock: { .now })
            try c.configure(tailnet: ControllerFixture.tailnet, vm: "demo-vm", source: "tag:demo-client", nodeKey: ControllerFixture.node,
                            readClientID: "fixture-reader", readSecret: "fixture-reader-material", writeClientID: "fixture-writer", writeSecret: "fixture-writer-material")
            let review = try await c.prepare(proposal: Compiler.example); localAPI.applyMode = mode
            await #expect(throws: LiveFailure.unknown) { try await c.execute(review) }
            #expect(localTrust.unresolved == review.id); #expect(localAPI.submitted.count == 1)
        }
    }
    @Test func journalFinishFailureIsUnknownWithoutRetry() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example); trust.denyFinish = true
        await #expect(throws: LiveFailure.unknown) { try await c.execute(review) }
        #expect(trust.unresolved == review.id); #expect(api.submitted.count == 1)
        await #expect(throws: LiveFailure.blocked) { try await controller().prepare(proposal: Compiler.example) }
    }
    @Test func reconciliationAndPinnedEnrollmentAreReadOnly() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        _ = try await c.execute(review); let writes = api.submitted.count, signatures = trust.signed.count
        #expect(try await c.reconcile().contains("matches the candidate"))
        #expect(try await c.checkEnrollment().contains("Waiting"))
        api.inventory = [ControllerFixture.device(node: ControllerFixture.otherNode)]
        #expect(try await c.checkEnrollment().contains("Waiting"))
        api.inventory = [ControllerFixture.device(node: ControllerFixture.otherNode, tags: [ControllerFixture.target])]
        await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        api.inventory = [ControllerFixture.device(tags: [ControllerFixture.target], authorized: false)]
        #expect(try await c.checkEnrollment().contains("waiting"))
        api.inventory = [ControllerFixture.device(tags: [ControllerFixture.target, "tag:extra"])]
        await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        api.inventory = [ControllerFixture.device(tags: [ControllerFixture.target])]
        #expect(try await c.checkEnrollment().contains("authorized pinned node"))
        #expect(api.submitted.count == writes); #expect(trust.signed.count == signatures)
        api.snapshot = PolicySnapshot(bytes: api.snapshot.bytes, etag: "\"external-change\"")
        await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        #expect(api.submitted.count == writes)
    }
    @Test func matchingPinnedNodeCannotHideASecondDestinationTagHolder() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        _ = try await c.execute(review)
        let writes = api.submitted.count, signatures = trust.signed.count
        let pinned = ControllerFixture.device(tags: [ControllerFixture.target])
        let conflict = TailnetDevice(id: "fixture-other-device", nodeID: "fixture-other-node", nodeKey: ControllerFixture.otherNode,
            authorized: false, tags: [ControllerFixture.target], name: "other.invalid", hostname: "other")
        for inventory in [[pinned, conflict], [conflict, pinned]] {
            api.inventory = inventory
            await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        }
        #expect(api.submitted.count == writes); #expect(trust.signed.count == signatures)
    }
    @Test func approvalExpiryDuringWriterTokenAcquisitionNeverDispatchesPOST() async throws {
        var t = ContinuousClock.now
        let c = try configured(clock: { t }), review = try await c.prepare(proposal: Compiler.example)
        api.onWriterToken = { t = t.advanced(by: .seconds(120)) }
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }
        #expect(api.submitted.isEmpty); #expect(trust.unresolved == nil)
        #expect(trust.outcomes[review.id] == "rejected")
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }
        #expect(api.submitted.isEmpty)
    }
    @Test func discardDuringWriterTokenAcquisitionNeverDispatchesPOST() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        api.onWriterToken = { c.discard() }
        await #expect(throws: LiveFailure.obsolete) { try await c.execute(review) }
        #expect(api.submitted.isEmpty); #expect(trust.unresolved == nil)
        #expect(trust.outcomes[review.id] == "rejected")
    }
    @Test func oldSuccessfulReceiptCannotDescribeANewerCrashedIntent() async throws {
        let c = try configured(), first = try await c.prepare(proposal: Compiler.example)
        _ = try await c.execute(first)
        let secondProposal = Data(String(decoding: Compiler.example, as: UTF8.self)
            .replacingOccurrences(of: ControllerFixture.target, with: "tag:workload-second").utf8)
        let second = try await c.prepare(proposal: secondProposal)
        trust.denyReceipt = true
        await #expect(throws: LiveFailure.blocked) { try await c.execute(second) }
        #expect(trust.unresolved == second.id); #expect(api.submitted.count == 1)
        let restarted = controller(), beforeReads = api.policiesRead
        await #expect(throws: LiveFailure.noReceipt) { try await restarted.reconcile() }
        #expect(api.policiesRead == beforeReads); #expect(api.submitted.count == 1)
        #expect(trust.unresolved == second.id)
    }
    @Test func credentialLengthsMatchTransportBoundsBeforeConfigurationIsStored() throws {
        for longID in [true, false] {
            let localTrust = ControllerTrust(), localAPI = ControllerAPI()
            let c = LiveController(trust: localTrust, makeAPI: { _ in localAPI }, clock: { .now })
            #expect(throws: LiveFailure.settings) {
                try c.configure(tailnet: ControllerFixture.tailnet, vm: "demo-vm", source: "tag:demo-client", nodeKey: ControllerFixture.node,
                    readClientID: longID ? String(repeating: "r", count: 257) : "fixture-reader",
                    readSecret: longID ? "fixture-reader-material" : String(repeating: "r", count: 4097),
                    writeClientID: "fixture-writer", writeSecret: "fixture-writer-material")
            }
            #expect(localTrust.slots["configuration"] == nil); #expect(localAPI.policiesRead == 0)
        }
    }
    @Test func enrollmentCannotUseMutableReceiptWithoutMatchingAppliedJournalRecord() async throws {
        let c = try configured(), review = try await c.prepare(proposal: Compiler.example)
        _ = try await c.execute(review)
        api.inventory = [ControllerFixture.device(tags: [ControllerFixture.target])]
        #expect(try await c.checkEnrollment().contains("authorized pinned node"))
        let before = api.policiesRead
        trust.reservations[review.id] = Data(repeating: 0, count: 32)
        await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        #expect(api.policiesRead == before); #expect(api.submitted.count == 1)
        trust.reservations[review.id] = Data(SHA256.hash(data: Data(review.text.utf8)))
        trust.outcomes[review.id] = "rejected"
        await #expect(throws: LiveFailure.enrollment) { try await c.checkEnrollment() }
        #expect(api.policiesRead == before); #expect(api.submitted.count == 1)
    }
    @Test func readFailureAndMissingReceiptsNeverProduceWrites() async throws {
        let c = try configured(); api.readFails = true
        await #expect(throws: LiveFailure.read) { try await c.prepare(proposal: Compiler.example) }
        api.readFails = false
        await #expect(throws: LiveFailure.noReceipt) { try await c.reconcile() }
        await #expect(throws: LiveFailure.noReceipt) { try await c.checkEnrollment() }
        #expect(api.submitted.isEmpty); #expect(trust.signed.isEmpty)
    }
}
