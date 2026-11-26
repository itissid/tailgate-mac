import Foundation

/// Identity captured by the human through an independently trusted VM console. This
/// type validates shape, not provenance: the trusted UI must not construct it from
/// an agent proposal, hostname match, latest device, or an enrollment URL.
public struct EnrollmentVMBinding: Equatable, Sendable {
    public let label: String
    public let nodeKey: String
    public let expectedDeviceID: String?

    public init(label: String, nodeKey: String, expectedDeviceID: String? = nil) throws {
        guard Self.safeLabel(label), Self.validNodeKey(nodeKey),
              expectedDeviceID.map(Self.safeID) ?? true else { throw EnrollmentError.invalidBinding }
        self.label = label
        self.nodeKey = nodeKey
        self.expectedDeviceID = expectedDeviceID
    }

    /// Include these exact values in the human-reviewed and signed plan. The
    /// display label alone is not an identity pin.
    public var reviewText: String {
        "VM: \(label)\nPinned node public key: \(nodeKey)\nExpected device ID: \(expectedDeviceID ?? "not yet assigned")"
    }

    private static func safeLabel(_ text: String) -> Bool {
        (1...80).contains(text.utf8.count) && text.utf8.allSatisfy { (32...126).contains($0) }
            && text == text.trimmingCharacters(in: .whitespaces)
    }
    fileprivate static func safeID(_ text: String) -> Bool {
        (1...128).contains(text.utf8.count) && text.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
        }
    }
    fileprivate static func validNodeKey(_ text: String) -> Bool {
        text.hasPrefix("nodekey:") && Self.hex64(String(text.dropFirst(8)))
    }
    fileprivate static func hex64(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    fileprivate static func validTag(_ text: String) -> Bool {
        guard text.hasPrefix("tag:"), (5...64).contains(text.utf8.count),
              let first = text.dropFirst(4).utf8.first, (97...122).contains(first) else { return false }
        return text.dropFirst(4).utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
    fileprivate static func validETag(_ text: String) -> Bool {
        // A strong quoted server ETag is mandatory. Never treat '*' or a weak
        // ETag as proof of the applied policy version.
        text.utf8.count >= 3 && text.utf8.count <= 256 && text.first == "\"" && text.last == "\""
            && text.dropFirst().dropLast().utf8.allSatisfy { (33...126).contains($0) && $0 != 34 }
    }
}

public enum EnrollmentError: String, Error, Equatable, LocalizedError, Sendable {
    case invalidBinding = "Enrollment requires a human-verified node public-key pin and valid local VM binding."
    case invalidPlan = "The applied enrollment plan is incomplete or invalid."
    case policyChanged = "Policy changed since the approved write. Stop and review again."
    case identityChanged = "The pinned device ID now has a different node public key. Stop; do not select another device."
    case ambiguousIdentity = "More than one device matched the identity pin. Enrollment cannot be confirmed."
    case unexpectedTags = "The pinned node has tags other than the one approved tag. Enrollment cannot be confirmed."
    case destinationTagConflict = "A non-pinned node also carries the reviewed destination tag. Access is broader than the intended VM; stop and reconcile without automatic cleanup."
    case expired = "Enrollment wait expired. No key or enrollment operation was attempted."
    case cancelled = "Enrollment wait cancelled. No cleanup write was attempted."
    case invalidObservation = "Enrollment inventory observation is invalid or unsupported."
    case keyPathDisabled = "Key enrollment is disabled: reviewed short TTL, isolated pinned receiver, and atomic policy binding are not established. Use explicit browser enrollment; no key was issued."
    public var errorDescription: String? { rawValue }
}

/// Construct only AFTER the broker reconciles the successful approved policy
/// write. The plan hash must cover the VM binding, mode, tag, and policy bytes.
/// This value is not an approval token and grants no write authority.
public struct BrowserEnrollmentPlan: Equatable, Sendable {
    public let reviewID: UUID
    public let tailnet: String
    public let reviewedPlanSHA256: String
    public let appliedPolicySHA256: String
    public let postApplyETag: String
    public let binding: EnrollmentVMBinding
    public let expectedTag: String
    public let startedAt: Date
    public let deadline: Date

    public init(reviewID: UUID, tailnet: String, reviewedPlanSHA256: String, appliedPolicySHA256: String,
                postApplyETag: String, binding: EnrollmentVMBinding, expectedTag: String,
                startedAt: Date, timeoutSeconds: Int = 300) throws {
        guard (1...200).contains(tailnet.utf8.count), tailnet != "-", tailnet.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 64].contains($0)
        }), EnrollmentVMBinding.hex64(reviewedPlanSHA256), EnrollmentVMBinding.hex64(appliedPolicySHA256),
              EnrollmentVMBinding.validETag(postApplyETag), EnrollmentVMBinding.validTag(expectedTag),
              startedAt.timeIntervalSince1970.isFinite, (1...900).contains(timeoutSeconds) else { throw EnrollmentError.invalidPlan }
        self.reviewID = reviewID
        self.tailnet = tailnet
        self.reviewedPlanSHA256 = reviewedPlanSHA256
        self.appliedPolicySHA256 = appliedPolicySHA256
        self.postApplyETag = postApplyETag
        self.binding = binding
        self.expectedTag = expectedTag
        self.startedAt = startedAt
        self.deadline = startedAt.addingTimeInterval(TimeInterval(timeoutSeconds))
    }
}

/// Public fields map to a fresh, authenticated Tailscale inventory response.
/// Missing nodeKey is intentionally representable and never substituted from a
/// hostname, machineKey, IP address, or legacy device name.
public struct EnrollmentDeviceObservation: Equatable, Sendable {
    public let id: String
    public let nodeKey: String?
    public let tags: [String]
    public let authorized: Bool
    public init(id: String, nodeKey: String?, tags: [String], authorized: Bool) {
        self.id = id; self.nodeKey = nodeKey; self.tags = tags; self.authorized = authorized
    }
}

/// The read-only caller brackets its inventory GET with two policy GETs. A
/// concurrent policy version change during observation must not produce success.
public struct EnrollmentSnapshot: Sendable {
    public let tailnet: String
    public let policyETagBefore: String
    public let policyETagAfter: String
    public let policySHA256Before: String
    public let policySHA256After: String
    public let devices: [EnrollmentDeviceObservation]
    public let observedAt: Date
    public init(tailnet: String, policyETagBefore: String, policyETagAfter: String, policySHA256Before: String,
                policySHA256After: String, devices: [EnrollmentDeviceObservation], observedAt: Date) {
        self.tailnet = tailnet
        self.policyETagBefore = policyETagBefore; self.policyETagAfter = policyETagAfter
        self.policySHA256Before = policySHA256Before; self.policySHA256After = policySHA256After
        self.devices = devices; self.observedAt = observedAt
    }
}

public enum EnrollmentWaitingReason: String, Equatable, Sendable {
    case pinnedNodeNotPresent = "Waiting for the pinned node to appear. No enrollment action was performed."
    case nodeNotAuthorized = "Pinned node found; waiting for explicit human authorization."
    case reviewedTagNotPresent = "Pinned node found; waiting for exactly the reviewed tag. No tag was applied."
    case freshInventoryRequired = "A fresh read-only inventory check is required."
}

/// A sanitized read-only receipt. It proves what was observed at checkedAt, not
/// indefinite connectivity, future policy state, or a cryptographically attested VM.
public struct EnrollmentVerifiedReceipt: Equatable, Sendable {
    public let reviewID: UUID
    public let reviewedPlanSHA256: String
    public let policySHA256: String
    public let policyETag: String
    public let deviceID: String
    public let nodeKey: String
    public let exactTag: String
    public let checkedAt: Date
}

public enum BrowserEnrollmentState: Equatable, Sendable {
    case waiting(EnrollmentWaitingReason)
    case verified(EnrollmentVerifiedReceipt)
    case stopped(EnrollmentError)
}

/// In-memory, read-only state machine. It owns no API client or credentials and
/// cannot mint keys, open login URLs, authorize/retag devices, or invoke a shell.
/// Each monitor belongs to one reviewed plan. Terminal states cannot be resumed
/// by substituting another snapshot or plan.
public struct BrowserEnrollmentMonitor: Sendable {
    public let plan: BrowserEnrollmentPlan
    public private(set) var state: BrowserEnrollmentState = .waiting(.pinnedNodeNotPresent)
    public init(plan: BrowserEnrollmentPlan) { self.plan = plan }

    @discardableResult public mutating func cancel() -> BrowserEnrollmentState {
        guard case .waiting = state else { return state }
        state = .stopped(.cancelled); return state
    }

    @discardableResult public mutating func inspect(_ snapshot: EnrollmentSnapshot, now: Date) -> BrowserEnrollmentState {
        guard case .waiting = state else { return state }
        if !now.timeIntervalSince1970.isFinite || now < plan.startedAt || now >= plan.deadline {
            state = .stopped(.expired); return state
        }
        guard snapshot.tailnet == plan.tailnet, snapshot.policyETagBefore == plan.postApplyETag, snapshot.policyETagAfter == plan.postApplyETag,
              snapshot.policySHA256Before == plan.appliedPolicySHA256, snapshot.policySHA256After == plan.appliedPolicySHA256 else {
            state = .stopped(.policyChanged); return state
        }
        guard snapshot.devices.count <= 10_000 else { state = .stopped(.invalidObservation); return state }
        // A destination tag grants access to every holder, not just the pinned
        // VM. Reject any other holder (including one with a missing key) before
        // a waiting or success result. Stale evidence of a conflict is also a
        // reason to stop and reconcile, never a reason to broaden access.
        guard !snapshot.devices.contains(where: { $0.nodeKey != plan.binding.nodeKey && $0.tags.contains(plan.expectedTag) }) else {
            state = .stopped(.destinationTagConflict); return state
        }
        guard snapshot.observedAt.timeIntervalSince1970.isFinite, snapshot.observedAt >= plan.startedAt,
              snapshot.observedAt <= now, now.timeIntervalSince(snapshot.observedAt) <= 30 else {
            state = .waiting(.freshInventoryRequired); return state
        }
        if let id = plan.binding.expectedDeviceID,
           snapshot.devices.contains(where: { $0.id == id && $0.nodeKey != plan.binding.nodeKey }) {
            state = .stopped(.identityChanged); return state
        }
        let matches = snapshot.devices.filter { $0.nodeKey == plan.binding.nodeKey }
        guard matches.count <= 1 else { state = .stopped(.ambiguousIdentity); return state }
        guard let device = matches.first else { state = .waiting(.pinnedNodeNotPresent); return state }
        guard EnrollmentVMBinding.safeID(device.id) else { state = .stopped(.invalidObservation); return state }
        guard snapshot.devices.filter({ $0.id == device.id }).count == 1 else { state = .stopped(.ambiguousIdentity); return state }
        if let id = plan.binding.expectedDeviceID, device.id != id { state = .stopped(.identityChanged); return state }
        guard device.tags.isEmpty || device.tags == [plan.expectedTag] else { state = .stopped(.unexpectedTags); return state }
        guard device.authorized else { state = .waiting(.nodeNotAuthorized); return state }
        guard device.tags == [plan.expectedTag] else { state = .waiting(.reviewedTagNotPresent); return state }
        state = .verified(EnrollmentVerifiedReceipt(reviewID: plan.reviewID, reviewedPlanSHA256: plan.reviewedPlanSHA256,
            policySHA256: plan.appliedPolicySHA256, policyETag: plan.postApplyETag, deviceID: device.id,
            nodeKey: plan.binding.nodeKey, exactTag: plan.expectedTag, checkedAt: now))
        return state
    }
}

/// No caller-supplied capability flag can turn this on. The service key format is
/// bearer-based; this build has neither a verified sub-day TTL contract nor a
/// secret-isolated VM receiver or cross-endpoint policy/key transaction. Fail
/// closed BEFORE any OAuth or network activity; do not fall back automatically.
public enum KeyEnrollmentAvailability {
    public static let isEnabled = false
    public static let explanation = EnrollmentError.keyPathDisabled.rawValue
    public static func requireAvailable() throws -> Never { throw EnrollmentError.keyPathDisabled }
}
