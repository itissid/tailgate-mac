import Foundation
import Testing
@testable import TailgateLive

struct EnrollmentTests {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private let key = "nodekey:" + String(repeating: "a", count: 64)
    private let hash = String(repeating: "b", count: 64)
    private let reviewHash = String(repeating: "c", count: 64)
    private let etag = "\"applied-policy-v2\""
    private let tag = "tag:workload-demo-api"
    private let target = "example.com"

    private func plan(deviceID: String? = nil, timeout: Int = 300) throws -> BrowserEnrollmentPlan {
        try BrowserEnrollmentPlan(reviewID: UUID(), tailnet: target, reviewedPlanSHA256: reviewHash,
            appliedPolicySHA256: hash, postApplyETag: etag,
            binding: EnrollmentVMBinding(label: "Human-pinned VM", nodeKey: key, expectedDeviceID: deviceID),
            expectedTag: tag, startedAt: start, timeoutSeconds: timeout)
    }
    private func device(id: String = "n123example", key: String? = nil, tags: [String]? = nil, authorized: Bool = true) -> EnrollmentDeviceObservation {
        EnrollmentDeviceObservation(id: id, nodeKey: key ?? self.key, tags: tags ?? [tag], authorized: authorized)
    }
    private func snapshot(_ devices: [EnrollmentDeviceObservation], before: String? = nil, after: String? = nil,
                          beforeHash: String? = nil, afterHash: String? = nil, time: Date? = nil,
                          tailnet: String? = nil) -> EnrollmentSnapshot {
        EnrollmentSnapshot(tailnet: tailnet ?? target, policyETagBefore: before ?? etag, policyETagAfter: after ?? etag,
            policySHA256Before: beforeHash ?? hash, policySHA256After: afterHash ?? hash,
            devices: devices, observedAt: time ?? start)
    }
    @Test func humanBindingRequiresExactKeyNotHostnameOrURL() throws {
        for bad in ["vm.example.com", "https://login.tailscale.com/a/abc", "", key.uppercased(), "nodekey:" + String(repeating: "g", count: 64)] {
            #expect(throws: EnrollmentError.invalidBinding) { try EnrollmentVMBinding(label: "VM", nodeKey: bad) }
        }
        for label in [" VM", "VM\nInjected summary", "", "VM\u{202e}"] {
            #expect(throws: EnrollmentError.invalidBinding) { try EnrollmentVMBinding(label: label, nodeKey: key) }
        }
        #expect(throws: EnrollmentError.invalidBinding) { try EnrollmentVMBinding(label: "VM", nodeKey: key, expectedDeviceID: "../other") }
        let binding = try EnrollmentVMBinding(label: "VM", nodeKey: key)
        #expect(binding.reviewText.contains(key)); #expect(binding.reviewText.contains("not yet assigned"))
    }
    @Test func planRequiresStrongETagAndExactTargetAndHashes() throws {
        let binding = try EnrollmentVMBinding(label: "VM", nodeKey: key)
        for bad in ["", "*", "W/\"weak\"", "not-quoted", "\"\"", "\"injected\nheader\""] {
            #expect(throws: EnrollmentError.invalidPlan) {
                try BrowserEnrollmentPlan(reviewID: UUID(), tailnet: target, reviewedPlanSHA256: reviewHash,
                    appliedPolicySHA256: hash, postApplyETag: bad, binding: binding, expectedTag: tag, startedAt: start)
            }
        }
        #expect(throws: EnrollmentError.invalidPlan) {
            try BrowserEnrollmentPlan(reviewID: UUID(), tailnet: "-", reviewedPlanSHA256: reviewHash,
                appliedPolicySHA256: hash, postApplyETag: etag, binding: binding, expectedTag: tag, startedAt: start)
        }
        #expect(throws: EnrollmentError.invalidPlan) {
            try BrowserEnrollmentPlan(reviewID: UUID(), tailnet: target, reviewedPlanSHA256: "not-a-hash",
                appliedPolicySHA256: hash, postApplyETag: etag, binding: binding, expectedTag: tag, startedAt: start)
        }
        #expect(throws: EnrollmentError.invalidPlan) { try plan(timeout: 0) }
        #expect(throws: EnrollmentError.invalidPlan) { try plan(timeout: 901) }
    }
    @Test func authorizedPinnedNodeWithExactTagVerifiesAppliedPlan() throws {
        let p = try plan(); var monitor = BrowserEnrollmentMonitor(plan: p)
        let result = monitor.inspect(snapshot([device()]), now: start)
        guard case let .verified(receipt) = result else { Issue.record("Expected verified receipt"); return }
        #expect(receipt.reviewID == p.reviewID); #expect(receipt.reviewedPlanSHA256 == reviewHash)
        #expect(receipt.policySHA256 == hash); #expect(receipt.policyETag == etag)
        #expect(receipt.deviceID == "n123example"); #expect(receipt.nodeKey == key); #expect(receipt.exactTag == tag)
        #expect(receipt.checkedAt == start)
    }
    @Test func missingOrUnpinnedDevicesNeverSubstituteLatestJoin() throws {
        var monitor = BrowserEnrollmentMonitor(plan: try plan())
        #expect(monitor.inspect(snapshot([]), now: start) == .waiting(.pinnedNodeNotPresent))
        #expect(monitor.inspect(snapshot([device(key: "nodekey:" + String(repeating: "d", count: 64), tags: [])]), now: start) == .waiting(.pinnedNodeNotPresent))
        let missing = EnrollmentDeviceObservation(id: "n123example", nodeKey: nil, tags: [], authorized: true)
        #expect(monitor.inspect(snapshot([missing]), now: start) == .waiting(.pinnedNodeNotPresent))
    }
    @Test func destinationTagOnAnyNonPinnedNodeStopsBeforeWaitingOrVerifying() throws {
        let otherKey = "nodekey:" + String(repeating: "d", count: 64)
        let otherNodes = [
            device(id: "nOther", key: otherKey),
            device(id: "nOther", key: otherKey, tags: ["tag:unrelated", tag, "tag:another"], authorized: false),
            EnrollmentDeviceObservation(id: "nOther", nodeKey: nil, tags: [tag], authorized: true)
        ]
        for other in otherNodes {
            for pinned in [[EnrollmentDeviceObservation](), [device()], [device(tags: [])], [device(authorized: false)]] {
                var monitor = BrowserEnrollmentMonitor(plan: try plan())
                #expect(monitor.inspect(snapshot(pinned + [other]), now: start) == .stopped(.destinationTagConflict))
                #expect(monitor.inspect(snapshot([device()]), now: start) == .stopped(.destinationTagConflict))
            }
            var stale = BrowserEnrollmentMonitor(plan: try plan())
            #expect(stale.inspect(snapshot([other]), now: start.addingTimeInterval(60)) == .stopped(.destinationTagConflict))
        }
        var unrelated = BrowserEnrollmentMonitor(plan: try plan())
        #expect(unrelated.inspect(snapshot([device(id: "nOther", key: otherKey, tags: ["tag:unrelated"])]), now: start) == .waiting(.pinnedNodeNotPresent))
    }
    @Test func unauthorizedNodeWaitsWithoutAuthorizingIt() throws {
        var monitor = BrowserEnrollmentMonitor(plan: try plan())
        #expect(monitor.inspect(snapshot([device(authorized: false)]), now: start) == .waiting(.nodeNotAuthorized))
        #expect(monitor.inspect(snapshot([device()]), now: start) != .waiting(.nodeNotAuthorized))
    }
    @Test func untaggedNodeWaitsWithoutRetaggingIt() throws {
        var monitor = BrowserEnrollmentMonitor(plan: try plan())
        #expect(monitor.inspect(snapshot([device(tags: [])]), now: start) == .waiting(.reviewedTagNotPresent))
        #expect(monitor.inspect(snapshot([device()]), now: start) != .waiting(.reviewedTagNotPresent))
    }
    @Test func anyExtraOrWrongTagStops() throws {
        for tags in [[tag, "tag:extra"], ["tag:extra"], [tag, tag]] {
            var monitor = BrowserEnrollmentMonitor(plan: try plan())
            #expect(monitor.inspect(snapshot([device(tags: tags)]), now: start) == .stopped(.unexpectedTags))
            #expect(monitor.inspect(snapshot([device()]), now: start) == .stopped(.unexpectedTags))
        }
    }
    @Test func wrongDeviceIDOrRotatedNodeKeyStops() throws {
        var rotated = BrowserEnrollmentMonitor(plan: try plan(deviceID: "n123example"))
        #expect(rotated.inspect(snapshot([device(key: "nodekey:" + String(repeating: "e", count: 64), tags: [])]), now: start) == .stopped(.identityChanged))
        var swapped = BrowserEnrollmentMonitor(plan: try plan(deviceID: "n123example"))
        #expect(swapped.inspect(snapshot([device(id: "nDifferent")]), now: start) == .stopped(.identityChanged))
    }
    @Test func duplicateKeysOrIDsCannotConfirmEnrollment() throws {
        var sameKey = BrowserEnrollmentMonitor(plan: try plan())
        #expect(sameKey.inspect(snapshot([device(), device(id: "nOther")]), now: start) == .stopped(.ambiguousIdentity))
        var sameID = BrowserEnrollmentMonitor(plan: try plan())
        #expect(sameID.inspect(snapshot([device(), device(key: "nodekey:" + String(repeating: "e", count: 64), tags: [])]), now: start) == .stopped(.ambiguousIdentity))
    }
    @Test func policyMustMatchBeforeAndAfterInventoryRead() throws {
        let cases = [snapshot([device()], before: "\"old\""), snapshot([device()], after: "\"new\""),
                     snapshot([device()], beforeHash: String(repeating: "e", count: 64)),
                     snapshot([device()], afterHash: String(repeating: "e", count: 64)),
                     snapshot([device()], tailnet: "another.example")]
        for observation in cases {
            var monitor = BrowserEnrollmentMonitor(plan: try plan())
            #expect(monitor.inspect(observation, now: start) == .stopped(.policyChanged))
        }
    }
    @Test func staleFutureOrPreApplyObservationsCannotVerify() throws {
        let now = start.addingTimeInterval(60)
        for time in [start, now.addingTimeInterval(1), start.addingTimeInterval(-1)] {
            var monitor = BrowserEnrollmentMonitor(plan: try plan())
            #expect(monitor.inspect(snapshot([device()], time: time), now: now) == .waiting(.freshInventoryRequired))
            #expect(monitor.inspect(snapshot([device()], time: now), now: now) != .waiting(.freshInventoryRequired))
        }
    }
    @Test func timeoutAndCancellationAreTerminalWithoutCleanup() throws {
        var expired = BrowserEnrollmentMonitor(plan: try plan())
        #expect(expired.inspect(snapshot([device()]), now: start.addingTimeInterval(300)) == .stopped(.expired))
        #expect(expired.inspect(snapshot([device()]), now: start) == .stopped(.expired))
        var cancelled = BrowserEnrollmentMonitor(plan: try plan())
        #expect(cancelled.cancel() == .stopped(.cancelled))
        #expect(cancelled.inspect(snapshot([device()]), now: start) == .stopped(.cancelled))
    }
    @Test func verifiedReceiptIsHistoricalAndCannotBeRebound() throws {
        var monitor = BrowserEnrollmentMonitor(plan: try plan())
        let verified = monitor.inspect(snapshot([device()]), now: start)
        #expect(monitor.inspect(snapshot([device(id: "nOther")], after: "\"new\""), now: start) == verified)
        #expect(monitor.cancel() == verified)
    }
    @Test func keyEnrollmentCannotBeEnabledByProposalOrCaller() throws {
        #expect(!KeyEnrollmentAvailability.isEnabled)
        #expect(KeyEnrollmentAvailability.explanation.contains("disabled"))
        #expect(throws: EnrollmentError.keyPathDisabled) { try KeyEnrollmentAvailability.requireAvailable() }
    }
}
