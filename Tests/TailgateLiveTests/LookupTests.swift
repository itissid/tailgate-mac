import CryptoKit
import Foundation
import Testing
@testable import TailgateLive

@MainActor private final class LookupStore: LookupTrust {
    var values: [String: Data] = [:]
    var slots = [String]()
    var messages = [Data]()
    var approve = true
    var verifyOK = true
    var onSign: (() -> Void)?
    func load(slot: String) throws -> Data {
        slots.append(slot)
        guard let data = values[slot] else { throw MacTrustError.missing }; return data
    }
    func sign(message: Data, reason: String) async throws -> Data {
        messages.append(message); onSign?()
        guard approve else { throw MacTrustError.signatureFailed }; return Data("signature".utf8)
    }
    func verify(message: Data, signature: Data) throws {
        guard verifyOK else { throw MacTrustError.signatureFailed }
    }
}
@MainActor private final class LookupFake: LookupService {
    var inventory = [LookupDevice]()
    var reads = 0
    var fail = false
    var onRead: (() -> Void)?
    func lookupInventory(using credential: OAuthCredential) async throws -> [LookupDevice] {
        reads += 1; onRead?(); if fail { throw TailnetAPIError.unavailable }; return inventory
    }
}

@MainActor struct LookupTests {
    private let store = LookupStore()
    private let api = LookupFake()
    private let name = "demo-vm"
    private var ips: [String] { [["100","100","1","2"].joined(separator: "."), ["fd7a", "115c", "a1e0", "", "1234"].joined(separator: ":")] }
    private func device(name: String = "demo-vm", id: String = "device-demo", key: String = "fixture-node", auth: Bool = true, tags: [String] = ["tag:demo"], ips: [String]? = nil) -> LookupDevice {
        .init(id: id, nodeKey: key, hostname: name, authorized: auth, tags: tags, addresses: ips)
    }
    private func query(_ fields: String = "name") -> Data { Data("TAILGATE-LOOKUP/1\n\(name)\n\(fields)\n".utf8) }
    private func setup(clock: @escaping () -> ContinuousClock.Instant = { .now }) throws -> DeviceLookupController {
        store.values["lookup-reader"] = try LookupConfiguration(tailnet: "tailnet.example", clientID: "reader-id", secret: "synthetic-reader-value").encoded()
        api.inventory = [device(ips: ips)]
        return DeviceLookupController(trust: store, makeService: { _ in api }, clock: clock)
    }
    @Test func strictQueryRejectsBroadOrAmbiguousForms() throws {
        for field in ["name", "name,tags", "name,ips", "name,tags,ips"] { _ = try LookupQuery(query(field)) }
        for value in ["", "TAILGATE-LOOKUP/1\n*\nname\n", "TAILGATE-LOOKUP/1\ndemo\nname,ips,tags\n", "TAILGATE-LOOKUP/1\ndemo\nips\n", "TAILGATE-LOOKUP/1\ndemo\nname,name\n", "TAILGATE-LOOKUP/1\ndemo.example\nname\n", "TAILGATE-LOOKUP/1\ndemo\nname\nextra", "TAILGATE-LOOKUP/1\nDemo\nname\n", "TAILGATE-LOOKUP/1\ndemo\nname\r\n", "TAILGATE-LOOKUP/1\ndemo*\nname\n", "TAILGATE-LOOKUP/1\ndemo,other\nname\n", "TAILGATE-LOOKUP/1\ndemo\nname\n\n"] {
            #expect(throws: LookupFailure.rejected) { try LookupQuery(Data(value.utf8)) }
        }
        #expect(throws: LookupFailure.rejected) { try LookupQuery(Data(repeating: 65, count: 161)) }
    }
    @Test func noRequestBeforeFetchAndNoDisclosureBeforeBiometricApproval() async throws {
        let c = try setup(); #expect(api.reads == 0); #expect(store.messages.isEmpty)
        let review = try await c.prepare(query: query())
        #expect(api.reads == 1); #expect(store.messages.isEmpty)
        #expect(review.text.contains("Exact response JSON")); #expect(!review.text.contains("fixture-node")); #expect(!review.text.contains("device-demo"))
        let bytes = try await c.disclose(review)
        #expect(api.reads == 2); #expect(store.messages == [Data(review.text.utf8)])
        #expect(String(decoding: bytes, as: UTF8.self) == "{\"device\":{\"name\":\"demo-vm\"},\"status\":\"disclosed\",\"version\":1}")
        #expect(Set(store.slots) == ["lookup-reader"])
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(review) }
    }
    @Test func selectionMinimizesFieldsAndNeverIncludesSiblingOrIdentity() async throws {
        let c = try setup()
        api.inventory.append(device(name: "another-vm", id: "sibling-id", key: "sibling-key", tags: ["tag:private-sibling"], ips: ["192.0.2.9"]))
        for fields in ["name", "name,tags", "name,ips", "name,tags,ips"] {
            let review = try await c.prepare(query: query(fields)), output = try await c.disclose(review)
            let obj = try #require(JSONSerialization.jsonObject(with: output) as? [String: Any]), body = try #require(obj["device"] as? [String: Any])
            #expect(body["name"] as? String == name)
            #expect((body["tags"] != nil) == fields.contains("tags")); #expect((body["ips"] != nil) == fields.contains("ips"))
            let text = String(decoding: output, as: UTF8.self)
            #expect(!text.contains("sibling")); #expect(!text.contains("fixture-node")); #expect(!text.contains("tailnet.example"))
        }
    }
    @Test func missingAmbiguousAndUnauthorizedLookIdentical() async throws {
        let c = try setup()
        for inventory in [[], [device(name: "demo")], [device(auth: false)], [device(), device(id: "different", key: "different")]] as [[LookupDevice]] {
            api.inventory = inventory
            await #expect(throws: LookupFailure.rejected) { try await c.prepare(query: query()) }
        }
        #expect(store.messages.isEmpty)
    }
    @Test func invalidIPRequestsFailClosedAndNeverRevealLANOrPublicEndpoints() async throws {
        let c = try setup()
        let invalid = ["192.0.2.3", "127.0.0.1", "10.0.0.1", "::1", "fe80::1", "2001:db8::1", "fd00::1", "example.com", ips[0] + "/32", ips[1] + "%en0", "::ffff:" + ips[0]]
        for address in invalid {
            api.inventory = [device(ips: [address])]
            await #expect(throws: LookupFailure.rejected) { try await c.prepare(query: query("name,ips")) }
        }
        for list in [nil, [], [ips[0], ips[0]], Array(repeating: ips[0], count: 9)] as [[String]?] {
            api.inventory = [device(ips: list)]
            await #expect(throws: LookupFailure.rejected) { try await c.prepare(query: query("name,ips")) }
        }
        // No IP request means no IP disclosure or synthetic validation failure.
        api.inventory = [device(ips: ["192.0.2.3"])]; _ = try await c.prepare(query: query())
    }
    @Test func declineVerificationFailureAndDiscardBurnTheReview() async throws {
        let c = try setup(), r = try await c.prepare(query: query())
        store.approve = false
        await #expect(throws: LookupFailure.declined) { try await c.disclose(r) }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(r) }
        store.approve = true; store.verifyOK = false
        let next = try await c.prepare(query: query())
        await #expect(throws: LookupFailure.declined) { try await c.disclose(next) }
        store.verifyOK = true
        let last = try await c.prepare(query: query()); store.onSign = { c.discard() }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(last) }
        #expect(api.reads == 3)
    }
    @Test func expiryBeforeDuringAndAfterPromptStopsDisclosure() async throws {
        var t = ContinuousClock.now
        let c = try setup(clock: { t }), first = try await c.prepare(query: query())
        t = t.advanced(by: .seconds(120))
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(first) }
        #expect(store.messages.isEmpty)
        let second = try await c.prepare(query: query()); store.onSign = { t = t.advanced(by: .seconds(120)) }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(second) }
        store.onSign = nil
        let third = try await c.prepare(query: query()); api.onRead = { t = t.advanced(by: .seconds(120)) }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(third) }
    }
    @Test func changedSelectedDataOrDeviceIdentityRequiresNewReview() async throws {
        let c = try setup()
        for changed in [device(id: "replacement", ips: ips), device(key: "replacement", ips: ips), device(auth: false, ips: ips), device(tags: ["tag:changed"], ips: ips), device(ips: [ips[0]])] {
            api.inventory = [device(ips: ips)]
            let review = try await c.prepare(query: query("name,tags,ips")); store.onSign = { api.inventory = [changed] }
            do { _ = try await c.disclose(review); Issue.record("Changed lookup must not disclose") } catch { #expect(error is LookupFailure) }
            store.onSign = nil
        }
    }
    @Test func replacingReviewEvenWithInvalidQueryInvalidatesPrevious() async throws {
        let c = try setup(), old = try await c.prepare(query: query())
        await #expect(throws: LookupFailure.rejected) { try await c.prepare(query: Data()) }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(old) }
    }
    @Test func configurationNeverFallsBackToWriterAndChangesInvalidateReview() async throws {
        let c = try setup(); store.values["lookup-reader"] = nil; store.values["configuration"] = Data("writer-bearing-config".utf8)
        await #expect(throws: LookupFailure.rejected) { try await c.prepare(query: query()) }
        #expect(Set(store.slots) == ["lookup-reader"])
        store.values["lookup-reader"] = try LookupConfiguration(tailnet: "tailnet.example", clientID: "reader-id", secret: "synthetic-reader-value").encoded()
        let review = try await c.prepare(query: query())
        store.onSign = { store.values["lookup-reader"] = try! LookupConfiguration(tailnet: "tailnet.example", clientID: "other-reader", secret: "other-reader-value").encoded() }
        await #expect(throws: LookupFailure.obsolete) { try await c.disclose(review) }
    }
    @Test func configurationBoundsAndFailureTextDoNotEchoInput() throws {
        for (id, secret) in [("", "x"), ("valid-id", ""), (String(repeating: "x", count: 257), "x"), ("valid-id", String(repeating: "x", count: 4097)), ("valid-id", "line\nbreak")] {
            #expect(throws: (any Error).self) { try LookupConfiguration(tailnet: "tailnet.example", clientID: id, secret: secret) }
        }
        #expect(!LookupFailure.rejected.localizedDescription.contains("demo-vm"))
    }
}
