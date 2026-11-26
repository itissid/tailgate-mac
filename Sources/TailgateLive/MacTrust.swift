import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

/// No secret or operating-system error payload is included in a displayed failure.
public enum MacTrustError: String, Error, LocalizedError {
    case untrustedApplication = "Live mode requires the installed, signed, hardened Tailgate app."
    case unavailable = "The protected Mac credential store is unavailable."
    case missing = "The requested protected item has not been provisioned."
    case invalidInput = "The protected operation contains invalid input."
    case biometricUnavailable = "Fresh Touch ID authentication is required and unavailable."
    case signatureFailed = "The exact plan was not signed or its signature is invalid."
    case keyChanged = "The biometric signing key or its pinned public key changed. Stop and reprovision explicitly."
    case unresolvedIntent = "A prior write has an unresolved outcome. Reconcile it before another write."
    case replay = "This write identifier has already been used."
    case alreadyProvisioned = "Credentials are already provisioned. A separately reviewed rotation is required."
    public var errorDescription: String? { rawValue }
}

/// The local authority. Constructing this in `swift run` fails before accessing Keychain.
/// Its public interface never releases the enclave private key. OAuth values returned by
/// `load` are for trusted in-process transport only; no IPC or CLI may expose this object.
@MainActor public final class MacTrust {
    private let accessGroup: String
    private let service: String
    private let keyTag: Data
    private let pinSlot = "signing-public-key-v1"
    private let activeSlot = "intent-active-v1"

    public init() throws {
        let identity = try Self.validateRunningApplication()
        accessGroup = identity
        service = identity + ".authority-v1"
        keyTag = Data((identity + ".approval-key-v1").utf8)
    }

    /// Provision non-journal configuration from the signed app's UI only. Values remain
    /// local, device-only, and inaccessible to a caller lacking this access group.
    public func store(slot: String, value: Data) throws {
        guard ["configuration", "receipt"].contains(slot), !value.isEmpty, value.count <= 65_536 else { throw MacTrustError.invalidInput }
        if slot == "configuration" {
            do { try add(slot: slot, data: value) } // immutable configuration prevents cross-process substitution
            catch MacTrustError.replay { throw MacTrustError.alreadyProvisioned }
            return
        }
        let q = query(slot: slot)
        let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: value] as CFDictionary)
        if status == errSecItemNotFound { try add(slot: slot, data: value) }
        else if status != errSecSuccess { throw MacTrustError.unavailable }
    }

    public func load(slot: String) throws -> Data {
        guard ["configuration", "receipt"].contains(slot) else { throw MacTrustError.invalidInput }
        return try read(slot: slot)
    }

    /// Signs the immutable bytes, not a mutable proposal reference. Key access controls
    /// enforce a fresh biometricCurrentSet authorization at SecKeyCreateSignature.
    public func sign(message: Data, reason: String) async throws -> Data {
        guard (1...1_048_576).contains(message.count), (1...180).contains(reason.utf8.count),
              reason.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else { throw MacTrustError.invalidInput }
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Cancel"
        context.touchIDAuthenticationAllowableReuseDuration = 0
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil), context.biometryType == .touchID else { throw MacTrustError.biometricUnavailable }
        context.localizedReason = reason
        let key = try signingKey(context: context)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data? else { throw MacTrustError.signatureFailed }
        try verify(message: message, signature: signature)
        return signature
    }

    public func verify(message: Data, signature: Data) throws {
        guard (1...1_048_576).contains(message.count), (1...256).contains(signature.count) else { throw MacTrustError.invalidInput }
        let pinned = try read(slot: pinSlot)
        var error: Unmanaged<CFError>?
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256]
        guard let key = SecKeyCreateWithData(pinned as CFData, attrs as CFDictionary, &error),
              SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, signature as CFData, &error) else { throw MacTrustError.signatureFailed }
    }

    /// A single active Keychain item serializes writes even across application instances.
    /// Add is atomic. A crash anywhere after acquiring it blocks subsequent writes.
    public func reserveIntent(id: UUID, digest: Data) throws {
        guard digest.count == 32 else { throw MacTrustError.invalidInput }
        try assertNoUnresolvedIntents()
        let idText = id.uuidString.lowercased()
        if try exists(slot: "intent-" + idText) { throw MacTrustError.replay }
        // Fixed slot is the atomic cross-process lock; include the digest here so
        // a crash before the per-ID record still permits read-only reconciliation.
        do { try add(slot: activeSlot, data: Data(idText.utf8) + digest) }
        catch MacTrustError.replay { throw MacTrustError.unresolvedIntent }
        // On history-add failure intentionally retain the active lock: fail closed.
        try add(slot: "intent-" + idText, data: digest)
    }

    /// Only a definite transport result may release the active lock. Unknown remains
    /// blocked across restart. Recording an outcome twice is a replay, not an update.
    public func finishIntent(id: UUID, outcome: String) throws {
        guard ["applied", "rejected", "unknown"].contains(outcome) else { throw MacTrustError.invalidInput }
        let idText = id.uuidString.lowercased()
        guard let lease = try activeLease(), lease.id == id,
              try read(slot: "intent-" + idText) == lease.digest else { throw MacTrustError.replay }
        try add(slot: "intent-result-" + idText, data: Data(outcome.utf8))
        if outcome != "unknown" {
            guard SecItemDelete(query(slot: activeSlot) as CFDictionary) == errSecSuccess else { throw MacTrustError.unavailable }
        }
    }

    public func assertNoUnresolvedIntents() throws {
        if try exists(slot: activeSlot) { throw MacTrustError.unresolvedIntent }
    }

    /// Read-only recovery hints. Neither clears a lock nor authorizes another POST.
    public func unresolvedDigest() throws -> Data? { try activeLease()?.digest }
    public func unresolvedID() throws -> UUID? { try activeLease()?.id }

    /// Authenticate a restoration receipt against immutable Keychain history, never
    /// against the replaceable UI receipt. Wrong digests are an integrity error.
    public func hasApplied(id: UUID, digest: Data) throws -> Bool {
        guard digest.count == 32 else { throw MacTrustError.invalidInput }
        let idText = id.uuidString.lowercased()
        let history: Data
        do { history = try read(slot: "intent-" + idText) }
        catch MacTrustError.missing { return false }
        guard history.count == 32, history == digest else { throw MacTrustError.replay }
        let outcome: Data
        do { outcome = try read(slot: "intent-result-" + idText) }
        catch MacTrustError.missing { return false }
        guard [Data("applied".utf8), Data("rejected".utf8), Data("unknown".utf8)].contains(outcome) else { throw MacTrustError.unavailable }
        return outcome == Data("applied".utf8)
    }

    private func activeLease() throws -> (id: UUID, digest: Data)? {
        let bytes: Data
        do { bytes = try read(slot: activeSlot) }
        catch MacTrustError.missing { return nil }
        guard bytes.count == 68, let text = String(data: bytes.prefix(36), encoding: .utf8),
              let id = UUID(uuidString: text), id.uuidString.lowercased() == text else { throw MacTrustError.unresolvedIntent }
        return (id, Data(bytes.suffix(32)))
    }

    // MARK: Data Protection Keychain
    private func query(slot: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service, kSecAttrAccount as String: slot,
         kSecAttrAccessGroup as String: accessGroup,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false]
    }
    private func add(slot: String, data: Data) throws {
        var q = query(slot: slot)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem { throw MacTrustError.replay }
        guard status == errSecSuccess else { throw MacTrustError.unavailable }
    }
    private func read(slot: String) throws -> Data {
        var q = query(slot: slot)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { throw MacTrustError.missing }
        guard status == errSecSuccess, let bytes = result as? Data else { throw MacTrustError.unavailable }
        return bytes
    }
    private func exists(slot: String) throws -> Bool {
        do { _ = try read(slot: slot); return true }
        catch MacTrustError.missing { return false }
    }

    // MARK: Secure Enclave
    private func signingKey(context: LAContext) throws -> SecKey {
        var q: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true, kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context]
        var found: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &found)
        if status == errSecSuccess, let found {
            let key = found as! SecKey
            guard try read(slot: pinSlot) == externalPublicKey(key) else { throw MacTrustError.keyChanged }
            return key
        }
        guard status == errSecItemNotFound else { throw MacTrustError.unavailable }
        guard !(try exists(slot: pinSlot)) else { throw MacTrustError.keyChanged }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                  [.privateKeyUsage, .biometryCurrentSet], &error) else { throw MacTrustError.unavailable }
        q = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256,
             kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, kSecUseDataProtectionKeychain as String: true,
             kSecUseAuthenticationContext as String: context,
             kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag, kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccessControl as String: access]]
        guard let key = SecKeyCreateRandomKey(q as CFDictionary, &error) else { throw MacTrustError.unavailable }
        // A failed pin write leaves an unusable key rather than silently trusting another.
        try add(slot: pinSlot, data: externalPublicKey(key))
        return key
    }
    private func externalPublicKey(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyPublicKey(key), let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else { throw MacTrustError.keyChanged }
        return bytes
    }

    // MARK: Production identity
    private static func validateRunningApplication() throws -> String {
        var process = kinfo_proc()
        var processSize = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, UInt32(mib.count), &process, &processSize, nil, 0) == 0,
              process.kp_proc.p_flag & P_TRACED == 0 else { throw MacTrustError.untrustedApplication }
        let bundle = Bundle.main
        guard bundle.bundleURL.pathExtension == "app", bundle.bundleURL.deletingLastPathComponent().path == "/Applications",
              bundle.bundleIdentifier == "dev.tailgate.mac",
              let team = bundle.object(forInfoDictionaryKey: "TailgateTeamIdentifier") as? String,
              team.count == 10, team.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }) else { throw MacTrustError.untrustedApplication }
        // Do not use resource lookup: it may resolve Resources/ or localized files
        // rather than the profile location macOS validates for this executable.
        let profile = bundle.bundleURL.appendingPathComponent("Contents/embedded.provisionprofile", isDirectory: false)
        var profileStat = stat()
        guard lstat(profile.path, &profileStat) == 0, profileStat.st_mode & S_IFMT == S_IFREG,
              profileStat.st_size > 0 else { throw MacTrustError.untrustedApplication }
        // Reject agent-replaceable deployments. Installation is an explicit human/admin
        // operation. No helper, source checkout or user-writable development app is trusted.
        try validateRootOwnedTree(bundle.bundleURL)
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { throw MacTrustError.untrustedApplication }
        let requirementText = "anchor apple generic and identifier \"dev.tailgate.mac\" and certificate leaf[subject.OU] = \"\(team)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw MacTrustError.untrustedApplication }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { throw MacTrustError.untrustedApplication }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any], let flags = values[kSecCodeInfoFlags as String] as? UInt32,
              flags & 0x10000 != 0, flags & 0x2 == 0,
              let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else { throw MacTrustError.untrustedApplication }
        let appID = team + ".dev.tailgate.mac"
        let permitted: Set<String> = ["com.apple.application-identifier", "com.apple.developer.team-identifier", "keychain-access-groups", "com.apple.security.app-sandbox", "com.apple.security.network.client", "com.apple.security.files.user-selected.read-only"]
        guard Set(entitlements.keys).isSubset(of: permitted),
              entitlements["com.apple.application-identifier"] as? String == appID,
              entitlements["com.apple.developer.team-identifier"] as? String == team,
              entitlements["keychain-access-groups"] as? [String] == [appID],
              entitlements["com.apple.security.app-sandbox"] as? Bool == true,
              entitlements["com.apple.security.network.client"] as? Bool == true,
              entitlements["com.apple.security.files.user-selected.read-only"] as? Bool == true else { throw MacTrustError.untrustedApplication }
        // Restricted keychain entitlements are checked by macOS against the embedded
        // profile; a copied bundle ID or an ad-hoc signature cannot claim this group.
        return appID
    }
    private static func validateRootOwnedTree(_ root: URL) throws {
        func check(_ url: URL) throws {
            var info = stat()
            guard lstat(url.path, &info) == 0, info.st_uid == 0,
                  info.st_mode & S_IFMT != S_IFLNK, info.st_mode & 0o022 == 0 else { throw MacTrustError.untrustedApplication }
            // A writable ACL can bypass restrictive POSIX mode bits. Release bundles
            // do not need extended ACL entries; reject rather than interpret them.
            errno = 0
            if let acl = acl_get_file(url.path, ACL_TYPE_EXTENDED) {
                defer { acl_free(UnsafeMutableRawPointer(acl)) }
                var entry: acl_entry_t?
                errno = 0
                guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) == -1, errno == EINVAL else { throw MacTrustError.untrustedApplication }
            } else {
                // Darwin returns ENOENT when no extended ACL is attached, even when
                // the file itself exists (verified above and by strict code validation).
                guard errno == ENOENT else { throw MacTrustError.untrustedApplication }
            }
        }
        try check(root)
        var enumerationFailed = false
        guard let iterator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: [], errorHandler: { _, _ in enumerationFailed = true; return false }) else { throw MacTrustError.untrustedApplication }
        for case let item as URL in iterator { try check(item) }
        guard !enumerationFailed else { throw MacTrustError.untrustedApplication }
    }
}
