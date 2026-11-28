import CryptoKit
import Darwin
import Foundation
import Security

// Learning-test helper only. Never linked into Tailgate. No default Keychain,
// signer imports, Keychain creation/deletion, search-list mutation or network.
private let identifier = "dev.tailgate.local-keychain-probe"
private let service = "tailgate.local-keychain-probe.dummy"
private enum LabError: Error {
    case invalid
    case status(OSStatus)
}

private func check(_ value: OSStatus) throws {
    guard value == errSecSuccess else { throw LabError.status(value) }
}
private func emit(_ status: String, _ code: OSStatus? = nil) -> Never {
    var value: [String: Any] = ["version": 1, "status": status]
    if let code { value["osstatus"] = Int(code) }
    let data = (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data()
    FileHandle.standardOutput.write(data + Data([10]))
    exit(status == "ok" || status == "denied" ? 0 : 3)
}
private func safeFile(_ path: String, maximum: Int = 4096) throws -> Data {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw LabError.invalid }
    defer { close(fd) }
    var before = stat()
    guard fstat(fd, &before) == 0, before.st_uid == getuid(), before.st_mode & S_IFMT == S_IFREG,
          before.st_mode & 0o077 == 0, before.st_nlink == 1,
          before.st_size > 0, before.st_size <= maximum else { throw LabError.invalid }
    var bytes = [UInt8](repeating: 0, count: maximum + 1)
    let n = read(fd, &bytes, bytes.count)
    var after = stat()
    guard n > 0, n <= maximum, fstat(fd, &after) == 0, n == after.st_size,
          before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
          before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else { throw LabError.invalid }
    return Data(bytes.prefix(n))
}
private func fixture(_ root: String, _ path: String) throws -> String {
    let base = URL(fileURLWithPath: root).standardizedFileURL
    let candidate = URL(fileURLWithPath: path).standardizedFileURL
    guard base.path.hasPrefix("/"), candidate.path.hasPrefix(base.path + "/") else { throw LabError.invalid }
    var state = stat()
    guard lstat(base.path, &state) == 0, state.st_mode & S_IFMT == S_IFDIR,
          state.st_uid == getuid(), state.st_mode & 0o077 == 0 else { throw LabError.invalid }
    var cursor = base
    for part in candidate.path.dropFirst(base.path.count + 1).split(separator: "/") {
        cursor.appendPathComponent(String(part))
        guard lstat(cursor.path, &state) == 0, state.st_mode & S_IFMT != S_IFLNK,
              state.st_uid == getuid(), state.st_mode & 0o022 == 0 else { throw LabError.invalid }
    }
    return candidate.path
}
private func openKeychain(root: String, path: String) throws -> SecKeychain {
    let concrete = try fixture(root, path)
    var state = stat()
    guard lstat(concrete, &state) == 0, state.st_mode & S_IFMT == S_IFREG,
          state.st_nlink == 1, state.st_mode & 0o077 == 0 else { throw LabError.invalid }
    let password = try safeFile(root + "/password.bin", maximum: 128)
    var keychain: SecKeychain?
    try check(SecKeychainOpen(concrete, &keychain))
    guard let keychain else { throw LabError.invalid }
    try password.withUnsafeBytes { raw in
        try check(SecKeychainUnlock(keychain, UInt32(raw.count), raw.baseAddress, true))
    }
    return keychain
}
private struct LabIdentity {
    let certificate: Data
    let publicKey: Data
    let codeHash: Data
    let requirement: Data
    let instructionsHash: Data
    let architecture: UInt32
}

/// Conservative fixture check: require different compiled instruction bytes, not
/// merely different signatures, timestamps, resources or version metadata. Thin
/// 64-bit Mach-O only; unsupported/fat fixtures are inconclusive, never a PASS.
private func instructionHash(bytes data: Data) throws -> Data {
    func word(_ at: Int) throws -> UInt32 {
        guard at >= 0, at <= data.count - 4 else { throw LabError.invalid }
        return (0..<4).reduce(UInt32(0)) { $0 | UInt32(data[at + $1]) << (8 * $1) }
    }
    func name(_ at: Int) throws -> String {
        guard at >= 0, at <= data.count - 16 else { throw LabError.invalid }
        return String(decoding: data[at..<at+16].prefix(while: { $0 != 0 }), as: UTF8.self)
    }
    guard try word(0) == 0xfeedfacf, try word(12) == 2 else { throw LabError.invalid }
    let commands = Int(try word(16)), bytes = Int(try word(20))
    guard (1...1024).contains(commands), bytes <= data.count - 32 else { throw LabError.invalid }
    var cursor = 32
    var hash: Data?
    for _ in 0..<commands {
        let kind = try word(cursor), size = Int(try word(cursor + 4))
        guard size >= 8, cursor <= 32 + bytes - size else { throw LabError.invalid }
        if kind == 0x19 { // LC_SEGMENT_64
            guard size >= 72 else { throw LabError.invalid }
            let sections = Int(try word(cursor + 64))
            guard sections <= (size - 72) / 80 else { throw LabError.invalid }
            for index in 0..<sections {
                let section = cursor + 72 + index * 80
                if try name(section) == "__text", try name(section + 16) == "__TEXT" {
                    let count = UInt64(try word(section + 40)) | UInt64(try word(section + 44)) << 32
                    let offset = Int(try word(section + 48))
                    guard hash == nil, count > 0, count <= UInt64(data.count),
                          offset <= data.count - Int(count) else { throw LabError.invalid }
                    hash = Data(SHA256.hash(data: data[offset..<offset+Int(count)]))
                }
            }
        }
        cursor += size
    }
    guard cursor == 32 + bytes, let hash else { throw LabError.invalid }
    return hash
}

private func signedIdentity(root: String, app: String, updateEvidence: Bool = false) throws -> LabIdentity {
    let path = try fixture(root, app)
    guard URL(fileURLWithPath: path).lastPathComponent == "KeychainProbe.app",
          let bundle = Bundle(path: path), bundle.bundleIdentifier == identifier,
          bundle.object(forInfoDictionaryKey: "CFBundleExecutable") as? String == "KeychainProbe" else { throw LabError.invalid }
    var code: SecStaticCode?
    try check(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code))
    guard let code else { throw LabError.invalid }
    var information: CFDictionary?
    try check(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information))
    guard let fields = information as? [String: Any],
          fields[kSecCodeInfoIdentifier as String] as? String == identifier,
          let certs = fields[kSecCodeInfoCertificates as String] as? [SecCertificate], certs.count == 1 else { throw LabError.invalid }
    let cert = SecCertificateCopyData(certs[0]) as Data
    let fingerprint = Insecure.SHA1.hash(data: cert).map { String(format: "%02x", $0) }.joined()
    // The exact embedded lab leaf is the explicit trust condition, not Apple trust
    // roots. Default static validation does not enable kSecCSAllowNetworkAccess.
    let source = "identifier \"\(identifier)\" and certificate leaf = H\"\(fingerprint)\""
    var requirement: SecRequirement?
    try check(SecRequirementCreateWithString(source as CFString, [], &requirement))
    try check(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement))
    guard let publicKey = SecCertificateCopyKey(certs[0]),
          let keyBytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { throw LabError.invalid }
    if !updateEvidence {
        return LabIdentity(certificate: cert, publicKey: keyBytes, codeHash: Data(), requirement: Data(), instructionsHash: Data(), architecture: 0)
    }
    guard let codeHash = fields[kSecCodeInfoUnique as String] as? Data, !codeHash.isEmpty else { throw LabError.invalid }
    var designated: SecRequirement?
    try check(SecCodeCopyDesignatedRequirement(code, [], &designated))
    guard let designated else { throw LabError.invalid }
    var encoded: CFData?
    try check(SecRequirementCopyData(designated, [], &encoded))
    guard let encoded else { throw LabError.invalid }
    let binary = path + "/Contents/MacOS/KeychainProbe"
    _ = try fixture(root, binary)
    let executable = try safeFile(binary, maximum: 16_777_216)
    guard executable.count >= 8 else { throw LabError.invalid }
    let architecture = (0..<4).reduce(UInt32(0)) { $0 | UInt32(executable[4 + $1]) << (8 * $1) }
    return LabIdentity(certificate: cert, publicKey: keyBytes, codeHash: codeHash,
                       requirement: encoded as Data, instructionsHash: try instructionHash(bytes: executable), architecture: architecture)
}

private func validPin(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func certificatePin(_ identity: LabIdentity) -> String {
    SHA256.hash(data: identity.certificate).map { String(format: "%02x", $0) }.joined()
}
private func updateEvidenceValid(_ a1: LabIdentity, _ a2: LabIdentity, _ b: LabIdentity,
                                 pinA: String, pinB: String) -> Bool {
    validPin(pinA) && validPin(pinB) && pinA != pinB &&
    certificatePin(a1) == pinA && certificatePin(a2) == pinA && certificatePin(b) == pinB &&
    a1.certificate == a2.certificate && a1.publicKey == a2.publicKey &&
    a1.certificate != b.certificate && a1.publicKey != b.publicKey &&
    a1.architecture == a2.architecture && a1.architecture == b.architecture &&
    a1.codeHash != a2.codeHash && a1.instructionsHash != a2.instructionsHash &&
    a1.requirement == a2.requirement
}
private func verifyUpdate(root: String, first: String, second: String, unrelated: String,
                          keychain: String, pinA: String, pinB: String) throws {
    guard validPin(pinA), validPin(pinB), pinA != pinB,
          Set([first, second, unrelated]).count == 3 else { throw LabError.invalid }
    let a1 = try signedIdentity(root: root, app: first, updateEvidence: true)
    let a2 = try signedIdentity(root: root, app: second, updateEvidence: true)
    let b = try signedIdentity(root: root, app: unrelated, updateEvidence: true)
    guard updateEvidenceValid(a1, a2, b, pinA: pinA, pinB: pinB) else { throw LabError.invalid }
    _ = try fixture(root, keychain)
}
private func restrictedAccess(app: String) throws -> SecAccess {
    var trusted: SecTrustedApplication?
    try check(SecTrustedApplicationCreateFromPath(app, &trusted))
    guard let trusted else { throw LabError.invalid }
    var access: SecAccess?
    try check(SecAccessCreate("Tailgate dummy identity test" as CFString, [trusted] as CFArray, &access))
    guard let access,
          let decryptACLs = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL], !decryptACLs.isEmpty else { throw LabError.invalid }
    // Nil means all applications in this legacy API; reject it for secret reads.
    for acl in decryptACLs {
        var applications: CFArray?, description: CFString?, selector = SecKeychainPromptSelector(rawValue: 0)
        try check(SecACLCopyContents(acl, &applications, &description, &selector))
        guard let applications, CFArrayGetCount(applications) == 1 else { throw LabError.invalid }
    }
    return access
}
private func seed(root: String, appA: String, appB: String, keychainPath: String) throws {
    let a = try signedIdentity(root: root, app: appA), b = try signedIdentity(root: root, app: appB)
    guard a.certificate != b.certificate, a.publicKey != b.publicKey else { throw LabError.invalid }
    let keychain = try openKeychain(root: root, path: keychainPath)
    let dummy = try safeFile(root + "/dummy.bin", maximum: 32)
    guard dummy.count == 32 else { throw LabError.invalid }
    for (account, app) in [("a", appA), ("b", appB)] {
        let access = try restrictedAccess(app: app)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecValueData as String: dummy, kSecUseKeychain as String: keychain,
            kSecAttrAccess as String: access, kSecUseDataProtectionKeychain as String: false]
        // Duplicates are a setup failure, never an update to arbitrary old items.
        try check(SecItemAdd(query as CFDictionary, nil))
    }
}
private func classify(_ status: OSStatus, valueMatches: Bool) -> String {
    if status == errSecSuccess { return valueMatches ? "ok" : "inconclusive" }
    if status == errSecInteractionNotAllowed || status == errSecAuthFailed { return "denied" }
    return "inconclusive"
}
private func readDummy(root: String, keychainPath: String, account: String) throws -> Never {
    guard ["a", "b"].contains(account) else { throw LabError.invalid }
    let keychain = try openKeychain(root: root, path: keychainPath)
    let expected = try safeFile(root + "/dummy.bin", maximum: 32)
    guard expected.count == 32 else { throw LabError.invalid }
    // An explicit one-element search list is a query bound, NOT a mutation of the
    // user's search list. Never omit it or fall back to a default Keychain.
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: account,
        kSecMatchSearchList as String: [keychain], kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne, kSecUseDataProtectionKeychain as String: false,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    emit(classify(status, valueMatches: (result as? Data) == expected), status)
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--self-test"] {
        guard classify(errSecSuccess, valueMatches: true) == "ok",
              classify(errSecSuccess, valueMatches: false) == "inconclusive",
              classify(errSecAuthFailed, valueMatches: false) == "denied",
              classify(errSecInteractionNotAllowed, valueMatches: false) == "denied",
              classify(errSecItemNotFound, valueMatches: false) == "inconclusive",
              classify(errSecInvalidKeychain, valueMatches: false) == "inconclusive" else { throw LabError.invalid }
        // Offline evidence parser controls. These bytes are synthetic, not signed
        // executables, and establish no real signer or Keychain acceptance.
        var fixtureBytes = Data(repeating: 0, count: 188)
        func put(_ at: Int, _ value: UInt32) {
            for i in 0..<4 { fixtureBytes[at+i] = UInt8(truncatingIfNeeded: value >> (8*i)) }
        }
        put(0, 0xfeedfacf); put(12, 2); put(16, 1); put(20, 152)
        put(32, 0x19); put(36, 152); put(96, 1)
        fixtureBytes.replaceSubrange(104..<110, with: Data("__text".utf8))
        fixtureBytes.replaceSubrange(120..<126, with: Data("__TEXT".utf8))
        put(144, 4); put(152, 184); put(184, 0xd65f03c0)
        let original = try instructionHash(bytes: fixtureBytes)
        fixtureBytes[28] = 1 // Header-only change is not an instruction change.
        guard try instructionHash(bytes: fixtureBytes) == original else { throw LabError.invalid }
        fixtureBytes[184] ^= 1
        guard try instructionHash(bytes: fixtureBytes) != original else { throw LabError.invalid }
        put(152, 9999)
        var rejected = false
        do { _ = try instructionHash(bytes: fixtureBytes) }
        catch LabError.invalid { rejected = true }
        guard rejected else { throw LabError.invalid }
        func evidence(_ cert: UInt8, _ code: UInt8, _ instructions: UInt8, _ requirement: UInt8 = 1) -> LabIdentity {
            LabIdentity(certificate: Data([cert]), publicKey: Data([cert]), codeHash: Data([code]),
                        requirement: Data([requirement]), instructionsHash: Data([instructions]), architecture: 0x100000c)
        }
        let a1 = evidence(1, 1, 1), a2 = evidence(1, 2, 2), other = evidence(2, 1, 1)
        let pinA = certificatePin(a1), pinB = certificatePin(other)
        guard updateEvidenceValid(a1, a2, other, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, a1, other, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, evidence(1, 2, 1), other, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, evidence(1, 1, 2), other, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, evidence(1, 2, 2, 2), other, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, a2, a1, pinA: pinA, pinB: pinB),
              !updateEvidenceValid(a1, a2, other, pinA: pinB, pinB: pinA) else { throw LabError.invalid }
        emit("ok")
    }
    // No dialog is permitted from fixture commands, including setup. Failure to
    // suppress interaction is fatal. This setting affects only this process.
    try check(SecKeychainSetUserInteractionAllowed(false))
    if args.count == 8, ["--verify-update", "--seed-update"].contains(args[0]) {
        try verifyUpdate(root: args[1], first: args[2], second: args[3], unrelated: args[4],
                         keychain: args[5], pinA: args[6], pinB: args[7])
        if args[0] == "--seed-update" {
            // Seed only A1's and B's ACLs. A2 is never added to a trusted list.
            try seed(root: args[1], appA: args[2], appB: args[4], keychainPath: args[5])
        }
        emit("ok")
    }
    if args.count == 5, args[0] == "--verify-pair" {
        let a = try signedIdentity(root: args[1], app: args[2]), b = try signedIdentity(root: args[1], app: args[3])
        guard a.certificate != b.certificate, a.publicKey != b.publicKey else { throw LabError.invalid }
        _ = try fixture(args[1], args[4]); emit("ok")
    }
    if args.count == 5, args[0] == "--seed" {
        try seed(root: args[1], appA: args[2], appB: args[3], keychainPath: args[4]); emit("ok")
    }
    if args.count == 4, args[0] == "--read" {
        try readDummy(root: args[1], keychainPath: args[2], account: args[3])
    }
    throw LabError.invalid
} catch LabError.status(let code) { emit("inconclusive", code) }
catch { emit("inconclusive") }
