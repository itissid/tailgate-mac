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
private func signedIdentity(root: String, app: String) throws -> (certificate: Data, publicKey: Data) {
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
    return (cert, keyBytes)
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
        emit("ok")
    }
    // No dialog is permitted from fixture commands, including setup. Failure to
    // suppress interaction is fatal. This setting affects only this process.
    try check(SecKeychainSetUserInteractionAllowed(false))
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
