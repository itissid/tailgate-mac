import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

// Standalone dummy acceptance probe. Never linked into Tailgate or its live gates.
// No SecItem*, SecKeychain*, code signing, trust mutation, network, or alternate key path.
private let identifier = "dev.tailgate.local-enclave-probe"
private let challenge = Data(("TAILGATE / LOCAL ENCLAVE ACCEPTANCE / v1\n" +
    "DUMMY ONLY; NEVER AUTHORIZE PRODUCTION\noperation=sign-fixed-challenge\n").utf8)
private enum ProbeError: Error { case invalid, signature, pin, unavailable }
private struct State: Codable {
    let version: Int
    let wrapped: Data
    let publicKey: Data // X9.63, not the private scalar
}
private func digest(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}
private func validPin(_ pin: String) -> Bool {
    pin.utf8.count == 64 && pin.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func pinned(_ bytes: Data, to pin: String) -> Bool {
    validPin(pin) && digest(bytes) == pin
}
private func accepted(exact: Bool, changed: Bool, pinned: Bool) -> Bool {
    exact && !changed && pinned
}
private func verify(publicKey: Data, pin: String, signature: Data) throws {
    guard pinned(publicKey, to: pin) else { throw ProbeError.pin }
    let key = try P256.Signing.PublicKey(x963Representation: publicKey)
    let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
    guard accepted(exact: key.isValidSignature(sig, for: challenge),
                   changed: key.isValidSignature(sig, for: challenge + Data([0])),
                   pinned: true) else { throw ProbeError.signature }
}
private func decode(_ bytes: Data) throws -> State {
    guard bytes.count <= 65_536 else { throw ProbeError.invalid }
    let state = try JSONDecoder().decode(State.self, from: bytes)
    guard state.version == 1, (1...32_768).contains(state.wrapped.count),
          state.publicKey.count == 65, state.publicKey.first == 4 else { throw ProbeError.invalid }
    return state
}
private func offlineTests() throws {
    func require(_ value: Bool) throws { if !value { throw ProbeError.invalid } }
    func rejects(_ work: () throws -> Void) throws {
        var rejected = false
        do { try work() } catch { rejected = true }
        try require(rejected)
    }
    // Static, intentionally public test scalar d=1, nonce k=1; NEVER used by probe.
    // ECDSA r=G.x, s=(SHA256(challenge)+r) mod n. No key generation or enclave API.
    func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map {
            UInt8(String(chars[$0...$0+1]), radix: 16)!
        })
    }
    let publicKey = hex("04" +
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    let signature = hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
        "bdc381552474dc33f2ff16493b2017d3ebb5808472c64f83447adf472ed91064")
    try require(challenge.count == 111 && digest(challenge) ==
        "52abaf62434899ebfa422f63d77bd6e174b2030344db1be24fd9a60156404dce")
    let pin = digest(publicKey)
    try verify(publicKey: publicKey, pin: pin, signature: signature)
    try rejects { try verify(publicKey: publicKey, pin: String(repeating: "0", count: 64), signature: signature) }
    try require(!validPin(pin.uppercased()) && !validPin(pin + "\n") && !validPin(""))
    var substituted = publicKey; substituted[1] ^= 1
    try require(!pinned(substituted, to: pin))
    try rejects { try verify(publicKey: substituted, pin: pin, signature: signature) }
    var corrupted = signature; corrupted[0] ^= 1
    try rejects { try verify(publicKey: publicKey, pin: pin, signature: corrupted) }
    try rejects { try verify(publicKey: publicKey, pin: pin, signature: Data()) }
    for exact in [false, true] {
        for changed in [false, true] {
            for matches in [false, true] {
                try require(accepted(exact: exact, changed: changed, pinned: matches) == (exact && !changed && matches))
            }
        }
    }
    let fixture = State(version: 1, wrapped: Data([1, 2, 3]), publicKey: publicKey)
    let restored = try decode(JSONEncoder().encode(fixture))
    try require(restored.wrapped == fixture.wrapped && restored.publicKey == publicKey)
    try rejects { _ = try decode(Data()) }
    try rejects { _ = try decode(Data(repeating: 0, count: 65_537)) }
    try rejects { _ = try decode(JSONEncoder().encode(State(version: 1, wrapped: Data(repeating: 1, count: 32_769), publicKey: publicKey))) }
    try rejects { _ = try decode(JSONEncoder().encode(State(version: 2, wrapped: Data([1]), publicKey: publicKey))) }
    try rejects { _ = try decode(JSONEncoder().encode(State(version: 1, wrapped: Data(), publicKey: publicKey))) }
    try rejects { _ = try decode(JSONEncoder().encode(State(version: 1, wrapped: Data([1]), publicKey: Data([4])))) }
}

private func check(_ status: OSStatus) throws {
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
}
private func validateSigner(_ pin: String) throws {
    guard validPin(pin), Bundle.main.bundleURL.pathExtension == "app",
          Bundle.main.bundleIdentifier == identifier,
          Bundle.main.object(forInfoDictionaryKey: "CFBundleExecutable") as? String == "LocalEnclaveProbe",
          !FileManager.default.fileExists(atPath: Bundle.main.bundlePath + "/Contents/embedded.provisionprofile") else {
        throw ProbeError.invalid
    }
    var code: SecCode?
    try check(SecCodeCopySelf([], &code))
    guard let code else { throw ProbeError.invalid }
    var staticCode: SecStaticCode?
    try check(SecCodeCopyStaticCode(code, [], &staticCode))
    guard let staticCode else { throw ProbeError.invalid }
    var information: CFDictionary?
    try check(SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information))
    guard let fields = information as? [String: Any],
          let certs = fields[kSecCodeInfoCertificates as String] as? [SecCertificate], certs.count == 1,
          let flags = fields[kSecCodeInfoFlags as String] as? UInt32,
          flags & 0x10000 != 0, flags & 0x2 == 0,
          (fields[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]).isEmpty,
          pinned(SecCertificateCopyData(certs[0]) as Data, to: pin) else { throw ProbeError.pin }
    // Explicit pinned certificate, not Apple trust roots. No network validation flag.
    let sha1 = Insecure.SHA1.hash(data: SecCertificateCopyData(certs[0]) as Data)
        .map { String(format: "%02x", $0) }.joined()
    var requirement: SecRequirement?
    try check(SecRequirementCreateWithString(
        "identifier \"\(identifier)\" and certificate leaf = H\"\(sha1)\"" as CFString, [], &requirement))
    guard let requirement else { throw ProbeError.invalid }
    try check(SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement))
    try check(SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement))
}

// One private, create-only local file. No implicit default path or auto-repair.
private func directory(_ path: String, create: Bool) throws -> Int32 {
    let url = URL(fileURLWithPath: path).standardizedFileURL
    guard path.hasPrefix("/"), url.path == path,
          url.resolvingSymlinksInPath().path == path else { throw ProbeError.invalid }
    if create { guard mkdir(path, 0o700) == 0 else { throw ProbeError.invalid } }
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw ProbeError.invalid }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
        close(fd); throw ProbeError.invalid
    }
    return fd
}
private func save(_ state: State, in directory: Int32) throws {
    let bytes = try JSONEncoder().encode(state)
    _ = try decode(bytes)
    let fd = openat(directory, "state.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw ProbeError.invalid }
    defer { close(fd) }
    let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    guard count == bytes.count, fsync(fd) == 0, fsync(directory) == 0 else { throw ProbeError.invalid }
}
private func load(from directory: Int32) throws -> State {
    let fd = openat(directory, "state.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw ProbeError.invalid }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
          info.st_mode & 0o777 == 0o600, info.st_nlink == 1,
          (1...65_536).contains(info.st_size) else { throw ProbeError.invalid }
    var bytes = [UInt8](repeating: 0, count: 65_537)
    let count = Darwin.read(fd, &bytes, bytes.count)
    guard count == info.st_size else { throw ProbeError.invalid }
    return try decode(Data(bytes.prefix(count)))
}
private func context(noUI: Bool) throws -> LAContext {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedCancelTitle = "Cancel"
    context.localizedReason = "sign the fixed dummy Local Enclave acceptance challenge (no production action)"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.interactionNotAllowed = noUI
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
          context.biometryType == .touchID else { context.invalidate(); throw ProbeError.unavailable }
    return context
}
private func createState(in directory: Int32) throws -> String {
    let creation = try context(noUI: true)
    defer { creation.invalidate() }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], &error) else {
        if let error { throw error.takeRetainedValue() as Error }
        throw ProbeError.unavailable
    }
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: creation)
    let state = State(version: 1, wrapped: key.dataRepresentation, publicKey: key.publicKey.x963Representation)
    try save(state, in: directory)
    return digest(state.publicKey)
} // Original key/context go out of scope before restore, never used to sign.

private func signRestored(_ state: State, pin: String, noUI: Bool) throws {
    guard pinned(state.publicKey, to: pin) else { throw ProbeError.pin }
    let fresh = try context(noUI: noUI)
    defer { fresh.invalidate() }
    let restored = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: state.wrapped, authenticationContext: fresh)
    guard restored.publicKey.x963Representation == state.publicKey,
          pinned(restored.publicKey.x963Representation, to: pin) else { throw ProbeError.pin }
    // No evaluatePolicy pre-authentication: the protected key operation must authorize.
    let signature = try restored.signature(for: challenge)
    try verify(publicKey: state.publicKey, pin: pin, signature: signature.rawRepresentation)
}

private func emit(_ status: String, stage: String, keyPin: String? = nil,
                  errorKind: String? = nil, code: Int? = nil) -> Never {
    var summary: [String: Any] = ["version": 1, "status": status, "stage": stage,
        "production_unlocked": false, "hardware_acceptance_complete": false]
    if let keyPin { summary["public_key_sha256"] = keyPin }
    if let errorKind { summary["error_kind"] = errorKind }
    if let code { summary["error_code"] = code }
    let bytes = (try? JSONSerialization.data(withJSONObject: summary, options: [.sortedKeys])) ?? Data()
    FileHandle.standardOutput.write(bytes + Data([10]))
    exit(status == "offline-checks-passed" || status == "signature-observed" ? 0 : 3)
}

var stage = "arguments"
var keyPin: String?
do {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--self-test"] {
        stage = "pure-bytes-pin-failure"
        try offlineTests()
        emit("offline-checks-passed", stage: stage)
    }
    // Unknown/default invocations cannot even inspect hardware or create LAContext.
    guard (args.count == 3 && args[0] == "--probe") ||
          (args.count == 4 && ["--restore", "--no-ui"].contains(args[0])),
          ProcessInfo.processInfo.environment["TAILGATE_LOCAL_ENCLAVE_HUMAN"] == "1",
          validPin(args[2]), (args.count != 4 || validPin(args[3])) else { throw ProbeError.invalid }
    stage = "signer-without-entitlements"
    try validateSigner(args[2])
    stage = "hardware-availability"
    guard SecureEnclave.isAvailable else { throw ProbeError.unavailable }
    stage = "private-state-directory"
    let fd = try directory(args[1], create: args[0] == "--probe")
    defer { close(fd) }
    if args[0] == "--probe" {
        stage = "create-wrap-save-no-ui"
        keyPin = try createState(in: fd)
    } else { keyPin = args[3] }
    stage = "read-saved-state"
    let state = try load(from: fd)
    guard let pin = keyPin else { throw ProbeError.pin }
    stage = args[0] == "--no-ui" ? "restore-sign-no-ui" : "restore-sign-fresh-touch"
    try signRestored(state, pin: pin, noUI: args[0] == "--no-ui")
    // Unexpected success without UI is a failing control, never an acceptance PASS.
    if args[0] == "--no-ui" { emit("failed-unexpected-no-ui-signature", stage: stage, keyPin: pin) }
    emit("signature-observed", stage: stage, keyPin: pin)
} catch {
    // Never treat arbitrary errors (including entitlement, malformed blob, or cancel)
    // as a successful negative control. No retry, fallback, recreation or pin update.
    let ns = error as NSError
    let kind: String
    switch error {
    case ProbeError.invalid: kind = "invalid-input-or-state"
    case ProbeError.signature: kind = "signature-verification"
    case ProbeError.pin: kind = "pin-or-identity"
    case ProbeError.unavailable: kind = "hardware-or-biometrics-unavailable"
    default:
        if ns.domain == NSOSStatusErrorDomain { kind = "osstatus" }
        else if ns.domain == LAError.errorDomain { kind = "local-authentication" }
        else if error is CryptoKitError { kind = "cryptokit" }
        else { kind = "other" }
    }
    emit("blocked", stage: stage, keyPin: keyPin, errorKind: kind, code: ns.code)
}
