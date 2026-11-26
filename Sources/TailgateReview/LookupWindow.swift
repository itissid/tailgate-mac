import AppKit
import Darwin
import Foundation
import SwiftUI
import TailgateLive

/// Parent exposes only this window for the exact lookup mode, with no setup route.
@MainActor enum LookupRuntime {
    static let isLookup = Array(CommandLine.arguments.dropFirst()) == ["--lookup-and-wait"]
    static let model = LookupModel()
    static func close() { model.interrupt() }
    static func emit(_ data: Data, code: Int32) -> Never {
        signal(SIGPIPE, SIG_IGN)
        let flags = fcntl(STDOUT_FILENO, F_GETFL)
        if flags >= 0 { _ = fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) }
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let n = Darwin.write(STDOUT_FILENO, base.advanced(by: sent), raw.count - sent)
                if n > 0 { sent += n }
                else if n < 0, errno == EINTR { continue }
                else { break } // Missing/truncated receipt is unknown, never false disclosure.
            }
        }
        Darwin._exit(code)
    }
}

private enum LookupInputError: Error { case invalid }
private func receiveLookup() throws -> Data {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    let flags = fcntl(STDIN_FILENO, F_GETFL)
    guard flags >= 0, fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { throw LookupInputError.invalid }
    defer { _ = fcntl(STDIN_FILENO, F_SETFL, flags) }
    var bytes = Data()
    while ContinuousClock.now < deadline {
        var p = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = Darwin.poll(&p, 1, 100)
        if result < 0 { if errno == EINTR { continue }; throw LookupInputError.invalid }
        if result == 0 { continue }
        guard p.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw LookupInputError.invalid }
        var chunk = [UInt8](repeating: 0, count: 257)
        let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        if count == 0 {
            // Pure frame checking only; no Keychain/controller is constructed here.
            guard let text = String(data: bytes, encoding: .ascii) else { throw LookupInputError.invalid }
            let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
            guard lines.count == 4, lines[0] == "TAILGATE-LOOKUP/1", lines[3].isEmpty,
                  validLookupName(String(lines[1])), ["name", "name,tags", "name,ips", "name,tags,ips"].contains(String(lines[2])) else { throw LookupInputError.invalid }
            return bytes
        }
        guard count > 0 else {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            throw LookupInputError.invalid
        }
        guard bytes.count + count <= 256 else { throw LookupInputError.invalid }
        bytes.append(contentsOf: chunk.prefix(count))
    }
    throw LookupInputError.invalid
}
private func validLookupName(_ text: String) -> Bool {
    let b = Array(text.utf8)
    func alnum(_ c: UInt8) -> Bool { (97...122).contains(c) || (48...57).contains(c) }
    return (1...63).contains(b.count) && b.first.map({ (97...122).contains($0) }) == true && b.last.map(alnum) == true && b.allSatisfy { alnum($0) || $0 == 45 }
}

@MainActor final class LookupModel: ObservableObject {
    enum Phase { case receiving, waiting, fetching, reviewing, approving, finished }
    @Published private(set) var phase: Phase = .receiving
    @Published private(set) var request = ""
    @Published private(set) var review: LookupReview?
    @Published private(set) var note = "Receiving one bounded exact-name lookup. No credentials or network accessed."
    private var query: Data?
    private var controller: DeviceLookupController?
    private var work: Task<Void, Never>?
    private var monitor: Task<Void, Never>?
    private var started = false
    private var epoch = UUID()
    private let parent = getppid()
    var busy: Bool { phase == .receiving || phase == .fetching || phase == .approving }

    func start() {
        guard !started else { return }; started = true
        signal(SIGPIPE, SIG_IGN)
        guard !anotherInstance() else { finish("rejected"); return }
        let deadline = ContinuousClock.now.advanced(by: .seconds(300))
        monitor = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard let self, self.phase != .finished else { return }
                if getppid() != self.parent || self.parent <= 1 || self.outputDisconnected() { self.interrupt(); return }
                if ContinuousClock.now >= deadline { self.interrupt(expired: true); return }
            }
        }
        work = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) { Result { try receiveLookup() } }.value
            guard let self, !Task.isCancelled, self.phase == .receiving else { return }
            switch result {
            case .success(let bytes):
                self.query = bytes; self.request = String(decoding: bytes, as: UTF8.self)
                self.phase = .waiting; self.note = "No lookup has run. Fetching uses your saved read-only credential; it does not disclose the result to the caller."
            case .failure: self.finish("rejected")
            }
        }
    }
    private func anotherInstance() -> Bool {
        NSRunningApplication.runningApplications(withBundleIdentifier: "dev.tailgate.mac").contains { $0.processIdentifier != getpid() }
    }
    private func outputDisconnected() -> Bool {
        var p = pollfd(fd: STDOUT_FILENO, events: 0, revents: 0)
        return Darwin.poll(&p, 1, 0) > 0 && p.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0
    }
    func fetch() {
        guard phase == .waiting, let query, !anotherInstance() else { return }
        phase = .fetching
        do { controller = try DeviceLookupController() } catch { finish("rejected"); return }
        let expected = epoch
        note = "Fetching an exact-name result for your local review. Nothing has been disclosed to Pi."
        work = Task { [weak self] in
            guard let self, let controller = self.controller else { return }
            do {
                let plan = try await controller.prepare(query: query)
                guard !Task.isCancelled, self.epoch == expected, self.phase == .fetching else { return }
                self.review = plan; self.phase = .reviewing
                self.note = "Read exactly what would leave this app. Touch ID separately approves disclosure, not a policy change."
            } catch { guard self.epoch == expected else { return }; self.finish("rejected") }
        }
    }
    func approve() {
        guard phase == .reviewing, let plan = review, let controller, !anotherInstance() else { return }
        phase = .approving; let expected = epoch
        note = "Awaiting fresh approval to disclose these fields. Closing returns no data."
        work = Task { [weak self] in
            guard let self else { return }
            do {
                let data = try await controller.disclose(plan)
                guard !Task.isCancelled, self.epoch == expected, self.phase == .approving else { return }
                guard !data.isEmpty, data.count <= 8192 else { self.finish("unknown"); return }
                self.end(data, code: 0)
            } catch { guard self.epoch == expected else { return }; self.finish("rejected") }
        }
    }
    func interrupt(expired: Bool = false) { finish(expired ? "expired" : phase == .approving ? "unknown" : "declined") }
    private func finish(_ status: String) {
        guard phase != .finished else { return }
        // All failures have identical data-free shape; even a match count is private.
        end(Data("{\"version\":1,\"status\":\"\(status)\"}\n".utf8), code: status == "unknown" ? 3 : 2)
    }
    private func end(_ data: Data, code: Int32) -> Never {
        phase = .finished; epoch = UUID(); controller?.discard(); work?.cancel(); monitor?.cancel()
        LookupRuntime.emit(data, code: code)
    }
}

struct LookupWindow: View {
    @ObservedObject private var model = LookupRuntime.model
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Tailgate / Device lookup").font(.title2.bold())
            Text("Approved output will be visible to the requesting Pi agent, its session history, and its configured model/provider. Do not approve sensitive fields unless you accept that disclosure.").fontWeight(.semibold)
            Divider()
            if let review = model.review {
                Text("SHA-256  \(review.fingerprint)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                ScrollView { Text(verbatim: review.text).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
            } else {
                Text("Untrusted caller request — exact hostname and selected fields only")
                ScrollView { Text(verbatim: model.request).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
            }
            Text(verbatim: model.note).foregroundStyle(.secondary)
            HStack {
                Button("Decline — return no device data") { model.interrupt() }
                Spacer()
                if model.review != nil {
                    Button("Disclose these exact fields with Touch ID…") { model.approve() }.disabled(model.busy)
                } else {
                    Button("Fetch for my local review…") { model.fetch() }.disabled(model.busy)
                }
            }
            Text("No policy write, enrollment, setup or list-all operation. Five-minute session limit.").font(.caption)
        }.padding(20).frame(minWidth: 720, minHeight: 540)
        .task { model.start() }
        .onDisappear { model.interrupt() }
    }
}
