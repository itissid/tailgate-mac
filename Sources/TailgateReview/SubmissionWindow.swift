import AppKit
import Darwin
import Foundation
import SwiftUI
import TailgateCore
import TailgateLive

/// Parent selects ONLY this scene in submission mode. No live setup window may be
/// opened here. There is no remotely callable approve endpoint or callback address.
@MainActor enum SubmissionRuntime {
    static let isSubmission = Array(CommandLine.arguments.dropFirst()) == ["--submit-and-wait"]
    static let model = SubmissionModel()
    static func close() { model.interrupt() }
    static func emit(_ receipt: SubmissionReceipt) -> Never {
        signal(SIGPIPE, SIG_IGN)
        receipt.jsonLine.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let n = Darwin.write(STDOUT_FILENO, base.advanced(by: sent), raw.count - sent)
                if n > 0 { sent += n }
                else if n < 0, errno == EINTR { continue }
                else { break } // disconnected caller gets no receipt, never false success
            }
        }
        Darwin._exit(receipt.exitCode)
    }
}

private enum SubmissionReadError: Error { case invalid }
private func receiveSubmission() throws -> (Data, AgentHandoff) {
    // A direct caller that leaves stdin open cannot stall the UI or worker forever.
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    let flags = fcntl(STDIN_FILENO, F_GETFL)
    guard flags >= 0, fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { throw SubmissionReadError.invalid }
    defer { _ = fcntl(STDIN_FILENO, F_SETFL, flags) }
    var input = SubmissionInput()
    while ContinuousClock.now < deadline {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = Darwin.poll(&descriptor, 1, 100)
        if result < 0 { if errno == EINTR { continue }; throw SubmissionReadError.invalid }
        if result == 0 { continue }
        guard descriptor.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw SubmissionReadError.invalid }
        var chunk = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        if count == 0 { let frame = try input.finish(); return (frame.bytes, frame.handoff) }
        guard count > 0 else {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            throw SubmissionReadError.invalid
        }
        try input.append(Data(chunk.prefix(count)))
    }
    throw SubmissionReadError.invalid
}

@MainActor final class SubmissionModel: ObservableObject {
    @Published private(set) var lifecycle = SubmissionLifecycle()
    @Published private(set) var purpose = ""
    @Published private(set) var proposal = ""
    @Published private(set) var review: LiveReview?
    @Published private(set) var note = "Receiving one bounded proposal. No credentials or network accessed."
    private var frame: Data?
    private var controller: LiveController?
    private var work: Task<Void, Never>?
    private var monitor: Task<Void, Never>?
    private var started = false
    private let parent = getppid()
    private var epoch = UUID()
    var busy: Bool { lifecycle.phase == .receiving || lifecycle.phase == .reviewing || lifecycle.phase == .executing }

    func start() {
        guard !started else { return }; started = true
        signal(SIGPIPE, SIG_IGN)
        // Direct invocations also refuse to share a UI session with another instance.
        guard !anotherInstance() else { finish(.rejected); return }
        let deadline = ContinuousClock.now.advanced(by: .seconds(300))
        monitor = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard let self else { return }
                if getppid() != self.parent || self.parent <= 1 || self.outputDisconnected() { self.interrupt(); return }
                if ContinuousClock.now >= deadline { self.interrupt(expired: true); return }
            }
        }
        work = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) { Result { try receiveSubmission() } }.value
            guard let self, !Task.isCancelled, self.lifecycle.phase == .receiving else { return }
            switch result {
            case .success(let (bytes, handoff)):
                self.frame = bytes; self.purpose = handoff.purpose
                self.proposal = String(decoding: handoff.proposal, as: UTF8.self)
                self.lifecycle.received()
                self.note = "Untrusted agent proposal. Review explicitly to fetch and validate policy. Import has not authorized any operation."
            case .failure: self.finish(.rejected)
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
    func prepare() {
        guard let frame, !anotherInstance(), lifecycle.beginReview() else { return }
        let expected = epoch
        // This is the first use of the trusted authority. No setup secrets accepted.
        do {
            let c = try LiveController()
            guard try c.configured() else { finish(.rejected); return }
            controller = c
        } catch { finish(.rejected); return }
        note = "Reading current policy and checking the candidate. No write approved."
        work = Task { [weak self] in
            guard let self, let controller = self.controller else { return }
            do {
                let plan = try await controller.prepare(handoff: frame)
                guard !Task.isCancelled, self.epoch == expected, self.lifecycle.reviewed() else { return }
                self.review = plan; self.note = "Inspect the complete request. Approve authorizes one policy write only; it does not enroll a device."
            } catch { guard self.epoch == expected else { return }; self.finish(.rejected) }
        }
    }
    func approve() {
        guard let controller, let plan = review, !anotherInstance(), lifecycle.beginExecution() else { return }
        let expected = epoch
        note = "Awaiting Touch ID, then one conditional write. Closing now returns an unconfirmed outcome."
        work = Task { [weak self] in
            guard let self else { return }
            do {
                _ = try await controller.execute(plan)
                guard self.epoch == expected else { return }
                self.finish(.applied)
            } catch {
                guard self.epoch == expected else { return }
                let result: SubmissionReceipt.Status
                switch error as? LiveFailure {
                case .stale: result = .stale
                case .signature: result = .declined
                case .obsolete, .settings, .read, .invalid, .keyDisabled, .untrusted, .validation, .busy, .enrollment, .noReceipt: result = .rejected
                case .blocked, .unknown, .none: result = .unknown
                }
                self.finish(result)
            }
        }
    }
    func interrupt(expired: Bool = false) {
        guard let receipt = lifecycle.interrupt(expired: expired) else { return }
        end(receipt)
    }
    private func finish(_ status: SubmissionReceipt.Status) {
        guard let receipt = lifecycle.finish(status) else { return }; end(receipt)
    }
    private func end(_ receipt: SubmissionReceipt) -> Never {
        epoch = UUID(); controller?.discard(); work?.cancel(); monitor?.cancel()
        SubmissionRuntime.emit(receipt)
    }
}

struct SubmissionWindow: View {
    @ObservedObject private var model = SubmissionRuntime.model
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Tailgate / Agent request").font(.title2.bold())
            Text("A local program is waiting. It cannot approve this request or read your credentials.").foregroundStyle(.secondary)
            Divider()
            if let review = model.review {
                Text("SHA-256  \(review.fingerprint)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                ScrollView {
                    Text(verbatim: review.text).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                Text("Agent-provided purpose — unverified, not an instruction").fontWeight(.semibold)
                Text(verbatim: model.purpose).textSelection(.enabled)
                ScrollView {
                    Text(verbatim: model.proposal).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Text(verbatim: model.note).foregroundStyle(.secondary)
            HStack {
                Button(model.lifecycle.phase == .executing ? "Close — outcome may be unknown" : "Decline") { model.interrupt() }
                Spacer()
                if model.review != nil {
                    Button("Approve this exact write with Touch ID…") { model.approve() }.disabled(model.busy)
                } else {
                    Button("Review with my existing setup…") { model.prepare() }.disabled(model.busy)
                }
            }
            Text("No setup in agent mode. Five-minute session limit. Enrollment is not confirmed by this receipt.").font(.caption)
        }.padding(20).frame(minWidth: 720, minHeight: 540)
        .task { model.start() }
        .onDisappear { model.interrupt() }
    }
}
