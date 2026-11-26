import AppKit
import Darwin
import Foundation
import LocalAuthentication
import SwiftUI
import TailgateCore

@MainActor private struct TrialTouchID: TrialGate {
    func approve(_ plan: TrialPlan) async -> Bool {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil), context.biometryType == .touchID else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Approve this FIXTURE ONLY rehearsal [\(plan.fingerprint.prefix(16))]")
        } catch { return false }
    }
}

private enum InputFailure: Error { case rejected }
private func readTrialInput() throws -> Data {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--example"] { return TrialPlan.example }
    guard args == ["--stdin"] else { throw InputFailure.rejected }
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    let old = fcntl(STDIN_FILENO, F_GETFL)
    guard old >= 0, fcntl(STDIN_FILENO, F_SETFL, old | O_NONBLOCK) == 0 else { throw InputFailure.rejected }
    defer { _ = fcntl(STDIN_FILENO, F_SETFL, old) }
    var data = Data()
    while ContinuousClock.now < deadline {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
        let ready = Darwin.poll(&descriptor, 1, 100)
        if ready < 0 { if errno == EINTR { continue }; throw InputFailure.rejected }
        if ready == 0 { continue }
        guard descriptor.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw InputFailure.rejected }
        var chunk = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        if count == 0 { return data }
        if count < 0 {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            throw InputFailure.rejected
        }
        guard data.count + count <= AgentHandoff.maximumBytes else { throw InputFailure.rejected }
        data.append(contentsOf: chunk.prefix(count))
    }
    throw InputFailure.rejected
}

@MainActor private enum TrialRuntime {
    static let model = TrialModel()
    static func emit(_ receipt: TrialReceipt) -> Never {
        signal(SIGPIPE, SIG_IGN)
        let flags = fcntl(STDOUT_FILENO, F_GETFL)
        if flags >= 0 { _ = fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) }
        receipt.jsonLine.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(STDOUT_FILENO, base.advanced(by: offset), raw.count - offset)
                if count > 0 { offset += count }
                else if count < 0, errno == EINTR { continue }
                else { break } // No complete receipt means no reported success.
            }
        }
        Darwin._exit(receipt.exitCode)
    }
}

@MainActor private final class TrialModel: ObservableObject {
    @Published private(set) var session: TrialSession?
    @Published private(set) var busy = true
    @Published private(set) var note = "Receiving a bounded fixture proposal. No authentication has occurred."
    private var started = false
    private var complete = false
    private var work: Task<Void, Never>?
    private var monitor: Task<Void, Never>?
    private let parentPID = getppid()

    func start() {
        guard !started else { return }; started = true
        signal(SIGPIPE, SIG_IGN)
        let totalDeadline = ContinuousClock.now.advanced(by: .seconds(300))
        monitor = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 200_000_000)
                guard let self, !self.complete else { return }
                var output = pollfd(fd: STDOUT_FILENO, events: 0, revents: 0)
                let gone = Darwin.poll(&output, 1, 0) > 0 && output.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0
                if self.parentPID <= 1 || getppid() != self.parentPID || gone { self.close(); return }
                if let timeout = self.session?.checkTimeout() { self.finish(timeout); return }
                if ContinuousClock.now >= totalDeadline { self.finish(TrialReceipt(.timeout)); return }
            }
        }
        work = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) { Result { try readTrialInput() } }.value
            guard let self, !self.complete, !Task.isCancelled else { return }
            do {
                self.session = try TrialSession(handoff: result.get())
                self.busy = false
                self.note = "Inspect the fixed synthetic policy. Approve requests fresh Touch ID; nothing will be written. Approval expires in 120 seconds."
            } catch { self.finish(TrialReceipt(.error)) }
        }
    }
    func approve() {
        guard !busy, !complete, let session else { return }; busy = true
        note = "Waiting for Touch ID for this fixture rehearsal only. No real request can execute."
        work = Task { [weak self] in
            do {
                let receipt = try await session.approve(gate: TrialTouchID())
                guard let self, !self.complete else { return }; self.finish(receipt)
            } catch { self?.finish(TrialReceipt(.error)) }
        }
    }
    func close() { finish(session?.cancel() ?? TrialReceipt(.declined)) }
    private func finish(_ receipt: TrialReceipt) {
        guard !complete else { return }; complete = true
        work?.cancel(); monitor?.cancel()
        TrialRuntime.emit(receipt)
    }
}

@MainActor private struct TrialWindow: View {
    @ObservedObject private var model = TrialRuntime.model
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Tailgate / Agent fixture rehearsal").font(.title2.bold())
            Text("DRY RUN ONLY — no network, credentials, enrollment or real policy writes.").fontWeight(.semibold)
            Text("This development build demonstrates the interaction. Touch ID does not sign this plan or establish production app trust.").font(.callout).foregroundStyle(.secondary)
            Divider()
            if let plan = model.session?.plan {
                GroupBox("UNTRUSTED AGENT PURPOSE — not authorization") {
                    Text(verbatim: plan.purpose).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("Immutable review SHA-256: \(plan.fingerprint)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                ScrollView {
                    Text(verbatim: plan.text).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }.background(Color(nsColor: .textBackgroundColor))
            } else { Spacer(); ProgressView("Receiving one fixture proposal…"); Spacer() }
            Text(verbatim: model.note).font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("Decline and return to agent") { model.close() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Approve FIXTURE ONLY with Touch ID…") { model.approve() }.disabled(model.busy)
            }
            Text("One attempt. Closing or Command-Q declines. A missing receipt never means success.").font(.caption).foregroundStyle(.secondary)
        }.padding(20).frame(minWidth: 700, minHeight: 560)
        .task { model.start() }
        .onDisappear { model.close() }
    }
}

@MainActor private final class TrialDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        TrialRuntime.model.close(); return .terminateCancel
    }
    func applicationWillTerminate(_ notification: Notification) { TrialRuntime.model.close() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main struct TailgateTrialApp: App {
    @NSApplicationDelegateAdaptor(TrialDelegate.self) private var delegate
    var body: some Scene { Window("Tailgate — FIXTURE ONLY", id: "trial") { TrialWindow() } }
}
