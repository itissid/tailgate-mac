import AppKit
import LocalAuthentication
import SwiftUI
import TailgateCore

@MainActor private struct TouchIDOnly: ReviewGate {
    func confirm(_ review: Review) async -> Bool {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil), context.biometryType == .touchID else { return false }
        let reason = "Approve this OFFLINE simulation: \(review.title) [\(review.fingerprint.prefix(16))]"
        do { return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) }
        catch { return false }
    }
}

@MainActor private final class Model: ObservableObject {
    let session = DryRunSession()
    @Published var proposal = String(decoding: Compiler.example, as: UTF8.self)
    @Published var review: Review?
    @Published var busy = false
    @Published var receipt = "No operations attempted."
    @Published var message = ""
    var stage: Stage { session.stage }

    func makeReview() {
        message = ""
        do {
            review = stage == .keyReview ? try session.reviewKey() : try session.reviewPolicy(proposal: Data(proposal.utf8))
        } catch { message = error.localizedDescription; review = nil }
    }
    func discard() { session.invalidateReview(); review = nil; message = "Review discarded." }
    func approve() async {
        guard !busy, let saved = review else { return }
        busy = true; defer { busy = false }
        do { try await session.execute(saved, gate: TouchIDOnly()) }
        catch { message = error.localizedDescription }
        review = nil; receipt = session.receipt
    }
    func check(simulate: Bool) {
        do {
            if simulate { try session.simulateFixtureJoin() }
            if session.stage != .stopped { try session.checkEnrollment() }
            message = session.stage == .browserWait || session.stage == .keyWait ? "Waiting: no matching authorized fixture device." : ""
        } catch { message = error.localizedDescription }
        receipt = session.receipt
    }
}

@MainActor private struct Workbench: View {
    @StateObject private var model = Model()
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Tailgate  /  Offline review").font(.title2.bold())
                Spacer()
                Button("Open live review window…") { openWindow(id: "live-review") }
            }
            Text("This window uses an offline fixture only. Quitting discards the fixture and all approvals.").foregroundStyle(.secondary)
            Divider()
            if let review = model.review {
                Text("SHA-256  \(review.fingerprint)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                ScrollView {
                    Text(verbatim: review.text).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }.frame(maxHeight: .infinity).background(Color(nsColor: .textBackgroundColor))
                HStack {
                    Button("Discard review") { model.discard() }
                    Spacer()
                    Button("Approve this simulation with Touch ID…") { Task { await model.approve() } }
                }.disabled(model.busy)
            } else if model.stage == .initial {
                Text("Untrusted proposal JSON — paste a proposal, then review the compiled request.")
                TextEditor(text: $model.proposal).font(.system(.body, design: .monospaced)).border(Color.secondary)
                Button("Review policy diff…") { model.makeReview() }
            } else if model.stage == .keyReview {
                Text("The approved policy is in the fixture. It did not authorize issuing a key.")
                Button("Review separate key request and delivery recipient…") { model.makeReview() }; Spacer()
            } else if model.stage == .browserWait || model.stage == .keyWait {
                Text(model.stage == .browserWait ? "Browser path: on a real VM, a human would complete SSO and request the approved tag. This demo never opens a login or tags a user-owned device." : "Key path: a fixture receipt is waiting at the pinned VM. No bearer key exists.")
                HStack {
                    Button("Check fixture enrollment (read only)") { model.check(simulate: false) }
                    Button("Simulate an authorized fixture VM joining") { model.check(simulate: true) }
                }; Spacer()
            } else { Spacer() }
            Divider()
            Text(verbatim: model.receipt).fontWeight(.medium)
            if !model.message.isEmpty { Text(verbatim: model.message).foregroundStyle(.secondary) }
        }.padding(20).frame(minWidth: 720, minHeight: 540)
        .onDisappear { model.session.invalidateReview() }
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true)
    }
    func applicationWillTerminate(_ notification: Notification) {
        if LookupRuntime.isLookup { LookupRuntime.close() }
        else if SubmissionRuntime.isSubmission { SubmissionRuntime.close() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
@main struct TailgateApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        Window(LookupRuntime.isLookup ? "Tailgate — device lookup" : (SubmissionRuntime.isSubmission ? "Tailgate — agent request" : "Tailgate — offline review"), id: "review") {
            if LookupRuntime.isLookup { LookupWindow() }
            else if SubmissionRuntime.isSubmission { SubmissionWindow() } else { Workbench() }
        }
        Window("Tailgate — live policy review", id: "live-review") {
            if LookupRuntime.isLookup || SubmissionRuntime.isSubmission { Text("Setup and other reviews are unavailable in an agent request session.") } else { LiveWorkbench() }
        }
    }
}
