import AppKit
import Darwin
import Foundation
import SwiftUI
import TailgateCore
import TailgateLive
import UniformTypeIdentifiers

/// The view model is inert until the operator explicitly activates the live session.
/// Foundation/network error descriptions and credential material never enter its status text.
@MainActor private final class LiveModel: ObservableObject {
    @Published var tailnet = ""
    @Published var vm = ""
    @Published var source = ""
    @Published var nodeKey = ""
    @Published var readClientID = ""
    @Published var readSecret = ""
    @Published var writeClientID = ""
    @Published var writeSecret = ""
    @Published private(set) var proposal = ""
    @Published private(set) var importedPurpose: String?
    @Published var review: LiveReview?
    @Published var active = false
    @Published var isConfigured = false
    @Published var busy = false
    @Published var setupExpanded = true
    @Published var status = "Live mode is inactive. No credentials or network have been accessed."

    private var controller: LiveController?
    private var importedHandoff: Data?
    private var epoch = UUID()
    private var taskID: UUID?
    private var task: Task<Void, Never>?

    var completeSetup: Bool {
        [tailnet, vm, source, nodeKey, readClientID, readSecret, writeClientID, writeSecret]
            .allSatisfy { !$0.isEmpty }
    }

    func activate() {
        guard !busy, !active else { return }
        do {
            // This user action is the first point at which trust checks or Keychain
            // access are permitted. No view initializer or onAppear calls this.
            let opened = try LiveController()
            let ready = try opened.configured()
            controller = opened
            active = true
            isConfigured = ready
            setupExpanded = !ready
            status = ready
                ? "Trusted live session opened with saved setup. No policy request has been sent."
                : "Trusted live session opened without saved setup. Complete private setup before preparing a proposal. No policy request has been sent."
        } catch {
            controller = nil
            isConfigured = false
            status = safeMessage(error, fallback: "Live mode could not open. Use a properly signed and provisioned release app with its required Mac security settings. No policy request was sent.")
        }
    }

    func saveConfiguration() {
        guard !busy, completeSetup, let controller else { return }
        invalidateReview()
        busy = true
        defer { busy = false; clearCredentials() }
        do {
            try controller.configure(tailnet: tailnet, vm: vm, source: source, nodeKey: nodeKey,
                                     readClientID: readClientID, readSecret: readSecret,
                                     writeClientID: writeClientID, writeSecret: writeSecret)
            setupExpanded = false
            isConfigured = true
            status = "Configuration saved to the app's private Keychain storage. Credential fields have been cleared. No policy request was sent."
        } catch {
            status = safeMessage(error, fallback: "Configuration was not confirmed. Credential fields have been cleared; correct the setup and enter them again. No policy request was sent.")
        }
    }

    func editProposal(_ value: String) {
        guard !busy else { return }
        invalidateReview()
        if importedHandoff != nil {
            status = "Imported context removed because its proposal was edited. This is now a manual JSON proposal; no request has been sent."
        }
        importedHandoff = nil
        importedPurpose = nil
        proposal = value
    }

    func importHandoff() {
        guard !busy else { return }
        invalidateReview()
        importedHandoff = nil
        importedPurpose = nil
        busy = true
        status = "Choose an untrusted .tailgate proposal file. Import does not authenticate or make a network request."
        let id = UUID(), currentEpoch = epoch
        taskID = id
        task = Task { [weak self] in
            guard let self else { return }
            defer { self.finishTask(id) }
            let panel = NSOpenPanel()
            panel.title = "Import untrusted agent proposal"
            panel.message = "Choose a .tailgate file. Import only reads data; it does not authenticate, contact Tailscale, or authorize a write."
            panel.prompt = "Import proposal"
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.allowsMultipleSelection = false
            panel.resolvesAliases = false
            panel.allowedContentTypes = [UTType(filenameExtension: "tailgate", conformingTo: .json) ?? .json]
            let response = await panel.begin()
            guard self.epoch == currentEpoch, !Task.isCancelled else { return }
            guard response == .OK, let url = panel.url else {
                self.status = "Import cancelled. No authentication, network request, or approval occurred."
                return
            }
            do {
                let bytes = try await Task.detached(priority: .userInitiated) {
                    try HandoffFile.read(url)
                }.value
                let handoff = try AgentHandoff.decode(bytes)
                guard self.epoch == currentEpoch, !Task.isCancelled else { return }
                // Preserve the immutable original bytes; the controller decodes and
                // binds this same envelope rather than trusting the editable preview.
                self.importedHandoff = bytes
                self.importedPurpose = handoff.purpose
                self.proposal = String(decoding: handoff.proposal, as: UTF8.self)
                self.status = "Agent proposal imported as untrusted data. No authentication, network request, or approval occurred. Editing its JSON removes the imported context."
            } catch {
                guard self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = "Import rejected. Choose a bounded, regular .tailgate file with no links and a valid handoff document. No authentication or network request occurred."
            }
        }
    }

    func configurationChanged() {
        guard !busy else { return }
        invalidateReview()
    }

    func discard() {
        invalidateReview()
        task?.cancel()
        status = busy
            ? "Review invalidated. Waiting for the active operation to stop; do not assume an in-flight write was undone."
            : "Review discarded. A new review and fresh Touch ID approval are required for any write."
    }

    private func invalidateReview() {
        epoch = UUID()
        review = nil
        controller?.discard()
    }

    private func safeMessage(_ error: Error, fallback: String) -> String {
        (error as? LiveFailure)?.errorDescription ?? fallback
    }

    private func clearCredentials() {
        nodeKey = ""
        readClientID = ""
        readSecret = ""
        writeClientID = ""
        writeSecret = ""
    }

    private func start(_ operation: @escaping @MainActor (LiveController, UUID) async -> Void) {
        guard !busy, let controller else { return }
        busy = true
        let id = UUID(), currentEpoch = epoch
        taskID = id
        task = Task { [weak self] in
            guard let self else { return }
            await operation(controller, currentEpoch)
            self.finishTask(id)
        }
    }

    private func finishTask(_ id: UUID) {
        guard taskID == id else { return }
        busy = false
        taskID = nil
        task = nil
    }

    func prepare() {
        guard !busy, isConfigured, !proposal.isEmpty else { return }
        invalidateReview()
        let input = Data(proposal.utf8), handoff = importedHandoff
        status = "Reading the current policy and checking this candidate. No policy write is authorized."
        start { [weak self] controller, currentEpoch in
            do {
                let prepared: LiveReview
                if let handoff {
                    prepared = try await controller.prepare(handoff: handoff)
                } else {
                    prepared = try await controller.prepare(proposal: input)
                }
                guard let self else { return }
                guard self.epoch == currentEpoch, !Task.isCancelled else {
                    controller.discard(); return
                }
                self.review = prepared
                self.status = "Review the complete immutable diff and request below. No write happens until you explicitly approve with Touch ID."
            } catch {
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = self.safeMessage(error, fallback: "The proposal could not be prepared or validated. Check the saved setup and supported policy format. No write was authorized.")
            }
        }
    }

    func approve() {
        guard !busy, let approved = review else { return }
        // Keep the exact plan visible while the biometric prompt is active. The
        // busy guard prevents another action; the controller consumes authorization.
        status = "Awaiting fresh Touch ID approval for the reviewed request."
        start { [weak self] controller, currentEpoch in
            defer {
                if let self, self.epoch == currentEpoch { self.review = nil }
            }
            do {
                let receipt = try await controller.execute(approved)
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                // The controller's receipt contract is sanitized status only.
                self.status = receipt
            } catch {
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = self.safeMessage(error, fallback: "The operation was not confirmed. This approval cannot be reused. Use the read-only recovery check before proposing another write.")
            }
        }
    }

    func checkEnrollment() {
        guard !busy, isConfigured else { return }
        invalidateReview()
        status = "Checking the pinned device and policy using read-only requests."
        start { [weak self] controller, currentEpoch in
            do {
                let receipt = try await controller.checkEnrollment()
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = receipt
            } catch {
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = self.safeMessage(error, fallback: "Enrollment could not be verified. No enrollment, tag change, or other write was attempted by this check.")
            }
        }
    }

    func reconcile() {
        guard !busy, isConfigured else { return }
        invalidateReview()
        status = "Reconciling the last operation using read-only requests. No retry will be sent."
        start { [weak self] controller, currentEpoch in
            do {
                let receipt = try await controller.reconcile()
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = receipt
            } catch {
                guard let self, self.epoch == currentEpoch, !Task.isCancelled else { return }
                self.status = self.safeMessage(error, fallback: "Recovery could not establish a definite outcome. Do not retry the write. No write was attempted by this check.")
            }
        }
    }

    func close() {
        invalidateReview()
        task?.cancel()
        clearCredentials()
        proposal = ""
        importedHandoff = nil
        importedPurpose = nil
        controller = nil
        active = false
        isConfigured = false
        status = "Live session closed and pending review invalidated. Any uncertain prior write must be reconciled before another write."
    }
}

/// Separate from the offline workbench. Creating this view performs no operation.
@MainActor struct LiveWorkbench: View {
    @StateObject private var model = LiveModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Tailgate / Live policy review").font(.title2.bold())
                Spacer()
                Button("Import agent proposal…") { model.importHandoff() }
                    .disabled(model.busy)
            }
            Text("This mode can change your real tailnet. The agent may propose; only this trusted Mac app can execute an approved write.")
                .foregroundStyle(.secondary)
            if let purpose = model.importedPurpose {
                GroupBox("UNTRUSTED AGENT CONTEXT — not authorization") {
                    Text(verbatim: purpose)
                        .font(.callout).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Divider()
            if model.active {
                liveContents
            } else {
                Text("Open a trusted session only when you are ready to use this Mac's private configuration. A development or incorrectly signed build is expected to refuse.")
                Button("Open trusted live session…") { model.activate() }
                    .disabled(model.busy)
                Spacer()
            }
            Divider()
            if model.busy {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Operation in progress — duplicate actions are blocked.")
                }.accessibilityElement(children: .combine)
            }
            Text(verbatim: model.status)
                .font(.callout).textSelection(.enabled)
        }
        .padding(20)
        .frame(minWidth: 720, minHeight: 600)
        .onDisappear { model.close() }
    }

    @ViewBuilder private var liveContents: some View {
        if let review = model.review {
            Text("Review SHA-256").font(.caption).foregroundStyle(.secondary)
            Text(verbatim: review.fingerprint)
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            ScrollView {
                Text(verbatim: review.text)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .accessibilityLabel("Exact reviewed policy diff and request")
            HStack {
                Button("Discard review") { model.discard() }
                Spacer()
                Button("Approve this exact write with Touch ID…") { model.approve() }
                    .disabled(model.busy)
            }
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    configuration
                    LookupProvisionForm().disabled(model.busy)
                    Text("Untrusted proposal JSON").font(.headline)
                    Text("Paste data only. Preparing checks the current policy and candidate; it does not authorize a write.")
                        .font(.callout).foregroundStyle(.secondary)
                    TextEditor(text: Binding(get: { model.proposal }, set: { model.editProposal($0) }))
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 180)
                        .border(Color.secondary)
                        .accessibilityLabel("Untrusted proposal JSON")
                        .disabled(model.busy)
                    HStack {
                        Button("Prepare and validate policy review…") { model.prepare() }
                            .disabled(model.busy || !model.isConfigured || model.proposal.isEmpty)
                        if model.busy {
                            Button("Invalidate pending approval") { model.discard() }
                        }
                    }
                    Divider()
                    HStack {
                        Button("Check pinned enrollment (read only)") { model.checkEnrollment() }
                        Button("Recover last outcome (read only)") { model.reconcile() }
                    }.disabled(model.busy || !model.isConfigured)
                    Text("Recovery never retries a policy write. Checking enrollment never logs in, changes tags, or enrolls a client.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var configuration: some View {
        DisclosureGroup("Private setup — provision policy clients once", isExpanded: $model.setupExpanded) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Enter values obtained independently of the agent. Leave this section alone to use previously saved setup. No credentials go to the proposal, clipboard, logs, or repository.")
                    .font(.callout).foregroundStyle(.secondary)
                LabeledContent("Tailnet ID") { TextField("Exact tailnet ID; not the default alias", text: $model.tailnet) }
                LabeledContent("Intended VM label") { TextField("Locally trusted VM label", text: $model.vm) }
                LabeledContent("Source tag") { TextField("Existing tag allowed to connect", text: $model.source) }
                LabeledContent("Pinned node key") { SecureField("Independently verified node key", text: $model.nodeKey) }
                LabeledContent("Read client ID") { SecureField("Read-only OAuth client ID", text: $model.readClientID) }
                LabeledContent("Read client secret") { SecureField("Read-only OAuth client secret", text: $model.readSecret) }
                LabeledContent("Write client ID") { SecureField("Scoped writer OAuth client ID", text: $model.writeClientID) }
                LabeledContent("Write client secret") { SecureField("Scoped writer OAuth client secret", text: $model.writeSecret) }
                Button("Save setup privately on this Mac") { model.saveConfiguration() }
                    .disabled(model.busy || !model.completeSetup)
                Text("Private input fields are cleared after every save attempt. Values are not read back into the form.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 8)
            .disabled(model.busy)
            .privacySensitive()
            .onChange(of: [model.tailnet, model.vm, model.source, model.nodeKey, model.readClientID,
                           model.readSecret, model.writeClientID, model.writeSecret]) { _ in model.configurationChanged() }
        }
    }
}

/// Reads only the file explicitly selected by the operator, never a proposal path.
/// Bounded descriptor reads avoid Data(contentsOf:) following a link or waiting on a FIFO.
private enum HandoffFile {
    private enum Rejected: Error { case file }

    static func read(_ url: URL) throws -> Data {
        guard url.isFileURL, url.pathExtension.lowercased() == "tailgate" else { throw Rejected.file }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let fd = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fd >= 0 else { throw Rejected.file }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0,
              (before.st_mode & S_IFMT) == S_IFREG, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= AgentHandoff.maximumBytes else { throw Rejected.file }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while bytes.count <= AgentHandoff.maximumBytes {
            let capacity = min(buffer.count, AgentHandoff.maximumBytes + 1 - bytes.count)
            let count = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress, capacity)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw Rejected.file
            }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard bytes.count <= AgentHandoff.maximumBytes, bytes.count == before.st_size,
              fstat(fd, &after) == 0, after.st_nlink == 1, after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec,
              after.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec else { throw Rejected.file }
        return bytes
    }
}
