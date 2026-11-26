import SwiftUI
import TailgateLive

// Only embedded in the explicitly activated, normal (non-agent) operator window.
@MainActor struct LookupProvisionForm: View {
    @State private var expanded = false
    @State private var tailnet = ""
    @State private var clientID = ""
    @State private var secret = ""
    @State private var result = ""
    var body: some View {
        DisclosureGroup("Optional: provision exact device lookups", isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Use a dedicated devices:core:read OAuth client only. This independent, create-only setup never needs a policy writer. Do not reuse a more privileged client.").font(.callout)
                TextField("Exact lookup tailnet ID", text: $tailnet)
                SecureField("Lookup-only client ID", text: $clientID)
                SecureField("Lookup-only client secret", text: $secret)
                Button("Save lookup reader privately on this Mac") {
                    defer { clientID = ""; secret = "" }
                    do {
                        let config = try LookupConfiguration(tailnet: tailnet, clientID: clientID, secret: secret)
                        try MacTrust().store(slot: "lookup-reader", value: config.encoded())
                        result = "Lookup reader saved. No query was sent."
                    } catch { result = "Reader not saved. Verify the signed app and inputs; an existing reader cannot be overwritten." }
                }.disabled(tailnet.isEmpty || clientID.isEmpty || secret.isEmpty)
                Text(verbatim: result).font(.caption)
            }.padding(.top, 6)
        }.onDisappear { clientID = ""; secret = "" }
    }
}
