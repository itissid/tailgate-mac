import SwiftUI
import TailgateCore

/// All permission labels come from the compiled policy. Agent text lives in a separate region.
struct TrialReviewCard: View {
    let plan: TrialPlan
    @State private var expanded = false
    @State private var exact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 12) {
                eyebrow("Proposed connection")
                HStack(alignment: .center, spacing: 14) {
                    endpoint("From", plan.access.source, "desktopcomputer")
                    Image(systemName: "arrow.right").foregroundStyle(.secondary).accessibilityLabel("to")
                    endpoint("To", plan.access.destination, "server.rack")
                }
                Divider().padding(.vertical, 2)
                eyebrow("Expected policy checks")
                HStack(spacing: 10) {
                    ForEach(plan.access.allowed, id: \.self) { check($0, allowed: true) }
                    ForEach(plan.access.denied, id: \.self) { check($0, allowed: false) }
                }
            }.padding(18).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.primary.opacity(0.12)))
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "quote.bubble").font(.title3).foregroundStyle(.purple).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Agent’s reason · unverified").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(verbatim: plan.purpose).font(.body).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }.padding(.horizontal, 4)
            Divider()
            DisclosureGroup(isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Policy view", selection: $exact) {
                        Text("Formatted JSON").tag(false); Text("Exact review").tag(true)
                    }.pickerStyle(.segmented).labelsHidden().frame(maxWidth: 260)
                    Text(exact ? "Original review text and exact policy bytes:" : "Same policy, indented for reading:").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: exact ? plan.text : plan.formattedPolicy)
                        .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                    Text("Review fingerprint · SHA-256").font(.caption.weight(.semibold))
                    Text(verbatim: plan.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }.padding(.top, 8)
            } label: { Label("Policy JSON and verification details", systemImage: "curlybraces").font(.callout.weight(.medium)) }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func eyebrow(_ title: String) -> some View {
        Text(verbatim: title.uppercased()).font(.system(size: 11, weight: .semibold)).tracking(1.1).foregroundStyle(.secondary)
    }
    private func endpoint(_ title: String, _ tag: String, _ icon: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Label(title, systemImage: icon).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            Text(verbatim: tag).font(.system(.body, design: .monospaced).weight(.semibold)).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func check(_ port: UInt16, allowed: Bool) -> some View {
        let color: Color = allowed ? .green : .red
        return HStack(spacing: 8) {
            Image(systemName: allowed ? "checkmark.circle.fill" : "minus.circle.fill").foregroundStyle(color).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(allowed ? "Allow" : "Deny").font(.caption.weight(.semibold))
                Text(verbatim: "\(plan.access.transport) \(port)").font(.system(.body, design: .monospaced).weight(.semibold))
            }
        }.frame(maxWidth: .infinity, alignment: .leading).padding(10)
            .background(color.opacity(0.09), in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(color.opacity(0.3)))
            .accessibilityElement(children: .combine)
    }
}
