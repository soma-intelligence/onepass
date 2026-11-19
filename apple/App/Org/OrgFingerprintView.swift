import SwiftUI
import VaultKit

/// An organisation's fingerprint as its 4 rows of 5 words (always the EFF English list, read aloud
/// across devices), then where this device got it from. VoiceOver reads it group by group.
struct OrgFingerprintView: View {
    let words: [[String]]
    let source: FfiPinSource
    /// The domain whose DNS record confirmed the fingerprint (`source == .dns`), from the invitation.
    var domain: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(words.enumerated()), id: \.offset) { index, group in
                    Text(group.joined(separator: " "))
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .accessibilityLabel(group.joined(separator: ", "))
                        .accessibilityIdentifier("org.fingerprint.group.\(index)")
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel(Text("org.join.fingerprint"))
            Label(sourceLine, systemImage: sourceSymbol)
                .font(.footnote)
                .foregroundStyle(confirmed ? Color.secondary : Color.orange)
                .accessibilityIdentifier("org.fingerprint.source")
        }
    }

    private var confirmed: Bool {
        if case .tofu(verified: false) = source { return false }
        return true
    }

    private var sourceLine: String {
        switch source {
        case .mdm:
            String(localized: "org.source.mdm")
        case .dns:
            if let domain, !domain.isEmpty {
                String(format: String(localized: "org.source.dns"), domain)
            } else {
                String(localized: "org.source.dnsNoDomain")
            }
        case .tofu(verified: false):
            String(localized: "org.source.tofu")
        case .tofu(verified: true):
            String(localized: "org.source.verified")
        }
    }

    private var sourceSymbol: String {
        switch source {
        case .mdm: "building.2"
        case .dns: "globe"
        case .tofu(verified: false): "exclamationmark.triangle"
        case .tofu(verified: true): "checkmark.seal"
        }
    }
}
