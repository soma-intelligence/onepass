import SwiftUI

/// À propos: license, version, source code, cryptography.
struct AboutSettings: View {
    /// Placeholder until the repository is public (architecture spec, section 11).
    static let sourceURL = URL(string: "https://github.com/soma-intelligence/onepass")!

    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    var body: some View {
        Form {
            Section {
                Text("OnePass est open source (AGPL-3.0)")
                    .accessibilityIdentifier("settings.about.license")
                LabeledContent("Version") {
                    Text(verbatim: version)
                        .textSelection(.enabled)
                }
                .accessibilityIdentifier("settings.about.version")
                Link(destination: Self.sourceURL) {
                    Label("Code source", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                .accessibilityIdentifier("settings.about.source")
            }
            Section {
                Text("Cryptographie post-quantique : ML-KEM-1024, ML-DSA-87, SLH-DSA")
                    .accessibilityIdentifier("settings.about.crypto")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("À propos")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}
