import SwiftUI
#if os(macOS)
import UpdateKit
#endif

/// À propos: license, version, source code, cryptography.
struct AboutSettings: View {
    /// Placeholder until the repository is public (architecture spec, section 11).
    static let sourceURL = URL(string: "https://github.com/soma-intelligence/onepass")!

    #if os(macOS)
    /// `nil` in builds without the update key: no updates section then.
    @Environment(AppUpdater.self) private var updater: AppUpdater?
    #endif

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
            #if os(macOS)
            if let updater {
                UpdatesSection(updater: updater)
            }
            #endif
            Section {
                LabeledContent("settings.about.postQuantum") {
                    Text(verbatim: "ML-KEM-1024 · ML-DSA-87 · SLH-DSA")
                }
                    .accessibilityIdentifier("settings.about.crypto")
            }
        }
        .settingsPage("À propos")
    }
}

#if os(macOS)
/// Réglages > À propos on the Mac (Developer ID build): automatic checks at launch and every 24 hours,
/// a check now, and what the check sends (spec 2026-11-02-mac-updater-design.md, section 7).
private struct UpdatesSection: View {
    @Bindable var updater: AppUpdater

    var body: some View {
        Section {
            Toggle("settings.about.updates.automatic", isOn: $updater.automaticallyChecksForUpdates)
                .accessibilityIdentifier("settings.about.updates.automatic")
            LabeledContent {
                Button("settings.about.updates.checkNow") { updater.checkForUpdates() }
                    .disabled(!updater.canCheckForUpdates)
                    .accessibilityIdentifier("settings.about.updates.checkNow")
            } label: {
                if let date = updater.lastUpdateCheckDate {
                    Text("settings.about.updates.lastCheck \(date.formatted(date: .abbreviated, time: .shortened))")
                }
            }
        } header: {
            Text("settings.about.updates.section")
        } footer: {
            Text("settings.about.updates.footer")
        }
    }
}
#endif
