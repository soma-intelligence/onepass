import DesignKit
import SafariServices
import SwiftUI
import VaultKit

#if os(iOS)
import UIKit
#endif

/// Turning the OnePass Safari extension on (MS-02 on the Mac, IOSSAF-13 on iPhone and iPad).
/// Safari keeps the switch and the website access; the app shows the state it can know and opens
/// the right settings page. The Mac reads the state from Safari; iOS has no such API, so the app
/// knows only whether the extension already answered here (a pairing it stored, `SafariSetup`).
enum SafariExtensionSetup {
    static var identifier: String? { SafariSetup.extensionIdentifier() }

    #if os(macOS)
    /// On, off, or nil when Safari does not answer (no extension in this build, Safari missing).
    static func isEnabled() async -> Bool? {
        guard let identifier else { return nil }
        return await withCheckedContinuation { done in
            SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: identifier) { state, error in
                done.resume(returning: error == nil ? state?.isEnabled : nil)
            }
        }
    }

    /// Safari > Réglages > Extensions, on OnePass.
    static func openSettings() {
        guard let identifier else { return }
        SFSafariApplication.showPreferencesForExtension(withIdentifier: identifier) { _ in }
    }
    #else
    /// The extension answered on this device once (it paired with the vault). False means not seen yet.
    static func isEnabled() async -> Bool? {
        await Task.detached(priority: .utility) { SafariSetup.extensionHasPaired() }.value
    }

    /// OnePass's page in Réglages, the closest the system lets an app open.
    @MainActor static func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
    #endif
}

/// Réglages > Remplissage automatique > Safari: the state and the way to turn it on.
struct SafariExtensionSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Section {
            #if os(macOS)
            LabeledContent("safari.setup.mac.state") {
                Group {
                    switch model.safariExtensionOn {
                    case true?: Label("app.on", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case false?: Text("app.off")
                    case nil: Text(verbatim: "")
                    }
                }
            }
            .accessibilityIdentifier("safari.setup.state")
            Button("safari.setup.mac.open", systemImage: "safari") { SafariExtensionSetup.openSettings() }
                .accessibilityIdentifier("safari.setup.open")
            #else
            if model.safariExtensionOn == true {
                Label("safari.setup.seen", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("safari.setup.seen")
            }
            SafariSetupSteps()
            Button("safari.setup.openSettings", systemImage: "gear") { SafariExtensionSetup.openSettings() }
                .accessibilityIdentifier("safari.setup.open")
            #endif
        } header: {
            Text(verbatim: "Safari")
        } footer: {
            #if os(macOS)
            Text("safari.setup.mac.footer")
            #else
            Text("safari.setup.ios.footer")
            #endif
        }
        .task { await model.refreshSafariExtensionState() }
    }
}

// iPhone, iPad and visionOS: the views that show the steps compile there (`#else` of the Mac).
#if os(iOS) || os(visionOS)
/// The three steps of Réglages, numbered.
struct SafariSetupSteps: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            step(1, "safari.setup.ios.step1")
            step(2, "safari.setup.ios.step2")
            step(3, "safari.setup.ios.step3")
        }
        .font(.footnote)
    }

    private func step(_ n: Int, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(verbatim: "\(n).").monospacedDigit().foregroundStyle(.secondary)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
    }
}
#endif

/// The one-time card of Accueil (iPhone) and of the sidebar (iPad and Mac): while the extension is
/// off (Mac) or has not answered yet (iOS), until closed once (`AppModel.dismissSafariSetupCard`).
struct SafariSetupCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "safari")
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text("safari.setup.title")
                    .font(.subheadline.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    withAnimation(.snappy) { model.dismissSafariSetupCard() }
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text("Fermer"))
                .accessibilityIdentifier("safari.setup.card.dismiss")
            }
            #if os(macOS)
            Text("safari.setup.mac.cardDetail")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                SafariExtensionSetup.openSettings()
            } label: {
                Text("safari.setup.mac.open").font(.footnote.weight(.semibold))
            }
            .buttonStyle(.glassProminent)
            .controlSize(.small)
            .accessibilityIdentifier("safari.setup.card.open")
            #else
            SafariSetupSteps()
                .foregroundStyle(.secondary)
            Button {
                SafariExtensionSetup.openSettings()
            } label: {
                Text("safari.setup.openSettings").font(.footnote.weight(.semibold))
            }
            .buttonStyle(.glassProminent)
            .controlSize(.small)
            .accessibilityIdentifier("safari.setup.card.open")
            #endif
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("safari.setup.card")
    }
}
