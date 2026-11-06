import DesignKit
import SwiftUI
import VaultKit

/// Shown once OnePass is turned on as a provider: "OnePass est prêt", and a reminder to open the
/// app first when this device has no usable account yet. With an account, "Afficher mes comptes
/// au-dessus du clavier" unlocks once and publishes the identities (G10), so QuickType works at once.
/// "OK" ends the configuration request.
struct ConfigurationView: View {
    let model: AutoFillModel
    let session: VaultSession

    private var needsApp: Bool {
        switch session.state {
        case .noAccount, .failed: true
        default: session.needsSecretKey
        }
    }

    var body: some View {
        AutoFillScaffold(title: Text(verbatim: ""), model: model) {
            ScrollView {
                VStack(spacing: 16) {
                    AppGlyph(size: 72)
                    Text("views.onepassReady")
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("autofill.configuration.title")
                    Text("views.passwordsPasskeysAndVerification")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    if needsApp {
                        Text("views.openOnepassToSet2")
                            .font(.callout.weight(.medium))
                            .multilineTextAlignment(.center)
                    } else if model.suggestionsPublished {
                        Label("views.suggestionsReady", systemImage: "checkmark.circle.fill")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(Theme.readableAccent)
                            .accessibilityIdentifier("autofill.configuration.published")
                    } else if session.environment.settings.quickTypeSuggestions {
                        // G10: the suggestions above the keyboard need the identities published once.
                        Button {
                            Task { await model.publishSuggestionsFromConfiguration() }
                        } label: {
                            Text("views.showAccountsAboveKeyboard")
                                .font(.callout.weight(.semibold))
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                        .controlSize(.large)
                        .accessibilityIdentifier("autofill.configuration.publish")
                    }
                    AutoFillPrimaryButton {
                        model.cancel()
                    } label: {
                        Text("common.ok")
                    }
                    .keyboardShortcut(.defaultAction)
                    .padding(.top, 8)
                    .accessibilityIdentifier("autofill.done")
                }
                .frame(maxWidth: 334)
                .padding(.horizontal, 28)
                .padding(.vertical, 32)
                .frame(maxWidth: .infinity)
            }
        }
    }
}
