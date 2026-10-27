import DesignKit
import SwiftUI
import VaultKit

/// Shown once OnePass is turned on as a provider: "OnePass est prêt", and a reminder to open the
/// app first when this device has no usable account yet. Both buttons end the configuration request.
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
                    Text("OnePass est prêt")
                        .font(.title2.weight(.semibold))
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("autofill.configuration.title")
                    Text("Tes mots de passe, passkeys et codes de vérification sont proposés au-dessus du clavier et dans la touche Mots de passe.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    if needsApp {
                        Text("Ouvre OnePass pour configurer ton coffre et te connecter.")
                            .font(.callout.weight(.medium))
                            .multilineTextAlignment(.center)
                    }
                    AutoFillPrimaryButton {
                        model.cancel()
                    } label: {
                        Text("OK")
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
