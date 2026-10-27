import DesignKit
import SwiftUI
import VaultKit

/// The extension's interface: one screen per `AutoFillModel.Screen`. The views only display and
/// forward the user's choices to the model; the model decides and completes the request.
struct AutoFillRootView: View {
    let model: AutoFillModel
    let session: VaultSession
    let request: AutoFillRequest

    var body: some View {
        screen
            .tint(Theme.accent)
    }

    @ViewBuilder private var screen: some View {
        switch model.screen {
        case .starting, .finished:
            // Before `start` nothing is decided yet; after the end the controller is dismissing the
            // extension and nothing from the vault stays on screen.
            Color.clear
        case .locked:
            UnlockView(model: model, session: session)
        case .noAccount:
            MessageView(
                model: model,
                title: String(localized: "Ouvre OnePass pour configurer ton coffre"),
                systemImage: "lock.shield",
                message: String(localized: "Crée ou restaure ton compte dans l'app OnePass, puis reviens ici."))
        case .needsSecretKey:
            MessageView(
                model: model,
                title: String(localized: "Ouvre OnePass pour configurer ton coffre"),
                systemImage: "key",
                message: String(localized: "Saisis ta Secret Key dans l'app OnePass sur cet appareil, puis reviens ici."))
        case .integrityFailure(let failure):
            IntegrityView(model: model, failure: failure)
        case .list(let matches, let others):
            CandidateListView(
                model: model, session: session, matches: matches, others: others, oneTimeCode: isOneTimeCodeList)
        case .passkeyRegistration(let suggestions):
            if case .passkeyRegistration(let registration) = request {
                PasskeyRegistrationView(
                    model: model, session: session, registration: registration, suggestions: suggestions)
            }
        case .save(let existing):
            if case .savePassword(let save) = request {
                SavePasswordView(model: model, session: session, request: save, existing: existing)
            }
        case .textItems(let items):
            TextItemsView(model: model, session: session, items: items)
        case .textFields(let item):
            TextFieldsView(model: model, session: session, item: item)
        case .configuration:
            ConfigurationView(model: model, session: session)
        }
    }

    /// One-time code list, or the list a direct code request falls back to.
    private var isOneTimeCodeList: Bool {
        switch request {
        case .oneTimeCodeList, .credential(_, .oneTimeCode, _, _): true
        default: false
        }
    }
}

/// Navigation bar with the title and "Annuler" (every screen), and "Retour" when `back` is set.
struct AutoFillScaffold<Content: View>: View {
    let title: Text
    let model: AutoFillModel
    var back: (() -> Void)?
    @ViewBuilder let content: Content

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { model.cancel() }
                            .accessibilityIdentifier("autofill.cancel")
                    }
                    if let back {
                        ToolbarItem(placement: .navigation) {
                            Button("Retour", systemImage: "chevron.backward", action: back)
                                .accessibilityIdentifier("autofill.back")
                        }
                    }
                }
        }
    }
}

/// The last error of the session, when it is worth showing (a refused biometric prompt is not).
struct SessionErrorText: View {
    let session: VaultSession

    var body: some View {
        if let error = session.lastError, error != .passwordRequired {
            Text(error.localizedMessage)
                .font(.footnote)
                .foregroundStyle(.red)
                .accessibilityIdentifier("autofill.error")
        }
    }
}

/// "Open OnePass" screens: nothing can be filled from the extension, only "Annuler".
private struct MessageView: View {
    let model: AutoFillModel
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        AutoFillScaffold(title: Text(verbatim: ""), model: model) {
            EmptyState(title: title, systemImage: systemImage, message: message)
        }
    }
}

/// The core refused tampered data: nothing is shown from the vault.
private struct IntegrityView: View {
    let model: AutoFillModel
    let failure: VaultError

    var body: some View {
        AutoFillScaffold(title: Text("Données refusées"), model: model) {
            VStack(spacing: 16) {
                if case .integrity(let kind) = failure {
                    IntegrityBanner(kind: kind)
                } else {
                    Text(failure.localizedMessage)
                }
                Text("Ouvre OnePass pour en savoir plus.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(20)
        }
    }
}

/// Item title used in accessibility identifiers (`autofill.candidate.<title>`).
func autofillIdentifier(_ prefix: String, _ title: String) -> String {
    "autofill.\(prefix).\(title)"
}
