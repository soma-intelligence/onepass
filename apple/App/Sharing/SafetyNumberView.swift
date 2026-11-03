import SwiftUI
import VaultKit

/// "Comparer le numéro de sécurité" (spec 5.3.2): both read the number aloud or side by side; a
/// match takes the contact from Link to Verified. The core checks the number shown again.
struct SafetyNumberView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let contact: FfiContact
    @State private var errorMessage: String?
    @State private var busy = false

    var body: some View {
        Form {
            Section {
                Text(contact.safetyNumber)
                    .font(.system(.title2, design: .monospaced).weight(.semibold))
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("sharing.safetyNumber")
            } header: {
                Text("sharing.contact.safetyNumber")
            } footer: {
                Text("sharing.safety.footer \(contact.nameLocal)")
            }
            Section {
                Button("sharing.safety.match") { confirm() }
                    .disabled(busy)
                    .accessibilityIdentifier("sharing.safety.match")
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("sharing.contact.compareSafetyNumber")
    }

    private func confirm() {
        busy = true
        Task {
            defer { busy = false }
            do {
                try await model.session.confirmSafetyNumber(of: contact.accountId, shown: contact.safetyNumber)
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
