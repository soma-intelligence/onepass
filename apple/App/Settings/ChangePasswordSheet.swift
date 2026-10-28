import DesignKit
import SwiftUI
import VaultKit

/// "Changer le mot de passe maître" (spec 2b 3.3): the current one, the new one twice with the strength
/// gauge. The keys and the Secret Key stay: the Emergency Kit remains valid, the other devices ask the
/// new password at their next unlock. Biometric unlock is enrolled again by the session.
struct ChangePasswordSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var confirmation = ""
    @State private var busy = false
    @State private var errorMessage: String?

    private var mismatch: Bool { !confirmation.isEmpty && confirmation != new }
    private var newAccepted: Bool { PasswordStrength.acceptsMasterPassword(new) }
    private var canSubmit: Bool { !current.isEmpty && newAccepted && new == confirmation && !busy }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Mot de passe actuel", text: $current)
                        .privacySensitive()
                        .accessibilityIdentifier("settings.changePassword.current")
                }
                Section {
                    SecureField("Nouveau mot de passe", text: $new)
                        .privacySensitive()
                        .accessibilityIdentifier("settings.changePassword.new")
                    StrengthMeter(bits: PasswordStrength.estimatedBits(new))
                    SecureField("Confirme-le", text: $confirmation)
                        .privacySensitive()
                        .onSubmit(run)
                        .accessibilityIdentifier("settings.changePassword.confirm")
                } footer: {
                    if mismatch {
                        Text("Les deux saisies sont différentes.").foregroundStyle(.red)
                    } else if !new.isEmpty, !newAccepted {
                        Text("Trop faible pour un mot de passe maître : cinq mots tirés au hasard marchent bien.")
                    } else {
                        Text("Ta Secret Key ne change pas : ton Emergency Kit reste valable. Tes autres appareils te demanderont le nouveau mot de passe.")
                    }
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("settings.changePassword.error")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Changer le mot de passe maître")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Changer", action: run)
                        .disabled(!canSubmit)
                        .accessibilityIdentifier("settings.changePassword.submit")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 340)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear {
            current = ""
            new = ""
            confirmation = ""
        }
    }

    private func run() {
        guard canSubmit else { return }
        busy = true
        errorMessage = nil
        // The fields are emptied on submission; the values live on in wiped buffers only.
        let typedCurrent = SecretBytes(utf8: current)
        let typedNew = SecretBytes(utf8: new)
        current = ""
        Task {
            defer {
                typedCurrent.wipe()
                typedNew.wipe()
                busy = false
            }
            do {
                try await model.session.changePassword(current: typedCurrent, new: typedNew)
                new = ""
                confirmation = ""
                model.settingsChanged()
                model.showToast(String(localized: "Mot de passe maître changé"))
                dismiss()
            } catch {
                let failure = VaultError(error)
                errorMessage = failure == .wrongPassword
                    ? String(localized: "Le mot de passe actuel est incorrect.") : failure.localizedMessage
            }
        }
    }
}
