import SwiftUI
import VaultKit

/// Enrollment in organizer-assisted recovery (spec 11.4): the organizer, the delay, then the risk
/// sentence shown and confirmed before anything is sealed, then the master password.
struct RecoveryEnrollView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var organizer: String?
    @State private var days = 3
    @State private var understood = false
    @State private var password = ""
    @State private var busy = false
    @State private var errorMessage: String?

    private var organizers: [FfiFamilyMember] {
        (model.session.sharing.family?.members ?? []).filter { $0.role == .organizer && !$0.nameLocal.isEmpty }
    }

    private var organizerName: String? { organizers.first { $0.accountId == organizer }?.nameLocal }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("family.organizer", selection: $organizer) {
                        ForEach(organizers, id: \.accountId) { Text($0.nameLocal).tag(Optional($0.accountId)) }
                    }
                    .accessibilityIdentifier("recovery.enroll.organizer")
                    Stepper("recovery.enroll.days \(days)", value: $days, in: 1...30)
                }
                if let organizerName {
                    Section {
                        Text(VaultSession.recoveryRiskText(organizer: organizerName, mailboxAccount: model.syncsThroughMailbox))
                            .accessibilityIdentifier("recovery.enroll.risk")
                        Toggle("recovery.enroll.understood", isOn: $understood)
                            .accessibilityIdentifier("recovery.enroll.understood")
                    }
                }
                if understood {
                    Section {
                        SecureField("recovery.enroll.password", text: $password)
                            .accessibilityIdentifier("recovery.enroll.password")
                    }
                }
                SharingErrorSection(message: errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle(Text("recovery.enroll.title"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("recovery.enroll.confirm") { enroll() }
                        .disabled(!understood || password.isEmpty || organizer == nil || busy)
                        .accessibilityIdentifier("recovery.enroll.confirm")
                }
            }
            .onAppear { organizer = organizer ?? organizers.first?.accountId }
        }
    }

    private func enroll() {
        guard let organizer else { return }
        busy = true
        let secret = SecretBytes(utf8: password)
        password = ""
        Task {
            defer {
                secret.wipe()
                busy = false
            }
            do {
                try await model.session.enrollRecovery(
                    organizer: organizer, delaySecs: UInt32(days * 24 * 3600), password: secret)
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
