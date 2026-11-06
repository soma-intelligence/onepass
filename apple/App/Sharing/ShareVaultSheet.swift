import SwiftUI
import VaultKit

/// "Partager ce coffre" and "Ajouter un membre" (spec 10): pick a contact and a role. A contact
/// added by link is offered with Lire only (decision 1); the core refuses more anyway. A personal
/// vault is shared first, then a sync round makes its mailbox before the member is added.
struct ShareVaultSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vaultID: String

    @State private var contactID: String?
    @State private var role: FfiRole = .read
    @State private var busy = false
    @State private var errorMessage: String?

    private var contacts: [FfiContact] {
        let members = Set(model.session.sharing.sharedVaults.first { $0.vaultId == vaultID }?.members.map(\.accountId) ?? [])
        return model.session.sharing.contacts.filter { !members.contains($0.accountId) }
    }

    private var chosen: FfiContact? { contacts.first { $0.accountId == contactID } }

    /// The roles offered for the chosen contact (decision 1).
    private var roles: [FfiRole] { chosen?.level == .link ? [.read] : [.read, .write, .manage] }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if contacts.isEmpty { Text("sharing.share.noContact").foregroundStyle(.secondary) }
                    ForEach(contacts, id: \.accountId) { contact in
                        Button {
                            contactID = contact.accountId
                            if contact.level == .link { role = .read }
                        } label: {
                            HStack {
                                ContactRow(contact: contact)
                                if contactID == contact.accountId {
                                    Image(systemName: "checkmark").foregroundStyle(.tint)
                                }
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("sharing.share.contact.\(contact.nameLocal)")
                    }
                } header: {
                    Text("settings.contacts.title")
                }
                Section {
                    Picker("sharing.share.role", selection: $role) {
                        ForEach(roles, id: \.self) { Text($0.title).tag($0) }
                    }
                    .accessibilityIdentifier("sharing.share.role")
                } footer: {
                    if chosen?.level == .link { Text("sharing.share.linkReadOnly") }
                }
                SharingErrorSection(message: errorMessage)
            }
            .formStyle(.grouped)
            .navigationTitle(Text("sharing.vault.addMember"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("sharing.share.send") { share() }
                        .disabled(chosen == nil || busy)
                        .accessibilityIdentifier("sharing.share.send")
                }
            }
        }
    }

    private func share() {
        guard let contactID else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let session = model.session
                if session.sharedRole(of: vaultID) == nil {
                    try await session.shareVault(vaultID)
                    // The vault's mailbox is made by the zone round (spec 13.3).
                    await session.environment.sync.syncNow()
                }
                try await session.addMember(contactID, to: vaultID, role: role)
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
