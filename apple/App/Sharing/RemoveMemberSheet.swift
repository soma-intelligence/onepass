import SwiftUI
import VaultKit

/// "Retirer" a member (spec 9.3): confirmed, then the sentence with the number of items they could
/// read and "Changer les mots de passe", which opens Watchtower on "Vus par un ancien membre".
struct RemoveMemberSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vaultID: String
    let member: FfiMember

    @State private var prompt: RemovalPrompt?
    @State private var busy = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                if let prompt {
                    Section {
                        Text(prompt.message)
                            .accessibilityIdentifier("sharing.removal.prompt")
                    }
                    Section {
                        Button("sharing.removal.changePasswords") {
                            let ids = model.session.sharing.seenByFormerMembers
                            dismiss()
                            model.showWatchtowerItems(title: VaultSession.seenByFormerMemberTitle, itemIDs: ids)
                        }
                        .accessibilityIdentifier("sharing.removal.changePasswords")
                        Button("sharing.removal.later") { dismiss() }
                    }
                } else {
                    Section {
                        Text("sharing.member.removeConfirm \(member.nameLocal)")
                    } footer: {
                        Text("sharing.member.removeFooter")
                    }
                    Section {
                        Button("sharing.member.remove", role: .destructive) { remove() }
                            .disabled(busy)
                            .accessibilityIdentifier("sharing.member.removeConfirm")
                    }
                    SharingErrorSection(message: errorMessage)
                }
            }
            .formStyle(.grouped)
            .navigationTitle(Text("sharing.member.remove"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                if prompt == nil {
                    ToolbarItem(placement: .cancellationAction) { Button("Annuler") { dismiss() } }
                }
            }
        }
    }

    private func remove() {
        busy = true
        Task {
            defer { busy = false }
            do {
                prompt = try await model.session.removeMember(member.accountId, from: vaultID)
                _ = try? await model.session.seenByFormerMemberItems()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
