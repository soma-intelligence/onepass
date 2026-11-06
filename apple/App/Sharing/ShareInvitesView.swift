import SwiftUI
import VaultKit

/// The invitations to shared vaults (spec 10.1): who invites, the vault's name hint and the role;
/// "Rejoindre" or "Refuser".
struct ShareInvitesView: View {
    @Environment(AppModel.self) private var model
    @State private var errorMessage: String?

    var body: some View {
        Form {
            ForEach(model.session.sharing.shareInvites, id: \.id) { invite in
                Section {
                    if let hint = invite.vaultNameHint {
                        Text("sharing.invites.from \(invite.fromNameLocal) \(hint)")
                    } else {
                        Text("sharing.invites.fromNoName \(invite.fromNameLocal)")
                    }
                    LabeledContent("sharing.share.role") { Text(invite.role.title) }
                    Button("sharing.invites.accept") {
                        act { _ = try await model.session.acceptShareInvite(invite.id) }
                    }
                    .accessibilityIdentifier("sharing.invites.accept")
                    Button("sharing.invites.decline", role: .destructive) {
                        act { try await model.session.declineShareInvite(invite.id) }
                    }
                }
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("sharing.invites.title")
    }

    private func act(_ work: @escaping () async throws -> Void) {
        errorMessage = nil
        Task {
            do { try await work() } catch { errorMessage = VaultError(error).localizedMessage }
        }
    }
}
