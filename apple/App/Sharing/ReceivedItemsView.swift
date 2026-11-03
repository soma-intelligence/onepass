import SwiftUI
import VaultKit

/// Copies of items a contact sent (spec 14.2): "Garder" puts the copy in a vault picked here,
/// "Refuser" drops it. A copy past its date is gone.
struct ReceivedItemsView: View {
    @Environment(AppModel.self) private var model
    @State private var vaultID: String?
    @State private var errorMessage: String?

    private var writable: [FfiVault] {
        model.session.vaults.filter { model.session.sharedRole(of: $0.id) != .read }
    }

    var body: some View {
        Form {
            Section {
                Picker("sharing.received.into", selection: $vaultID) {
                    ForEach(writable, id: \.id) { Text($0.meta.name).tag(Optional($0.id)) }
                }
            }
            ForEach(model.session.sharing.receivedItems, id: \.sendId) { item in
                Section {
                    LabeledContent(item.title) { Text("sharing.received.from \(item.fromNameLocal)") }
                    Button("sharing.received.keep") {
                        guard let into = vaultID ?? writable.first?.id else { return }
                        act { _ = try await model.session.acceptReceivedItem(item.sendId, into: into) }
                    }
                    .accessibilityIdentifier("sharing.received.keep")
                    Button("sharing.received.decline", role: .destructive) {
                        act { try await model.session.declineReceivedItem(item.sendId) }
                    }
                }
            }
            SharingErrorSection(message: errorMessage)
        }
        .settingsPage("sharing.received.title")
    }

    private func act(_ work: @escaping () async throws -> Void) {
        errorMessage = nil
        Task {
            do { try await work() } catch { errorMessage = VaultError(error).localizedMessage }
        }
    }
}
