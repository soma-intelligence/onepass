import DesignKit
import SwiftUI
import VaultKit

/// Previous passwords of an item, newest first, masked with Révéler and Copier.
/// Loaded when shown, dropped when it goes away.
struct PasswordHistoryView: View {
    @Environment(AppModel.self) private var model
    let ref: ItemRef
    @State private var entries: [FfiHistoryEntry] = []
    @State private var error: String?

    var body: some View {
        Form {
            if let error {
                Text(error).foregroundStyle(.red)
            }
            Section {
                ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                    FieldRow(
                        label: "Remplacé le \(FieldDates.timestamp(entry.replacedAt))", value: entry.value,
                        isSecret: true, monospaced: true, copyIdentifier: "history.copy.\(index)",
                        onCopy: { model.session.copy(entry.value, concealed: true) },
                        onReveal: { _ in model.session.noteActivity() })
                        .privacySensitive()
                }
            } footer: {
                Text("Les anciens mots de passe restent chiffrés avec l'élément.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Versions précédentes")
        .task {
            do {
                entries = try await model.session.passwordHistory(vaultID: ref.vaultID, itemID: ref.itemID)
                    .sorted { $0.replacedAt > $1.replacedAt }
            } catch {
                self.error = VaultError(error).localizedMessage
            }
        }
        .onDisappear { entries = [] }
    }
}
