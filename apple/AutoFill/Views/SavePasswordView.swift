import DesignKit
import SwiftUI
import VaultKit

/// "Enregistrer dans OnePass" (new Login: title and vault), or "Mettre à jour <titre>" when a Login
/// of the same site and username holds another password (the old one goes to its history). The
/// password itself is never displayed.
struct SavePasswordView: View {
    let model: AutoFillModel
    let session: VaultSession
    let request: SavePasswordRequest
    let existing: FfiAutofillCandidate?

    @State private var title: String
    @State private var vaultID: String
    /// "Enregistrer comme nouvel élément" chosen on the update sheet.
    @State private var asNewItem = false
    @State private var busy = false

    init(model: AutoFillModel, session: VaultSession, request: SavePasswordRequest, existing: FfiAutofillCandidate?) {
        self.model = model
        self.session = session
        self.request = request
        self.existing = existing
        _title = State(initialValue: AutoFillModel.defaultTitle(for: request))
        _vaultID = State(initialValue: session.vaults.first?.id ?? "")
    }

    /// The Login updated, nil for a new one.
    private var updating: FfiAutofillCandidate? { asNewItem ? nil : existing }

    var body: some View {
        AutoFillScaffold(title: heading, model: model) {
            Form {
                if let updating {
                    Section {
                        HStack(spacing: 12) {
                            ItemIcon(type: .login, title: updating.title, siteIcon: nil, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: updating.title)
                                Text(verbatim: updating.user).font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    } footer: {
                        Text("Le nouveau mot de passe remplace l'ancien, qui reste dans l'historique de l'élément.")
                    }
                } else {
                    Section {
                        TextField("Titre", text: $title, prompt: Text(verbatim: AutoFillModel.defaultTitle(for: request)))
                            .accessibilityIdentifier("autofill.title")
                        VaultPicker(vaults: session.vaults, selection: $vaultID)
                    }
                }
                Section {
                    LabeledContent(request.serviceIsApp ? "App" : "Site") {
                        Text(verbatim: request.service).lineLimit(1)
                    }
                    LabeledContent("Identifiant") {
                        Text(verbatim: request.user.isEmpty ? String(localized: "Aucun") : request.user)
                    }
                    LabeledContent("Mot de passe") {
                        Text(verbatim: FieldRow.mask).accessibilityLabel(Text("masqué"))
                    }
                }
                Section {
                    SessionErrorText(session: session)
                    Button {
                        save()
                    } label: {
                        Text(updating == nil ? "Enregistrer" : "Mettre à jour").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || !canSave)
                    .accessibilityIdentifier("autofill.save")
                    if existing != nil {
                        Button(asNewItem ? "Mettre à jour l'élément existant" : "Enregistrer comme nouvel élément") {
                            asNewItem.toggle()
                        }
                        .disabled(busy)
                        .accessibilityIdentifier("autofill.save.toggle")
                    }
                }
            }
            .formStyle(.grouped)
        }
    }

    private var heading: Text {
        if let updating { Text("Mettre à jour \(updating.title)") } else { Text("Enregistrer dans OnePass") }
    }

    private var canSave: Bool {
        updating != nil || session.vaults.contains { $0.id == vaultID }
    }

    private func save() {
        guard !busy, canSave else { return }
        busy = true
        session.lastError = nil
        let title = title
        let target = updating.map { (vaultID: $0.vaultId, itemID: $0.itemId) }
        let vaultID = vaultID
        Task {
            if let target {
                await model.save(title: title, vaultID: target.vaultID, updating: target.itemID)
            } else {
                await model.save(title: title, vaultID: vaultID, updating: nil)
            }
            busy = false
        }
    }
}
