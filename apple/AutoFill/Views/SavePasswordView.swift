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
        AutoFillScaffold(title: Text("OnePass"), model: model) {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    AutoFillHeader(
                        type: .login, iconTitle: updating?.title ?? title, url: serviceURL, title: heading,
                        subtitle: request.service)
                        .padding(.bottom, 14)
                    if let updating {
                        AutoFillLabel("élément mis à jour")
                        AutoFillCardRows {
                            AutoFillRow(type: .login, title: updating.title, detail: updating.user, url: updating.url) {
                                EmptyView()
                            }
                        }
                        Text("Le nouveau mot de passe remplace l'ancien, qui reste dans l'historique de l'élément.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 6)
                            .padding(.bottom, 10)
                    } else {
                        AutoFillLabel("nouvel élément")
                        AutoFillCardRows {
                            AutoFillFieldRow(label: Text("titre")) {
                                TextField("Titre", text: $title, prompt: Text(verbatim: AutoFillModel.defaultTitle(for: request)))
                                    .textFieldStyle(.plain)
                                    .accessibilityIdentifier("autofill.title")
                            }
                            VaultPicker(vaults: session.vaults, selection: $vaultID)
                        }
                        .padding(.bottom, 10)
                    }
                    AutoFillLabel("connexion")
                    AutoFillCardRows {
                        AutoFillFieldRow(label: request.serviceIsApp ? Text("app") : Text("site")) {
                            Text(verbatim: request.service).lineLimit(1).truncationMode(.middle)
                        }
                        AutoFillFieldRow(label: Text("identifiant")) {
                            Text(verbatim: request.user.isEmpty ? String(localized: "Aucun") : request.user)
                                .foregroundStyle(request.user.isEmpty ? .secondary : .primary)
                        }
                        AutoFillFieldRow(label: Text("mot de passe")) {
                            Text(verbatim: FieldRow.mask).accessibilityLabel(Text("masqué"))
                        }
                    }
                    SessionErrorText(session: session)
                        .padding(.horizontal, 6)
                    AutoFillPrimaryButton {
                        save()
                    } label: {
                        if busy {
                            ProgressView()
                        } else {
                            Text(updating == nil ? "Enregistrer" : "Mettre à jour")
                        }
                    }
                    .disabled(busy || !canSave)
                    .padding(.top, 14)
                    .accessibilityIdentifier("autofill.save")
                    if existing != nil {
                        Button(asNewItem ? "Mettre à jour l'élément existant" : "Enregistrer comme nouvel élément") {
                            withAnimation(.snappy) { asNewItem.toggle() }
                        }
                        .font(.subheadline.weight(.medium))
                        .frame(maxWidth: .infinity)
                        .padding(.top, 6)
                        .disabled(busy)
                        .accessibilityIdentifier("autofill.save.toggle")
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    /// The site's address for its icon (an app identifier has none).
    private var serviceURL: String? {
        guard !request.serviceIsApp else { return nil }
        return request.service.contains("://") ? request.service : "https://\(request.service)"
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
