import DesignKit
import SwiftUI
import VaultKit

/// "Enregistrer une passkey pour <rp>": add it to a Login of the relying party (same or empty
/// username), or to a new item in the chosen vault. Nothing is created before the explicit
/// "Enregistrer la passkey" (ruling A9).
struct PasskeyRegistrationView: View {
    let model: AutoFillModel
    let session: VaultSession
    let registration: PasskeyRegistrationRequest
    let suggestions: [FfiAutofillCandidate]

    private enum Target: Hashable {
        case item(vaultID: String, itemID: String)
        case newItem
    }

    @State private var target: Target
    @State private var vaultID: String
    @State private var busy = false

    init(
        model: AutoFillModel, session: VaultSession, registration: PasskeyRegistrationRequest,
        suggestions: [FfiAutofillCandidate]
    ) {
        self.model = model
        self.session = session
        self.registration = registration
        self.suggestions = suggestions
        _target = State(initialValue: suggestions.first.map { .item(vaultID: $0.vaultId, itemID: $0.itemId) } ?? .newItem)
        _vaultID = State(initialValue: session.vaults.first?.id ?? "")
    }

    var body: some View {
        AutoFillScaffold(title: Text("Enregistrer une passkey pour \(registration.rpID)"), model: model) {
            Form {
                Section {
                    LabeledContent("Site") { Text(verbatim: registration.rpID) }
                    LabeledContent("Identifiant") { Text(verbatim: registration.userName) }
                }
                if !suggestions.isEmpty {
                    Section {
                        ForEach(suggestions, id: \.key) { candidate in
                            choice(.item(vaultID: candidate.vaultId, itemID: candidate.itemId)) {
                                HStack(spacing: 12) {
                                    ItemIcon(type: .login, title: candidate.title, siteIcon: nil, size: 28)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Ajouter à \(candidate.title)")
                                        if !candidate.user.isEmpty {
                                            Text(verbatim: candidate.user).font(.subheadline).foregroundStyle(.secondary)
                                        }
                                    }
                                }
                            }
                            .accessibilityIdentifier(autofillIdentifier("candidate", candidate.title))
                        }
                    } header: {
                        Text("Éléments existants")
                    }
                }
                Section {
                    choice(.newItem) {
                        Label("Nouvel élément", systemImage: "plus.circle")
                    }
                    .accessibilityIdentifier("autofill.passkey.new")
                    if target == .newItem {
                        VaultPicker(vaults: session.vaults, selection: $vaultID)
                    }
                }
                Section {
                    SessionErrorText(session: session)
                    Button {
                        register()
                    } label: {
                        Text("Enregistrer la passkey").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || !canRegister)
                    .accessibilityIdentifier("autofill.passkey.register")
                }
            }
            .formStyle(.grouped)
        }
    }

    private func choice<Label: View>(_ value: Target, @ViewBuilder label: () -> Label) -> some View {
        Button {
            target = value
        } label: {
            HStack {
                label()
                Spacer(minLength: 0)
                if target == value {
                    Image(systemName: "checkmark").foregroundStyle(Theme.accent)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(target == value ? .isSelected : [])
    }

    private var canRegister: Bool {
        switch target {
        case .item: true
        case .newItem: session.vaults.contains { $0.id == vaultID }
        }
    }

    private func register() {
        guard !busy, canRegister else { return }
        busy = true
        session.lastError = nil
        let target = target
        let vaultID = vaultID
        Task {
            switch target {
            case .item(let itemVault, let itemID):
                await model.registerPasskey(into: itemID, vaultID: itemVault)
            case .newItem:
                await model.registerPasskey(into: nil, vaultID: vaultID)
            }
            busy = false
        }
    }
}

/// The visible vaults with their badge.
struct VaultPicker: View {
    let vaults: [FfiVault]
    @Binding var selection: String

    var body: some View {
        Picker("Coffre", selection: $selection) {
            ForEach(vaults, id: \.id) { vault in
                Label {
                    Text(verbatim: vault.meta.name)
                } icon: {
                    VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 20)
                }
                .tag(vault.id)
            }
        }
        .accessibilityIdentifier("autofill.vault")
    }
}
