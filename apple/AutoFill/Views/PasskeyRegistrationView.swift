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
        AutoFillScaffold(title: Text("views.newPasskey"), model: model) {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    AutoFillHeader(
                        type: .login, iconTitle: registration.rpID, url: "https://\(registration.rpID)",
                        title: Text("views.savePasskeyFor \(registration.rpID)"),
                        subtitle: registration.userName)
                        .padding(.bottom, 14)
                    AutoFillLabel("views.addTo")
                    AutoFillCardRows {
                        ForEach(suggestions, id: \.key) { candidate in
                            choice(.item(vaultID: candidate.vaultId, itemID: candidate.itemId)) {
                                AutoFillRow(
                                    type: .login, title: String(localized: "views.addTo \(candidate.title)"),
                                    detail: candidate.user, url: candidate.url
                                ) {
                                    AutoFillChoiceMark(selected: target == .item(vaultID: candidate.vaultId, itemID: candidate.itemId))
                                }
                            }
                            .accessibilityIdentifier(autofillIdentifier("candidate", candidate.title))
                        }
                        choice(.newItem) {
                            HStack(spacing: 12) {
                                Image(systemName: "plus")
                                    .font(.system(size: 16, weight: .semibold))
                                    .foregroundStyle(Theme.accent)
                                    .frame(width: 36, height: 36)
                                    .background(Theme.accent.opacity(0.12), in: .rect(cornerRadius: 9, style: .continuous))
                                Text("views.newItem")
                                    .font(.body.weight(.semibold))
                                    .foregroundStyle(.primary)
                                Spacer(minLength: 4)
                                AutoFillChoiceMark(selected: target == .newItem)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 9)
                            .frame(minHeight: 56)
                        }
                        .accessibilityIdentifier("autofill.passkey.new")
                        if target == .newItem {
                            VaultPicker(vaults: session.vaults, selection: $vaultID)
                        }
                    }
                    Text("views.passkeyStaysInOnepass")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.top, 2)
                    SessionErrorText(session: session)
                        .padding(.horizontal, 6)
                    AutoFillPrimaryButton {
                        register()
                    } label: {
                        if busy { ProgressView() } else { Text("views.savePasskey") }
                    }
                    .disabled(busy || !canRegister)
                    .padding(.top, 14)
                    .accessibilityIdentifier("autofill.passkey.register")
                }
                .animation(.snappy, value: target)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
        }
    }

    private func choice<Label: View>(_ value: Target, @ViewBuilder label: () -> Label) -> some View {
        Button {
            target = value
        } label: {
            label()
        }
        .buttonStyle(AutoFillRowStyle())
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

/// The visible vaults with their badge, as a row of a card.
struct VaultPicker: View {
    let vaults: [FfiVault]
    @Binding var selection: String

    private var current: FfiVault? { vaults.first { $0.id == selection } }

    var body: some View {
        HStack(spacing: 12) {
            Text("term.vault")
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            // A menu picker draws its closed label from the row's icon when the icon is a custom view:
            // the badge alone (an initial, "P") stood for the vault. The rows carry the name only; the
            // badge of the chosen vault sits next to the menu.
            if let current {
                VaultBadge(name: current.meta.name, colorName: current.meta.color, size: 20)
                    .accessibilityHidden(true)
            }
            Picker("term.vault", selection: $selection) {
                ForEach(vaults, id: \.id) { vault in
                    Text(verbatim: vault.meta.name)
                        .tag(vault.id)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .accessibilityIdentifier("autofill.vault")
        }
        .padding(.leading, 16)
        .padding(.trailing, 8)
        .padding(.vertical, 6)
        .frame(minHeight: 48)
    }
}
