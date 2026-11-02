import DesignKit
import SwiftUI
import VaultKit

/// Ajouter un compte (multi-account spec 7): the kind, a name and a color, then either a new account
/// (its own sign up, its own Secret Key) or one that exists (its Emergency Kit). An organisation account
/// needs its server, not built yet: the choice is shown and explained, never offered (ruling P10).
struct AddAccountSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var kind: Kind = .business
    @State private var label = ""
    @State private var color: FfiAccountColor = AccountProfile.defaultColor(for: .business)

    enum Kind: Hashable, CaseIterable {
        case personal, business, managed

        var title: LocalizedStringKey {
            switch self {
            case .personal: "accounts.kind.personal"
            case .business: "accounts.kind.business"
            case .managed: "accounts.kind.managed"
            }
        }

        var subtitle: LocalizedStringKey {
            switch self {
            case .personal: "accounts.add.kind.personal.subtitle"
            case .business: "accounts.add.kind.business.subtitle"
            case .managed: "accounts.add.kind.managed.subtitle"
            }
        }

        var core: FfiAccountKind {
            switch self {
            case .personal: .personal
            case .business: .business
            case .managed: .managed(serverUrl: "", orgId: "")
            }
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(Kind.allCases, id: \.self) { option in
                        kindRow(option)
                    }
                } header: {
                    Text("accounts.add.kind")
                } footer: {
                    Text("accounts.add.kind.footer")
                }
                Section {
                    TextField("accounts.detail.name", text: $label)
                        .accessibilityIdentifier("accounts.add.name")
                    AccountColorPicker(color: $color)
                } header: {
                    Text("accounts.add.look")
                }
                Section {
                    Button {
                        begin(signIn: false)
                    } label: {
                        Label("accounts.add.create", systemImage: "person.badge.plus")
                    }
                    .accessibilityIdentifier("accounts.add.create")
                    Button {
                        begin(signIn: true)
                    } label: {
                        Label("accounts.add.signIn", systemImage: "doc.text.viewfinder")
                    }
                    .accessibilityIdentifier("accounts.add.signIn")
                } footer: {
                    Text("accounts.add.footer")
                }
                .disabled(kind == .managed)
            }
            .formStyle(.grouped)
            .navigationTitle("accounts.add")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                        .accessibilityIdentifier("accounts.add.dismiss")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 520)
        #endif
    }

    private func kindRow(_ option: Kind) -> some View {
        let available = option != .managed || model.accounts.serverAvailable(option.core)
        return Button {
            guard available else { return }
            if color == AccountProfile.defaultColor(for: kind.core) {
                color = AccountProfile.defaultColor(for: option.core)
            }
            kind = option
        } label: {
            HStack(spacing: 12) {
                Image(systemName: AccountProfile.symbol(for: option.core))
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(
                        AccountStyle.color(AccountProfile.defaultColor(for: option.core)).gradient,
                        in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                VStack(alignment: .leading, spacing: 1) {
                    Text(option.title).foregroundStyle(.primary)
                    Text(available ? option.subtitle : "accounts.add.kind.managed.unavailable")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                if kind == option {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Theme.accent)
                }
            }
            .contentShape(.rect)
            .opacity(available ? 1 : 0.5)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(kind == option ? .isSelected : [])
        .accessibilityIdentifier("accounts.add.kind.\(option)")
    }

    private func begin(signIn: Bool) {
        let name = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let chosen = kind.core
        let chosenColor = color
        dismiss()
        do {
            try model.beginAddingAccount(kind: chosen, label: name, color: chosenColor, signIn: signIn)
        } catch {
            model.showToast(error.message, kind: .error)
        }
    }
}
