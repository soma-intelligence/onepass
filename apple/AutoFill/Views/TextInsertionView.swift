import DesignKit
import SwiftUI
import VaultKit

/// "Choisis un élément": every live item of the visible vaults (no Crypto Wallet), searchable.
struct TextItemsView: View {
    let model: AutoFillModel
    let session: VaultSession
    let items: [FfiItemSummary]

    @State private var query = ""
    @State private var busy = false

    var body: some View {
        AutoFillScaffold(title: Text("Choisis un élément"), model: model) {
            List {
                SessionErrorText(session: session)
                if shown.isEmpty {
                    Text(query.isEmpty ? "Aucun élément." : "Aucun résultat.").foregroundStyle(.secondary)
                }
                ForEach(shown, id: \.id) { item in
                    Button {
                        choose(item)
                    } label: {
                        HStack(spacing: 12) {
                            ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: item.title).foregroundStyle(.primary).lineLimit(1)
                                if !item.subtitle.isEmpty {
                                    Text(verbatim: item.subtitle)
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.forward")
                                .font(.footnote)
                                .foregroundStyle(.tertiary)
                                .accessibilityHidden(true)
                        }
                        .contentShape(Rectangle())
                    }
                    .accessibilityIdentifier(autofillIdentifier("item", item.title))
                }
            }
            .searchable(text: $query, prompt: Text("Rechercher dans OnePass"))
            .disabled(busy)
        }
    }

    private var shown: [FfiItemSummary] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return items }
        return items.filter { $0.title.localizedStandardContains(needle) || $0.subtitle.localizedStandardContains(needle) }
    }

    private func choose(_ item: FfiItemSummary) {
        guard !busy else { return }
        busy = true
        session.lastError = nil
        Task {
            await model.chooseText(item: item)
            busy = false
        }
    }
}

/// "Choisis un champ": the fields of the chosen item that can be inserted as text. Secret values
/// stay masked; the chosen field is inserted (the current code for a one-time password field).
struct TextFieldsView: View {
    let model: AutoFillModel
    let session: VaultSession
    let item: FfiItem

    @State private var busy = false

    var body: some View {
        AutoFillScaffold(title: Text("Choisis un champ"), model: model, back: { Task { await model.showTextItems() } }) {
            List {
                Section {
                    SessionErrorText(session: session)
                    let fields = model.insertableFields(of: item)
                    if fields.isEmpty {
                        Text("Aucun champ à insérer dans cet élément.").foregroundStyle(.secondary)
                    }
                    ForEach(fields, id: \.id) { field in
                        Button {
                            insert(field)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: field.displayLabel).font(.footnote).foregroundStyle(.secondary)
                                Text(verbatim: Self.preview(field))
                                    .foregroundStyle(.primary)
                                    .lineLimit(1)
                                    .accessibilityValue(Self.isSecret(field) ? Text("masqué") : Text(verbatim: Self.preview(field)))
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .accessibilityIdentifier(autofillIdentifier("field", field.label))
                    }
                } header: {
                    Text(verbatim: item.title)
                }
            }
            .disabled(busy)
        }
    }

    private func insert(_ field: FfiField) {
        guard !busy else { return }
        busy = true
        session.lastError = nil
        Task {
            await model.insert(field: field)
            busy = false
        }
    }

    private static func isSecret(_ field: FfiField) -> Bool {
        switch field.kind {
        case .concealed, .password, .otp, .mnemonic: true
        default: false
        }
    }

    /// What the row shows: bullets for a secret, the value otherwise. A one-time code is never
    /// computed for display.
    private static func preview(_ field: FfiField) -> String {
        if isSecret(field) { return FieldRow.mask }
        switch field.value {
        case .text(let value), .url(let value), .email(let value), .phone(let value):
            return value
        case .menu(let value):
            return CoreLabels.menuOption(value)
        case .barcode(let value, _):
            return value
        case .number(let value):
            return String(value)
        default:
            return FieldRow.mask
        }
    }
}
