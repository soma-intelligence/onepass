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
        AutoFillScaffold(title: Text("views.chooseItem"), model: model) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    SessionErrorText(session: session)
                        .padding(.horizontal, 6)
                    AutoFillLabel(query.isEmpty ? "views.allItems" : "views.results")
                    if shown.isEmpty {
                        Text(query.isEmpty ? "views.noItems" : "views.noResults")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .autofillCard()
                    } else {
                        AutoFillCardRows {
                            ForEach(shown, id: \.id) { item in
                                Button {
                                    choose(item)
                                } label: {
                                    AutoFillRow(
                                        type: item.itemType, title: item.title,
                                        detail: item.listSubtitle.isEmpty ? ItemCategory.of(item.itemType).singular : item.listSubtitle,
                                        url: item.primaryUrl
                                    ) {
                                        Image(systemName: "chevron.forward")
                                            .font(.footnote.weight(.semibold))
                                            .foregroundStyle(.tertiary)
                                            .accessibilityHidden(true)
                                    }
                                }
                                .buttonStyle(AutoFillRowStyle())
                                .accessibilityIdentifier(autofillIdentifier("item", item.title))
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 24)
            }
            .scrollDismissesKeyboard(.immediately)
            .searchable(text: $query, prompt: Text("views.searchOnepass"))
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
        AutoFillScaffold(title: Text("views.chooseField"), model: model, back: { Task { await model.showTextItems() } }) {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    AutoFillHeader(
                        type: item.itemType, iconTitle: item.title,
                        url: (item.urls.first(where: \.primary) ?? item.urls.first)?.url,
                        title: Text(verbatim: item.title), subtitle: ItemCategory.of(item.itemType).singular)
                        .padding(.bottom, 14)
                    SessionErrorText(session: session)
                        .padding(.horizontal, 6)
                    AutoFillLabel("views.fieldToInsert")
                    let fields = model.insertableFields(of: item)
                    if fields.isEmpty {
                        Text("views.itemHasNoFields")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .autofillCard()
                    } else {
                        AutoFillCardRows {
                            ForEach(fields, id: \.id) { field in
                                Button {
                                    insert(field)
                                } label: {
                                    HStack(spacing: 8) {
                                        AutoFillFieldRow(label: Text(verbatim: Self.labelCase(field.displayLabel))) {
                                            Text(verbatim: Self.preview(field))
                                                .foregroundStyle(.primary)
                                                .lineLimit(1)
                                        }
                                        .accessibilityValue(Self.isSecret(field) ? Text("views.hidden") : Text(verbatim: Self.preview(field)))
                                        Image(systemName: "text.insert")
                                            .font(.system(size: 16, weight: .medium))
                                            .foregroundStyle(Theme.readableAccent)
                                            .padding(.trailing, 16)
                                            .accessibilityHidden(true)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(AutoFillRowStyle())
                                .accessibilityIdentifier(autofillIdentifier("field", field.label))
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
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

    /// As the app's labels: lowercase in French, a capital first elsewhere (`LabelCase`).
    private static func labelCase(_ label: String) -> String { LabelCase.detail(label) }

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
