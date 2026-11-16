import DesignKit
import SwiftUI
import VaultKit

/// "+ ajouter plus" in a card of its own: a popover with a search, the template fields folded away
/// (one at a time, or all), the custom field kinds, and "Nouvelle section".
struct AddMoreCard: View {
    @Bindable var editor: ItemEditorModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var open = false

    var body: some View {
        EditorCard {
            Button {
                open.toggle()
            } label: {
                HStack {
                    Label("item.addMore", systemImage: "plus")
                        .foregroundStyle(Theme.accent)
                    Spacer()
                    Image(systemName: "chevron.down").foregroundStyle(.secondary)
                }
                .font(.body.weight(.medium))
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .editorRowPadding()
            .accessibilityIdentifier("editor.addField")
            .popover(isPresented: $open, arrowEdge: .bottom) {
                AddFieldPopover(
                    hidden: hiddenRows.map { AddFieldPopover.Hidden(key: $0.key, label: $0.label, symbol: FieldSymbols.symbol(for: $0.field)) },
                    customKinds: FieldSymbols.customKinds,
                    showAll: { close { editor.showAllFields = true } },
                    reveal: { key in close { editor.pin(key) } },
                    addCustom: { kind in close { editor.addCustomField(kind: kind) } },
                    addSection: { close { editor.addSection() } })
                .presentationCompactAdaptation(.popover)
            }
        }
    }

    private func close(_ change: () -> Void) {
        open = false
        withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { change() }
    }

    /// The folded template fields, in template order.
    private var hiddenRows: [(key: UUID, label: String, field: FfiField)] {
        let item = editor.draft.item
        return item.sections.filter { !editor.draft.isFreeSection($0.id) }.flatMap { section in
            let shown = Set(editor.shownRows(section).map(\.key))
            return zip(editor.keys(sectionID: section.id), section.fields).compactMap { key, field in
                shown.contains(key) || field.kind == .passkey || field.kind == .file
                    ? nil : (key, field.displayLabel(itemType: item.itemType), field)
            }
        }
    }
}

/// Symbols of the "ajouter plus" popover and the custom field kinds it offers.
enum FieldSymbols {
    static let customKinds: [AddFieldPopover.Kind] = [
        (FfiFieldType.text, String(localized: "item.text")), (.concealed, String(localized: "item.hidden")),
        (.password, String(localized: "term.password")), (.date, String(localized: "Date")),
        (.url, String(localized: "item.url")), (.email, String(localized: "item.email")),
        (.phone, String(localized: "app.phone")), (.location, String(localized: "item.place")),
    ].map { AddFieldPopover.Kind(kind: $0.0, label: $0.1, symbol: symbol(for: $0.0)) }

    /// By the field's id where the kind says too little (PIN, codes de secours, question), else by
    /// its kind.
    static func symbol(for field: FfiField) -> String {
        switch field.id {
        case "totp": return "timer"
        case "pin": return "number"
        case "backup_codes": return "list.number"
        case "security_question": return "questionmark.bubble"
        case "security_answer": return "key"
        case "recovery_phone": return "phone"
        default: return symbol(for: field.kind)
        }
    }

    static func symbol(for kind: FfiFieldType) -> String {
        switch kind {
        case .text: "textformat"
        case .concealed: "eye.slash"
        case .password: "key"
        case .url: "link"
        case .email: "envelope"
        case .phone: "phone"
        case .date: "calendar"
        case .monthYear: "calendar.badge.clock"
        case .number: "number"
        case .money: "eurosign"
        case .address: "house"
        case .menu: "list.bullet"
        case .otp: "timer"
        case .passkey: "person.badge.key"
        case .sshKey: "terminal"
        case .file: "paperclip"
        case .location: "mappin.and.ellipse"
        case .mnemonic: "text.word.spacing"
        case .barcode: "barcode"
        case .itemLink: "link.badge.plus"
        }
    }
}

/// The custom field kinds as a grid of small tiles ("+ ajouter un champ" of a free section).
struct CustomKindGrid: View {
    let add: (FfiFieldType) -> Void
    private static let columns = Array(repeating: GridItem(.flexible(), spacing: Theme.Space.s), count: 4)

    var body: some View {
        LazyVGrid(columns: Self.columns, spacing: Theme.Space.s) {
            ForEach(FieldSymbols.customKinds) { kind in
                AddFieldTile(label: kind.label, symbol: kind.symbol) { add(kind.kind) }
                    .accessibilityIdentifier("editor.addField.custom.\(String(describing: kind.kind))")
            }
        }
    }
}

/// The "ajouter plus" popover: a search over everything it offers, the folded template fields as
/// icon rows (with "Tout afficher"), then the custom field kinds as a grid of small tiles.
struct AddFieldPopover: View {
    struct Hidden: Identifiable {
        let key: UUID
        let label: String
        let symbol: String
        var id: UUID { key }
    }

    struct Kind: Identifiable {
        let kind: FfiFieldType
        let label: String
        let symbol: String
        var id: String { label }
    }

    let hidden: [Hidden]
    let customKinds: [Kind]
    let showAll: () -> Void
    let reveal: (UUID) -> Void
    let addCustom: (FfiFieldType) -> Void
    let addSection: () -> Void
    @State private var query = ""
    @FocusState private var searchFocused: Bool

    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }

    private var shownHidden: [Hidden] {
        trimmed.isEmpty ? hidden : hidden.filter { $0.label.localizedStandardContains(trimmed) }
    }

    private var shownKinds: [Kind] {
        trimmed.isEmpty ? customKinds : customKinds.filter { $0.label.localizedStandardContains(trimmed) }
    }

    private static let columns = Array(repeating: GridItem(.flexible(), spacing: Theme.Space.s), count: 4)

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(spacing: Theme.Space.s) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("item.searchFields", text: $query)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .accessibilityIdentifier("editor.addField.search")
            }
            .padding(.horizontal, Theme.Space.m)
            .padding(.vertical, Theme.Space.s)
            .background(.fill.quaternary, in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous).strokeBorder(.white.opacity(0.07)) }

            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.m) {
                    if !shownHidden.isEmpty {
                        HStack {
                            heading("Champs du modèle")
                            Spacer()
                            if hidden.count > 1, trimmed.isEmpty {
                                Button("item.showAll", action: showAll)
                                    .buttonStyle(.plain)
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(Theme.accent)
                                    .accessibilityIdentifier("editor.moreFields")
                            }
                        }
                        VStack(spacing: Theme.Space.xxs) {
                            ForEach(shownHidden) { row in
                                AddFieldRow(label: row.label, symbol: row.symbol) { reveal(row.key) }
                            }
                        }
                    }
                    if !shownKinds.isEmpty {
                        if !shownHidden.isEmpty { Divider() }
                        heading("Champ personnalisé")
                        LazyVGrid(columns: Self.columns, spacing: Theme.Space.s) {
                            ForEach(shownKinds) { kind in
                                AddFieldTile(label: kind.label, symbol: kind.symbol) { addCustom(kind.kind) }
                                    .accessibilityIdentifier("editor.addField.custom.\(String(describing: kind.kind))")
                            }
                        }
                    }
                    if trimmed.isEmpty {
                        Divider()
                        AddFieldRow(label: String(localized: "editor.section.new"), symbol: "rectangle.stack.badge.plus", action: addSection)
                            .accessibilityIdentifier("editor.addSection")
                    }
                    if shownHidden.isEmpty, shownKinds.isEmpty {
                        Text("item.noMatchingField")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, Theme.Space.m)
                    }
                }
            }
            .frame(maxHeight: 420)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Theme.Space.m)
        .frame(width: 340)
        .onAppear { searchFocused = true }
    }

    private func heading(_ text: LocalizedStringKey) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
    }
}

struct AddFieldRow: View {
    let label: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Theme.Space.m) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(Theme.accent))
                    .frame(width: 24, height: 24)
                    .background(hovering ? AnyShapeStyle(.white.opacity(0.15)) : AnyShapeStyle(Theme.accent.opacity(0.14)),
                        in: .rect(cornerRadius: Theme.Radius.chip, style: .continuous))
                Text(label).foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                Spacer(minLength: 0)
                Image(systemName: "plus")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.white)
                    .opacity(hovering ? 1 : 0)
            }
            .padding(.horizontal, Theme.Space.s)
            .padding(.vertical, Theme.Space.xs)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.85)) : AnyShapeStyle(.clear), in: .rect(cornerRadius: Theme.Radius.chip, style: .continuous))
            .contentShape(.rect(cornerRadius: Theme.Radius.chip, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

struct AddFieldTile: View {
    let label: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: Theme.Space.xs) {
                Image(systemName: symbol)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(Theme.accent))
                    .frame(height: 20)
                Text(label)
                    .font(.caption)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, Theme.Space.s)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.85)) : AnyShapeStyle(.fill.quaternary),
                in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous).strokeBorder(.white.opacity(0.07)) }
            .contentShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

