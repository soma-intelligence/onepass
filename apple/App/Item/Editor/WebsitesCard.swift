import DesignKit
import SwiftUI
import VaultKit

/// The websites card: each website with its match rule and (−), a ☰ handle when there are two or
/// more, then "+ ajouter un autre site". The card itself moves with `handle`.
struct WebsitesCard: View {
    @Bindable var editor: ItemEditorModel
    let handle: ReorderHandle

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Space.xs) {
            handle.padding(.top, Theme.Space.xs)
            EditorCard {
                let rows = editor.urlKeys.map(UrlRowID.init)
                ReorderableStack(
                    items: rows,
                    accessibilityName: { row in Text(verbatim: url(row.key)?.url ?? "") },
                    onMove: { editor.moveURL(from: $0, to: $1) }
                ) { row, rowHandle in
                    VStack(spacing: 0) {
                        if row.key != rows.first?.key { CardDivider() }
                        UrlRow(editor: editor, key: row.key, handle: rows.count > 1 ? rowHandle : nil)
                    }
                }
                if !editor.urlKeys.isEmpty { CardDivider() }
                AddRowButton(
                    title: editor.urlKeys.isEmpty ? String(localized: "item.addWebsite") : String(localized: "item.addAnotherWebsite")
                ) {
                    editor.addURL()
                }
                .accessibilityIdentifier("editor.addURL")
            }
        }
    }

    private func url(_ key: UUID) -> FfiUrl? {
        editor.urlIndex(of: key).flatMap { editor.draft.item.urls[safe: $0] }
    }
}

private struct UrlRowID: Identifiable {
    let key: UUID
    var id: UUID { key }
}

/// One website: its address, the match rule menu (and "site principal" when there are several),
/// and its (−). Bindings look the row's index up on each access, so removing a row never writes
/// into a neighbor.
private struct UrlRow: View {
    @Bindable var editor: ItemEditorModel
    let key: UUID
    let handle: ReorderHandle?

    private var position: Int { editor.urlIndex(of: key) ?? 0 }
    private var url: FfiUrl? { editor.urlIndex(of: key).flatMap { editor.draft.item.urls[safe: $0] } }

    private func binding<T>(_ keyPath: WritableKeyPath<FfiUrl, T>, default fallback: T) -> Binding<T> {
        Binding(
            get: { url?[keyPath: keyPath] ?? fallback },
            set: { new in
                guard let i = editor.urlIndex(of: key), editor.draft.item.urls.indices.contains(i) else { return }
                editor.draft.item.urls[i][keyPath: keyPath] = new
            })
    }

    var body: some View {
        let many = editor.urlKeys.count > 1
        HStack(alignment: .center, spacing: Theme.Space.m) {
            if let handle { handle.padding(.leading, -Theme.Space.s) }
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                EditorLabel(many && (url?.primary ?? false) ? String(localized: "item.primaryWebsite") : String(localized: "app.website"))
                TextField("app.website", text: binding(\.url, default: ""), prompt: Text("https://"))
                    .labelsHidden()
                    .fieldInput(.url)
                    .accessibilityIdentifier("editor.url.\(position)")
            }
            Menu {
                Picker("item.matching", selection: binding(\.rule, default: .domain)) {
                    ForEach(UrlRules.all, id: \.self) { Text(UrlRules.label($0)).tag($0) }
                }
                .pickerStyle(.inline)
                if many {
                    Button("item.mainWebsite", systemImage: "star") {
                        if let i = editor.urlIndex(of: key) { editor.draft.setPrimaryURL(at: i) }
                    }
                }
            } label: {
                Image(systemName: "slider.horizontal.3").font(.title3).foregroundStyle(.secondary)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("item.matchingForAutofill")
            .accessibilityLabel(Text("item.matching"))
            RemoveRowButton {
                if let i = editor.urlIndex(of: key) { editor.removeURL(at: i) }
            }
            .accessibilityLabel(Text("item.removeWebsite"))
        }
        .editorRowPadding()
    }
}

/// Match rules of a website, and their names.
enum UrlRules {
    static let all: [FfiMatchRule] = [.domain, .exactHost, .exactUrl, .never]

    static func label(_ rule: FfiMatchRule) -> String {
        switch rule {
        case .domain: String(localized: "item.domain")
        case .exactHost: String(localized: "item.exactHost")
        case .exactUrl: String(localized: "item.exactUrl")
        case .never: String(localized: "item.never")
        }
    }
}
