import SwiftUI
import VaultKit

/// Websites of the item: repeatable, each with a match rule; one is the primary URL. Rows have a
/// stable identity (`ItemEditorModel.urlKeys`) and bindings look their index up on each access,
/// so removing a row never writes into a neighbor or reads past the end.
struct UrlListEditor: View {
    @Bindable var editor: ItemEditorModel

    static func ruleLabel(_ rule: FfiMatchRule) -> String {
        switch rule {
        case .domain: String(localized: "Domaine")
        case .exactHost: String(localized: "Hôte exact")
        case .exactUrl: String(localized: "URL exacte")
        case .never: String(localized: "Jamais")
        }
    }

    static let rules: [FfiMatchRule] = [.domain, .exactHost, .exactUrl, .never]

    private func url(_ key: UUID) -> FfiUrl? {
        editor.urlIndex(of: key).flatMap { editor.draft.item.urls[safe: $0] }
    }

    private func binding<T>(_ key: UUID, _ keyPath: WritableKeyPath<FfiUrl, T>, default fallback: T) -> Binding<T> {
        Binding(
            get: { url(key)?[keyPath: keyPath] ?? fallback },
            set: { new in
                guard let i = editor.urlIndex(of: key), editor.draft.item.urls.indices.contains(i) else { return }
                editor.draft.item.urls[i][keyPath: keyPath] = new
            })
    }

    var body: some View {
        let many = editor.urlKeys.count > 1
        ForEach(Array(editor.urlKeys.enumerated()), id: \.element) { position, key in
            if position > 0 { CardDivider() }
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    EditorLabel(many && (url(key)?.primary ?? false) ? String(localized: "site web principal") : String(localized: "site web"))
                    TextField("site web", text: binding(key, \.url, default: ""), prompt: Text("https://"))
                        .labelsHidden()
                        .fieldInput(.url)
                        .accessibilityIdentifier("editor.url.\(position)")
                }
                Menu {
                    Picker("Correspondance", selection: binding(key, \.rule, default: .domain)) {
                        ForEach(Self.rules, id: \.self) { Text(Self.ruleLabel($0)).tag($0) }
                    }
                    .pickerStyle(.inline)
                    if many {
                        Button("Site principal", systemImage: "star") {
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
                .help("Correspondance pour le remplissage")
                .accessibilityLabel(Text("Correspondance"))
                RemoveRowButton {
                    if let i = editor.urlIndex(of: key) { editor.removeURL(at: i) }
                }
                .accessibilityLabel(Text("Retirer ce site web"))
            }
            .editorRowPadding()
        }
        if !editor.urlKeys.isEmpty { CardDivider() }
        AddRowButton(
            title: editor.urlKeys.isEmpty ? String(localized: "ajouter un site web") : String(localized: "ajouter un autre site web")) {
            editor.addURL()
        }
        .accessibilityIdentifier("editor.addURL")
    }
}
