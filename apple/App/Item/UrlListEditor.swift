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
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Button {
                        if let i = editor.urlIndex(of: key) { editor.removeURL(at: i) }
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(Text("Retirer ce site web"))
                    TextField("site web", text: binding(key, \.url, default: ""), prompt: Text("https://"))
                        .fieldInput(.url)
                        .accessibilityIdentifier("editor.url.\(position)")
                }
                HStack {
                    Picker("Correspondance", selection: binding(key, \.rule, default: .domain)) {
                        ForEach(Self.rules, id: \.self) { Text(Self.ruleLabel($0)).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .font(.footnote)
                    Spacer()
                    if many {
                        let primary = url(key)?.primary ?? false
                        Button {
                            if let i = editor.urlIndex(of: key) { editor.draft.setPrimaryURL(at: i) }
                        } label: {
                            Label("Principale", systemImage: primary ? "star.fill" : "star")
                        }
                        .buttonStyle(.borderless)
                        .font(.footnote)
                        .accessibilityValue(primary ? Text("oui") : Text("non"))
                    }
                }
            }
        }
        Button("+ ajouter un site web") { editor.addURL() }
            .accessibilityIdentifier("editor.addURL")
    }
}
