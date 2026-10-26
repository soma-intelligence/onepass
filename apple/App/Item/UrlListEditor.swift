import SwiftUI
import VaultKit

/// Websites of the item: repeatable, each with a match rule; one is the primary URL.
struct UrlListEditor: View {
    @Binding var draft: ItemDraft

    static func ruleLabel(_ rule: FfiMatchRule) -> String {
        switch rule {
        case .domain: String(localized: "Domaine")
        case .exactHost: String(localized: "Hôte exact")
        case .exactUrl: String(localized: "URL exacte")
        case .never: String(localized: "Jamais")
        }
    }

    static let rules: [FfiMatchRule] = [.domain, .exactHost, .exactUrl, .never]

    var body: some View {
        ForEach(draft.item.urls.indices, id: \.self) { i in
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Button {
                        draft.removeURL(at: i)
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(Text("Retirer ce site web"))
                    TextField("site web", text: $draft.item.urls[i].url, prompt: Text("https://"))
                        .fieldInput(.url)
                        .accessibilityIdentifier("editor.url.\(i)")
                }
                HStack {
                    Picker("Correspondance", selection: $draft.item.urls[i].rule) {
                        ForEach(Self.rules, id: \.self) { Text(Self.ruleLabel($0)).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .font(.footnote)
                    Spacer()
                    if draft.item.urls.count > 1 {
                        Button {
                            draft.setPrimaryURL(at: i)
                        } label: {
                            Label(
                                "Principale",
                                systemImage: draft.item.urls[i].primary ? "star.fill" : "star")
                        }
                        .buttonStyle(.borderless)
                        .font(.footnote)
                        .accessibilityValue(draft.item.urls[i].primary ? Text("oui") : Text("non"))
                    }
                }
            }
        }
        Button("+ ajouter un site web") { draft.addURL() }
            .accessibilityIdentifier("editor.addURL")
    }
}
