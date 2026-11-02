import SwiftUI
import VaultKit

/// "Mot de passe proposé" (spec G5): the profile AutoFill uses for the strong password it proposes
/// on a signup field. "Fort" by default, "Lisible", or "Personnalisé" with a length (8 to 64),
/// digits and symbols. Stored in the App Group (`GeneratorProfileStore`), read by the extension at
/// each request; a device setting, never synced.
struct GeneratorProfileSection: View {
    private enum Kind: Hashable {
        case strong, readable, custom
    }

    private let store = GeneratorProfileStore.shared()
    @State private var profile: GeneratorProfile = .strong

    var body: some View {
        Section {
            Picker("Profil", selection: kind) {
                Text("settings.autofill.generator.strong").tag(Kind.strong)
                Text("settings.autofill.generator.readable").tag(Kind.readable)
                Text("settings.autofill.generator.custom").tag(Kind.custom)
            }
            .accessibilityIdentifier("autofill.generator.profile")
            if case .custom(let length, let digits, let symbols) = profile {
                VStack(alignment: .leading) {
                    LabeledContent("Longueur") {
                        Text("\(length)").monospacedDigit()
                    }
                    Slider(
                        value: Binding(
                            get: { Double(length) },
                            set: { save(.custom(length: Int($0.rounded()), digits: digits, symbols: symbols)) }),
                        in: Double(GeneratorProfile.customLengths.lowerBound)...Double(
                            GeneratorProfile.customLengths.upperBound),
                        step: 1
                    ) {
                        Text("Longueur")
                    }
                    .accessibilityIdentifier("autofill.generator.length")
                }
                Toggle("Chiffres", isOn: Binding(
                    get: { digits },
                    set: { save(.custom(length: length, digits: $0, symbols: symbols)) }))
                    .accessibilityIdentifier("autofill.generator.digits")
                Toggle("Symboles", isOn: Binding(
                    get: { symbols },
                    set: { save(.custom(length: length, digits: digits, symbols: $0)) }))
                    .accessibilityIdentifier("autofill.generator.symbols")
            }
        } header: {
            Text("settings.autofill.generator.header")
        } footer: {
            Text(footer)
        }
        .onAppear { profile = store.profile }
    }

    private var footer: LocalizedStringKey {
        switch profile {
        case .strong:
            "settings.autofill.generator.strong.footer"
        case .readable:
            "settings.autofill.generator.readable.footer"
        case .custom:
            "settings.autofill.generator.custom.footer"
        }
    }

    private var kind: Binding<Kind> {
        Binding(
            get: {
                switch profile {
                case .strong: .strong
                case .readable: .readable
                case .custom: .custom
                }
            },
            set: { kind in
                switch kind {
                case .strong: save(.strong)
                case .readable: save(.readable)
                case .custom:
                    if case .custom = profile { return }
                    save(GeneratorProfile.defaultCustom)
                }
            })
    }

    private func save(_ new: GeneratorProfile) {
        profile = new
        store.profile = new
    }
}
