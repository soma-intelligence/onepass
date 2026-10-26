import DesignKit
import SwiftUI
import VaultKit

/// Password generator (core `generatePassword`): characters (8 to 100, default 20; digits, symbols,
/// without ambiguous characters), passphrase (3 to 10 words, default 5; separator; French or
/// English) or PIN (4 to 12 digits). Entropy from `passwordEntropyBits` on the strength meter.
struct GeneratorSheet: View {
    enum Mode: String, CaseIterable, Identifiable {
        case characters, words, pin
        var id: Self { self }
        var label: String {
            switch self {
            case .characters: String(localized: "Caractères")
            case .words: String(localized: "Phrase de passe")
            case .pin: String(localized: "PIN")
            }
        }
    }

    /// `.use` fills a field of an item ("Utiliser"); `.copy` is the standalone generator opened by
    /// the "Générer un mot de passe" Control, whose value only goes to the clipboard ("Copier").
    enum Purpose {
        case use, copy
    }

    let onUse: (String) -> Void
    /// Also called on "Utiliser", with the recipe bits the sheet's meter showed.
    var onUseWithBits: (@MainActor (String, Double) -> Void)?
    var purpose: Purpose = .use
    @Environment(\.dismiss) private var dismiss

    @State private var mode: Mode = .characters
    @State private var length = 20.0
    @State private var digits = true
    @State private var symbols = true
    @State private var avoidAmbiguous = false
    @State private var wordCount = 5.0
    @State private var separator = "-"
    @State private var french = true
    @State private var pinLength = 6.0
    @State private var generated = ""
    @State private var failed = false

    static let separators: [(String, String)] = [
        ("-", String(localized: "Tiret")), (".", String(localized: "Point")),
        ("_", String(localized: "Tiret bas")), (" ", String(localized: "Espace")),
        (",", String(localized: "Virgule")),
    ]

    var recipe: FfiPasswordRecipe {
        switch mode {
        case .characters:
            .characters(length: UInt32(length), digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous)
        case .words:
            .words(count: UInt32(wordCount), separator: separator, french: french, capitalize: false)
        case .pin:
            .pin(length: UInt32(pinLength))
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(generated.isEmpty ? " " : generated)
                        .font(.title3.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("generator.value")
                    StrengthMeter(bits: passwordEntropyBits(recipe: recipe))
                    Button("Régénérer", systemImage: "arrow.clockwise") { regenerate() }
                        .accessibilityIdentifier("generator.regenerate")
                    if failed {
                        Text(VaultError.invalidInputMessage("recipe")).foregroundStyle(.red).font(.footnote)
                    }
                }
                Section {
                    Picker("Type", selection: $mode) {
                        ForEach(Mode.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("generator.mode")
                    switch mode {
                    case .characters:
                        stepperSlider("Longueur", value: $length, range: 8...100)
                        Toggle("Chiffres", isOn: $digits)
                        Toggle("Symboles", isOn: $symbols)
                        Toggle("Sans caractères ambigus", isOn: $avoidAmbiguous)
                    case .words:
                        stepperSlider("Mots", value: $wordCount, range: 3...10)
                        Picker("Séparateur", selection: $separator) {
                            ForEach(Self.separators, id: \.0) { Text($0.1).tag($0.0) }
                        }
                        Picker("Langue", selection: $french) {
                            Text("Français").tag(true)
                            Text("Anglais").tag(false)
                        }
                    case .pin:
                        stepperSlider("Chiffres", value: $pinLength, range: 4...12)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Générateur")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(purpose == .copy ? "Fermer" : "Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(purpose == .copy ? "Copier" : "Utiliser") {
                        onUse(generated)
                        onUseWithBits?(generated, passwordEntropyBits(recipe: recipe))
                        dismiss()
                    }
                    .disabled(generated.isEmpty)
                    .accessibilityIdentifier("generator.use")
                }
            }
            .onChange(of: recipe, initial: true) { regenerate() }
        }
        .presentationDetents([.large])
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 460)
        #endif
    }

    private func stepperSlider(_ label: LocalizedStringKey, value: Binding<Double>, range: ClosedRange<Double>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(label)
                Spacer()
                Text("\(Int(value.wrappedValue))").monospacedDigit().foregroundStyle(.secondary)
            }
            Slider(value: value, in: range, step: 1)
                .accessibilityLabel(Text(label))
                .accessibilityValue(Text("\(Int(value.wrappedValue))"))
        }
    }

    private func regenerate() {
        do {
            generated = try generatePassword(recipe: recipe)
            failed = false
        } catch {
            generated = ""
            failed = true
        }
    }
}
