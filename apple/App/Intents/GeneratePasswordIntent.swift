import AppIntents
import Foundation
import VaultKit

/// "Générer un mot de passe": random characters (the generator sheet's character recipe), returned
/// to the shortcut without opening or unlocking the app. Nothing is stored: it is not a vault
/// secret (ruling W14).
struct GeneratePasswordIntent: AppIntent {
    static let title: LocalizedStringResource = "Générer un mot de passe"
    static let description = IntentDescription("Génère un mot de passe aléatoire, sans l'enregistrer.")

    @Parameter(title: "Longueur", default: 20, inclusiveRange: (8, 64))
    var length: Int

    @Parameter(title: "Symboles", default: true)
    var symbols: Bool

    static var parameterSummary: some ParameterSummary {
        Summary("Générer un mot de passe de \(\.$length) caractères") {
            \.$symbols
        }
    }

    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let recipe = FfiPasswordRecipe.characters(
            length: UInt32(min(max(length, 8), 64)), digits: true, symbols: symbols, avoidAmbiguous: false)
        guard let password = try? generatePassword(recipe: recipe) else { throw IntentError.generationFailed }
        return .result(value: password)
    }
}
