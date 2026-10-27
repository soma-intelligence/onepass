import AppIntents
import Foundation

/// "Copier le code à usage unique": opens the app, which asks a fresh authentication and copies
/// the code with the OnePass clipboard (90 s, local only). The code never goes back to the
/// shortcut, so it cannot be chained (ruling W13).
struct CopyTotpIntent: AppIntent {
    static let title: LocalizedStringResource = "Copier le code à usage unique"
    static let description = IntentDescription(
        "Copie le code à usage unique d'un élément après authentification. Le code n'est jamais transmis au raccourci.")
    static let supportedModes: IntentModes = .foreground

    @Parameter(title: "Élément")
    var item: ItemEntity

    static var parameterSummary: some ParameterSummary {
        Summary("Copier le code de \(\.$item)")
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        guard let ref = item.ref else { throw IntentError.itemNotFound }
        let model = try await IntentBridge.awaitModel()
        model.handle(.copyTotp(ref))
        return .result()
    }
}
