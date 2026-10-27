import AppIntents
import Foundation

/// "Ouvrir un élément": opens the app on the item's detail. Locked: the lock screen first, then
/// the detail (the route waits in `AppModel.pendingRoute`).
struct OpenItemIntent: AppIntent {
    static let title: LocalizedStringResource = "Ouvrir un élément"
    static let description = IntentDescription("Ouvre un élément dans OnePass.")
    static let supportedModes: IntentModes = .foreground

    @Parameter(title: "Élément")
    var item: ItemEntity

    static var parameterSummary: some ParameterSummary {
        Summary("Ouvrir \(\.$item)")
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        guard let ref = item.ref else { throw IntentError.itemNotFound }
        let model = try await IntentBridge.awaitModel()
        model.handle(.link(.item(vaultID: ref.vaultID, itemID: ref.itemID)))
        return .result()
    }
}
