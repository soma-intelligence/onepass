import AppIntents
import Foundation

/// "Verrouiller OnePass": locks the session of the app process without opening the app. A process
/// that was not running holds no key: it is already locked.
struct LockVaultIntent: AppIntent {
    static let title: LocalizedStringResource = "Verrouiller OnePass"
    static let description = IntentDescription("Verrouille OnePass sur cet appareil.")

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        IntentBridge.model?.lock()
        return .result(dialog: "OnePass est verrouillé")
    }
}
