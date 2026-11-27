import AppIntents
import Foundation

/// "Verrouiller Cleon": locks the session of the app process without opening the app. A process
/// that was not running holds no key: it is already locked.
struct LockVaultIntent: AppIntent {
    static let title: LocalizedStringResource = "Verrouiller Cleon"
    static let description = IntentDescription("intents.locksOnepassOnDevice")

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        IntentBridge.model?.lock()
        return .result(dialog: "Cleon est verrouillé")
    }
}
