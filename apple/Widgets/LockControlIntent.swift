import AppIntents
import Foundation
import GlanceKit

/// "Verrouiller OnePass", run in the widget extension: records the request in the App Group and
/// posts the Darwin notification. A running app locks at once; otherwise it locks on its next
/// return to the foreground if the request is newer than its last unlock. An app that is not
/// running holds no key.
struct LockControlIntent: AppIntent {
    static let title: LocalizedStringResource = "Verrouiller OnePass"
    static let description = IntentDescription("Verrouille OnePass sur cet appareil.")

    func perform() async throws -> some IntentResult {
        if let defaults = UserDefaults(suiteName: AppGroup.identifier) {
            LockSignal(defaults: defaults).request()
        }
        return .result()
    }
}
