import AppIntents
import GlanceKit
import SwiftUI
import WidgetKit

/// Control Center, Lock Screen and Action button (spec 8).

/// Opens the app's generator sheet (`onepass://generator`).
struct GeneratorControl: ControlWidget {
    static let kind = "me.somalabs.onepass.control.generator"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: OpenURLIntent(OnePassLink.generator.url)) {
                Label("Générer un mot de passe", systemImage: "key.horizontal")
            }
        }
        .displayName("Générer un mot de passe")
        .description("Ouvre le générateur de mots de passe de OnePass.")
    }
}

/// Opens the app's search (`onepass://search`).
struct SearchControl: ControlWidget {
    static let kind = "me.somalabs.onepass.control.search"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: OpenURLIntent(OnePassLink.search.url)) {
                Label("Rechercher dans OnePass", systemImage: "magnifyingglass")
            }
        }
        .displayName("Rechercher dans OnePass")
        .description("Ouvre la recherche de OnePass.")
    }
}

/// Locks the app without opening it (`LockControlIntent`).
struct LockControl: ControlWidget {
    static let kind = "me.somalabs.onepass.control.lock"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: LockControlIntent()) {
                Label("Verrouiller OnePass", systemImage: "lock.fill")
            }
        }
        .displayName("Verrouiller OnePass")
        .description("Verrouille OnePass sur cet appareil.")
    }
}
