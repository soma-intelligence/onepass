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
                Label("controls.generatePassword", systemImage: "key.horizontal")
            }
        }
        .displayName("controls.generatePassword")
        .description("controls.opensOnepassPasswordGenerator")
    }
}

/// Opens the app's search (`onepass://search`).
struct SearchControl: ControlWidget {
    static let kind = "me.somalabs.onepass.control.search"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: OpenURLIntent(OnePassLink.search.url)) {
                Label("controls.searchOnepass", systemImage: "magnifyingglass")
            }
        }
        .displayName("controls.searchOnepass")
        .description("controls.opensOnepassSearch")
    }
}

/// Locks the app without opening it (`LockControlIntent`).
struct LockControl: ControlWidget {
    static let kind = "me.somalabs.onepass.control.lock"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind) {
            ControlWidgetButton(action: LockControlIntent()) {
                Label("widgets.lockOnepass", systemImage: "lock.fill")
            }
        }
        .displayName("widgets.lockOnepass")
        .description("widgets.locksOnepassOnDevice")
    }
}
