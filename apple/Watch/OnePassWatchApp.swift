import CompanionLink
import SwiftUI

@main
struct OnePassWatchApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var host = WatchModelHost()

    var body: some Scene {
        WindowGroup {
            WatchRootView(model: host.model)
                .onChange(of: scenePhase, initial: true) { _, phase in
                    host.scenePhaseChanged(phase)
                }
        }
    }
}

/// Picks the model once per process: the real `WatchVault`, or in Debug the in-memory demo
/// (`-OnePassWatchDemo YES`, fictional data, no key).
@MainActor
final class WatchModelHost {
    let model: any WatchEntriesModel
    private let vault: WatchVault?
    private var started = false

    init() {
        #if DEBUG
            if UserDefaults.standard.bool(forKey: "OnePassWatchDemo") {
                model = DemoWatchModel()
                vault = nil
                return
            }
        #endif
        let vault = WatchVault(
            transport: WatchConnectivityTransport(),
            keys: SystemWatchKeyStore(),
            payloadURL: Self.payloadURL
        )
        self.vault = vault
        model = vault
    }

    /// Foreground opens the vault, anything else releases it (spec 5.2).
    func scenePhaseChanged(_ phase: ScenePhase) {
        guard let vault else { return }
        if phase == .active {
            // `start()` also retries after a passcode was set on the watch.
            if !started || vault.state == .needsPasscode {
                started = true
                vault.start()
            } else {
                vault.activate()
            }
        } else {
            vault.deactivate()
        }
    }

    private static var payloadURL: URL {
        URL.applicationSupportDirectory
            .appending(path: "OnePass", directoryHint: .isDirectory)
            .appending(path: "companion.sealed", directoryHint: .notDirectory)
    }
}
