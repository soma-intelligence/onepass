import Foundation
import Observation
import Security
import SwiftUI
import VaultKit
import os

/// An item of a vault, for navigation (the full item is loaded by the detail view only).
struct ItemRef: Hashable, Sendable {
    var vaultID: String
    var itemID: String
}

/// Owns the vault session, the sync coordinator, the site icon loader and the navigation state.
/// One per process: every window of the app shares it (spec 6.3).
@MainActor
@Observable
final class AppModel {
    let session: VaultSession
    @ObservationIgnored let coordinator: SyncCoordinator?
    @ObservationIgnored let iconLoader: SiteIconLoader

    /// Built with `ONEPASS_CLOUDKIT` (signed Release-CloudKit configuration, ruling R8).
    let cloudKitEnabled: Bool
    private(set) var syncStatus: SyncStatus = .disabled

    /// The onboarding stays on screen until "Ouvrir OnePass", even though the account creation
    /// already unlocked the session.
    var onboardingInProgress = false

    // Navigation (filled by the browse screens).
    var selection: ItemFilter = .all
    var selectedItem: ItemRef?
    var editing = false

    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    @ObservationIgnored private var started = false

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "app")

    init() {
        #if DEBUG
        DebugReset.applyIfRequested()
        #endif
        let databaseURL = VaultEnvironment.defaultDatabaseURL()
        var coordinator: SyncCoordinator?
        #if ONEPASS_CLOUDKIT
        let remote: (any RemoteRecordStore)? = CloudKitRemote(containerIdentifier: "iCloud.me.somalabs.onepass")
        cloudKitEnabled = true
        #else
        let remote: (any RemoteRecordStore)? = nil
        cloudKitEnabled = false
        #endif
        do {
            let store = try openSyncStore(dbPath: databaseURL.path)
            coordinator = SyncCoordinator(store: store, remote: remote)
        } catch {
            Self.log.error("sync store not opened, sync disabled")
        }
        self.coordinator = coordinator
        // `live` uses the same `defaultDatabaseURL()` as the sync store.
        let environment = VaultEnvironment.live(sync: coordinator ?? NoSync())
        session = VaultSession(environment: environment)

        let settings = environment.settings
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        iconLoader = SiteIconLoader(
            cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true),
            enabled: { settings.siteIconsEnabled })
        onboardingInProgress = session.state == .noAccount
    }

    var settings: VaultSettings { session.environment.settings }

    /// Starts listening to the sync layer and runs a first round. Called once by the root view.
    func start() {
        guard !started, let coordinator else { return }
        started = true
        tasks.append(Task { [weak self] in
            for await _ in await coordinator.remoteChanges() {
                await self?.session.reload()
            }
        })
        tasks.append(Task { [weak self] in
            for await status in await coordinator.statusUpdates() {
                self?.syncStatus = status
            }
        })
        tasks.append(Task { await coordinator.syncNow() })
    }

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            session.scenePhaseChanged(.active)
            if let coordinator { Task { await coordinator.syncNow() } }
        case .inactive:
            session.scenePhaseChanged(.inactive)
        case .background:
            session.scenePhaseChanged(.background)
        @unknown default:
            break
        }
    }

    /// Spec 7: the creation is refused when this iCloud already holds an account (ruling R13).
    /// No CloudKit: always false.
    func remoteHasAccount() async throws -> Bool {
        guard cloudKitEnabled, let coordinator else { return false }
        let found = try await coordinator.remoteHasAccount()
        await session.reload()
        return found
    }

    /// "Réessayer" on "Données refusées": a sync round, then the store is read again.
    func retryAfterFailure() async {
        await coordinator?.syncNow()
        await session.refresh()
    }

    /// Lock button and menu command.
    func lock() {
        selectedItem = nil
        editing = false
        session.lock()
    }

    /// Initials for the account badge ("Camille Durand" gives "CD"), empty without a name.
    var initials: String {
        let words = settings.displayName.split(whereSeparator: { $0.isWhitespace || $0 == "-" })
        return words.prefix(2).compactMap { $0.first.map { String($0).uppercased() } }.joined()
    }
}

#if DEBUG
/// `-OnePassUITestReset YES` (UI tests, Task 17): wipes the store, the settings and this app's
/// keychain items before anything is opened. Debug builds only.
enum DebugReset {
    static func applyIfRequested() {
        guard UserDefaults.standard.bool(forKey: "OnePassUITestReset") else { return }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.removeItem(at: base.appendingPathComponent("OnePass", isDirectory: true))
        if let domain = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: domain)
        }
        // Only the service VaultKit writes to, in both keychains (the legacy one is the Debug fallback).
        for legacy in [false, true] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "me.somalabs.onepass",
            ]
            if !legacy { query[kSecUseDataProtectionKeychain as String] = true }
            SecItemDelete(query as CFDictionary)
        }
    }
}
#endif
