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
    @ObservationIgnored private let remote: (any RemoteRecordStore)?

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
    /// One automatic biometric attempt per app activation, whatever the number of windows.
    @ObservationIgnored private var autoBiometricsPending = true

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "app")

    init() {
        #if DEBUG
        DebugReset.applyIfRequested()
        #endif
        Self.sweepEmergencyKits()
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
        self.remote = remote
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
        guard !started else { return }
        started = true
        #if DEBUG
        seedAccountIfRequested()
        #endif
        guard let coordinator else { return }
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

    /// The app's aggregate scene phase (forwarded from `OnePassApp`), not a single window's.
    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            autoBiometricsPending = true
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

    #if DEBUG
    /// Screenshots: `-OnePassDebugSeedAccount YES` creates a fictional account (Camille Durand) when
    /// none exists, then locks, so the lock screen can be captured. Debug builds only.
    private func seedAccountIfRequested() {
        guard UserDefaults.standard.bool(forKey: "OnePassDebugSeedAccount"), session.state == .noAccount
        else { return }
        Task {
            _ = try? await session.createAccount(
                password: "ruisseau-tapis-orage-comete", displayName: "Camille Durand", mode: .personal)
            onboardingInProgress = false
            session.lock()
        }
    }
    #endif

    /// True once per app activation: the lock screen of the first window that asks may try
    /// biometric unlock automatically.
    func takeAutomaticBiometricAttempt() -> Bool {
        defer { autoBiometricsPending = false }
        return autoBiometricsPending
    }

    /// CloudKit build: whether an iCloud account is signed in. Unsigned build: true (local only).
    func iCloudAccountAvailable() async -> Bool {
        guard cloudKitEnabled, let remote else { return true }
        return await remote.accountAvailable()
    }

    /// Emergency Kit PDFs left in the temporary folder by a previous run (killed during the step).
    private static func sweepEmergencyKits() {
        let tmp = FileManager.default.temporaryDirectory
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? []
        for name in entries where name.hasPrefix("kit-") {
            try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name, isDirectory: true))
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

    /// "Réessayer" on "Données refusées": a complete fetch from scratch, then the store is read again.
    func retryAfterFailure() async {
        await coordinator?.refetchFromScratch()
        await session.reload()
        if case .failed = session.state { await session.refresh() }
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
