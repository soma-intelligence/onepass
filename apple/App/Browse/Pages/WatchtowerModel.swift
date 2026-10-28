import Foundation
import Observation
import UserNotifications
import VaultKit
import os

/// Runs Watchtower off the main actor and keeps the last report until the data it was made from
/// changes (summaries, hidden vaults, the breach setting). Emptied on lock.
///
/// With "Vérifier les fuites" on: an offline pass first (shown at once), then the HIBP ranges of
/// the prefixes that pass asked for, the 2FA and passkey catalogs and the HIBP breach catalog, then
/// the final pass. Off: nothing leaves the device, and the catalogs are used only if a copy is
/// already on disk.
///
/// With "Me prévenir" on, each finished report goes through `WatchtowerAlerts`: new compromised
/// passwords, breached sites, exposed sign-in accounts and expirations become one local notification
/// that names no item.
@MainActor
@Observable
final class WatchtowerModel {
    enum Phase: Equatable {
        case idle
        case analyzing
        /// Ranges downloaded so far over the prefixes to look up.
        case checkingBreaches(done: Int, total: Int)
        case ready
        case failed(String)
    }

    private(set) var report: FfiWatchtowerReport?
    private(set) var phase: Phase = .idle
    /// The shown report had the HIBP breach catalog (`breached_site` ran).
    private(set) var breachCatalogUsed = false

    /// What the shown report was computed from.
    private struct Key: Equatable {
        var revision: Int
        var hidden: Set<String>
        var breaches: Bool
    }

    @ObservationIgnored private var computedFor: Key?
    @ObservationIgnored private var running: Task<Void, Never>?
    @ObservationIgnored private let fetcher = WatchtowerFetcher()
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "watchtower")

    private static let breachKey = "onepass.watchtower.checkBreaches"
    private static let notifyKey = "onepass.watchtower.notify"
    private static let memoryKey = "onepass.watchtower.alertMemory"

    /// "Me prévenir", off by default. Turning it on asks the system once; the next report only fills
    /// the memory, so nothing already on the page is notified. Off: the memory is dropped.
    var notify: Bool {
        get {
            access(keyPath: \.notify)
            return AppModel.browseDefaults.bool(forKey: Self.notifyKey)
        }
        set {
            withMutation(keyPath: \.notify) {
                AppModel.browseDefaults.set(newValue, forKey: Self.notifyKey)
                AppModel.browseDefaults.removeObject(forKey: Self.memoryKey)
            }
            if newValue {
                Task {
                    let granted = (try? await UNUserNotificationCenter.current()
                        .requestAuthorization(options: [.alert, .sound])) ?? false
                    if !granted { self.notify = false }
                }
            }
        }
    }

    /// "Vérifier les fuites", on by default. Stored with the browse defaults (the demo has its own).
    var checkBreaches: Bool {
        get {
            access(keyPath: \.checkBreaches)
            return AppModel.browseDefaults.object(forKey: Self.breachKey) as? Bool ?? true
        }
        set {
            withMutation(keyPath: \.checkBreaches) {
                AppModel.browseDefaults.set(newValue, forKey: Self.breachKey)
            }
        }
    }

    var isRunning: Bool {
        switch phase {
        case .analyzing, .checkingBreaches: true
        default: false
        }
    }

    /// Starts an analysis unless the report on screen already matches the data.
    func refreshIfNeeded(_ session: VaultSession) {
        guard session.state == .unlocked else { return }
        let key = Key(revision: session.summariesRevision, hidden: session.hiddenVaultIDs, breaches: checkBreaches)
        if key == computedFor, report != nil || isRunning { return }
        run(session, key: key)
    }

    /// "Analyser à nouveau": the catalogs on disk stay, the ranges in memory too (an hour at most).
    func refresh(_ session: VaultSession) {
        guard session.state == .unlocked else { return }
        let key = Key(revision: session.summariesRevision, hidden: session.hiddenVaultIDs, breaches: checkBreaches)
        run(session, key: key)
    }

    /// Posts the new alertable findings of a finished report (one notification, counts only).
    private func alert(_ report: FfiWatchtowerReport) {
        guard notify else { return }
        let remembered = (AppModel.browseDefaults.array(forKey: Self.memoryKey) as? [String]).map(Set.init)
        let (alerts, memory) = WatchtowerAlerts.diff(report, remembered: remembered)
        AppModel.browseDefaults.set(memory.sorted(), forKey: Self.memoryKey)
        guard !alerts.isEmpty else { return }
        let content = UNMutableNotificationContent()
        content.title = String(localized: "Watchtower")
        content.body = WatchtowerAlerts.body(for: alerts)
        content.sound = .default
        content.threadIdentifier = "watchtower"
        let request = UNNotificationRequest(identifier: "watchtower.\(UUID().uuidString)", content: content, trigger: nil)
        let log = Self.log
        UNUserNotificationCenter.current().add(request) { error in
            if error != nil { log.error("watchtower notification not posted") }
        }
    }

    func clear() {
        running?.cancel()
        running = nil
        report = nil
        breachCatalogUsed = false
        computedFor = nil
        phase = .idle
        let fetcher = fetcher
        Task { await fetcher.clear() }
    }

    private func run(_ session: VaultSession, key: Key) {
        running?.cancel()
        computedFor = key
        phase = .analyzing
        let fetcher = fetcher
        running = Task { [weak self] in
            do {
                // Offline pass: local checks, the catalogs already on disk, the prefixes to fetch.
                let cached = await fetcher.siteDirectories(allowNetwork: false)
                let cachedBreaches = await fetcher.breachCatalog(allowNetwork: false)
                let first = try await session.watchtowerReport(
                    ranges: key.breaches ? [] : nil, twofaDirectory: cached.twofa, passkeysDirectory: cached.passkeys,
                    breachCatalog: cachedBreaches)
                guard let self, !Task.isCancelled else { return }
                self.report = first
                self.breachCatalogUsed = cachedBreaches != nil
                guard key.breaches else {
                    self.phase = .ready
                    self.alert(first)
                    return
                }
                self.phase = .checkingBreaches(done: 0, total: first.missingPrefixes.count)
                async let sites = fetcher.siteDirectories(allowNetwork: true)
                async let breaches = fetcher.breachCatalog(allowNetwork: true)
                let ranges = await fetcher.ranges(for: first.missingPrefixes) { done, total in
                    Task { @MainActor [weak self] in
                        guard let self, case .checkingBreaches = self.phase, !Task.isCancelled else { return }
                        self.phase = .checkingBreaches(done: done, total: total)
                    }
                }
                let directories = await sites
                let catalog = await breaches
                guard !Task.isCancelled else { return }
                let second = try await session.watchtowerReport(
                    ranges: ranges, twofaDirectory: directories.twofa, passkeysDirectory: directories.passkeys,
                    breachCatalog: catalog)
                guard !Task.isCancelled else { return }
                self.report = second
                self.breachCatalogUsed = catalog != nil
                self.phase = .ready
                self.alert(second)
            } catch {
                guard let self, !Task.isCancelled else { return }
                Self.log.error("watchtower report failed")
                self.computedFor = nil
                self.phase = .failed(VaultError(error).localizedMessage)
            }
        }
    }
}
