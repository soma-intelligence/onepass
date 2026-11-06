import Foundation
import Observation
import OSLog
import Sparkle

/// The Mac app's updater: Sparkle's standard controller, started only when the Info.plist carries a
/// safe update configuration (`UpdateConfiguration`). It checks once at launch and then every 24 hours
/// while automatic checks are on, and on demand ("Rechercher les mises à jour…"). Sparkle verifies the
/// feed's and the archive's EdDSA signatures and that the new app is Developer ID signed by the same
/// team; `UpdateGuard` refuses anything not strictly newer. Installing always asks the user.
@MainActor
@Observable
public final class AppUpdater {
    /// Checks happen once at launch and then on this interval (Info.plist `SUScheduledCheckInterval`
    /// says the same, so Sparkle's own scheduler agrees before this object sets it).
    public static let checkInterval: TimeInterval = 24 * 60 * 60

    /// Whether "Rechercher les mises à jour…" can run now (no check or install in progress).
    public private(set) var canCheckForUpdates = false

    /// The Settings switch. Stored by Sparkle in the app's defaults (`SUEnableAutomaticChecks`).
    public var automaticallyChecksForUpdates: Bool {
        didSet {
            guard controller.updater.automaticallyChecksForUpdates != automaticallyChecksForUpdates else { return }
            controller.updater.automaticallyChecksForUpdates = automaticallyChecksForUpdates
        }
    }

    public private(set) var lastUpdateCheckDate: Date?

    @ObservationIgnored private let controller: SPUStandardUpdaterController
    @ObservationIgnored private let guardDelegate: UpdateGuard
    @ObservationIgnored private var observations: [NSKeyValueObservation] = []

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "updates")

    /// `nil` when the bundle has no update key (development builds) or an unsafe configuration.
    public init?(bundle: Bundle = .main) {
        let info = bundle.infoDictionary ?? [:]
        switch UpdateConfiguration.status(info: info) {
        case .enabled:
            break
        case .disabled:
            return nil
        case .invalid(let problem):
            Self.log.error("updates off: unsafe update configuration (\(problem.rawValue, privacy: .public))")
            return nil
        }
        guardDelegate = UpdateGuard(installedVersion: info["CFBundleVersion"] as? String ?? "")
        controller = SPUStandardUpdaterController(
            startingUpdater: false, updaterDelegate: guardDelegate, userDriverDelegate: nil)
        let updater = controller.updater
        // Nothing beyond a plain GET: no system profile, no extra parameter or header.
        updater.sendsSystemProfile = false
        updater.updateCheckInterval = Self.checkInterval
        automaticallyChecksForUpdates = updater.automaticallyChecksForUpdates
        do {
            try updater.start()
        } catch {
            Self.log.error("updates off: Sparkle did not start (\(error.localizedDescription, privacy: .public))")
            return nil
        }
        canCheckForUpdates = updater.canCheckForUpdates
        lastUpdateCheckDate = updater.lastUpdateCheckDate
        observations = [
            updater.observe(\.canCheckForUpdates, options: [.new]) { [weak self] updater, _ in
                MainActor.assumeIsolated { self?.canCheckForUpdates = updater.canCheckForUpdates }
            },
            updater.observe(\.lastUpdateCheckDate, options: [.new]) { [weak self] updater, _ in
                MainActor.assumeIsolated { self?.lastUpdateCheckDate = updater.lastUpdateCheckDate }
            },
        ]
        // At every launch, then on Sparkle's 24 h schedule (Sparkle: call it right after starting).
        if updater.automaticallyChecksForUpdates {
            updater.checkForUpdatesInBackground()
        }
    }

    /// "Rechercher les mises à jour…": Sparkle's window shows the result, even "up to date".
    public func checkForUpdates() {
        controller.checkForUpdates(nil)
    }
}

/// Sparkle delegate: OnePass's own downgrade guard on the item Sparkle chose.
@MainActor
final class UpdateGuard: NSObject, SPUUpdaterDelegate {
    let installedVersion: String

    init(installedVersion: String) {
        self.installedVersion = installedVersion
    }

    enum Refusal: Error, Equatable {
        case notNewer(installed: String, offered: String)
    }

    nonisolated static func check(installed: String, offered: String) throws(Refusal) {
        guard UpdateVersionPolicy.isUpgrade(from: installed, to: offered) else {
            throw .notNewer(installed: installed, offered: offered)
        }
    }

    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        do {
            try Self.check(installed: installedVersion, offered: item.versionString)
        } catch {
            throw NSError(domain: SUSparkleErrorDomain, code: Int(SUError.noUpdateError.rawValue), userInfo: [
                NSLocalizedDescriptionKey: String(
                    localized: "updates.refused.notNewer",
                    defaultValue: "This update is not newer than the installed version: OnePass refused it.",
                    bundle: .module),
            ])
        }
    }
}
