import Foundation
import Observation
import VaultKit
import os

/// "Wi-Fi automatique" (spec docs/specs/2026-11-04-wifi-auto.md). Off by default, one switch in
/// Réglages > Général, no other screen. While the primary account is unlocked and the app is on
/// screen, WPA router items of its vaults are installed on the device, once per version of their
/// Wi-Fi fields. iPhone and iPad (NEHotspotConfiguration joins at once): only a router with a place
/// within 200 m of the device, the position asked "when in use" and only when such a router is
/// pending. Mac (CoreWLAN saves a profile, joins nothing): every router. "Rejoindre" in a router
/// item installs that one network by hand. On the Mac, a network the Mac joins that
/// the vault lacks is saved to it, with a quiet notification and "Annuler".
/// Logs carry counts only, never an SSID.
@MainActor
@Observable
final class WifiAutoController {
    static let enabledKey = "onepass.wifi.auto"
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "wifi")

    /// The Réglages switch. Off by default (unset reads as off): installing every network at launch made iOS try to join networks far out of range on each start.
    var enabled: Bool {
        didSet {
            defaults.set(enabled, forKey: Self.enabledKey)
            #if os(macOS)
            if !enabled { mac.stop() }
            #endif
            if enabled, let model { schedule(model) }
        }
    }

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let installer: (any WifiInstaller)?
    @ObservationIgnored private var active = false
    @ObservationIgnored private var running: Task<Void, Never>?
    @ObservationIgnored private var again = false
    @ObservationIgnored private weak var model: AppModel?
    #if os(macOS)
    @ObservationIgnored private(set) lazy var mac = MacWifiMonitor(controller: self)
    #endif

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        enabled = defaults.object(forKey: Self.enabledKey) as? Bool ?? false
        #if os(iOS)
        installer = HotspotInstaller()
        #elseif os(macOS)
        installer = CoreWLANInstaller()
        #else
        installer = nil
        #endif
    }

    /// UI tests, screenshots, Debug helpers and demo data never touch the device's Wi-Fi (the
    /// switch keeps its saved value; nothing runs).
    private static var suppressed: Bool {
        #if DEBUG
        TestIsolation.isActive || DemoData.requested
        #else
        false
        #endif
    }

    /// The ledger of this device, in the session's keychain (the isolated one under UI tests).
    func store(for session: VaultSession) -> any WifiLedgerStore {
        KeychainWifiLedgerStore(keychain: session.environment.keychain)
    }

    /// The app came on screen or left it (aggregate scene phase).
    func appActive(_ isActive: Bool, model: AppModel) {
        active = isActive
        if isActive { schedule(model) }
    }

    /// The vault changed (unlock, edit, sync): a quiet pass, coalesced.
    func schedule(_ model: AppModel) {
        self.model = model
        guard isRunnable else { return }
        if running != nil {
            again = true
            return
        }
        running = Task { [weak self] in
            // Let a burst of changes (unlock, then the first sync) settle.
            try? await Task.sleep(for: .milliseconds(800))
            await self?.pass()
        }
    }

    private func pass() async {
        defer {
            running = nil
            if again, let model {
                again = false
                schedule(model)
            }
        }
        guard isRunnable, let model else { return }
        let session = model.primarySession
        guard session.state == .unlocked else { return }
        guard let inputs = try? await session.wifiRouterInputs() else { return }
        if let installer {
            let ledger = store(for: session)
            let hidden = session.hiddenVaultIDs
            #if os(iOS)
            var position: WifiPosition?
            if WifiAutoSync.needsPosition(inputs: inputs, hiddenVaults: hidden, store: ledger),
                let fix = try? await LocationAccess.shared.currentLocation(accuracy: WifiProximity.maxAccuracy)
            {
                position = WifiPosition(
                    point: GeoPoint(latitude: fix.coordinate.latitude, longitude: fix.coordinate.longitude),
                    accuracy: fix.horizontalAccuracy)
            }
            let proximity = WifiProximityRule.near(position)
            #else
            let proximity = WifiProximityRule.everywhere
            #endif
            guard isRunnable else { return }
            let report = await WifiAutoSync.run(
                inputs: inputs, hiddenVaults: hidden, store: ledger, installer: installer, proximity: proximity)
            if report.attempted > 0 {
                Self.log.info(
                    "wifi pass: \(report.attempted) pending, \(report.installed) installed, \(report.declined) declined")
            }
        }
        #if os(macOS)
        guard isRunnable else { return }
        mac.start()
        await mac.captureCurrentNetwork(vaultSSIDs: WifiCapture.vaultSSIDs(inputs))
        #endif
    }

    /// "Rejoindre" in a router item: installs that one network now, whatever the switch and the
    /// distance. Nil when there is no installer here or the item cannot be joined.
    func join(itemID: String, session: VaultSession) async -> WifiInstallOutcome? {
        guard let installer, session.state == .unlocked,
            let inputs = try? await session.wifiRouterInputs()
        else { return nil }
        return await WifiAutoSync.join(itemID: itemID, inputs: inputs, store: store(for: session), installer: installer)
    }

    /// Whether this device has a "Rejoindre" button (iPhone, iPad).
    static var canJoinByHand: Bool {
        #if os(iOS)
        true
        #else
        false
        #endif
    }

    /// The primary session, for the Mac's capture (unlocked only).
    var unlockedSession: VaultSession? {
        guard let session = model?.primarySession, session.state == .unlocked else { return nil }
        return session
    }

    var isRunnable: Bool { enabled && onScreen && !Self.suppressed }

    /// iPhone: the system question needs the app in the foreground. Mac: the app runs while its
    /// window is open, whichever app is in front (the Mac joins networks from the menu bar).
    private var onScreen: Bool {
        #if os(macOS)
        true
        #else
        active
        #endif
    }

    var modelForMonitor: AppModel? { model }
}
