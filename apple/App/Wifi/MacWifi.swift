#if os(macOS)
import CoreLocation
import CoreWLAN
import Foundation
import SecurityFoundation
import UserNotifications
import VaultKit
import os

/// Mac: networks join the preferred list of the Wi-Fi interface through CoreWLAN, password in the
/// System keychain, the way System Settings stores them. Both need an administrator: one
/// authorization per batch (one prompt), and nothing at all when every network is already known
/// to the Mac (which is the common case: iCloud Keychain already brings the iPhone's networks).
/// A list read without the Location permission has no SSIDs: it is never committed
/// (`WifiProfileMerge.canCommit`), so the user's networks can never be erased.
struct CoreWLANInstaller: WifiInstaller {
    func install(_ networks: [WifiNetwork]) async -> [(WifiNetwork, WifiInstallOutcome)] {
        await Task.detached(priority: .utility) { Self.installNow(networks) }.value
    }

    private nonisolated static func installNow(_ networks: [WifiNetwork]) -> [(WifiNetwork, WifiInstallOutcome)] {
        // No interface or no Location yet: nothing recorded, tried again at the next pass.
        guard let interface = CWWiFiClient.shared().interface(), let configuration = interface.configuration() else {
            return []
        }
        let profiles = configuration.networkProfiles.array.compactMap { $0 as? CWNetworkProfile }
        guard WifiProfileMerge.canCommit(existing: profiles.map(\.ssidData)) else { return [] }
        let toAdd = WifiProfileMerge.toAdd(existing: profiles.compactMap(\.ssidData), networks: networks)
        let addedIDs = Set(toAdd.map(\.itemID))
        // Already a preferred network of this Mac: the Mac's own entry is kept as is.
        var out = networks.filter { !addedIDs.contains($0.itemID) }.map { ($0, WifiInstallOutcome.installed) }
        guard !toAdd.isEmpty else { return out }

        // One administrator prompt for the whole batch. Cancelled: not asked again until a network
        // changes in the vault.
        guard let authorization = SFAuthorization.authorization() as? SFAuthorization else {
            return out + toAdd.map { ($0, .failed) }
        }
        do {
            try authorization.obtain(
                withRight: "system.preferences", flags: [.interactionAllowed, .extendRights, .preAuthorize])
        } catch {
            return out + toAdd.map { ($0, .declined) }
        }

        // The profiles first, the passwords after: a refused commit leaves nothing behind (not
        // even a password in the System keychain); a refused password leaves a preferred network
        // the Mac asks the password of when it meets it, which is visible and harmless.
        let mutable = CWMutableConfiguration(configuration: configuration)
        let list = NSMutableOrderedSet(orderedSet: mutable.networkProfiles)
        for network in toAdd {
            let profile = CWMutableNetworkProfile()
            profile.ssidData = Data(network.ssid.utf8)
            profile.security = security(network.security)
            list.add(profile)
        }
        mutable.networkProfiles = list
        do {
            try interface.commitConfiguration(mutable, authorization: authorization)
        } catch {
            // Refused by the system (sandbox, policy): not retried until the item changes, so the
            // administrator prompt does not come back at every activation.
            return out + toAdd.map { ($0, .rejected) }
        }
        for network in toAdd {
            let saved = CWKeychainSetWiFiPassword(.system, Data(network.ssid.utf8), network.password) == errSecSuccess
            out.append((network, saved ? .installed : .rejected))
        }
        return out
    }

    private nonisolated static func security(_ s: WifiSecurity) -> CWSecurity {
        switch s {
        // Transition: joins the WPA3 router and its WPA2 side, as the core's "wpa2/wpa3".
        case .wpa3Personal: .wpa3Transition
        case .wpa2Personal: .wpa2Personal
        }
    }
}

/// Device to vault on the Mac. Watches the SSID of the Wi-Fi interface (which macOS gives only to
/// an app with the Location permission, asked the first time the feature runs) and, when the Mac
/// is on a WPA network the vault lacks, reads its password from the System keychain and saves a
/// router item to the first unshared vault of the primary account. macOS shows its own keychain prompt for
/// that password, once per new network; a network is never considered twice.
@MainActor
final class MacWifiMonitor: NSObject, CWEventDelegate, CLLocationManagerDelegate, UNUserNotificationCenterDelegate {
    nonisolated static let category = "wifi.saved"
    nonisolated static let undoAction = "wifi.undo"
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "wifi")

    private weak var controller: WifiAutoController?
    private var location: CLLocationManager?
    private var monitoring = false
    private var capturing = false

    init(controller: WifiAutoController) {
        self.controller = controller
    }

    func start() {
        if location == nil {
            let manager = CLLocationManager()
            manager.delegate = self
            location = manager
            // The first run of the feature: the SSID needs the Location permission on macOS.
            if manager.authorizationStatus == .notDetermined { manager.requestWhenInUseAuthorization() }
        }
        guard !monitoring else { return }
        let client = CWWiFiClient.shared()
        client.delegate = self
        do {
            try client.startMonitoringEvent(with: .ssidDidChange)
            monitoring = true
        } catch {
            Self.log.error("wifi: SSID events unavailable")
        }
        installNotificationCategory()
    }

    func stop() {
        guard monitoring else { return }
        try? CWWiFiClient.shared().stopMonitoringEvent(with: .ssidDidChange)
        monitoring = false
    }

    nonisolated func ssidDidChangeForWiFiInterface(withName interfaceName: String) {
        Task { @MainActor in self.controller?.schedulePassFromMonitor() }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in self.controller?.schedulePassFromMonitor() }
    }

    /// The network the Mac is on, saved to the vault if it qualifies.
    func captureCurrentNetwork(vaultSSIDs: Set<String>) async {
        guard !capturing, let controller, let session = controller.unlockedSession else { return }
        guard let interface = CWWiFiClient.shared().interface(), let ssid = interface.ssid() else { return }
        guard let security = Self.personal(interface.security()) else { return }
        let store = controller.store(for: session)
        guard var ledger = store.load() else { return }
        guard WifiCapture.isCandidate(ssid: ssid, vaultSSIDs: vaultSSIDs, ledger: ledger) else { return }
        capturing = true
        defer { capturing = false }

        // Considered once, whatever happens next (a refused keychain prompt is not shown again).
        ledger.markCaptured(ssid)
        store.save(ledger)
        let password = await Task.detached(priority: .utility) { () -> String? in
            var value: NSString?
            let status = CWKeychainFindWiFiPassword(.system, Data(ssid.utf8), &value)
            return status == errSecSuccess ? value as String? : nil
        }.value
        let joined = password.map { WifiJoined(ssid: ssid, password: $0, security: security) }
        guard WifiCapture.shouldCapture(joined, vaultSSIDs: vaultSSIDs, ledger: WifiLedger()), let joined else { return }
        // Never a shared vault: a home network's password is not shared by surprise.
        guard session.state == .unlocked, let vault = session.vaults.first(where: { $0.shared == nil })?.id else {
            return
        }
        do {
            var item = try session.newItem(type: .router, vaultID: vault)
            item.title = ssid
            for (id, value) in joined.fields {
                for s in item.sections.indices {
                    if let f = item.sections[s].fields.firstIndex(where: { $0.id == id }) {
                        item.sections[s].fields[f].value = value
                    }
                }
            }
            let saved = try await session.save(ItemDraft(item: item).preparedForSave())
            notifySaved(ssid: ssid, itemID: saved.id, vaultID: saved.vaultId)
        } catch {
            Self.log.error("wifi: network not saved")
        }
    }

    private static func personal(_ s: CWSecurity) -> WifiSecurity? {
        switch s {
        case .wpa3Personal, .wpa3Transition: .wpa3Personal
        case .wpa2Personal, .wpaPersonal, .wpaPersonalMixed, .personal: .wpa2Personal
        default: nil  // open, OWE, WEP, enterprise, unknown
        }
    }

    // MARK: - Notification

    private func installNotificationCategory() {
        let center = UNUserNotificationCenter.current()
        Task {
            let undo = UNNotificationAction(identifier: Self.undoAction, title: "Annuler", options: [])
            let category = UNNotificationCategory(identifier: Self.category, actions: [undo], intentIdentifiers: [])
            var all = await center.notificationCategories().filter { $0.identifier != Self.category }
            all.insert(category)
            center.setNotificationCategories(all)
        }
        // The Mac app has no other delegate; other notifications keep the default behavior.
        if center.delegate == nil { center.delegate = self }
    }

    /// Quiet (provisional) delivery: no permission prompt, straight to the Notification Center.
    private func notifySaved(ssid: String, itemID: String, vaultID: String) {
        let center = UNUserNotificationCenter.current()
        Task {
            _ = try? await center.requestAuthorization(options: [.alert, .provisional])
            let content = UNMutableNotificationContent()
            content.body = "Wi-Fi « \(ssid) » enregistré dans OnePass"
            content.categoryIdentifier = Self.category
            content.userInfo = ["itemID": itemID, "vaultID": vaultID]
            content.interruptionLevel = .passive
            let request = UNNotificationRequest(identifier: "wifi.saved.\(itemID)", content: content, trigger: nil)
            try? await center.add(request)
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        notification.request.content.categoryIdentifier == Self.category ? [.banner, .list] : []
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        let content = response.notification.request.content
        guard content.categoryIdentifier == Self.category, response.actionIdentifier == Self.undoAction,
            let itemID = content.userInfo["itemID"] as? String, let vaultID = content.userInfo["vaultID"] as? String
        else { return }
        await MainActor.run { self.undo(itemID: itemID, vaultID: vaultID) }
    }

    /// "Annuler": the item goes to Supprimés récemment; the network stays considered, so it is not
    /// saved again.
    private func undo(itemID: String, vaultID: String) {
        guard let session = controller?.unlockedSession else { return }
        Task { try? await session.trash(itemID: itemID, vaultID: vaultID) }
    }
}

extension WifiAutoController {
    /// An SSID or Location change seen by the Mac monitor.
    func schedulePassFromMonitor() {
        guard isRunnable, let model = modelForMonitor else { return }
        schedule(model)
    }
}
#endif
