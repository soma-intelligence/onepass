import CoreLocation
import Foundation
import Observation
import UserNotifications
import VaultKit
import os

/// "Are you travelling?" (spec 2026-11-02 travel detection, section 6). Off until the user turns it
/// on in Réglages > Travel Mode. Uses the location permission the app already has for Nearby and
/// never asks for one. On every return to the foreground (at most every 3 hours) one reduced
/// accuracy fix; with "Always" already granted, significant location changes too (no continuous
/// GPS). The fix becomes a geohash cell on the device and is compared with the usual cells learned
/// there (`TravelDetector`); nothing leaves the device, not even to Apple's geocoder.
@MainActor
@Observable
final class TravelDetection: NSObject, CLLocationManagerDelegate {
    static let enabledKey = "onepass.travel.suggest"
    nonisolated static let notificationID = "travel.suggest"
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "travel")

    /// The Réglages switch. Off by default.
    var enabled: Bool {
        didSet {
            defaults.set(enabled, forKey: Self.enabledKey)
            if enabled {
                startBackgroundIfAllowed()
                check(travelling: nil, force: true)
            } else {
                stopBackground()
                suggestion = .none
            }
        }
    }

    /// What the card shows.
    private(set) var suggestion: TravelSuggestion = .none
    /// How many usual places are known (Réglages).
    private(set) var usualCount = 0

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let store: TravelPlacesStore?
    @ObservationIgnored private var places = TravelPlaces()
    @ObservationIgnored private var manager: CLLocationManager?
    /// Travel Mode state for the fix in flight (`nil`: the last one known).
    @ObservationIgnored private var pendingTravelling: Bool??
    @ObservationIgnored private var inBackground = false

    init(defaults: UserDefaults = .standard, keychain: any KeychainStore = SystemKeychain(accessGroup: nil)) {
        self.defaults = defaults
        enabled = defaults.bool(forKey: Self.enabledKey)
        store = (try? TravelPlacesStore.defaultURL()).map { TravelPlacesStore(url: $0, keychain: keychain) }
        super.init()
        places = store?.load() ?? TravelPlaces()
        usualCount = TravelDetector.usualCells(places).count
        #if DEBUG
        // Screenshots and UI tests: `-travel-seed-home 48.8566,2.3522` learns that place at once.
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "-travel-seed-home"), i + 1 < args.count {
            let parts = args[i + 1].split(separator: ",").compactMap { Double($0) }
            if parts.count == 2 { seedHome(latitude: parts[0], longitude: parts[1]) }
        }
        #endif
        if enabled {
            restoreCard()
            startBackgroundIfAllowed()
        }
    }

    // MARK: - Checks

    /// On the foreground: `travelling` is the session's Travel Mode state (`nil` when locked: the
    /// last one known). Throttled unless `force`.
    func check(travelling: Bool?, force: Bool = false) {
        guard enabled else { return }
        if let travelling { places.travelActive = travelling }
        restoreCard()
        let now = Date.now.timeIntervalSince1970
        if !force, let last = places.lastCheck, now - last < TravelDetector.throttle { return }
        let manager = makeManager()
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: break
        // Never asked from here: Nearby asks, when the user opens it.
        default: return
        }
        pendingTravelling = .some(travelling)
        manager.requestLocation()
    }

    /// Travel Mode turned on or off in this app: the card follows at once.
    func travelChanged(active: Bool) {
        places.travelActive = active
        if active {
            TravelDetector.accepted(&places)
            suggestion = .none
        } else {
            places.welcomeDismissed = false
            if suggestion == .welcomeBack { suggestion = .none }
        }
        save()
    }

    // MARK: - Answers

    /// "Oui": the caller opens the Travel Mode confirmation.
    func answerYes() {
        // Until the next check reads the session: a cancelled confirmation asks again then.
        TravelDetector.accepted(&places)
        suggestion = .none
        save()
        clearNotification()
    }

    /// "Non": this place becomes a usual one.
    func answerNo() {
        if case .suggest(let cell, _) = suggestion { TravelDetector.teach(&places, cell: cell) }
        suggestion = .none
        usualCount = TravelDetector.usualCells(places).count
        save()
        clearNotification()
    }

    /// "Plus tard": quiet until home.
    func answerNotNow() {
        TravelDetector.snooze(&places)
        suggestion = .none
        save()
        clearNotification()
    }

    func dismissWelcome() {
        places.welcomeDismissed = true
        suggestion = .none
        save()
    }

    /// Réglages > Oublier les lieux appris.
    func forgetPlaces() {
        try? store?.wipe()
        places = TravelPlaces()
        usualCount = 0
        suggestion = .none
    }

    // MARK: - Location

    private func makeManager() -> CLLocationManager {
        if let manager { return manager }
        let manager = CLLocationManager()
        // A city is plenty: cells are about 150 km wide.
        manager.desiredAccuracy = kCLLocationAccuracyReduced
        manager.delegate = self
        self.manager = manager
        return manager
    }

    private func startBackgroundIfAllowed() {
        #if os(iOS)
        let manager = makeManager()
        guard manager.authorizationStatus == .authorizedAlways,
            CLLocationManager.significantLocationChangeMonitoringAvailable()
        else { return }
        manager.startMonitoringSignificantLocationChanges()
        #endif
    }

    private func stopBackground() {
        #if os(iOS)
        manager?.stopMonitoringSignificantLocationChanges()
        #endif
    }

    func appMovedToBackground(_ background: Bool) {
        inBackground = background
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let last = locations.last else { return }
        let coordinate = last.coordinate
        MainActor.assumeIsolated { process(latitude: coordinate.latitude, longitude: coordinate.longitude) }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: any Error) {
        MainActor.assumeIsolated { Self.log.notice("travel check: no fix") }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        MainActor.assumeIsolated {
            if enabled { startBackgroundIfAllowed() }
        }
    }

    /// One fix: the verdict, the card, the one notification of a trip seen from the background.
    func process(latitude: Double, longitude: Double) {
        guard enabled else { return }
        let travelling = (pendingTravelling ?? nil) ?? places.travelActive
        pendingTravelling = nil
        let cell = TravelDetector.cell(latitude: latitude, longitude: longitude)
        let day = Int(Date.now.timeIntervalSince1970 / 86_400)
        places.lastCheck = Date.now.timeIntervalSince1970
        let result = TravelDetector.check(&places, cell: cell, day: day, travelling: travelling)
        usualCount = TravelDetector.usualCells(places).count
        suggestion = result
        save()
        if case .suggest(_, let notify) = result, notify, inBackground { postNotification() }
    }

    /// The card of a trip still waiting for an answer, from the stored state (a relaunch from the
    /// notification).
    private func restoreCard() {
        if let cell = places.pendingCell, !places.travelActive, suggestion == .none {
            suggestion = .suggest(cell: cell, notify: false)
        }
    }

    private func save() {
        do { try store?.save(places) } catch { Self.log.error("travel places not saved") }
    }

    // MARK: - Notification

    /// Passive: no sound, no lighting the screen, and Focus or the system's reduced interruptions
    /// decide whether it shows at all. Only when the user already allows notifications.
    private func postNotification() {
        let center = UNUserNotificationCenter.current()
        Task {
            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional
            else { return }
            let content = UNMutableNotificationContent()
            content.title = String(localized: "Tu voyages ?")
            content.body = String(localized: "Active le Travel Mode avant la frontière.")
            content.interruptionLevel = .passive
            content.relevanceScore = 0.3
            let request = UNNotificationRequest(identifier: Self.notificationID, content: content, trigger: nil)
            try? await center.add(request)
        }
    }

    private func clearNotification() {
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [Self.notificationID])
        center.removePendingNotificationRequests(withIdentifiers: [Self.notificationID])
    }

    #if DEBUG
    /// UI tests and screenshots: learn `cell` as usual right away (`-travel-seed-home lat,lon`).
    func seedHome(latitude: Double, longitude: Double) {
        let cell = TravelDetector.cell(latitude: latitude, longitude: longitude)
        let today = Int(Date.now.timeIntervalSince1970 / 86_400)
        for day in (today - TravelDetector.usualDays)..<today { TravelDetector.observe(&places, cell: cell, day: day) }
        places.lastCheck = nil
        usualCount = TravelDetector.usualCells(places).count
        save()
    }
    #endif
}
