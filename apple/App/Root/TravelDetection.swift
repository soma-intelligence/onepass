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
/// Planned trips and the time zone count too (spec 2026-11-14): `TravelPlanner` picks the card, and
/// a trip marked automatic turns Travel Mode on at the first unlock in its window.
@MainActor
@Observable
final class TravelDetection: NSObject, CLLocationManagerDelegate {
    static let enabledKey = "onepass.travel.suggest"
    nonisolated static let notificationID = "travel.suggest"
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "travel")

    /// The Réglages switch (places and time zone). Off by default. Planned trips work without it.
    var enabled: Bool {
        didSet {
            defaults.set(enabled, forKey: Self.enabledKey)
            if enabled {
                startBackgroundIfAllowed()
                check(travelling: nil, force: true)
            } else {
                stopBackground()
                placeSuggestion = .none
                refresh()
            }
        }
    }

    /// What the card shows (`TravelPlanner.decide`).
    private(set) var prompt: TravelPrompt = .none
    /// The card has something to ask (`.autoEnter` is AppModel's to act on, never a card).
    var showsCard: Bool {
        switch prompt {
        case .suggest, .welcomeBack: true
        case .none, .autoEnter: false
        }
    }
    /// Planned trips (Réglages > Voyages).
    private(set) var trips: [TravelTrip] = []
    /// Why the last automatic entry failed, shown under the trip's card.
    private(set) var lastAutoError: String?
    /// How many usual places are known (Réglages).
    private(set) var usualCount = 0

    /// The clock of every planner call (`-travel-now` in DEBUG).
    @ObservationIgnored var now: () -> Date = { .now }

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let store: TravelPlacesStore?
    @ObservationIgnored private let reminders: any TravelReminderCenter
    @ObservationIgnored private var places = TravelPlaces()
    /// The detector's last answer for a fix (`.none` before the first one).
    @ObservationIgnored private var placeSuggestion: TravelSuggestion = .none
    /// "Plus tard" on a starting trip: hidden until the next return to the foreground only, since
    /// its window lasts the whole trip.
    @ObservationIgnored private var hiddenTripID: UUID?
    @ObservationIgnored private var manager: CLLocationManager?
    /// Travel Mode state for the fix in flight (`nil`: the last one known).
    @ObservationIgnored private var pendingTravelling: Bool??
    @ObservationIgnored private var inBackground = false

    init(
        defaults: UserDefaults = .standard, keychain: any KeychainStore = SystemKeychain(accessGroup: nil),
        reminders: any TravelReminderCenter = SystemTravelReminderCenter()
    ) {
        self.defaults = defaults
        self.reminders = reminders
        enabled = defaults.bool(forKey: Self.enabledKey)
        store = (try? TravelPlacesStore.defaultURL()).map { TravelPlacesStore(url: $0, keychain: keychain) }
        super.init()
        places = store?.load() ?? TravelPlaces()
        usualCount = TravelDetector.usualCells(places).count
        trips = places.trips
        #if DEBUG
        let args = ProcessInfo.processInfo.arguments
        // `-travel-now <seconds since 1970>` replaces the clock of every planner call.
        if let i = args.firstIndex(of: "-travel-now"), i + 1 < args.count, let seconds = Double(args[i + 1]) {
            let fixed = Date(timeIntervalSince1970: seconds)
            now = { fixed }
        }
        // Screenshots and UI tests: `-travel-seed-home 48.8566,2.3522` learns that place at once.
        if let i = args.firstIndex(of: "-travel-seed-home"), i + 1 < args.count {
            let parts = args[i + 1].split(separator: ",").compactMap { Double($0) }
            if parts.count == 2 { seedHome(latitude: parts[0], longitude: parts[1]) }
        }
        // `-travel-seed-trip <hours>,<YES|NO>`: a week long trip leaving in `hours`, automatic or not.
        if let i = args.firstIndex(of: "-travel-seed-trip"), i + 1 < args.count {
            let parts = args[i + 1].split(separator: ",")
            if parts.count == 2, let hours = Double(parts[0]) {
                seedTrip(inHours: hours, autoEnter: parts[1] == "YES")
            }
        }
        #endif
        if enabled {
            restoreCard()
            startBackgroundIfAllowed()
        }
    }

    // MARK: - Checks

    /// On the foreground: `travelling` is the session's Travel Mode state (`nil` when locked: the
    /// last one known). The planner decides every time; the position request stays throttled to
    /// every 3 hours unless `force`.
    func check(travelling: Bool?, force: Bool = false) {
        hiddenTripID = nil
        guard inUse else { return }
        if let travelling { places.travelActive = travelling }
        if enabled {
            if !places.travelActive {
                // The time zone is observed like a cell: it works without the location permission.
                let date = now()
                TravelPlanner.observe(
                    &places, timeZone: .current, at: date, day: Int(date.timeIntervalSince1970 / 86_400))
            }
            restoreCard()
        }
        let allowed = locationAllowed
        decide(place: allowed ? placeSuggestion : nil, unlocked: false)
        save()
        guard allowed else { return }
        let seconds = now().timeIntervalSince1970
        if !force, let last = places.lastCheck, seconds - last < TravelDetector.throttle { return }
        pendingTravelling = .some(travelling)
        makeManager().requestLocation()
    }

    /// The vault was just unlocked: the id of the trip to enter Travel Mode for on its own, marked
    /// tried first (one automatic attempt per trip, whatever comes of it), else `nil`.
    func unlocked(travelling: Bool) -> UUID? {
        guard inUse else { return nil }
        places.travelActive = travelling
        decide(place: locationAllowed ? placeSuggestion : nil, unlocked: true)
        guard case .autoEnter(let id) = prompt else {
            save()
            return nil
        }
        TravelPlanner.markAutoTried(&places, id: id)
        lastAutoError = nil
        prompt = .none
        save()
        return id
    }

    /// The automatic entry did not happen: the trip's card asks instead, with the reason (`nil`
    /// when the owner cancelled the presence check: nothing to explain).
    func autoEnterFailed(id: UUID, message: String?) {
        guard !places.travelActive else { return }
        lastAutoError = message
        prompt = .suggest(.tripStarting(id), notify: false)
    }

    /// Travel Mode turned on or off in this app: the card follows at once.
    func travelChanged(active: Bool) {
        places.travelActive = active
        if active {
            TravelDetector.accepted(&places)
            TravelPlanner.entered(&places, now: now())
            placeSuggestion = .none
            lastAutoError = nil
            prompt = .none
            // Already in Travel Mode: the reminders have nothing left to say.
            for trip in places.trips { reminders.remove(ids: TravelTripReminders.ids(for: trip.id)) }
        } else {
            places.welcomeDismissed = false
            if prompt == .welcomeBack { prompt = .none }
            for trip in places.trips { scheduleReminders(trip) }
        }
        save()
    }

    // MARK: - Trips

    /// Create the trip or replace the one with the same id, and its reminders. Throws
    /// `TravelPlannerError`.
    func saveTrip(_ trip: TravelTrip) throws {
        try TravelPlanner.save(&places, trip: trip, now: now())
        save()
        reminders.remove(ids: TravelTripReminders.ids(for: trip.id))
        let upcoming = places.travelActive ? [] : TravelTripReminders.reminders(for: trip, now: now(), calendar: .current)
        let center = reminders
        Task {
            // Asked once, when the first trip is saved; never from anywhere else.
            await Self.requestNotificationsIfUndetermined()
            for reminder in upcoming { await center.schedule(reminder) }
        }
        refresh()
    }

    func deleteTrip(id: UUID) {
        TravelPlanner.delete(&places, id: id)
        reminders.remove(ids: TravelTripReminders.ids(for: id))
        if hiddenTripID == id { hiddenTripID = nil }
        save()
        refresh()
    }

    private func scheduleReminders(_ trip: TravelTrip) {
        reminders.remove(ids: TravelTripReminders.ids(for: trip.id))
        let upcoming = TravelTripReminders.reminders(for: trip, now: now(), calendar: .current)
        guard !upcoming.isEmpty else { return }
        let center = reminders
        Task { for reminder in upcoming { await center.schedule(reminder) } }
    }

    private static func requestNotificationsIfUndetermined() async {
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .notDetermined else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .sound])
    }

    // MARK: - Answers

    /// "Oui": the caller opens the Travel Mode confirmation.
    func answerYes() {
        // Until the next check reads the session: a cancelled confirmation asks again then.
        TravelDetector.accepted(&places)
        placeSuggestion = .none
        lastAutoError = nil
        prompt = .none
        save()
        clearNotification()
    }

    /// "Non": the place or the time zone becomes usual, or the trip is deleted.
    func answerNo() {
        guard case .suggest(let reason, _) = prompt else { return }
        TravelPlanner.answerNo(&places, reason: reason, timeZone: .current, now: now())
        switch reason {
        case .away: placeSuggestion = .none
        case .tripStarting(let id): reminders.remove(ids: TravelTripReminders.ids(for: id))
        default: break
        }
        lastAutoError = nil
        prompt = .none
        usualCount = TravelDetector.usualCells(places).count
        save()
        clearNotification()
    }

    /// "Plus tard": a place or a time zone stays quiet until home; a starting trip until the next
    /// return to the foreground.
    func answerNotNow() {
        guard case .suggest(let reason, _) = prompt else { return }
        switch reason {
        case .tripStarting(let id): hiddenTripID = id
        default:
            TravelDetector.snooze(&places)
            placeSuggestion = .none
        }
        lastAutoError = nil
        prompt = .none
        save()
        clearNotification()
    }

    func dismissWelcome() {
        places.welcomeDismissed = true
        TravelPlanner.dismissWelcome(&places, now: now())
        placeSuggestion = .none
        prompt = .none
        save()
    }

    /// Réglages > Oublier les lieux appris.
    func forgetPlaces() {
        try? store?.wipe()
        // The trips go with the file: so do their reminders.
        for trip in places.trips { reminders.remove(ids: TravelTripReminders.ids(for: trip.id)) }
        places = TravelPlaces()
        usualCount = 0
        trips = []
        placeSuggestion = .none
        hiddenTripID = nil
        lastAutoError = nil
        prompt = .none
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
        if let travelling = pendingTravelling ?? nil { places.travelActive = travelling }
        pendingTravelling = nil
        let cell = TravelDetector.cell(latitude: latitude, longitude: longitude)
        let seconds = now().timeIntervalSince1970
        places.lastCheck = seconds
        let result = TravelDetector.check(
            &places, cell: cell, day: Int(seconds / 86_400), travelling: places.travelActive)
        usualCount = TravelDetector.usualCells(places).count
        decide(place: result, unlocked: false)
        // Kept for the next decisions without a fix: the notification belongs to this one only.
        if case .suggest(let cell, _) = result {
            placeSuggestion = .suggest(cell: cell, notify: false)
        } else {
            placeSuggestion = result
        }
        save()
        if case .suggest(.away, true) = prompt, inBackground { postNotification() }
    }

    /// The planner's answer for this instant becomes the card. Trips count with or without the
    /// switch; places and the time zone only with it.
    private func decide(place: TravelSuggestion?, unlocked: Bool) {
        let signals = TravelSignals(
            now: now(), travelling: places.travelActive, unlocked: unlocked, place: enabled ? place : nil,
            timeZone: .current, atAirport: false)
        var next = TravelPlanner.decide(&places, signals)
        switch next {
        case .suggest(.tripStarting(let id), _) where id == hiddenTripID:
            next = .none
        case .suggest(.away, _), .suggest(.newTimeZone, _), .suggest(.atAirport, _), .suggest(.flightFound, _):
            if !enabled { next = .none }
        default:
            break
        }
        if case .suggest(.tripStarting(let id), _) = next, case .suggest(.tripStarting(id), _) = prompt {
            // The same trip's card: its error stays.
        } else {
            lastAutoError = nil
        }
        prompt = next
        trips = places.trips
    }

    /// The decision again after a change made in the app (trip saved, switch turned off).
    private func refresh() {
        decide(place: locationAllowed ? placeSuggestion : nil, unlocked: false)
        save()
    }

    /// The switch is on or a trip is planned. Otherwise nothing runs and nothing is written: the
    /// local file and its key exist only for an owner who uses travel detection.
    private var inUse: Bool { enabled || !places.trips.isEmpty }

    /// The switch is on and the app already has the location permission (never asked from here:
    /// Nearby asks, when the user opens it).
    private var locationAllowed: Bool {
        guard enabled else { return false }
        switch makeManager().authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways: return true
        default: return false
        }
    }

    /// The card of a trip still waiting for an answer, from the stored state (a relaunch from the
    /// notification).
    private func restoreCard() {
        if let cell = places.pendingCell, !places.travelActive, placeSuggestion == .none {
            placeSuggestion = .suggest(cell: cell, notify: false)
            if prompt == .none { prompt = .suggest(.away(cell: cell), notify: false) }
        }
    }

    private func save() {
        trips = places.trips
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
            content.title = String(localized: "travel.suggest.title")
            content.body = String(localized: "travel.suggest.notificationBody")
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
        let today = Int(now().timeIntervalSince1970 / 86_400)
        for day in (today - TravelDetector.usualDays)..<today { TravelDetector.observe(&places, cell: cell, day: day) }
        places.lastCheck = nil
        usualCount = TravelDetector.usualCells(places).count
        save()
    }

    /// UI tests: one trip leaving in `hours`, a week long. A fixed id, so a relaunch replaces it.
    func seedTrip(inHours hours: Double, autoEnter: Bool) {
        let id = UUID(uuidString: "7A3E1C2B-0000-4000-8000-00000000A11E")!
        let start = now().addingTimeInterval(hours * 3600)
        let trip = TravelTrip(id: id, start: start, end: start.addingTimeInterval(7 * 86_400), autoEnter: autoEnter)
        try? TravelPlanner.save(&places, trip: trip, now: now())
        save()
    }
    #endif
}
