import Foundation

/// Why the app proposes Travel Mode.
public enum TravelReason: Equatable, Sendable {
    /// Far from every usual cell.
    case away(cell: String)
    /// A planned trip is about to start.
    case tripStarting(UUID)
    /// A flight found in the calendar (produced by phase B, never by `decide`).
    case flightFound(eventID: String, start: Date, end: Date)
    case atAirport
    /// The device clock moved to a time zone the owner is not used to.
    case newTimeZone
}

/// What the app should do after a check.
public enum TravelPrompt: Equatable, Sendable {
    case none
    /// Ask "Are you travelling?" (`notify`: post the one notification of this trip too).
    case suggest(TravelReason, notify: Bool)
    /// Enter Travel Mode on its own (the trip allowed it, the vault is unlocked).
    case autoEnter(UUID)
    /// Travel Mode is on and the trip is over.
    case welcomeBack
}

/// Everything one check knows. `place` is `TravelDetector.check`'s answer, `nil` without a position.
public struct TravelSignals: Sendable {
    public var now: Date
    public var travelling: Bool
    public var unlocked: Bool
    public var place: TravelSuggestion?
    public var timeZone: TimeZone
    public var atAirport: Bool

    public init(
        now: Date, travelling: Bool, unlocked: Bool, place: TravelSuggestion?, timeZone: TimeZone,
        atAirport: Bool
    ) {
        self.now = now
        self.travelling = travelling
        self.unlocked = unlocked
        self.place = place
        self.timeZone = timeZone
        self.atAirport = atAirport
    }
}

public enum TravelPlannerError: Error, Equatable, Sendable {
    case endBeforeStart
    case tooManyTrips
}

/// Pure rules that pick the prompt from the trips, the time zone and the place (spec 2026-11-14,
/// section 4). No location, no clock, no I/O: the caller passes everything in.
public enum TravelPlanner {
    public static let maxTrips = 16
    /// A trip counts as started this long before its departure.
    public static let leadTime: TimeInterval = 3 * 3600
    /// A trip stays this long after its end (for the "back home?" card).
    public static let keepAfterEnd: TimeInterval = 7 * 86_400
    /// Days an offset must be seen on before it is usual.
    public static let usualOffsetDays = 3

    private static let secondsPerDay: TimeInterval = 86_400

    // MARK: Decision

    public static func decide(_ places: inout TravelPlaces, _ s: TravelSignals) -> TravelPrompt {
        prune(&places, now: s.now)

        if s.travelling {
            let finished = places.trips.contains {
                $0.end <= s.now && $0.id != places.welcomeTripDismissed
            }
            return finished || s.place == .welcomeBack ? .welcomeBack : .none
        }

        if let trip = activeTrip(places, now: s.now) {
            if trip.autoEnter, !trip.autoTried, s.unlocked { return .autoEnter(trip.id) }
            return .suggest(.tripStarting(trip.id), notify: false)
        }

        if s.atAirport { return .suggest(.atAirport, notify: false) }

        if case .suggest(let cell, let notify)? = s.place {
            return .suggest(.away(cell: cell), notify: notify)
        }

        let usual = isUsual(places, timeZone: s.timeZone, at: s.now)
        if !usual, observedDays(places) >= usualOffsetDays, !places.tripSnoozed {
            return .suggest(.newTimeZone, notify: false)
        }

        // Without a position nothing else ends a snooze: a usual time zone again means home.
        if s.place == nil, usual { places.tripSnoozed = false }
        return .none
    }

    // MARK: Time zone

    private static func key(_ timeZone: TimeZone, at date: Date) -> String {
        "\(timeZone.identifier)|\(timeZone.secondsFromGMT(for: date))"
    }

    private static func observedDays(_ places: TravelPlaces) -> Int {
        Set(places.usualOffsets.values.flatMap { $0 }).count
    }

    /// Remember that the device was in `timeZone` on `day`, trimming days older than the window.
    public static func observe(_ places: inout TravelPlaces, timeZone: TimeZone, at: Date, day: Int) {
        let k = key(timeZone, at: at)
        var days = places.usualOffsets[k] ?? []
        if !days.contains(day) { days.append(day) }
        places.usualOffsets[k] = days
        for (name, value) in places.usualOffsets {
            let kept = value.filter { $0 > day - TravelDetector.windowDays }
            places.usualOffsets[name] = kept.isEmpty ? nil : kept
        }
    }

    /// Usual: this offset was seen on enough days, or the same zone has a usual offset (daylight
    /// saving time moves Paris by an hour without the owner going anywhere).
    public static func isUsual(_ places: TravelPlaces, timeZone: TimeZone, at: Date) -> Bool {
        if Set(places.usualOffsets[key(timeZone, at: at)] ?? []).count >= usualOffsetDays { return true }
        let prefix = timeZone.identifier + "|"
        return places.usualOffsets.contains { name, days in
            name.hasPrefix(prefix) && Set(days).count >= usualOffsetDays
        }
    }

    // MARK: Trips

    /// The trip whose window (`start - leadTime ..< end`) holds `now`.
    public static func activeTrip(_ places: TravelPlaces, now: Date) -> TravelTrip? {
        places.trips.first { now >= $0.start.addingTimeInterval(-leadTime) && now < $0.end }
    }

    /// Create the trip, or replace the one with the same `id`.
    public static func save(_ places: inout TravelPlaces, trip: TravelTrip, now: Date) throws {
        guard trip.end > trip.start else { throw TravelPlannerError.endBeforeStart }
        if let index = places.trips.firstIndex(where: { $0.id == trip.id }) {
            places.trips[index] = trip
            return
        }
        guard places.trips.count < maxTrips else { throw TravelPlannerError.tooManyTrips }
        places.trips.append(trip)
    }

    public static func delete(_ places: inout TravelPlaces, id: UUID) {
        places.trips.removeAll { $0.id == id }
    }

    /// Forget trips that ended more than `keepAfterEnd` ago.
    public static func prune(_ places: inout TravelPlaces, now: Date) {
        places.trips.removeAll { $0.end.addingTimeInterval(keepAfterEnd) < now }
    }

    /// The one automatic attempt of this trip was made, whatever came of it.
    public static func markAutoTried(_ places: inout TravelPlaces, id: UUID) {
        guard let index = places.trips.firstIndex(where: { $0.id == id }) else { return }
        places.trips[index].autoTried = true
    }

    // MARK: Answers

    /// "No, I'm not travelling".
    public static func answerNo(
        _ places: inout TravelPlaces, reason: TravelReason, timeZone: TimeZone, now: Date
    ) {
        switch reason {
        case .newTimeZone:
            // Three distinct days ending today make this offset usual at once.
            let today = Int(now.timeIntervalSince1970 / secondsPerDay)
            for i in 0..<usualOffsetDays { observe(&places, timeZone: timeZone, at: now, day: today - i) }
        case .tripStarting(let id):
            delete(&places, id: id)
        case .away(let cell):
            TravelDetector.teach(&places, cell: cell)
        case .atAirport, .flightFound:
            break
        }
    }
}
