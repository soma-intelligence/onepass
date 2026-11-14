import Foundation
import Testing

@testable import VaultKit

@Suite("Travel planner")
struct TravelPlannerTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)  // fixed instant
    static let paris = TimeZone(identifier: "Europe/Paris")!
    static let tokyo = TimeZone(identifier: "Asia/Tokyo")!

    static func signals(
        travelling: Bool = false, unlocked: Bool = false, place: TravelSuggestion? = nil,
        timeZone: TimeZone = paris, atAirport: Bool = false, now: Date = now
    ) -> TravelSignals {
        TravelSignals(
            now: now, travelling: travelling, unlocked: unlocked, place: place, timeZone: timeZone,
            atAirport: atAirport)
    }

    /// Paris seen on `days` distinct days before `now`.
    static func parisSeen(_ days: Int, at date: Date = now) -> TravelPlaces {
        var places = TravelPlaces()
        let today = Int(date.timeIntervalSince1970 / 86_400)
        for i in 0..<days {
            TravelPlanner.observe(&places, timeZone: paris, at: date, day: today - i)
        }
        return places
    }

    static func trip(
        startIn: TimeInterval, length: TimeInterval = 5 * 86_400, autoEnter: Bool = false
    ) -> TravelTrip {
        let start = now.addingTimeInterval(startIn)
        return TravelTrip(start: start, end: start.addingTimeInterval(length), autoEnter: autoEnter)
    }

    @Test func learningSaysNothing() {
        var places = Self.parisSeen(2)
        #expect(TravelPlanner.decide(&places, Self.signals(timeZone: Self.tokyo)) == .none)
    }

    @Test func newTimeZoneAfterThreeDays() {
        var places = Self.parisSeen(3)
        #expect(
            TravelPlanner.decide(&places, Self.signals(timeZone: Self.tokyo))
                == .suggest(.newTimeZone, notify: false))
    }

    @Test func dstShiftAtHomeIsUsual() {
        let january = Date(timeIntervalSince1970: 1_768_000_000)  // 2026-01-09
        let july = Date(timeIntervalSince1970: 1_784_000_000)  // 2026-07-14
        var places = Self.parisSeen(3, at: january)
        #expect(Self.paris.secondsFromGMT(for: january) == 3600)
        #expect(Self.paris.secondsFromGMT(for: july) == 7200)
        #expect(TravelPlanner.isUsual(places, timeZone: Self.paris, at: july))
        #expect(TravelPlanner.decide(&places, Self.signals(now: july)) == .none)
    }

    @Test func noLocationStillDecides() {
        var places = Self.parisSeen(3)
        let t = Self.trip(startIn: 2 * 3600)
        places.trips = [t]
        #expect(
            TravelPlanner.decide(&places, Self.signals(place: nil))
                == .suggest(.tripStarting(t.id), notify: false))
    }

    @Test func tripWindowStartsThreeHoursBefore() {
        var places = TravelPlaces()
        places.trips = [Self.trip(startIn: 3 * 3600 + 1)]
        #expect(TravelPlanner.decide(&places, Self.signals()) == .none)
        let t = Self.trip(startIn: 3 * 3600)
        places.trips = [t]
        #expect(TravelPlanner.decide(&places, Self.signals()) == .suggest(.tripStarting(t.id), notify: false))
    }

    @Test func autoEnterOnlyWhenUnlocked() {
        var places = TravelPlaces()
        let t = Self.trip(startIn: 3600, autoEnter: true)
        places.trips = [t]
        #expect(
            TravelPlanner.decide(&places, Self.signals(unlocked: false))
                == .suggest(.tripStarting(t.id), notify: false))
        #expect(TravelPlanner.decide(&places, Self.signals(unlocked: true)) == .autoEnter(t.id))
    }

    @Test func autoEnterOnlyOnce() {
        var places = TravelPlaces()
        let t = Self.trip(startIn: 3600, autoEnter: true)
        places.trips = [t]
        TravelPlanner.markAutoTried(&places, id: t.id)
        #expect(
            TravelPlanner.decide(&places, Self.signals(unlocked: true))
                == .suggest(.tripStarting(t.id), notify: false))
    }

    @Test func tripBeatsAirportAndAway() {
        var places = TravelPlaces()
        let t = Self.trip(startIn: 3600)
        places.trips = [t]
        let s = Self.signals(place: .suggest(cell: "xn7", notify: true), atAirport: true)
        #expect(TravelPlanner.decide(&places, s) == .suggest(.tripStarting(t.id), notify: false))
    }

    @Test func awayPassesThrough() {
        var places = TravelPlaces()
        let s = Self.signals(place: .suggest(cell: "xn7", notify: true))
        #expect(TravelPlanner.decide(&places, s) == .suggest(.away(cell: "xn7"), notify: true))
    }

    @Test func travellingOnlyWelcomesBack() {
        var places = Self.parisSeen(3)
        let finished = TravelTrip(
            start: Self.now.addingTimeInterval(-6 * 86_400), end: Self.now.addingTimeInterval(-86_400))
        places.trips = [finished]
        let s = Self.signals(travelling: true, timeZone: Self.tokyo)
        #expect(TravelPlanner.decide(&places, s) == .welcomeBack)
        places.welcomeTripDismissed = finished.id
        #expect(TravelPlanner.decide(&places, s) == .none)
        places.trips = [Self.trip(startIn: -3600)]
        #expect(TravelPlanner.decide(&places, s) == .none)
    }

    @Test func backToBackTripsNoWelcomeBetweenLegs() {
        var places = TravelPlaces()
        let first = Self.finished(endedAgo: 3600)
        let second = TravelTrip(
            start: Self.now.addingTimeInterval(-1800), end: Self.now.addingTimeInterval(4 * 86_400))
        places.trips = [first, second]
        let s = Self.signals(travelling: true, place: .welcomeBack, timeZone: Self.tokyo)
        #expect(TravelPlanner.decide(&places, s) == .none)
        // The second leg over too: now the journey is.
        let after = Self.signals(
            travelling: true, timeZone: Self.tokyo, now: second.end.addingTimeInterval(3600))
        #expect(TravelPlanner.decide(&places, after) == .welcomeBack)
    }

    @Test func noOnTimeZoneTeachesIt() {
        var places = Self.parisSeen(3)
        let s = Self.signals(timeZone: Self.tokyo)
        #expect(TravelPlanner.decide(&places, s) == .suggest(.newTimeZone, notify: false))
        TravelPlanner.answerNo(&places, reason: .newTimeZone, timeZone: Self.tokyo, now: Self.now)
        #expect(TravelPlanner.decide(&places, s) == .none)
    }

    @Test func noOnTripDeletesIt() {
        var places = TravelPlaces()
        let t = Self.trip(startIn: 3600)
        places.trips = [t]
        TravelPlanner.answerNo(&places, reason: .tripStarting(t.id), timeZone: Self.paris, now: Self.now)
        #expect(places.trips.isEmpty)
    }

    @Test func noOnAwayTeachesTheCell() {
        var places = TravelPlaces()
        TravelPlanner.answerNo(&places, reason: .away(cell: "xn7"), timeZone: Self.paris, now: Self.now)
        #expect(places.taught.contains("xn7"))
    }

    @Test func pruneSevenDaysAfterEnd() {
        var places = TravelPlaces()
        let old = TravelTrip(
            start: Self.now.addingTimeInterval(-9 * 86_400),
            end: Self.now.addingTimeInterval(-7 * 86_400 - 1))
        let kept = TravelTrip(
            start: Self.now.addingTimeInterval(-9 * 86_400),
            end: Self.now.addingTimeInterval(-7 * 86_400 + 1))
        places.trips = [old, kept]
        TravelPlanner.prune(&places, now: Self.now)
        #expect(places.trips.map(\.id) == [kept.id])
    }

    @Test func saveRejectsEndBeforeStartAndSeventeenthTrip() throws {
        var places = TravelPlaces()
        let bad = TravelTrip(start: Self.now, end: Self.now.addingTimeInterval(-1))
        #expect(throws: TravelPlannerError.endBeforeStart) {
            try TravelPlanner.save(&places, trip: bad, now: Self.now)
        }
        for i in 0..<16 {
            try TravelPlanner.save(
                &places, trip: Self.trip(startIn: Double(i + 1) * 86_400), now: Self.now)
        }
        #expect(throws: TravelPlannerError.tooManyTrips) {
            try TravelPlanner.save(&places, trip: Self.trip(startIn: 30 * 86_400), now: Self.now)
        }
        // Replacing an existing trip is not a seventeenth.
        var first = places.trips[0]
        first.autoEnter = true
        try TravelPlanner.save(&places, trip: first, now: Self.now)
        #expect(places.trips.count == 16)
        #expect(places.trips[0].autoEnter)
        TravelPlanner.delete(&places, id: first.id)
        #expect(places.trips.count == 15)
    }

    @Test func homeAgainWithoutLocationEndsSnooze() {
        var places = Self.parisSeen(3)
        places.tripSnoozed = true
        #expect(TravelPlanner.decide(&places, Self.signals(place: nil)) == .none)
        #expect(!places.tripSnoozed)
    }

    static func finished(endedAgo: TimeInterval) -> TravelTrip {
        let end = now.addingTimeInterval(-endedAgo)
        return TravelTrip(start: end.addingTimeInterval(-3 * 86_400), end: end)
    }

    @Test func twoFinishedTripsOnlyLatestCounts() {
        var places = TravelPlaces()
        let older = Self.finished(endedAgo: 5 * 86_400)
        let latest = Self.finished(endedAgo: 86_400)
        places.trips = [older, latest]
        places.welcomeTripDismissed = latest.id
        let s = Self.signals(travelling: true, timeZone: Self.tokyo)
        #expect(TravelPlanner.decide(&places, s) == .none)
        TravelPlanner.dismissWelcome(&places, now: Self.now)
        #expect(places.welcomeTripDismissed == latest.id)
    }

    @Test func enteringAfterPastTripShowsNoWelcome() {
        var places = TravelPlaces()
        places.trips = [Self.finished(endedAgo: 3 * 86_400)]
        TravelPlanner.entered(&places, now: Self.now)
        let s = Self.signals(travelling: true, timeZone: Self.tokyo)
        #expect(TravelPlanner.decide(&places, s) == .none)
        let later = Self.now.addingTimeInterval(2 * 86_400)
        let t = TravelTrip(start: Self.now, end: Self.now.addingTimeInterval(86_400))
        places.trips.append(t)
        #expect(
            TravelPlanner.decide(&places, Self.signals(travelling: true, timeZone: Self.tokyo, now: later))
                == .welcomeBack)
    }

    @Test func overlappingTripsEarliestStartWins() {
        var places = TravelPlaces()
        let late = Self.trip(startIn: 3600)
        let early = Self.trip(startIn: -3600)
        places.trips = [late, early]
        #expect(TravelPlanner.activeTrip(places, now: Self.now)?.id == early.id)
    }

    @Test func snoozeSuppressesNewTimeZone() {
        var places = Self.parisSeen(3)
        places.tripSnoozed = true
        #expect(TravelPlanner.decide(&places, Self.signals(timeZone: Self.tokyo)) == .none)
    }

    @Test func welcomeBackFromPlace() {
        var places = TravelPlaces()
        let s = Self.signals(travelling: true, place: .welcomeBack)
        #expect(TravelPlanner.decide(&places, s) == .welcomeBack)
    }

    @Test func observeDropsDaysOlderThanSixtyDays() {
        var places = TravelPlaces()
        TravelPlanner.observe(&places, timeZone: Self.paris, at: Self.now, day: 100)
        TravelPlanner.observe(&places, timeZone: Self.paris, at: Self.now, day: 160)
        let days = places.usualOffsets.values.flatMap { $0 }
        #expect(days == [160])
    }

    @Test func daysCountAcrossSeveralKeys() {
        var places = TravelPlaces()
        let today = Int(Self.now.timeIntervalSince1970 / 86_400)
        TravelPlanner.observe(&places, timeZone: Self.paris, at: Self.now, day: today)
        TravelPlanner.observe(&places, timeZone: Self.tokyo, at: Self.now, day: today - 1)
        TravelPlanner.observe(&places, timeZone: Self.tokyo, at: Self.now, day: today - 2)
        let ny = TimeZone(identifier: "America/New_York")!
        #expect(TravelPlanner.decide(&places, Self.signals(timeZone: ny)) == .suggest(.newTimeZone, notify: false))
    }

    @Test func saveRejectsAnEndedTrip() {
        var places = TravelPlaces()
        let t = Self.finished(endedAgo: 1)
        #expect(throws: TravelPlannerError.alreadyEnded) {
            try TravelPlanner.save(&places, trip: t, now: Self.now)
        }
    }
}
