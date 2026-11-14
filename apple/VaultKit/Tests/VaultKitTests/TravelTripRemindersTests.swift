import Foundation
import Testing

@testable import VaultKit

@Suite("TravelTripReminders")
struct TravelTripRemindersTests {
    private var paris: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "Europe/Paris")!
        return c
    }

    private func date(_ y: Int, _ m: Int, _ d: Int, _ h: Int, _ min: Int = 0) -> Date {
        paris.date(from: DateComponents(year: y, month: m, day: d, hour: h, minute: min))!
    }

    private func trip() -> TravelTrip {
        TravelTrip(start: date(2026, 12, 3, 10), end: date(2026, 12, 10, 18))
    }

    @Test func eveAndGo() {
        let t = trip()
        let r = TravelTripReminders.reminders(for: t, now: date(2026, 11, 20, 9), calendar: paris)
        #expect(r.map(\.kind) == [.eve, .go])
        #expect(r[0].fire == date(2026, 12, 2, 19))
        #expect(r[1].fire == date(2026, 12, 3, 7))
        #expect(r[0].id == "travel.trip.\(t.id.uuidString).eve")
        #expect(r[1].id == "travel.trip.\(t.id.uuidString).go")
    }

    @Test func pastRemindersDropped() {
        let r = TravelTripReminders.reminders(for: trip(), now: date(2026, 12, 2, 20), calendar: paris)
        #expect(r.map(\.kind) == [.go])
    }

    @Test func departureWithinThreeHours() {
        let t = trip()
        let r = TravelTripReminders.reminders(
            for: t, now: t.start.addingTimeInterval(-3600), calendar: paris)
        #expect(r.isEmpty)
    }

    @Test func idsMatchReminders() {
        let t = trip()
        let r = TravelTripReminders.reminders(for: t, now: date(2026, 11, 1, 9), calendar: paris)
        #expect(TravelTripReminders.ids(for: t.id) == r.map(\.id))
    }
}
