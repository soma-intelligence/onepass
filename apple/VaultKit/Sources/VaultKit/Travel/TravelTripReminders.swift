import Foundation

/// One local reminder of a planned trip. Fires on this device only.
public struct TravelReminder: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// The evening before departure.
        case eve
        /// Three hours before departure.
        case go
    }

    public var id: String
    public var fire: Date
    public var kind: Kind

    public init(id: String, fire: Date, kind: Kind) {
        self.id = id
        self.fire = fire
        self.kind = kind
    }
}

/// The app implements this with `UNUserNotificationCenter`; VaultKit only describes what to schedule.
@MainActor
public protocol TravelReminderCenter {
    func schedule(_ reminder: TravelReminder) async
    func remove(ids: [String])
}

public enum TravelTripReminders {
    /// The reminders still ahead of `now`, soonest first. The eve is 19:00 in the caller's time
    /// zone, so it follows the owner's wall clock.
    public static func reminders(for trip: TravelTrip, now: Date, calendar: Calendar) -> [TravelReminder] {
        var out: [TravelReminder] = []
        if let eveDay = calendar.date(byAdding: .day, value: -1, to: trip.start),
            let eve = calendar.date(bySettingHour: 19, minute: 0, second: 0, of: eveDay)
        {
            out.append(TravelReminder(id: id(for: trip.id, suffix: "eve"), fire: eve, kind: .eve))
        }
        out.append(
            TravelReminder(
                id: id(for: trip.id, suffix: "go"), fire: trip.start.addingTimeInterval(-3 * 3600),
                kind: .go))
        return out.filter { $0.fire > now }.sorted { $0.fire < $1.fire }
    }

    /// Every id a trip can have scheduled, so a changed or removed trip can clear them all.
    public static func ids(for tripID: UUID) -> [String] {
        [id(for: tripID, suffix: "eve"), id(for: tripID, suffix: "go")]
    }

    private static func id(for tripID: UUID, suffix: String) -> String {
        "travel.trip.\(tripID.uuidString).\(suffix)"
    }
}
