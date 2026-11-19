import Foundation

/// A trip the owner planned, read from the calendar, or noticed at an airport. Lives only in
/// `TravelPlaces` (the local encrypted file): never synced, never sent.
public struct TravelTrip: Codable, Equatable, Sendable, Identifiable {
    public enum Source: String, Codable, Sendable {
        case manual, calendar, airport
    }

    public var id: UUID
    public var start: Date
    public var end: Date
    public var source: Source
    /// The owner agreed to enter Travel Mode on its own before the border.
    public var autoEnter: Bool
    /// The calendar event this trip came from, so a rescan does not add it twice.
    public var calendarEventID: String?
    /// The one automatic attempt of this trip was made (success or not).
    public var autoTried: Bool

    public init(
        id: UUID = UUID(), start: Date, end: Date, source: Source = .manual, autoEnter: Bool = false,
        calendarEventID: String? = nil, autoTried: Bool = false
    ) {
        self.id = id
        self.start = start
        self.end = end
        self.source = source
        self.autoEnter = autoEnter
        self.calendarEventID = calendarEventID
        self.autoTried = autoTried
    }
}
