import SwiftUI
import VaultKit

/// One planned trip (Réglages > Travel Mode > Voyages): departure, return, and whether OnePass may
/// turn Travel Mode on by itself before the border. Pushed from `TravelSettings`; `trip` is `nil`
/// for a new one. Saving goes through `TravelDetection.saveTrip`, which owns the rules.
struct TravelTripEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    private let existing: TravelTrip?
    @State private var start: Date
    @State private var end: Date
    @State private var autoEnter: Bool
    @State private var errorMessage: String?

    init(trip: TravelTrip?) {
        existing = trip
        let start = trip?.start ?? Date()
        _start = State(initialValue: start)
        _end = State(initialValue: trip?.end ?? start.addingTimeInterval(7 * 86_400))
        _autoEnter = State(initialValue: trip?.autoEnter ?? false)
    }

    var body: some View {
        Form {
            Section {
                DatePicker("trip.start", selection: $start, displayedComponents: [.date, .hourAndMinute])
                    .accessibilityIdentifier("trip.start")
                DatePicker("trip.end", selection: $end, displayedComponents: .date)
                    .accessibilityIdentifier("trip.end")
            }
            Section {
                Toggle("trip.auto", isOn: $autoEnter)
                    .accessibilityIdentifier("trip.auto")
            } footer: {
                Text("trip.auto.footer")
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier("trip.error")
                }
            }
            Section {
                Button("trip.save") { save() }
                    .disabled(end <= start)
                    .accessibilityIdentifier("trip.save")
            }
        }
        .settingsPage("settings.travel.addTrip")
        .onChange(of: start) { _, _ in errorMessage = nil }
        .onChange(of: end) { _, _ in errorMessage = nil }
    }

    private func save() {
        // An edit keeps the trip's identity; a new start date earns a new automatic attempt.
        var trip = existing ?? TravelTrip(start: start, end: end)
        let startMoved = existing.map { $0.start != start } ?? false
        trip.start = start
        trip.end = end
        trip.autoEnter = autoEnter
        if startMoved { trip.autoTried = false }
        do {
            try model.travel.saveTrip(trip)
            dismiss()
        } catch let error as TravelPlannerError {
            errorMessage = Self.message(error)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private static func message(_ error: TravelPlannerError) -> String {
        switch error {
        case .endBeforeStart: String(localized: "trip.error.endBeforeStart")
        case .tooManyTrips: String(localized: "trip.error.tooMany")
        case .alreadyEnded: String(localized: "trip.error.ended")
        }
    }
}
