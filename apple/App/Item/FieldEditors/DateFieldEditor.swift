import SwiftUI
import VaultKit

/// Calendar dates are kept as plain year, month, day: converted through a fixed UTC Gregorian
/// calendar so no time zone shifts the day.
enum FieldDates {
    static let calendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }()

    /// The app's language (French or English), not the system region alone: dates read like the
    /// rest of the interface.
    static let french = Locale(identifier: Bundle.main.preferredLocalizations.first ?? "fr")

    static func date(_ value: FfiDate) -> Date? {
        calendar.date(from: DateComponents(year: Int(value.year), month: Int(value.month), day: Int(value.day)))
    }

    static func ffiDate(_ date: Date) -> FfiDate {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return FfiDate(year: Int32(c.year ?? 2000), month: UInt8(c.month ?? 1), day: UInt8(c.day ?? 1))
    }

    /// "3 mars 2026".
    static func long(_ value: FfiDate) -> String {
        guard let date = date(value) else { return "" }
        var style = Date.FormatStyle(date: .long, time: .omitted, locale: french)
        style.timeZone = calendar.timeZone
        return date.formatted(style)
    }

    /// "03/2030".
    static func monthYear(year: UInt16, month: UInt8) -> String {
        String(format: "%02d/%04d", Int(month), Int(year))
    }

    static let monthNames: [String] = {
        let formatter = DateFormatter()
        formatter.locale = french
        return formatter.standaloneMonthSymbols ?? []
    }()

    /// "jeudi 22 octobre 2026 à 18:04" (local time).
    static func timestamp(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(
            .dateTime.weekday(.wide).day().month(.wide).year().hour().minute().locale(french))
    }

    /// "3 mars 2026" (local time).
    static func day(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(
            .dateTime.day().month(.wide).year().locale(french))
    }
}

/// Date field: "Ajouter une date" while empty, then a date picker and a clear button.
struct DateFieldEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var date: Binding<Date> {
        Binding(
            get: {
                if case .date(let d) = value, let date = FieldDates.date(d) { return date }
                return Date()
            },
            set: { value = .date(value: FieldDates.ffiDate($0)) })
    }

    var body: some View {
        if case .date = value {
            HStack {
                DatePicker(field.displayLabel, selection: date, displayedComponents: .date)
                    .labelsHidden()
                    .environment(\.locale, FieldDates.french)
                    .environment(\.calendar, FieldDates.calendar)
                    .environment(\.timeZone, FieldDates.calendar.timeZone)
                    .accessibilityIdentifier("editor.field.\(field.id)")
                Spacer()
                Button("Effacer", systemImage: "xmark.circle.fill") { value = .empty }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
        } else {
            Button {
                value = .date(value: FieldDates.ffiDate(Date()))
            } label: {
                Label("Ajouter une date", systemImage: "calendar.badge.plus")
            }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("editor.field.\(field.id)")
        }
    }
}

/// Month and year field (card expiry...): two pickers.
struct MonthYearEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var current: (year: UInt16, month: UInt8)? {
        if case .monthYear(let year, let month) = value { (year, month) } else { nil }
    }

    private static var years: [UInt16] {
        let now = FieldDates.calendar.component(.year, from: Date())
        return (now - 30...now + 20).map { UInt16($0) }
    }

    var body: some View {
        if let current {
            HStack {
                Picker("Mois", selection: Binding(
                    get: { current.month },
                    set: { value = .monthYear(year: current.year, month: $0) })
                ) {
                    ForEach(1...12, id: \.self) { m in
                        Text(FieldDates.monthNames[safe: m - 1] ?? String(m)).tag(UInt8(m))
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("editor.field.\(field.id)")
                Picker("Année", selection: Binding(
                    get: { current.year },
                    set: { value = .monthYear(year: $0, month: current.month) })
                ) {
                    ForEach(Self.years + (Self.years.contains(current.year) ? [] : [current.year]), id: \.self) {
                        Text(verbatim: String($0)).tag($0)
                    }
                }
                .labelsHidden()
                Spacer()
                Button("Effacer", systemImage: "xmark.circle.fill") { value = .empty }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
        } else {
            Button("Choisir le mois et l'année") {
                let c = FieldDates.calendar.dateComponents([.year, .month], from: Date())
                value = .monthYear(year: UInt16(c.year ?? 2026), month: UInt8(c.month ?? 1))
            }
            .accessibilityIdentifier("editor.field.\(field.id)")
        }
    }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}
