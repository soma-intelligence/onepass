import SwiftUI
import VaultKit

/// Location: label, address, latitude, longitude, radius (no map in milestone 2).
struct LocationEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private static let blank = FfiLocation(label: "", address: nil, lat: 0, lon: 0, radiusM: 100, suggestNearby: false)

    private var location: FfiLocation {
        if case .location(let l) = value { l } else { Self.blank }
    }

    private func update(_ change: (inout FfiLocation) -> Void) {
        var l = location
        change(&l)
        value = l == Self.blank ? .empty : .location(value: l)
    }

    private static let coordinate = FloatingPointFormatStyle<Double>.number.precision(.fractionLength(0...6))
        .locale(Locale(identifier: "en_US_POSIX")).grouping(.never)

    var body: some View {
        VStack(spacing: 8) {
            TextField("Étiquette", text: Binding(get: { location.label }, set: { t in update { $0.label = t } }))
                .accessibilityIdentifier("editor.field.\(field.id)")
            TextField(
                "Adresse",
                text: Binding(get: { location.address ?? "" }, set: { t in update { $0.address = t.isEmpty ? nil : t } }))
            HStack {
                TextField(
                    "Latitude", value: Binding(get: { location.lat }, set: { v in update { $0.lat = min(max(v, -90), 90) } }),
                    format: Self.coordinate)
                TextField(
                    "Longitude",
                    value: Binding(get: { location.lon }, set: { v in update { $0.lon = min(max(v, -180), 180) } }),
                    format: Self.coordinate)
            }
            .fieldInput(.money)
            HStack {
                Text("Rayon (m)").foregroundStyle(.secondary)
                TextField(
                    "Rayon", value: Binding(get: { location.radiusM }, set: { v in update { $0.radiusM = v } }),
                    format: .number.grouping(.never))
                    .multilineTextAlignment(.trailing)
                    .fieldInput(.number)
            }
        }
    }

    /// "Bureau · 12 rue de l'Exemple · 48.85661, 2.35222 · rayon 100 m".
    static func summary(_ l: FfiLocation) -> String {
        var parts: [String] = []
        if !l.label.isEmpty { parts.append(l.label) }
        if let address = l.address, !address.isEmpty { parts.append(address) }
        parts.append(String(format: "%.5f, %.5f", l.lat, l.lon))
        parts.append("rayon \(l.radiusM) m")
        return parts.joined(separator: " · ")
    }
}
