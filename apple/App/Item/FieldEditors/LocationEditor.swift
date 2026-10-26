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

    var body: some View {
        VStack(spacing: 8) {
            TextField("Étiquette", text: Binding(get: { location.label }, set: { t in update { $0.label = t } }))
                .accessibilityIdentifier("editor.field.\(field.id)")
            TextField(
                "Adresse",
                text: Binding(get: { location.address ?? "" }, set: { t in update { $0.address = t.isEmpty ? nil : t } }))
            HStack {
                coordinate("Latitude", value: location.lat, range: -90...90) { v in update { $0.lat = v } }
                    .accessibilityIdentifier("editor.field.\(field.id).lat")
                coordinate("Longitude", value: location.lon, range: -180...180) { v in update { $0.lon = v } }
                    .accessibilityIdentifier("editor.field.\(field.id).lon")
            }
            HStack {
                Text("Rayon (m)").foregroundStyle(.secondary)
                ParsedTextField(
                    title: String(localized: "Rayon"), prompt: "100", kind: .number,
                    value: Int64(location.radiusM),
                    parse: { NumberInput.integer($0).flatMap { (0...Int64(UInt32.max)).contains($0) ? $0 : nil } },
                    format: { String($0) },
                    commit: { v in update { $0.radiusM = UInt32(v ?? 0) } })
                    .multilineTextAlignment(.trailing)
            }
        }
    }

    /// Latitude or longitude typed as text: minus sign, "," or "." accepted, parsed on every keystroke,
    /// out of range values refused.
    private func coordinate(
        _ title: String, value: Double, range: ClosedRange<Double>, commit: @escaping (Double) -> Void
    ) -> some View {
        ParsedTextField(
            title: title, prompt: "0,0", kind: .location, value: value,
            parse: { NumberInput.double($0).flatMap { range.contains($0) ? $0 : nil } },
            format: NumberInput.text,
            commit: { commit($0 ?? 0) })
    }

    /// "Bureau · 12 rue de l'Exemple · 48.85661, 2.35222 · rayon 100 m".
    static func summary(_ l: FfiLocation) -> String {
        var parts: [String] = []
        if !l.label.isEmpty { parts.append(l.label) }
        if let address = l.address, !address.isEmpty { parts.append(address) }
        parts.append(String(format: "%.5f, %.5f", l.lat, l.lon))
        parts.append(String(localized: "rayon \(l.radiusM) m"))
        return parts.joined(separator: " · ")
    }
}
