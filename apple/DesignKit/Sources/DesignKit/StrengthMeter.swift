import SwiftUI

/// Four segments, thresholds at 40, 60, 80 and 100 bits of entropy.
public struct StrengthMeter: View {
    private let bits: Double

    public init(bits: Double) { self.bits = bits }

    nonisolated static let thresholds: [Double] = [40, 60, 80, 100]
    nonisolated static var labels: [String] {
        [
            String(localized: "trop court", bundle: DesignKitStrings.bundle),
            String(localized: "faible", bundle: DesignKitStrings.bundle),
            String(localized: "moyen", bundle: DesignKitStrings.bundle),
            String(localized: "bon", bundle: DesignKitStrings.bundle),
            String(localized: "excellent", bundle: DesignKitStrings.bundle),
        ]
    }

    /// Number of lit segments, 0 to 4.
    public nonisolated static func level(forBits bits: Double) -> Int {
        thresholds.filter { bits >= $0 }.count
    }

    public nonisolated static func label(forBits bits: Double) -> String { labels[level(forBits: bits)] }

    private var tint: Color { Self.tint(forBits: bits) }

    /// Red up to "faible", orange for "moyen", green from "bon".
    public nonisolated static func tint(forBits bits: Double) -> Color {
        switch level(forBits: bits) {
        case 0, 1: .red
        case 2: .orange
        default: .green
        }
    }

    public var body: some View {
        let level = Self.level(forBits: bits)
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { i in
                    Capsule()
                        .fill(i < level ? tint : Color.secondary.opacity(0.25))
                        .frame(height: 4)
                }
            }
            .accessibilityHidden(true)
            Text(Self.label(forBits: bits)).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Force du mot de passe"))
        .accessibilityValue(Text(Self.label(forBits: bits)))
    }
}

/// Compact strength for a read-only row: the word ("Excellent") and a small ring filled by level.
public struct StrengthBadge: View {
    private let bits: Double

    public init(bits: Double) { self.bits = bits }

    public var body: some View {
        let level = StrengthMeter.level(forBits: bits)
        let tint = StrengthMeter.tint(forBits: bits)
        let word = StrengthMeter.label(forBits: bits)
        HStack(spacing: 7) {
            Text(word.prefix(1).uppercased() + word.dropFirst())
                .font(.callout.weight(.medium))
                .foregroundStyle(tint)
            ZStack {
                Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 2.5)
                Circle()
                    // An empty ring for "trop court" would read as a missing value: show a sliver.
                    .trim(from: 0, to: max(Double(level), 0.4) / 4)
                    .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 16, height: 16)
            .accessibilityHidden(true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Force du mot de passe"))
        .accessibilityValue(Text(word))
    }
}

#Preview("StrengthBadge") {
    VStack(alignment: .trailing, spacing: 10) {
        ForEach([20.0, 45, 65, 85, 120], id: \.self) { StrengthBadge(bits: $0) }
    }
    .padding()
}

#Preview("StrengthMeter") {
    VStack(alignment: .leading, spacing: 10) {
        ForEach([20.0, 45, 65, 85, 120], id: \.self) { StrengthMeter(bits: $0) }
    }
    .padding()
    .frame(width: 260)
}
