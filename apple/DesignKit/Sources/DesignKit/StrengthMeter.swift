import SwiftUI

/// Four segments, thresholds at 40, 60, 80 and 100 bits of entropy.
public struct StrengthMeter: View {
    private let bits: Double

    public init(bits: Double) { self.bits = bits }

    nonisolated static let thresholds: [Double] = [40, 60, 80, 100]
    nonisolated static let labels = ["trop court", "faible", "moyen", "bon", "excellent"]

    /// Number of lit segments, 0 to 4.
    public nonisolated static func level(forBits bits: Double) -> Int {
        thresholds.filter { bits >= $0 }.count
    }

    public nonisolated static func label(forBits bits: Double) -> String { labels[level(forBits: bits)] }

    private var tint: Color {
        switch Self.level(forBits: bits) {
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

#Preview("StrengthMeter") {
    VStack(alignment: .leading, spacing: 10) {
        ForEach([20.0, 45, 65, 85, 120], id: \.self) { StrengthMeter(bits: $0) }
    }
    .padding()
    .frame(width: 260)
}
