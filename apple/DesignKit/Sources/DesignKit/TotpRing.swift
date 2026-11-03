import SwiftUI

/// Circular countdown for a one-time code.
public struct TotpRing: View {
    private let remaining: Int
    private let period: Int
    private let exact: Double?

    /// `exact`: the seconds left with their fraction, so the ring drains continuously (redrawn
    /// every frame by the caller) instead of jumping once a second.
    public init(remaining: Int, period: Int, exact: Double? = nil) {
        self.remaining = remaining
        self.period = period
        self.exact = exact
    }

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max((exact ?? Double(remaining)) / Double(period), 0), 1)
    }

    /// Accent, blending to red over the last five seconds rather than switching at once.
    private func blended(_ calm: Color) -> Color {
        let left = exact ?? Double(remaining)
        let warning = min(max((6 - left) / 2, 0), 1)
        return calm.mix(with: .red, by: warning)
    }

    private var tint: Color { blended(Theme.accent) }

    public var body: some View {
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(verbatim: "\(max(remaining, 0))")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .contentTransition(.numericText(countsDown: true))
                .animation(.snappy(duration: 0.3), value: remaining)
        }
        .frame(width: 28, height: 28)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("term.oneTimeCode", bundle: DesignKitStrings.bundle))
        .accessibilityValue(Text("totpRing.secondsLeft \(max(remaining, 0))", bundle: DesignKitStrings.bundle))
    }
}

/// Countdown pill of a one-time code in a read-only row: a small ring and the seconds left.
public struct TotpCountdown: View {
    private let remaining: Int
    private let period: Int
    private let exact: Double?

    /// `exact`: the seconds left with their fraction, so the ring drains continuously (redrawn
    /// every frame by the caller) instead of jumping once a second.
    public init(remaining: Int, period: Int, exact: Double? = nil) {
        self.remaining = remaining
        self.period = period
        self.exact = exact
    }

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max((exact ?? Double(remaining)) / Double(period), 0), 1)
    }

    /// Accent, blending to red over the last five seconds rather than switching at once.
    private func blended(_ calm: Color) -> Color {
        let left = exact ?? Double(remaining)
        let warning = min(max((6 - left) / 2, 0), 1)
        return calm.mix(with: .red, by: warning)
    }

    private var tint: Color { blended(Theme.accent.mix(with: .white, by: 0.35)) }

    public var body: some View {
        HStack(spacing: 5) {
            ZStack {
                Circle().stroke(Color.secondary.opacity(0.3), lineWidth: 2)
                Circle()
                    .trim(from: 0, to: fraction)
                    .stroke(tint, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 12, height: 12)
            Text(verbatim: "\(max(remaining, 0))")
                .font(.caption.monospacedDigit().weight(.medium))
                .foregroundStyle(remaining <= 5 ? Color.red : Color.secondary)
                .contentTransition(.numericText(countsDown: true))
                .animation(.snappy(duration: 0.3), value: remaining)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.secondary.opacity(0.14), in: Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("term.oneTimeCode", bundle: DesignKitStrings.bundle))
        .accessibilityValue(Text("totpRing.secondsLeft \(max(remaining, 0))", bundle: DesignKitStrings.bundle))
    }
}

#Preview("TotpRing") {
    HStack(spacing: 16) {
        TotpRing(remaining: 24, period: 30)
        TotpRing(remaining: 12, period: 30)
        TotpRing(remaining: 3, period: 30)
        TotpCountdown(remaining: 21, period: 30)
        TotpCountdown(remaining: 4, period: 30)
    }
    .padding()
}
