import SwiftUI

/// Circular countdown for a one-time code.
public struct TotpRing: View {
    private let remaining: Int
    private let period: Int

    public init(remaining: Int, period: Int) {
        self.remaining = remaining
        self.period = period
    }

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max(Double(remaining) / Double(period), 0), 1)
    }

    private var tint: Color { remaining <= 5 ? .red : Theme.accent }

    public var body: some View {
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(max(remaining, 0))")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .frame(width: 28, height: 28)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Code à usage unique"))
        .accessibilityValue(Text("encore \(max(remaining, 0)) secondes"))
    }
}

/// Countdown pill of a one-time code in a read-only row: a small ring and the seconds left.
public struct TotpCountdown: View {
    private let remaining: Int
    private let period: Int

    public init(remaining: Int, period: Int) {
        self.remaining = remaining
        self.period = period
    }

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max(Double(remaining) / Double(period), 0), 1)
    }

    private var tint: Color { remaining <= 5 ? .red : Theme.accent.mix(with: .white, by: 0.35) }

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
            Text("\(max(remaining, 0))")
                .font(.caption.monospacedDigit().weight(.medium))
                .foregroundStyle(remaining <= 5 ? Color.red : Color.secondary)
                .contentTransition(.numericText(countsDown: true))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.secondary.opacity(0.14), in: Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Code à usage unique"))
        .accessibilityValue(Text("encore \(max(remaining, 0)) secondes"))
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
