import DesignKit
import SwiftUI

/// Countdown ring: full at the start of the period, empty when the code changes. Its color is the
/// countdown wash: the accent, blending to red over the last seconds.
struct TotpRing: View {
    let remaining: UInt32
    let period: UInt32

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(1, Double(remaining) / Double(period))
    }

    var body: some View {
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(Theme.Wash.countdownColor(Color.accentColor, secondsLeft: Double(remaining)),
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text("totpRing.text \(remaining)")
                .font(.system(size: 9, weight: .semibold))
                .monospacedDigit()
        }
        .accessibilityElement()
        .accessibilityLabel(Text("totpRing.secondsLeft \(remaining)"))
    }
}
