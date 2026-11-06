import SwiftUI

/// A scan under way (Watchtower's analysis, its breach check): the step's name, its figures on the
/// right, and a slim rounded track that fills in the accent. With no figures yet (the analysis has
/// no count) a short segment travels along the track; with Reduce Motion it breathes in place
/// instead. Flat color, no glow, no gradient.
public struct ScanProgressBar: View {
    private let title: Text
    private let detail: Text?
    /// 0...1, nil while the scan has no figures.
    private let fraction: Double?
    private let tint: Color

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(title: Text, detail: Text? = nil, done: Int? = nil, total: Int? = nil, tint: Color = Theme.accent) {
        self.title = title
        self.detail = detail
        self.fraction = Self.fraction(done: done, total: total)
        self.tint = tint
    }

    /// `done` of `total`, clamped, nil without a total.
    public static func fraction(done: Int?, total: Int?) -> Double? {
        guard let done, let total, total > 0 else { return nil }
        return min(max(Double(done) / Double(total), 0), 1)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                title
                    .font(.subheadline.weight(.semibold))
                Spacer(minLength: 4)
                if let detail {
                    detail
                        .font(.subheadline)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .contentTransition(.numericText())
                }
            }
            track
                .frame(height: 6)
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(fraction.map { Text($0, format: .percent.precision(.fractionLength(0))) } ?? Text(""))
    }

    private var track: some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            ZStack(alignment: .leading) {
                Capsule().fill(Color.primary.opacity(0.09))
                if let fraction {
                    Capsule()
                        .fill(tint)
                        // Never thinner than its own height: a started scan always shows a dot.
                        .frame(width: max(proxy.size.height, width * fraction))
                        .animation(.smooth(duration: 0.4), value: fraction)
                } else if reduceMotion {
                    TimelineView(.animation(minimumInterval: 1 / 30)) { context in
                        let t = context.date.timeIntervalSinceReferenceDate
                        Capsule()
                            .fill(tint)
                            .opacity(0.35 + 0.25 * (1 + sin(t * 2.4)) / 2)
                    }
                } else {
                    TimelineView(.animation) { context in
                        let segment = width * 0.32
                        // One pass every 1.4 s, eased at both ends, from just outside the left edge
                        // to just outside the right one.
                        let phase = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.4) / 1.4
                        let eased = phase * phase * (3 - 2 * phase)
                        Capsule()
                            .fill(tint)
                            .frame(width: segment)
                            .offset(x: -segment + (width + segment) * eased)
                    }
                    .clipShape(Capsule())
                }
            }
        }
    }
}

#Preview("ScanProgressBar") {
    VStack(spacing: 28) {
        ScanProgressBar(title: Text(verbatim: "Analyse des éléments"))
        ScanProgressBar(
            title: Text(verbatim: "Vérification des fuites"), detail: Text(verbatim: "42 sur 120"), done: 42, total: 120)
    }
    .padding(24)
}
