import SwiftUI

extension Theme {
    /// The wash tokens: the red to green scale, the alert and accent fills, the countdown blend and
    /// the flat fallback. Strength meter, TOTP ring, Watchtower arc and cards all read from here.
    public enum Wash {
        /// Scale stops, position then color. Green holds from 0.8 up, so a strong result is plain
        /// green and never a rainbow end to end.
        private static let stops: [(position: Double, color: Color)] = [
            (0, .red), (0.4, .orange), (0.6, .yellow), (0.8, .green),
        ]

        /// The scale color at `position` (clamped to 0...1), interpolated between the stops.
        public static func scaleColor(at position: Double) -> Color {
            let p = min(max(position, 0), 1)
            guard let last = stops.last, p < last.position else { return stops.last?.color ?? .green }
            for (lower, upper) in zip(stops, stops.dropFirst()) where p <= upper.position {
                let t = (p - lower.position) / (upper.position - lower.position)
                return lower.color.mix(with: upper.color, by: t)
            }
            return last.color
        }

        /// The scale as an angular gradient over the half circle (centered on the bottom, 180 to 360
        /// degrees), the same sweep as the Watchtower gauge.
        ///
        /// `fraction` is accepted for the call-site contract but deliberately unused: the gradient
        /// never compresses to the filled part. The caller masks it by the filled arc, so a low
        /// score shows only the red end and a full one reaches green.
        public static func scale(fraction: Double) -> AnyShapeStyle {
            AnyShapeStyle(
                AngularGradient(
                    stops: stops.map { Gradient.Stop(color: $0.color, location: $0.position) },
                    center: .bottom, startAngle: .degrees(180), endAngle: .degrees(360)))
        }

        /// The scale color of segment `index` out of `count` (the last lit segment of a full meter
        /// lands on green).
        public static func segmentColor(index: Int, of count: Int) -> Color {
            scaleColor(at: Double(index + 1) / Double(count))
        }

        /// A soft vertical wash of `base`: a touch lighter on top, a touch darker below.
        public static func alert(_ base: Color) -> LinearGradient {
            LinearGradient(
                colors: [base.mix(with: .white, by: 0.08), base.mix(with: .black, by: 0.06)],
                startPoint: .top, endPoint: .bottom)
        }

        /// The accent wash: lightened on top, the plain accent below.
        public static var accent: LinearGradient {
            LinearGradient(
                colors: [Theme.accent.mix(with: .white, by: 0.10), Theme.accent],
                startPoint: .top, endPoint: .bottom)
        }

        /// `calm`, blending to red over the last five seconds rather than switching at once.
        public static func countdownColor(_ calm: Color, secondsLeft: Double) -> Color {
            let warning = min(max((6 - secondsLeft) / 2, 0), 1)
            return calm.mix(with: .red, by: warning)
        }

        /// Whether the scale gauge draws a filled arc: an empty (nil) or zero score shows the track only.
        public static func scaleShowsFill(score: Int?) -> Bool {
            (score ?? 0) > 0
        }

        /// Washes give way to flat fills when either accessibility setting is on.
        public static func isFlat(increaseContrast: Bool, reduceTransparency: Bool) -> Bool {
            increaseContrast || reduceTransparency
        }
    }
}
