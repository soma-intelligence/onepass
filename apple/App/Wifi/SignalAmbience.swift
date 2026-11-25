import DesignKit
import SwiftUI

/// A quiet, living backdrop for a tool card: a slow mesh of the item's colour with soft waves
/// leaving the card's edge, as a signal would. Built for the Wi-Fi join code first; any tool page
/// (a passkey, an SSH key, a hotspot) can adopt it with `.signalAmbience(...)`.
///
/// Why these choices:
/// - The waves take the source's own rounded square, its radius growing with the distance, so
///   every ring stays concentric with the card instead of turning into circles around a square.
/// - Everything fades to nothing before the view's edge: no frame, no radius of its own to clash
///   with the cards above and below.
/// - It costs little: one `Canvas` and one `MeshGradient` redrawn at most 30 times a second by a
///   `TimelineView`, paused when the scene is not active. With Reduce Motion it is one still frame.
/// - It never takes a tap or a VoiceOver stop.
struct SignalAmbience: View {
    /// The item's colour (its identity tint).
    let tint: Color
    /// The card the waves leave from, placed at the top centre of the view.
    let source: CGSize
    /// The card's corner radius; each ring adds its distance to it.
    let sourceRadius: CGFloat
    /// Distance from the view's top to the card's top.
    var sourceTop: CGFloat = 0

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.colorScheme) private var colorScheme

    /// Seconds for one wave to travel out and fade. Slow on purpose: a backdrop that pulls the
    /// eye from the code would defeat it.
    private static let period: Double = 6
    private static let waves = 3
    /// How far a wave travels past the card's edge before it is gone.
    private static let reach: CGFloat = 56
    /// The phase drawn when motion is reduced: three rings well spread, a frame that reads as a
    /// still picture rather than an animation stopped halfway.
    private static let stillTime: Double = 1.4

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30, paused: reduceMotion || scenePhase != .active)) { context in
            let t = reduceMotion ? Self.stillTime : context.date.timeIntervalSinceReferenceDate
            ZStack {
                mesh(t)
                waves(t)
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private var dark: Bool { colorScheme == .dark }

    // MARK: - Mesh

    /// A 3 x 3 mesh in shades of the tint, its middle points drifting on slow, out of step sine
    /// waves (periods of 11 to 17 s), so the colour breathes without ever looping visibly. Masked to
    /// a soft ellipse so it melts into the page.
    private func mesh(_ t: Double) -> some View {
        let drift = { (period: Double, phase: Double) in Float(sin(t * 2 * .pi / period + phase) * 0.08) }
        let points: [SIMD2<Float>] = [
            [0, 0], [0.5 + drift(13, 0), 0], [1, 0],
            [0, 0.5 + drift(17, 1)], [0.5 + drift(11, 2), 0.5 + drift(15, 3)], [1, 0.5 + drift(14, 4)],
            [0, 1], [0.5 + drift(16, 5), 1], [1, 1],
        ]
        let base = tint.opacity(0)
        let soft = tint.opacity(dark ? 0.20 : 0.12)
        let warm = IdentityHue.shifted(tint, by: 0.06).opacity(dark ? 0.16 : 0.10)
        let cool = IdentityHue.shifted(tint, by: -0.06).opacity(dark ? 0.16 : 0.10)
        return MeshGradient(width: 3, height: 3, points: points, colors: [
            base, warm, base,
            cool, soft, warm,
            base, cool, base,
        ])
        .mask {
            RadialGradient(colors: [.black, .black.opacity(0.6), .clear], center: .center, startRadius: 0,
                endRadius: max(source.width, source.height) * 0.9)
        }
    }

    // MARK: - Waves

    private func waves(_ t: Double) -> some View {
        let ring = dark ? tint.mix(with: .white, by: 0.35) : tint
        return Canvas { context, size in
            // The source sits at the top centre, as the join code does in its card.
            let origin = CGRect(x: (size.width - source.width) / 2, y: sourceTop, width: source.width,
                height: source.height)
            for index in 0..<Self.waves {
                // Each wave is a third of a period behind the one before.
                let progress = (t / Self.period + Double(index) / Double(Self.waves)).truncatingRemainder(dividingBy: 1)
                let distance = CGFloat(progress) * Self.reach
                // Fades in quickly off the edge, then out with the distance: no ring pops.
                let alpha = min(progress / 0.12, 1) * pow(1 - progress, 1.6) * (dark ? 0.5 : 0.38)
                let rect = origin.insetBy(dx: -distance, dy: -distance)
                let path = Path(roundedRect: rect, cornerRadius: sourceRadius + distance, style: .continuous)
                context.stroke(path, with: .color(ring.opacity(alpha)), lineWidth: 1.5 - CGFloat(progress) * 0.75)
            }
        }
        // The rings rise from the card like the Wi-Fi glyph's arcs: they fade out over the top
        // padding (the card above stays clean) and are gone just under the card's bottom edge, so
        // they never cross the caption under the code.
        .mask {
            GeometryReader { proxy in
                let height = max(proxy.size.height, 1)
                let top = min(0.5, sourceTop / height)
                let bottom = min(1, (sourceTop + source.height) / height)
                let gone = min(1, (sourceTop + source.height + Theme.Space.s) / height)
                LinearGradient(stops: [.init(color: .clear, location: 0), .init(color: .black, location: top),
                    .init(color: .black, location: bottom * 0.85), .init(color: .clear, location: gone)],
                    startPoint: .top, endPoint: .bottom)
            }
        }
    }
}

/// Hue turns for the mesh's warm and cool corners (a fraction of the wheel), saturation and
/// brightness kept, so the mesh stays the item's colour family.
private enum IdentityHue {
    static func shifted(_ color: Color, by turn: Double) -> Color {
        let c = color.resolve(in: EnvironmentValues())
        let (r, g, b) = (Double(c.red), Double(c.green), Double(c.blue))
        let high = max(r, g, b), low = min(r, g, b), chroma = high - low
        guard chroma > 0 else { return color }
        var hue: Double
        if high == r {
            hue = ((g - b) / chroma).truncatingRemainder(dividingBy: 6)
        } else if high == g {
            hue = (b - r) / chroma + 2
        } else {
            hue = (r - g) / chroma + 4
        }
        hue = (hue / 6 + turn).truncatingRemainder(dividingBy: 1)
        if hue < 0 { hue += 1 }
        return Color(hue: hue, saturation: chroma / high, brightness: high, opacity: Double(c.opacity))
    }
}

extension View {
    /// Puts `SignalAmbience` behind this view, the waves leaving a `source`-sized card at its top
    /// centre. Adds `Theme.Space.xl` above and below so the first rings have room before they fade;
    /// horizontally the waves use the width the view already has.
    func signalAmbience(tint: Color, source: CGSize, sourceRadius: CGFloat) -> some View {
        padding(.vertical, Theme.Space.xl)
            .background {
                SignalAmbience(tint: tint, source: source, sourceRadius: sourceRadius, sourceTop: Theme.Space.xl)
            }
    }
}
