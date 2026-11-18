#if os(iOS)
import DesignKit
import SwiftUI

/// The first second of a cold launch. It carries on from the launch screen (`LaunchMark`, the bare
/// tile, on `LaunchBackground`, both at the same place): the six dots of the mark land one by one,
/// the bar draws upward, then the mark lifts and the splash fades onto the screen under it (the
/// lock screen, whose Face ID try already runs). Reduce Motion: the whole mark, then a plain fade.
struct RXSplash: View {
    let finished: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var dotsShown = 0
    @State private var barShown = false
    @State private var leaving = false

    /// The launch screen's tile, in points (`LaunchMark` is 96 pt).
    static let size: CGFloat = 96
    /// The dots on the mark's 100 grid, in landing order: left column, then right, top to bottom.
    private static let dots: [CGPoint] = [
        CGPoint(x: 23.5, y: 24), CGPoint(x: 23.5, y: 50), CGPoint(x: 23.5, y: 76),
        CGPoint(x: 49.5, y: 24), CGPoint(x: 49.5, y: 50), CGPoint(x: 49.5, y: 76),
    ]

    var body: some View {
        ZStack {
            Color("LaunchBackground")
                .opacity(leaving ? 0 : 1)
            mark
                .scaleEffect(leaving ? 1.14 : 1)
                .opacity(leaving ? 0 : 1)
        }
        .ignoresSafeArea()
        .allowsHitTesting(!leaving)
        .accessibilityHidden(true)
        .sensoryFeedback(.impact(weight: .light, intensity: 0.6), trigger: barShown) { _, shown in shown }
        .task { await play() }
    }

    private var mark: some View {
        ZStack {
            AppGlyphTile(size: Self.size)
            lattice
                .frame(width: Self.size * 0.6, height: Self.size * 0.6)
        }
        .frame(width: Self.size, height: Self.size)
    }

    private var lattice: some View {
        GeometryReader { proxy in
            let unit = min(proxy.size.width, proxy.size.height) / 100
            ZStack(alignment: .topLeading) {
                ForEach(Self.dots.indices, id: \.self) { index in
                    let landed = dotsShown > index
                    Circle()
                        .fill(Color.white.opacity(0.55))
                        .frame(width: 18 * unit, height: 18 * unit)
                        .scaleEffect(landed ? 1 : 0.2)
                        .opacity(landed ? 1 : 0)
                        .position(x: Self.dots[index].x * unit, y: Self.dots[index].y * unit)
                }
                AppGlyph.Lattice.Bar()
                    .fill(Color.white)
                    // Grows from its foot (the bar spans y 15 to 85 on the grid).
                    .scaleEffect(x: 1, y: barShown ? 1 : 0.001, anchor: UnitPoint(x: 0.765, y: 0.85))
                    .opacity(barShown ? 1 : 0)
            }
        }
    }

    private func play() async {
        if reduceMotion {
            dotsShown = Self.dots.count
            barShown = true
            await pause(250)
            withAnimation(.easeOut(duration: 0.25)) { leaving = true }
            await pause(260)
            finished()
            return
        }
        await pause(60)
        for count in 1...Self.dots.count {
            withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) { dotsShown = count }
            await pause(45)
        }
        withAnimation(.spring(response: 0.34, dampingFraction: 0.78)) { barShown = true }
        await pause(320)
        withAnimation(.easeIn(duration: 0.26)) { leaving = true }
        await pause(270)
        finished()
    }

    /// A pause that never throws: the splash always ends, even if its task is cancelled.
    private func pause(_ milliseconds: Int) async {
        try? await Task.sleep(for: .milliseconds(milliseconds))
    }
}
#endif
