import SwiftUI

/// The empty detail column's picture: a vault door with its wheel, a padlock, a coin, a card and an
/// envelope tucked behind it, drawn as one engraved, near-monochrome object that sits just above
/// the background (light lines and faint fills, dark outlines). Original artwork, all in shapes.
public struct VaultIllustration: View {
    private let size: CGFloat
    @Environment(\.colorScheme) private var scheme
    private var ink: Ink { .of(scheme) }

    public init(size: CGFloat = 320) {
        self.size = size
    }

    public var body: some View {
        let u = size / 100
        let line = max(1, u * 0.9)
        ZStack {
            // Sparkles above the door.
            ForEach(0..<5, id: \.self) { i in
                let angle = Angle.degrees(-140 + Double(i) * 25)
                Capsule()
                    .fill(ink.edge)
                    .frame(width: u * 1.1, height: u * (i == 2 ? 7 : 4.5))
                    .offset(y: -u * 44)
                    .rotationEffect(angle + .degrees(90))
            }
            // Envelope, left.
            envelope(u: u, line: line)
                .rotationEffect(.degrees(-28))
                .offset(x: -u * 31, y: -u * 6)
            // Card, right.
            card(u: u, line: line)
                .rotationEffect(.degrees(-24))
                .offset(x: u * 33, y: u * 1)
            // Coin, right top.
            coin(u: u, line: line)
                .offset(x: u * 24, y: -u * 19)
            // Padlock, top.
            padlock(u: u, line: line)
                .rotationEffect(.degrees(14))
                .offset(x: u * 1, y: -u * 29)
            // The door: frame ring, door, wheel.
            Circle().fill(ink.base).overlay { Circle().strokeBorder(ink.edge, lineWidth: line) }
                .frame(width: u * 62, height: u * 62)
                .offset(y: u * 6)
            Circle().fill(ink.face).overlay { Circle().strokeBorder(ink.edge, lineWidth: line) }
                .overlay { Circle().strokeBorder(ink.highlight, lineWidth: line * 0.8).padding(u * 2.2) }
                .frame(width: u * 54, height: u * 54)
                .offset(y: u * 3)
            Circle().fill(ink.shade)
                .frame(width: u * 40, height: u * 40)
                .offset(x: -u * 1.5, y: u * 5)
            wheel(u: u, line: line).offset(y: u * 3)
            // Two bolts on the door's right.
            Circle().fill(ink.shade).frame(width: u * 3.2).offset(x: u * 20, y: -u * 2)
            Circle().fill(ink.shade).frame(width: u * 5.5).offset(x: u * 21, y: u * 6)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private func wheel(u: CGFloat, line: CGFloat) -> some View {
        ZStack {
            ForEach([45.0, 135.0], id: \.self) { angle in
                ZStack {
                    Capsule().fill(ink.face).overlay { Capsule().strokeBorder(ink.edge, lineWidth: line) }
                        .frame(width: u * 38, height: u * 4.6)
                    // Grips at both ends.
                    HStack {
                        Capsule().fill(ink.base).overlay { Capsule().strokeBorder(ink.edge, lineWidth: line) }
                            .frame(width: u * 9, height: u * 5.6)
                        Spacer()
                        Capsule().fill(ink.base).overlay { Capsule().strokeBorder(ink.edge, lineWidth: line) }
                            .frame(width: u * 9, height: u * 5.6)
                    }
                    .frame(width: u * 38)
                }
                .rotationEffect(.degrees(angle))
            }
            Circle().fill(ink.base).overlay { Circle().strokeBorder(ink.edge, lineWidth: line) }
                .frame(width: u * 20, height: u * 20)
            Circle().fill(ink.face).overlay { Circle().strokeBorder(ink.edge, lineWidth: line * 1.6) }
                .frame(width: u * 14, height: u * 14)
            // The keyhole: a round head and a tapered slot.
            VStack(spacing: -u * 0.6) {
                Circle().fill(ink.edge).frame(width: u * 3.6, height: u * 3.6)
                Capsule().fill(ink.edge).frame(width: u * 1.8, height: u * 4.2)
            }
        }
    }

    private func padlock(u: CGFloat, line: CGFloat) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: u * 3.5, style: .continuous)
                .fill(ink.base)
                .overlay { RoundedRectangle(cornerRadius: u * 3.5, style: .continuous).strokeBorder(ink.edge, lineWidth: line) }
                .frame(width: u * 18, height: u * 16)
            VStack(spacing: -u * 0.4) {
                Circle().fill(ink.edge).frame(width: u * 3.2)
                Capsule().fill(ink.edge).frame(width: u * 1.4, height: u * 3.2)
            }
        }
    }

    private func coin(u: CGFloat, line: CGFloat) -> some View {
        ZStack {
            Circle().fill(ink.base).overlay { Circle().strokeBorder(ink.edge, lineWidth: line) }
            Circle().strokeBorder(ink.edge, lineWidth: line * 0.8).padding(u * 1.6)
            Text(verbatim: "$").font(.system(size: u * 6, weight: .heavy, design: .rounded)).foregroundStyle(ink.edge)
                .rotationEffect(.degrees(18))
        }
        .frame(width: u * 13, height: u * 13)
    }

    private func card(u: CGFloat, line: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: u * 1.8, style: .continuous)
            .fill(ink.base)
            .overlay { RoundedRectangle(cornerRadius: u * 1.8, style: .continuous).strokeBorder(ink.edge, lineWidth: line) }
            .overlay(alignment: .top) { Rectangle().fill(ink.edge).frame(height: u * 2.4).padding(.top, u * 3) }
            .overlay(alignment: .bottomTrailing) {
                RoundedRectangle(cornerRadius: u * 0.8).fill(ink.edge).frame(width: u * 4.5, height: u * 2.6)
                    .padding(u * 2)
            }
            .frame(width: u * 20, height: u * 13)
    }

    private func envelope(u: CGFloat, line: CGFloat) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: u * 1.2, style: .continuous)
                .fill(ink.base)
                .overlay { RoundedRectangle(cornerRadius: u * 1.2, style: .continuous).strokeBorder(ink.edge, lineWidth: line) }
            Path { p in
                p.move(to: .init(x: 0, y: 0))
                p.addLine(to: .init(x: u * 10, y: u * 7))
                p.addLine(to: .init(x: u * 20, y: 0))
            }
            .stroke(ink.edge, style: StrokeStyle(lineWidth: line, lineJoin: .round))
            .frame(width: u * 20, height: u * 13)
        }
        .frame(width: u * 20, height: u * 13)
    }

    /// Engraving inks: opaque grays a few steps around the page (so the pieces behind the door stay
    /// hidden), darker outlines. Light and dark appearances each get their own set.
    private struct Ink {
        let base, face, shade, highlight, edge: Color

        static func of(_ scheme: ColorScheme) -> Ink {
            scheme == .dark
                ? Ink(base: Color(white: 0.155), face: Color(white: 0.172), shade: Color(white: 0.145),
                      highlight: Color(white: 0.2), edge: Color(white: 0.085))
                : Ink(base: Color(white: 0.93), face: Color(white: 0.95), shade: Color(white: 0.91),
                      highlight: Color(white: 0.98), edge: Color(white: 0.78))
        }
    }
}
