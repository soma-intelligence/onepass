import SwiftUI

/// The empty detail column's picture: a vault door seen face on, with a graduated dial ring, a
/// six-arm wheel and a keyhole that glows in the accent, a few credentials floating behind it
/// (card, key, padlock) and small sparkles. Soft light from above: gradient faces, hairline
/// highlights, drop shadows, no hard outlines. Original artwork, drawn entirely in shapes.
public struct VaultIllustration: View {
    private let size: CGFloat
    private let tint: Color
    @Environment(\.colorScheme) private var scheme

    public init(size: CGFloat = 320, tint: Color = Color(red: 0.37, green: 0.36, blue: 0.90)) {
        self.size = size
        self.tint = tint
    }

    private var dark: Bool { scheme == .dark }
    /// Face of a surface lit from above: lighter top, darker bottom.
    private func face(_ top: Double, _ bottom: Double) -> LinearGradient {
        let ink: Color = dark ? .white : .black
        return LinearGradient(colors: [ink.opacity(top), ink.opacity(bottom)], startPoint: .top, endPoint: .bottom)
    }
    /// The rim catching the light on top and fading out below.
    private func rim(_ strength: Double = 1) -> LinearGradient {
        let ink: Color = dark ? .white : .black
        return LinearGradient(colors: [ink.opacity((dark ? 0.22 : 0.12) * strength), ink.opacity(0.02)],
            startPoint: .top, endPoint: .bottom)
    }
    /// Opaque ground under the translucent faces, close to the page.
    private var base: Color { dark ? Color(white: 0.135) : Color(white: 0.965) }
    private var shadow: Color { .black.opacity(dark ? 0.55 : 0.12) }

    public var body: some View {
        let u = size / 100
        ZStack {
            // Accent glow behind everything.
            Circle()
                .fill(RadialGradient(colors: [tint.opacity(dark ? 0.22 : 0.12), .clear],
                    center: .center, startRadius: 0, endRadius: u * 50))
                .frame(width: u * 100, height: u * 100)

            card(u: u).rotationEffect(.degrees(-16)).offset(x: u * 33, y: -u * 19)
            key(u: u).rotationEffect(.degrees(-38)).offset(x: -u * 35, y: -u * 18)
            door(u: u)

            padlock(u: u).rotationEffect(.degrees(-9)).offset(x: -u * 27, y: u * 25)

            sparkle(u: u, side: 4.2).offset(x: u * 36, y: u * 22)
            sparkle(u: u, side: 2.8).offset(x: u * 24, y: -u * 34)
            sparkle(u: u, side: 2.2).offset(x: -u * 38, y: u * 6)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    // MARK: - Door

    private func door(u: CGFloat) -> some View {
        ZStack {
            // Frame, on an opaque base so nothing behind shows through.
            Circle()
                .fill(base)
                .overlay { Circle().fill(face(0.11, 0.03)) }
                .overlay { Circle().strokeBorder(rim(), lineWidth: max(1, u * 0.35)) }
                .frame(width: u * 64, height: u * 64)
                .shadow(color: shadow, radius: u * 6, y: u * 4)
            // Graduated dial ring.
            ForEach(0..<60, id: \.self) { i in
                let major = i.isMultiple(of: 5)
                Capsule()
                    .fill((dark ? Color.white : .black).opacity(major ? 0.22 : 0.09))
                    .frame(width: u * (major ? 0.55 : 0.35), height: u * (major ? 2.4 : 1.4))
                    .offset(y: -u * 28.6)
                    .rotationEffect(.degrees(Double(i) * 6))
            }
            // Recessed door: darker on top, as if set back.
            Circle()
                .fill(face(0.015, 0.075))
                .overlay { Circle().strokeBorder(LinearGradient(colors: [.black.opacity(dark ? 0.6 : 0.15), .clear],
                    startPoint: .top, endPoint: .bottom), lineWidth: u * 0.8) }
                .frame(width: u * 50, height: u * 50)
            wheel(u: u)
        }
    }

    private func wheel(u: CGFloat) -> some View {
        ZStack {
            ForEach(0..<3, id: \.self) { i in
                ZStack {
                    Capsule()
                        .fill(base)
                        .overlay { Capsule().fill(face(0.24, 0.08)) }
                        .overlay { Capsule().strokeBorder(rim(0.8), lineWidth: max(0.5, u * 0.2)) }
                        .frame(width: u * 2.6, height: u * 38)
                    // Grips.
                    VStack {
                        grip(u: u)
                        Spacer()
                        grip(u: u)
                    }
                    .frame(height: u * 40)
                }
                .rotationEffect(.degrees(Double(i) * 60 + 30))
                .shadow(color: shadow.opacity(0.6), radius: u * 1.5, y: u * 1)
            }
            // Hub.
            Circle()
                .fill(base)
                .overlay { Circle().fill(face(0.26, 0.09)) }
                .overlay { Circle().strokeBorder(rim(1.2), lineWidth: max(1, u * 0.3)) }
                .frame(width: u * 15, height: u * 15)
                .shadow(color: shadow, radius: u * 2, y: u * 1.5)
            Circle()
                .fill(face(0.04, 0.14))
                .frame(width: u * 9.5, height: u * 9.5)
            keyhole(u: u, scale: 1)
        }
    }

    private func grip(u: CGFloat) -> some View {
        Circle()
            .fill(base)
            .overlay { Circle().fill(face(0.3, 0.1)) }
            .overlay { Circle().strokeBorder(rim(1.1), lineWidth: max(0.5, u * 0.25)) }
            .frame(width: u * 5.2, height: u * 5.2)
    }

    /// The keyhole in the accent, lit from inside.
    private func keyhole(u: CGFloat, scale: CGFloat) -> some View {
        let fill = LinearGradient(colors: [tint.mix(with: .white, by: 0.35), tint], startPoint: .top, endPoint: .bottom)
        return VStack(spacing: -u * 0.5 * scale) {
            Circle().fill(fill).frame(width: u * 3.2 * scale, height: u * 3.2 * scale)
            UnevenRoundedRectangle(topLeadingRadius: u * 0.2, bottomLeadingRadius: u * 0.6,
                    bottomTrailingRadius: u * 0.6, topTrailingRadius: u * 0.2)
                .fill(fill)
                .frame(width: u * 1.8 * scale, height: u * 3.4 * scale)
        }
        .shadow(color: tint.opacity(0.8), radius: u * 2 * scale)
    }

    // MARK: - Floating pieces

    private func glassTile(u: CGFloat, width: CGFloat, height: CGFloat, radius: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: u * radius, style: .continuous)
            .fill(base)
            .overlay { RoundedRectangle(cornerRadius: u * radius, style: .continuous).fill(face(0.13, 0.04)) }
            .overlay { RoundedRectangle(cornerRadius: u * radius, style: .continuous).strokeBorder(rim(), lineWidth: max(0.5, u * 0.25)) }
            .frame(width: u * width, height: u * height)
            .shadow(color: shadow, radius: u * 3, y: u * 2)
    }

    private func card(u: CGFloat) -> some View {
        glassTile(u: u, width: 24, height: 15.5, radius: 2.4)
            .overlay(alignment: .topLeading) {
                VStack(alignment: .leading, spacing: u * 1.6) {
                    RoundedRectangle(cornerRadius: u * 0.6)
                        .fill(LinearGradient(colors: [tint.mix(with: .white, by: 0.3), tint], startPoint: .top, endPoint: .bottom))
                        .frame(width: u * 4.6, height: u * 3.4)
                    HStack(spacing: u * 1.1) {
                        ForEach(0..<4, id: \.self) { _ in
                            Capsule().fill((dark ? Color.white : .black).opacity(0.16)).frame(width: u * 3, height: u * 0.9)
                        }
                    }
                }
                .padding(u * 2.6)
            }
    }

    private func key(u: CGFloat) -> some View {
        let ink: Color = dark ? .white : .black
        return HStack(spacing: -u * 0.4) {
            Circle()
                .fill(base)
                .overlay { Circle().fill(face(0.16, 0.05)) }
                .overlay { Circle().strokeBorder(rim(), lineWidth: max(0.5, u * 0.25)) }
                .overlay { Circle().fill(dark ? Color(white: 0.13) : Color(white: 0.96)).frame(width: u * 3, height: u * 3) }
                .frame(width: u * 9, height: u * 9)
            ZStack(alignment: .bottomTrailing) {
                Capsule().fill(base).overlay { Capsule().fill(face(0.16, 0.06)) }.frame(width: u * 13, height: u * 2.4)
                HStack(spacing: u * 1) {
                    Rectangle().fill(ink.opacity(0.12)).frame(width: u * 1.2, height: u * 2.2)
                    Rectangle().fill(ink.opacity(0.12)).frame(width: u * 1.2, height: u * 3)
                }
                .offset(x: -u * 1, y: u * 2.4)
            }
        }
        .shadow(color: shadow, radius: u * 3, y: u * 2)
    }

    private func padlock(u: CGFloat) -> some View {
        VStack(spacing: -u * 1.2) {
            Circle()
                .trim(from: 0.5, to: 1)
                .stroke(face(0.2, 0.08), style: StrokeStyle(lineWidth: u * 1.8, lineCap: .round))
                .frame(width: u * 8.5, height: u * 8.5)
                .offset(y: u * 2.2)
            glassTile(u: u, width: 13, height: 10.5, radius: 2.2)
                .overlay { keyhole(u: u, scale: 0.55) }
        }
    }

    private func sparkle(u: CGFloat, side: CGFloat) -> some View {
        Image(systemName: "sparkle")
            .font(.system(size: u * side, weight: .medium))
            .foregroundStyle(tint.mix(with: .white, by: 0.3).opacity(0.75))
            .shadow(color: tint.opacity(0.6), radius: u * 1)
    }
}
