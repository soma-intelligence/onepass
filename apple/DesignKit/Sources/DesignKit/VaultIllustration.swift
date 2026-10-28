import SwiftUI

/// The empty detail column's picture: a vault door seen face on, with a graduated dial ring, a
/// six-arm wheel and a keyhole that glows in the accent, a key, a card and a padlock floating
/// around it, and a few sparkles. One light from the top left: brushed faces, bevels catching
/// it, soft drop shadows, a faint accent rim on the far side. Original artwork, all shapes.
public struct VaultIllustration: View {
    private let size: CGFloat
    private let tint: Color
    @Environment(\.colorScheme) private var scheme

    public init(size: CGFloat = 320, tint: Color = Color(red: 0.37, green: 0.36, blue: 0.90)) {
        self.size = size
        self.tint = tint
    }

    private var dark: Bool { scheme == .dark }
    private var ink: Color { dark ? .white : .black }
    /// Opaque ground under the translucent faces, close to the page.
    private var base: Color { dark ? Color(white: 0.14) : Color(white: 0.965) }
    private var shadow: Color { .black.opacity(dark ? 0.6 : 0.14) }

    /// A face lit from the top left.
    private func face(_ lit: Double, _ shade: Double) -> LinearGradient {
        LinearGradient(colors: [ink.opacity(lit), ink.opacity(shade)], startPoint: .topLeading, endPoint: .bottomTrailing)
    }
    /// A bevel: bright where the light hits, gone on the far side.
    private func bevel(_ strength: Double = 1) -> LinearGradient {
        LinearGradient(colors: [ink.opacity((dark ? 0.3 : 0.16) * strength), ink.opacity(0.03), ink.opacity(0.0)],
            startPoint: .topLeading, endPoint: .bottomTrailing)
    }
    /// The far side's edge, catching a little of the accent.
    private var accentRim: LinearGradient {
        LinearGradient(colors: [.clear, .clear, tint.opacity(dark ? 0.55 : 0.35)],
            startPoint: .topLeading, endPoint: .bottomTrailing)
    }
    private var accentFill: LinearGradient {
        LinearGradient(colors: [tint.mix(with: .white, by: 0.45), tint, tint.mix(with: .black, by: 0.15)],
            startPoint: .top, endPoint: .bottom)
    }

    public var body: some View {
        let u = size / 100
        ZStack {
            Circle()
                .fill(RadialGradient(colors: [tint.opacity(dark ? 0.2 : 0.1), tint.opacity(0.03), .clear],
                    center: .center, startRadius: 0, endRadius: u * 52))
                .frame(width: u * 104, height: u * 104)

            card(u: u).rotationEffect(.degrees(-15)).offset(x: u * 33, y: -u * 19)
            key(u: u).rotationEffect(.degrees(-36)).offset(x: -u * 34, y: -u * 19)

            door(u: u)

            padlock(u: u).rotationEffect(.degrees(-10)).offset(x: -u * 28, y: u * 26)

            sparkle(u: u, side: 4.4).offset(x: u * 37, y: u * 23)
            sparkle(u: u, side: 2.8).offset(x: u * 25, y: -u * 35)
            sparkle(u: u, side: 2.1).offset(x: -u * 40, y: u * 6)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    // MARK: - Door

    private func door(u: CGFloat) -> some View {
        ZStack {
            // Long soft shadow, then the frame.
            Circle()
                .fill(shadow)
                .frame(width: u * 64, height: u * 64)
                .blur(radius: u * 5)
                .offset(x: u * 2, y: u * 5)
            Circle()
                .fill(base)
                .overlay { Circle().fill(face(0.12, 0.03)) }
                .overlay { Circle().strokeBorder(bevel(1.2), lineWidth: max(1, u * 0.45)) }
                .overlay { Circle().strokeBorder(accentRim, lineWidth: max(1, u * 0.35)) }
                .frame(width: u * 64, height: u * 64)
            // Graduated dial ring, majors a little brighter.
            ForEach(0..<72, id: \.self) { i in
                let major = i.isMultiple(of: 6)
                Capsule()
                    .fill(ink.opacity(major ? 0.26 : 0.1))
                    .frame(width: u * (major ? 0.5 : 0.3), height: u * (major ? 2.2 : 1.2))
                    .offset(y: -u * 28.7)
                    .rotationEffect(.degrees(Double(i) * 5))
            }
            // A fine groove between the ring and the door.
            Circle()
                .strokeBorder(ink.opacity(dark ? 0.06 : 0.05), lineWidth: max(0.5, u * 0.2))
                .frame(width: u * 53.5, height: u * 53.5)
            // Recessed door: lit edge at the bottom right (set back), brushed face.
            Circle()
                .fill(base)
                .overlay {
                    Circle().fill(AngularGradient(colors: [
                        ink.opacity(0.05), ink.opacity(0.09), ink.opacity(0.04), ink.opacity(0.08), ink.opacity(0.05),
                    ], center: .center))
                }
                .overlay {
                    Circle().strokeBorder(LinearGradient(colors: [.black.opacity(dark ? 0.7 : 0.18), .clear, ink.opacity(0.14)],
                        startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: u * 0.9)
                }
                .frame(width: u * 50, height: u * 50)
            // Specular sheen across the upper left of the door.
            Circle()
                .trim(from: 0.55, to: 0.8)
                .stroke(LinearGradient(colors: [.clear, Color.white.opacity(dark ? 0.16 : 0.95), .clear],
                    startPoint: .leading, endPoint: .trailing), style: StrokeStyle(lineWidth: u * 0.6, lineCap: .round))
                .frame(width: u * 45, height: u * 45)
            wheel(u: u)
        }
    }

    private func wheel(u: CGFloat) -> some View {
        ZStack {
            ForEach(0..<3, id: \.self) { i in
                ZStack {
                    Capsule()
                        .fill(base)
                        .overlay { Capsule().fill(LinearGradient(colors: [ink.opacity(0.08), ink.opacity(0.26), ink.opacity(0.08)],
                            startPoint: .leading, endPoint: .trailing)) }
                        .frame(width: u * 2.2, height: u * 37)
                    VStack {
                        grip(u: u)
                        Spacer()
                        grip(u: u)
                    }
                    .frame(height: u * 40)
                }
                .rotationEffect(.degrees(Double(i) * 60 + 30))
            }
            .shadow(color: shadow.opacity(0.7), radius: u * 1.2, x: u * 0.5, y: u * 1)
            // Hub with a knurled edge.
            Circle()
                .fill(base)
                .overlay { Circle().fill(face(0.28, 0.08)) }
                .overlay { Circle().strokeBorder(bevel(1.4), lineWidth: max(1, u * 0.35)) }
                .frame(width: u * 15, height: u * 15)
                .shadow(color: shadow, radius: u * 2, x: u * 0.6, y: u * 1.5)
            ForEach(0..<36, id: \.self) { i in
                Capsule()
                    .fill(ink.opacity(0.1))
                    .frame(width: u * 0.22, height: u * 0.9)
                    .offset(y: -u * 6.6)
                    .rotationEffect(.degrees(Double(i) * 10))
            }
            // The keyhole's well, the accent glowing from inside.
            Circle()
                .fill(LinearGradient(colors: [.black.opacity(dark ? 0.35 : 0.1), ink.opacity(0.06)],
                    startPoint: .top, endPoint: .bottom))
                .overlay { Circle().strokeBorder(LinearGradient(colors: [.black.opacity(0.5), ink.opacity(0.15)],
                    startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: max(0.5, u * 0.3)) }
                .frame(width: u * 9.6, height: u * 9.6)
            keyhole(u: u, scale: 1)
        }
    }

    private func grip(u: CGFloat) -> some View {
        Circle()
            .fill(base)
            .overlay { Circle().fill(face(0.34, 0.1)) }
            .overlay { Circle().strokeBorder(bevel(1.3), lineWidth: max(0.5, u * 0.25)) }
            // Specular dot.
            .overlay(alignment: .topLeading) {
                Circle().fill(Color.white.opacity(dark ? 0.35 : 0.9)).frame(width: u * 1.1, height: u * 1.1)
                    .blur(radius: u * 0.3).padding(u * 1)
            }
            .frame(width: u * 5, height: u * 5)
    }

    /// The keyhole as an actual cut, lit in the accent from inside: its upper edge in shadow,
    /// its lower edge catching the light, a soft halo of the accent around it.
    private func keyhole(u: CGFloat, scale: CGFloat) -> some View {
        let shape = KeyholeShape()
        return shape
            // Lit in the accent from inside: deep at the top, brighter toward the foot.
            .fill(LinearGradient(colors: [tint.mix(with: .black, by: 0.55), tint, tint.mix(with: .white, by: 0.35)],
                startPoint: .top, endPoint: .bottom))
            .overlay {
                shape.stroke(LinearGradient(colors: [.black.opacity(0.8), .clear, ink.opacity(dark ? 0.35 : 0.6)],
                    startPoint: .top, endPoint: .bottom), lineWidth: max(0.5, u * 0.25 * scale))
            }
            .frame(width: u * 3.6 * scale, height: u * 6.2 * scale)
            .shadow(color: tint.opacity(0.55), radius: u * 1.4 * scale)
    }

    // MARK: - Floating pieces

    private func plate(u: CGFloat, width: CGFloat, height: CGFloat, radius: CGFloat) -> some View {
        let shape = RoundedRectangle(cornerRadius: u * radius, style: .continuous)
        return shape
            .fill(base)
            .overlay { shape.fill(face(0.15, 0.04)) }
            .overlay { shape.strokeBorder(bevel(1.2), lineWidth: max(0.5, u * 0.3)) }
            .frame(width: u * width, height: u * height)
            .shadow(color: shadow, radius: u * 3.5, x: u * 1, y: u * 2.5)
    }

    private func card(u: CGFloat) -> some View {
        plate(u: u, width: 25, height: 16, radius: 2.4)
            .overlay(alignment: .topLeading) {
                VStack(alignment: .leading, spacing: u * 2) {
                    // Chip with its contact lines.
                    RoundedRectangle(cornerRadius: u * 0.7, style: .continuous)
                        .fill(accentFill)
                        .overlay {
                            VStack(spacing: u * 0.55) {
                                ForEach(0..<3, id: \.self) { _ in Rectangle().fill(.white.opacity(0.25)).frame(height: u * 0.15) }
                            }
                            .padding(.horizontal, u * 0.6)
                        }
                        .frame(width: u * 4.6, height: u * 3.4)
                    HStack(spacing: u * 1.2) {
                        ForEach(0..<4, id: \.self) { _ in
                            HStack(spacing: u * 0.45) {
                                ForEach(0..<4, id: \.self) { _ in Circle().fill(ink.opacity(0.22)).frame(width: u * 0.6) }
                            }
                        }
                    }
                }
                .padding(u * 2.6)
            }
    }

    /// A plain machined key: one flat piece (rounded bow with its hole, collar, blade with a cut
    /// bit), brushed along its length, a thin lit edge on top. Drawn as a single path.
    private func key(u: CGFloat) -> some View {
        let shape = KeyShape()
        return shape
            .fill(base, style: FillStyle(eoFill: true))
            .overlay {
                shape.fill(LinearGradient(colors: [ink.opacity(dark ? 0.26 : 0.16), ink.opacity(dark ? 0.1 : 0.05)],
                    startPoint: .top, endPoint: .bottom), style: FillStyle(eoFill: true))
            }
            .overlay {
                shape.stroke(LinearGradient(colors: [ink.opacity(dark ? 0.35 : 0.2), ink.opacity(0.02)],
                    startPoint: .top, endPoint: .bottom), lineWidth: max(0.5, u * 0.22))
            }
            .frame(width: u * 26, height: u * 10)
            .shadow(color: shadow, radius: u * 2.5, x: u * 0.8, y: u * 2)
    }

    private func padlock(u: CGFloat) -> some View {
        ZStack(alignment: .top) {
            // Shackle: a U with straight legs going into the body.
            Shackle()
                .stroke(LinearGradient(colors: [ink.opacity(0.4), ink.opacity(0.14)], startPoint: .leading, endPoint: .trailing),
                    style: StrokeStyle(lineWidth: u * 1.7, lineCap: .round))
                .frame(width: u * 8, height: u * 8)
            plate(u: u, width: 13.5, height: 10.5, radius: 2.4)
                .overlay { keyhole(u: u, scale: 0.55) }
                .offset(y: u * 6)
        }
        .frame(width: u * 13.5, height: u * 16.5)
    }

    private func sparkle(u: CGFloat, side: CGFloat) -> some View {
        Image(systemName: "sparkle")
            .font(.system(size: u * side, weight: .medium))
            .foregroundStyle(LinearGradient(colors: [tint.mix(with: .white, by: 0.55), tint.mix(with: .white, by: 0.15)],
                startPoint: .top, endPoint: .bottom))
            .shadow(color: tint.opacity(0.7), radius: u * 1.2)
    }
}

/// The keyhole's slot: wider at the bottom, rounded foot.
private struct Trapezoid: Shape {
    func path(in rect: CGRect) -> Path {
        let inset = rect.width * 0.22
        var p = Path()
        p.move(to: CGPoint(x: rect.minX + inset, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX - inset, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - rect.width * 0.25))
        p.addQuadCurve(to: CGPoint(x: rect.maxX - rect.width * 0.25, y: rect.maxY), control: CGPoint(x: rect.maxX, y: rect.maxY))
        p.addLine(to: CGPoint(x: rect.minX + rect.width * 0.25, y: rect.maxY))
        p.addQuadCurve(to: CGPoint(x: rect.minX, y: rect.maxY - rect.width * 0.25), control: CGPoint(x: rect.minX, y: rect.maxY))
        p.closeSubpath()
        return p
    }
}

/// A padlock's shackle: two legs joined by a half circle on top.
private struct Shackle: Shape {
    func path(in rect: CGRect) -> Path {
        let r = rect.width / 2
        var p = Path()
        p.move(to: CGPoint(x: rect.minX, y: rect.maxY))
        p.addLine(to: CGPoint(x: rect.minX, y: rect.minY + r))
        p.addArc(center: CGPoint(x: rect.midX, y: rect.minY + r), radius: r,
            startAngle: .degrees(180), endAngle: .degrees(0), clockwise: false)
        p.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        return p
    }
}

/// A classic keyhole: round head over a slot that widens slightly to a flat foot.
private struct KeyholeShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let head = w / 2
        var p = Path()
        p.addEllipse(in: CGRect(x: rect.midX - head, y: rect.minY, width: w, height: w))
        let top = rect.minY + w * 0.75
        p.move(to: CGPoint(x: rect.midX - w * 0.2, y: top))
        p.addLine(to: CGPoint(x: rect.midX + w * 0.2, y: top))
        p.addLine(to: CGPoint(x: rect.midX + w * 0.34, y: rect.maxY))
        p.addLine(to: CGPoint(x: rect.midX - w * 0.34, y: rect.maxY))
        p.closeSubpath()
        return p
    }
}

/// A key seen flat, bow on the left: the bow's hole is a second subpath (even-odd fill).
private struct KeyShape: Shape {
    func path(in rect: CGRect) -> Path {
        let h = rect.height
        let bowR = h * 0.5
        let bowC = CGPoint(x: rect.minX + bowR, y: rect.midY)
        let blade = h * 0.22
        var p = Path()
        // Bow, slightly squared like a real one.
        p.addRoundedRect(in: CGRect(x: rect.minX, y: rect.minY, width: bowR * 2, height: h),
            cornerSize: CGSize(width: bowR * 0.8, height: bowR * 0.8), style: .continuous)
        // Collar and blade, with the bit's cuts on the lower edge near the tip.
        let x0 = rect.minX + bowR * 1.85
        let tip = rect.maxX
        var b = Path()
        b.move(to: CGPoint(x: x0, y: rect.midY - blade * 1.2))
        b.addLine(to: CGPoint(x: x0 + h * 0.35, y: rect.midY - blade * 1.2))
        b.addLine(to: CGPoint(x: x0 + h * 0.45, y: rect.midY - blade / 2))
        b.addLine(to: CGPoint(x: tip - h * 0.12, y: rect.midY - blade / 2))
        b.addQuadCurve(to: CGPoint(x: tip, y: rect.midY), control: CGPoint(x: tip, y: rect.midY - blade / 2))
        // Bit: a small plate under the blade near the tip, with two cuts.
        let bitTop = rect.midY + blade / 2
        let bx = tip - h * 0.18
        let depth = h * 0.3
        let profile: [(CGFloat, CGFloat)] = [
            (0, 0), (0, depth), (-h * 0.1, depth), (-h * 0.1, depth * 0.55), (-h * 0.2, depth * 0.55),
            (-h * 0.2, depth), (-h * 0.34, depth), (-h * 0.34, 0),
        ]
        for (dx, dy) in profile {
            b.addLine(to: CGPoint(x: bx + dx, y: bitTop + dy))
        }
        b.addLine(to: CGPoint(x: x0 + h * 0.45, y: bitTop))
        b.addLine(to: CGPoint(x: x0 + h * 0.35, y: rect.midY + blade * 1.2))
        b.addLine(to: CGPoint(x: x0, y: rect.midY + blade * 1.2))
        b.closeSubpath()
        p.addPath(b)
        // The hole (even-odd): a second subpath inside the bow.
        p.addEllipse(in: CGRect(x: bowC.x - bowR * 0.42, y: bowC.y - bowR * 0.42, width: bowR * 0.84, height: bowR * 0.84))
        return p
    }
}
