import SwiftUI
import VaultKit

/// Illustrated icon of an item type: a small, soft, slightly raised object (ID badge, passport,
/// legal pad, router...) lit from the top, drawn with shapes so it stays crisp from 16 to 128 pt.
/// Below 24 pt the small details (text lines, LEDs, stars) are dropped.
public struct CategoryArtwork: View {
    private let type: FfiItemType
    private let size: CGFloat
    private let monogram: String?

    public init(type: FfiItemType, size: CGFloat) {
        self.init(type: type, size: size, monogram: nil)
    }

    /// `monogram`: for logins only, a letter drawn on the tile in place of the keyhole.
    public init(type: FfiItemType, size: CGFloat, monogram: String?) {
        self.type = type
        self.size = size
        self.monogram = monogram.flatMap { m in
            m.trimmingCharacters(in: .whitespacesAndNewlines).first.map { String($0).uppercased() }
        }
    }

    public var body: some View {
        let k = ArtKit(size: size)
        ZStack(alignment: .topLeading) {
            if k.detailed { k.groundShadow }
            Art.drawing(type, k, monogram: monogram)
        }
        .frame(width: size, height: size, alignment: .topLeading)
        .accessibilityHidden(true)
    }
}

// MARK: - Kit

/// A color in sRGB components, so the art can derive its own lighter face and darker edge.
struct Tone: Sendable {
    let r: Double, g: Double, b: Double

    init(_ hex: UInt32) {
        r = Double((hex >> 16) & 0xFF) / 255
        g = Double((hex >> 8) & 0xFF) / 255
        b = Double(hex & 0xFF) / 255
    }

    init(r: Double, g: Double, b: Double) {
        self.r = r
        self.g = g
        self.b = b
    }

    static let white = Tone(0xFFFFFF)
    /// Shadow ink: a deep blue grey, so shaded edges stay colorful instead of muddy.
    static let ink = Tone(0x0F172A)

    func mix(_ o: Tone, _ t: Double) -> Tone {
        Tone(r: r + (o.r - r) * t, g: g + (o.g - g) * t, b: b + (o.b - b) * t)
    }

    func tint(_ t: Double) -> Tone { mix(.white, t) }
    func shade(_ t: Double) -> Tone { mix(.ink, t) }
    var c: Color { Color(red: r, green: g, blue: b) }
    var isPale: Bool { 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.88 }
}

/// Coordinates of every drawing live in a 100 x 100 box; `s` maps them to points.
@MainActor
struct ArtKit {
    let size: CGFloat
    var u: CGFloat { size / 100 }
    /// Text lines, LEDs and other small parts.
    var detailed: Bool { size >= 24 }
    /// Extra finesse that only reads on big icons.
    var rich: Bool { size >= 48 }

    func s(_ v: CGFloat) -> CGFloat { v * u }
    /// Height of the darker band under each raised part.
    var depth: CGFloat { max(s(4), 1) }
    var gloss: CGFloat { max(s(3), 0.75) }

    var groundShadow: some View {
        Ellipse()
            .fill(
                EllipticalGradient(
                    colors: [.black.opacity(0.16), .black.opacity(0)], center: .center,
                    startRadiusFraction: 0, endRadiusFraction: 0.5)
            )
            .at(self, 14, 85, 72, 11)
    }
}

extension View {
    /// Places the view in the 100 x 100 box of the drawing (x, y = top left corner).
    func at(_ k: ArtKit, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, rot: Double = 0) -> some View {
        frame(width: k.s(w), height: k.s(h))
            .rotationEffect(.degrees(rot))
            .position(x: k.s(x + w / 2), y: k.s(y + h / 2))
    }
}

/// A shape drawn in unit coordinates of its frame.
struct UPath: Shape {
    let build: @Sendable (inout Path, (CGFloat, CGFloat) -> CGPoint) -> Void

    func path(in r: CGRect) -> Path {
        var p = Path()
        build(&p) { x, y in CGPoint(x: r.minX + x * r.width, y: r.minY + y * r.height) }
        return p
    }

    static func poly(_ pts: [(CGFloat, CGFloat)]) -> UPath {
        UPath { p, m in
            p.addLines(pts.map { m($0.0, $0.1) })
            p.closeSubpath()
        }
    }

    static func star(points n: Int = 5, inner: CGFloat = 0.42) -> UPath {
        UPath { p, m in
            var pts: [CGPoint] = []
            for i in 0..<(n * 2) {
                let a = -Double.pi / 2 + Double(i) * .pi / Double(n)
                let rad = i.isMultiple(of: 2) ? 0.5 : 0.5 * inner
                pts.append(m(0.5 + rad * cos(a), 0.53 + rad * sin(a)))
            }
            p.addLines(pts)
            p.closeSubpath()
        }
    }

    static func gear(teeth n: Int) -> UPath {
        UPath { p, m in
            let step = 2 * Double.pi / Double(n)
            var pts: [CGPoint] = []
            for i in 0..<n {
                let a = -Double.pi / 2 + Double(i) * step
                for (da, rad) in [(-0.30, 0.41), (-0.17, 0.5), (0.17, 0.5), (0.30, 0.41)] {
                    pts.append(m(0.5 + rad * cos(a + da * step), 0.5 + rad * sin(a + da * step)))
                }
            }
            p.addLines(pts)
            p.closeSubpath()
        }
    }

    /// Shield: flat shoulders, rounded flanks, point at the bottom.
    static let shield = UPath { p, m in
        p.move(to: m(0.5, 0))
        p.addQuadCurve(to: m(1, 0.14), control: m(0.78, 0.12))
        p.addLine(to: m(1, 0.46))
        p.addCurve(to: m(0.5, 1), control1: m(1, 0.76), control2: m(0.74, 0.92))
        p.addCurve(to: m(0, 0.46), control1: m(0.26, 0.92), control2: m(0, 0.76))
        p.addLine(to: m(0, 0.14))
        p.addQuadCurve(to: m(0.5, 0), control: m(0.22, 0.12))
        p.closeSubpath()
    }
}

/// A raised part: darker band under it, a face lighter at the top, and a soft gloss on the top edge.
struct Slab<S: Shape>: View {
    let shape: S
    let tone: Tone
    let k: ArtKit
    var depth: CGFloat? = nil
    var gloss = true

    var body: some View {
        ZStack {
            shape.fill(tone.shade(0.32).c).offset(y: depth ?? k.depth)
            shape.fill(
                LinearGradient(
                    colors: [tone.tint(0.24).c, tone.c, tone.shade(0.05).c], startPoint: .top, endPoint: .bottom))
            if gloss {
                shape
                    .stroke(
                        LinearGradient(
                            colors: [.white.opacity(0.55), .white.opacity(0)], startPoint: .top,
                            endPoint: UnitPoint(x: 0.5, y: 0.4)),
                        lineWidth: k.gloss
                    )
                    .clipShape(shape)
            }
            if tone.isPale {
                // Hairline so white objects keep their edge on a white background.
                shape.stroke(Tone.ink.c.opacity(0.1), lineWidth: max(k.s(1), 0.5))
            }
        }
    }
}

@MainActor
extension ArtKit {
    func rr(_ r: CGFloat) -> RoundedRectangle { RoundedRectangle(cornerRadius: s(r), style: .continuous) }

    func slab<S: Shape>(
        _ shape: S, _ tone: Tone, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat,
        depth: CGFloat? = nil, gloss: Bool = true
    ) -> some View {
        Slab(shape: shape, tone: tone, k: self, depth: depth.map(s), gloss: gloss).at(self, x, y, w, h)
    }

    /// A flat rounded bar (text line, slot, stripe).
    func bar(_ color: Color, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, r: CGFloat? = nil) -> some View {
        rr(r ?? h / 2).fill(color).at(self, x, y, w, h)
    }

    func dot(_ color: Color, _ cx: CGFloat, _ cy: CGFloat, _ d: CGFloat) -> some View {
        Circle().fill(color).at(self, cx - d / 2, cy - d / 2, d, d)
    }

    func symbol(
        _ name: String, _ color: Color, _ pt: CGFloat, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat,
        weight: Font.Weight = .bold
    ) -> some View {
        Image(systemName: name)
            .font(.system(size: s(pt), weight: weight))
            .foregroundStyle(color)
            .at(self, x, y, w, h)
    }
}

// MARK: - Palette

/// One palette for the whole set: Tailwind 400 to 500 levels, so every icon has the same
/// saturation and lightness whatever the darker tile colors of `ItemCategory`.
enum Pal {
    static let teal = Tone(0x14B8A6)
    static let deepTeal = Tone(0x0F9488)
    static let pink = Tone(0xEC4899)
    static let rose = Tone(0xF43F5E)
    static let red = Tone(0xEF4444)
    static let orange = Tone(0xF97316)
    static let amber = Tone(0xF59E0B)
    static let gold = Tone(0xFBBF24)
    static let yellow = Tone(0xFCD34D)
    static let green = Tone(0x22C55E)
    static let emerald = Tone(0x10B981)
    static let cyan = Tone(0x06B6D4)
    static let sky = Tone(0x0EA5E9)
    static let lightBlue = Tone(0x60A5FA)
    static let blue = Tone(0x3B82F6)
    static let royal = Tone(0x2563EB)
    static let navy = Tone(0x4361D8)
    static let indigo = Tone(0x6366F1)
    static let violet = Tone(0x8B5CF6)
    static let purple = Tone(0xA855F7)
    static let periwinkle = Tone(0x6B83D6)
    static let slate = Tone(0x64748B)
    static let steel = Tone(0x94A3B8)
    static let charcoal = Tone(0x334155)
    static let paper = Tone(0xF5F7FA)
    static let tire = Tone(0x1F2937)
    static let glass = Tone(0xBAE6FD)
    static let lime = Tone(0x4ADE80)
}

// MARK: - Drawings

@MainActor
enum Art {
    static func drawing(_ type: FfiItemType, _ k: ArtKit, monogram: String?) -> AnyView {
        switch type {
        case .login: AnyView(login(k, monogram))
        case .password: AnyView(password(k))
        case .email: AnyView(email(k))
        case .server: AnyView(server(k))
        case .database: AnyView(database(k))
        case .router: AnyView(router(k))
        case .apiCredential: AnyView(api(k))
        case .sshKey: AnyView(ssh(k))
        case .creditCard: AnyView(creditCard(k))
        case .bankAccount: AnyView(bank(k))
        case .cryptoWallet: AnyView(crypto(k))
        case .subscription: AnyView(subscription(k))
        case .identity: AnyView(identity(k))
        case .idCard: AnyView(idCard(k))
        case .passport: AnyView(passport(k))
        case .driverLicense: AnyView(driverLicense(k))
        case .socialSecurityNumber: AnyView(ssn(k))
        case .medicalRecord: AnyView(medical(k))
        case .membership: AnyView(membership(k))
        case .rewardProgram: AnyView(reward(k))
        case .insurance: AnyView(insurance(k))
        case .vehicle: AnyView(vehicle(k))
        case .accessCode: AnyView(accessCode(k))
        case .secureNote: AnyView(secureNote(k))
        case .document: AnyView(document(k))
        case .softwareLicense: AnyView(softwareLicense(k))
        }
    }

    /// Teal tile with a keyhole, or the login's first letter.
    @ViewBuilder static func login(_ k: ArtKit, _ monogram: String?) -> some View {
        let t = Pal.teal
        k.slab(k.rr(22), t, 12, 12, 76, 74)
        if let monogram {
            Text(verbatim: monogram)
                .font(.system(size: k.s(44), weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .shadow(color: t.shade(0.45).c.opacity(0.55), radius: 0, y: k.s(2))
                .at(k, 12, 12, 76, 74)
        } else {
            let hole = t.shade(0.5).c
            k.dot(hole, 50, 42, 24)
            UPath.poly([(0.22, 0), (0.78, 0), (1, 1), (0, 1)]).fill(hole).at(k, 43, 46, 14, 24)
            if k.detailed {
                // Lower lip of the cut, lit from above.
                k.bar(.white.opacity(0.35), 43, 69, 14, 2.5)
            }
        }
    }

    /// Password field: four masked characters and a caret.
    @ViewBuilder static func password(_ k: ArtKit) -> some View {
        let t = Pal.deepTeal
        k.slab(k.rr(16), t, 8, 28, 84, 42)
        if k.detailed {
            ForEach(0..<4, id: \.self) { i in
                k.dot(.white, 24 + CGFloat(i) * 13, 49, 9)
            }
            k.bar(.white.opacity(0.85), 76, 39, 3.5, 20)
        } else {
            ForEach(0..<3, id: \.self) { i in
                k.dot(.white, 30 + CGFloat(i) * 20, 49, 13)
            }
        }
    }

    @ViewBuilder static func email(_ k: ArtKit) -> some View {
        let t = Pal.pink
        k.slab(k.rr(10), t, 10, 24, 80, 56)
        if k.detailed {
            // Lower folds.
            UPath { p, m in
                p.move(to: m(0.04, 0.95))
                p.addLine(to: m(0.42, 0.52))
                p.move(to: m(0.96, 0.95))
                p.addLine(to: m(0.58, 0.52))
            }
            .stroke(t.shade(0.18).c.opacity(0.6), style: StrokeStyle(lineWidth: k.s(2.5), lineCap: .round))
            .at(k, 10, 24, 80, 56)
        }
        // Flap, with its own shadow so it lifts off the body.
        UPath.poly([(0.02, 0.02), (0.98, 0.02), (0.5, 0.62)]).fill(t.shade(0.22).c.opacity(0.55))
            .at(k, 10, 27, 80, 56)
        UPath { p, m in
            p.move(to: m(0.03, 0))
            p.addLine(to: m(0.97, 0))
            p.addQuadCurve(to: m(0.5, 0.6), control: m(0.6, 0.5))
            p.addQuadCurve(to: m(0.03, 0), control: m(0.4, 0.5))
            p.closeSubpath()
        }
        .fill(LinearGradient(colors: [t.tint(0.42).c, t.tint(0.2).c], startPoint: .top, endPoint: .bottom))
        .at(k, 10, 24, 80, 56)
        k.dot(Pal.gold.c, 50, 55, 9)
    }

    @ViewBuilder static func server(_ k: ArtKit) -> some View {
        let t = Pal.slate
        ForEach(0..<3, id: \.self) { i in
            let y = 14 + CGFloat(i) * 25
            k.slab(k.rr(7), t, 12, y, 76, 19, depth: 3)
            k.dot(Pal.lime.c, 22, y + 9.5, k.detailed ? 6 : 9)
            if k.detailed {
                k.bar(.white.opacity(0.45), 56, y + 6, 24, 3)
                k.bar(.white.opacity(0.45), 56, y + 11, 24, 3)
            }
        }
    }

    @ViewBuilder static func database(_ k: ArtKit) -> some View {
        let t = Pal.periwinkle
        // Body with an elliptical bottom, shaded left to right like a can.
        UPath { p, m in
            p.move(to: m(0, 0.13))
            p.addLine(to: m(0, 0.87))
            p.addCurve(to: m(1, 0.87), control1: m(0, 1.04), control2: m(1, 1.04))
            p.addLine(to: m(1, 0.13))
            p.closeSubpath()
        }
        .fill(LinearGradient(colors: [t.tint(0.18).c, t.c, t.shade(0.22).c], startPoint: .leading, endPoint: .trailing))
        .at(k, 20, 10, 60, 78)
        if k.detailed {
            ForEach([0.4, 0.64], id: \.self) { y in
                UPath { p, m in
                    p.move(to: m(0, y))
                    p.addCurve(to: m(1, y), control1: m(0, y + 0.17), control2: m(1, y + 0.17))
                }
                .stroke(t.tint(0.4).c, style: StrokeStyle(lineWidth: k.s(2.5), lineCap: .round))
                .at(k, 20, 10, 60, 78)
            }
        }
        Ellipse().fill(LinearGradient(colors: [t.tint(0.5).c, t.tint(0.3).c], startPoint: .top, endPoint: .bottom))
            .at(k, 20, 10, 60, 20)
        if k.detailed {
            Ellipse().stroke(.white.opacity(0.45), lineWidth: k.gloss).at(k, 21, 11, 58, 18)
        }
    }

    @ViewBuilder static func router(_ k: ArtKit) -> some View {
        let w = Tone(0xF1F5F9)
        let wave = Pal.blue.c
        k.slab(k.rr(3), Pal.steel, 20, 24, 7, 32, depth: 0, gloss: false)
        k.slab(k.rr(3), Pal.steel, 73, 24, 7, 32, depth: 0, gloss: false)
        k.slab(k.rr(10), w, 8, 52, 84, 30, depth: 5)
        // Waves above the box: Circle().trim 0.625 to 0.875 is the top quarter.
        let arcs: [CGFloat] = k.detailed ? [15, 26] : [22]
        ForEach(arcs, id: \.self) { r in
            Circle().trim(from: 0.625, to: 0.875)
                .stroke(wave, style: StrokeStyle(lineWidth: k.s(k.detailed ? 5.5 : 8), lineCap: .round))
                .at(k, 50 - r, 46 - r, r * 2, r * 2)
        }
        k.dot(wave, 50, 44, k.detailed ? 8 : 10)
        if k.detailed {
            k.dot(Pal.green.c, 20, 67, 5)
            k.dot(Pal.blue.c, 29, 67, 5)
            k.dot(Pal.blue.c, 38, 67, 5)
            k.bar(Pal.steel.c.opacity(0.6), 56, 65.5, 26, 3)
        }
    }

    @ViewBuilder static func api(_ k: ArtKit) -> some View {
        let t = Pal.cyan
        k.slab(k.rr(20), t, 12, 13, 76, 72)
        k.symbol("curlybraces", .white, k.detailed ? 34 : 40, 12, 13, 76, k.detailed ? 60 : 72, weight: .heavy)
        if k.detailed {
            ForEach(0..<3, id: \.self) { i in
                k.dot(.white.opacity(0.75), 40 + CGFloat(i) * 10, 70, 5)
            }
        }
    }

    @ViewBuilder static func ssh(_ k: ArtKit) -> some View {
        let t = Pal.charcoal
        k.slab(k.rr(12), t, 8, 15, 84, 70)
        if k.detailed {
            UnevenRoundedRectangle(
                topLeadingRadius: k.s(12), bottomLeadingRadius: 0, bottomTrailingRadius: 0,
                topTrailingRadius: k.s(12), style: .continuous
            )
            .fill(t.tint(0.18).c)
            .at(k, 8, 15, 84, 14)
            k.dot(Tone(0xF87171).c, 18, 22, 5)
            k.dot(Pal.gold.c, 26, 22, 5)
            k.dot(Pal.lime.c, 34, 22, 5)
            Text(verbatim: ">_")
                .font(.system(size: k.s(30), weight: .heavy, design: .monospaced))
                .foregroundStyle(Pal.lime.c)
                .at(k, 14, 34, 56, 42)
        } else {
            Text(verbatim: ">_")
                .font(.system(size: k.s(40), weight: .heavy, design: .monospaced))
                .foregroundStyle(Pal.lime.c)
                .at(k, 8, 15, 84, 70)
        }
    }

    /// Card face shared by the card-like types.
    @ViewBuilder static func card(_ k: ArtKit, _ t: Tone) -> some View {
        k.slab(k.rr(9), t, 7, 22, 86, 56)
    }

    @ViewBuilder static func creditCard(_ k: ArtKit) -> some View {
        let t = Pal.lightBlue
        card(k, t)
        Rectangle().fill(t.shade(0.42).c).at(k, 7, 33, 86, 11)
        k.slab(k.rr(3), Pal.gold, 16, 51, 16, 12, depth: 1.5)
        if k.detailed {
            k.bar(Pal.gold.shade(0.25).c.opacity(0.6), 16, 56.3, 16, 1.4)
            ForEach(0..<4, id: \.self) { i in
                k.bar(.white.opacity(0.85), 40 + CGFloat(i) * 12.5, 55, 9, 4)
            }
            k.bar(.white.opacity(0.55), 16, 68, 30, 3.5)
        }
    }

    @ViewBuilder static func bank(_ k: ArtKit) -> some View {
        let t = Pal.amber
        k.slab(UPath.poly([(0.5, 0), (1, 1), (0, 1)]), t, 10, 10, 80, 24, depth: 0)
        k.bar(t.shade(0.2).c, 12, 34, 76, 6, r: 2)
        let cols: [CGFloat] = k.detailed ? [21, 37, 53, 69] : [24, 45, 66]
        let cw: CGFloat = k.detailed ? 10 : 10
        ForEach(cols, id: \.self) { x in
            k.slab(k.rr(2), t.tint(0.3), x, 41, cw, 32, depth: 0)
        }
        k.slab(k.rr(4), t, 8, 73, 84, 13)
        if k.detailed { k.dot(.white.opacity(0.85), 50, 25, 7) }
    }

    @ViewBuilder static func crypto(_ k: ArtKit) -> some View {
        let w = Pal.blue
        let coin = Pal.gold
        k.slab(Circle(), coin, 40, 6, 38, 38, depth: 2.5)
        k.symbol("bitcoinsign", coin.shade(0.35).c, 22, 40, 6, 38, 38, weight: .heavy)
        k.slab(k.rr(12), w, 8, 32, 84, 54)
        k.slab(k.rr(9), w.tint(0.12), 60, 47, 34, 24, depth: 2)
        k.dot(.white, 72, 59, 8)
    }

    @ViewBuilder static func subscription(_ k: ArtKit) -> some View {
        let t = Pal.purple
        k.slab(k.rr(12), Pal.paper, 12, 16, 76, 70)
        UnevenRoundedRectangle(
            topLeadingRadius: k.s(12), bottomLeadingRadius: 0, bottomTrailingRadius: 0, topTrailingRadius: k.s(12),
            style: .continuous
        )
        .fill(LinearGradient(colors: [t.tint(0.2).c, t.c], startPoint: .top, endPoint: .bottom))
        .at(k, 12, 16, 76, 22)
        k.bar(t.shade(0.45).c, 30, 9, 7, 16)
        k.bar(t.shade(0.45).c, 63, 9, 7, 16)
        k.symbol("arrow.triangle.2.circlepath", t.c, k.detailed ? 28 : 34, 12, 38, 76, 46, weight: .heavy)
    }

    /// Avatar on a white photo frame.
    static func avatar(_ k: ArtKit, _ t: Tone, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, round: Bool)
        -> some View
    {
        let wd = k.s(w)
        let ht = k.s(h)
        let shape = round ? AnyShape(Circle()) : AnyShape(k.rr(6))
        let fill = t.tint(0.08).c
        return ZStack {
            shape.fill(Color.white)
            Circle().fill(fill).frame(width: wd * 0.38, height: wd * 0.38).position(x: wd / 2, y: ht * 0.4)
            UPath { p, m in
                p.move(to: m(0, 1))
                p.addCurve(to: m(1, 1), control1: m(0, 0.0), control2: m(1, 0.0))
                p.closeSubpath()
            }
            .fill(fill)
            .frame(width: wd * 0.66, height: ht * 0.42)
            .position(x: wd / 2, y: ht * (0.64 + 0.21))
        }
        .frame(width: wd, height: ht)
        .clipShape(shape)
        .position(x: k.s(x + w / 2), y: k.s(y + h / 2))
    }

    @ViewBuilder static func identity(_ k: ArtKit) -> some View {
        let t = Pal.green
        k.slab(k.rr(12), t, 20, 17, 60, 72)
        avatar(k, t, 34, 28, 32, 32, round: true)
        if k.detailed {
            k.bar(.white.opacity(0.9), 31, 66, 38, 5)
            UPath { p, m in
                p.move(to: m(0, 0.7))
                p.addCurve(to: m(0.35, 0.4), control1: m(0.1, 0.1), control2: m(0.25, 0.1))
                p.addCurve(to: m(0.65, 0.5), control1: m(0.42, 0.9), control2: m(0.55, 0.9))
                p.addCurve(to: m(1, 0.35), control1: m(0.75, 0.15), control2: m(0.88, 0.2))
            }
            .stroke(.white.opacity(0.75), style: StrokeStyle(lineWidth: k.s(2.2), lineCap: .round))
            .at(k, 34, 74, 30, 9)
        }
        // Clip.
        k.slab(k.rr(4), Pal.steel, 38, 8, 24, 16, depth: 2)
        k.bar(Pal.charcoal.c.opacity(0.8), 43, 13.5, 14, 4)
    }

    @ViewBuilder static func idCard(_ k: ArtKit) -> some View {
        let t = Pal.emerald
        card(k, t)
        avatar(k, t, 15, 31, 27, 34, round: false)
        if k.detailed {
            k.bar(.white.opacity(0.9), 50, 35, 34, 5)
            k.bar(.white.opacity(0.65), 50, 46, 26, 5)
            k.bar(.white.opacity(0.65), 50, 57, 30, 5)
        }
    }

    @ViewBuilder static func passport(_ k: ArtKit) -> some View {
        let t = Pal.royal
        let g = Pal.yellow.c
        k.slab(k.rr(7), t, 20, 9, 60, 80)
        UnevenRoundedRectangle(
            topLeadingRadius: k.s(7), bottomLeadingRadius: k.s(7), bottomTrailingRadius: 0, topTrailingRadius: 0,
            style: .continuous
        )
        .fill(t.shade(0.22).c)
        .at(k, 20, 9, 8, 80)
        let lw = k.s(k.detailed ? 3.2 : 5)
        Circle().stroke(g, lineWidth: lw).at(k, 38, 25, 32, 32)
        Ellipse().stroke(g, lineWidth: lw).at(k, 47, 25, 14, 32)
        if k.detailed {
            k.bar(g, 38, 39.6, 32, 2.8)
            k.rr(2.5).stroke(g, lineWidth: k.s(2.6)).at(k, 47, 67, 14, 10)
        }
    }

    @ViewBuilder static func driverLicense(_ k: ArtKit) -> some View {
        let t = Pal.rose
        card(k, t)
        avatar(k, t, 15, 31, 27, 34, round: false)
        if k.detailed {
            k.symbol("car.fill", .white, 15, 50, 30, 30, 18)
            k.bar(.white.opacity(0.75), 50, 53, 34, 5)
            k.bar(.white.opacity(0.75), 50, 63, 24, 5)
        }
    }

    @ViewBuilder static func ssn(_ k: ArtKit) -> some View {
        let t = Pal.navy
        k.slab(UPath.shield, t, 17, 8, 66, 80)
        if k.detailed {
            ForEach(Array([(33.0, 34.0), (50.0, 28.0), (67.0, 34.0)].enumerated()), id: \.offset) { _, c in
                UPath.star().fill(Color.white).at(k, c.0 - 7.5, c.1 - 7.5, 15, 15)
            }
            k.bar(.white.opacity(0.85), 34, 50, 32, 5)
            k.bar(.white.opacity(0.6), 39, 60, 22, 5)
        } else {
            UPath.star().fill(Color.white).at(k, 31, 26, 38, 38)
        }
    }

    @ViewBuilder static func medical(_ k: ArtKit) -> some View {
        let t = Pal.red
        k.rr(7).stroke(t.shade(0.3).c, lineWidth: k.s(6)).at(k, 36, 13, 28, 22)
        k.slab(k.rr(14), t, 8, 25, 84, 61)
        k.slab(k.rr(3), Pal.paper, 43, 37, 14, 38, depth: 2, gloss: false)
        k.slab(k.rr(3), Pal.paper, 31, 49, 38, 14, depth: 2, gloss: false)
    }

    @ViewBuilder static func membership(_ k: ArtKit) -> some View {
        let t = Pal.violet
        card(k, t)
        UnevenRoundedRectangle(
            topLeadingRadius: 0, bottomLeadingRadius: k.s(9), bottomTrailingRadius: k.s(9), topTrailingRadius: 0,
            style: .continuous
        )
        .fill(t.shade(0.2).c)
        .at(k, 7, 66, 86, 12)
        k.dot(.white, 30, 44, 30)
        UPath.star().fill(Pal.gold.c).at(k, 19, 33, 22, 22)
        if k.detailed {
            k.bar(.white.opacity(0.9), 52, 35, 32, 5)
            k.bar(.white.opacity(0.65), 52, 46, 22, 5)
        }
    }

    @ViewBuilder static func reward(_ k: ArtKit) -> some View {
        let t = Tone(0xF472B6)
        let ribbon = Pal.gold
        k.slab(k.rr(6), t, 15, 45, 70, 42)
        k.bar(ribbon.c, 45, 45, 10, 42, r: 0)
        k.slab(k.rr(6), t.tint(0.08), 10, 32, 80, 17, depth: 3)
        k.bar(ribbon.tint(0.15).c, 45, 32, 10, 17, r: 0)
        Ellipse().fill(ribbon.c).at(k, 27, 15, 24, 16, rot: 28)
        Ellipse().fill(ribbon.c).at(k, 49, 15, 24, 16, rot: -28)
        if k.detailed {
            Ellipse().fill(ribbon.shade(0.25).c).at(k, 33, 20, 11, 6, rot: 28)
            Ellipse().fill(ribbon.shade(0.25).c).at(k, 56, 20, 11, 6, rot: -28)
        }
        k.dot(ribbon.shade(0.12).c, 50, 28, 11)
    }

    @ViewBuilder static func insurance(_ k: ArtKit) -> some View {
        let t = Pal.sky
        let pole = Pal.charcoal.c
        k.bar(pole, 48.25, 5, 3.5, 10)
        k.bar(pole, 48.25, 50, 3.5, 30, r: 1)
        Circle().trim(from: 0, to: 0.5)
            .stroke(pole, style: StrokeStyle(lineWidth: k.s(3.5), lineCap: .round))
            .at(k, 37.75, 72, 12.5, 12.5)
        let canopy = UPath { p, m in
            p.move(to: m(0, 0.78))
            p.addCurve(to: m(1, 0.78), control1: m(0, -0.2), control2: m(1, -0.2))
            for i in 0..<4 {
                let x0 = 1 - CGFloat(i) * 0.25
                p.addQuadCurve(to: m(x0 - 0.25, 0.78), control: m(x0 - 0.125, 0.58))
            }
            p.closeSubpath()
        }
        k.slab(canopy, t, 8, 12, 84, 48, depth: 3)
        if k.detailed {
            UPath { p, m in
                p.move(to: m(0.5, 0.04))
                p.addQuadCurve(to: m(0.25, 0.7), control: m(0.26, 0.2))
                p.move(to: m(0.5, 0.04))
                p.addQuadCurve(to: m(0.75, 0.7), control: m(0.74, 0.2))
            }
            .stroke(t.shade(0.2).c.opacity(0.55), style: StrokeStyle(lineWidth: k.s(2.2), lineCap: .round))
            .at(k, 8, 12, 84, 48)
        }
    }

    @ViewBuilder static func vehicle(_ k: ArtKit) -> some View {
        let t = Pal.orange
        k.slab(UPath.poly([(0.2, 0), (0.76, 0), (1, 1), (0, 1)]), t.tint(0.08), 22, 26, 54, 26, depth: 0)
        if k.detailed {
            UPath.poly([(0.3, 0), (1, 0), (1, 1), (0, 1)]).fill(Pal.glass.c).at(k, 29, 31, 18, 16)
            UPath.poly([(0, 0), (0.62, 0), (1, 1), (0, 1)]).fill(Pal.glass.c).at(k, 51, 31, 19, 16)
        } else {
            UPath.poly([(0.15, 0), (0.85, 0), (1, 1), (0, 1)]).fill(Pal.glass.c).at(k, 30, 31, 40, 16)
        }
        k.slab(k.rr(11), t, 6, 47, 88, 25)
        if k.detailed {
            k.bar(Pal.yellow.c, 85, 53, 6, 5)
            k.bar(Tone(0xB91C1C).c, 8, 53, 4, 6)
            k.bar(t.shade(0.2).c.opacity(0.6), 48, 52, 7, 2.5)
        }
        ForEach([29.0, 71.0], id: \.self) { cx in
            k.dot(Pal.tire.c, cx, 72, 22)
            k.dot(Pal.steel.tint(0.3).c, cx, 72, k.detailed ? 9 : 10)
        }
    }

    @ViewBuilder static func accessCode(_ k: ArtKit) -> some View {
        let t = Pal.indigo
        k.slab(k.rr(16), t, 18, 7, 64, 82)
        if k.detailed {
            k.bar(t.shade(0.42).c, 26, 15, 48, 14, r: 4)
            ForEach(0..<4, id: \.self) { i in
                k.dot(Pal.lime.c, 38 + CGFloat(i) * 8, 22, 4)
            }
            ForEach(0..<9, id: \.self) { i in
                k.dot(.white.opacity(0.92), 36 + CGFloat(i % 3) * 14, 42 + CGFloat(i / 3) * 14, 9)
            }
        } else {
            ForEach(0..<4, id: \.self) { i in
                k.dot(.white, 40 + CGFloat(i % 2) * 20, 38 + CGFloat(i / 2) * 22, 13)
            }
        }
    }

    @ViewBuilder static func secureNote(_ k: ArtKit) -> some View {
        let t = Pal.yellow
        k.slab(k.rr(6), t, 17, 14, 66, 75)
        let lines: [CGFloat] = k.detailed ? [36, 46, 56, 66, 76] : [40, 56, 72]
        ForEach(lines, id: \.self) { y in
            k.bar(Tone(0xD9A20A).c.opacity(0.55), 24, y, 52, k.detailed ? 2 : 4, r: 1)
        }
        if k.detailed {
            k.bar(Pal.red.c.opacity(0.55), 31, 22, 1.6, 64, r: 0.8)
        }
        k.slab(k.rr(4), Pal.slate, 13, 8, 74, 15, depth: 2.5)
    }

    @ViewBuilder static func document(_ k: ArtKit) -> some View {
        let page = Pal.paper
        k.slab(UPath.poly([(0, 0), (0.66, 0), (1, 0.25), (1, 1), (0, 1)]), page, 16, 8, 58, 80, depth: 4)
        UPath.poly([(0.66, 0), (0.66, 0.25), (1, 0.25)]).fill(Pal.steel.tint(0.25).c).at(k, 16, 8, 58, 80)
        if k.detailed {
            ForEach(Array([(24.0, 34.0, 30.0), (24.0, 44.0, 40.0), (24.0, 54.0, 34.0), (24.0, 64.0, 22.0)].enumerated()),
                id: \.offset) { _, l in
                k.bar(Pal.steel.tint(0.3).c, l.0, l.1, l.2, 4)
            }
        }
        nib(k).at(k, 54, 40, 30, 46, rot: 38)
    }

    /// Fountain pen nib: point down, slit and breather hole.
    static func nib(_ k: ArtKit) -> some View {
        let t = Pal.blue
        let body = UPath.poly([(0.5, 1), (0.04, 0.52), (0.2, 0.18), (0.8, 0.18), (0.96, 0.52)])
        return ZStack {
            body.fill(t.shade(0.3).c).offset(y: k.s(2.5))
            body.fill(LinearGradient(colors: [t.tint(0.22).c, t.c], startPoint: .top, endPoint: .bottom))
            if k.detailed {
                UPath { p, m in
                    p.move(to: m(0.5, 0.97))
                    p.addLine(to: m(0.5, 0.56))
                }
                .stroke(.white, style: StrokeStyle(lineWidth: k.s(2), lineCap: .round))
                Circle().fill(.white).frame(width: k.s(6), height: k.s(6)).position(x: k.s(15), y: k.s(46 * 0.52))
            }
            UnevenRoundedRectangle(
                topLeadingRadius: k.s(3), bottomLeadingRadius: 0, bottomTrailingRadius: 0, topTrailingRadius: k.s(3),
                style: .continuous
            )
            .fill(t.shade(0.25).c)
            .frame(width: k.s(20), height: k.s(9))
            .position(x: k.s(15), y: k.s(4.5))
        }
    }

    @ViewBuilder static func softwareLicense(_ k: ArtKit) -> some View {
        let t = Pal.blue
        k.slab(UPath.gear(teeth: 8), t, 10, 7, 80, 80)
        k.dot(t.shade(0.3).c, 50, 49, 42)
        k.dot(.white, 50, 47, 40)
        k.symbol("checkmark", Pal.green.c, k.detailed ? 20 : 24, 30, 27, 40, 40, weight: .black)
    }
}

#Preview("CategoryArtwork") {
    LazyVGrid(columns: Array(repeating: GridItem(.fixed(72)), count: 7), spacing: 12) {
        ForEach(ItemCategory.all) { c in
            CategoryArtwork(type: c.type, size: 64)
        }
    }
    .padding()
}
