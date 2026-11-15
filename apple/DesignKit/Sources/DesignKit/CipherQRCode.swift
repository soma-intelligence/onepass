#if !os(watchOS)
import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// The modules of a QR code, read from CoreImage's generator: `side` modules a side, no quiet zone.
public struct QRMatrix: Equatable, Sendable {
    public let side: Int
    let dark: [Bool]

    /// Error correction Q (25%): the mark drawn over the middle hides a few modules.
    public init?(text: String, correction: String = "Q") {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = correction
        guard let raw = filter.outputImage else { return nil }
        let extent = raw.extent.integral
        let width = Int(extent.width), height = Int(extent.height)
        guard width > 0, height > 0, let space = CGColorSpace(name: CGColorSpace.sRGB),
            let image = CIContext(options: [.useSoftwareRenderer: true]).createCGImage(raw, from: extent),
            let context = CGContext(
                data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4, space: space,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
            let pixels = context.data?.bindMemory(to: UInt8.self, capacity: width * height * 4)
        else { return nil }
        context.interpolationQuality = .none
        context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
        // The generator leaves a white margin: the code is the box of the dark pixels (its three
        // finder patterns reach three corners). The bitmap's rows run top-down, like the image's.
        func isDark(_ x: Int, _ y: Int) -> Bool { pixels[(y * width + x) * 4] < 128 }
        var minX = width, minY = height, maxX = -1, maxY = -1
        for y in 0..<height {
            for x in 0..<width where isDark(x, y) {
                minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y)
            }
        }
        guard maxX >= minX, maxX - minX == maxY - minY, maxX - minX + 1 >= 21 else { return nil }
        let side = maxX - minX + 1
        var dark = [Bool](repeating: false, count: side * side)
        for y in 0..<side {
            for x in 0..<side { dark[y * side + x] = isDark(minX + x, minY + y) }
        }
        self.side = side
        self.dark = dark
    }

    func isDark(_ x: Int, _ y: Int) -> Bool { dark[y * side + x] }

    /// Inside one of the three 7 x 7 finder patterns (drawn as one rounded eye each).
    func isFinder(_ x: Int, _ y: Int) -> Bool {
        (x < 7 && y < 7) || (x >= side - 7 && y < 7) || (x < 7 && y >= side - 7)
    }

    /// Centers of the three finder patterns, in modules.
    var eyes: [(x: Double, y: Double)] {
        [(3.5, 3.5), (Double(side) - 3.5, 3.5), (3.5, Double(side) - 3.5)]
    }

    private final class Box { let matrix: QRMatrix; init(_ matrix: QRMatrix) { self.matrix = matrix } }
    nonisolated(unsafe) private static let cache: NSCache<NSString, Box> = {
        let cache = NSCache<NSString, Box>()
        cache.countLimit = 8
        return cache
    }()

    /// The matrix of `text`, kept for the redraws of an animation.
    static func cached(_ text: String) -> QRMatrix? {
        if let hit = cache.object(forKey: text as NSString) { return hit.matrix }
        guard let matrix = QRMatrix(text: text) else { return nil }
        cache.setObject(Box(matrix), forKey: text as NSString)
        return matrix
    }
}

/// A pairing code on its white tile, as one object through the three moments of a pairing:
///
/// - `code`: the QR in round dots with the OnePass mark in the middle. It arrives as a wave of
///   cipher characters from the center that settle into dots, then stands still: nothing moves
///   while a camera reads it. A thin ring around the tile drains until `expiresAt`.
/// - `connecting`: the same wave turns the dots back into cipher characters and clears the tile;
///   six characters keep scrambling in the middle while the devices connect.
/// - `verify`: the scrambling characters settle one by one, left to right, into the code to compare.
///
/// The scrambling characters are decoration (grey, hexadecimal): the code shows only once settled.
/// The tile stays white with dark modules in dark mode too: cameras need the contrast. With Reduce
/// Motion (or `animated` false) each moment is drawn still and the tile cross-fades.
public struct CipherQRCode: View {
    public enum Stage: Equatable, Sendable {
        case code(String)
        case connecting
        case verify(String)
    }

    private let stage: Stage
    private let expiresAt: Date?
    private let animated: Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The QR on the tile: the last `code` text, kept while it dissolves.
    @State private var shownText: String?
    @State private var appearAt = Date.distantPast
    @State private var dissolveAt: Date?
    @State private var settleAt: Date?
    /// The canvas redraws every frame only while something moves.
    @State private var running = false
    @State private var quietAfter: Double?
    @State private var run = 0
    @State private var ringStart = Date()

    public init(stage: Stage, expiresAt: Date? = nil, animated: Bool = true) {
        self.stage = stage
        self.expiresAt = expiresAt
        self.animated = animated
    }

    private static let corner: CGFloat = 22
    static let ink = Color(white: 0.07)

    public var body: some View {
        Group {
            if animated && !reduceMotion {
                TimelineView(.animation(paused: !running)) { timeline in
                    Canvas { context, size in
                        var context = context
                        Self.draw(
                            &context, size: size, matrix: shownText.flatMap(QRMatrix.cached),
                            frame: frame(at: timeline.date))
                    }
                }
                .onChange(of: stage, initial: true) { _, new in advance(to: new) }
                .task(id: run) {
                    guard let quietAfter else { return }
                    try? await Task.sleep(for: .seconds(quietAfter))
                    if !Task.isCancelled { running = false }
                }
            } else {
                still
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .background(Color.white, in: RoundedRectangle(cornerRadius: Self.corner, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: Self.corner, style: .continuous)
                .strokeBorder(Color.black.opacity(0.08), lineWidth: 0.5)
        }
        .overlay { ring }
        .onChange(of: expiresAt, initial: true) { ringStart = Date() }
    }

    // MARK: - Still (Reduce Motion)

    @ViewBuilder private var still: some View {
        ZStack {
            Canvas { context, size in
                var context = context
                let text: String? = if case .code(let text) = stage { text } else { nil }
                let code: String? = if case .verify(let code) = stage { code } else { nil }
                Self.draw(
                    &context, size: size, matrix: text.flatMap(QRMatrix.cached),
                    frame: Frame(
                        appear: .infinity, dissolve: text == nil ? .infinity : nil, settle: code == nil ? nil : .infinity,
                        code: code, scrambles: false))
            }
            if stage == .connecting {
                ProgressView().tint(Self.ink)
            }
        }
        .animation(.easeOut(duration: 0.2), value: stage)
    }

    // MARK: - The ring

    @ViewBuilder private var ring: some View {
        if case .code = stage, let expiresAt {
            TimelineView(.periodic(from: .now, by: 1)) { timeline in
                let total = max(1, expiresAt.timeIntervalSince(ringStart))
                // One second ahead: the linear animation lands on the value as the second ends.
                let left = min(1, max(0, (expiresAt.timeIntervalSince(timeline.date) - 1) / total))
                let shape = RoundedRectangle(cornerRadius: Self.corner - 4, style: .continuous).inset(by: 4)
                ZStack {
                    shape.stroke(Color(white: 0.9), lineWidth: 2)
                    shape.trim(from: 0, to: left)
                        .stroke(Color(white: 0.56), style: StrokeStyle(lineWidth: 2, lineCap: .round))
                        .animation(.linear(duration: 1), value: left)
                }
            }
            .transition(.opacity)
            .accessibilityHidden(true)
        }
    }

    // MARK: - The clock of the animation

    private func frame(at now: Date) -> Frame {
        let code: String? = if case .verify(let code) = stage { code } else { nil }
        return Frame(
            appear: now.timeIntervalSince(appearAt), dissolve: dissolveAt.map(now.timeIntervalSince),
            settle: settleAt.map(now.timeIntervalSince), code: code, scrambles: true)
    }

    private func advance(to stage: Stage) {
        let now = Date()
        switch stage {
        case .code(let text):
            shownText = text
            appearAt = now
            dissolveAt = nil
            settleAt = nil
            quietAfter = Timing.wave + Timing.glyphIn + Timing.dotIn + 0.3
        case .connecting:
            startDissolve(now)
            settleAt = nil
            quietAfter = nil
        case .verify(let code):
            let start = startDissolve(now)
            // The characters scramble at least a moment before they settle.
            let settle = max(now, start.addingTimeInterval(Timing.slotsAt + Timing.slotsIn + 0.25))
            settleAt = settle
            quietAfter = settle.timeIntervalSince(now) + Double(code.count) * Timing.settleStep + 0.4
        }
        running = true
        run += 1
    }

    /// The moment the dots started to turn into cipher (now, unless they already have). With no QR
    /// on the tile there is nothing to clear: the characters in the middle come at once.
    @discardableResult private func startDissolve(_ now: Date) -> Date {
        if let dissolveAt { return dissolveAt }
        let start = shownText == nil ? now.addingTimeInterval(-Timing.slotsAt) : now
        dissolveAt = start
        return start
    }

    // MARK: - Drawing

    enum Timing {
        /// The wave takes this long from the center to the corners.
        static let wave = 0.62
        /// Appearance: a cell shows cipher this long, then its dot grows in.
        static let glyphIn = 0.2
        static let dotIn = 0.3
        /// Connection: a dot shrinks, its cipher holds, then fades.
        static let dotOut = 0.09
        static let glyphHold = 0.23
        static let glyphOut = 0.13
        /// The characters in the middle: when they come after the wave starts, and how long they take.
        static let slotsAt = 0.52
        static let slotsIn = 0.35
        /// One character settles every step, and a scrambling one changes every tick.
        static let settleStep = 0.13
        static let tick = 0.06
    }

    /// Where the animation is, in seconds since each of its moments (`nil`: not started,
    /// `.infinity`: long done).
    struct Frame {
        var appear: Double
        var dissolve: Double?
        var settle: Double?
        var code: String?
        /// False for the still drawings: no scrambling character is ever drawn.
        var scrambles: Bool
    }

    private static let hex = Array("0123456789ABCDEF")

    private static func unit(_ value: Double) -> Double { min(1, max(0, value)) }
    private static func easeOut(_ p: Double) -> Double { 1 - pow(1 - p, 3) }
    private static func easeIn(_ p: Double) -> Double { p * p * p }
    /// Ease out with a slight overshoot (a dot popping in).
    private static func back(_ p: Double) -> Double {
        guard p > 0 else { return 0 }
        let s = 1.6, q = p - 1
        return q * q * ((s + 1) * q + s) + 1
    }

    /// A value in 0..<1 from two integers, the same on every device (the cipher is decoration, not
    /// randomness).
    static func noise(_ a: Int, _ b: Int) -> Double {
        var x = UInt64(truncatingIfNeeded: a) &* 0x9E37_79B9_7F4A_7C15 ^ UInt64(truncatingIfNeeded: b) &* 0xC2B2_AE3D_27D4_EB4F
        x ^= x >> 31
        x = x &* 0x94D0_49BB_1331_11EB
        x ^= x >> 29
        return Double(x & 0xFFFF) / 65536
    }

    /// Scale of the dots and eyes, and opacity of the cipher, at distance `d` (0 center, 1 corner).
    static func cell(_ frame: Frame, distance d: Double) -> (dot: Double, glyph: Double) {
        let inWave = frame.appear - d * Timing.wave
        var dot = back(unit((inWave - Timing.glyphIn) / Timing.dotIn))
        var glyph = inWave < 0 ? 0 : inWave < Timing.glyphIn ? unit(inWave / 0.06) : 1 - unit((inWave - Timing.glyphIn) / 0.11)
        if let dissolve = frame.dissolve {
            let outWave = dissolve - d * Timing.wave
            dot *= 1 - unit(outWave / Timing.dotOut)
            glyph = outWave < 0 ? glyph : outWave < Timing.glyphHold ? 1 : 1 - unit((outWave - Timing.glyphHold) / Timing.glyphOut)
        }
        return (dot, frame.scrambles ? glyph : 0)
    }

    static func draw(_ context: inout GraphicsContext, size: CGSize, matrix: QRMatrix?, frame: Frame) {
        let side = min(size.width, size.height)
        let margin = side * 0.085
        let area = side - 2 * margin
        let origin = CGPoint(x: (size.width - area) / 2, y: (size.height - area) / 2)
        let center = CGPoint(x: size.width / 2, y: size.height / 2)
        let reach = Double(area) * 0.7071
        func distance(_ point: CGPoint) -> Double {
            min(1, Double(hypot(point.x - center.x, point.y - center.y)) / reach)
        }
        let ink = GraphicsContext.Shading.color(ink)
        let markSide = area * 0.2

        if let matrix {
            let cell = area / CGFloat(matrix.side)
            let clear = markSide / 2 + cell * 0.4
            var dots = Path()
            for y in 0..<matrix.side {
                for x in 0..<matrix.side where matrix.isDark(x, y) && !matrix.isFinder(x, y) {
                    let point = CGPoint(x: origin.x + (CGFloat(x) + 0.5) * cell, y: origin.y + (CGFloat(y) + 0.5) * cell)
                    if abs(point.x - center.x) < clear, abs(point.y - center.y) < clear { continue }
                    let radius = cell * 0.46 * Self.cell(frame, distance: distance(point)).dot
                    guard radius > 0.05 else { continue }
                    dots.addEllipse(in: CGRect(x: point.x - radius, y: point.y - radius, width: 2 * radius, height: 2 * radius))
                }
            }
            context.fill(dots, with: ink)
            for eye in matrix.eyes {
                let point = CGPoint(x: origin.x + CGFloat(eye.x) * cell, y: origin.y + CGFloat(eye.y) * cell)
                let module = cell * Self.cell(frame, distance: distance(point)).dot
                guard module > 0.05 else { continue }
                func square(_ half: CGFloat, _ corner: CGFloat) -> Path {
                    Path(roundedRect: CGRect(x: point.x - half * module, y: point.y - half * module, width: 2 * half * module, height: 2 * half * module),
                        cornerRadius: corner * module, style: .continuous)
                }
                context.fill(square(3.5, 2.2), with: ink)
                context.fill(square(2.5, 1.5), with: .color(.white))
                context.fill(square(1.5, 0.9), with: ink)
            }
            // The OnePass mark, one color, over the middle.
            let markScale = back(unit((frame.appear - 0.15) / 0.4)) * (1 - unit((frame.dissolve ?? 0) / 0.2))
            if markScale > 0.01 {
                let s = markSide * markScale
                let tile = CGRect(x: center.x - s / 2, y: center.y - s / 2, width: s, height: s)
                context.fill(Path(roundedRect: tile, cornerRadius: s * 0.24, style: .continuous), with: ink)
                let lattice = tile.insetBy(dx: s * 0.2, dy: s * 0.2)
                context.fill(AppGlyph.Lattice.Dots().path(in: lattice), with: .color(.white.opacity(0.55)))
                context.fill(AppGlyph.Lattice.Bar().path(in: lattice), with: .color(.white))
            }
        }

        // The cipher: one character per cell of a coarser grid, changing every tick.
        if frame.scrambles, matrix != nil {
            let columns = max(8, Int(area / 10))
            let step = area / CGFloat(columns)
            let tick = Int((max(frame.appear, 0) + (frame.dissolve ?? 0)) / Timing.tick) & 0xFFFF
            let glyphs = hex.map {
                context.resolve(Text(String($0)).font(.system(size: step * 0.92, weight: .semibold, design: .monospaced)).foregroundColor(Self.ink))
            }
            let appearing = frame.dissolve == nil
            for row in 0..<columns {
                for column in 0..<columns {
                    let index = row * columns + column
                    let presence = noise(index, 7)
                    guard presence < 0.66 else { continue }
                    let point = CGPoint(x: origin.x + (CGFloat(column) + 0.5) * step, y: origin.y + (CGFloat(row) + 0.5) * step)
                    if appearing, abs(point.x - center.x) < markSide / 2 + step * 0.5, abs(point.y - center.y) < markSide / 2 + step * 0.5 {
                        continue
                    }
                    let alpha = Self.cell(frame, distance: distance(point)).glyph * (presence < 0.42 ? 1 : 0.38)
                    guard alpha > 0.02 else { continue }
                    context.opacity = alpha
                    context.draw(glyphs[Int(noise(index, tick) * 16) & 15], at: point)
                }
            }
            context.opacity = 1
        }

        // The characters in the middle: scrambling while the devices connect, then the code.
        guard let dissolve = frame.dissolve else { return }
        let count = frame.code?.count ?? 6
        let code = frame.code.map(Array.init)
        let shown = easeOut(unit((dissolve - Timing.slotsAt) / Timing.slotsIn))
        guard shown > 0.01, frame.scrambles || code != nil else { return }
        let fontSize = side * (count <= 6 ? 0.15 : 0.9 / CGFloat(count))
        func resolved(_ character: Character) -> GraphicsContext.ResolvedText {
            context.resolve(Text(String(character)).font(.system(size: fontSize, weight: .semibold, design: .monospaced)).foregroundColor(Self.ink))
        }
        let advance = resolved("0").measure(in: size).width * 1.08
        let tick = Int(dissolve / Timing.tick) & 0xFFFF
        // Six characters sit in two groups of three, like the code on the other screen.
        let gap: CGFloat = count == 6 ? 0.6 : 0
        let total = CGFloat(count) + gap
        for index in 0..<count {
            let settled = code != nil && (frame.settle ?? -1) >= Double(index) * Timing.settleStep
            let character: Character = if settled, let code { code[index] } else { hex[Int(noise(900 + index, tick) * 16) & 15] }
            guard settled || frame.scrambles else { continue }
            let slot = CGFloat(index) + (count == 6 && index >= 3 ? gap : 0) + 0.5
            context.opacity = shown * (settled ? 1 : 0.42)
            context.draw(resolved(character), at: CGPoint(x: center.x + (slot - total / 2) * advance, y: center.y))
        }
        context.opacity = 1
    }
}

#Preview("CipherQRCode") {
    @Previewable @State var stage = CipherQRCode.Stage.code("OPPAIR1:preview-preview-preview-preview-preview-preview-preview")
    VStack(spacing: 16) {
        CipherQRCode(stage: stage, expiresAt: Date().addingTimeInterval(30)).frame(width: 260)
        HStack {
            Button("QR") { stage = .code("OPPAIR1:preview-\(Int(Date().timeIntervalSince1970) % 1000)-preview-preview-preview-preview") }
            Button("Connexion") { stage = .connecting }
            Button("Code") { stage = .verify("482913") }
        }
    }
    .padding(40)
}
#endif
