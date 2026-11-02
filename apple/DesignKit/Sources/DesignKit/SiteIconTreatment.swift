import CoreGraphics
import Foundation

/// How a site icon sits on its tile, read from its pixels once (cached with the decoded image).
///
/// - Artwork that fills its square edge to edge (an app icon, a touch icon on its brand color) fills
///   the tile, as on the home screen.
/// - A mark on a plain white or black square (many favicons) loses that square: the plain color is
///   cleared from the edges inward (enclosed areas keep it), and the mark is then treated as below.
///   No more white squares in a dark list, no black squares in a light one.
/// - A mark on a transparent background sits on a neutral tile that suits it: a one color mark (a
///   black "T", a grey logo) takes the text color of the appearance, dark on light, light on dark; a
///   colored mark keeps its colors on a tile that keeps it readable (a navy mark gets a light tile in
///   dark mode, a pale one a dark tile in light mode).
public enum SiteIconTreatment: Equatable, Sendable {
    case fullBleed
    /// `monochrome`: drawn as a template in the text color. `luminance`: of the mark's opaque
    /// pixels, 0 (black) to 1 (white).
    case mark(monochrome: Bool, luminance: Double)

    /// The pixels of an image, RGBA premultiplied, drawn at `side` (or its own size, if smaller).
    struct Bitmap {
        let width: Int
        let height: Int
        var pixels: [UInt8]

        init?(_ image: CGImage, maxSide: Int = 256) {
            let scale = min(1, Double(maxSide) / Double(max(image.width, image.height)))
            width = max(1, Int((Double(image.width) * scale).rounded()))
            height = max(1, Int((Double(image.height) * scale).rounded()))
            pixels = [UInt8](repeating: 0, count: width * height * 4)
            guard let space = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
            let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
                guard let context = CGContext(
                    data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8,
                    bytesPerRow: width * 4, space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
                else { return false }
                context.interpolationQuality = .high
                context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
                return true
            }
            guard drawn else { return nil }
        }

        func alpha(_ i: Int) -> Int { Int(pixels[i * 4 + 3]) }

        /// Straight (not premultiplied) color of pixel `i`, 0...1.
        func color(_ i: Int) -> (r: Double, g: Double, b: Double) {
            let a = Double(pixels[i * 4 + 3])
            guard a > 0 else { return (0, 0, 0) }
            return (Double(pixels[i * 4]) / a, Double(pixels[i * 4 + 1]) / a, Double(pixels[i * 4 + 2]) / a)
        }

        /// Indices of the outermost ring of pixels.
        var border: [Int] {
            var out: [Int] = []
            for x in 0..<width { out.append(x); out.append((height - 1) * width + x) }
            for y in 1..<max(1, height - 1) { out.append(y * width); out.append(y * width + width - 1) }
            return out
        }

        func makeImage() -> CGImage? {
            guard let space = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
            var copy = pixels
            return copy.withUnsafeMutableBytes { buffer -> CGImage? in
                CGContext(
                    data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4,
                    space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)?.makeImage()
            }
        }
    }

    static func luminance(_ c: (r: Double, g: Double, b: Double)) -> Double {
        0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b
    }

    static func chroma(_ c: (r: Double, g: Double, b: Double)) -> Double {
        max(c.r, c.g, c.b) - min(c.r, c.g, c.b)
    }

    /// The icon ready for its tile: a plain square background cleared when there is one, and how to
    /// show the result.
    public static func prepare(_ image: CGImage) -> (image: CGImage, treatment: SiteIconTreatment) {
        guard var bitmap = Bitmap(image) else { return (image, .fullBleed) }
        let border = bitmap.border
        let opaqueBorder = border.filter { bitmap.alpha($0) > 230 }.count
        if Double(opaqueBorder) >= Double(border.count) * 0.9 {
            // Opaque to the edge: a plain white or black square around a mark loses its square,
            // anything else is artwork.
            guard let plain = plainColor(bitmap, border), clearBackground(&bitmap, from: border, color: plain),
                let cleared = bitmap.makeImage()
            else { return (image, .fullBleed) }
            return (cleared, classify(bitmap))
        }
        return (image, classify(bitmap))
    }

    /// The color the whole border shares when it is near white or near black, else nil.
    static func plainColor(_ bitmap: Bitmap, _ border: [Int]) -> (r: Double, g: Double, b: Double)? {
        let colors = border.map(bitmap.color)
        let n = Double(colors.count)
        let mean = (r: colors.map(\.r).reduce(0, +) / n, g: colors.map(\.g).reduce(0, +) / n,
            b: colors.map(\.b).reduce(0, +) / n)
        let close = colors.filter { abs($0.r - mean.r) + abs($0.g - mean.g) + abs($0.b - mean.b) < 0.12 }.count
        guard Double(close) >= n * 0.97 else { return nil }
        let lum = luminance(mean)
        guard (lum > 0.9 || lum < 0.1), chroma(mean) < 0.08 else { return nil }
        return mean
    }

    /// Clears the pixels of `color` reachable from the border (a flood fill: a white inside a mark
    /// stays). Refused (false, nothing kept) when it would leave almost nothing or almost everything:
    /// a white square with a hairline mark, or a full-bleed white app icon with a small detail.
    static func clearBackground(_ bitmap: inout Bitmap, from border: [Int], color: (r: Double, g: Double, b: Double))
        -> Bool
    {
        let total = bitmap.width * bitmap.height
        var cleared = [Bool](repeating: false, count: total)
        var stack = border
        var count = 0
        func matches(_ i: Int) -> Bool {
            guard bitmap.alpha(i) > 200 else { return false }
            let c = bitmap.color(i)
            return abs(c.r - color.r) + abs(c.g - color.g) + abs(c.b - color.b) < 0.18
        }
        while let i = stack.popLast() {
            guard !cleared[i], matches(i) else { continue }
            cleared[i] = true
            count += 1
            let x = i % bitmap.width, y = i / bitmap.width
            if x > 0 { stack.append(i - 1) }
            if x < bitmap.width - 1 { stack.append(i + 1) }
            if y > 0 { stack.append(i - bitmap.width) }
            if y < bitmap.height - 1 { stack.append(i + bitmap.width) }
        }
        // Background under a third of the square: artwork on white, not a mark on a square.
        guard count >= total / 3, count <= total * 97 / 100 else { return false }
        var pixels = bitmap.pixels
        for i in 0..<total {
            if cleared[i] {
                pixels[i * 4] = 0; pixels[i * 4 + 1] = 0; pixels[i * 4 + 2] = 0; pixels[i * 4 + 3] = 0
            } else if !matches(i) {
                // The antialiased rim of the mark, half background: keep it, softened toward clear
                // where it touches cleared pixels (no white halo on a dark tile).
                let x = i % bitmap.width, y = i / bitmap.width
                let touches = (x > 0 && cleared[i - 1]) || (x < bitmap.width - 1 && cleared[i + 1])
                    || (y > 0 && cleared[i - bitmap.width]) || (y < bitmap.height - 1 && cleared[i + bitmap.width])
                if touches {
                    let c = bitmap.color(i)
                    // How far this pixel is from the background: 0 is background, 1 is the mark.
                    let distance = min(1, (abs(c.r - color.r) + abs(c.g - color.g) + abs(c.b - color.b)) / 1.2)
                    let a = Double(pixels[i * 4 + 3]) * distance
                    for k in 0..<4 { pixels[i * 4 + k] = UInt8((Double(pixels[i * 4 + k]) * distance).rounded()) }
                    pixels[i * 4 + 3] = UInt8(min(255, a.rounded()))
                }
            }
        }
        bitmap.pixels = pixels
        return true
    }

    /// A mark on a transparent background: one color or several, and how light it is.
    static func classify(_ bitmap: Bitmap) -> SiteIconTreatment {
        var lum = 0.0, weight = 0.0, colorful = 0.0
        for i in 0..<(bitmap.width * bitmap.height) {
            let a = Double(bitmap.alpha(i)) / 255
            guard a > 0.5 else { continue }
            let c = bitmap.color(i)
            lum += luminance(c) * a
            if chroma(c) > 0.18 { colorful += a }
            weight += a
        }
        guard weight > 0 else { return .mark(monochrome: true, luminance: 0) }
        return .mark(monochrome: colorful / weight < 0.06, luminance: lum / weight)
    }
}
