import CoreGraphics
@testable import DBDiff

/// Synthetic screens: a light background, a card, a few text-like stripes and a dark button.
/// Structured enough for SSIM to have texture, and fully deterministic.
enum Fixtures {
    static func screen(width: Int = 120, height: Int = 200, shift: (dx: Int, dy: Int) = (0, 0), buttonColor: RGBA = RGBA(20, 90, 220)) -> RGBAImage {
        var img = RGBAImage(width: width, height: height, fill: RGBA(246, 246, 247))
        func rect(_ x: Int, _ y: Int, _ w: Int, _ h: Int, _ c: RGBA) {
            let y0 = max(0, y + shift.dy), y1 = min(height, y + h + shift.dy)
            let x0 = max(0, x + shift.dx), x1 = min(width, x + w + shift.dx)
            guard y1 > y0, x1 > x0 else { return }
            for yy in y0..<y1 {
                for xx in x0..<x1 { img[xx, yy] = c }
            }
        }
        rect(10, 20, 100, 70, .white)
        for i in 0..<5 {
            rect(18, 28 + i * 11, 40 + (i * 13) % 50, 5, RGBA(30, 30, 35))
        }
        rect(20, 150, 80, 24, buttonColor)
        for x in stride(from: 26, to: 94, by: 6) { rect(x, 159, 3, 6, .white) }
        return img
    }

    /// Adds deterministic pseudo-random noise of amplitude `amount` to every channel.
    static func noisy(_ image: RGBAImage, amount: Int, seed: UInt64 = 42) -> RGBAImage {
        var out = image
        var state = seed
        for i in 0..<(out.pixels.count) where i % 4 != 3 {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            let n = Int((state >> 33) % UInt64(2 * amount + 1)) - amount
            out.pixels[i] = UInt8(clamping: Int(out.pixels[i]) + n)
        }
        return out
    }
}
