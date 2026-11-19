import CoreGraphics
import Foundation
import ImageIO

/// 64-bit difference hash of an icon, computed exactly like `dhash` in scripts/icon_pack.py.
/// Used to recognise hosting-platform favicons (see the brand-logo accuracy spec).
public enum IconHash {
    /// Hash of the first image in `data`, or nil when it does not decode.
    public static func dHash(_ data: Data) -> UInt64? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let declaredWidth = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
              let declaredHeight = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
              declaredWidth > 0, declaredHeight > 0,
              declaredWidth <= maxSide, declaredHeight <= maxSide,
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
        let width = image.width, height = image.height
        guard width > 0, height > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: width * height * 4)
        let drawn = bytes.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(
                data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8,
                bytesPerRow: width * 4, space: CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
            context.interpolationQuality = .none
            context.setBlendMode(.copy)
            context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        guard drawn else { return nil }

        var gray = [Double](repeating: 0, count: width * height)
        for i in 0..<(width * height) {
            let a = Double(bytes[i * 4 + 3])
            func over(_ k: Int) -> Double {
                let straight = a > 0 ? min(255.0, (Double(bytes[i * 4 + k]) * 255.0 / a).rounded()) : 0.0
                return straight * a / 255.0 + 255.0 * (1.0 - a / 255.0)
            }
            let r = over(0), g = over(1), b = over(2)
            gray[i] = 0.299 * r + 0.587 * g + 0.114 * b
        }

        let cols = spans(width, 9), rows = spans(height, 8)
        var cells = [[Double]]()
        for row in rows {
            var line = [Double]()
            for col in cols {
                var total = 0.0
                for (y, wy) in row.weights {
                    var acc = 0.0
                    for (x, wx) in col.weights { acc += gray[y * width + x] * wx }
                    total += acc * wy
                }
                line.append(total / ((col.hi - col.lo) * (row.hi - row.lo)))
            }
            cells.append(line)
        }
        var bits: UInt64 = 0
        for line in cells {
            for x in 0..<8 { bits = (bits << 1) | (line[x] > line[x + 1] + 1e-9 ? 1 : 0) }
        }
        return bits
    }

    /// Largest accepted width and height, in pixels.
    static let maxSide = 4096

    /// Number of differing bits.
    public static func distance(_ a: UInt64, _ b: UInt64) -> Int { (a ^ b).nonzeroBitCount }

    private struct Span { var lo: Double; var hi: Double; var weights: [(Int, Double)] }

    private static func spans(_ count: Int, _ cells: Int) -> [Span] {
        (0..<cells).map { c in
            let lo = Double(c * count) / Double(cells), hi = Double((c + 1) * count) / Double(cells)
            let first = Int(lo), last = min(count - 1, Int(hi))
            var weights = [(Int, Double)]()
            for i in first...last {
                let w = min(Double(i + 1), hi) - max(Double(i), lo)
                if w > 0.0 { weights.append((i, w)) }
            }
            return Span(lo: lo, hi: hi, weights: weights)
        }
    }
}
