import CoreGraphics
import SwiftUI

/// The identity color of an item: the tint of the wash behind its detail header.
public enum IdentityTint {
    /// Side of the context the icon is scaled into before averaging.
    private static let sampleSide = 16

    /// Colors with an HSB saturation under this read as gray and use the accent instead.
    private static let minimumSaturation = 0.15

    /// Pixels need at least this HSB saturation and brightness to count as a color (not gray, black or white).
    private static let minimumPixelSaturation = 0.25
    private static let minimumPixelBrightness = 0.2
    private static let hueBuckets = 12

    /// The dominant saturated color of an icon: the pixels with alpha above 0.5 are read from a
    /// 16 x 16 sRGB copy, near-gray, near-black and near-white ones dropped, the rest bucketed by
    /// hue (12 buckets of 30 degrees), and the mean of the fullest bucket returned (a tie goes to
    /// the lower bucket). A mean over a multicolor logo would be mud. Nil when no pixel qualifies.
    public static func dominant(of image: CGImage) -> Color? {
        let side = sampleSide
        var pixels = [UInt8](repeating: 0, count: side * side * 4)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard
                let space = CGColorSpace(name: CGColorSpace.sRGB),
                let context = CGContext(
                    data: buffer.baseAddress, width: side, height: side, bitsPerComponent: 8,
                    bytesPerRow: side * 4, space: space,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
            else { return false }
            context.interpolationQuality = .medium
            context.draw(image, in: CGRect(x: 0, y: 0, width: side, height: side))
            return true
        }
        guard drawn else { return nil }

        var sums = [(red: Double, green: Double, blue: Double, count: Double)](
            repeating: (0, 0, 0, 0), count: hueBuckets)
        for i in stride(from: 0, to: pixels.count, by: 4) {
            let alpha = Double(pixels[i + 3]) / 255
            guard alpha > 0.5 else { continue }
            // The context stores premultiplied components, so divide the alpha back out.
            let red = min(Double(pixels[i]) / 255 / alpha, 1)
            let green = min(Double(pixels[i + 1]) / 255 / alpha, 1)
            let blue = min(Double(pixels[i + 2]) / 255 / alpha, 1)
            let high = max(red, green, blue)
            let chroma = high - min(red, green, blue)
            guard high >= minimumPixelBrightness, chroma / high >= minimumPixelSaturation else { continue }
            var hue: Double
            if high == red {
                hue = (green - blue) / chroma
            } else if high == green {
                hue = 2 + (blue - red) / chroma
            } else {
                hue = 4 + (red - green) / chroma
            }
            hue = (hue * 60).truncatingRemainder(dividingBy: 360)
            if hue < 0 { hue += 360 }
            let bucket = min(Int(hue / 30), hueBuckets - 1)
            sums[bucket].red += red
            sums[bucket].green += green
            sums[bucket].blue += blue
            sums[bucket].count += 1
        }
        var best = 0
        for bucket in 1..<hueBuckets where sums[bucket].count > sums[best].count { best = bucket }
        let winner = sums[best]
        guard winner.count > 0 else { return nil }
        return Color(
            .sRGB, red: winner.red / winner.count, green: winner.green / winner.count,
            blue: winner.blue / winner.count, opacity: 1)
    }

    /// The first of the brand color, the icon's dominant color, then the category color. An icon
    /// with no color in it (a black or white logo) takes the accent, not the category color.
    public static func color(brand: String?, siteIcon: CGImage?, category: Color) -> Color {
        if let color = brand.flatMap(ItemIcon.brandColor) { return fallback(color) }
        guard let siteIcon else { return fallback(category) }
        return dominant(of: siteIcon) ?? Theme.accent
    }

    /// The accent for a color too gray to tint a wash (black, white and grays), else the color.
    public static func fallback(_ color: Color) -> Color {
        let resolved = color.resolve(in: EnvironmentValues())
        let high = max(resolved.red, resolved.green, resolved.blue)
        let low = min(resolved.red, resolved.green, resolved.blue)
        let saturation = high > 0 ? Double((high - low) / high) : 0
        return saturation < minimumSaturation ? Theme.accent : color
    }
}

extension Theme.Wash {
    /// The identity wash opacity at its top edge. Dark mode is the stronger one, capped at 22% so
    /// titles stay readable.
    public static func identityOpacity(dark: Bool) -> Double {
        dark ? 0.22 : 0.14
    }

    /// The wash behind an item's detail header, from the identity color down to clear. The view
    /// sizes it to 30% of the screen height.
    public static func identity(_ color: Color, dark: Bool) -> LinearGradient {
        LinearGradient(
            colors: [color.opacity(identityOpacity(dark: dark)), color.opacity(0)],
            startPoint: .top, endPoint: .bottom)
    }
}
