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
    /// hue (12 buckets of 30 degrees centered on 0, 30, ... 330, so reds either side of 0 share
    /// one), and the mean of the fullest bucket returned (a tie goes to the lower bucket). A mean
    /// over a multicolor logo would be mud. Nil when no pixel qualifies.
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
            let bucket = Int((hue + 15) / 30) % hueBuckets
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
    /// The leading glow's opacity at its corner (the trailing one draws at 85% of it). Dark mode is
    /// the stronger one, at 28%: the glows fade fast from the corners, so the title still reads.
    public static func identityOpacity(dark: Bool) -> Double {
        dark ? 0.28 : 0.14
    }

    /// How far each glow turns the identity color around the hue wheel, in degrees: the leading
    /// one a little cooler, the trailing one a little warmer, so the two corners differ without
    /// leaving the item's color.
    static let leadingHueShift: Double = -14
    static let trailingHueShift: Double = 22

    /// The trailing glow's strength against the leading one.
    static let trailingStrength = 0.85

    /// How far a glow reaches, as a fraction of the box it is drawn in (SwiftUI measures an
    /// elliptical gradient's radius against the box's full width and height). Over a box 58% of
    /// the screen tall this reaches 71% of the width and 41% of the height.
    static let glowReach: CGFloat = 0.71

    /// The two glows behind an item's detail header: soft ellipses from the top corners, each in
    /// the identity color turned slightly around the hue wheel, fading out on a smooth curve so no
    /// edge shows. The view stacks them in a box 58% of the screen tall.
    public static func identityGlows(_ color: Color, dark: Bool) -> (leading: EllipticalGradient, trailing: EllipticalGradient) {
        let peak = identityOpacity(dark: dark)
        return (
            glow(IdentityTint.rotated(color, by: leadingHueShift), peak: peak, center: .topLeading),
            glow(IdentityTint.rotated(color, by: trailingHueShift), peak: peak * trailingStrength, center: .topTrailing)
        )
    }

    /// One glow, its alpha following 1 - smoothstep(r) from the center out.
    private static func glow(_ color: Color, peak: Double, center: UnitPoint) -> EllipticalGradient {
        let curve: [(Double, Double)] = [(0, 1), (0.25, 0.844), (0.5, 0.5), (0.75, 0.156), (1, 0)]
        return EllipticalGradient(
            stops: curve.map { .init(color: color.opacity(peak * $0.1), location: $0.0) },
            center: center, startRadiusFraction: 0, endRadiusFraction: glowReach)
    }
}

extension IdentityTint {
    /// `color` turned `degrees` around the HSB hue wheel, saturation and brightness kept.
    static func rotated(_ color: Color, by degrees: Double) -> Color {
        let c = color.resolve(in: EnvironmentValues())
        let (r, g, b) = (Double(c.red), Double(c.green), Double(c.blue))
        let high = max(r, g, b), chroma = high - min(r, g, b)
        guard chroma > 0 else { return color }
        var hue: Double
        if high == r {
            hue = (g - b) / chroma
        } else if high == g {
            hue = 2 + (b - r) / chroma
        } else {
            hue = 4 + (r - g) / chroma
        }
        hue = (hue * 60 + degrees).truncatingRemainder(dividingBy: 360)
        if hue < 0 { hue += 360 }
        return Color(hue: hue / 360, saturation: chroma / high, brightness: high, opacity: Double(c.opacity))
    }
}
