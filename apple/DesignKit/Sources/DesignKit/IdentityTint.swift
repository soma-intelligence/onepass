import CoreGraphics
import SwiftUI

/// The identity color of an item: the tint of the wash behind its detail header.
public enum IdentityTint {
    /// Side of the context the icon is scaled into before averaging.
    private static let sampleSide = 16

    /// Colors with an HSB saturation under this read as gray and use the accent instead.
    private static let minimumSaturation = 0.15

    /// The mean color of the pixels with alpha above 0.5, drawn into a 16 x 16 sRGB context.
    /// Nil when no pixel qualifies.
    public static func average(of image: CGImage) -> Color? {
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

        var red = 0.0, green = 0.0, blue = 0.0
        var count = 0.0
        for i in stride(from: 0, to: pixels.count, by: 4) {
            let alpha = Double(pixels[i + 3]) / 255
            guard alpha > 0.5 else { continue }
            // The context stores premultiplied components, so divide the alpha back out.
            red += Double(pixels[i]) / 255 / alpha
            green += Double(pixels[i + 1]) / 255 / alpha
            blue += Double(pixels[i + 2]) / 255 / alpha
            count += 1
        }
        guard count > 0 else { return nil }
        return Color(
            .sRGB, red: min(red / count, 1), green: min(green / count, 1), blue: min(blue / count, 1),
            opacity: 1)
    }

    /// The first of the brand color, the site icon average and the category color, then `fallback(_:)`.
    public static func color(brand: String?, siteIcon: CGImage?, category: Color) -> Color {
        let picked =
            brand.flatMap(ItemIcon.brandColor)
            ?? siteIcon.flatMap(average(of:))
            ?? category
        return fallback(picked)
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
