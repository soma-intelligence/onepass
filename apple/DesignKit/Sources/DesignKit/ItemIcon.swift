import ImageIO
import SwiftUI
import VaultKit

/// Row icon: the site icon when one was loaded, otherwise the illustrated category artwork
/// (for logins, the teal tile carries the title's first letter when there is one).
public struct ItemIcon: View {
    private let type: FfiItemType
    private let title: String
    private let size: CGFloat
    private let image: CGImage?

    @ScaledMetric(relativeTo: .body) private var scale: CGFloat = 1

    private let brand: String?

    /// `brand`: a credit card's network ("visa", "mastercard", "amex"...): the card shows that
    /// network's mark on its color instead of the generic card artwork.
    public init(type: FfiItemType, title: String, siteIcon: Data?, size: CGFloat = 38, brand: String? = nil) {
        self.type = type
        self.title = title
        self.size = size
        self.image = siteIcon.flatMap(Self.filled)
        self.brand = type == .creditCard ? brand : nil
    }

    /// The networks with a mark in the app's assets (`card-<brand>`), and the color of their tile.
    static func brandColor(_ brand: String) -> Color? {
        switch brand {
        case "visa": Color(red: 0x1A / 255, green: 0x1F / 255, blue: 0x71 / 255)
        case "mastercard": Color(red: 0x1C / 255, green: 0x1C / 255, blue: 0x1E / 255)
        case "amex": Color(red: 0x2E / 255, green: 0x77 / 255, blue: 0xBC / 255)
        case "discover": Color(red: 0xF2 / 255, green: 0x65 / 255, blue: 0x1E / 255)
        case "jcb": Color(red: 0x0B / 255, green: 0x4E / 255, blue: 0xA2 / 255)
        case "diners_club": Color(red: 0x00 / 255, green: 0x79 / 255, blue: 0xBE / 255)
        default: nil
        }
    }

    private final class Box: @unchecked Sendable {
        let image: CGImage
        init(_ image: CGImage) { self.image = image }
    }

    nonisolated(unsafe) private static let cache: NSCache<NSData, Box> = {
        let cache = NSCache<NSData, Box>()
        cache.countLimit = 300
        return cache
    }()

    /// The site icon decoded, its plain margin trimmed (cached per icon: rows redraw often).
    nonisolated static func filled(_ data: Data) -> CGImage? {
        if let hit = cache.object(forKey: data as NSData) { return hit.image }
        guard let decoded = decode(data) else { return nil }
        let result = trimmed(decoded) ?? decoded
        cache.setObject(Box(result), forKey: data as NSData)
        return result
    }

    /// Many sites ship their mark small in the middle of a plain square (white or transparent):
    /// the tile then showed a tiny logo in a wide margin. When the four corners share one color,
    /// the image is cropped to a square around what differs from it, with a little air, so the
    /// mark fills the tile. Full-bleed artwork (corners that differ) is left alone.
    nonisolated static func trimmed(_ image: CGImage) -> CGImage? {
        let side = 128
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
            let context = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: side * 4,
                space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
            let pixels = context.data?.bindMemory(to: UInt8.self, capacity: side * side * 4)
        else { return nil }
        context.interpolationQuality = .high
        context.draw(image, in: CGRect(x: 0, y: 0, width: side, height: side))
        func px(_ x: Int, _ y: Int) -> (Int, Int, Int, Int) {
            let i = (y * side + x) * 4
            return (Int(pixels[i]), Int(pixels[i + 1]), Int(pixels[i + 2]), Int(pixels[i + 3]))
        }
        func close(_ a: (Int, Int, Int, Int), _ b: (Int, Int, Int, Int)) -> Bool {
            if a.3 < 24, b.3 < 24 { return true }
            return abs(a.0 - b.0) + abs(a.1 - b.1) + abs(a.2 - b.2) + abs(a.3 - b.3) < 40
        }
        let corner = px(1, 1)
        guard close(corner, px(side - 2, 1)), close(corner, px(1, side - 2)), close(corner, px(side - 2, side - 2))
        else { return nil }
        var minX = side, minY = side, maxX = -1, maxY = -1
        for y in 0..<side {
            for x in 0..<side where !close(px(x, y), corner) {
                minX = min(minX, x); maxX = max(maxX, x)
                minY = min(minY, y); maxY = max(maxY, y)
            }
        }
        guard maxX >= minX, maxY >= minY else { return nil }
        let content = max(maxX - minX + 1, maxY - minY + 1)
        // Already filling the square: nothing to gain.
        guard content < side * 82 / 100 else { return nil }
        // A small source cropped and blown up turns to mush: only trim when enough pixels remain.
        guard CGFloat(content) * CGFloat(max(image.width, image.height)) / CGFloat(side) >= 96 else { return nil }
        let crop = min(side, Int((Double(content) * 1.18).rounded()))
        let centerX = (minX + maxX + 1) / 2, centerY = (minY + maxY + 1) / 2
        let originX = max(0, min(side - crop, centerX - crop / 2))
        let originY = max(0, min(side - crop, centerY - crop / 2))
        // Back to the source's pixels (the bitmap's memory rows run top-down, like CGImage's).
        let ratioX = CGFloat(image.width) / CGFloat(side), ratioY = CGFloat(image.height) / CGFloat(side)
        let rect = CGRect(
            x: CGFloat(originX) * ratioX, y: CGFloat(originY) * ratioY,
            width: CGFloat(crop) * ratioX, height: CGFloat(crop) * ratioY
        ).integral
        return image.cropping(to: rect)
    }

    /// PNG (or any ImageIO format) to CGImage, same code on iOS and macOS.
    nonisolated static func decode(_ data: Data) -> CGImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            CGImageSourceGetCount(source) > 0
        else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }

    /// Fewer source pixels than the tile shows on a Retina screen (with a little slack): drawn
    /// at its own size rather than stretched.
    static func isLowResolution(_ image: CGImage, side: CGFloat) -> Bool {
        CGFloat(min(image.width, image.height)) < side * 2 * 0.75
    }

    private var category: ItemCategory { .of(type) }
    private var corner: CGFloat { size * 9 / 38 }
    private var side: CGFloat { size * min(scale, 1.6) }

    public var body: some View {
        Group {
            if image == nil, let brand, let color = Self.brandColor(brand) {
                BrandCard(brand: brand, color: color, width: side)
                    .frame(width: side, height: side)
            } else if let image, Self.isLowResolution(image, side: side) {
                // A small favicon is not stretched into a blur: it sits at its own size (one
                // source pixel per screen pixel on Retina, at most 60% of the tile), crisp, on a
                // neutral tile.
                Image(decorative: image, scale: 2)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .frame(width: min(side * 0.6, CGFloat(image.width) / 2), height: min(side * 0.6, CGFloat(image.height) / 2))
                    .frame(width: side, height: side)
                    .background(Color.primary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: corner, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: corner, style: .continuous)
                            .strokeBorder(Color.primary.opacity(0.08)))
            } else if let image {
                Image(decorative: image, scale: 1)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFill()
                    .frame(width: side, height: side)
                    .background(Color.primary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: corner, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: corner, style: .continuous)
                            .strokeBorder(Color.primary.opacity(0.08)))
            } else {
                CategoryArtwork(type: type, size: side, monogram: type == .login ? title : nil)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "\(category.singular), \(title)"))
    }
}

#Preview("ItemIcon") {
    HStack(spacing: 12) {
        ItemIcon(type: .login, title: "Atlas Cloud", siteIcon: nil)
        ItemIcon(type: .creditCard, title: "Carte Camille Durand", siteIcon: nil)
        ItemIcon(type: .router, title: "Wi-Fi Maison", siteIcon: nil, size: 52)
    }
    .padding()
}

/// A credit card seen face on (ISO proportions) in its network's color: a chip on the left and the
/// network's mark in the lower right, Mastercard drawn in its own three colors.
private struct BrandCard: View {
    let brand: String
    let color: Color
    let width: CGFloat

    var body: some View {
        let height = width / 1.586
        let shape = RoundedRectangle(cornerRadius: width * 0.09, style: .continuous)
        shape
            .fill(LinearGradient(colors: [color.mix(with: .white, by: 0.12), color, color.mix(with: .black, by: 0.2)],
                startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay(alignment: .topLeading) {
                // Chip.
                RoundedRectangle(cornerRadius: width * 0.025, style: .continuous)
                    .fill(LinearGradient(colors: [Color(red: 0.95, green: 0.83, blue: 0.5), Color(red: 0.78, green: 0.62, blue: 0.3)],
                        startPoint: .top, endPoint: .bottom))
                    .frame(width: width * 0.17, height: width * 0.13)
                    .padding(.leading, width * 0.1)
                    .padding(.top, height * 0.22)
            }
            .overlay(alignment: .bottomTrailing) {
                mark
                    .padding(.trailing, width * 0.07)
                    .padding(.bottom, height * (brand == "amex" ? 0.1 : 0.12))
            }
            .overlay { shape.strokeBorder(Color.white.opacity(0.14), lineWidth: 0.5) }
            .frame(width: width, height: height)
            .shadow(color: .black.opacity(0.25), radius: width * 0.04, y: width * 0.02)
    }

    @ViewBuilder private var mark: some View {
        if brand == "mastercard" {
            // The real mark: red and yellow circles, orange where they overlap.
            let d = width * 0.22
            ZStack {
                Circle().fill(Color(red: 0xEB / 255, green: 0x00 / 255, blue: 0x1B / 255)).frame(width: d, height: d).offset(x: -d * 0.3)
                Circle().fill(Color(red: 0xF7 / 255, green: 0x9E / 255, blue: 0x1B / 255)).frame(width: d, height: d).offset(x: d * 0.3)
                Circle().fill(Color(red: 0xFF / 255, green: 0x5F / 255, blue: 0x00 / 255)).frame(width: d, height: d).offset(x: d * 0.3)
                    .mask { Circle().frame(width: d, height: d).offset(x: -d * 0.3) }
            }
            .frame(width: d * 1.6, height: d)
        } else {
            Image("card-\(brand)", bundle: .main)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .foregroundStyle(.white)
                // The marks sit in a square 24 pt box: the Visa wordmark is a thin band across it,
                // so its box is sized by width and its empty top and bottom are pulled back in.
                .frame(width: width * (brand == "visa" ? 0.5 : brand == "amex" ? 0.3 : 0.42),
                    height: width * (brand == "visa" ? 0.5 : brand == "amex" ? 0.3 : 0.24))
                .frame(height: brand == "visa" ? width * 0.17 : nil)
        }
    }
}
