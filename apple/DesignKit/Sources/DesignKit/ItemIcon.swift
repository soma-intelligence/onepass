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

    public init(type: FfiItemType, title: String, siteIcon: Data?, size: CGFloat = 38) {
        self.type = type
        self.title = title
        self.size = size
        self.image = siteIcon.flatMap(Self.filled)
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
            if let image, Self.isLowResolution(image, side: side) {
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
