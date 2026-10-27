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
        self.image = siteIcon.flatMap(Self.decode)
    }

    /// PNG (or any ImageIO format) to CGImage, same code on iOS and macOS.
    nonisolated static func decode(_ data: Data) -> CGImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            CGImageSourceGetCount(source) > 0
        else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }

    private var category: ItemCategory { .of(type) }
    private var corner: CGFloat { size * 9 / 38 }
    private var side: CGFloat { size * min(scale, 1.6) }

    public var body: some View {
        Group {
            if let image {
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
