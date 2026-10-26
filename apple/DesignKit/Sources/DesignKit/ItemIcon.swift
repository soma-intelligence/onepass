import ImageIO
import SwiftUI
import VaultKit

/// Row icon: the site icon when one was loaded, otherwise the category tile
/// (a letter for logins, the category symbol for the other types).
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
                    .scaledToFill()
                    .frame(width: side, height: side)
                    .background(Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: corner, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: corner, style: .continuous)
                            .strokeBorder(Color.primary.opacity(0.08)))
            } else {
                RoundedRectangle(cornerRadius: corner, style: .continuous)
                    .fill(category.color)
                    .frame(width: side, height: side)
                    .overlay { glyph }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "\(category.singular), \(title)"))
    }

    @ViewBuilder private var glyph: some View {
        if type == .login, let first = title.trimmingCharacters(in: .whitespaces).first {
            Text(String(first).uppercased())
                .font(.system(size: side * 0.47, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        } else {
            Image(systemName: category.symbol)
                .font(.system(size: side * 0.47, weight: .medium))
                .foregroundStyle(.white)
        }
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
