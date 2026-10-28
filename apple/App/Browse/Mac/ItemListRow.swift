import DesignKit
import SwiftUI
import VaultKit

/// One row of an item list (Mac and iPad list column, iPhone lists): icon (site icon when loaded,
/// otherwise the category tile), title, subtitle, the vault name when the list mixes vaults, and a
/// star on the icon's corner for favorites. Platform neutral: the host list handles selection or navigation.
struct ItemListRow: View {
    @Environment(AppModel.self) private var model
    private let summary: FfiItemSummary
    private let vaultName: String?
    @State private var siteIcon: Data?

    init(summary: FfiItemSummary, vaultName: String?) {
        self.summary = summary
        self.vaultName = vaultName
    }

    /// A login with no username that signs in with a provider: "Se connecte avec GitHub".
    private var signInLine: String? {
        guard summary.subtitle.isEmpty, let provider = summary.signInProvider else { return nil }
        return String(localized: "Se connecte avec \(LoginProvider.displayName(provider))")
    }

    private var secondLine: String {
        let parts = [signInLine ?? summary.subtitle, vaultName ?? ""].filter { !$0.isEmpty }
        return parts.isEmpty ? ItemCategory.of(summary.itemType).singular : parts.joined(separator: " · ")
    }

    var body: some View {
        HStack(spacing: 12) {
            ItemIcon(type: summary.itemType, title: summary.title, siteIcon: siteIcon, size: 34)
                .favoriteBadge(summary.favorite, iconSize: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text(summary.title)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                Text(secondLine)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("list.row.\(summary.title)")
        .task(id: summary.primaryUrl) {
            guard let url = summary.primaryUrl else {
                siteIcon = nil
                return
            }
            siteIcon = await model.iconLoader.icon(for: url)
        }
    }
}

extension View {
    /// A favorite's star on the bottom-right corner of an item icon: an amber star cut into the
    /// icon (a transparent outline around it, so it reads on any row background, selected or not).
    func favoriteBadge(_ isFavorite: Bool, iconSize: CGFloat) -> some View {
        modifier(FavoriteBadge(isOn: isFavorite, iconSize: iconSize))
    }
}

private struct FavoriteBadge: ViewModifier {
    let isOn: Bool
    let iconSize: CGFloat

    static let amber = Color(red: 0xF5 / 255, green: 0xA6 / 255, blue: 0x23 / 255)

    private var starSize: CGFloat { (iconSize * 0.42).rounded() }
    /// The star's center sits on the icon's corner, pulled in a little so most of it overlaps.
    private var inset: CGFloat { iconSize * 0.1 }

    func body(content: Content) -> some View {
        if isOn {
            content
                .mask {
                    Rectangle()
                        .overlay(alignment: .bottomTrailing) { star.scaleEffect(1.45).blendMode(.destinationOut) }
                        .compositingGroup()
                }
                .overlay(alignment: .bottomTrailing) {
                    star.foregroundStyle(Self.amber).accessibilityLabel(Text("Favori"))
                }
        } else {
            content
        }
    }

    private var star: some View {
        Image(systemName: "star.fill")
            .font(.system(size: starSize, weight: .semibold))
            .frame(width: starSize * 1.2, height: starSize * 1.2)
            .offset(x: starSize * 0.6 - inset, y: starSize * 0.6 - inset)
    }
}
