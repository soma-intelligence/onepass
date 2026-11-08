import DesignKit
import SwiftUI
import VaultKit

/// Top of the detail, straight on the window glass: big icon, title, then one secondary line with
/// the category (and the list subtitle) and the vault badge.
struct ItemHeader: View {
    @Environment(AppModel.self) private var model
    let item: FfiItem
    /// Tells the detail which icon data the header draws, so the identity wash follows it.
    var onIcon: (Data?) -> Void = { _ in }
    @State private var siteIcon: Data?

    private var iconData: Data? { siteIcon ?? model.iconLoader.cachedIcon(for: primaryURL, title: item.title) }

    private var vault: FfiVault? { model.session.allVaults.first { $0.id == item.vaultId } }

    private var subtitle: String {
        let category = ItemCategory.of(item.itemType).singular
        let summary = model.session.summaries.first { $0.id == item.id }?.listSubtitle ?? ""
        return summary.isEmpty ? category : "\(category) · \(summary)"
    }

    private var primaryURL: String? {
        (item.urls.first(where: \.primary) ?? item.urls.first)?.url
    }

    @ViewBuilder private var vaultBadge: some View {
        if let vault {
            HStack(spacing: Theme.Space.xs) {
                VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 16)
                Text(vault.meta.name).lineLimit(1)
            }
            .padding(.leading, Theme.Space.xxs)
            .padding(.trailing, Theme.Space.s)
            .padding(.vertical, Theme.Space.xxs)
            .background(.fill.quaternary, in: Capsule())
            .accessibilityElement(children: .combine)
            .accessibilityLabel(Text("item.vault \(vault.meta.name)"))
        }
    }

    var body: some View {
        HStack(alignment: .center, spacing: Theme.Space.l) {
            ItemIcon(type: item.itemType, title: item.title, siteIcon: iconData, size: 64, brand: item.cardBrandName)
                .favoriteBadge(item.favorite, iconSize: 64)
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                HStack(alignment: .firstTextBaseline, spacing: Theme.Space.s) {
                    Text(item.title)
                        .font(.title.weight(.bold))
                        .lineLimit(2)
                        .accessibilityIdentifier("item.title")
                }
                #if os(iOS)
                // iPhone: the subtitle on its own line when the vault badge would cut it.
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: Theme.Space.s) {
                        Text(subtitle).lineLimit(1)
                        vaultBadge
                    }
                    VStack(alignment: .leading, spacing: Theme.Space.xs) {
                        Text(subtitle).lineLimit(2)
                        vaultBadge
                    }
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
                #else
                // The vault already leads the toolbar (its menu moves the item): named once.
                Text(subtitle)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                #endif
            }
            Spacer(minLength: 0)
        }
        .onChange(of: iconData, initial: true) { _, data in onIcon(data) }
        .task(id: primaryURL) {
            guard let url = primaryURL else {
                siteIcon = nil
                return
            }
            siteIcon = await model.iconLoader.icon(for: url, title: item.title)
        }
    }
}
