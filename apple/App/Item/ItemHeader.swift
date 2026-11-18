import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Top of the detail, straight on the window glass: big icon, title, then one secondary line with
/// the category (and the list subtitle) and the vault badge.
struct ItemHeader: View {
    @Environment(AppModel.self) private var model
    let item: FfiItem
    /// The RX header (iPhone): a centred 76 pt tile, the large title, the subtitle, the vault chip.
    var centered = false
    /// Tells the detail which icon data the header draws, so the identity wash follows it.
    var onIcon: (Data?) -> Void = { _ in }
    /// The automatic icon the task found (the chosen one is read from memory at each frame).
    @State private var resolved: ResolvedIcon?

    /// The site icon tile: 56 pt on iPhone and iPad, 64 pt on the Mac.
    #if os(iOS)
    private static let iconSize: CGFloat = 56
    #else
    private static let iconSize: CGFloat = 64
    #endif

    private var taskID: ItemIconTaskID {
        ItemIconTaskID(url: primaryURL, title: item.title, custom: CustomIconKey(item), epoch: model.iconEpoch)
    }

    private var iconData: Data? { model.iconLoader.shownIcon(taskID, resolved: resolved) }

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
                Text(vault.meta.name).dbText(maxLines: 2)
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
        Group {
            if centered {
                rxBody
            } else {
                classicBody
            }
        }
        .onChange(of: iconData, initial: true) { _, data in onIcon(data) }
        .task(id: taskID) {
            let id = taskID
            resolved = ResolvedIcon(id: id, data: await model.iconLoader.icon(for: id.url, title: id.title, custom: id.custom))
        }
    }

    private var rxBody: some View {
        VStack(spacing: Theme.RX.Space.s) {
            ItemIcon(type: item.itemType, title: item.title, siteIcon: iconData, size: 76, brand: item.cardBrandName,
                useCategory: item.usesCategoryIcon, tint: ItemTint.color(named: item.color),
                domain: ItemIconResolver.registrableDomain(primaryURL))
                .favoriteBadge(item.favorite, iconSize: 76)
                .shadow(color: .black.opacity(0.12), radius: 9, y: 6)
                .padding(.bottom, Theme.RX.Space.xs)
            Text(item.title)
                .rxFont(.largeTitle)
                .foregroundStyle(Theme.RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .accessibilityIdentifier("item.title")
            Text(subtitle)
                .rxFont(.callout)
                .foregroundStyle(Theme.RX.Palette.textSecondary.color)
                .multilineTextAlignment(.center)
                .dbText(maxLines: 3)
            vaultBadge
                .rxFont(.footnoteBold)
                .foregroundStyle(Theme.RX.Palette.textPrimary.color)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, Theme.RX.Space.xs)
    }

    private var classicBody: some View {
        HStack(alignment: .center, spacing: Theme.Space.l) {
            ItemIcon(type: item.itemType, title: item.title, siteIcon: iconData, size: Self.iconSize, brand: item.cardBrandName,
                useCategory: item.usesCategoryIcon, tint: ItemTint.color(named: item.color),
                domain: ItemIconResolver.registrableDomain(primaryURL))
                .favoriteBadge(item.favorite, iconSize: Self.iconSize)
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
    }
}
