import DesignKit
import SwiftUI
import VaultKit

/// Top of the detail, straight on the window glass: big icon, title, then one secondary line with
/// the category (and the list subtitle) and the vault badge.
struct ItemHeader: View {
    @Environment(AppModel.self) private var model
    let item: FfiItem
    @State private var siteIcon: Data?

    private var vault: FfiVault? { model.session.allVaults.first { $0.id == item.vaultId } }

    private var subtitle: String {
        let category = ItemCategory.of(item.itemType).singular
        let summary = model.session.summaries.first { $0.id == item.id }?.subtitle ?? ""
        return summary.isEmpty ? category : "\(category) · \(summary)"
    }

    private var primaryURL: String? {
        (item.urls.first(where: \.primary) ?? item.urls.first)?.url
    }

    @ViewBuilder private var vaultBadge: some View {
        if let vault {
            HStack(spacing: 5) {
                VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 16)
                Text(vault.meta.name).lineLimit(1)
            }
            .padding(.leading, 3)
            .padding(.trailing, 8)
            .padding(.vertical, 2)
            .background(.fill.quaternary, in: Capsule())
            .accessibilityElement(children: .combine)
            .accessibilityLabel(Text("Coffre \(vault.meta.name)"))
        }
    }

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            ItemIcon(type: item.itemType, title: item.title, siteIcon: siteIcon, size: 64)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(item.title)
                        .font(.title.weight(.bold))
                        .lineLimit(2)
                        .accessibilityIdentifier("item.title")
                    if item.favorite {
                        Image(systemName: "star.fill")
                            .font(.callout)
                            .foregroundStyle(.yellow)
                            .accessibilityLabel(Text("Favori"))
                    }
                }
                #if os(iOS)
                // iPhone: the subtitle on its own line when the vault badge would cut it.
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 8) {
                        Text(subtitle).lineLimit(1)
                        vaultBadge
                    }
                    VStack(alignment: .leading, spacing: 5) {
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
        .task(id: primaryURL) {
            guard let url = primaryURL else {
                siteIcon = nil
                return
            }
            siteIcon = await model.iconLoader.icon(for: url)
        }
    }
}
