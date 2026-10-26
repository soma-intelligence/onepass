import DesignKit
import SwiftUI
import VaultKit

/// Top of the detail (mockups `Main` and `PhoneItem`): icon, title, subtitle, vault badge.
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

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            ItemIcon(type: item.itemType, title: item.title, siteIcon: siteIcon, size: 56)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title)
                    .font(.title2.weight(.semibold))
                    .lineLimit(2)
                    .accessibilityIdentifier("item.title")
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if let vault {
                    HStack(spacing: 6) {
                        VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 18)
                        Text(vault.meta.name).font(.footnote).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel(Text("Coffre \(vault.meta.name)"))
                }
            }
            Spacer(minLength: 0)
            if item.favorite {
                Image(systemName: "star.fill")
                    .foregroundStyle(.yellow)
                    .accessibilityLabel(Text("Favori"))
            }
        }
        .padding(.vertical, 4)
        .task(id: primaryURL) {
            guard let url = primaryURL else {
                siteIcon = nil
                return
            }
            siteIcon = await model.iconLoader.icon(for: url)
        }
    }
}
