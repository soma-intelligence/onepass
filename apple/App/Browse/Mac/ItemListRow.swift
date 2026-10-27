import DesignKit
import SwiftUI
import VaultKit

/// One row of an item list (Mac and iPad list column, iPhone lists): icon (site icon when loaded,
/// otherwise the category tile), title, subtitle, the vault name when the list mixes vaults, and a
/// star for favorites. Platform neutral: the host list handles selection or navigation.
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
            if summary.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(.yellow)
                    .accessibilityLabel(Text("Favori"))
            }
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
