import ImageIO
import SwiftUI
import Testing
import VaultKit

@testable import DesignKit

@Suite struct ItemIconChoiceSheet {
    /// The icon choices of the item editor (spec 2026-11-13) through the real `ItemIcon`, light and
    /// dark, to `ONEPASS_FEEDBACK_DIR/item-icon-choices.png` (captures only, skipped otherwise).
    /// Fictitious data: a made up site icon, made up titles.
    @MainActor @Test func render() throws {
        guard let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"] else { return }
        // Real brand icons from the bundled icon pack (public assets, no vault data).
        let packURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("IconPack/onepass-icons.bin")
        let pack = try IconPack(data: try Data(contentsOf: packURL))
        let hosts = ["github.com", "google.com", "apple.com", "netflix.com", "spotify.com", "notion.so",
            "paypal.com", "amazon.fr", "airbnb.com", "slack.com"]
        let rows: [(FfiItemType, String, Data?)] = hosts.map { (.login, $0, pack.icon(forHost: $0)?.data) }
        let columns: [(String, Bool, String?)] = [
            ("Avant", false, nil), ("Après : site + couleur", false, "indigo"),
            ("Catégorie", true, nil), ("Catégorie + couleur", true, "teal"),
        ]
        func sheet(_ scheme: ColorScheme) -> some View {
            Grid(horizontalSpacing: 22, verticalSpacing: 14) {
                GridRow {
                    Text(verbatim: "")
                    ForEach(columns.indices, id: \.self) { c in
                        Text(verbatim: columns[c].0).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    }
                }
                ForEach(rows.indices, id: \.self) { r in
                    GridRow {
                        Text(verbatim: rows[r].1).font(.callout).frame(width: 130, alignment: .leading)
                        ForEach(columns.indices, id: \.self) { c in
                            ItemIcon(
                                type: rows[r].0, title: rows[r].1, siteIcon: rows[r].2, size: 44,
                                useCategory: columns[c].1, tint: ItemTint.color(named: columns[c].2))
                        }
                    }
                }
            }
            .padding(24)
            .background(scheme == .dark ? Color(white: 0.07) : Color(white: 0.96))
            .environment(\.colorScheme, scheme)
        }
        let renderer = ImageRenderer(content: VStack(spacing: 0) { sheet(.light); sheet(.dark) })
        renderer.scale = 2
        let image = try #require(renderer.cgImage)
        let url = URL(fileURLWithPath: folder).appendingPathComponent("item-icon-brands.png")
        let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
    }
}
