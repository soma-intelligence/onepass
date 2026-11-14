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

    /// The monogram tile (`MonogramStyle`) as a list shows it, light and dark, to
    /// `ONEPASS_FEEDBACK_DIR/item-icon-monograms.png`: a color per domain (two items of one site
    /// match), the letter from the title or else the domain, the category artwork when neither
    /// has one, and a small site icon drawn bare next to a sharp one. Fictitious titles and domains.
    @MainActor @Test func monograms() throws {
        guard let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"] else { return }
        let rows: [(title: String, domain: String?, icon: Data?, note: String)] = [
            ("Atlas Cloud", "atlas-cloud.example", nil, "atlas-cloud.example"),
            ("Atlas (travail)", "atlas-cloud.example", nil, "même domaine"),
            ("banque horizon", "banque-horizon.example", nil, "minuscule"),
            ("Zéphyr Voyages", "zephyr.example", nil, "accent"),
            ("4G Box", "box4g.example", nil, "chiffre"),
            ("Nébuleuse", nil, nil, "sans adresse"),
            ("Orme & Fils", "orme.example", nil, "esperluette"),
            ("Quartz Mail", "quartz.example", nil, "Q"),
            ("🔑 Wi-Fi", "kiwi-net.example", nil, "emoji : lettre du domaine"),
            ("🔑", nil, nil, "emoji sans domaine"),
            ("", nil, nil, "titre vide"),
            ("Petit favicon", "petit.example", Self.favicon(64), "64 px stocké : nu"),
            ("Favicon net", "net.example", Self.favicon(256), "256 px : plein"),
        ]
        func sheet(_ scheme: ColorScheme) -> some View {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(rows.indices, id: \.self) { r in
                    HStack(spacing: 12) {
                        ItemIcon(type: .login, title: rows[r].title, siteIcon: rows[r].icon, size: 38, domain: rows[r].domain)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(verbatim: rows[r].title.isEmpty ? "(sans titre)" : rows[r].title).font(.body)
                            Text(verbatim: rows[r].note).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                        ItemIcon(type: .login, title: rows[r].title, siteIcon: rows[r].icon, size: 64, domain: rows[r].domain)
                    }
                    .frame(width: 330)
                }
                HStack(spacing: 10) {
                    ForEach(MonogramStyle.palette.indices, id: \.self) { i in
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .fill(scheme == .dark ? MonogramStyle.palette[i].dark : MonogramStyle.palette[i].light)
                            .frame(width: 18, height: 18)
                    }
                }
            }
            .padding(24)
            .background(scheme == .dark ? Color(white: 0.07) : Color(white: 0.96))
            .environment(\.colorScheme, scheme)
        }
        let renderer = ImageRenderer(content: HStack(spacing: 0) { sheet(.light); sheet(.dark) })
        renderer.scale = 3
        let image = try #require(renderer.cgImage)
        let url = URL(fileURLWithPath: folder).appendingPathComponent("item-icon-monograms.png")
        let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
    }

    /// A made up site icon, `side` pixels: a rounded orange square with a white bar, transparent
    /// corners (an app icon shape, drawn full bleed when sharp enough).
    static func favicon(_ side: Int) -> Data {
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        let s = CGFloat(side)
        context.addPath(CGPath(roundedRect: CGRect(x: 0, y: 0, width: s, height: s), cornerWidth: s * 0.22, cornerHeight: s * 0.22, transform: nil))
        context.setFillColor(CGColor(red: 0.95, green: 0.45, blue: 0.1, alpha: 1))
        context.fillPath()
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        context.fill(CGRect(x: s * 0.3, y: s * 0.2, width: s * 0.16, height: s * 0.6))
        context.fill(CGRect(x: s * 0.3, y: s * 0.64, width: s * 0.4, height: s * 0.16))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(data, "public.png" as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, nil)
        CGImageDestinationFinalize(destination)
        return data as Data
    }
}
