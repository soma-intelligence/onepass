import ImageIO
import SwiftUI
import Testing
import VaultKit

@testable import DesignKit

@Suite struct IconPackContactSheet {
    /// Before and after site icons through the real `ItemIcon`, light and dark, list rows (40 pt)
    /// and the detail header size (72 pt), to `ONEPASS_FEEDBACK_DIR/icon-pack-contact-sheet.png`
    /// (captures only). `ONEPASS_ICON_SHEET` holds `before/` and `after/`, one file per row named
    /// `<order>-<title>.<png|webp|ico>`; a row with no file in a column shows what the app shows
    /// with no icon (the monogram tile). An optional `notes.json` (row name to text) adds a last
    /// column, and `ONEPASS_ICON_SHEET_NAME` names the PNG (default `icon-pack-contact-sheet`).
    @MainActor @Test func render() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let sheet = environment["ONEPASS_ICON_SHEET"], let folder = environment["ONEPASS_FEEDBACK_DIR"]
        else { return }
        func files(_ column: String) -> [String: Data] {
            let path = sheet + "/" + column
            let names = (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
            var out: [String: Data] = [:]
            for name in names where !name.hasPrefix(".") {
                out[(name as NSString).deletingPathExtension] = FileManager.default.contents(atPath: path + "/" + name)
            }
            return out
        }
        let before = files("before"), after = files("after")
        let notes = FileManager.default.contents(atPath: sheet + "/notes.json")
            .flatMap { try? JSONDecoder().decode([String: String].self, from: $0) } ?? [:]
        let rows = Set(before.keys).union(after.keys).union(files("none").keys).sorted()
        func title(_ row: String) -> String {
            row.split(separator: "-", maxSplits: 1).last.map(String.init) ?? row
        }
        func cell(_ data: Data?, _ row: String, _ scheme: ColorScheme, size: CGFloat) -> some View {
            ItemIcon(type: .login, title: title(row), siteIcon: data, size: size)
                .frame(width: size + 16, height: 88)
                .background(scheme == .dark ? Color(white: 0.11) : Color.white)
                .environment(\.colorScheme, scheme)
        }
        let header = HStack(spacing: 0) {
            Text(verbatim: "").frame(width: 120)
            ForEach(["Before", "After", "After, header"], id: \.self) { label in
                Text(verbatim: label).font(.headline)
                    .frame(width: label == "After, header" ? 2 * 88 : 2 * 56, alignment: .center)
                    .padding(.horizontal, 8)
            }
            if !notes.isEmpty {
                Text(verbatim: "Status").font(.headline).frame(width: 300, alignment: .leading).padding(.leading, 8)
            }
        }
        let view = VStack(alignment: .leading, spacing: 2) {
            header.padding(.bottom, 8)
            ForEach(rows, id: \.self) { row in
                HStack(spacing: 0) {
                    Text(verbatim: title(row)).font(.body.weight(.medium)).frame(width: 120, alignment: .leading)
                    HStack(spacing: 0) {
                        cell(before[row], row, .light, size: 40)
                        cell(before[row], row, .dark, size: 40)
                    }.padding(.horizontal, 8)
                    HStack(spacing: 0) {
                        cell(after[row], row, .light, size: 40)
                        cell(after[row], row, .dark, size: 40)
                    }.padding(.horizontal, 8)
                    HStack(spacing: 0) {
                        cell(after[row], row, .light, size: 72)
                        cell(after[row], row, .dark, size: 72)
                    }.padding(.horizontal, 8)
                    if !notes.isEmpty {
                        Text(verbatim: notes[row] ?? "").font(.callout).lineLimit(4)
                            .frame(width: 300, alignment: .leading).padding(.leading, 8)
                    }
                }
            }
        }
        .padding(24)
        .background(Color(white: 0.86))
        .environment(\.colorScheme, .light)
        let renderer = ImageRenderer(content: view)
        renderer.scale = 3
        let image = try #require(renderer.cgImage)
        let name = environment["ONEPASS_ICON_SHEET_NAME"] ?? "icon-pack-contact-sheet"
        let url = URL(fileURLWithPath: folder).appendingPathComponent(name + ".png")
        let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
    }
}
