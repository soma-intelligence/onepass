import ImageIO
import Foundation
import Testing
import VaultKit

@testable import DesignKit

@Suite struct ItemCategoryTests {
    /// Labels are compared in French, the source language, whatever the machine's language.
    init() { DesignKitStrings.pinSourceLanguage() }

    @Test func everyTypeHasACategory() {
        #expect(ItemCategory.all.count == 26)
        #expect(Set(ItemCategory.all.map(\.plural)).count == 26)
        #expect(Set(ItemCategory.all.map(\.singular)).count == 26)
        for info in itemTypes() {
            #expect(ItemCategory.of(info.itemType).type == info.itemType)
            #expect(!ItemCategory.of(info.itemType).symbol.isEmpty)
        }
    }

    @Test func hexMatchesTileColor() {
        #expect(ItemCategory.of(.login).hex == 0x0E9F9F)
        #expect(ItemCategory.all.allSatisfy { $0.hex <= 0xFFFFFF })
    }

    @Test func orderMatchesCore() {
        #expect(ItemCategory.all.map(\.type) == itemTypes().map(\.itemType))
    }

    @Test func singularMatchesCoreLabels() {
        for info in itemTypes() {
            #expect(ItemCategory.of(info.itemType).singular == info.label)
        }
    }

    @Test func strengthLabels() {
        #expect(StrengthMeter.label(forBits: 0) == "trop court")
        #expect(StrengthMeter.label(forBits: 39.9) == "trop court")
        #expect(StrengthMeter.label(forBits: 40) == "faible")
        #expect(StrengthMeter.label(forBits: 60) == "moyen")
        #expect(StrengthMeter.label(forBits: 80) == "bon")
        #expect(StrengthMeter.label(forBits: 99.9) == "bon")
        #expect(StrengthMeter.label(forBits: 100) == "excellent")
        #expect(StrengthMeter.level(forBits: 39) == 0)
        #expect(StrengthMeter.level(forBits: 250) == 4)
    }

    @Test func integrityTexts() {
        #expect(IntegrityBanner.message(for: "unknown") == "Le stockage a renvoyé des données altérées.")
        #expect(IntegrityBanner.message(for: "manifest_rollback") != IntegrityBanner.message(for: "unknown"))
        #expect(IntegrityBanner.message(for: "account_missing") == "Le compte a disparu du stockage.")
    }

    @Test func noEmDashInTexts() {
        for c in ItemCategory.all {
            #expect(!c.plural.contains("\u{2014}"))
        }
    }

    @Test func vaultColorsResolve() {
        for name in ["blue", "teal", "orange", "green", "purple", "pink", "gray", "inconnu"] {
            _ = VaultBadge.color(named: name)
        }
        #expect(VaultBadge.initial(of: "  projet Atlas") == "P")
        #expect(VaultBadge.initial(of: "") == "?")
    }
}

@Suite struct ItemIconTests {
    // 1x1 PNG.
    static let png = Data(
        base64Encoded:
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")!

    @Test func decodesPNGAndRejectsGarbage() {
        #expect(ItemIcon.decode(Self.png) != nil)
        #expect(ItemIcon.decode(Data([1, 2, 3])) == nil)
        #expect(ItemIcon.decode(Data()) == nil)
    }
}

@Suite struct FieldDisclosureTests {
    @Test func largeOnSecretRevealsAndNotifies() {
        var d = FieldDisclosure()
        let n = d.showLarge(isSecret: true)
        #expect(n)
        #expect(d.revealed && d.large)
    }

    @Test func remaskClosesLarge() {
        var d = FieldDisclosure()
        _ = d.showLarge(isSecret: true)
        let n = d.reveal(false, isSecret: true)
        #expect(n)
        #expect(!d.revealed && !d.large)
    }

    @Test func plainFieldNeverNotifies() {
        var d = FieldDisclosure()
        let n = d.showLarge(isSecret: false)
        #expect(!n)
        #expect(d.large && !d.revealed)
        let m = d.reveal(true, isSecret: false)
        #expect(!m)
    }
}

@Suite struct FieldAutoRemaskTests {
    @Test func remasksAfterDelayOnly() {
        let t0 = Date(timeIntervalSince1970: 1000)
        var d = FieldDisclosure()
        _ = d.reveal(true, isSecret: true, now: t0)
        #expect(!d.shouldRemask(now: t0.addingTimeInterval(29.9), after: 30))
        #expect(d.shouldRemask(now: t0.addingTimeInterval(30), after: 30))
    }

    @Test func largeDisplayCountsAndRemaskClosesIt() {
        let t0 = Date(timeIntervalSince1970: 0)
        var d = FieldDisclosure()
        _ = d.showLarge(isSecret: true, now: t0)
        #expect(d.shouldRemask(now: t0.addingTimeInterval(31), after: 30))
        _ = d.reveal(false, isSecret: true, now: t0.addingTimeInterval(31))
        #expect(!d.large && d.revealedAt == nil)
        #expect(!d.shouldRemask(now: t0.addingTimeInterval(99), after: 30))
    }

    @Test func maskedOrPlainNeverRemask() {
        let d = FieldDisclosure()
        #expect(!d.shouldRemask(now: Date.distantFuture, after: 30))
    }
}

import CoreGraphics
import SwiftUI

/// Site icons on their tiles: artwork fills the tile, a mark loses its plain square and is read
/// for its colors.
@Suite struct SiteIconTreatmentTests {
    /// `side` square: `background` (nil: transparent) with a centered square mark of `markColor`
    /// covering `markFraction` of the side.
    static func icon(
        side: Int = 64, background: (Double, Double, Double)?, markColor: (Double, Double, Double), markFraction: Double = 0.4
    ) -> CGImage {
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        if let background {
            context.setFillColor(red: background.0, green: background.1, blue: background.2, alpha: 1)
            context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        }
        let mark = Double(side) * markFraction
        context.setFillColor(red: markColor.0, green: markColor.1, blue: markColor.2, alpha: 1)
        context.fill(CGRect(x: (Double(side) - mark) / 2, y: (Double(side) - mark) / 2, width: mark, height: mark))
        return context.makeImage()!
    }

    /// White square, colored disc, and inside it a white shape: a round hole or a thin bar.
    static func discWithInside(hole: Bool) -> CGImage {
        let side = 128
        let context = CGContext(
            data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(red: 1, green: 1, blue: 1, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: side, height: side))
        context.setFillColor(red: 0.05, green: 0.45, blue: 0.95, alpha: 1)
        context.fillEllipse(in: CGRect(x: 24, y: 24, width: 80, height: 80))
        context.setFillColor(red: 1, green: 1, blue: 1, alpha: 1)
        if hole {
            context.fillEllipse(in: CGRect(x: 44, y: 44, width: 40, height: 40))
        } else {
            context.fill(CGRect(x: 40, y: 61, width: 48, height: 6))
        }
        return context.makeImage()!
    }

    static func alphaAtCenter(_ image: CGImage) -> UInt8 {
        let bitmap = SiteIconTreatment.Bitmap(image)!
        return UInt8(bitmap.alpha((bitmap.height / 2) * bitmap.width + bitmap.width / 2))
    }

    @Test func roundHoleInAMarkIsCleared() {
        // The loops of an infinity on a white square: background, not a white part of the mark.
        let (image, _) = SiteIconTreatment.prepare(Self.discWithInside(hole: true))
        #expect(Self.alphaAtCenter(image) == 0)
    }

    @Test func thinWhiteShapeInAMarkStays() {
        // A white check or bar inside a colored badge is the mark's own white.
        let (image, _) = SiteIconTreatment.prepare(Self.discWithInside(hole: false))
        #expect(Self.alphaAtCenter(image) == 255)
    }

    @Test func fullBleedArtworkFillsTheTile() {
        // A brand color to the edges with a white mark inside: an app icon.
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: (0.1, 0.4, 0.9), markColor: (1, 1, 1)))
        #expect(treatment == .fullBleed)
    }

    @Test func blackMarkOnTransparentIsAOneColorMark() {
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: nil, markColor: (0, 0, 0)))
        guard case .mark(let monochrome, _, let dark) = treatment else { Issue.record("not a mark"); return }
        #expect(monochrome)
        #expect(dark > 0.95)
    }

    @Test func redMarkKeepsItsColors() {
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: nil, markColor: (0.89, 0.1, 0.13)))
        guard case .mark(let monochrome, _, _) = treatment else { Issue.record("not a mark"); return }
        #expect(!monochrome)
    }

    @Test func plainWhiteSquareIsCleared() throws {
        let (image, treatment) = SiteIconTreatment.prepare(Self.icon(background: (1, 1, 1), markColor: (0.05, 0.05, 0.3)))
        guard case .mark(let monochrome, _, let dark) = treatment else { Issue.record("not a mark"); return }
        #expect(!monochrome || dark > 0.5)
        // The corners are transparent now, the mark is still there.
        let bitmap = try #require(SiteIconTreatment.Bitmap(image))
        #expect(bitmap.alpha(0) == 0)
        #expect(bitmap.alpha(bitmap.width * bitmap.height / 2 + bitmap.width / 2) > 200)
    }

    @Test func whiteArtworkWithASmallDetailStaysArtwork() {
        // Almost all white: clearing it would leave a speck. Kept as it is.
        let (_, treatment) = SiteIconTreatment.prepare(
            Self.icon(background: (1, 1, 1), markColor: (0.9, 0.2, 0.2), markFraction: 0.1))
        #expect(treatment == .fullBleed)
    }

    @Test func tileBackgroundKeepsTheMarkReadable() {
        // Navy mark in dark mode: a light tile. Pale mark in light mode: a dark tile. Any other mark,
        // and every one color mark, sits bare with no tile.
        #expect(ItemIcon.markBackground(monochrome: true, pale: 0, dark: 1, darkMode: true) == nil)
        #expect(ItemIcon.markBackground(monochrome: false, pale: 0, dark: 0.8, darkMode: true) == Color(white: 0.94))
        #expect(ItemIcon.markBackground(monochrome: false, pale: 0.95, dark: 0, darkMode: false) == Color(white: 0.19))
        #expect(ItemIcon.markBackground(monochrome: false, pale: 0.7, dark: 0, darkMode: false) == nil)
        #expect(ItemIcon.markBackground(monochrome: false, pale: 0.5, dark: 0, darkMode: true) == nil)
    }
}

@Suite struct ScanProgressBarTests {
    @Test func fractionIsClampedAndNeedsATotal() {
        #expect(ScanProgressBar.fraction(done: 3, total: 12) == 0.25)
        #expect(ScanProgressBar.fraction(done: 20, total: 12) == 1)
        #expect(ScanProgressBar.fraction(done: -1, total: 12) == 0)
        #expect(ScanProgressBar.fraction(done: 3, total: 0) == nil)
        #expect(ScanProgressBar.fraction(done: nil, total: 12) == nil)
    }

    /// Renders the bar to a PNG for the feedback captures (only when `ONEPASS_FEEDBACK_DIR` is set).
    @MainActor @Test func renderForCaptures() throws {
        guard let folder = ProcessInfo.processInfo.environment["ONEPASS_FEEDBACK_DIR"], !folder.isEmpty else { return }
        for (name, scheme) in [("light", ColorScheme.light), ("dark", .dark)] {
            let view = VStack(spacing: 24) {
                ScanProgressBar(title: Text(verbatim: "Analyse des éléments"))
                ScanProgressBar(
                    title: Text(verbatim: "Vérification des fuites"), detail: Text(verbatim: "42 sur 120"),
                    done: 42, total: 120)
            }
            .padding(20)
            .frame(width: 360)
            .background(scheme == .dark ? Color(white: 0.11) : Color.white)
            .environment(\.colorScheme, scheme)
            let renderer = ImageRenderer(content: view)
            renderer.scale = 3
            let image = try #require(renderer.cgImage)
            let url = URL(fileURLWithPath: folder).appendingPathComponent("scan-progress-\(name).png")
            let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil))
            CGImageDestinationAddImage(destination, image, nil)
            #expect(CGImageDestinationFinalize(destination))
        }
    }
}

@Suite struct SiteIconTileCaptures {
    /// Renders each icon of `ONEPASS_ICON_SAMPLES` (a folder of PNG or ICO files) as its raw image
    /// and as list tiles in light and dark, to `ONEPASS_FEEDBACK_DIR` (captures only).
    @MainActor @Test func renderSamples() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let samples = environment["ONEPASS_ICON_SAMPLES"], let folder = environment["ONEPASS_FEEDBACK_DIR"]
        else { return }
        let files = try FileManager.default.contentsOfDirectory(atPath: samples).sorted()
        let icons = files.compactMap { name -> (String, Data)? in
            guard let data = FileManager.default.contents(atPath: samples + "/" + name) else { return nil }
            return ((name as NSString).deletingPathExtension, data)
        }
        let view = VStack(alignment: .leading, spacing: 14) {
            ForEach(icons, id: \.0) { name, data in
                HStack(spacing: 18) {
                    Text(verbatim: name).font(.headline).frame(width: 90, alignment: .leading)
                    if let raw = ItemIcon.decode(data) {
                        Image(decorative: raw, scale: 1).resizable().interpolation(.high)
                            .frame(width: 38, height: 38)
                            .background(Color.gray.opacity(0.2))
                    }
                    ForEach([ColorScheme.light, .dark], id: \.self) { scheme in
                        ItemIcon(type: .login, title: name, siteIcon: data, size: 38)
                            .padding(10)
                            .background(scheme == .dark ? Color(white: 0.11) : Color.white)
                            .environment(\.colorScheme, scheme)
                    }
                }
            }
        }
        .padding(20)
        .background(Color(white: 0.6))
        let renderer = ImageRenderer(content: view)
        renderer.scale = 3
        let image = try #require(renderer.cgImage)
        let url = URL(fileURLWithPath: folder).appendingPathComponent("site-icon-tiles.png")
        let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
    }
}
