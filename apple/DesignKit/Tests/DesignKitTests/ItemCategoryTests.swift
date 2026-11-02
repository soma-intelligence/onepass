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

    @Test func fullBleedArtworkFillsTheTile() {
        // A brand color to the edges with a white mark inside: an app icon.
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: (0.1, 0.4, 0.9), markColor: (1, 1, 1)))
        #expect(treatment == .fullBleed)
    }

    @Test func blackMarkOnTransparentIsAOneColorMark() {
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: nil, markColor: (0, 0, 0)))
        guard case .mark(let monochrome, let luminance) = treatment else { Issue.record("not a mark"); return }
        #expect(monochrome)
        #expect(luminance < 0.05)
    }

    @Test func redMarkKeepsItsColors() {
        let (_, treatment) = SiteIconTreatment.prepare(Self.icon(background: nil, markColor: (0.89, 0.1, 0.13)))
        guard case .mark(let monochrome, _) = treatment else { Issue.record("not a mark"); return }
        #expect(!monochrome)
    }

    @Test func plainWhiteSquareIsCleared() throws {
        let (image, treatment) = SiteIconTreatment.prepare(Self.icon(background: (1, 1, 1), markColor: (0.05, 0.05, 0.3)))
        guard case .mark(let monochrome, let luminance) = treatment else { Issue.record("not a mark"); return }
        #expect(!monochrome || luminance < 0.2)
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
        // Navy mark in dark mode: a light tile. Pale mark in light mode: a dark tile.
        #expect(ItemIcon.markBackground(monochrome: false, luminance: 0.1, dark: true) == Color(white: 0.94))
        #expect(ItemIcon.markBackground(monochrome: false, luminance: 0.9, dark: false) == Color(white: 0.19))
        #expect(ItemIcon.markBackground(monochrome: false, luminance: 0.5, dark: false) == .white)
    }
}
