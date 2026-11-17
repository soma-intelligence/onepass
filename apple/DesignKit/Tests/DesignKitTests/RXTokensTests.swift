import CoreText
import SwiftUI
import Testing
@testable import DesignKit

@Suite("RX tokens")
struct RXTokensTests {
    private typealias RX = Theme.RX

    @Test func readsHex() throws {
        let tone = try #require(RX.Tone(css: "#5856D6"))
        #expect(tone == RX.Tone(red: 0x58 / 255, green: 0x56 / 255, blue: 0xD6 / 255))
        #expect(tone.alpha == 1)
    }

    @Test func readsRGBA() throws {
        let tone = try #require(RX.Tone(css: "rgba(118,118,128,0.24)"))
        #expect(tone == RX.Tone(red: 118 / 255, green: 118 / 255, blue: 128 / 255, alpha: 0.24))
        #expect(RX.Tone(css: " rgba(255, 255, 255, 0.72) ")?.alpha == 0.72)
    }

    @Test func refusesGarbage() {
        for bad in ["", "#FFF", "#GGGGGG", "rgb(1,2,3)", "rgba(1,2,3)", "rgba(300,0,0,1)", "rgba(0,0,0,2)", "indigo"] {
            #expect(RX.Tone(css: bad) == nil, "accepted \(bad)")
        }
    }

    @Test func resolvesPerScheme() {
        let page = RX.Palette.pageBackground
        #expect(page.tone(for: .light) == RX.Tone(css: "#F2F2F7"))
        #expect(page.tone(for: .dark) == RX.Tone(css: "#000000"))
        #expect(RX.Palette.accentText.tone(for: .dark) == RX.Tone(css: "#A3A2E8"))
    }

    /// The Penpot file has 18 colour tokens; every name appears once, and the accent base is the
    /// house indigo in both modes.
    @Test func paletteMatchesPenpot() {
        let names = RX.Palette.all.map(\.name)
        #expect(names.count == 18)
        #expect(Set(names).count == names.count)
        #expect(RX.Palette.accent.light == RX.Palette.accent.dark)
        #expect(RX.Palette.accent.light == RX.Tone(css: "#5856D6"))
    }

    @Test func spacingAndRadius() {
        #expect([RX.Space.xs, RX.Space.s, RX.Space.m, RX.Space.l, RX.Space.xl, RX.Space.xxl] == [4, 8, 12, 16, 24, 32])
        #expect([RX.Radius.chip, RX.Radius.tile, RX.Radius.card, RX.Radius.sheet] == [12, 16, 24, 36])
        #expect(RX.Metrics.glassButton == 44)
        #expect(RX.Metrics.actionDisc == 48)
        #expect(RX.Metrics.itemPitch == 64)
        #expect(RX.Metrics.menuPitch == 56)
        #expect(RX.Metrics.discGlyph(diameter: 40) == 20)
        #expect(RX.Metrics.discGlyph(diameter: 36) == 18)
    }

    @Test func typographyTable() {
        #expect(RX.Typography.allCases.count == 12)
        #expect(RX.Typography.display.spec.size == 56)
        #expect(RX.Typography.bodyMedium.spec.weight == 500)
        #expect(RX.Typography.callout.spec.size == 15)
        #expect(RX.Typography.caption.spec.tracking == 0.1)
        #expect(RX.Typography.headline.weight == .semibold)
        #expect(RX.Typography.bodyMedium.weight == .medium)
        #expect(RX.Typography.display.weight == .bold)
    }

    @Test func bundlesInter() throws {
        #expect(RX.Inter.isAvailable)
        let font = CTFontCreateWithName("Inter" as CFString, 17, nil)
        #expect(CTFontCopyFamilyName(font) as String == "Inter")
        // The Latin subset covers French, English, Spanish and Italian.
        let text = "çœéñ€àèìòù¿¡’« »"
        var glyphs = [CGGlyph](repeating: 0, count: text.utf16.count)
        #expect(CTFontGetGlyphsForCharacters(font, Array(text.utf16), &glyphs, glyphs.count))
        // The typographies resolve to Inter at their weight, the code to the system face.
        let context = EnvironmentValues().fontResolutionContext
        let headline = RX.Typography.headline.font(size: 17).resolve(in: context).ctFont
        #expect(CTFontCopyFamilyName(headline) as String == "Inter")
        let code = RX.Typography.monoCode.font(size: 28).resolve(in: context).ctFont
        #expect(CTFontCopyFamilyName(code) as String != "Inter")
        let licence = try #require(RX.Inter.licenceURL)
        #expect(try String(contentsOf: licence, encoding: .utf8).contains("SIL OPEN FONT LICENSE Version 1.1"))
    }

    @Test func cssWeights() {
        let pairs: [(Int, Font.Weight)] = [(100, .ultraLight), (300, .light), (400, .regular), (500, .medium),
                                           (600, .semibold), (700, .bold), (800, .heavy), (900, .black)]
        for (css, weight) in pairs {
            #expect(RX.Typography.fontWeight(css) == weight, "weight \(css)")
        }
    }

    /// SwiftUI draws lines at about 1.2 x the size: only the extra goes into line spacing, never a
    /// negative value for tight typographies.
    @Test func lineSpacing() {
        #expect(abs(RX.Typography.lineSpacing(size: 17, lineHeight: 1.3) - 1.7) < 0.0001)
        #expect(RX.Typography.lineSpacing(size: 56, lineHeight: 1.0) == 0)
        #expect(RX.Typography.lineSpacing(size: 22, lineHeight: 1.2) == 0)
    }

    @Test func flagDefaultsOff() {
        #expect(RXDesign.isOn(stored: nil, launchArgument: nil) == false)
        #expect(RXDesign.isOn(stored: nil, launchArgument: true) == true)
        #expect(RXDesign.isOn(stored: false, launchArgument: true) == false)
        #expect(RXDesign.isOn(stored: true, launchArgument: nil) == true)
        #expect(RXDesign.storageKey == "onepass.design.rx")
    }

    /// The RX logo scale fills the tile and still leaves an inset on the mark's long side.
    @Test func rxLogoKeepsAnInset() {
        #expect(ItemIcon.rxMarkScale > 1)
        #expect(ItemIcon.markMaxSide * ItemIcon.rxMarkScale <= 0.9)
        #expect(ItemIcon.markOpticalSide * ItemIcon.rxMarkScale >= 0.65)
    }

    /// The hero fades over 70% of its height and never leaves 0...1.
    @Test func heroFade() {
        #expect(RXHeroPage<EmptyView, EmptyView>.fade(offset: -40, heroHeight: 300) == 0)
        #expect(RXHeroPage<EmptyView, EmptyView>.fade(offset: 105, heroHeight: 300) == 0.5)
        #expect(RXHeroPage<EmptyView, EmptyView>.fade(offset: 900, heroHeight: 300) == 1)
    }
}
