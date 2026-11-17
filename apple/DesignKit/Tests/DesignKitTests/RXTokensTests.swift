import CoreText
import SwiftUI
import Testing
import DesignBridgeKit
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

    /// Every colour token of the Penpot file (the generated manifest) has exactly one entry in
    /// `Palette.all`, and its light and dark values are the Penpot values, one by one.
    @Test func paletteMatchesPenpot() throws {
        let colours = RXPenpot.manifest.filter { $0.type == "color" }
        let names = RX.Palette.all.map(\.name)
        #expect(Set(names).count == names.count)
        #expect(Set(names) == Set(colours.map(\.name)))
        for entry in colours {
            let token = try #require(RX.Palette.all.first { $0.name == entry.name }?.token, "\(entry.name) missing")
            for (mode, scheme) in [("light", ColorScheme.light), ("dark", .dark)] {
                let css = try #require(entry.values[mode])
                #expect(token.tone(for: scheme) == RX.Tone(css: css), "\(entry.name) \(mode): \(css)")
            }
        }
    }

    /// The spacing and radius API returns the Penpot value of each token, and every Penpot
    /// dimension token is reachable from the API.
    @Test func dimensionsMatchPenpot() throws {
        let api: [String: CGFloat] = [
            "space.xs": RX.Space.xs, "space.sm": RX.Space.s, "space.md": RX.Space.m, "space.lg": RX.Space.l,
            "space.xl": RX.Space.xl, "space.2xl": RX.Space.xxl,
            "radius.chip": RX.Radius.chip, "radius.tile": RX.Radius.tile, "radius.card": RX.Radius.card,
            "radius.sheet": RX.Radius.sheet, "radius.pill": RX.Radius.pill,
        ]
        let dims = RXPenpot.manifest.filter { $0.type == "dimension" }
        #expect(Set(dims.map(\.name)) == Set(api.keys))
        for entry in dims {
            for (mode, raw) in entry.values {
                #expect(api[entry.name] == CGFloat(Double(raw) ?? .nan), "\(entry.name) \(mode): \(raw)")
            }
        }
        #expect(RX.Space.gutter == RX.Space.l)
    }

    /// Each typography returns the Penpot size, weight, tracking, line height and text style.
    @Test func typographyMatchesPenpot() throws {
        let typos = RXPenpot.manifest.filter { $0.type == "typography" }
        #expect(typos.count == RX.Typography.allCases.count)
        let styles: [String: Font.TextStyle] = [
            "largeTitle": .largeTitle, "title": .title, "title2": .title2, "headline": .headline, "body": .body,
            "callout": .callout, "footnote": .footnote, "caption2": .caption2,
        ]
        for t in RX.Typography.allCases {
            let name = t.rawValue.unicodeScalars.reduce(into: "") { out, c in
                out += CharacterSet.uppercaseLetters.contains(c) ? " " + String(c).lowercased() : String(c)
            }
            let penpotName = name.prefix(1).uppercased() + name.dropFirst()
            let entry = try #require(typos.first { $0.name == penpotName }, "no Penpot typography \(penpotName)")
            let f = try #require(entry.values["light"]).split(separator: "|").map(String.init)
            #expect(f.count == 6)
            let penpotSize = CGFloat(Double(f[0])!)
            #expect(t.spec.size == penpotSize, "\(penpotName) size")
            #expect(t.spec.weight == Int(f[1]), "\(penpotName) weight")
            #expect(t.spec.tracking == CGFloat(Double(f[2])!), "\(penpotName) tracking")
            #expect(t.spec.lineHeight == CGFloat(Double(f[3])!), "\(penpotName) line height")
            #expect(t.textStyle == styles[f[5]], "\(penpotName) text style")
        }
    }

    /// Springs and the press scale from designbridge.json reach Swift unchanged.
    @Test func motionMatchesManifest() throws {
        let springs: [String: RXPenpot.SpringToken] = [
            "motion.spring.snappy": RXPenpot.Motion.snappy, "motion.spring.smooth": RXPenpot.Motion.smooth,
            "motion.spring.bouncy": RXPenpot.Motion.bouncy,
        ]
        for entry in RXPenpot.manifest where entry.type == "spring" {
            let s = try #require(springs[entry.name])
            let f = try #require(entry.values["light"]).split(separator: "|").compactMap { Double($0) }
            #expect([s.duration, s.bounce] == f, "\(entry.name)")
            #expect((0.15...0.5).contains(s.duration))
        }
        #expect(RXPenpot.Motion.pressScale == 0.97)
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
        // Every typography resolves to Inter at its weight, the code included (tabular digits).
        let context = EnvironmentValues().fontResolutionContext
        let headline = RX.Typography.headline.font(size: 17).resolve(in: context).ctFont
        #expect(CTFontCopyFamilyName(headline) as String == "Inter")
        let code = RX.Typography.monoCode.font(size: 30).resolve(in: context).ctFont
        #expect(CTFontCopyFamilyName(code) as String == "Inter")
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

    /// The hero is DesignBridge's scroll hero: it fades over 60% of its height (the kit's
    /// default, which the RX page keeps) and never leaves 0...1.
    @Test func heroFade() {
        func progress(_ offset: CGFloat) -> CGFloat {
            DBScrollHeroMetrics(offset: offset, heroHeight: 300, fadeDistance: 300 * 0.6, parallax: nil,
                                reduceMotion: false).progress
        }
        #expect(progress(-40) == 0)
        #expect(progress(90) == 0.5)
        #expect(progress(900) == 1)
    }
}
