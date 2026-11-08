import Testing
import SwiftUI
@testable import DesignKit

@Suite("Theme metrics")
struct ThemeMetricsTests {
    @Test func spacingScale() {
        let scale: [CGFloat] = [
            Theme.Space.xxs, Theme.Space.xs, Theme.Space.s, Theme.Space.m,
            Theme.Space.l, Theme.Space.xl, Theme.Space.xxl,
        ]
        #expect(scale == [2, 4, 8, 12, 16, 24, 32])
        #expect(Theme.Space.inCard == 12)
        #expect(Theme.Space.betweenSections == 24)
        #expect(Theme.Space.gutter(regularWidth: false) == 16)
        #expect(Theme.Space.gutter(regularWidth: true) == 20)
    }

    @Test func radii() {
        let radii: [CGFloat] = [
            Theme.Radius.chip, Theme.Radius.control, Theme.Radius.card, Theme.Radius.sheet,
        ]
        #expect(radii == [8, 12, 18, 26])
        #expect(Theme.Radius.nested(outer: 18, padding: 12) == 6)
        #expect(Theme.Radius.nested(outer: 8, padding: 12) == 0)
    }

    @Test func cardShadowValues() {
        #expect(Theme.cardShadow.radius == 12)
        #expect(Theme.cardShadow.y == 4)
    }
}
