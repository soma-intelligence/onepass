import Foundation
import Testing

@testable import VaultKit

@Suite("Card last four in lists")
struct CardMaskTests {
    private func card(_ last4: String?, subtitle: String = "") -> FfiItemSummary {
        var s = summary("Amex Platinum", subtitle: subtitle, type: .creditCard)
        s.cardLast4 = last4
        return s
    }

    @Test func maskIsShortDotsThenLastFour() {
        #expect(CardMask.text("1005") == "•••• 1005")
        #expect(card("4242").cardMask == "•••• 4242")
        #expect(card("4242").listSubtitle == "•••• 4242")
    }

    @Test func noLastFourMeansNoMask() {
        #expect(card(nil).cardMask == nil)
        #expect(card("").cardMask == nil)
        #expect(card(nil).listSubtitle == "")
    }

    @Test func coreSubtitleWinsOverTheMask() {
        #expect(card("4242", subtitle: "Camille Durand").listSubtitle == "Camille Durand")
        #expect(summary("Atlas", subtitle: "camille@exemple.fr").listSubtitle == "camille@exemple.fr")
    }
}
