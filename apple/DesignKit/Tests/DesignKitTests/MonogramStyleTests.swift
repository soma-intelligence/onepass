import Foundation
import Testing

@testable import DesignKit

@Suite("MonogramStyle")
struct MonogramStyleTests {
    private let fixtureDomains: [String] = [
        "bacloud.co.uk",
        "balu.fr",
        "banet.co.uk",
        "banet.de",
        "bankba.de",
        "bankcloud.co.uk",
        "bankdra.co.uk",
        "bankgro.fr",
        "bankgro.org",
        "bankko.net",
        "bankmail.com",
        "bankpay.net",
        "bankpay.org",
        "bapay.io",
        "bapel.org",
        "basun.io",
        "baze.io",
        "baze.net",
        "cloudcloud.com",
        "cloudgro.io",
        "cloudko.co.uk",
        "cloudko.org",
        "cloudne.net",
        "cloudso.de",
        "cloudsun.com",
        "cloudvi.org",
        "cloudweb.fr",
        "dracloud.org",
        "dradra.net",
        "fradra.com",
        "framail.org",
        "frami.com",
        "frapay.de",
        "frasun.io",
        "fravi.co.uk",
        "groba.net",
        "groso.co.uk",
        "groweb.org",
        "kofra.com",
        "kogro.org",
        "kopay.fr",
        "lubank.org",
        "lucloud.org",
        "lumi.io",
        "mailcloud.net",
        "mailgro.fr",
        "mailko.fr",
        "mailnet.net",
        "mailvi.com",
        "migro.fr",
        "miko.io",
        "miso.io",
        "mivi.com",
        "neba.org",
        "nefra.io",
        "neko.co.uk",
        "nenet.fr",
        "nepay.net",
        "nepel.io",
        "netcloud.com",
        "netmail.de",
        "netnet.com",
        "netze.io",
        "nevi.co.uk",
        "paydra.co.uk",
        "pelbank.co.uk",
        "pelbank.org",
        "pellu.net",
        "pelmi.com",
        "pelne.de",
        "pelso.org",
        "sogro.io",
        "solu.org",
        "suncloud.com",
        "sundra.co.uk",
        "sunfra.io",
        "sunfra.net",
        "sunko.io",
        "sunmi.com",
        "sunne.fr",
        "sunsun.de",
        "sunvi.org",
        "sunze.io",
        "tacloud.net",
        "tacloud.org",
        "tagro.de",
        "vicloud.io",
        "vita.co.uk",
        "viweb.de",
        "vize.fr",
        "webfra.io",
        "webpay.org",
        "zegro.de",
        "zemail.net",
        "zene.co.uk",
        "zenet.com",
        "zepay.fr",
        "zesun.de",
        "zevi.de",
        "zeweb.org"
    ]

    private func luminance(_ c: MonogramStyle.RGB) -> Double {
        func lin(_ v: Int) -> Double {
            let s = Double(v) / 255
            return s <= 0.03928 ? s / 12.92 : pow((s + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * lin(c.red) + 0.7152 * lin(c.green) + 0.0722 * lin(c.blue)
    }

    /// WCAG 2 contrast of white text on a background.
    private func whiteContrast(_ c: MonogramStyle.RGB) -> Double { 1.05 / (luminance(c) + 0.05) }

    @Test func paletteHasTwelveEntries() {
        #expect(MonogramStyle.palette.count == 12)
        #expect(MonogramStyle.paletteRGB.count == 12)
    }

    @Test func sameDomainSameColor() {
        #expect(MonogramStyle.colorIndex(seed: "free.fr") == MonogramStyle.colorIndex(seed: "FREE.fr"))
    }

    @Test func indexInRange() {
        for d in fixtureDomains { #expect((0..<12).contains(MonogramStyle.colorIndex(seed: d))) }
    }

    @Test func spreadsOver100Domains() {
        #expect(fixtureDomains.count == 100)
        #expect(Set(fixtureDomains.map { MonogramStyle.colorIndex(seed: $0) }).count >= 10)
    }

    @Test func whiteTextContrast() {
        for c in MonogramStyle.paletteRGB {
            #expect(whiteContrast(c.light) >= 3)
            #expect(whiteContrast(c.dark) >= 3)
        }
    }

    @Test func letterFromTitle() { #expect(MonogramStyle.letter(title: " banque postale", domain: nil) == "B") }
    @Test func digitKept() { #expect(MonogramStyle.letter(title: "1Fichier", domain: nil) == "1") }
    @Test func emojiFallsBackToDomain() {
        #expect(MonogramStyle.letter(title: "🏦 Compte", domain: "labanquepostale.fr") == "L")
    }
    @Test func blankTitleUsesDomain() { #expect(MonogramStyle.letter(title: "   ", domain: "ameli.fr") == "A") }
    @Test func nothing() { #expect(MonogramStyle.letter(title: "", domain: nil) == nil) }
}
