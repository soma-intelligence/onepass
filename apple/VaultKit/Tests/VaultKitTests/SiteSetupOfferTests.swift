import Foundation
import Testing

@testable import VaultKit

@Suite("Site setup offer")
struct SiteSetupOfferTests {
    private func link(
        _ id: String, host: String = "github.com", settings: String? = nil, help: String? = nil,
        recipe: Bool = false
    ) -> FfiSiteLink {
        FfiSiteLink(itemId: id, host: host, settingsUrl: settings, helpUrl: help, hasRecipe: recipe)
    }

    private func report(_ checks: [String: [FfiSiteLink]]) -> FfiWatchtowerReport {
        FfiWatchtowerReport(
            score: 80, itemsAnalyzed: 1,
            checks: checks.map {
                FfiWatchtowerCheck(
                    check: $0.key, findings: UInt32($0.value.count), itemIds: $0.value.map(\.itemId),
                    siteLinks: $0.value)
            },
            strength: [0, 0, 0, 0, 0], pwned: .checked, missingPrefixes: [], sitesChecked: true)
    }

    private func login(primary: String = "https://www.github.com/login") -> FfiItem {
        var item = draftItem(.login)
        item.urls = [FfiUrl(label: "", url: primary, rule: .domain, primary: true)]
        return item
    }

    @Test func twoFactorComesBeforePasskey() {
        let item = login()
        let r = report([
            "passkey_available": [link(item.id, settings: "https://github.com/settings/security")],
            "missing_2fa": [link(item.id, help: "https://docs.github.com/2fa")],
        ])
        let offers = SiteSetupOffer.offers(for: item, report: r)
        #expect(offers.map(\.kind) == [.twoFactor, .passkey])
        #expect(offers.allSatisfy { $0.itemID == item.id })
    }

    @Test func excludedCheckGivesNoOffer() {
        var item = login()
        item.watchtowerExclusions = ["missing_2fa"]
        let r = report([
            "missing_2fa": [link(item.id, help: "https://docs.github.com/2fa")],
            "passkey_available": [link(item.id)],
        ])
        #expect(SiteSetupOffer.offers(for: item, report: r).map(\.kind) == [.passkey])
        item.watchtowerExclusions = ["missing_2fa", "passkey_available"]
        #expect(SiteSetupOffer.offers(for: item, report: r).isEmpty)
    }

    @Test func loginWithACodeGetsNoTwoFactorOffer() {
        var item = login()
        item.sections[0].fields.append(
            FfiField(
                id: "totp", label: "", kind: .otp, value: .otp(value: "JBSWY3DPEHPK3PXP"), required: false,
                repeatable: false, autofill: true))
        item.loginMethods = [.passkey]
        let r = report([
            "missing_2fa": [link(item.id, help: "https://docs.github.com/2fa")],
            "passkey_available": [link(item.id)],
        ])
        #expect(SiteSetupOffer.offers(for: item, report: r).isEmpty)
    }

    @Test func notALoginOrTrashedOrArchivedGetsNoOffer() {
        let r = { (id: String) in self.report(["missing_2fa": [self.link(id, help: "https://docs.github.com/2fa")]]) }
        let note = draftItem(.secureNote)
        #expect(SiteSetupOffer.offers(for: note, report: r(note.id)).isEmpty)
        var trashed = login()
        trashed.trashedAt = 1_790_000_100
        #expect(SiteSetupOffer.offers(for: trashed, report: r(trashed.id)).isEmpty)
        var archived = login()
        archived.archived = true
        #expect(SiteSetupOffer.offers(for: archived, report: r(archived.id)).isEmpty)
        #expect(SiteSetupOffer.offers(for: login(), report: nil).isEmpty)
    }

    @Test func settingsUrlBeatsHelp() {
        let item = login()
        let r = report([
            "missing_2fa": [link(item.id, settings: "https://github.com/settings/security", help: "https://docs.github.com/2fa")]
        ])
        let offer = SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: r)
        #expect(offer?.action == .openSettings(URL(string: "https://github.com/settings/security")!))
        let helpOnly = report(["missing_2fa": [link(item.id, help: "https://docs.github.com/2fa")]])
        #expect(
            SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: helpOnly)?.action
                == .seeHow(URL(string: "https://docs.github.com/2fa")!))
    }

    @Test func twoFactorWithoutSettingsOrHelpGivesNoOffer() {
        let item = login()
        let r = report(["missing_2fa": [link(item.id)]])
        #expect(SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: r) == nil)
        #expect(SiteSetupOffer.offers(for: item, report: r).isEmpty)
    }

    @Test func passkeyWithoutSettingsFindsTheWellKnownPage() {
        let item = login()
        let r = report(["passkey_available": [link(item.id, help: "https://docs.github.com/passkeys")]])
        #expect(
            SiteSetupOffer.offer(kind: .passkey, itemID: item.id, report: r)?.action
                == .findPasskeyPage(host: "github.com"))
        let withSettings = report(["passkey_available": [link(item.id, settings: "https://github.com/settings/security")]])
        #expect(
            SiteSetupOffer.offer(kind: .passkey, itemID: item.id, report: withSettings)?.action
                == .openSettings(URL(string: "https://github.com/settings/security")!))
    }

    @Test func hostIsTheMatchedOneNotThePrimary() {
        let item = login(primary: "https://login.example.org")
        let r = report(["passkey_available": [link(item.id, host: "github.com")]])
        let offer = SiteSetupOffer.offer(kind: .passkey, itemID: item.id, report: r)
        #expect(offer?.host == "github.com")
        #expect(offer?.action == .findPasskeyPage(host: "github.com"))
        #expect(SiteSetupOffer.offers(for: item, report: r).first?.host == "github.com")
    }

    @Test func hasRecipeIsCarriedButNeverChangesTheAction() {
        let item = login()
        let plain = report(["missing_2fa": [link(item.id, settings: "https://github.com/settings/security")]])
        let recipe = report(["missing_2fa": [link(item.id, settings: "https://github.com/settings/security", recipe: true)]])
        let a = SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: plain)
        let b = SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: recipe)
        #expect(a?.hasRecipe == false)
        #expect(b?.hasRecipe == true)
        #expect(a?.action == b?.action)
    }

    @Test func otherItemsLinksAreNotUsed() {
        let item = login()
        let r = report(["missing_2fa": [link("other", help: "https://docs.github.com/2fa")]])
        #expect(SiteSetupOffer.offer(kind: .twoFactor, itemID: item.id, report: r) == nil)
    }
}
