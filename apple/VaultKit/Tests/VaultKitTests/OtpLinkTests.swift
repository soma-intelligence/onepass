import Foundation
import Testing

@testable import VaultKit

@Suite("Verification code links")
struct OtpLinkTests {
    static let link = "otpauth://totp/Test:moi@exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Test"
    /// Google Authenticator export of one account, GitHub:quentin, secret "12345678901234567890".
    static let migration =
        "otpauth-migration://offline?data=CjQKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg5HaXRIdWI6cXVlbnRpbhoGR2l0SHViIAEoATAC"

    @Test(arguments: [
        ("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP", true),
        ("OTPAUTH://totp/X?secret=JBSWY3DPEHPK3PXP", true),
        ("otpauth-migration://offline?data=abc", true),
        ("onepass://item/a/b", false),
        ("https://example.com", false),
    ])
    func routesOnlyVerificationCodeSchemes(url: String, expected: Bool) throws {
        #expect(OtpLink.handles(try #require(URL(string: url))) == expected)
        #expect(OtpLink.isLink(url) == expected)
    }

    @Test func singleLinkGivesOneAccountWithItsNames() throws {
        let accounts = try OtpLink.accounts(in: Self.link)
        #expect(accounts.count == 1)
        let account = accounts[0]
        #expect(account.issuer == "Test")
        #expect(account.account == "moi@exemple.fr")
        #expect(account.title == "Test")
        #expect(account.username == "moi@exemple.fr")
        let code = try #require(account.code(at: Date(timeIntervalSince1970: 59)))
        #expect(code.code.count == 6)
        #expect(code.period == 30)
        // The secret never shows in a description.
        #expect(!String(describing: account).contains("JBSWY3DPEHPK3PXP"))
        #expect(!String(reflecting: account).contains("JBSWY3DPEHPK3PXP"))
    }

    @Test func migrationListsItsAccounts() throws {
        let accounts = try OtpLink.accounts(in: Self.migration)
        #expect(accounts.map(\.title) == ["GitHub"])
        #expect(accounts[0].username == "quentin")
        #expect(accounts[0].code(at: Date(timeIntervalSince1970: 59))?.code == "287082")
    }

    @Test(arguments: [
        "otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/X",
        "https://example.com",
    ])
    func refusesWhatIsNotATotpLink(link: String) {
        #expect(throws: (any Error).self) { try OtpLink.accounts(in: link) }
    }

    @Test func suggestionsPutTheIssuerFirst() throws {
        let account = try #require(try OtpLink.accounts(in: Self.link).first)
        func summary(_ id: String, _ title: String, _ subtitle: String = "", url: String? = nil) -> FfiItemSummary {
            FfiItemSummary(
                id: id, vaultId: "v", itemType: .login, title: title, subtitle: subtitle, favorite: false, tags: [],
                primaryUrl: url, archived: false, trashedAt: nil, createdAt: 0, updatedAt: 0, signInProvider: nil,
                cardBrand: nil)
        }
        let logins = [
            summary("a", "Banque"),
            summary("b", "Autre", "moi@exemple.fr"),
            summary("c", "Compte test"),
            summary("d", "Site", url: "https://test.exemple.fr"),
        ]
        #expect(account.suggestions(in: logins).map(\.id) == ["c", "d", "b"])
    }
}

@Suite("Verification code links into items")
@MainActor
struct OtpLinkSessionTests {
    func unlocked() async throws -> (SessionHarness, VaultSession) {
        let h = try SessionHarness()
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return (h, session)
    }

    func otp(_ item: FfiItem) -> String? {
        item.sections.lazy.flatMap(\.fields).first { $0.id == "totp" }?.value.text
    }

    @Test func createsALoginNamedAfterTheIssuer() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let account = try #require(try OtpLink.accounts(in: OtpLinkTests.link).first)
        let item = try await session.createLogin(with: account, vaultID: session.allVaults[0].id)
        #expect(item.itemType == .login)
        #expect(item.title == "Test")
        #expect(item.sections.lazy.flatMap(\.fields).first { $0.id == "username" }?.value.text == "moi@exemple.fr")
        let uri = try #require(otp(item))
        #expect(try totpNow(secretOrUri: uri, unixSeconds: 59).code
            == totpNow(secretOrUri: "JBSWY3DPEHPK3PXP", unixSeconds: 59).code)
        #expect(session.otpCandidateLogins(query: "test").map(\.id) == [item.id])
    }

    @Test func attachesToAnExistingLoginAndReplacesItsCode() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let vault = session.allVaults[0].id
        var login = try session.newItem(type: .login, vaultID: vault)
        login.title = "GitHub"
        fillRequired(&login)
        login = try await session.save(login)
        #expect(try await session.otpTarget(itemID: login.id, vaultID: vault, confirmed: false) == .ready(hasOtp: false))

        let github = try #require(try OtpLink.accounts(in: OtpLinkTests.migration).first)
        let stored = try await session.attachOtp(github, toItemID: login.id, vaultID: vault, confirmed: false)
        #expect(stored.title == "GitHub")
        let first = try #require(otp(stored))
        #expect(try totpNow(secretOrUri: first, unixSeconds: 59).code == "287082")
        #expect(previousCodes(stored).isEmpty)
        #expect(try await session.otpTarget(itemID: login.id, vaultID: vault, confirmed: false) == .ready(hasOtp: true))

        // Replacing keeps the previous code in a concealed "Ancien code" field.
        let other = try #require(try OtpLink.accounts(in: OtpLinkTests.link).first)
        let replaced = try await session.attachOtp(other, toItemID: login.id, vaultID: vault, confirmed: false)
        #expect(try totpNow(secretOrUri: try #require(otp(replaced)), unixSeconds: 59).code
            == totpNow(secretOrUri: "JBSWY3DPEHPK3PXP", unixSeconds: 59).code)
        #expect(previousCodes(replaced) == [first])
        let kept = try #require(replaced.sections.first { $0.id == ItemDraft.customSectionID }?.fields.last)
        #expect(kept.kind == .concealed)
        #expect(kept.label == "Ancien code")
        #expect(session.summaries.count == 1)

        // The same code again stores nothing new.
        let again = try await session.attachOtp(other, toItemID: login.id, vaultID: vault, confirmed: false)
        #expect(previousCodes(again) == [first])
    }

    /// A `reprompt` Login says nothing and takes nothing before the user is confirmed.
    @Test func repromptLoginNeedsConfirmationFirst() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let vault = session.allVaults[0].id
        var login = try session.newItem(type: .login, vaultID: vault)
        login.title = "Banque"
        login.reprompt = true
        fillRequired(&login)
        login = try await session.save(login)
        let account = try #require(try OtpLink.accounts(in: OtpLinkTests.link).first)

        #expect(try await session.otpTarget(itemID: login.id, vaultID: vault, confirmed: false) == .confirmFirst)
        await #expect(throws: VaultError.self) {
            try await session.attachOtp(account, toItemID: login.id, vaultID: vault, confirmed: false)
        }
        #expect((otp(try await session.loadItem(vaultID: vault, itemID: login.id)) ?? "").isEmpty)

        #expect(try await session.otpTarget(itemID: login.id, vaultID: vault, confirmed: true) == .ready(hasOtp: false))
        let stored = try await session.attachOtp(account, toItemID: login.id, vaultID: vault, confirmed: true)
        #expect(!(otp(stored) ?? "").isEmpty)
    }

    /// A link or copy request waiting for the unlock lasts 2 minutes, and never across a clock moved back.
    @Test func waitingRequestExpires() {
        let queued = Date(timeIntervalSince1970: 1_000_000)
        #expect(!PendingRequest.isExpired(queuedAt: queued, now: queued))
        #expect(!PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(120)))
        #expect(PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(121)))
        #expect(PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(-1)))
    }

    @Test func refusesAnItemThatIsNotALogin() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let vault = session.allVaults[0].id
        var note = try session.newItem(type: .secureNote, vaultID: vault)
        note.title = "Note"
        fillRequired(&note)
        note = try await session.save(note)
        let account = try #require(try OtpLink.accounts(in: OtpLinkTests.link).first)
        await #expect(throws: VaultError.self) {
            try await session.attachOtp(account, toItemID: note.id, vaultID: vault, confirmed: true)
        }
    }

    /// The values of the concealed "Ancien code" fields.
    private func previousCodes(_ item: FfiItem) -> [String] {
        item.sections.first { $0.id == ItemDraft.customSectionID }?.fields
            .filter { $0.label == "Ancien code" }.map(\.value.text) ?? []
    }
}
