import Foundation
import Testing

@testable import VaultKit

/// AutoFill opens one account per request: the one whose work domains claim the host, else the
/// primary account (multi-account spec 8).
@MainActor
@Suite("AutoFill account routing", .serialized)
struct AccountRoutingTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func theHostComesFromTheServiceThePasskeyOrTheSave() {
        let list = AutoFillRequest.credentialList(services: ["https://jira.acme.com/login", "acme.com"], passkey: nil)
        #expect(list.routingHost == "jira.acme.com")
        let bare = AutoFillRequest.oneTimeCodeList(services: ["", "mail.acme.com"])
        #expect(bare.routingHost == "mail.acme.com")
        let passkey = AutoFillRequest.credentialList(
            services: ["https://example.com"],
            passkey: PasskeyRequest(rpID: "acme.com", clientDataHash: Data(), allowedCredentialIDs: []))
        #expect(passkey.routingHost == "acme.com")
        // QuickType suggestions come from the primary account's identities only (ruling P6).
        let quickType = AutoFillRequest.credential(recordID: "v:i", kind: .password, passkey: nil, service: "acme.com")
        #expect(quickType.routingHost == nil)
        #expect(AutoFillRequest.textToInsert.routingHost == nil)
    }

    @Test func aClaimedHostOpensItsAccountOnlyOnceItsStoreExists() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let slot = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try h.accounts.update(slot, label: "Soma Labs", color: .orange, workDomains: ["somalabs.me"])
        let work = AutoFillRequest.credentialList(services: ["https://app.somalabs.me/"], passkey: nil)
        let other = AutoFillRequest.credentialList(services: ["https://github.com/"], passkey: nil)
        let lookalike = AutoFillRequest.credentialList(services: ["https://evilsomalabs.me/"], passkey: nil)

        // No store yet (the sign up did not happen): the primary account answers.
        let url = try h.store.databaseURL(slot: slot)
        if !FileManager.default.fileExists(atPath: url.path) {
            #expect(h.store.slot(for: work) == AccountDirectoryStore.primarySlot)
        }

        try await h.createAccount(in: slot, name: "Quentin")
        #expect(h.store.slot(for: work) == slot)
        #expect(h.store.slot(for: other) == AccountDirectoryStore.primarySlot)
        #expect(h.store.slot(for: lookalike) == AccountDirectoryStore.primarySlot)
    }
}
