import Foundation
import Testing

@testable import VaultKit

/// A session whose identity store is `store`, with a short debounce.
@MainActor
private func publishingSession(_ h: SessionHarness, store: any IdentityStoreClient) -> VaultSession {
    var environment = h.environment
    environment.identityStore = store
    environment.identityDebounce = .milliseconds(20)
    return VaultSession(environment: environment)
}

@MainActor
@discardableResult
private func addLogin(_ session: VaultSession, title: String, url: String) async throws -> FfiItem {
    var item = try session.newItem(type: .login, vaultID: session.allVaults[0].id)
    item.title = title
    for s in item.sections.indices {
        for f in item.sections[s].fields.indices {
            switch item.sections[s].fields[f].id {
            case "username": item.sections[s].fields[f].value = .text(value: "camille@exemple.fr")
            case "password": item.sections[s].fields[f].value = .password(value: "Mot-de-passe-Atlas-7")
            default: break
            }
        }
    }
    item.urls = [FfiUrl(label: "", url: url, rule: .domain, primary: true)]
    fillRequired(&item)
    return try await session.save(item)
}

/// Whether the system identity store is behind the vault, as the app and the provider both read it.
@MainActor
@Suite("Identity publish ledger")
struct IdentityPublishTests {
    @Test func behindUntilPublishedUnderTheCurrentMark() throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let ledger = IdentityPublishLedger(settings: h.settings)
        // Nothing was ever published: behind.
        #expect(ledger.isBehind)

        let first = ledger.generation
        #expect(ledger.generation == first)
        ledger.markPublished(first)
        #expect(!ledger.isBehind)

        // A change after the mark was read: a publication under the old mark leaves it behind.
        ledger.markChanged()
        #expect(ledger.isBehind)
        ledger.markPublished(first)
        #expect(ledger.isBehind)
        ledger.markPublished(ledger.generation)
        #expect(!ledger.isBehind)

        // An emptied store is behind again.
        ledger.reset()
        #expect(ledger.isBehind)
    }

    /// The marks are per account: an added account's scope never reads the primary one's.
    @Test func marksArePerAccount() throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let primary = IdentityPublishLedger(settings: h.settings)
        let added = IdentityPublishLedger(settings: VaultSettings(defaults: h.settings.baseDefaults, scope: "b"))
        primary.markPublished(primary.generation)
        #expect(!primary.isBehind)
        #expect(added.isBehind)
        // Another instance over the same suite (the provider's process) reads the same marks.
        #expect(!IdentityPublishLedger(settings: VaultSettings(defaults: h.settings.baseDefaults)).isBehind)
    }

    @Test func aPublishedWriteIsNotBehind() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = publishingSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        // Written, not published yet (debounce).
        #expect(session.autofillIdentitiesBehind)
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)
        #expect(!session.autofillIdentitiesBehind)
    }

    /// A write whose publication never reaches the store (provider off) stays behind.
    @Test func disabledStoreStaysBehind() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore(enabled: false)
        let session = publishingSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(session.autofillIdentitiesBehind)

        // Turned on: the next unlock publishes.
        session.lock()
        await session.waitForAutofillIdentities()
        store.enabled = true
        try await session.unlock(password: testPassword)
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)
        #expect(!session.autofillIdentitiesBehind)
    }

    /// A sync applied while locked publishes nothing: the store is marked behind, and the next
    /// unlock publishes.
    @Test func syncWhileLockedMarksBehindUntilTheNextUnlock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = publishingSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        session.lock()
        await session.waitForAutofillIdentities()
        #expect(!session.autofillIdentitiesBehind)
        let published = store.replaceCount

        await session.reload()
        await session.waitForAutofillIdentities()
        #expect(session.state == .locked)
        #expect(store.replaceCount == published)
        #expect(session.autofillIdentitiesBehind)

        try await session.unlock(password: testPassword)
        await session.waitForAutofillIdentities()
        #expect(store.replaceCount == published + 1)
        #expect(!session.autofillIdentitiesBehind)
    }

    /// A pending refresh dropped by a lock (the extension's `publishPending: false`) stays behind.
    @Test func droppedRefreshStaysBehind() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        var environment = h.environment
        environment.identityStore = store
        environment.identityDebounce = .seconds(600)
        let session = VaultSession(environment: environment)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        session.lock(publishPending: false)
        await session.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)
        #expect(session.autofillIdentitiesBehind)
    }

    /// Turning the suggestions off empties the store; nothing counts as published any more.
    @Test func clearedStoreIsBehind() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = publishingSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(!session.autofillIdentitiesBehind)
        session.setQuickTypeSuggestions(false)
        await session.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)
        #expect(session.autofillIdentitiesBehind)
    }
}
