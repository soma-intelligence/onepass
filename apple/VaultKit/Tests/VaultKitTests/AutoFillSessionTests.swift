import Foundation
import Testing

@testable import VaultKit

/// A session whose identity store is in memory, with a short debounce.
@MainActor
private func autofillSession(
    _ h: SessionHarness, store: InMemoryIdentityStore, notifier: StoreChangeNotifier? = nil
) -> VaultSession {
    var environment = h.environment
    environment.identityStore = store
    environment.identityDebounce = .milliseconds(20)
    if let notifier { environment.storeChanges = notifier }
    return VaultSession(environment: environment)
}

/// A Login of `vaultID` (first vault by default) with a username, a password and one URL.
@MainActor
@discardableResult
private func addLogin(
    _ session: VaultSession, title: String, url: String, user: String = "camille@exemple.fr",
    vaultID: String? = nil
) async throws -> FfiItem {
    var item = try session.newItem(type: .login, vaultID: vaultID ?? session.allVaults[0].id)
    item.title = title
    for s in item.sections.indices {
        for f in item.sections[s].fields.indices {
            switch item.sections[s].fields[f].id {
            case "username": item.sections[s].fields[f].value = .text(value: user)
            case "password": item.sections[s].fields[f].value = .password(value: "Mot-de-passe-Atlas-7")
            default: break
            }
        }
    }
    item.urls = [FfiUrl(label: "", url: url, rule: .domain, primary: true)]
    fillRequired(&item)
    return try await session.save(item)
}

@MainActor
@Suite("AutoFill session")
struct AutoFillSessionTests {
    @Test func replacesAfterUnlockAndSave() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let item = try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr/connexion")
        await session.waitForAutofillIdentities()

        let ids = store.identities
        #expect(ids.count == 1)
        #expect(ids.first?.kind == .password)
        #expect(ids.first?.service == "atlas.exemple.fr")
        #expect(ids.first?.user == "camille@exemple.fr")
        #expect(ids.first?.recordId.hasSuffix(item.id) == true)
    }

    @Test func settingOffClearsStore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)

        session.setQuickTypeSuggestions(false)
        await session.waitForAutofillIdentities()
        #expect(h.settings.quickTypeSuggestions == false)
        #expect(store.identities.isEmpty)

        // Off: later writes publish nothing.
        try await addLogin(session, title: "Bis", url: "https://bis.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)
    }

    @Test func settingBackOnRefills() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.setQuickTypeSuggestions(false)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)

        session.setQuickTypeSuggestions(true)
        await session.waitForAutofillIdentities()
        #expect(h.settings.quickTypeSuggestions)
        #expect(store.identities.map(\.service) == ["atlas.exemple.fr"])
    }

    @Test func hiddenVaultExcluded() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await session.createVault(FfiVaultMeta(
            name: "Projet Atlas", icon: "folder", color: "orange", travelSafe: false, mcpAccess: false))
        let atlas = try #require(session.allVaults.first { $0.meta.name == "Projet Atlas" })
        try await addLogin(session, title: "Perso", url: "https://perso.exemple.fr")
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr", vaultID: atlas.id)
        await session.waitForAutofillIdentities()
        #expect(Set(store.identities.map(\.service)) == ["perso.exemple.fr", "atlas.exemple.fr"])

        session.setVaultHidden(atlas.id, hidden: true)
        await session.waitForAutofillIdentities()
        #expect(store.identities.map(\.service) == ["perso.exemple.fr"])

        // Candidates leave the hidden vault out too.
        let candidates = try await session.autofillCandidates(service: "atlas.exemple.fr", includeAll: true)
        #expect(candidates.allSatisfy { $0.vaultId != atlas.id })
    }

    @Test func disabledStoreIsLeftAlone() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore(enabled: false)
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.replaceCount == 0)
        #expect(store.identities.isEmpty)
    }

    @Test func lockKeepsIdentities() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)
        // One or two replacements so far: the account creation and the new Login are two requests,
        // merged only when the second comes within the debounce (not under a loaded test run).
        let published = store.replaceCount
        #expect(published >= 1)

        session.lock()
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)
        #expect(store.removeCount == 0)

        // Locked: a refresh request does nothing.
        session.refreshAutofillIdentities()
        await session.waitForAutofillIdentities()
        #expect(store.replaceCount == published)
    }

    /// "Restaurer avec mon Emergency Kit" / "Repartir de zéro": the vanished account's identities go.
    @Test func resetForRecoveryEmptiesStore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        #expect(store.identities.count == 1)
        session.lock()
        await session.waitForReleasedSessions()

        try dropAccountParams(h.environment.databaseURL.path)
        await session.reload()
        #expect(session.isAccountMissing)
        try await session.resetForRecovery()
        await session.waitForAutofillIdentities()
        #expect(session.state == .noAccount)
        #expect(store.identities.isEmpty)
        #expect(store.removeCount == 1)
    }

    @Test func clearAutofillIdentitiesEmptiesStore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addLogin(session, title: "Atlas", url: "https://atlas.exemple.fr")
        await session.waitForAutofillIdentities()
        session.lock()
        session.clearAutofillIdentities()
        await session.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)
        #expect(store.removeCount == 1)
    }

    @Test func passkeyRoundTripThroughSession() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let store = InMemoryIdentityStore()
        let session = autofillSession(h, store: store)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vaultID = session.allVaults[0].id
        let registration = try await session.createPasskey(FfiPasskeyCreation(
            vaultId: vaultID, itemId: nil, rpId: "example.com", userName: "camille",
            userHandle: Data([1, 2, 3, 4]), clientDataHash: Data(repeating: 9, count: 32),
            excludedCredentialIds: []))
        #expect(registration.vaultId == vaultID)
        #expect(!registration.credentialId.isEmpty)
        #expect(session.summaries.contains { $0.id == registration.itemId && $0.itemType == .login })

        let assertion = try await session.passkeyAssertion(
            vaultID: vaultID, itemID: registration.itemId, credentialID: registration.credentialId,
            clientDataHash: Data(repeating: 7, count: 32))
        #expect(assertion.credentialId == registration.credentialId)
        #expect(assertion.userHandle == Data([1, 2, 3, 4]))
        #expect(!assertion.signature.isEmpty)

        let candidates = try await session.autofillCandidates(service: "example.com", includeAll: false)
        #expect(candidates.map(\.itemId) == [registration.itemId])

        await session.waitForAutofillIdentities()
        let passkey = try #require(store.identities.first { $0.kind == .passkey })
        #expect(passkey.service == "example.com")
        #expect(passkey.credentialId == registration.credentialId)
        #expect(passkey.userHandle == Data([1, 2, 3, 4]))

        // The same credential cannot be registered twice for this relying party.
        await #expect(throws: VaultError.self) {
            _ = try await session.createPasskey(FfiPasskeyCreation(
                vaultId: vaultID, itemId: nil, rpId: "example.com", userName: "camille",
                userHandle: Data([1, 2, 3, 4]), clientDataHash: Data(repeating: 9, count: 32),
                excludedCredentialIds: [registration.credentialId]))
        }
    }

    @Test func notificationReloadsSummaries() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let notifier = StoreChangeNotifier(name: "me.somalabs.onepass.tests.\(UUID().uuidString)")
        let store = InMemoryIdentityStore()
        let first = autofillSession(h, store: store, notifier: notifier)
        _ = try await first.createAccount(password: testPassword, displayName: "", mode: .personal)
        await first.waitForSyncNotifications()
        let writesBefore = h.sync.events.filter { $0 == .written }.count

        // Another process (the extension) on the same store: a second session, never observed by the first.
        let second = autofillSession(h, store: InMemoryIdentityStore())
        try await second.unlock(password: testPassword)
        let created = try await addLogin(second, title: "Depuis l'extension", url: "https://ext.exemple.fr")
        #expect(!first.summaries.contains { $0.id == created.id })

        let revision = first.externalChangeRevision
        notifier.post()
        #expect(await eventually { first.summaries.contains { $0.id == created.id } })
        // The signal an open item editor waits for (warns before overwriting the new version).
        #expect(await eventually { first.externalChangeRevision > revision })
        await first.waitForSyncNotifications()
        #expect(h.sync.events.filter { $0 == .written }.count > writesBefore)
        await first.waitForAutofillIdentities()
        #expect(store.identities.contains { $0.service == "ext.exemple.fr" })
        second.lock()
    }

    /// Locked: nothing is reloaded, but the sync layer is told (pending rows push without unlocking).
    @Test func notificationWhileLockedOnlySignalsSync() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let notifier = StoreChangeNotifier(name: "me.somalabs.onepass.tests.\(UUID().uuidString)")
        let session = autofillSession(h, store: InMemoryIdentityStore(), notifier: notifier)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        await session.waitForSyncNotifications()
        let events = h.sync.events

        notifier.post()
        #expect(await eventually {
            await session.waitForSyncNotifications()
            return h.sync.events.count > events.count
        })
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty)
        #expect(h.sync.events == events + [.written])
    }

    /// The observer task ends with its session: per-request sessions of the extension do not pile up.
    @Test func observerEndsWithSession() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let notifier = StoreChangeNotifier(name: "me.somalabs.onepass.tests.\(UUID().uuidString)")
        var session: VaultSession? = autofillSession(h, store: InMemoryIdentityStore(), notifier: notifier)
        let observer = try #require(session?.storeChangeObserver)
        #expect(!observer.isCancelled)
        session = nil
        #expect(await eventually { observer.isCancelled })
        await observer.value
    }
}
