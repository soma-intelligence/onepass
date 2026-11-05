import Foundation
import Testing

@testable import VaultKit

/// The generated passwords waiting for a Login (G3): per account, deduplicated, bounded, expiring.
@Suite("Generated password drafts")
struct GeneratedPasswordDraftsTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func draft(_ service: String, _ password: String, user: String = "camille@exemple.fr", at: Date? = nil)
        -> GeneratedPasswordDraft
    {
        GeneratedPasswordDraft(
            SavePasswordRequest(
                service: service, serviceIsApp: false, user: user, password: password, title: nil,
                event: .generatedPasswordFilled),
            at: at ?? now)
    }

    @Test func sameDraftReplacesItselfAndTheOldestGoFirst() {
        let drafts = GeneratedPasswordDrafts(keychain: InMemoryKeychain(), scope: nil)
        drafts.add(draft("a.exemple.fr", "Un-1"), now: now)
        drafts.add(draft("a.exemple.fr", "Un-1"), now: now)
        #expect(drafts.load(now: now).count == 1)
        for i in 2...7 { drafts.add(draft("a.exemple.fr", "Mot-\(i)"), now: now) }
        let kept = drafts.load(now: now).map(\.password)
        #expect(kept.count == GeneratedPasswordDrafts.limit)
        #expect(kept.first == "Mot-3")
        #expect(kept.last == "Mot-7")
    }

    @Test func removeByPasswordAndService() {
        let drafts = GeneratedPasswordDrafts(keychain: InMemoryKeychain(), scope: nil)
        drafts.add(draft("a.exemple.fr", "Commun-1"), now: now)
        drafts.add(draft("b.exemple.fr", "Commun-1"), now: now)
        drafts.remove(password: "Commun-1", service: "a.exemple.fr", now: now)
        #expect(drafts.load(now: now).map(\.service) == ["b.exemple.fr"])
        drafts.remove(password: "Commun-1", now: now)
        #expect(drafts.load(now: now).isEmpty)
    }

    @Test func expiredOrFutureDraftsAreDropped() {
        let drafts = GeneratedPasswordDrafts(keychain: InMemoryKeychain(), scope: nil)
        drafts.add(draft("a.exemple.fr", "Vieux-1", at: now.addingTimeInterval(-GeneratedPasswordDrafts.lifetime)), now: now)
        drafts.add(draft("b.exemple.fr", "Futur-2", at: now.addingTimeInterval(60)), now: now)
        drafts.add(draft("c.exemple.fr", "Frais-3"), now: now)
        #expect(drafts.load(now: now).map(\.password) == ["Frais-3"])
    }

    /// Each account keeps its own drafts in the shared keychain.
    @Test func accountsDoNotShareDrafts() {
        let keychain = InMemoryKeychain()
        let primary = GeneratedPasswordDrafts(keychain: keychain, scope: nil)
        let work = GeneratedPasswordDrafts(keychain: keychain, scope: "0123")
        primary.add(draft("a.exemple.fr", "Perso-1"), now: now)
        #expect(work.load(now: now).isEmpty)
        #expect(primary.load(now: now).count == 1)
    }
}
