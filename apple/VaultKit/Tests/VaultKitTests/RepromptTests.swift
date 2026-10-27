import Foundation
import Testing

@testable import VaultKit

@MainActor
@Suite("Reprompt")
struct RepromptTests {
    @Test func presenceNeedsBiometricEnrollment() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)

        // Not enrolled: no system prompt, the master password is asked instead.
        #expect(await session.confirmUserPresence(prompt: "Afficher") == false)
        #expect(h.presence.prompts == 0)

        try await session.enrollBiometrics(password: testPassword)
        #expect(await session.confirmUserPresence(prompt: "Afficher"))
        h.presence.answer(false)
        #expect(await session.confirmUserPresence(prompt: "Afficher") == false)
        #expect(h.presence.prompts == 2)

        // Locked: never confirmed.
        h.presence.answer(true)
        session.lock()
        #expect(await session.confirmUserPresence(prompt: "Afficher") == false)
    }

    @Test func masterPasswordCheckKeepsTheSession() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(session, title: "Projet Atlas")
        await session.waitForSyncNotifications()
        let eventsBefore = h.sync.events

        await #expect(throws: VaultError.wrongPassword) { try await session.verifyMasterPassword("faux") }
        #expect(h.settings.failedUnlocks == 1)
        #expect(session.state == .unlocked)

        try await session.verifyMasterPassword(testPassword)
        #expect(h.settings.failedUnlocks == 0)
        #expect(session.state == .unlocked)
        #expect(session.summaries.map(\.title) == ["Projet Atlas"])
        // The open session is still the one in use: a write goes through, no unlock or lock was announced.
        try await addItem(session, title: "Mutuelle")
        await session.waitForSyncNotifications()
        #expect(h.sync.events == eventsBefore + [.written])

        session.lock()
        await #expect(throws: VaultError.passwordRequired) { try await session.verifyMasterPassword(testPassword) }
    }
}
