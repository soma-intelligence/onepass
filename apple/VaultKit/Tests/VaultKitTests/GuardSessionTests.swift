import Foundation
import Testing

@testable import VaultKit

/// Guarded Kit (spec 2026-11-20, sections 7 to 9) through `VaultSession`, against the three
/// in-process realms of the test core (`FfiTestRealmNet`, dev-fast-kdf only). The realm list is
/// global to the process: one serialized test walks the whole life of a guard.
@MainActor
@Suite("Guarded Kit session", .serialized, .tags(.slow))
struct GuardSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private static func session(_ h: SessionHarness, net: FfiTestRealmNet) -> VaultSession {
        var environment = h.environment
        environment.realmTransport = net.transport()
        return VaultSession(environment: environment)
    }

    private static func setRealms(_ net: FfiTestRealmNet, down: Bool) throws {
        for index in UInt8(0)..<3 { try net.setDown(index: index, down: down) }
    }

    @Test func enableUnlockRestoreDisable() async throws {
        let net = try FfiTestRealmNet()
        let first = try SessionHarness()
        defer { first.cleanUp() }
        let phone = Self.session(first, net: net)
        let secretKey = try await phone.createAccount(
            password: testPassword, displayName: "Camille Durand", mode: .personal)
        try await addItem(phone, title: "Projet Atlas")
        let accountID = try #require(first.settings.accountID)
        let kept = GuardVault(keychain: first.keychain)

        // Off by default; the test realms make it available.
        var state = try await phone.guardState()
        #expect(state.available && !state.on)

        // A wrong password turns nothing on and counts toward the throttle.
        await #expect(throws: VaultError.wrongPassword) {
            try await phone.enableGuard(password: SecretBytes(utf8: "faux"))
        }
        #expect(try !kept.contains(accountID: accountID))

        try await phone.enableGuard(password: SecretBytes(utf8: testPassword))
        state = try await phone.guardState()
        #expect(state.on && state.threshold == 2 && state.realms == 3 && state.realmSetCurrent)
        let keptGuard = try #require(try kept.load(accountID: accountID))
        #expect(keptGuard.version == state.version && keptGuard.secret.count == GuardVault.length)
        keptGuard.wipe()

        // The kept G unlocks with every realm down.
        try Self.setRealms(net, down: true)
        phone.lock()
        // A typo with a current kept G stays on this device: a plain wrong password, never the
        // realms (down here, so a realm call would show `guardUnavailable`).
        await #expect(throws: VaultError.wrongPassword) { try await phone.unlock(password: "faux") }
        try await phone.unlock(password: testPassword)
        #expect(phone.state == .unlocked)
        #expect(phone.summaries.map(\.title) == ["Projet Atlas"])
        // Settings checks of the password work on a guarded account (kept G, no realm).
        try await phone.verifyMasterPassword(SecretBytes(utf8: testPassword))
        try Self.setRealms(net, down: false)

        // A new device with the Emergency Kit: no G there, so the realms.
        let second = try SessionHarness()
        defer { second.cleanUp() }
        for suffix in ["", "-wal", "-shm"] {
            let source = URL(fileURLWithPath: first.environment.databaseURL.path + suffix)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            try FileManager.default.copyItem(
                at: source, to: URL(fileURLWithPath: second.environment.databaseURL.path + suffix))
        }
        let restored = Self.session(second, net: net)
        #expect(restored.needsSecretKey)

        try Self.setRealms(net, down: true)
        await #expect(throws: VaultError.guardUnavailable) {
            try await restored.restore(secretKey: secretKey, password: testPassword)
        }
        try Self.setRealms(net, down: false)

        do {
            try await restored.restore(secretKey: secretKey, password: "faux")
            Issue.record("a wrong password restored the account")
        } catch VaultError.guardWrongPassword(let remaining) {
            // The typo on the phone spent nothing at the realms: this is their first failure.
            #expect(remaining == 9)
        }
        #expect(restored.state != .unlocked)

        // The owner's poll sees the failed attempt.
        let health = try await phone.guardHealth()
        #expect(!health.failures.isEmpty)
        #expect(health.realmsAnswered == 3 && health.realmsTotal == 3 && !health.needsRenewal)
        #expect(VaultSession.guardFailureDates(health).count == health.failures.count)

        try await restored.restore(secretKey: secretKey, password: testPassword)
        #expect(restored.state == .unlocked)
        #expect(restored.summaries.map(\.title) == ["Projet Atlas"])
        let restoredGuard = try #require(try GuardVault(keychain: second.keychain).load(accountID: accountID))
        #expect(restoredGuard.version == state.version && restoredGuard.secret.count == GuardVault.length)
        restoredGuard.wipe()

        // Renewal keeps G under a new version: the phone keeps the new version and still unlocks
        // without the realms.
        try await phone.renewGuard(password: SecretBytes(utf8: testPassword))
        let renewed = try await phone.guardState().version
        #expect(renewed > state.version)
        #expect(try kept.load(accountID: accountID)?.version == renewed)
        try Self.setRealms(net, down: true)
        phone.lock()
        try await phone.unlock(password: testPassword)
        #expect(phone.state == .unlocked)
        try Self.setRealms(net, down: false)

        // The restored device checks the password with its own current G, never the realms.
        try Self.setRealms(net, down: true)
        try await restored.verifyMasterPassword(SecretBytes(utf8: testPassword))
        try Self.setRealms(net, down: false)

        // A password change on a guarded account registers again; the next unlock still works.
        let newPassword = "Nouveau cheval 77 !"
        try await phone.changePassword(current: testPassword, new: newPassword)
        #expect(try await phone.guardState().on)
        phone.lock()
        try await phone.unlock(password: newPassword)
        #expect(phone.state == .unlocked)

        // Off: G erased here, the account unlocks with the password and the Secret Key alone.
        try await phone.disableGuard(password: SecretBytes(utf8: newPassword))
        #expect(try await !phone.guardState().on)
        #expect(try !kept.contains(accountID: accountID))
        try Self.setRealms(net, down: true)
        phone.lock()
        try await phone.unlock(password: newPassword)
        #expect(phone.state == .unlocked)
        try Self.setRealms(net, down: false)
    }

    /// The live transport refuses anything that is not HTTPS before any request.
    @Test func liveTransportRefusesPlainHTTP() {
        let transport = URLSessionRealmTransport(timeout: 1)
        #expect(throws: OnePassError.self) { _ = try transport.call(url: "http://realm.example", request: Data([1])) }
        #expect(throws: OnePassError.self) { _ = try transport.call(url: "not a url", request: Data([1])) }
    }

    @Test func guardErrorsHaveFrenchMessages() {
        #expect(VaultError(OnePassError.GuardWrongPassword(remaining: 3)) == .guardWrongPassword(remaining: 3))
        #expect(VaultError(OnePassError.GuardUnavailable(reached: 1, needed: 2)) == .guardUnavailable)
        #expect(VaultError.guardWrongPassword(remaining: 3).isWrongPassword)
        #expect(VaultError.guardWrongPassword(remaining: 3).localizedMessage
            == "Mot de passe incorrect. Il te reste 3 essais.")
        #expect(VaultError.guardWrongPassword(remaining: 1).localizedMessage
            == "Mot de passe incorrect. Il te reste 1 essai.")
        #expect(!VaultError.guardUnavailable.localizedMessage.isEmpty)
    }
}
