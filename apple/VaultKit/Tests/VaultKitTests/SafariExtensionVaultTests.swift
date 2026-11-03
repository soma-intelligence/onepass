import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// The vault of the iOS Safari extension (spec 2026-11-03-ios-safari-autofill 4): its own session on
/// the shared store, the app's biometric policy, no Face ID loop, the master password.
@MainActor
@Suite("Safari extension vault")
struct SafariExtensionVaultTests {
    /// A clock the test moves.
    final class Now: Sendable {
        private let value = Mutex(Date(timeIntervalSince1970: 1_800_000_000))
        func get() -> Date { value.withLock { $0 } }
        func advance(_ s: TimeInterval) { value.withLock { $0 = $0.addingTimeInterval(s) } }
    }

    /// An account with biometrics enrolled, created by the "app", then the extension's own vault.
    func make(_ h: SessionHarness, now: Now) async throws -> SafariExtensionVault {
        let app = h.makeSession()
        _ = try await app.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        try await app.enrollBiometrics(password: testPassword)
        app.lock()
        return SafariExtensionVault(
            environment: h.environment, pairingKeychain: InMemoryKeychain(), biometryKind: { "faceID" },
            now: { now.get() })
    }

    @Test func faceIDOpensTheVaultAndTheBridgeConnects() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = try await make(h, now: Now())
        let before = vault.state()
        #expect(before == .init(locked: true, account: "Camille", biometry: "faceID"))
        let after = await vault.unlockWithBiometrics()
        #expect(after.locked == false)
        #expect(after.failure == nil)
        let fd = try vault.connect()
        #expect(fd >= 0)
        close(fd)
    }

    /// A cancel keeps the button; a second try right after is refused without a prompt (no loop);
    /// after the gap, the explicit button works.
    @Test func noSecondPromptRightAfterACancel() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let now = Now()
        let vault = try await make(h, now: now)
        h.keyring.failNextDecrypt(with: .cancelled)
        let first = await vault.unlockWithBiometrics()
        #expect(first.locked)
        #expect(first.failure == .cancelled)
        #expect(first.biometry == "faceID")

        // Would succeed if it reached the keyring: it must not.
        let looped = await vault.unlockWithBiometrics()
        #expect(looped.locked)
        #expect(looped.failure == .cancelled)

        now.advance(SafariExtensionVault.biometricGap + 0.1)
        let explicit = await vault.unlockWithBiometrics()
        #expect(!explicit.locked)
    }

    /// After a reboot the policy wants the password: no biometry offered, the password opens.
    @Test func rebootAsksThePassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = try await make(h, now: Now())
        h.clock.reboot()
        let refused = await vault.unlockWithBiometrics()
        #expect(refused.locked)
        #expect(refused.failure == .passwordRequired)
        #expect(refused.biometry == "none")

        let wrong = SecretBytes(utf8: "faux")
        let bad = await vault.unlock(password: wrong)
        wrong.wipe()
        #expect(bad.failure == .wrongPassword)
        #expect(bad.locked)

        let right = SecretBytes(utf8: testPassword)
        let good = await vault.unlock(password: right)
        right.wipe()
        #expect(!good.locked)
        #expect(good.failure == nil)
    }

    /// 14 days without the password: same as a reboot.
    @Test func fourteenDaysAskThePassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = try await make(h, now: Now())
        h.clock.advance(15 * 86400)
        let refused = await vault.unlockWithBiometrics()
        #expect(refused.failure == .passwordRequired)
        #expect(refused.biometry == "none")
    }

    /// A biometry change (key invalidated): the password, never Face ID again until re-enrolled.
    @Test func biometryChangeAsksThePassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = try await make(h, now: Now())
        h.keyring.invalidate()
        let refused = await vault.unlockWithBiometrics()
        #expect(refused.failure == .passwordRequired)
        #expect(refused.biometry == "none")
    }

    @Test func noAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = SafariExtensionVault(
            environment: h.environment, pairingKeychain: InMemoryKeychain(), biometryKind: { "faceID" })
        let s = vault.state()
        #expect(s.locked)
        #expect(s.failure == .noAccount)
    }
}
