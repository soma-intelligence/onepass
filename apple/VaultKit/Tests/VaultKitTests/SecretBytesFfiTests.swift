import Foundation
import Testing

@testable import VaultKit

/// Task 7 part B: the master password and the Secret Key cross the FFI as bytes; the buffers stay the
/// caller's (wiped by it), and the byte paths behave like the `String` ones did.
@MainActor
@Suite("Secrets cross the FFI as bytes", .timeLimit(.minutes(2)))
struct SecretBytesFfiTests {
    @Test func byteCallsCreateUnlockVerifyAndLeaveTheCallersBuffer() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let password = SecretBytes(utf8: testPassword)
        let secretKey = try await session.createAccount(password: password, displayName: "", mode: .personal)
        // The returned key is the one stored in the keychain, in a buffer the caller owns.
        let stored = try #require(h.settings.accountID.flatMap { try? SecretKeyVault(keychain: h.keychain).load(accountID: $0) })
        #expect(secretKey.string() == stored)
        secretKey.wipe()
        #expect(secretKey.isEmpty)
        // The password buffer is left to the caller: still there after each call.
        #expect(password.string() == testPassword)

        session.lock()
        await session.waitForReleasedSessions()
        let wrong = SecretBytes(utf8: "pas le bon mot de passe")
        await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: wrong) }
        #expect(h.settings.failedUnlocks == 1)
        try await session.unlock(password: password)
        #expect(session.state == .unlocked)
        #expect(h.settings.failedUnlocks == 0)
        try await session.verifyMasterPassword(password)
        await #expect(throws: VaultError.wrongPassword) { try await session.verifyMasterPassword(wrong) }
        #expect(password.string() == testPassword)
        password.wipe()
        wrong.wipe()
    }

    @Test func passwordThatIsNotUtf8IsRefusedWithoutAnAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let invalid = SecretBytes(copying: [0xFF, 0xFE, 0x41])
        await #expect(throws: VaultError.self) {
            _ = try await session.createAccount(password: invalid, displayName: "", mode: .personal)
        }
        #expect(session.state == .noAccount)
    }
}
