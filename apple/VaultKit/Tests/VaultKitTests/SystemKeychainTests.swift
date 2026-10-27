import Foundation
import Testing

@testable import VaultKit

/// The real keychain under a throwaway service name (never `me.somalabs.onepass`). `swift test` runs
/// unsigned, without the keychain entitlement: the data protection keychain refuses writes (-34018)
/// and answers "not found" to reads, which is the Debug fallback path of an ad hoc signed Mac build.
@Suite("System keychain", .serialized)
struct SystemKeychainTests {
    private static func makeKeychain() -> SystemKeychain {
        SystemKeychain(service: "me.somalabs.onepass.tests.\(UUID().uuidString)", accessGroup: nil)
    }

    @Test func writeThenReadAndContainsAgree() throws {
        let keychain = Self.makeKeychain()
        defer { try? keychain.delete("secretkey.test") }
        #expect(try keychain.contains("secretkey.test") == false)
        #expect(try keychain.read("secretkey.test") == nil)

        try keychain.write("secretkey.test", Data("A3-FICTIF-123456".utf8))
        #expect(try keychain.contains("secretkey.test"))
        #expect(try keychain.read("secretkey.test") == Data("A3-FICTIF-123456".utf8))

        try keychain.write("secretkey.test", Data("A3-FICTIF-654321".utf8))
        #expect(try keychain.read("secretkey.test") == Data("A3-FICTIF-654321".utf8))

        try keychain.delete("secretkey.test")
        #expect(try keychain.contains("secretkey.test") == false)
        #expect(try keychain.read("secretkey.test") == nil)
    }

    @Test func secretKeyVaultReadsBackWhatItStored() throws {
        let vault = SecretKeyVault(keychain: Self.makeKeychain())
        defer { try? vault.remove(accountID: "compte-fictif") }
        try vault.store("A3-FICTIF-123456", accountID: "compte-fictif")
        #expect(try vault.contains(accountID: "compte-fictif"))
        #expect(try vault.load(accountID: "compte-fictif") == "A3-FICTIF-123456")
    }

    /// The tester's bug: after a lock, and after a relaunch, the session asks for the password only.
    @MainActor
    @Test func lockAndRelaunchNeedOnlyThePassword() async throws {
        let keychain = Self.makeKeychain()
        let h = try SessionHarness(keychain: keychain)
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        let accountID = try #require(h.settings.accountID)
        defer { try? SecretKeyVault(keychain: keychain).remove(accountID: accountID) }
        #expect(!session.needsSecretKey)

        session.lock()
        #expect(session.state == .locked)
        #expect(!session.needsSecretKey)
        try await session.unlock(password: testPassword)
        #expect(session.state == .unlocked)
        session.lock()
        await session.waitForReleasedSessions()

        let relaunched = h.makeSession()
        #expect(relaunched.state == .locked)
        #expect(!relaunched.needsSecretKey)
        try await relaunched.unlock(password: testPassword)
        #expect(relaunched.state == .unlocked)
        relaunched.lock()
        await relaunched.waitForReleasedSessions()
    }
}
