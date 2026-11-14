import CryptoKit
import Foundation
import Testing

@testable import VaultKit

/// Managed accounts against the core: the genesis names the org, signed by the Swift halves.
@MainActor
@Suite("Org FFI")
struct OrgFfiTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    static let orgID = "5f3e2d1c0b0a99887766554433221100"
    static let slot = "a0b1c2d3e4f5061728394a5b6c7d8e9f"

    /// Creates a managed account with fresh pending keys (Secure Enclave or software), returns the store path.
    private func createManaged(
        _ h: SessionHarness, secureEnclave: Bool, accountID: String? = nil
    ) async throws -> (session: VaultSession, path: String) {
        let keys = try ManagedDeviceKeys.createPending(
            keychain: h.keychain, slot: Self.slot, secureEnclave: secureEnclave)
        let session = h.makeSession()
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let secretKey = try await session.createManagedAccount(
            password: password, displayName: "Marie", mode: .personal, orgID: Self.orgID,
            accountID: accountID, keys: keys)
        #expect(!(secretKey.string() ?? "").isEmpty)
        secretKey.wipe()
        return (session, h.environment.databaseURL.path)
    }

    @Test func managedAccountGenesisNamesTheOrg() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, path) = try await createManaged(h, secureEnclave: false)
        #expect(session.state == .unlocked)
        #expect(try managedAccountOrg(dbPath: path) == Self.orgID)
        let accountID = try #require(h.settings.accountID)
        #expect(h.settings.displayName == "Marie")
        // The Secret Key is in the keychain under the new account: lock then unlock works.
        session.lock()
        try await session.unlock(password: testPassword)
        #expect(session.state == .unlocked)
        #expect(h.settings.accountID == accountID)
    }

    @Test func anInvitedAccountKeepsTheRosterID() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let invited = "0123456789abcdef0123456789abcdef"
        _ = try await createManaged(h, secureEnclave: false, accountID: invited)
        #expect(h.settings.accountID == invited)
    }

    @Test func personalAccountStillHasNoOrg() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Marie", mode: .personal)
        #expect(session.state == .unlocked)
        #expect(try managedAccountOrg(dbPath: h.environment.databaseURL.path) == nil)
    }

    @Test func aSecondAccountIsRefused() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, _) = try await createManaged(h, secureEnclave: false)
        let keys = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: Self.slot, secureEnclave: false)
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        await #expect(throws: VaultError.accountExists) {
            _ = try await session.createManagedAccount(
                password: password, displayName: "Marie", mode: .personal, orgID: Self.orgID,
                accountID: nil, keys: keys)
        }
    }

    @Test(.enabled(if: SecureEnclave.isAvailable))
    func secureEnclaveHalfSignsForTheCore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (_, path) = try await createManaged(h, secureEnclave: true)
        #expect(try managedAccountOrg(dbPath: path) == Self.orgID)
    }
}
