import Foundation
import Testing

@testable import VaultKit

@Suite("Secret Key vault")
struct SecretKeyVaultTests {
    @Test func secretKeyRoundtripsPerAccount() throws {
        let vault = SecretKeyVault(keychain: InMemoryKeychain())
        try vault.store("A3-ABCDEF-123456", accountID: "a")
        try vault.store("A3-ZZZZZZ-999999", accountID: "b")
        #expect(try vault.load(accountID: "a") == "A3-ABCDEF-123456")
        #expect(try vault.load(accountID: "b") == "A3-ZZZZZZ-999999")
        #expect(try vault.load(accountID: "c") == nil)
        try vault.remove(accountID: "a")
        #expect(try vault.load(accountID: "a") == nil)
        #expect(try vault.load(accountID: "b") != nil)
    }
}
