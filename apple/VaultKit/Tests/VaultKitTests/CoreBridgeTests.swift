import Foundation
import Testing

@testable import VaultKit

@Suite("Core bridge")
struct CoreBridgeTests {
    @Test func hasAccountIsFalseForEmptyStore() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let dbPath = dir.appendingPathComponent("store.db").path
        #expect(try hasAccount(dbPath: dbPath) == false)
    }

    @Test func generatePasswordRespectsLength() throws {
        let recipe = FfiPasswordRecipe.characters(
            length: 24, digits: true, symbols: true, avoidAmbiguous: false)
        let password = try generatePassword(recipe: recipe)
        #expect(password.count == 24)
    }
}
