import Foundation
import Testing

@testable import VaultKit

/// The per-vault "agent web fill" setting of Réglages > Développeur: it writes the `fill` scope in the
/// signed MCP policy, on the vault turned on only (spec 4 of the agent browser fill design).
@MainActor
@Suite("Agent fill policy", .timeLimit(.minutes(3)))
struct AgentFillPolicyTests {
    @Test func testFillScopeIsWrittenOnlyForVaultsTurnedOn() async throws {
        let harness = try SessionHarness()
        defer { harness.cleanUp() }
        let session = harness.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await session.createVault(FfiVaultMeta(
            name: "Agents", icon: "sparkles", color: "purple", travelSafe: false, mcpAccess: true))
        let dir = FileManager.default.temporaryDirectory.appending(path: "op-fill-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let personal = try #require(session.allVaults.first { $0.meta.name == "Personnel" })
        let agents = try #require(session.allVaults.first { $0.meta.name == "Agents" })
        var meta = personal.meta
        meta.mcpAccess = true
        try await session.updateVault(id: personal.id, meta: meta)
        try await session.setMcpPolicy(dataDirectory: dir.path, vaults: [
            FfiClientScopes(vaultId: personal.id, scopes: ["metadata", "use"]),
            FfiClientScopes(vaultId: agents.id, scopes: ["metadata", "use"]),
        ], allowGenerate: false)

        func scopes(_ id: String) async throws -> [String] {
            try await session.mcpPolicy(dataDirectory: dir.path).vaults.first { $0.vaultId == id }?.scopes ?? []
        }
        // Off by default.
        #expect(try await !scopes(agents.id).contains("fill"))
        #expect(try await !scopes(personal.id).contains("fill"))

        try await session.setAgentFill(dataDirectory: dir.path, vaultID: agents.id, on: true)
        #expect(try await scopes(agents.id).contains("fill"))
        #expect(try await !scopes(personal.id).contains("fill"))
        // The rest of the policy is kept.
        #expect(try await Set(scopes(personal.id)) == ["metadata", "use"])
        #expect(try await Set(scopes(agents.id)) == ["metadata", "use", "fill"])
        #expect(try await !session.mcpPolicy(dataDirectory: dir.path).allowGenerate)

        try await session.setAgentFill(dataDirectory: dir.path, vaultID: agents.id, on: false)
        #expect(try await Set(scopes(agents.id)) == ["metadata", "use"])
        #expect(try await !scopes(personal.id).contains("fill"))
    }
}
