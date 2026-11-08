import Foundation
import OnePassCore

/// Milestone 7 in the apps, the session side: SSH Key items, the keys the agent offers, and what the
/// Développeur settings show and change (signed MCP policy, paired clients, grants, audit log). The
/// files live in `dataDirectory` (`DeveloperPaths.dataDirectory`).
extension VaultSession {
    /// A new SSH Key item with a generated key. Returns its id.
    @discardableResult
    public func generateSSHKey(type: FfiSshKeyType, _ new: FfiNewSshKey) async throws -> String {
        try await write { try $0.generateSshKey(keyType: type, new: new) }
    }

    /// A new SSH Key item from a private key file's text (OpenSSH or PEM). The passphrase of an
    /// encrypted key is not kept.
    @discardableResult
    public func importSSHKey(privateKey: String, passphrase: String?, _ new: FfiNewSshKey) async throws -> String {
        try await write { try $0.importSshKey(privateKey: privateKey, passphrase: passphrase, new: new) }
    }

    public func agentKeys() async throws -> [FfiAgentKey] {
        try await read { try $0.agentKeys() }
    }

    public func mcpPolicy(dataDirectory: String) async throws -> FfiMcpPolicy {
        try await read { try $0.mcpPolicy(dataDirPath: dataDirectory) }
    }

    public func setMcpPolicy(dataDirectory: String, vaults: [FfiClientScopes], allowGenerate: Bool) async throws {
        try await read { try $0.setMcpPolicy(dataDirPath: dataDirectory, vaults: vaults, allowGenerate: allowGenerate) }
    }

    /// Turns agent web fill (`fill_in_browser`, scope `fill`) on or off for one exposed vault, and
    /// signs the policy again (spec 4: off by default, vault by vault). The other vaults and
    /// `allowGenerate` keep their values. A vault not exposed gets nothing: turn exposure on first.
    /// A paired client still needs `fill` in its own scopes, as for any other scope. Turning off removes
    /// that client `fill` too.
    public func setAgentFill(dataDirectory: String, vaultID: String, on: Bool) async throws {
        let policy = try await mcpPolicy(dataDirectory: dataDirectory)
        let entries = policy.vaults.compactMap { vault -> FfiClientScopes? in
            guard vault.mcpAccess, !vault.scopes.isEmpty else { return nil }
            var scopes = vault.scopes.filter { $0 != "fill" }
            if on, vault.vaultId == vaultID { scopes.append("fill") }
            return FfiClientScopes(vaultId: vault.vaultId, scopes: scopes)
        }
        try await setMcpPolicy(dataDirectory: dataDirectory, vaults: entries, allowGenerate: policy.allowGenerate)
        // Turning off also strips `fill` from every paired client on this vault (client scopes are stored
        // per vault), so turning it on again never silently re-grants an old client.
        if !on {
            for client in try await pairedClients(dataDirectory: dataDirectory) {
                for entry in client.scopes where entry.vaultId == vaultID && entry.scopes.contains("fill") {
                    try await setClientScopes(
                        dataDirectory: dataDirectory, clientID: client.id, vaultID: vaultID,
                        scopes: entry.scopes.filter { $0 != "fill" })
                }
            }
        }
    }

    public func pairedClients(dataDirectory: String) async throws -> [FfiPairedClient] {
        try await read { try $0.pairedClients(dataDirPath: dataDirectory) }
    }

    public func setClientScopes(dataDirectory: String, clientID: String, vaultID: String, scopes: [String]) async throws {
        try await read {
            try $0.setClientScopes(dataDirPath: dataDirectory, clientId: clientID, vaultId: vaultID, scopes: scopes)
        }
    }

    public func unpairClient(dataDirectory: String, clientID: String) async throws {
        try await read { try $0.unpairClient(dataDirPath: dataDirectory, clientId: clientID) }
    }

    /// Pairs the program at `path` (ad hoc or unsigned code). Returns its client id.
    public func pairProgram(dataDirectory: String, path: String) async throws -> String {
        try await read { try $0.pairProgram(dataDirPath: dataDirectory, path: path) }
    }

    public func liveGrants(dataDirectory: String) async throws -> [FfiGrant] {
        try await read { try $0.liveGrants(dataDirPath: dataDirectory) }
    }

    /// Revokes one grant, or every grant when `grantID` is nil.
    public func revokeGrants(dataDirectory: String, grantID: String?) async throws {
        try await read { try $0.revokeGrants(dataDirPath: dataDirectory, grantId: grantID) }
    }

    public func auditReport(dataDirectory: String) async throws -> FfiAuditReport {
        try await read { try $0.auditReport(dataDirPath: dataDirectory) }
    }

    public func rotateAuditLog(dataDirectory: String) async throws {
        try await read { try $0.rotateAuditLog(dataDirPath: dataDirectory) }
    }
}
