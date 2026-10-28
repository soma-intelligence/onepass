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
