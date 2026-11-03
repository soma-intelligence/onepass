import Foundation
import OnePassCore

/// The family (sharing spec 11) and the item sends (spec 14.2). Each call refreshes `sharing`.
extension VaultSession {
    /// Creates the family and its shared vault; this account is its organizer.
    @discardableResult
    public func createFamily(vaultName: String, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.createFamily(vaultName: vaultName, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    @discardableResult
    public func inviteToFamily(_ contactID: String, role: FfiFamilyRole, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.inviteToFamily(contact: contactID, role: role, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    @discardableResult
    public func acceptFamilyInvite(_ inviteID: String, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.acceptFamilyInvite(inviteId: inviteID, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    @discardableResult
    public func removeFromFamily(_ accountID: String, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.removeFromFamily(accountId: accountID, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    public func leaveFamily(at now: Date = Date()) async throws {
        let t = Self.unix(now)
        try await write { try $0.leaveFamily(now: t) }
        try await refreshSharing(at: now)
    }

    @discardableResult
    public func setFamilyRole(_ role: FfiFamilyRole, of accountID: String, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.setFamilyRole(accountId: accountID, role: role, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    @discardableResult
    public func addFamilyVault(_ vaultID: String, at now: Date = Date()) async throws -> FfiFamily {
        let t = Self.unix(now)
        let family = try await write { try $0.addFamilyVault(vaultId: vaultID, now: t) }
        try await refreshSharing(at: now)
        return family
    }

    // MARK: - Item sends

    /// Sends a copy of an item to a contact, kept until `expiresAt` (30 days at most). Returns the
    /// send id.
    @discardableResult
    public func sendItem(
        _ itemID: String, in vaultID: String, to contactID: String, expiresAt: Date, at now: Date = Date()
    ) async throws -> String {
        let (t, until) = (Self.unix(now), Self.unix(expiresAt))
        return try await write { try $0.sendItem(vaultId: vaultID, itemId: itemID, to: contactID, expiresAt: until, now: t) }
    }

    /// Keeps a received copy in `vaultID`.
    @discardableResult
    public func acceptReceivedItem(_ sendID: String, into vaultID: String, at now: Date = Date()) async throws -> FfiItem {
        let t = Self.unix(now)
        let item = try await write { try $0.acceptReceivedItem(sendId: sendID, into: vaultID, now: t) }
        try await refreshSharing(at: now)
        return item
    }

    public func declineReceivedItem(_ sendID: String) async throws {
        try await write { try $0.declineReceivedItem(sendId: sendID) }
        try await refreshSharing()
    }

    /// Drops the sends past their date; how many went.
    @discardableResult
    public func purgeExpiredSends(at now: Date = Date()) async throws -> UInt32 {
        let t = Self.unix(now)
        let purged = try await write { try $0.purgeExpiredSends(now: t) }
        try await refreshSharing(at: now)
        return purged
    }
}
