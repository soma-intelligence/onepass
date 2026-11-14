import Foundation
import OnePassCore

/// The org calls `OrgSession` makes, one per `OrgClient` method. `keys` are this device's keys
/// (`DeviceKeySource`); they sign in the core and never leave this process.
public protocol OrgBackend: Sendable {
    func state() async throws -> FfiOrgState?
    func pin(source: FfiPinSource, expected: Data?, now: Int64) async throws -> FfiOrgState
    func refresh() async throws -> FfiOrgState
    func markVerified() async throws -> FfiOrgState
    func joinRequests() async throws -> [FfiJoinRequest]
    func postJoinRequest(
        session: Session, keys: DeviceKeyPair, invite: FfiOrgInvite, displayName: String, now: Int64
    ) async throws -> FfiJoinPosted
    /// Revokes the credential this backend's client holds (a member drops the link's, R27).
    func revokeOwnCredential() async throws
    func declineJoinRequest(accountID: String) async throws
    func summarize(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit) async throws -> FfiEditSummary
    func edit(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit, now: Int64) async throws -> FfiEditOutcome
    func createInvite(
        session: Session, keys: DeviceKeyPair, label: String, domain: String?, roles: [FfiOrgRole], now: Int64
    ) async throws -> FfiInviteLink
    func ownerKeysAvailable(session: Session, keys: DeviceKeyPair) async throws -> Bool
    func setOwners(session: Session, keys: DeviceKeyPair, owners: [String], now: Int64) async throws -> FfiOrgState
}

/// `OrgBackend` over the FFI's `OrgClient`, each call on the core thread (it blocks on the network).
public struct FfiOrgBackend: OrgBackend {
    private let client: OrgClient

    public init(client: OrgClient) { self.client = client }

    public func state() async throws -> FfiOrgState? {
        try await CoreThread.run { [client] in try client.state() }
    }

    public func pin(source: FfiPinSource, expected: Data?, now: Int64) async throws -> FfiOrgState {
        try await CoreThread.run { [client] in try client.pin(source: source, expectedFingerprint: expected, now: now) }
    }

    public func refresh() async throws -> FfiOrgState {
        try await CoreThread.run { [client] in try client.refresh() }
    }

    public func markVerified() async throws -> FfiOrgState {
        try await CoreThread.run { [client] in try client.markVerified() }
    }

    public func joinRequests() async throws -> [FfiJoinRequest] {
        try await CoreThread.run { [client] in try client.joinRequests() }
    }

    public func postJoinRequest(
        session: Session, keys: DeviceKeyPair, invite: FfiOrgInvite, displayName: String, now: Int64
    ) async throws -> FfiJoinPosted {
        try await CoreThread.run { [client] in
            try client.postJoinRequest(
                session: session, classical: keys.classical, pq: keys.pq, invite: invite, displayName: displayName,
                now: now)
        }
    }

    public func revokeOwnCredential() async throws {
        try await CoreThread.run { [client] in try client.revokeOwnCredential() }
    }

    public func declineJoinRequest(accountID: String) async throws {
        try await CoreThread.run { [client] in try client.declineJoinRequest(accountId: accountID) }
    }

    public func summarize(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit) async throws -> FfiEditSummary {
        try await CoreThread.run { [client] in
            try client.summarize(session: session, classical: keys.classical, pq: keys.pq, edit: edit)
        }
    }

    public func edit(
        session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit, now: Int64
    ) async throws -> FfiEditOutcome {
        try await CoreThread.run { [client] in
            try client.editRoster(session: session, classical: keys.classical, pq: keys.pq, edit: edit, now: now)
        }
    }

    public func createInvite(
        session: Session, keys: DeviceKeyPair, label: String, domain: String?, roles: [FfiOrgRole], now: Int64
    ) async throws -> FfiInviteLink {
        try await CoreThread.run { [client] in
            try client.createInvite(
                session: session, classical: keys.classical, pq: keys.pq, label: label, domain: domain, roles: roles,
                now: now)
        }
    }

    public func ownerKeysAvailable(session: Session, keys: DeviceKeyPair) async throws -> Bool {
        try await CoreThread.run { [client] in
            try client.ownerKeysetAvailable(session: session, classical: keys.classical, pq: keys.pq)
        }
    }

    public func setOwners(
        session: Session, keys: DeviceKeyPair, owners: [String], now: Int64
    ) async throws -> FfiOrgState {
        try await CoreThread.run { [client] in
            try client.setOwners(session: session, classical: keys.classical, pq: keys.pq, owners: owners, now: now)
        }
    }
}
