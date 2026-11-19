import Foundation

extension VaultSession {
    /// `createAccount`'s flow (Secret Key in the keychain, settings, install) with the managed genesis:
    /// the account's lineage names `orgID` (32 hex) and is signed by `keys`, this device's keys
    /// (`ManagedDeviceKeys`). `accountID`: the id the org roster invited (the join link's), or `nil`
    /// for a fresh one (the org's creator). Returns the Secret Key in display form (the caller wipes it).
    public func createManagedAccount(
        password: SecretBytes, displayName: String, mode: DeviceMode, orgID: String, accountID: String?,
        keys: DeviceKeyPair
    ) async throws -> SecretBytes {
        let device = Self.deviceIdentity(mode: mode)
        return try await createAccount(password: password, displayName: displayName, mode: mode, device: device) {
            path, bytes, kdf in
            try OnePassCore.createManagedAccount(
                dbPath: path, password: bytes, kdf: kdf, classical: keys.classical, pq: keys.pq,
                name: device.name, kind: device.kind, mode: device.mode, orgId: orgID, accountId: accountID)
        }
    }

    /// Publishes `draft` on the organisation's server with this unlocked managed account (its creator)
    /// signing with `keys`: the org mailbox is made with `serverInvite`, the genesis, roster and owner
    /// keyset are written, and the pin is kept in `stateDir`. The org mailbox's managing credential is
    /// the creator's own org seed in `credentials`, made and stored in the keychain before the publish
    /// (R39), so the server never knows a manager credential the device could lose; a retry reuses it.
    /// `VaultError.passwordRequired` while locked.
    public func publishOrg(
        _ draft: OrgDraft, endpoint: FfiMailboxEndpoint, serverInvite: String, keys: DeviceKeyPair, name: String,
        stateDir: String, credentials: ManagedOrgCredentials
    ) async throws -> FfiOrgCreated {
        guard let core = coreSession else { throw VaultError.passwordRequired }
        let now = Int64(Date().timeIntervalSince1970)
        return try await Self.publishWithStoredSeed(credentials: credentials) { seed in
            try await CoreThread.run {
                try draft.publish(
                    endpoint: endpoint, serverInvite: serverInvite, credentialSeed: seed, session: core,
                    classical: keys.classical, pq: keys.pq, name: name, stateDir: stateDir, now: now)
            }
        }
    }

    /// `publish` with the creator's own org seed: the stored one, else a new one stored first (R39).
    static func publishWithStoredSeed<Created>(
        credentials: ManagedOrgCredentials, publish: (Data) async throws -> Created
    ) async throws -> Created {
        let seed = try credentials.ownSeedStoringNew()
        defer { seed.wipe() }
        return try await publish(seed.withData { Data($0) })
    }
}

extension OrgPinPlan {
    /// The error `OrgSession.pin` throws for this plan when it refuses it, nil for a plan that pins: lets
    /// a caller stop before it makes anything for the organisation.
    public var refusal: OrgActionError? {
        switch self {
        case .refuse(.mdmInvalid):
            .other(String(localized: "org.error.mdmInvalid", bundle: VaultKitStrings.bundle))
        case .refuse:
            .refused(.pinMismatch)
        case .pin:
            nil
        }
    }
}
