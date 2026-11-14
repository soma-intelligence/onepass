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
}
