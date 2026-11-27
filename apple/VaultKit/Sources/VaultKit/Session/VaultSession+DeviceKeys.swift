import CryptoKit
import Foundation
import OnePassCore
import os

/// This device's keys for a personal account (key rotation v2, spec 6.2 and 15): what contact cards,
/// shared vaults and recovery cancels sign with. A new account is created on v2 with them; an
/// account from before v2 migrates at the first unlock on each device (`migrateToV2IfNeeded`).
extension VaultSession {
    nonisolated private static let keysLog = Logger(subsystem: "me.somalabs.onepass", category: "device-keys")

    /// This account's device keys in this device's Keychain, nil before the account exists. The
    /// item may still be missing (`deviceKeys()` then throws `NotFound`).
    public var accountDeviceKeys: AccountDeviceKeys? {
        guard let accountID = settings.accountID else { return nil }
        return AccountDeviceKeys(keychain: environment.keychain, accountID: accountID)
    }

    /// The account's device keys when the Keychain holds them and they read, nil otherwise.
    public func readableDeviceKeys() -> AccountDeviceKeys? {
        guard let keys = accountDeviceKeys, (try? keys.deviceKeys()) != nil else { return nil }
        return keys
    }

    /// What the contact flows sign and travel with (sharing plan 4): this account's readable device
    /// keys and its zone transport `zones`. Nil until both exist (an account not migrated yet on
    /// this device, a build without a hosted server).
    public func contactTransport(zones: AccountZones?) -> (keys: AccountDeviceKeys, zones: AccountZones)? {
        guard let zones, let keys = readableDeviceKeys() else { return nil }
        return (keys, zones)
    }

    /// A personal account created on key rotation v2: device keys made under the pending name of
    /// `slot` (Secure Enclave when `secureEnclave`), the account whose genesis this device signs
    /// with them, then the keys moved under the account id. Same flow as
    /// `createAccount(password:displayName:mode:)` otherwise (Secret Key in the keychain, settings,
    /// unlock), and the same return: the Secret Key in display form, wiped by the caller. Keys that
    /// cannot move under the account id stay pending and are logged: the account exists and its
    /// Secret Key must reach the Emergency Kit, so that never fails the creation.
    public func createPersonalAccount(
        password: SecretBytes, displayName: String, mode: DeviceMode, slot: String,
        secureEnclave: Bool = SecureEnclave.isAvailable
    ) async throws -> SecretBytes {
        let keychain = environment.keychain
        let pending = try AccountDeviceKeys.createPending(keychain: keychain, slot: slot, secureEnclave: secureEnclave)
        let device = Self.deviceIdentity(mode: mode)
        let secretKey: SecretBytes
        do {
            secretKey = try await createAccount(password: password, displayName: displayName, mode: mode, device: device) {
                path, bytes, kdf in
                try createAccountV2Bytes(
                    dbPath: path, password: bytes, kdf: kdf, classical: pending.classical, pq: pending.pq,
                    name: device.name, kind: device.kind, mode: device.mode)
            }
        } catch {
            // No account names these keys: they go.
            AccountDeviceKeys.discardPending(keychain: keychain, slot: slot)
            throw error
        }
        if let accountID = settings.accountID {
            do {
                try AccountDeviceKeys.adoptPending(keychain: keychain, slot: slot, accountID: accountID)
            } catch {
                Self.keysLog.error("device keys of a new account left pending")
            }
        }
        return secretKey
    }

    /// The migration of an account from before key rotation v2 on this device (spec 15), right
    /// after an unlock: nothing when the session is locked, the account already v2 on this device, or
    /// another migration of the same account runs. Otherwise a sync round first (the genesis another
    /// device already wrote is joined, not doubled), this device's keys (the stored ones, else fresh
    /// ones stored first: `AccountDeviceKeys.existingOrCreate`), then `migrate_to_v2` (this device's
    /// genesis, or its intro under another device's) and a sync round that pushes it. Never touches
    /// the unlock: the caller runs it after, and a failure throws for the log and is tried again at
    /// the next unlock. Returns what the core did, nil when nothing ran.
    @discardableResult
    public func migrateToV2IfNeeded(secureEnclave: Bool = SecureEnclave.isAvailable) async throws -> FfiMigration? {
        guard let core = coreSession, let accountID = settings.accountID else { return nil }
        guard LineageMigrationGate.running.insert(accountID).inserted else { return nil }
        defer { LineageMigrationGate.running.remove(accountID) }
        guard try await CoreThread.run({ try core.lineageStatus().state }) == .legacy else { return nil }
        await environment.sync.syncNow()
        // Locked (or another account opened) during the round: the next unlock tries again.
        guard coreSession === core else { return nil }
        let keys = try AccountDeviceKeys.existingOrCreate(
            keychain: environment.keychain, accountID: accountID, secureEnclave: secureEnclave)
        let outcome = try await CoreThread.run { try core.migrateToV2(classical: keys.classical, pq: keys.pq) }
        await environment.sync.localChangesWritten()
        return outcome
    }

    /// `migrateToV2IfNeeded` for the app's unlock: failures are logged, never shown nor thrown.
    public func migrateToV2AfterUnlock() async {
        do {
            switch try await migrateToV2IfNeeded() {
            case .genesis?: Self.keysLog.info("account migrated to key rotation v2 (genesis)")
            case .joined?: Self.keysLog.info("account migrated to key rotation v2 (joined)")
            case .already?, nil: break
            }
        } catch {
            Self.keysLog.error("key rotation v2 migration failed, tried again at the next unlock")
        }
    }
}

/// The accounts whose migration runs now, across every session of the process (one per account).
@MainActor
enum LineageMigrationGate {
    static var running: Set<String> = []
}
