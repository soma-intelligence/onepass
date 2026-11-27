import Foundation
import OnePassCore
import os

/// What a password unlock hands back: the session, the Account Unlock Key and, for a guarded
/// account, `G` (Guarded Kit spec 7.2) with its guard version, for this device to keep. The caller
/// wipes the buffers.
struct PasswordUnlocked: Sendable {
    let session: Session
    let auk: SecretBytes
    let guardSecret: SecretBytes?
    let guardVersion: UInt32
}

/// Guarded Kit (spec 2026-11-20, sections 7 to 9): "Protection du kit d'urgence" in Réglages >
/// Sécurité. Once on, the keyset is sealed under a key that also needs `G`, shared 2 of 3 between
/// three realms run by Soma: a thief of the Emergency Kit gets 15 online attempts, no more. This
/// device keeps `G` with its guard version in the Keychain (`GuardVault`) and unlocks without the
/// realms. Rule: a password typed on a device whose kept `G` is current never reaches the realms
/// (a typo there would spend one of their attempts, and the 10th erases the guard for good,
/// decision Q4). The realms are asked only without a kept `G`, or when the store's guard version
/// moved on (renewed, or the password changed, on another device), and on a new device restoring
/// from the kit.
extension VaultSession {
    nonisolated private static let guardLog = Logger(subsystem: "me.somalabs.onepass", category: "guard")

    var guardVault: GuardVault { GuardVault(keychain: environment.keychain) }

    /// The `G` this device kept for `accountID` with its version (the caller wipes it), nil without
    /// one or when the Keychain cannot answer.
    func keptGuard(accountID: String?) -> KeptGuard? {
        guard let accountID else { return nil }
        return (try? guardVault.load(accountID: accountID)) ?? nil
    }

    /// After an unlock or a change: keeps the `G` handed back with its version, or erases a kept one
    /// when the account is not guarded (any more). A failed write is only logged: the next password
    /// unlock asks the realms again and keeps it then.
    func keepGuard(_ secret: SecretBytes?, version: UInt32, accountID: String) {
        do {
            if let secret {
                try guardVault.store(secret, version: version, accountID: accountID)
            } else if try guardVault.contains(accountID: accountID) {
                try guardVault.remove(accountID: accountID)
            }
        } catch {
            Self.guardLog.error("guard secret not updated in the keychain")
        }
    }

    // MARK: - Core calls (core thread)

    /// The guard version of the store's newest params (unverified, read without keys), nil for an
    /// unguarded account or a store that cannot be read (the unlock then reports the store error).
    nonisolated private static func storeGuardVersion(_ dbPath: String) -> UInt32? {
        (try? guardVersion(dbPath: dbPath)) ?? nil
    }

    /// `unlock_with_password` on an account that may be guarded.
    /// - Unguarded store: the usual byte path. Should the store say otherwise after all
    ///   (`GuardRequired`, before any derivation), the realms.
    /// - Kept `G` of the store's version: that `G` only, no transport. A wrong password stays
    ///   `WrongPassword` here and counts toward the local lockout alone.
    /// - No kept `G`, or one of another version: the realms (a wrong password costs one attempt
    ///   there, `GuardWrongPassword`).
    nonisolated static func unlockMaybeGuarded(
        dbPath: String, password: SecretBytes, secretKey: SecretBytes, kept: KeptGuard?,
        transport: any FfiRealmTransport
    ) throws -> PasswordUnlocked {
        guard let current = storeGuardVersion(dbPath) else {
            do {
                var unlocked = try password.withData { password in
                    try secretKey.withData { secretKey in
                        try unlockWithPasswordBytes(dbPath: dbPath, password: password, secretKey: secretKey)
                    }
                }
                return PasswordUnlocked(
                    session: unlocked.session, auk: SecretBytes(taking: &unlocked.auk), guardSecret: nil,
                    guardVersion: 0)
            } catch OnePassError.GuardRequired {
                return try unlockGuarded(
                    dbPath: dbPath, password: password, secretKey: secretKey, kept: nil, transport: transport)
            }
        }
        if let kept, kept.version == current {
            return try unlockGuarded(
                dbPath: dbPath, password: password, secretKey: secretKey, kept: kept.secret, transport: nil)
        }
        return try unlockGuarded(
            dbPath: dbPath, password: password, secretKey: secretKey, kept: nil, transport: transport)
    }

    /// The master password check of an account that may be guarded: the Account Unlock Key (the
    /// caller wipes it), no session, no device state written, never the realms. Unguarded:
    /// `verify_password`. Guarded with a kept `G` of the store's version: `verify_password_guarded`.
    /// Guarded without one: `GuardRequired` (a password unlock brings the current `G` first).
    nonisolated static func verifyMaybeGuarded(
        dbPath: String, password: SecretBytes, secretKey: SecretBytes, kept: KeptGuard?
    ) throws -> SecretBytes {
        guard let current = storeGuardVersion(dbPath) else {
            var auk = try password.withData { password in
                try secretKey.withData { secretKey in
                    try verifyPasswordBytes(dbPath: dbPath, password: password, secretKey: secretKey)
                }
            }
            return SecretBytes(taking: &auk)
        }
        guard let kept, kept.version == current else { throw OnePassError.GuardRequired }
        guard let typed = password.string(), let key = secretKey.string() else { throw OnePassError.WrongPassword }
        var auk = try kept.secret.withData { g in
            try verifyPasswordGuarded(dbPath: dbPath, password: typed, secretKey: key, guard: g)
        }
        return SecretBytes(taking: &auk)
    }

    /// `unlock_with_password_guarded`, then the verified guard version of the opened session. The
    /// guarded calls take `String`s: the password and the Secret Key cross the FFI as temporary
    /// strings there.
    nonisolated private static func unlockGuarded(
        dbPath: String, password: SecretBytes, secretKey: SecretBytes, kept: SecretBytes?,
        transport: (any FfiRealmTransport)?
    ) throws -> PasswordUnlocked {
        guard let typed = password.string(), let key = secretKey.string() else { throw OnePassError.WrongPassword }
        var unlocked = try kept.map { kept in
            try kept.withData { g in
                try unlockWithPasswordGuarded(
                    dbPath: dbPath, password: typed, secretKey: key, guard: g, transport: transport)
            }
        } ?? unlockWithPasswordGuarded(dbPath: dbPath, password: typed, secretKey: key, guard: nil, transport: transport)
        let auk = SecretBytes(taking: &unlocked.auk)
        var guardSecret: SecretBytes?
        if var secret = unlocked.`guard` { guardSecret = SecretBytes(taking: &secret) }
        let version = guardSecret == nil ? 0 : ((try? unlocked.session.guardState().version) ?? 0)
        return PasswordUnlocked(
            session: unlocked.session, auk: auk, guardSecret: guardSecret, guardVersion: version)
    }

    // MARK: - Settings

    /// Off or on, whether this build can turn it on (`available` is false until the realms are
    /// pinned in a release), and whether the realm list changed since the guard was set up.
    public func guardState() async throws -> FfiGuardState {
        try await read { try $0.guardState() }
    }

    /// "Protection du kit d'urgence" on (spec 8.1), after the master password (the Secret Key comes
    /// from this device's Keychain). Registers `G` at every realm (all must answer), re-seals the
    /// keyset, keeps `G` here and enrolls biometric unlock again with the new Account Unlock Key.
    /// The screen then offers a new Emergency Kit. The caller wipes `password`.
    public func enableGuard(password: SecretBytes) async throws {
        try await guardChange(password: password) { session, password, secretKey, transport in
            var change = try session.enableGuard(password: password, secretKey: secretKey, transport: transport)
            return (SecretBytes(taking: &change.auk), SecretBytes(taking: &change.`guard`))
        }
    }

    /// Registers again (spec 8.3, 8.4): `newGuard` false keeps `G` (realm list changed in a
    /// release, a realm lost it), true draws a new one. The caller wipes `password`.
    public func renewGuard(password: SecretBytes, newGuard: Bool = false) async throws {
        try await guardChange(password: password) { session, password, secretKey, transport in
            var change = try session.renewGuard(
                password: password, secretKey: secretKey, transport: transport, newGuard: newGuard)
            return (SecretBytes(taking: &change.auk), SecretBytes(taking: &change.`guard`))
        }
        guardRenewalDue = false
    }

    /// "Protection du kit d'urgence" off: the keyset back under the password and the Secret Key
    /// alone, the guard deleted at the realms, the kept `G` erased here. The caller wipes
    /// `password`.
    public func disableGuard(password: SecretBytes) async throws {
        try await guardChange(password: password) { session, password, secretKey, transport in
            var auk = try session.disableGuard(password: password, secretKey: secretKey, transport: transport)
            return (SecretBytes(taking: &auk), nil)
        }
        guardRenewalDue = false
    }

    /// The owner poll of spec 8.4: failed restore attempts the realms logged (Unix seconds, newest
    /// first) and whether a realm lost the guard (then the next password unlock renews it). Off:
    /// an empty report.
    public func guardHealth() async throws -> FfiGuardHealth {
        let transport = environment.realmTransport
        let health = try await read { try $0.guardHealth(transport: transport) }
        if health.needsRenewal { guardRenewalDue = true }
        return health
    }

    /// `guardHealth().failures` as dates, newest first.
    public nonisolated static func guardFailureDates(_ health: FfiGuardHealth) -> [Date] {
        health.failures.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// After a password unlock of a guarded account: renews the guard (same `G`) when the realm list
    /// of this release differs from the one it was set up with, or a health poll found a realm that
    /// lost it. Silent and in the background: a failure waits for the next unlock or the button in
    /// Réglages.
    func renewGuardAfterUnlock(password: SecretBytes) {
        let copy = password.withUnsafeBytes { SecretBytes(copying: $0) }
        Task { [weak self] in
            defer { copy.wipe() }
            guard let self, self.state == .unlocked,
                let state = try? await self.guardState(), state.on, state.available,
                !state.realmSetCurrent || self.guardRenewalDue
            else { return }
            do {
                try await self.renewGuard(password: copy)
            } catch {
                Self.guardLog.error("guard renewal after unlock failed")
            }
        }
    }

    // MARK: - Shared

    /// Runs one change of the guard with the password and the Secret Key, then: the throttle is
    /// reset, `G` kept or erased, biometric unlock enrolled again with the new Account Unlock Key
    /// (turned off if that fails), every remote unlock envelope dropped (they sealed the old one),
    /// and the sync told. A wrong password counts toward the throttle.
    private func guardChange(
        password: SecretBytes,
        _ op: @escaping @Sendable (Session, String, String, any FfiRealmTransport) throws -> (SecretBytes, SecretBytes?)
    ) async throws {
        guard state == .unlocked else { throw fail(.passwordRequired) }
        try checkLockout()
        let (accountID, secretKey) = try loadSecretKey()
        defer { secretKey.wipe() }
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let transport = environment.realmTransport
        let changed: (auk: SecretBytes, secret: SecretBytes?, version: UInt32)
        do {
            changed = try await read { session in
                guard let typed = password.string(), let key = secretKey.string() else {
                    throw VaultError.wrongPassword
                }
                let (auk, secret) = try op(session, typed, key, transport)
                // The version `G` now belongs to, kept with it (a later unlock compares it).
                let version = secret == nil ? 0 : ((try? session.guardState().version) ?? 0)
                return (auk, secret, version)
            }
        } catch {
            let failure = VaultError(error)
            if failure.isWrongPassword { recordFailedUnlock() }
            throw fail(failure)
        }
        defer {
            changed.auk.wipe()
            changed.secret?.wipe()
        }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        keepGuard(changed.secret, version: changed.version, accountID: accountID)
        reenrollBiometrics(accountID: accountID, auk: changed.auk)
        passwordChangedHere?()
        notifySync { await $0.localChangesWritten() }
    }

    /// The keyset now opens under a new Account Unlock Key: a biometric enrollment wraps it again,
    /// or is turned off when that fails (the next unlock then asks the password).
    func reenrollBiometrics(accountID: String, auk: SecretBytes) {
        if biometrics.isEnrolled(accountID: accountID) {
            let allowWatch = settings.allowWatchUnlock
            do {
                try auk.withData { try biometrics.enroll(auk: $0, accountID: accountID, allowWatch: allowWatch) }
            } catch {
                biometrics.disable(accountID: accountID)
            }
        }
        biometricsRevision += 1
    }
}
