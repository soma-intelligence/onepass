import Foundation
import OnePassCore

/// Organizer-assisted recovery (sharing spec 11.4 to 11.7): the member enrolls with an organizer,
/// the organizer asks after a loss, the member's devices show the request (locked too) and can
/// cancel it, then the organizer hands the share over face to face (`RecoveryReleaseFlow`,
/// `RecoverWithHelpFlow`).
extension VaultSession {
    // MARK: - Member

    /// What the member reads and confirms before enrolling (spec 11.4, 11.7): who could open the
    /// vault together. `mailboxAccount`: the account syncs through a mailbox (Emergency Kit) rather
    /// than iCloud.
    public static func recoveryRiskText(organizer: String, mailboxAccount: Bool) -> String {
        mailboxAccount
            ? String(localized: "recovery.enroll.riskKit \(organizer)", bundle: VaultKitStrings.bundle)
            : String(localized: "recovery.enroll.riskICloud \(organizer)", bundle: VaultKitStrings.bundle)
    }

    /// Enrolls with `organizer` (a family organizer and a verified contact). The core checks the
    /// password and the Secret Key; the FFI takes them as `String`s, wiped by the core.
    @discardableResult
    public func enrollRecovery(
        organizer: String, delaySecs: UInt32, password: SecretBytes, at now: Date = Date()
    ) async throws -> FfiRecoveryEnrollment {
        let t = Self.unix(now)
        let (pw, sk) = try recoveryCredentials(password)
        let enrollment = try await write {
            try $0.enrollRecovery(organizer: organizer, delaySecs: delaySecs, password: pw, secretKey: sk, now: t)
        }
        try await refreshSharing(at: now)
        return enrollment
    }

    public func disableRecovery(password: SecretBytes) async throws {
        let (pw, sk) = try recoveryCredentials(password)
        try await write { try $0.disableRecovery(password: pw, secretKey: sk) }
        try await refreshSharing()
    }

    /// Reads the recovery requests for this account from the store, without unlocking: the app calls
    /// it at launch and after each sync round, locked or not (spec 11.5).
    public func refreshRecoveryAlerts() async {
        let path = dbPath
        guard FileManager.default.fileExists(atPath: path) else {
            recoveryAlerts = []
            return
        }
        recoveryAlerts = (try? await background { try OnePassCore.recoveryAlerts(dbPath: path) }) ?? []
    }

    /// "<organisateur> a demandé à récupérer ton compte. Ce sera possible le <date> à <heure>. Si ce
    /// n'est pas toi, annule."
    public static func recoveryAlertMessage(_ alert: FfiRecoveryAlert) -> String {
        let at = Date(timeIntervalSince1970: TimeInterval(alert.releaseAfter))
        return String(
            localized: "recovery.alert \(alert.organizerNameLocal) \(longDate(at)) \(shortTime(at))",
            bundle: VaultKitStrings.bundle)
    }

    /// "Annuler" on a member device, locked or not: a cancel signed by this device's keys, no
    /// password. The zone round sends it (from the cached seeds while locked).
    public func cancelRecovery(_ enrollmentID: String, keys: any DeviceKeySource, at now: Date = Date()) async throws {
        let (path, t) = (dbPath, Self.unix(now))
        let pair: DeviceKeyPair
        do {
            pair = try keys.deviceKeys()
        } catch {
            throw fail(VaultError(error))
        }
        do {
            try await background {
                try OnePassCore.cancelRecovery(dbPath: path, enrollmentId: enrollmentID, classical: pair.classical, pq: pair.pq, now: t)
            }
        } catch {
            throw fail(VaultError(error))
        }
        notifySync { await $0.localChangesWritten() }
        await refreshRecoveryAlerts()
    }

    // MARK: - Organizer

    /// "<membre> t'a choisi pour l'aider à récupérer son compte." (spec 11.4, organizer side).
    public static func helperMessage(_ helper: FfiHelper) -> String {
        String(localized: "recovery.helper.chosen \(helper.nameLocal)", bundle: VaultKitStrings.bundle)
    }

    /// The organizer asks to recover `member`'s account: the delay starts now, on this clock.
    @discardableResult
    public func requestRecovery(of member: String, password: SecretBytes, at now: Date = Date()) async throws -> FfiRecoveryStatus {
        let t = Self.unix(now)
        let (pw, sk) = try recoveryCredentials(password)
        let status = try await write { try $0.requestRecovery(member: member, password: pw, secretKey: sk, now: t) }
        try await refreshSharing(at: now)
        return status
    }

    public func recoveryStatus(of member: String, at now: Date = Date()) async throws -> FfiRecoveryStatus {
        let t = Self.unix(now)
        return try await read { try $0.recoveryStatus(member: member, now: t) }
    }

    // MARK: - Helpers

    /// The typed password and this device's Secret Key as the `String`s the FFI takes.
    private func recoveryCredentials(_ password: SecretBytes) throws -> (String, String) {
        guard let pw = password.string() else { throw fail(.validation(field: "password", reason: "password encoding")) }
        let stored = try loadSecretKey()
        defer { stored.secretKey.wipe() }
        guard let sk = stored.secretKey.string() else { throw fail(.passwordRequired) }
        return (pw, sk)
    }
}
