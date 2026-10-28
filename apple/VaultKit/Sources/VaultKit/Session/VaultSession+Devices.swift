import Foundation
import OnePassCore

#if canImport(UIKit)
import UIKit
#endif

/// How this device lists itself in the signed device list (spec 2b 4.3).
struct DeviceIdentity: Sendable {
    var name: String
    var kind: FfiDeviceKind
    var mode: FfiDeviceMode
}

extension DeviceMode {
    var ffi: FfiDeviceMode {
        switch self {
        case .personal: .personal
        case .shared: .shared
        }
    }

    /// The mode of a full grant (a public grant never reaches the store).
    init?(_ mode: FfiDeviceMode) {
        switch mode {
        case .personal: self = .personal
        case .shared: self = .shared
        case .public: return nil
        }
    }
}

extension VaultSession {
    /// Longest device name the core keeps.
    static let maxDeviceNameLength = 64

    /// This device's name and type, in the mode given.
    static func deviceIdentity(mode: DeviceMode) -> DeviceIdentity {
        DeviceIdentity(name: String(currentDeviceName().prefix(maxDeviceNameLength)), kind: currentDeviceKind, mode: mode.ffi)
    }

    /// The name the user gave this device.
    static func currentDeviceName() -> String {
        #if os(macOS)
        Host.current().localizedName ?? "Mac"
        #elseif os(watchOS)
        "Apple Watch"
        #else
        UIDevice.current.name
        #endif
    }

    /// This device's type in the device list.
    static var currentDeviceKind: FfiDeviceKind {
        #if os(macOS)
        .mac
        #elseif os(visionOS)
        .vision
        #elseif os(watchOS)
        .other
        #else
        UIDevice.current.userInterfaceIdiom == .pad ? .tablet : .phone
        #endif
    }

    /// The store holds account params newer than the ones this device last unlocked (the master
    /// password changed on another device). False before a first unlock and when the store cannot be
    /// read. A missing file is never opened (opening would create it).
    nonisolated static func paramsChangedElsewhere(dbPath: String) -> Bool {
        guard FileManager.default.fileExists(atPath: dbPath),
            let stored = try? storeParamsEpoch(dbPath: dbPath),
            let pinned = try? pinnedParamsEpoch(dbPath: dbPath),
            pinned > 0
        else { return false }
        return stored > pinned
    }

    // MARK: - Devices

    /// Reads the signed device list and this device's id again.
    public func refreshDevices() async throws {
        let (list, me) = try await read { session in (try session.devices(), session.thisDeviceId()) }
        devices = list
        thisDeviceID = me
    }

    /// Marks another device revoked (ruling A8: fresh presence first, Face ID or Touch ID, else
    /// `password`). This device cannot revoke itself from the list (ruling A6). Refreshes the list and
    /// lets the sync layer send it.
    public func revokeDevice(_ id: String, password: SecretBytes? = nil) async throws {
        try await confirmPresence(password: password, prompt: Self.revokePrompt)
        try await write { try $0.revokeDevice(id: id) }
        try await refreshDevices()
    }

    /// `revokeDevice(_:password:)` with a typed `String` (tests).
    public func revokeDevice(_ id: String, password: String) async throws {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        try await revokeDevice(id, password: bytes)
    }

    /// Renames a device of the list (a revoked one is refused).
    public func renameDevice(_ id: String, name: String) async throws {
        try await write { try $0.renameDevice(id: id, name: name) }
        try await refreshDevices()
    }

    /// Deletes an empty vault (trashed items go with it). The last vault and a vault with live items
    /// are refused ("Le dernier coffre ne peut pas être supprimé.", "Vide ce coffre avant de le
    /// supprimer.").
    public func deleteVault(_ id: String) async throws {
        try await write { try $0.deleteVault(vaultId: id) }
        if hiddenVaultIDs.contains(id) { setVaultHidden(id, hidden: false) }
    }

    // MARK: - Master password

    /// `changePassword(current:new:)` with typed `String`s (tests).
    public func changePassword(current: String, new: String) async throws {
        let (a, b) = (SecretBytes(utf8: current), SecretBytes(utf8: new))
        defer {
            a.wipe()
            b.wipe()
        }
        try await changePassword(current: a, new: b)
    }

    /// Changes the master password (the core checks `current` and the Secret Key first; a wrong one
    /// counts toward the failure throttle). The session goes on. When biometric unlock was enrolled it
    /// is enrolled again with the new Account Unlock Key (the old one no longer opens the account);
    /// if that fails it is turned off and the next unlock asks the password. Other devices then show
    /// `passwordChangedElsewhere` until they unlock with the new password. The caller wipes both.
    public func changePassword(current: SecretBytes, new: SecretBytes) async throws {
        guard state == .unlocked else { throw fail(.passwordRequired) }
        try checkLockout()
        let (accountID, secretKey) = try loadSecretKey()
        defer { secretKey.wipe() }
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let auk: SecretBytes
        do {
            auk = try await read { session in
                guard let current = current.string(), let new = new.string(), let key = secretKey.string() else {
                    throw VaultError.wrongPassword
                }
                var bytes = try session.changePassword(current: current, secretKey: key, new: new)
                return SecretBytes(taking: &bytes)
            }
        } catch {
            let failure = VaultError(error)
            if failure == .wrongPassword { recordFailedUnlock() }
            throw fail(failure)
        }
        defer { auk.wipe() }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        if biometrics.isEnrolled(accountID: accountID) {
            let allowWatch = settings.allowWatchUnlock
            do {
                try auk.withData { try biometrics.enroll(auk: $0, accountID: accountID, allowWatch: allowWatch) }
            } catch {
                biometrics.disable(accountID: accountID)
            }
        }
        biometricsRevision += 1
        notifySync { await $0.localChangesWritten() }
    }

    // MARK: - Presence

    /// A fresh check of the user (ruling A8): Face ID or Touch ID when enrolled, else the master
    /// password, never the device passcode (L4: a passcode seen over the shoulder must not add a
    /// device). Without a password and without biometrics, throws `.passwordRequired` (the UI then
    /// asks the password and calls again).
    func confirmPresence(password: SecretBytes?, prompt: String) async throws {
        if let password {
            try await verifyMasterPassword(password)
        } else if await !confirmBiometricPresence(prompt: prompt) {
            throw fail(.passwordRequired)
        }
    }

    /// Face ID or Touch ID only, when biometric unlock is enrolled. False means: ask the master
    /// password.
    func confirmBiometricPresence(prompt: String) async -> Bool {
        guard state == .unlocked, canUseBiometrics else { return false }
        let gen = generation
        let confirmed = await environment.presence.confirmWithBiometrics(prompt: prompt)
        guard confirmed, gen == generation, state == .unlocked else { return false }
        noteActivity()
        return true
    }

    nonisolated static var revokePrompt: String {
        String(localized: "Retirer cet appareil de ton compte", bundle: VaultKitStrings.bundle)
    }
    nonisolated static var approvePrompt: String {
        String(localized: "Ajouter un appareil à ton compte", bundle: VaultKitStrings.bundle)
    }
}
