import Foundation
import OnePassCore
import os

/// The account profile (display name and photo) every device shows. The vault holds it as a hidden
/// item that syncs like the others, the newest write winning; `VaultSettings.displayName` and
/// `profilePhoto` are this device's copy, read by the views and while locked.
///
/// - An edit shows at once (the copy), then reaches the vault after `profileWriteDelay`. Until it is
///   written, `profilePending` keeps it: a lock in between writes it at the next unlock.
/// - Each snapshot carries the vault's profile: it replaces the copy unless a write waits.
/// - No profile in the vault yet but a copy here (from before the profile synced, or a pairing):
///   the copy is published as a seed, which any profile a device set for real overrides.
extension VaultSession {
    /// Show the new name and photo now and write them to the vault, which syncs them to every
    /// device. The name is cut to 64 characters, control characters dropped; a photo over 256 KiB is
    /// left out (the editor stores 256 px JPEGs, far below).
    public func setProfile(name: String, photo: Data?) {
        let clean = String(name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        settings.displayName = String(clean.prefix(Self.maxProfileNameLength))
        settings.profilePhoto = photo.flatMap { $0.count > Self.maxProfilePhotoBytes ? nil : $0 }
        settings.profilePending = true
        profileRevision &+= 1
        profileTask?.cancel()
        let delay = profileWriteDelay
        profileTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await self?.writeProfile()
        }
    }

    nonisolated private static let profileLog = Logger(subsystem: "me.somalabs.onepass", category: "profile")
    nonisolated static let maxProfileNameLength = 64
    nonisolated static let maxProfilePhotoBytes = 256 * 1024

    /// The vault's profile from a snapshot: replaces this device's copy, or receives it.
    func syncProfile(_ remote: FfiProfile?) {
        guard profileTask == nil else { return }
        if settings.profilePending {
            profileTask = Task { [weak self] in await self?.writeProfile() }
            return
        }
        guard let remote else {
            if !settings.displayName.isEmpty || settings.profilePhoto != nil {
                profileTask = Task { [weak self] in await self?.seedProfile() }
            }
            return
        }
        adopt(remote)
    }

    private func adopt(_ profile: FfiProfile) {
        let photo = profile.photo.isEmpty ? nil : profile.photo
        guard settings.displayName != profile.name || settings.profilePhoto != photo else { return }
        settings.displayName = profile.name
        settings.profilePhoto = photo
        profileRevision &+= 1
    }

    /// Writes this device's copy to the vault. A failure keeps `profilePending` for the next unlock.
    func writeProfile() async {
        let name = settings.displayName
        let photo = settings.profilePhoto ?? Data()
        do {
            _ = try await write { try $0.setProfile(name: name, photo: photo) }
            // An edit made during the write keeps its own pending write.
            if settings.displayName == name, (settings.profilePhoto ?? Data()) == photo {
                settings.profilePending = false
            }
        } catch {
            Self.profileLog.error("account profile not written to the vault")
        }
        profileTask = nil
    }

    private func seedProfile() async {
        let name = settings.displayName
        let photo = settings.profilePhoto ?? Data()
        do {
            let profile = try await write { try $0.seedProfile(name: name, photo: photo) }
            profileTask = nil
            if let profile { adopt(profile) }
        } catch {
            Self.profileLog.error("account profile not seeded in the vault")
            profileTask = nil
        }
    }
}
