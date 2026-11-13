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
/// - The profile also names a main identity and a main credit card (`mainIdentity`, `mainCard`),
///   read from each snapshot (`profileMainIdentity`, `profileMainCard`).
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

    // MARK: Main identity and card

    /// The identity the Profile page and Home show first: the one the account profile names, else
    /// the first active Identity of the visible vaults by title (none chosen, or the chosen one gone,
    /// archived or trashed). Nil without any Identity.
    public var mainIdentity: FfiItemSummary? { mainItem(profileMainIdentity, of: .identity) }

    /// The payment card the Profile page shows first, as `mainIdentity` among the credit cards.
    public var mainCard: FfiItemSummary? { mainItem(profileMainCard, of: .creditCard) }

    /// Names the main identity of the account profile for every device (nil: none, the first by
    /// title then shows). The item must be an active Identity (`VaultError` otherwise).
    public func setMainIdentity(_ ref: (vaultID: String, itemID: String)?) async throws {
        try await setProfileMain(
            identity: ref.map { FfiItemRef(vaultId: $0.vaultID, itemId: $0.itemID) },
            card: chosen(profileMainCard, of: .creditCard)?.ref)
    }

    /// Names the main credit card of the account profile, as `setMainIdentity`.
    public func setMainCard(_ ref: (vaultID: String, itemID: String)?) async throws {
        try await setProfileMain(
            identity: chosen(profileMainIdentity, of: .identity)?.ref,
            card: ref.map { FfiItemRef(vaultId: $0.vaultID, itemId: $0.itemID) })
    }

    /// The chosen item if still active and visible, else the first of its type by title.
    private func mainItem(_ ref: FfiItemRef?, of type: FfiItemType) -> FfiItemSummary? {
        if let chosen = chosen(ref, of: type) { return chosen }
        return usableSummaries().filter { $0.itemType == type }.min(by: Self.titleFirst)
    }

    private func chosen(_ ref: FfiItemRef?, of type: FfiItemType) -> FfiItemSummary? {
        guard let ref else { return nil }
        return usableSummaries().first { $0.itemType == type && $0.id == ref.itemId && $0.vaultId == ref.vaultId }
    }

    /// Writes both choices, dated now, the name and photo kept. The other choice is passed only while
    /// its item is still there (the core refuses a gone one). An account with no profile in the vault
    /// yet first gets this device's copy as a seed, so the write does not publish an empty name.
    private func setProfileMain(identity: FfiItemRef?, card: FfiItemRef?) async throws {
        let name = settings.displayName
        let photo = settings.profilePhoto ?? Data()
        try await write { session in
            _ = try session.seedProfile(name: name, photo: photo)
            return try session.setProfileMain(identity: identity, card: card)
        }
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
