import Foundation

/// This device's zone credential seeds (sharing spec 13.4), one per zone mailbox, in the Keychain
/// under `mailbox.zone.<mailbox id hex>`, readable after the first unlock (a background wake syncs
/// the zones before the user unlocks) and never synced off the device. The core caches a seed here
/// at each unlocked round and deletes it when the zone is left.
public final class ZoneSeedKeychain: FfiZoneSeedStore, @unchecked Sendable {
    public static func key(mailboxID: Data) -> String {
        "mailbox.zone.\(mailboxID.map { String(format: "%02x", $0) }.joined())"
    }

    private let keychain: any KeychainStore

    public init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    public func get(mailboxId: Data) -> Data? {
        try? keychain.read(Self.key(mailboxID: mailboxId))
    }

    public func put(mailboxId: Data, seed: Data) {
        // A failed write leaves the seed in the core's sealed store; the next unlocked round
        // writes it again.
        try? keychain.writeAfterFirstUnlock(Self.key(mailboxID: mailboxId), seed)
    }

    public func delete(mailboxId: Data) {
        try? keychain.delete(Self.key(mailboxID: mailboxId))
    }
}
