import Foundation

/// This device's mailbox credential seeds, one per mailbox, in the Keychain under
/// `mailbox.credential.<mailbox id hex>`, readable after the first unlock (a background wake syncs
/// before the user unlocks) and never synced off the device. A recovery credential's seed is never
/// stored here: it is derived from the Secret Key when needed, then wiped.
public struct MailboxCredentialStore: Sendable {
    public static func key(mailboxID: String) -> String { "mailbox.credential.\(mailboxID)" }

    private let keychain: any KeychainStore

    public init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    public func seed(mailboxID: String) throws -> SecretBytes? {
        try keychain.read(Self.key(mailboxID: mailboxID)).map { SecretBytes(copying: $0) }
    }

    public func store(seed: SecretBytes, mailboxID: String) throws {
        try seed.withData { try keychain.writeAfterFirstUnlock(Self.key(mailboxID: mailboxID), $0) }
    }

    public func delete(mailboxID: String) throws {
        try keychain.delete(Self.key(mailboxID: mailboxID))
    }
}
