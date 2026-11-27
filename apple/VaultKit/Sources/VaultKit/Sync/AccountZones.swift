import Foundation
import OnePassCore
import os

/// One open account's zone transport (sharing spec 13, decision 15): the core's `ZoneSyncHandle` on
/// this device's zone seeds (`ZoneSeedKeychain`), whose rounds the account's sync coordinator runs
/// after each private round, and whose `contact_zone_create` makes a contact pair's mailbox. Every
/// account reaches contacts and shared vaults through the hosted mailbox: an account that syncs
/// through a mailbox makes its zones under it (`useAccountMailbox`), any other (iCloud) gets an
/// anchor mailbox on the hosted server, made by the core on its first share.
public struct AccountZones: Sendable {
    public let handle: ZoneSyncHandle
    public let sync: FfiZoneSyncAdapter
    /// The hosted mailbox server (Info.plist `OnePassMailboxURL`): the anchor's and the invite drops'.
    public let hosted: URL

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "sharing")

    /// The zones of the account whose sync store is `store`; nil without a hosted server in this
    /// build (no `OnePassMailboxURL`).
    public static func make(
        store: SyncStoreHandle, keychain: any KeychainStore, hosted: URL? = MailboxEndpoints.hosted()
    ) -> AccountZones? {
        guard let hosted else { return nil }
        let handle = ZoneSyncHandle(seeds: ZoneSeedKeychain(keychain: keychain), defaultBaseUrl: hosted.absoluteString)
        return AccountZones(handle: handle, sync: FfiZoneSyncAdapter(handle: handle, store: store), hosted: hosted)
    }

    /// The account syncs through the mailbox `home`: new zones are made under it, with this
    /// device's manager credential. Without the credential (Keychain restored elsewhere) the zones
    /// fall back to the anchor and the log says so.
    public func useAccountMailbox(_ home: MailboxHome, keychain: any KeychainStore) {
        do {
            guard let seed = try MailboxCredentialStore(keychain: keychain).seed(mailboxID: home.mailboxID) else {
                Self.log.error("mailbox credential missing, zones on the anchor")
                return
            }
            defer { seed.wipe() }
            try seed.withData {
                try handle.setAccountMailbox(endpoint: home.endpoint, mailboxId: home.mailboxID, credentialSeed: $0)
            }
        } catch {
            Self.log.error("account mailbox not set on the zones")
        }
    }
}
