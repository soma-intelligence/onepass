# How Cleon syncs through iCloud, and what Apple can see

Cleon syncs your vault end to end encrypted through **CloudKit, in your own private iCloud database**. Each record is encrypted by the Cleon Rust core before it leaves the device, then stored by CloudKit in `encryptedValues`, so it is encrypted a second time by Apple; the threat model assumes Apple's layer fails and counts only Cleon's own encryption and signatures. There is no Cleon account server and no subscription for sync.

## What lands in iCloud

Private CloudKit database, zone `Cleon`, record type `OPRecord`. For each record:

| Field | Content |
|---|---|
| Record name | `"<type code>.<id hex>"` (type 1 to 6, opaque UUIDv7) |
| `kind`, `version` | In clear |
| `data` | The core's encrypted blob, inside CloudKit `encryptedValues` |
| System fields | Creation and modification dates, device, change tag |

Records over 900 KiB are refused by the Rust core before being written.

## What Apple (or anyone holding the iCloud data) learns

The number of items per vault, which vault each item belongs to, padded sizes, versions, manifest sequence numbers, plus the dates and rhythm of writes. It never reads a title, URL, item type, tag or any field value. Blob sizes are rounded up to tiers (256 bytes minimum, then powers of two up to 64 KiB, then multiples of 64 KiB).

## What happens if iCloud data is tampered with

Every vault has a signed, hash-chained manifest with a Merkle root, and each device pins the last manifest it saw. A replayed, forked, injected or dropped record is refused, and the app shows a "Data Refused" screen with the type of attack. The app never repairs storage by itself. Deletions coming from the server for the account parameters, keyset or a vault already seen are ignored and logged (Settings > Sync shows how many deletions from iCloud were refused, with the details).

## Conflicts between devices

Writes go to a local pending area and are sent with a conditional save (`ifServerRecordUnchanged`), ordered so a manifest never arrives before its items. If the server moved ahead, the vault is held back and rebased while unlocked: the newest `updated_at` wins per item, ties broken by hash byte order. A local deletion of an item edited elsewhere is dropped; a local edit of an item deleted elsewhere brings it back.

## Switching iCloud accounts

On the first sync the app records the CloudKit user id. If a different iCloud account signs in later, sync stops and the app says "The iCloud account changed" until you sign back in or explicitly choose to use the new account. A zone holding another Cleon account is refused.

## Building it yourself

CloudKit sync is compiled only into the signed `Release-CloudKit` configuration, which needs your own Apple Developer team and iCloud container. Unsigned builds run locally only. See [Build from source](../../README.md#build-from-source).

## Related

- [Can I self-host Cleon sync?](self-hosted-sync-server.md)
- [Cleon threat model](threat-model.md)
- [Add a new device](add-a-device.md)
- [README](../../README.md)
