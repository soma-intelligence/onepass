# How Cleon Travel Mode works before you cross a border

Travel Mode removes every vault you have not marked **"Safe for Travel"** from your iPhone, iPad or Mac before a border crossing, without deleting it from iCloud. Back home, you turn it off and the hidden vaults come back, checked against the last signed manifests the device saw, so a server cannot slip you an old or altered copy. Cleon can also plan ahead: add a trip and it reminds you, then offers or turns on Travel Mode during the trip.

## Turn it on

1. Mark the vaults you want to keep on the device as "Safe for Travel". Single items can be marked safe for travel too.
2. Turn on Travel Mode in Settings (Mac and iOS). The other vaults leave the device.
3. After the trip, turn off Travel Mode. The vaults are copied back and verified like any sync.

## Trips and suggestions

- Add a trip and Cleon reminds you the evening before ("Remember to turn on Travel Mode before the border.") and three hours before.
- At your first unlock during the trip, it offers or turns on Travel Mode.
- Away from home, the app suggests it ("Suggest Travel Mode" in Settings). An unusual time zone counts as a sign you've left.
- Watchtower flags a funded crypto wallet whose recovery phrase is not protected by Travel Mode.
- Travel Mode erases the local autofill history and records nothing while you travel.

## What happens under the hood

- **On:** each vault without `travel_safe` is loaded through the verified path. Before anything is deleted, the upstream copy must contain, byte for byte, every record of that verified state (key, metadata, manifest and listed items), so the only copy is never erased. Then local records are deleted and the database is compacted (`VACUUM`).
- **State:** the last manifests seen go into a `TravelState`: a fresh symmetric key wrapped to the account's hybrid ML-KEM-1024 + X25519 key, the state encrypted with AES-256-GCM-SIV, signed by the account key and padded to a fixed 65,536 bytes. It cannot be read or forged without the unlocked account.
- **Off:** records are copied back from the upstream, which is not trusted. Only items listed in the upstream manifest are copied, and a lower sequence number, a fork or a removed item is refused, with the local state restored exactly.

The account itself and travel-safe vaults are never touched.

## Limits the project documents

- The presence of the travel state file reveals that Travel Mode is on; its fixed size hides how many vaults are hidden.
- File system snapshots and Time Machine can keep older copies of the database: out of reach of any software.
- During travel, the MCP audit log and policy still name hidden vault ids (opaque ids, no names or content).

## With the development CLI

```bash
onepass vault create "Travel" --travel-safe
onepass travel push   --upstream upstream.db
onepass travel on     --upstream upstream.db
onepass travel status
onepass travel off    --upstream upstream.db
```

The CLI's upstream is a development SQLite file standing in for sync.

## Related

- [How sync through iCloud works](icloud-sync.md)
- [Cleon threat model](threat-model.md)
- [Cleon command line (CLI)](command-line-cli.md)
- [README](../../README.md)
