# Cleon vs KeePassXC: synced Apple app or local password file

KeePassXC is an open source desktop password manager that keeps your vault in a local file; in the Cleon project's own 2026-10-28 desk review it scored highest overall (39 of 55) and ahead of Cleon on proof. Cleon is an open source (AGPL) password manager for iPhone, iPad, Mac, Apple Watch and Vision Pro that syncs end to end encrypted through your private iCloud, with passkeys, AutoFill and post-quantum hybrid encryption; it tied KeePassXC on design (29 of 40) but has no external audit yet. To move, export from KeePassXC as KeePass 2 XML: Cleon does not read `.kdbx` files directly.

This page states only what this repository documents about KeePassXC, as of November 2026.

## Side by side

| | Cleon | KeePassXC |
|---|---|---|
| Type (README scoring table) | Cloud sync (CloudKit), Apple apps and extension | Local file, desktop |
| Desk review, design /40 | 29 | 29 |
| Desk review, proof /15 | 5 | 10 |
| Total /55 | 34 | 39 |
| Sync | Built in, through your private iCloud, with signed manifests that detect a hostile server | Check the vendor |
| Apple Watch, Vision Pro, iOS AutoFill | Yes | Check the vendor |
| Post-quantum public-key encryption | ML-KEM-1024 + X25519 hybrid | Not found in the 2026-10-28 review, where Cleon was the only one of 11 managers scored shipping it |
| Windows, Linux | No app (development CLI only on Linux) | Desktop app, per the README table type; check the vendor for platforms |

The review scored Cleon from its code and the other managers from public evidence. It is a desk review rather than a penetration test.

## Moving from KeePassXC (or KeePass) to Cleon

1. In KeePassXC or KeePass: File > Export as **KeePass 2 XML**.
2. In Cleon: "Import from Another Password Manager…", source "KeePass, KeePassXC", pick the XML file. Or with the development CLI: `onepass import vault.xml --format keepass-xml --dry-run`, then without `--dry-run`.
3. Delete the XML file once the import is done: it holds your passwords in clear.

A `.kdbx` file is recognized by its signature and refused with `KeePass KDBX is not supported: export as KeePass 2 XML`. The XML parser refuses entity expansion beyond predefined entities and caps depth at 256.

## Where each fits

- **KeePassXC** fits if you want a local file you control, desktop platforms, and a long public track record.
- **Cleon** fits if you want sync across iPhone, iPad, Mac and Apple Watch without managing a file, system AutoFill and passkeys on Apple devices, or post-quantum encryption.

## Related

- [Import from another password manager](../guides/import-from-other-password-managers.md)
- [Cleon vs Bitwarden](onepass-vs-bitwarden.md)
- [How sync through iCloud works](../guides/icloud-sync.md)
- [README: How Cleon compares](../../README.md#how-onepass-compares)
