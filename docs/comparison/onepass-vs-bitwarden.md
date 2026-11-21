# OnePass vs Bitwarden: two open source password managers compared

OnePass and Bitwarden are both open source password managers. OnePass (AGPL-3.0-or-later) targets Apple devices only, syncs through your own private iCloud, and uses post-quantum hybrid encryption; it is young and has no external audit. Bitwarden runs as a cloud service or self-hosted, and in the project's own 2026-10-28 desk review it scored ahead of OnePass on proof (tests, releases, maturity), while OnePass scored higher on design.

This page states only what this repository documents about Bitwarden, as of November 2026. For Bitwarden's current platforms, plans and prices, check Bitwarden's own site.

## Side by side

| | OnePass | Bitwarden |
|---|---|---|
| Type (README scoring table) | Cloud sync through CloudKit, Apple apps and extension | Cloud or self-host |
| Desk review, design /40 | 29 | 22 |
| Desk review, proof /15 | 5 | 9 |
| Total /55 | 34 | 31 |
| External audit | None yet, planned for milestone 8 | Check the vendor |
| Self-hosting | Not in a release; the mailbox server in `mailbox/` is work in progress | Yes, per the README table |
| Post-quantum public-key encryption | ML-KEM-1024 + X25519 hybrid | Not found in the 2026-10-28 review, where OnePass was the only one of 11 managers scored shipping it |
| Platforms | iPhone, iPad, Mac, Apple Watch, Vision Pro; Safari, Chrome, Firefox extension | Check the vendor |

The review scored OnePass from its code and the other 10 from public evidence, which favors products with years of public bug reports. It is a desk review rather than a penetration test. The README notes that KeePassXC, Bitwarden, Proton Pass, gopass and Passbolt are ahead of OnePass on proof.

## Moving from Bitwarden to OnePass

1. In Bitwarden: Tools > Export Vault, as **unencrypted** .json (or .csv).
2. In OnePass: "Import from Another Password Manager…", source "Bitwarden", pick the file. Or from the development CLI: `onepass import bitwarden.json --vault Personal`.
3. Delete the unencrypted export once the import is done.

A Bitwarden export marked `encrypted: true` is refused with a message asking for a plain export: OnePass never decrypts a third-party format. Details: [Import from another password manager](../guides/import-from-other-password-managers.md).

## Where each fits

- **OnePass** fits if you use only Apple devices and want post-quantum encryption, iCloud-based sync without a separate account server, and built-in MCP and SSH agent access.
- **Bitwarden** fits if you need self-hosting today, non-Apple platforms, or a longer public track record.

## Related

- [OnePass vs 1Password](onepass-vs-1password.md)
- [OnePass vs KeePassXC](onepass-vs-keepassxc.md)
- [OnePass vs Proton Pass](onepass-vs-proton-pass.md)
- [Can I self-host OnePass sync?](../guides/self-hosted-sync-server.md)
- [README: How OnePass compares](../../README.md#how-onepass-compares)
