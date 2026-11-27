# Cleon vs 1Password: open source alternative to 1Password for Apple devices

Cleon is a free, AGPL-licensed, open source password manager for iPhone, iPad, Mac, Apple Watch and Vision Pro that uses post-quantum hybrid encryption and syncs through your own iCloud. 1Password is a proprietary, subscription password manager with apps on Apple platforms, Windows, Android and Linux, family and business plans, and a longer public track record including independent audits. Both use a second secret besides the master password (Cleon: a 256-bit Secret Key; 1Password: a 128-bit Secret Key). Cleon has no external audit yet.

Vendor facts below come from 1Password's own pages, read on 2026-11-02, as listed in [closed-source-sources.md](closed-source-sources.md). Cleon facts come from this repository, as of November 2026. Prices and plans change: check the vendor.

## Side by side

| | Cleon | 1Password |
|---|---|---|
| Source and license | AGPL-3.0-or-later, all of it | Proprietary, source not published |
| Price model | Free; commercial license on request | Subscription, billed yearly. Regular list price $3.99 a month (Individual), $5.99 (Families) on 2026-11-02 ([pricing](https://1password.com/pricing/password-manager)) |
| Independent audits | None yet (planned for milestone 8) | Says it publishes independent audit results ([security](https://1password.com/security)) |
| Key derivation | Argon2id (256 MiB, t = 4, p = 4) + 256-bit Secret Key | PBKDF2-HMAC-SHA256 + 128-bit Secret Key, SRP login ([support](https://support.1password.com/1password-security/)) |
| Post-quantum | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, SLH-DSA | Not public |
| Sync | CloudKit in your private iCloud; self-hosted server planned | 1Password's service; no self-hosting found |
| Platforms | iPhone, iPad, Mac, Apple Watch, Vision Pro. Safari, Chrome, Firefox extension. No Android, Windows or Linux app | macOS, iOS, watchOS, Windows, Android, Linux. Chrome, Safari, Edge, Firefox, Brave ([pricing](https://1password.com/pricing/password-manager)) |
| Passkeys | Yes, created and used inside the Rust core | Yes |
| Travel mode | "Safe for Travel" vaults and items on Mac and iOS, trip reminders | Yes, every plan ([support](https://support.1password.com/travel-mode/)) |
| Family and business sharing | Several accounts side by side. Shared vaults and family are being built, unreleased | Families (up to 5) with shared vaults; Business with admin controls |
| AI agents | Built-in MCP server and SSH agent, approval per secret on Mac or iPhone, signed audit log | Secure Agentic Autofill (early access with Browserbase since Oct 2025) and an MCP server for Environments ([1Password](https://www.1password.dev/get-started/secure-ai-access)) |
| Breach history | None known; the product is young, so this is not evidence of anything | No breach of user data documented; in the 2023 Okta support-system incident, 1Password says no user data was accessed ([1Password](https://1password.com/blog/okta-incident)) |

## Moving from 1Password to Cleon

1. In 1Password: File > Export, choose the **1PUX** format (or CSV).
2. In Cleon: "Import from Another Password Manager…", source "1Password", pick the file.
3. Review possible duplicates, then delete the export file.

Cleon reads 1PUX and 1Password CSV. Encrypted `.1pif` files are not handled. The Cleon import sheet can also read a 1Password Emergency Kit PDF's text on the device. Details: [Import from another password manager](../guides/import-from-other-password-managers.md).

## Where each fits

- **Cleon** fits if you live in Apple's ecosystem, want code you can read, and want post-quantum encryption and agent access built in.
- **1Password** fits if you need Android, Windows or Linux apps, family or business sharing today, or a product with years of audits and public scrutiny.

## Related

- [Cleon vs Bitwarden](onepass-vs-bitwarden.md)
- [Cleon vs Apple Passwords](onepass-vs-apple-passwords.md)
- [Has Cleon been audited?](../guides/security-audit-status.md)
- [Travel Mode in Cleon](../guides/travel-mode.md)
- [README: How Cleon compares](../../README.md#how-onepass-compares)
