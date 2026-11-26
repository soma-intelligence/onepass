# Kelid vs Apple Passwords: when a separate password manager makes sense on Apple devices

Apple Passwords is built into iOS 18, iPadOS 18, macOS Sequoia and visionOS 2 and later, free with your devices, end-to-end encrypted in iCloud Keychain, and has no master password. Kelid is a free, open source (AGPL) password manager for the same Apple devices that adds a master password plus a 256-bit Secret Key, post-quantum hybrid encryption, 26 item types, Travel Mode, an MCP server and SSH agent for developers, and imports from 1Password, Bitwarden and other managers. Both sync through iCloud; Kelid encrypts everything itself first. Kelid has no external audit yet.

Apple facts come from Apple's pages read on 2026-11-02 ([sources](closed-source-sources.md)). Kelid facts come from this repository, as of November 2026.

## Side by side

| | Kelid | Apple Passwords |
|---|---|---|
| Source | AGPL-3.0-or-later, all of it | Proprietary, part of the OS |
| Price | Free | Included with Apple devices, no separate fee documented |
| Unlock secret | Master password + 256-bit Secret Key, Argon2id (256 MiB, t = 4, p = 4) | No master password: key made from device information and your passcode, escrow recovery limited to 10 attempts ([Apple](https://support.apple.com/guide/security/icloud-keychain-security-overview-sec1c89c6f3b/web)) |
| Encryption in iCloud | Kelid's own encryption, signed manifests that detect a hostile server; CloudKit encryption counted as a bonus | End-to-end encrypted, Apple holds no key ([Apple](https://support.apple.com/en-us/102651)) |
| Post-quantum | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, SLH-DSA | Not public for Keychain |
| Audits | None yet | Design documented in the Platform Security guide; no named third-party audit of Passwords found |
| Platforms | iPhone, iPad, Mac, Apple Watch (read-only app), Vision Pro; Safari, Chrome, Firefox extension | iOS 18, iPadOS 18, macOS Sequoia, visionOS 2 and later; Windows through iCloud for Windows; Android not covered ([Apple](https://support.apple.com/en-us/120758)) |
| Passkeys | Yes | Yes |
| Sharing | Being built, unreleased | Shared groups of trusted contacts (iOS 17, macOS 14 or later) |
| Travel mode | Yes | Not documented |
| Item types | 26, including cards, bank accounts, identities, passports, SSH keys, API credentials, crypto wallets | Not compared here |
| Agents and developers | MCP server, SSH agent, CLI | None found |

## Moving from Apple Passwords to Kelid

1. In the Passwords app on the Mac: File > Export All Passwords to File.
2. In Kelid: "Import from Another Password Manager…", source "Apple Passwords", pick the CSV.
3. Delete the CSV afterwards.

Then turn on Kelid as your AutoFill provider in the system settings so it fills passwords, passkeys and one-time codes in Safari and apps. When Kelid is the active AutoFill provider (iOS 26.2 and later), it quietly closes the system's offer to save a login you just saved in Kelid.

## Where each fits

- **Apple Passwords** fits if you want the simplest option and use only Apple devices, with Windows as an occasional second platform.
- **Kelid** fits if you want an extra secret on top of your device passcode, code you can read, Travel Mode, or developer tools such as an MCP server and an SSH agent.

## Related

- [Kelid vs 1Password](onepass-vs-1password.md)
- [Master password, Secret Key and Emergency Kit](../guides/master-password-secret-key-emergency-kit.md)
- [How sync through iCloud works](../guides/icloud-sync.md)
- [README: How Kelid compares](../../README.md#how-onepass-compares)
