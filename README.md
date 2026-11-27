<div align="center">

<img src="docs/assets/brand/icon.svg" width="96" height="96" alt="Kelid app icon">

# Kelid

### Every password, one calm place.

Kelid is an open source, post-quantum password manager for iPhone, iPad, Mac, Apple Watch and Vision Pro that keeps your passwords, passkeys and 2FA codes end to end encrypted on your devices and in your own private iCloud.<br>
Free, AGPL-3.0-or-later, on the App Store, with every line of code public.

<br>

[![Download on the App Store](https://img.shields.io/badge/Download_on_the-App_Store-000000?style=for-the-badge&logo=apple&logoColor=white)](https://apps.apple.com/app/id6831411523)
&nbsp;
[![Join the TestFlight beta](https://img.shields.io/badge/Join_the-TestFlight_beta-0D96F6?style=for-the-badge&logo=apple&logoColor=white)](https://testflight.apple.com/join/MhmPEd7b)
&nbsp;
[![Website](https://img.shields.io/badge/Visit-somalabs.me%2Fonepass-5856D6?style=for-the-badge)](https://somalabs.me/onepass)

<br>

<img src="docs/assets/readme/hero-devices.jpg" width="100%" alt="Kelid on Mac, iPad, iPhone and Apple Watch, showing a fictional demo vault">

<br><br>

[![Core CI](https://img.shields.io/github/actions/workflow/status/soma-intelligence/onepass/core.yml?branch=main&label=core&logo=rust&logoColor=white)](https://github.com/soma-intelligence/onepass/actions/workflows/core.yml)
[![Extension CI](https://img.shields.io/github/actions/workflow/status/soma-intelligence/onepass/extension.yml?branch=main&label=extension&logo=typescript&logoColor=white)](https://github.com/soma-intelligence/onepass/actions/workflows/extension.yml)
[![Release](https://img.shields.io/github/v/release/soma-intelligence/onepass?include_prereleases&label=release&color=5856D6)](https://github.com/soma-intelligence/onepass/releases)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-5856D6)](LICENSE)
[![Stars](https://img.shields.io/github/stars/soma-intelligence/onepass?style=flat&color=5856D6&logo=github)](https://github.com/soma-intelligence/onepass/stargazers)
<br>
![Platforms](https://img.shields.io/badge/iOS%20·%20iPadOS%20·%20macOS%20·%20watchOS%20·%20visionOS-26%2B-1D1D2B?logo=apple&logoColor=white)
![Post-quantum](https://img.shields.io/badge/crypto-ML--KEM--1024%20·%20ML--DSA--87%20·%20SLH--DSA-1D1D2B)
![No tracking](https://img.shields.io/badge/analytics-none-1D1D2B)

**[Quick start](#quick-start)** · **[At a glance](#at-a-glance)** · **[Tour](#a-quick-tour)** · **[Why Kelid](#why-kelid)** · **[Features](#features)** · **[Security](#security-model)** · **[Compare](#how-kelid-compares)** · **[Install](#install)** · **[FAQ](#faq)** · **[Docs](#documentation)** · **[Build](#build-from-source)** · **[Roadmap](#roadmap)**

</div>

## Quick start

**Use the app** on iPhone, iPad, Mac, Apple Watch or Vision Pro:

1. Install Kelid from the [App Store](https://apps.apple.com/app/id6831411523). It's free.
2. Open it, choose **Create Vault** and pick a master password. Kelid makes your Secret Key and an Emergency Kit to keep.
3. On Home, tap **Turn On Kelid**. The next sign-in field you tap in Safari or an app offers your logins.

**Try the code** with Rust installed, no account needed:

```bash
git clone https://github.com/soma-intelligence/onepass.git && cd onepass
cargo run -q --manifest-path core/Cargo.toml -p onepass-cli -- generate --words 5
```

The second line builds the Rust core and prints a fresh five-word passphrase. Next steps: [Install](#install) for the extension and Mac builds, [Build from source](#build-from-source) for the apps.

> [!IMPORTANT]
> Kelid is on the App Store (version 1.0.2, November 2026) for iPhone, iPad, Apple Watch, Mac and Vision Pro. Its core **has not had an external security audit yet** (planned for milestone 8): the design, the formal models and the tests are public, but no outside firm has reviewed them. Weigh that before Kelid holds your only copy of a secret, and keep an encrypted export. The dev CLI and the dev native messaging host keep secrets in a form meant for development only: the apps are the way to use Kelid day to day.

## At a glance

| | |
|---|---|
| **What it is** | A password manager for Apple devices. 26 item types: logins (with passkeys and TOTP codes), cards, bank accounts, identities, passports, SSH keys, API credentials, secure notes and more |
| **License** | [AGPL-3.0-or-later](LICENSE), commercial license on request |
| **Platforms** | iOS, iPadOS, macOS, watchOS and visionOS 26 or later. Browser extension for Safari, Chrome and Firefox. No Android, Windows or Linux app |
| **Stack** | Rust core (`core/`), native SwiftUI apps (`apple/`, native on the Mac too, without Catalyst), TypeScript MV3 extension (`extension/`) |
| **Cryptography** | Argon2id + 256-bit Secret Key, AES-256-GCM-SIV, ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, SLH-DSA |
| **Sync** | End to end encrypted over CloudKit, in your private iCloud database. Self-hosted server planned |
| **Version** | 1.0.2 on the App Store (2026-11-21). Source, Mac direct download and CLI: `v0.3.0` (latest tag, `MARKETING_VERSION` in `apple/project.yml`) |
| **Install** | [App Store](https://apps.apple.com/app/id6831411523), [TestFlight](https://testflight.apple.com/join/MhmPEd7b) or [GitHub Releases](https://github.com/soma-intelligence/onepass/releases) (Mac) |
| **Audit status** | No external audit yet (planned for M8). [What exists instead](docs/guides/security-audit-status.md) |
| **Price** | Free. No subscription, no analytics, no telemetry |
| **Homepage** | [somalabs.me/onepass](https://somalabs.me/onepass) |
| **Maker** | [Soma Labs](https://somalabs.me) |

## A quick tour

<table>
<tr>
<td width="33%"><img src="docs/assets/readme/tour/iphone-01-home.jpg" alt="Home: every password, one calm place. Logins, cards and passkeys on every Apple device"></td>
<td width="33%"><img src="docs/assets/readme/tour/iphone-02-detail.jpg" alt="Sign in without the hunt: passwords and one-time codes fill in Safari and apps"></td>
<td width="33%"><img src="docs/assets/readme/tour/iphone-03-watchtower.jpg" alt="See what needs a fix: Watchtower flags weak and reused passwords"></td>
</tr>
<tr>
<td><img src="docs/assets/readme/tour/iphone-04-duplicates.jpg" alt="Tidy up duplicates: see what differs, then merge in one go"></td>
<td><img src="docs/assets/readme/tour/iphone-05-locked.jpg" alt="Yours alone, end to end: encrypted on your device and in your private iCloud"></td>
<td><img src="docs/assets/readme/tour/iphone-06-items.jpg" alt="Open source, top to bottom: read every line of the code that guards your vault"></td>
</tr>
</table>

<table>
<tr>
<td width="50%"><img src="docs/assets/readme/tour/mac-01-browse.jpg" alt="Kelid on the Mac: sidebar, item list and a login with its one-time code"></td>
<td width="50%"><img src="docs/assets/readme/tour/mac-02-watchtower.jpg" alt="Watchtower on the Mac: a score dial and one card per check"></td>
</tr>
<tr>
<td><img src="docs/assets/readme/tour/mac-03-duplicates.jpg" alt="Possible duplicates on the Mac, with the fields that differ side by side"></td>
<td><img src="docs/assets/readme/tour/mac-04-locked.jpg" alt="The locked Mac app, waiting for the master password"></td>
</tr>
</table>

<p align="center"><sub>Real captures of the apps, filled with a fictional demo vault. Native SwiftUI on every platform, Mac included (not Catalyst).</sub></p>

## Why Kelid

<table>
<tr>
<td width="33%" valign="top">

### 🔐 Post-quantum, today
Vault keys are wrapped with hybrid **ML-KEM-1024 + X25519**. Manifests and backups carry hybrid **ML-DSA-87 + Ed25519** signatures, and your account identity is an **SLH-DSA** key. Data harvested today stays safe against tomorrow's quantum computers.

</td>
<td width="33%" valign="top">

### 🛡️ The server is the adversary
Every vault carries a signed, hash-chained manifest with a Merkle root. A broken or malicious sync backend can't roll back, fork, inject, drop or swap items without the app noticing.

</td>
<td width="33%" valign="top">

### 🔑 Two secrets, not one
Your key comes from your master password **and** a 256-bit Secret Key made on your device. A stolen copy of the sync data is useless without both.

</td>
</tr>
<tr>
<td valign="top">

### ⚡ One gesture to sign in
Click the field, pick the account, you're in. One-click sign-in walks multi-step logins and "Sign in with Google, Apple, Microsoft or GitHub" chains, and one-time codes fill themselves.

</td>
<td valign="top">

### 🤖 Made for AI agents
An MCP server lets agents *use* a credential without ever *seeing* it. Every request asks you first, on the Mac or on your iPhone with Face ID, and lands in a signed audit log. An SSH agent asks before every signature.

</td>
<td valign="top">

### 🔍 Open and tested
AGPL, top to bottom. Fuzzing, NIST ACVP vectors, differential tests between two crypto libraries, ProVerif models and a seeded autofill lab that counts leaks. No analytics, no telemetry, no ads.

</td>
</tr>
</table>

## What's new

Shipped on `main` in November 2026:

- **One-gesture login.** From the browser extension, the in-field icon or iPhone AutoFill, one deliberate gesture ends with you signed in, plus one biometric approval when the vault is locked.
- **Two-factor setup in one click.** The extension finds a site's 2FA setup QR code on the page, decodes it locally, saves the secret on the login and fills the first code. The apps suggest it on every login whose site supports 2FA or passkeys.
- **A fresh look.** Every platform got the redesign: calmer colors that carry meaning, an item editor in cards, item headers tinted by the site's own color.
- **19,323 site icons** for 22,541 domains, bundled with the app and never fetched site by site, plus an icon library to pick your own.
- **Key usage log.** Each item shows where its secret was used: AutoFill, the CLI, the SSH agent or an AI agent through MCP. Synced and sealed like the item itself.
- **Travel Mode that plans ahead.** Add a trip and Kelid reminds you the evening before and three hours before, then offers or turns on Travel Mode at your first unlock during the trip. An unusual time zone counts as a sign you've left.
- **Duplicates review.** See which copies are safe to merge and which differ, field by field, then merge in one go.
- **Profile, account and security** in one place, with Delete My Account on iPhone, iPad, Mac and Vision Pro.
- **Encrypted attachments** on any item, with a built-in PDF reader.

## Features

<details open>
<summary><b>Vault and items</b></summary>

- 26 item types: logins, passwords, secure notes, credit cards, bank accounts, crypto wallets, identities, passports, driver licenses, SSH keys, API credentials, servers, databases, routers, software licenses, documents and more. Logins also hold passkeys and TOTP secrets. Crypto wallets show watch-only balances on iPhone and iPad, read from public addresses: the recovery phrase is never sent anywhere.
- Multiple vaults, fast search, favorites, TOTP codes, `onepass://vault/item/field` secret references.
- Password and passphrase generator (EFF word lists).
- Auto-lock, unlock with Face ID, Touch ID or Apple Watch on Mac. The master password is required again after a reboot or after 14 days.
- Home shows what matters now: Nearby items on a map, Favorites, Recents. Change your master password and delete empty vaults from Settings.
- Emergency Kit PDF with a QR code, generated on device.
- Personal and shared device modes.

</details>

<details>
<summary><b>Devices</b></summary>

- **Add a device from another one.** The new iPhone, iPad or Mac shows a QR code, renewed every 30 seconds. An unlocked iPhone or iPad scans it, both screens show the same 6-digit code, and you confirm with Face ID or your master password. Nothing leaves before both confirmations.
- **Signed device list** in Settings > Devices: rename, or remove a device. A removed device erases its data, Secret Key and biometric enrollment the next time it unlocks or syncs.
- **Public computer mode.** Lend a few items to a borrowed device for 15 to 60 minutes. The guest session lives in memory only, is read-only, and ends on expiry, from your phone, after 5 idle minutes or when the app leaves the screen.

</details>

<details>
<summary><b>Sync</b></summary>

- End-to-end encrypted sync over **CloudKit**, inside your private iCloud database. Apple's own encryption is a bonus, not a dependency: the threat model assumes it fails.
- Self-hosted server (Rust, Postgres + S3) planned after v1.

</details>

<details>
<summary><b>AutoFill and passkeys</b></summary>

- System AutoFill provider on iPhone, iPad and Mac: QuickType suggestions, one-time codes in verification fields, unlock right inside the AutoFill sheet.
- **Passkeys** created and used inside the Rust core. The private key never reaches Swift.
- Save new passwords and suggest strong ones (iOS 26.2+).

</details>

<details>
<summary><b>Browser extension</b></summary>

- Manifest V3, TypeScript, no framework, in the app's look, in French, English, Spanish and Italian.
- **Safari** extension built into the Mac app. **Chrome and Firefox** builds talk to the same app through its signed relay. One end-to-end encrypted, post-quantum channel. On the Mac that runs the app, the extension pairs on its own, with no code to type (real-browser check pending). "Unlock in Kelid" in the extension brings the app forward to unlock, even when it was closed.
- Inline menu under the focused field, keyboard included. **One-click sign-in** that walks multi-step logins and "Sign in with Google, Apple, Microsoft or GitHub" chains, remembers which provider account you use on each site, and stops as soon as a step leaves the allowed domains.
- Save and update prompts, never-save list, HTTPS origins only. Payment iframes from other sites are never filled.

</details>

<details>
<summary><b>Watchtower</b></summary>

- A score dial and one card per check: weak, reused and old passwords, sites that support 2FA or passkeys where you have not turned them on, breached sites, exposed accounts, and a funded crypto wallet whose recovery phrase is not protected by Travel Mode.
- Notifications for new findings, and per-item exclusions.
- Leaked password check through Have I Been Pwned **k-anonymity** (5-character hash prefix, padded responses). Offline modes available.

</details>

<details>
<summary><b>Import and export (21 formats)</b></summary>

| Source | Formats |
|---|---|
| 1Password | 1PUX, CSV |
| Bitwarden | JSON, CSV |
| Chrome, Safari, Firefox | CSV |
| LastPass | CSV |
| Dashlane | CSV, ZIP |
| Proton Pass | CSV |
| NordPass, Keeper, RoboForm | CSV |
| Enpass | JSON |
| KeePass 2 | XML |
| FIDO Credential Exchange | CXF |
| Other | `otpauth://` URIs, Wi-Fi QR codes, Kelid archive, Kelid CSV |

Export to a signed, encrypted `.onepass` archive (passphrase or account recipient). Plaintext CSV export exists but needs an explicit `--plaintext` flag.

</details>

<details>
<summary><b>Apple Watch, Vision Pro and widgets</b></summary>

- Standalone, read-only Watch app with TOTP rings, complications and Smart Stack. At most 50 items, and never login passwords, CVVs, PINs or notes.
- iOS widgets ("Codes", "Favorites"), Controls (generate, search, lock), App Intents and Shortcuts.
- visionOS layout from the same app target.

</details>

<details>
<summary><b>Developer tools</b></summary>

All in Settings > Developer on the Mac, and stopped as soon as the app locks (unless your iPhone unlocks it for agents, below).

- **MCP server**: AI clients launch `OnePass.app/Contents/Helpers/onepass-mcp` (a copyable `mcpServers` block is in the app). Scoped tools (`metadata`, `use`, `write`, `totp`, `reveal`), vaults exposed only if a signed policy lists them, per-client grants you can revoke. Commands run with secrets injected and masked in output. Every secret request asks you in a floating panel, with Touch ID.
- **Web fill for agents**: the `fill_in_browser` tool fills a login or a card into a Chromium page (Chrome, Edge, Brave, Arc through the extension, or any browser an agent drives over local CDP) and returns only the names of the fields filled, never a value. The `fill` scope is off by default: turn it on per vault in Settings > Developer, then tick "Web fill" in the client's menu. A login asks for a strong gesture the first time, then can stay approved for the same client, item, site and browser (once, 5, 15 or 60 minutes). A card asks every time, is never remembered and never submitted. A page script, or an agent that can run JS in the page or read the DOM over CDP, can read what was filled, so fill only browsers you trust.
- **Agent-ready MCP**: one command adds Kelid to an AI client, `OnePass.app/Contents/Helpers/onepass-mcp install --client claude-code|claude-desktop|codex|cursor` (`--dry-run` shows the diff, a backup is kept, only the `onepass` entry changes; Settings > Developer gives you the command to copy). Approve each request on the Mac panel or on your iPhone with Face ID, whichever answers first; the agent is told a 4-letter code to match on screen, and the audit log records where you approved. Away from a locked Mac, your iPhone can unlock it for agents only: the app's own screens stay locked, the window lasts 1 hour by default (15 minutes to 8 hours) and ends on sleep, lock or "Lock now" on the phone. Off by default, enrolled per Mac and iPhone pair.
- **SSH agent**: Ed25519, ECDSA P-256/384/521 and RSA 3072/4096 keys from your vaults, generated or imported in the app. Approval for every signature, or for 5, 15 or 60 minutes. Agent forwarding refused by default.
- **Audit log**: hash-chained and signed, readable in the app.
- **Travel Mode** (Mac and iOS): mark vaults "Safe for Travel", and the others leave the device before you cross a border without being deleted from iCloud. Back home, they come back and are checked against the last manifests seen. Away from home, the app suggests turning it on, and single items can be marked safe for travel.
- **`onepass` CLI** with `onepass mcp` and `onepass ssh-agent` for development and Linux.

</details>

<p align="center">
  <img alt="A terminal session: reading a secret by reference, a TOTP code, a passphrase and a Watchtower report" src="docs/assets/readme/terminal.svg" width="760">
</p>

## Use cases

- Use Kelid to keep passwords, passkeys and one-time codes for every site on iPhone, iPad, Mac, Apple Watch and Vision Pro, synced through your own iCloud.
- Use Kelid to move off 1Password, Bitwarden, LastPass, Dashlane, Proton Pass, Apple Passwords or KeePass ([import guide](docs/guides/import-from-other-password-managers.md)).
- Use Kelid to set up two-factor authentication on a site from its QR code and fill the first code ([how](docs/guides/two-factor-codes-totp.md)).
- Use Kelid to let Claude Code, Codex or Cursor run a command with an API key it never sees ([MCP guide](docs/guides/mcp-server-ai-agents.md)).
- Use Kelid as your SSH agent, with an approval for each signature ([SSH guide](docs/guides/ssh-agent.md)).
- Use Kelid to take sensitive vaults off your devices before a border crossing ([Travel Mode](docs/guides/travel-mode.md)).
- Use Kelid to find weak, reused and breached passwords without sending them anywhere ([Watchtower](docs/guides/breached-password-check.md)).

## How it works

1. **One Rust core does all the cryptography.** `core/onepass-core` derives keys, seals every item, signs manifests, parses imports, computes TOTP codes and passkey signatures. The apps call it through UniFFI bindings (`core/onepass-ffi`), so private keys and TOTP seeds never reach Swift.
2. **Native apps on top.** `apple/` holds one SwiftUI app for iPhone, iPad, Mac and Vision Pro, plus the Watch app, widgets, the AutoFill provider and the Safari extension. `VaultKit` wraps the core: session, sync, pairing, bridge.
3. **Sync stores only sealed blobs.** Records go to your private CloudKit database. Every vault carries a signed, hash-chained manifest, so the app detects any record the server drops, replays or forges.
4. **Browsers talk to the app, never to the vault.** The extension pairs with the Mac app over an ML-KEM-1024 + X25519 channel and asks only for what the current HTTPS page needs.
5. **Agents go through approvals.** The Mac app hosts an MCP server and an SSH agent (`onepass-mcp`, `onepass-ssh-agent`, `onepass-guard`) that ask you before every secret and write a signed audit log.

## Security model

The full whitepaper and threat model live in [`docs/security/README.md`](docs/security/README.md). The short version:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/keys-dark.svg">
  <img alt="Key hierarchy: master password and Secret Key go through Argon2id and HKDF to the Account Unlock Key, which seals the keyset, which wraps one key per vault, which wraps one key per item" src="docs/assets/readme/keys-light.svg" width="100%">
</picture>

```
argon2_out = Argon2id(password_nfc, salt, m = 256 MiB, t = 4, p = 4)
AUK        = HKDF-SHA256(salt, argon2_out || secret_key, "onepass/auk/v1")
```
The Argon2id parameters above are enforced floors. The Secret Key is 256 bits, shown as 53 base32 characters with a Luhn mod 32 check character.

### Primitives

| Purpose | Algorithm |
|---|---|
| Password hashing | Argon2id v1.3 |
| Key derivation | HKDF-SHA256 |
| Blob encryption | AES-256-GCM-SIV + HMAC-SHA256 key commitment, size-tier padding |
| Vault key wrapping | ML-KEM-1024 + X25519 hybrid KEM |
| Manifests, backups, MCP policy | ML-DSA-87 + Ed25519 hybrid signature (both must verify) |
| Account root identity | SLH-DSA-SHA2-256s (FIPS 205) |
| Biometric unlock | Secure Enclave P-256 key, ECIES (X9.63, SHA-256, AES-GCM) |
| Passkeys | ECDSA P-256 (ES256) |
| Extension channel | ML-KEM-1024 + X25519, AES-256-GCM per direction, SAS pairing |

Crypto comes from `aws-lc-rs`, `argon2` and `slh-dsa` in Rust, and from WebCrypto plus `@noble/post-quantum` and `@noble/curves` in the extension.

### Threat model in brief
- **In scope:** a malicious or compromised storage backend (CloudKit, a future server, the network, a stolen disk) that modifies, replays, deletes, reorders or injects records. Hostile web pages and compromised renderers. Untrusted AI agents talking to the MCP server.
- **Out of scope:** a device compromised at OS level (root, jailbreak). An attacker who reads process memory (secrets are zeroized, `mlock` is not implemented yet). Traffic analysis beyond size-tier padding.
- **Known gaps** are listed honestly in the security doc and in the design specs.

### How it is tested

| | |
|---|---|
| **Known answers** | NIST ACVP vectors for ML-KEM-1024, ML-DSA-87 and SLH-DSA |
| **Differential** | `aws-lc-rs` against `libcrux`, property tests on the AEAD |
| **Fuzzing** | 48 `cargo-fuzz` targets in `core/fuzz`, 20 of them run in CI on every push that touches `core/` |
| **Hostile server** | a malicious store test suite that replays every known server-side attack |
| **Formal models** | ProVerif (`formal/`) for account creation and unlock, vault manifests, the Emergency Kit and the extension bridge, including runs where one half of each hybrid KEM is broken. `make formal`, [results](docs/security/formal/results.md) |
| **Autofill lab** | hundreds of seeded, fictional websites served locally (`extension/lab/`). First 200-site run: 63.8% fill rate and **0 leaks** ([report](docs/lab/2026-10-26-autofill-lab-run.md)) |

Found a vulnerability? Please do not open a public issue. See [Reporting a vulnerability](#reporting-a-vulnerability).

## How Kelid compares

As of November 2026. Two honest caveats first.

- **Kelid is the youngest product in every table below, and the only one without an outside audit.** Its design is strong on paper and its proof is thin. The vendors below have years of public scrutiny, bug bounties, audits and real users. Kelid has none of those yet (an external audit is planned for M8).
- **Everything about other products comes from their own pages or from named reports, checked on 2026-11-02.** Each claim links to its source, and the full dated list is in [docs/comparison/closed-source-sources.md](docs/comparison/closed-source-sources.md). Where a vendor does not say, the cell says "not public" or "not found". That is not proof of absence. Prices and plans change: check the vendor before you buy. Product names are the property of their owners and are used here only to name them.

### Against open source managers

On 2026-10-28 Kelid was scored against 10 open source managers with one 11-point rubric: design (8 dimensions, out of 40) and proof, meaning tests, releases and maturity (3 dimensions, out of 15). **Kelid was scored from its code, the others from public evidence**, which favors products that have had years of public bug reports. It is a desk review, not a pentest.

| Product | Type | Design /40 | Proof /15 | Total /55 |
|---|---|---|---|---|
| KeePassXC | Local file, desktop | 29 | 10 | 39 |
| **Kelid v0.2.0** | Cloud sync (CloudKit), Apple and extension | **29** | **5** | **34** |
| [Proton Pass](https://proton.me/blog/pass-open-source-security-audit) | Cloud | 24 | 9 | 33 |
| AliasVault | Cloud or self-host | 26 | 6 | 32 |
| Bitwarden | Cloud or self-host | 22 | 9 | 31 |
| gopass | Git and GPG or age | 21 | 10 | 31 |
| Passbolt | Self-host, teams | 21 | 9 | 30 |
| KeePassDX | Local file, Android | 24 | 6 | 30 |
| Psono | Self-host, teams | 21 | 8 | 29 |
| Vaultwarden | Bitwarden server, self-host | 20 | 8 | 28 |
| Strongbox | Local file, Apple | 24 | 4 | 28 |

Kelid ties for first on design and is second to last on proof. It is the only one of the 11 scored shipping hybrid post-quantum public-key encryption, and its KDF default is the strongest found. Proton Pass is open source with published audits ([Cure53, 2023](https://proton.me/blog/pass-open-source-security-audit), [Recurity Labs, Jan to Apr 2026](https://proton.me/business/pass/security)), wraps keys with bcrypt ([Proton](https://proton.me/blog/proton-pass-security-model)), and since 2026-05-21 offers read-only, vault-scoped [access tokens for AI agents](https://proton.me/blog/pass-access-tokens). KeePassXC, Bitwarden, Proton Pass, gopass and Passbolt are ahead of it on proof.

### Against closed source managers

<details>
<summary><b>1Password, NordPass, Dashlane, Keeper, LastPass and Apple Passwords, side by side</b></summary>


"Closed source" here means the vendor does not publish the source of its apps and servers. None of the vendor pages reviewed link to any, so "not published" rests on that absence.

#### Trust and cryptography

| | Source and license | Independent audits | Key derivation, Secret Key | Zero-knowledge | Post-quantum |
|---|---|---|---|---|---|
| **Kelid** | AGPL-3.0-or-later, all of it | None yet. Own desk review (2026-10-28), ProVerif models, 19 fuzz targets, NIST ACVP vectors | Argon2id (256 MiB, t=4, p=4) + 256-bit Secret Key | Yes, end to end. Signed, hash-chained manifests detect a hostile server | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, SLH-DSA |
| 1Password | Proprietary, source not published | Says it publishes independent audit results ([security][1p-sec]) | PBKDF2-HMAC-SHA256 + 128-bit Secret Key, SRP login ([support][1p-support]) | Not named on the page, but the account password is never shared ([support][1p-support]) | Not public |
| NordPass | Proprietary, source not published | Says Cure53 audited it, first in March 2020, and that Business holds ISO 27001 and SOC 2 Type 2 ([NordPass][np-sec]). Reports not retrieved | Argon2id, XChaCha20-Poly1305. No Secret Key described ([NordPass][np-sec]) | Claimed ([NordPass][np-sec]) | Not public |
| Dashlane | Proprietary, source not published | No independent audit report found | Argon2d (3 iterations, 32 MB, 2 threads), AES-256-CBC + HMAC-SHA256. No Secret Key ([Dashlane][dl-sec]) | Claimed ([Dashlane][dl-sec]) | Prototype only, not shipped ([Dashlane][dl-pq], 2022, updated 2024) |
| Keeper | Proprietary, source not published | Third-party pen tests (NCC Group, Cybertest), reports to business customers under NDA. SOC 2 Type 2, ISO 27001 and FedRAMP High claimed ([Keeper][kp-sec], [docs][kp-model]) | PBKDF2, 1,000,000 iterations, AES-256-GCM per-record keys. No Secret Key ([Keeper docs][kp-model]) | Claimed ([Keeper][kp-sec]) | Not public |
| LastPass | Proprietary, source not published | SOC 2 and ISO 27001/27701 control audits, zero findings per [LastPass][lp-news]. No published cryptographic audit found | PBKDF2-SHA256, 600,000 iterations by default, up to 1,000,000. No Secret Key. Argon2 and AES-GCM are in rollout ([LastPass][lp-zk], [bulletin][lp-support]) | Claimed ([LastPass][lp-zk]) | Not public |
| Apple Passwords | Proprietary, part of the OS | Design documented in the [Platform Security guide][ap-sec]. No named third-party audit of Passwords found | No master password: key made from device information and your passcode, escrow recovery limited to 10 attempts ([Apple][ap-sec]) | End-to-end encrypted, Apple holds no key ([Apple][ap-e2e]) | Not public for Keychain |

#### Platforms and features

| | Self-hosting | Platforms | Passkeys | Travel mode | Family and business sharing | Agent and MCP access |
|---|---|---|---|---|---|---|
| **Kelid** | Planned after v1. Today sync is CloudKit in your own iCloud | iPhone, iPad, Mac, Apple Watch, Vision Pro. Safari, Chrome and Firefox extension. CLI (development). **No Android, Windows or Linux app** | Yes, created and used inside the Rust core | "Safe for Travel" vaults and items on Mac and iOS, with a suggestion when you are away from home | Several accounts side by side (personal and business). **Being built, not in a release yet:** shared vaults, family, mailbox for invites. No business admin console | Built in: MCP server and SSH agent, per-secret approval on Mac or iPhone, signed audit log |
| 1Password | Not offered, none found | macOS, iOS, watchOS, Windows, Android, Linux. Chrome, Safari, Edge, Firefox, Brave ([pricing][1p-price]) | Yes ([pricing][1p-price]) | Yes, every plan ([support][1p-travel]) | Families (up to 5) with shared vaults. Business with admin controls ([pricing][1p-price], [travel][1p-travel]) | Secure Agentic Autofill, early access with Browserbase since Oct 2025, and an MCP server for Environments ([1Password][1p-ai]) |
| NordPass | Not offered, none found | Windows, macOS, Linux, iOS, Android and browsers ([NordPass][np-pass]) | Yes ([NordPass][np-pass]) | Not documented | Family (6 vaults) with sharing and emergency access. Business plan ([NordPass][np-pass]) | None found |
| Dashlane | Not offered, none found | iOS, Android, Windows, macOS. Linux only through the browser extension ([Dashlane][dl-pass]) | Yes ([Dashlane][dl-pass]) | Not documented | Friends and Family (10 members). Business with SSO and SCIM ([Dashlane][dl-plans], [business][dl-biz]) | Official MCP server (beta) for Business audit logs, read only. No credential access documented ([Dashlane][dl-mcp]) |
| Keeper | Not offered for the vault, none found | Not checked | Yes ([Keeper][kp-fam]) | Not documented | Family (up to 5, separate vaults). Business ([Keeper][kp-fam]) | Secrets Manager MCP server with confirmation prompts, and Agent Kit for coding agents (May 2026) ([Keeper docs][kp-mcp]) |
| LastPass | Not offered, none found | Not checked | Yes on individual plans ([LastPass][lp-price]) | Not documented | Families plan (includes Premium features). Business ([LastPass][lp-price]) | None official found |
| Apple Passwords | No | iOS 18, iPadOS 18, macOS Sequoia, visionOS 2 and later. Windows through iCloud for Windows with Chrome, Edge or Firefox extension. Android not covered ([Apple][ap-pw], [Windows][ap-win]) | Yes ([Apple][ap-pw]) | Not documented | Shared groups of trusted contacts, iOS 17 and macOS 14 or later ([Apple][ap-pw]). No business offering documented | None found |

#### Price and track record

| | Price model | Breach history |
|---|---|---|
| **Kelid** | Free, AGPL. No subscription and no hosted service to pay for. A commercial license is available on request | None known. The product is young, so this is not evidence of anything |
| 1Password | Subscription, billed yearly. Regular list price $3.99 a month (Individual) and $5.99 (Families) on 2026-11-02, with first-year promotions ([pricing][1p-price]) | No breach of user data documented. In the 2023 Okta support-system incident, 1Password says no user data was accessed ([1Password][1p-okta]) |
| NordPass | Subscription with a free tier. Current prices not retrieved, check the [plans page](https://nordpass.com/plans/) | None found in the sources reviewed |
| Dashlane | Subscription, annual billing only, no monthly plans ([Dashlane][dl-plans]) | Security advisory on its support site: a brute-force attack let an attacker register a device on fewer than 20 personal accounts and download their encrypted vaults, which stayed encrypted ([Dashlane][dl-adv]). Date not retrieved |
| Keeper | Subscription with a free tier of 10 items on one mobile device ([Keeper][kp-fam]) | None found in the sources reviewed |
| LastPass | Subscription, and its free plan has been restricted over time ([LastPass blog][lp-free], [pricing][lp-price]) | **2022 breach, documented:** attackers took source code, then copies of cloud backups from five dates in Aug and Sep 2022. Vault fields such as passwords were encrypted, website URLs were not ([Schneier][lp-sch], [Help Net Security][lp-hns], [Wikipedia][lp-wiki]) |
| Apple Passwords | Included with Apple devices, no separate fee documented | None found for iCloud Keychain |

#### Where each choice fits

- **Pick Kelid if** you live in Apple's ecosystem, want a password manager whose code you and others can read, and want post-quantum encryption and agent access built in. Wait if you need proof from outside: it has no external audit yet, no family sharing in a release, no Android or Windows app and no self-hosted server.
- **Pick 1Password, NordPass, Dashlane or Keeper if** you need Android, Windows or Linux apps, family or business sharing today, and a longer track record. The tables above show how they differ on the points that can be checked.
- **Pick Apple Passwords if** you want the simplest option and only use Apple devices, with Windows as an occasional second platform.
- **Pick LastPass with care.** The 2022 breach is documented, and the vendor has since raised its iteration defaults ([LastPass][lp-support]).

</details>

One page per alternative, with how to move your data: [Kelid vs 1Password](docs/comparison/onepass-vs-1password.md) · [vs Bitwarden](docs/comparison/onepass-vs-bitwarden.md) · [vs Apple Passwords](docs/comparison/onepass-vs-apple-passwords.md) · [vs KeePassXC](docs/comparison/onepass-vs-keepassxc.md) · [vs Proton Pass](docs/comparison/onepass-vs-proton-pass.md).

Spot an error or an out-of-date claim? Open an issue with a link to the vendor's page and we will correct it.

[1p-sec]: https://1password.com/security
[1p-support]: https://support.1password.com/1password-security/
[1p-price]: https://1password.com/pricing/password-manager
[1p-travel]: https://support.1password.com/travel-mode/
[1p-ai]: https://www.1password.dev/get-started/secure-ai-access
[1p-okta]: https://1password.com/blog/okta-incident
[np-sec]: https://nordpass.com/security/
[np-pass]: https://nordpass.com/family-password-manager/
[dl-sec]: https://www.dashlane.com/security
[dl-pq]: https://www.dashlane.com/blog/preparing-for-the-quantum-world
[dl-pass]: https://support.dashlane.com/hc/en-us/articles/32830330815762-Create-and-save-a-passkey-using-Dashlane
[dl-plans]: https://support.dashlane.com/hc/en-us/articles/360001166969-Compare-Dashlane-personal-plans
[dl-biz]: https://www.dashlane.com/pricing
[dl-mcp]: https://www.dashlane.com/blog/mcp-server-audit-log-access
[dl-adv]: https://support.dashlane.com/hc/en-us/articles/36038764990866-Security-advisory-Brute-force-attack-on-Dashlane-user-accounts
[kp-sec]: https://www.keepersecurity.com/security.html
[kp-model]: https://docs.keeper.io/enterprise-guide/keeper-encryption-model
[kp-fam]: https://www.keepersecurity.com/pricing/personal-and-family.html
[kp-mcp]: https://docs.keeper.io/en/keeperpam/secrets-manager/integrations/model-context-protocol-mcp-for-ai-agents
[lp-zk]: https://www.lastpass.com/security/zero-knowledge-security
[lp-support]: https://support.lastpass.com/help/what-have-we-done-to-ensure-lastpass-is-safe-to-use
[lp-news]: https://www.lastpass.com/company/newsroom/da86056a-167c-4e6f-a506-b99d07c30501
[lp-price]: https://www.lastpass.com/pricing
[lp-free]: https://blog.lastpass.com/posts/changes-to-lastpass-free
[lp-sch]: https://www.schneier.com/blog/archives/2022/12/lastpass-breach.html
[lp-hns]: https://www.helpnetsecurity.com/?p=251654
[lp-wiki]: https://en.wikipedia.org/wiki/2022_LastPass_data_breach
[ap-sec]: https://support.apple.com/guide/security/icloud-keychain-security-overview-sec1c89c6f3b/web
[ap-e2e]: https://support.apple.com/en-us/102651
[ap-pw]: https://support.apple.com/en-us/120758
[ap-win]: https://support.apple.com/guide/icloud-windows/set-up-icloud-passwords-icw2babf5e03/icloud

## Privacy

Kelid has no analytics and no telemetry. The Mac app's update check is the one request it makes to GitHub: at launch and every 24 hours it reads the signed update feed of the latest release on GitHub. That is a plain HTTPS GET to `github.com` (redirected to GitHub's release storage) with the usual User-Agent (app name and version, Sparkle version), and nothing else: no account, device or install identifier, no system profile, no cookie. Settings > About > "Automatically Check for Updates" turns it off. The iPhone, iPad, Apple Watch and Vision Pro apps update through the App Store and never check on their own.

Autofill history stays on the device. To put the account you use on a site first, Kelid remembers which suggestion you picked, on which site, in which browser (Safari, Chrome and others) and in which browser profile. A profile is an opaque random id the extension draws once and keeps in that profile's own storage: browsers do not give extensions the profile name. Only item ids, the site, the browser kind, the rank and the time are kept, never a password, username or any other field value. Each event is sealed with a key derived from your account key (AES-256-GCM-SIV) and filed under a keyed hash of the site, in the vault database of that device. It is never synced, never sent to a server and never reaches any analytics service. Events older than 180 days go, with at most 200 per site and 5000 in all. Settings > AutoFill > "Learn from my choices" turns it off and erases it, the button under it clears it, "Forget site" erases that site's events, and Travel Mode erases all of them and records nothing while you travel.

Crypto balances are off by default. Once you turn them on, the iPhone and iPad apps send your wallets' public addresses to the blockchain explorers you pick (mempool.space, PublicNode and the Solana Foundation by default, or your own), and ask CoinGecko for prices unless you turn prices off. Those services see your addresses and your IP address. The recovery phrase and private keys never leave the device.

## Install

| Platform | Where |
|---|---|
| iPhone, iPad, Apple Watch, Mac, Vision Pro | [App Store](https://apps.apple.com/app/id6831411523), free |
| Same, newest builds first | [TestFlight public beta](https://testflight.apple.com/join/MhmPEd7b) |
| Mac (direct download, self-updating) | [Releases](https://github.com/soma-intelligence/onepass/releases) |
| Chrome, Firefox | From a clone, see below. Chrome Web Store listing pending |

Website: [somalabs.me/onepass](https://somalabs.me/onepass) · [Privacy policy](https://somalabs.me/onepass/privacy)

Pre-release Mac builds are on the [Releases](https://github.com/soma-intelligence/onepass/releases) page: a notarized Mac app (`Kelid-<version>-mac.zip`), the Chrome extension, and `SHA256SUMS`. Move Kelid to Applications, open it once, then turn the extension on in Safari > Settings > Extensions. The Mac app then updates itself from the latest release (Kelid > Check for Updates…): an update installs only with your approval, and only if its archive and feed carry the release key's EdDSA signature and the app is signed by the same Apple team ([details](docs/security/release-pipeline.md#mises-à-jour-de-lapp-mac)).

For Chrome or Firefox, point the browser at the app's relay from a clone of this repository:
```bash
node extension/scripts/install-app-host.mjs --app /Applications/OnePass.app --browser firefox
```
Chrome pairing needs the extension's ID in the app's allow list (`ONEPASS_BROWSER_EXTENSIONS` in `apple/project.yml`) until the Web Store listing is live.

## Build from source

### Requirements

| Component | Needs |
|---|---|
| Rust core and CLI | Rust 1.99.1 (pinned in `core/rust-toolchain.toml`), nightly + `cargo-fuzz` for fuzzing |
| Apple apps | macOS with Xcode 27, XcodeGen (`brew install xcodegen`), watchOS 27 and visionOS 27 simulator runtimes |
| Extension | Node 22, plus `cargo`, `openssl` and Playwright Chromium for end-to-end tests |

Apps target iOS 26, iPadOS 26, macOS 26, watchOS 26 and visionOS 26 or later.

### Clone
```bash
git clone https://github.com/soma-intelligence/onepass.git
```

### Core and CLI
```bash
make -C core check
```
Runs `cargo fmt --check`, `clippy -D warnings`, the full test suite and `cargo deny`.

Try the CLI (dev mode, not for real secrets):
```bash
cargo run --manifest-path core/Cargo.toml -p onepass-cli -- --help
```
```bash
onepass account create
onepass item create login --title "Example" --field username=alice --field password=hunter2
onepass item get "Example" --reveal
onepass read "onepass://Personnel/Example/password"
onepass totp "Example"
onepass generate --words 5
onepass import export.1pux --dry-run
onepass watchtower
onepass backup create --out vault.onepass --passphrase
```

### Apple apps
Add the Rust targets once:
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-watchos aarch64-apple-watchos-sim aarch64-apple-visionos aarch64-apple-visionos-sim
```
Build the Rust XCFramework and Swift bindings, then the apps:
```bash
make -C apple core
```
```bash
make -C apple build-mac
```
Other targets: `build-ios`, `build-watch`, `build-vision`, `test`, `uitest`, `uitest-autofill`, `screenshots`. The Xcode project is generated from `apple/project.yml` with `make -C apple project`. More in [`apple/README.md`](apple/README.md).

CloudKit sync is only compiled into the signed `Release-CloudKit` configuration, which needs your own Apple Developer team and iCloud container.

### Browser extension
```bash
cd extension && npm ci && npm run check
```
`npm run check` typechecks, runs the unit tests and builds every browser. End-to-end tests run with `npm run e2e`, and the autofill lab with `npm run lab:smoke`. More in [`extension/README.md`](extension/README.md).

## Repository layout

```
onepass/
├── core/                      Rust workspace
│   ├── onepass-core           crypto, accounts, vaults, items, sync, TOTP, import/export,
│   │                          Watchtower, passkeys
│   ├── onepass-cli            the `onepass` command line
│   ├── onepass-ffi            UniFFI bindings for Swift
│   ├── onepass-guard          approvals, signed config, chained audit log
│   ├── onepass-mcp            MCP server
│   ├── onepass-ssh-agent      SSH agent
│   ├── onepass-bridge         extension ↔ app protocol and host connection loop
│   ├── onepass-relay          bridge socket rendezvous, and the relay Chrome and Firefox launch
│   ├── onepass-mcp-relay      the `onepass-mcp` relay between an MCP client and the Mac app
│   ├── onepass-native-host    native messaging host (development only)
│   ├── onepass-peer           checks which local process is calling (code signature, hardened runtime)
│   ├── onepass-sync, onepass-mailbox  sync driver and client of the mailbox server
│   ├── onepass-wifi           Wi-Fi networks of the vault on Windows and Linux
│   └── fuzz/                  cargo-fuzz targets
├── apple/                     SwiftUI apps (XcodeGen)
│   ├── VaultKit               Swift package over the Rust core: session, sync, pairing, bridge
│   ├── DesignKit              colors, icons, motion, shared components
│   ├── CompanionKit           widgets and iPhone ↔ Watch link
│   ├── App/                   iOS, iPadOS, macOS and visionOS app (Browse, Pairing, Developer, …)
│   ├── AutoFill/              system AutoFill provider
│   ├── SafariExtension/       Safari Web Extension shipped inside the Mac app
│   └── Watch/, Widgets/, …    Apple Watch app, widgets, Controls
├── extension/                 MV3 browser extension (TypeScript, esbuild)
│   ├── src/                   background, content scripts, bridge, UI
│   ├── e2e/                   Playwright tests
│   └── lab/                   seeded autofill lab
├── mailbox/                   sync server on Supabase (work in progress, self-hostable)
├── android/                   Android groundwork: core bindings and Wi-Fi, no app yet
├── formal/                    ProVerif models of the protocols
└── docs/
    ├── security/              whitepaper and threat model
    ├── specs/                 design specs per milestone
    ├── guides/                one-question how-to pages
    ├── comparison/            Kelid against named alternatives
    └── lab/                   autofill lab reports
```

## Roadmap

| | Milestone | Scope | Status |
|:-:|---|---|---|
| ✅ | M1 | Rust core, crypto, 26 item types, dev CLI | Done |
| ✅ | M2 | Apple apps, unlock, CloudKit sync | Done (real iCloud verification pending) |
| ✅ | M3 | System AutoFill, passkeys, one-time codes | Done |
| ✅ | M4 | Browser extension, encrypted native messaging | Done, served by the Mac app (Chrome Web Store listing pending) |
| ✅ | M5 | Watchtower, import, export, signed backups | Done |
| ✅ | M6 | Apple Watch, Vision Pro, widgets, Shortcuts | Done |
| ✅ | M7 | MCP server, SSH agent, Travel Mode | Done, in the Mac app |
| ✅ | M2b | QR device linking, signed device list, revocation, public computer mode | Done, in the apps (two-device iCloud verification pending) |
| ✅ | Agent-ready | Approval on iPhone, remote unlock for agents, one-command install in MCP clients | Done (real device and CloudKit verification pending) |
| ⬜ | M8 | External audit, public launch | Planned |
| 🟡 | Sharing | Multiple accounts, contacts, shared vaults, family, invite mailbox | Multiple accounts done. Sharing being built |
| ⬜ | Later | Self-hosted server, organizations, web app (WASM), recovery codes | Planned |

Each milestone has its design spec in [`docs/specs/`](docs/specs/).

## FAQ

**Is Kelid free?**
Yes. The apps are free on the App Store, with no subscription, no hosted service to pay for and no ads. The code is AGPL-3.0-or-later; a commercial license is available on request.

**Is Kelid open source?**
Yes, all of it: the Rust core, the Apple apps, the browser extension, the sync server and the formal models are in this repository under AGPL-3.0-or-later.

**Is Kelid a good open source alternative to 1Password?**
For Apple-only users, it covers the same core jobs (passwords, passkeys, TOTP, AutoFill, Watchtower, Travel Mode) and adds post-quantum encryption and agent access. It lacks Android, Windows and Linux apps, family sharing in a release, and an external audit. See [Kelid vs 1Password](docs/comparison/onepass-vs-1password.md).

**Has Kelid been audited?**
Not yet. An external audit is planned for milestone 8. The whitepaper, ProVerif models, fuzzing and test vectors are public. See [audit status](docs/guides/security-audit-status.md).

**What post-quantum algorithms does Kelid use?**
ML-KEM-1024 + X25519 to wrap vault keys, ML-DSA-87 + Ed25519 to sign manifests and backups, and SLH-DSA-SHA2-256s for the account identity. See [post-quantum cryptography](docs/guides/post-quantum-encryption.md).

**Does Kelid work on Android, Windows or Linux?**
No app yet. Chrome and Firefox extensions work with the Mac app, and a development CLI runs on Linux. See [platform status](docs/guides/android-windows-linux.md).

**Where is my data stored?**
On your devices and, encrypted by Kelid before upload, in your own private iCloud database (CloudKit). There is no Kelid account server. See [iCloud sync](docs/guides/icloud-sync.md).

**Can I self-host Kelid?**
Not in a released app yet. The sync server for that work (`mailbox/`, on Supabase) is in the repository with self-hosting steps, and the roadmap lists a self-hosted server as planned. See [self-hosting](docs/guides/self-hosted-sync-server.md).

**Does Kelid support passkeys?**
Yes, in AutoFill on iPhone, iPad and Mac and in the browser extension. Private keys are created and used inside the Rust core. See [passkeys](docs/guides/passkeys.md).

**How do I import from 1Password, Bitwarden or LastPass?**
Export from the old manager, then use "Import from Another Password Manager…" in Kelid. It reads 21 formats, including 1PUX, Bitwarden JSON, LastPass CSV and KeePass 2 XML. See the [import guide](docs/guides/import-from-other-password-managers.md).

**What happens if I forget my master password?**
You need both your master password and your Secret Key (on your Emergency Kit) to unlock. The repository documents no recovery without them for a personal account; recovery codes are on the roadmap. See [master password and Secret Key](docs/guides/master-password-secret-key-emergency-kit.md).

**Can AI agents use my passwords safely?**
Through the built-in MCP server, an agent can run a command or fill a form with a secret without seeing it, only in vaults you expose, and only after you approve each request on the Mac or iPhone. See the [MCP guide](docs/guides/mcp-server-ai-agents.md).

**Does Kelid collect analytics?**
No analytics and no telemetry. The Mac app checks GitHub for its signed update feed (you can turn that off). The [Privacy](#privacy) section describes what leaves the device.

**How do I verify a download?**
Check `SHA256SUMS`, then the SLSA provenance with `gh attestation verify`, and for the Mac app its notarization. See [verify a download](docs/guides/verify-a-download.md).

## Documentation

**Guides** (one question per page)

| Topic | Guide |
|---|---|
| Getting started | [Import from another password manager](docs/guides/import-from-other-password-managers.md) · [Add a new device](docs/guides/add-a-device.md) · [Export or back up a vault](docs/guides/export-and-backup.md) |
| Everyday use | [Passkeys](docs/guides/passkeys.md) · [2FA codes and QR setup](docs/guides/two-factor-codes-totp.md) · [Browser extension](docs/guides/browser-extension.md) · [Watchtower and breached passwords](docs/guides/breached-password-check.md) · [Travel Mode](docs/guides/travel-mode.md) · [Apple Watch, Vision Pro, widgets](docs/guides/apple-watch-vision-pro-widgets.md) |
| Developers | [MCP server for AI agents](docs/guides/mcp-server-ai-agents.md) · [SSH agent](docs/guides/ssh-agent.md) · [Command line](docs/guides/command-line-cli.md) |
| Security | [Threat model](docs/guides/threat-model.md) · [Post-quantum cryptography](docs/guides/post-quantum-encryption.md) · [Master password, Secret Key, Emergency Kit](docs/guides/master-password-secret-key-emergency-kit.md) · [Audit status](docs/guides/security-audit-status.md) · [Verify a download](docs/guides/verify-a-download.md) |
| Sync and platforms | [iCloud sync](docs/guides/icloud-sync.md) · [Self-hosting](docs/guides/self-hosted-sync-server.md) · [Android, Windows, Linux](docs/guides/android-windows-linux.md) |

**Comparisons:** [vs 1Password](docs/comparison/onepass-vs-1password.md) · [vs Bitwarden](docs/comparison/onepass-vs-bitwarden.md) · [vs Apple Passwords](docs/comparison/onepass-vs-apple-passwords.md) · [vs KeePassXC](docs/comparison/onepass-vs-keepassxc.md) · [vs Proton Pass](docs/comparison/onepass-vs-proton-pass.md) · [sources for the closed source table](docs/comparison/closed-source-sources.md)

**Reference** (several in French): [security whitepaper and threat model](docs/security/README.md) · [crypto review](docs/security/crypto-review.md) · [formal model results](docs/security/formal/results.md) · [release pipeline](docs/security/release-pipeline.md) · [reproducible builds](docs/security/reproducible-builds.md) · [design specs](docs/specs/) · [autofill lab reports](docs/lab/) · [Rust core](core/README.md) · [Apple apps](apple/README.md) · [extension](extension/README.md) · [mailbox server](mailbox/README.md) · [formal models](formal/README.md) · [Wi-Fi on Windows and Linux](docs/wifi-windows-linux.md) · [site pack](docs/site-pack.md) · [icon pack](docs/icon-pack.md) · [translations](docs/i18n.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md) · [llms.txt](llms.txt)

## Contributing

Contributions are welcome, especially reviews of the crypto and the threat model.

1. Read the [security doc](docs/security/README.md) and the spec for the area you want to touch.
2. Open an issue to discuss anything larger than a small fix.
3. Keep `make -C core check`, `make -C apple test` and `npm run check` green. CI runs them on macOS and Linux.
4. New crypto or storage code comes with tests, and with a fuzz target when it parses untrusted input.

Before your first pull request is merged, you sign the [contributor license agreement](CLA.md) once, by replying to the bot. More in [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a vulnerability

Please report security issues privately through [GitHub Security Advisories](https://github.com/soma-intelligence/onepass/security/advisories/new) or to security@somalabs.me, never in a public issue. We acknowledge reports within 72 hours. The full policy, including safe harbor for good faith research, is in [SECURITY.md](SECURITY.md).

## More from Soma Labs

- [Soma Flight](https://github.com/soma-intelligence/Soma_Flight): flight tracker with a log of every trip.
- [Prism](https://github.com/soma-intelligence/prism): open source health app built on Apple Health.

## License

Kelid is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE). You can use, study, change and share it. If you distribute a modified version, or run one as a network service, you must publish its source under the same license.

For a commercial license without the AGPL terms, write to security@somalabs.me with "License" in the subject. Third-party word lists keep their own licenses, listed in [`core/onepass-core/data/LICENSES.md`](core/onepass-core/data/LICENSES.md). Site icons come from a pack built from Simple Icons (CC0), gilbarbara/logos (CC0) and 2FA Directory (MIT), downloaded whole and never site by site: see [`docs/icon-pack.md`](docs/icon-pack.md) and [`NOTICE`](NOTICE). Logos remain trademarks of their owners.

---

<div align="center">
<sub>Built by <a href="https://somalabs.me">Soma Labs</a>.</sub>
</div>
