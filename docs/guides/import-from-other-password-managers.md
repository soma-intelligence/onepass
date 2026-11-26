# How to import passwords into Cleon from another password manager

Cleon imports unencrypted exports from 1Password, Bitwarden, Apple Passwords, Chrome and other browsers, LastPass, Dashlane, Proton Pass, NordPass, Keeper, RoboForm, Enpass and KeePass or KeePassXC (as KeePass 2 XML), plus Credential Exchange (CXF) files, `otpauth://` links and Wi-Fi QR codes. In the app, use "Import from Another Password Manager…" (in Browse, or Settings > General), pick the source or "Detect Automatically", and choose the file. Parsing happens on your device in the Rust core; nothing is uploaded.

## Supported sources and how to export from each

The export steps below are the hints the app itself shows in its import sheet (`apple/App/Settings/ImportSheet.swift`).

| Source | Format name (`--format`) | How to export from the source |
|---|---|---|
| 1Password | `1pux`, `1password-csv` | File > Export, then the 1PUX format (or CSV) |
| Bitwarden | `bitwarden-json`, `bitwarden-csv` | Tools > Export Vault, as unencrypted .json or .csv |
| Apple Passwords | `safari-csv` | Passwords app: File > Export All Passwords to File |
| Safari | `safari-csv` | File > Export Browsing Data, with passwords (.zip or .csv) |
| Google Chrome | `chrome-csv` | Google Password Manager > Settings > Export passwords |
| Microsoft Edge, Brave, Opera, Arc, Vivaldi | `chrome-csv` | The browser's password settings > Export passwords |
| Firefox | `firefox-csv` | about:logins > ⋯ > Export Logins |
| LastPass | `lastpass-csv` | Advanced Options > Export > LastPass CSV File |
| Dashlane | `dashlane-zip`, `dashlane-csv` | Settings > Export Data > CSV (the .zip or one of the .csv files) |
| Proton Pass | `protonpass-csv` | Settings > Export, as CSV |
| NordPass | `nordpass-csv` | Settings > Import and Export > Export Items (.csv) |
| Keeper | `keeper-csv` | Settings > Export > .csv file |
| RoboForm | `roboform-csv` | Options > Export logins and notes (.csv) |
| Enpass | `enpass-json` | File > Export, as .json |
| KeePass, KeePassXC | `keepass-xml` | File > Export as KeePass 2 XML |
| Any app that speaks Credential Exchange | `cxf` | A .json file in Credential Exchange Format |
| Google Authenticator and other TOTP apps | `otpauth` | `otpauth://` links, one per line |
| Wi-Fi networks | `wifi-qr` | Wi-Fi QR code text (`WIFI:S:...`), one per line |
| Cleon | `onepass`, `onepass-csv` | A `.onepass` archive or Cleon's own CSV export |

## What Cleon refuses, and why

- **Encrypted third-party exports.** A Bitwarden export with `encrypted: true` and an encrypted Dashlane `.dash` file are refused with a message asking for a plain export. Cleon never decrypts another vendor's format.
- **KeePass `.kdbx` databases.** A KDBX file is recognized by its signature and refused with `KeePass KDBX is not supported: export as KeePass 2 XML`. Export from KeePass or KeePassXC as KeePass 2 XML instead.
- **Encrypted 1Password `.1pif`.** Not handled; use 1PUX or CSV.

## Duplicates and dry runs

Before writing, the app shows items in the file that look like items already in the vault. Exact copies are skipped and the others merged unless you choose otherwise (Merge, Skip or Import for each, or Merge all / Skip all). Values stored differently from the source end up in an "Imported" section of each item.

## Import from the command line

The development CLI uses the same parsers:

```bash
onepass import export.1pux --dry-run          # report only, writes nothing
onepass import bitwarden.json --vault Personal
onepass import passwords.csv --format chrome-csv
onepass import --wifi-keychain                # Wi-Fi networks of the macOS keychain
```

The format is detected from the content unless you pass `--format`. The CLI is a development tool: see [the CLI guide](command-line-cli.md) before putting real secrets in it.

## Limits that protect you from a hostile file

An import file is treated as hostile input (`docs/security/README.md`, section 8, in French): 256 MiB per file, 1,000,000 rows or items, strict UTF-8 CSV, no XML entity expansion, zip archives read as streams and capped at 512 MiB decompressed, and every parser has a `cargo-fuzz` target. All items are validated before the first write. Delete the plaintext export from your disk once the import is done.

## Related

- [Export or back up a Cleon vault](export-and-backup.md)
- [Cleon vs 1Password](../comparison/onepass-vs-1password.md)
- [Cleon vs Bitwarden](../comparison/onepass-vs-bitwarden.md)
- [Cleon vs KeePassXC](../comparison/onepass-vs-keepassxc.md)
- [Store 2FA codes in Cleon](two-factor-codes-totp.md)
- [README](../../README.md)
