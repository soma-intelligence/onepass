# Cleon command line (`onepass` CLI): commands and limits

`onepass` is the command line of Cleon, built from `core/onepass-cli` in this repository. It creates accounts and vaults, reads secrets by `onepass://` reference, prints TOTP codes, generates passwords, imports and exports, runs Watchtower, makes signed backups, and serves the MCP server and SSH agent. **It is a development tool**: it prints a `DEV MODE` banner, has no auto-lock, no biometrics and no sync, and the README says not to put real secrets in a development account. The apps are the way to use Cleon day to day.

## Get it

Build from a clone (Rust 1.99.1 is pinned in `core/rust-toolchain.toml`):

```bash
git clone https://github.com/soma-intelligence/onepass.git
cargo run --manifest-path onepass/core/Cargo.toml -p onepass-cli -- --help
```

Release pages also carry prebuilt `onepass-<version>-aarch64-apple-darwin` and `onepass-<version>-x86_64-unknown-linux-gnu` binaries. The Linux binary needs `libdbus-1` at run time. The macOS binary is only ad hoc signed and not notarized, so after a browser download it needs `xattr -d com.apple.quarantine` and `chmod +x`.

## Commands

| Command | What it does |
|---|---|
| `onepass account create` | Create the account of this data directory (prints the Secret Key once) |
| `onepass account devices`, `rotate-keys`, `remove-device <id>` | List devices, rotate every key, remove a device |
| `onepass vault list`, `vault create "Work"` | List and create vaults (`--mcp-access`, `--travel-safe` at creation) |
| `onepass item create login --title "Example" --field username=alice --field password=...` | Create an item |
| `onepass item list`, `item get "Example" --reveal` | List items, show one |
| `onepass read "onepass://Personal/Example/password"` | Print one secret by reference |
| `onepass totp "Example"` | Print the current one-time code |
| `onepass generate --words 5` | Generate a password, passphrase or PIN (no account needed) |
| `onepass import <file> [--format <name>] [--dry-run]` | Import another manager's export, an archive, or keychain Wi-Fi (`--wifi-keychain`) |
| `onepass export --out vault.onepass --generate-passphrase` | Encrypted archive (CSV only with `--plaintext`) |
| `onepass watchtower [--offline] [--hibp-dir <dir>]` | Breaches, reuse, strength, 2FA, expiry |
| `onepass backup create`, `restore`, `inspect` | Signed account backup |
| `onepass mcp`, `mcp policy show\|set`, `mcp audit` | MCP server over stdio, its policy and audit log |
| `onepass ssh-key ...`, `onepass ssh-agent` | SSH keys and the SSH agent |
| `onepass travel push\|on\|status\|off --upstream <file>` | Travel Mode against a development upstream file |
| `onepass wifi install-agent` | Keep vault Wi-Fi networks in sync with Windows or Linux |

Global options: `--data-dir <dir>` (default `~/.onepass-dev`) and `--json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage error |
| 2 | Wrong password |
| 3 | Integrity failure (stored data was tampered with) |
| 4 | Not found |
| 5 | Concurrent write: nothing was saved, run the command again |

## `onepass://` references

`onepass read` takes `onepass://vault/item/[section/]field`. A field name that matches several fields of the item without a section is refused (`ambiguous field, add the section`) instead of giving the first one to a script. `totp` names the item's one filled OTP field. If the reader closes stdout (`onepass read ... | head -c1`), the command stops quietly with code 0.

## Where the CLI keeps its secrets

- The Secret Key is in the system secret store: the macOS login keychain (service `me.somalabs.onepass.cli`) or the Linux Secret Service (GNOME Keyring, KWallet, KeePassXC). Any process of the same user can read those.
- Without a reachable store (server without a session bus, CI), `account create` refuses. `--insecure-file-secret-key` then keeps the Secret Key **in clear** in `device.bin`, and every command reminds you on stderr.
- `device.bin` (mode `0600`, folder `0700`) holds device state and device keys protected only by file permissions; the CLI has no Secure Enclave.
- Every command takes an exclusive lock on `<data-dir>/lock`, so two commands in parallel run one after the other.

## Related

- [Import from another password manager](import-from-other-password-managers.md)
- [Let an AI agent use a password without seeing it](mcp-server-ai-agents.md)
- [Use Cleon as an SSH agent](ssh-agent.md)
- [Travel Mode](travel-mode.md)
- [Is Cleon on Android, Windows or Linux?](android-windows-linux.md)
- [README](../../README.md)
