# AGENTS.md

Notes for coding agents working in this repository. Humans: start with [CONTRIBUTING.md](CONTRIBUTING.md), which this file summarizes and never overrides.

## What this is

OnePass, an open source (AGPL-3.0-or-later), post-quantum password manager for iPhone, iPad, Mac, Apple Watch and Vision Pro. One Rust core does all the cryptography; native SwiftUI apps and a TypeScript browser extension sit on top.

## Layout

| Path | What | Language |
|---|---|---|
| `core/` | Cargo workspace: `onepass-core` (crypto, vaults, sync, import, Watchtower, passkeys), `onepass-cli`, `onepass-ffi` (UniFFI), `onepass-guard`, `onepass-mcp`, `onepass-ssh-agent`, `onepass-bridge`, `onepass-relay`, `onepass-sync`, `onepass-mailbox`, `fuzz/` | Rust 1.99.1 (pinned in `core/rust-toolchain.toml`) |
| `apple/` | Apps, AutoFill, Safari extension, Watch, widgets. Xcode project generated from `apple/project.yml` (XcodeGen) | Swift |
| `extension/` | MV3 browser extension, Playwright e2e, autofill lab | TypeScript, Node 22 |
| `mailbox/` | Sync server on Supabase (migrations, edge functions) | SQL, TypeScript |
| `android/` | Gradle project: core bindings and Wi-Fi only, no app | Kotlin |
| `formal/` | ProVerif models, run by `make formal` | ProVerif |
| `ml/` | Autofill model tooling | Python (uv) |
| `docs/security/` | Whitepaper and threat model (French) | |
| `docs/specs/`, `docs/superpowers/` | Design specs and internal plans | |
| `docs/guides/`, `docs/comparison/` | User-facing how-to and comparison pages (English) | |

## Build and test

```bash
make -C core check                 # fmt, clippy -D warnings, tests, cargo deny
make -C core quick                 # only crates changed since origin/main (cargo-nextest)
make -C apple core && make -C apple test && make -C apple build-mac
cd extension && npm ci && npm run check
scripts/verify.sh                  # runs only the checks your diff touches
python3 -I scripts/i18n/i18n.py check
make formal                        # ProVerif, compares with formal/expected.txt
```

`. scripts/dev-env.sh` once per shell sets up the shared compile cache. Heavy steps go through `scripts/heavy.sh` (one at a time per Mac).

## Rules that matter here

- New crypto, storage or parsing code comes with tests. Code that parses untrusted input (imports, archives, records from the store, browser messages) also gets a `cargo-fuzz` target in `core/fuzz`.
- Secrets never cross the FFI or the extension bridge in clear unless the design says so. Keep them in zeroizing buffers. Private keys and TOTP seeds stay in Rust.
- No new core dependency without a reason in the pull request; `cargo deny` must stay green.
- Every user-facing string gets a semantic key and all four languages (French source, English, Spanish, Italian) in the same change. Read [docs/i18n.md](docs/i18n.md).
- Commit messages: imperative, conventional prefix (`feat(core):`, `fix(extension):`, `docs:`).
- Do not edit `docs/security/formal/results.md` by hand; `formal/run.sh` generates it.
- Do not weaken the Argon2id floor, the `dev-fast-kdf` guards, or the release refusal of development environment variables.
- Never put real secrets in tests, fixtures or a development data directory (`~/.onepass-dev`).
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Where to read before changing something

- Crypto, vault format, sync: `docs/security/README.md` and the matching spec in `docs/specs/`.
- CLI, MCP server, SSH agent, Travel Mode: `core/README.md`.
- Apps: `apple/README.md`. Extension: `extension/README.md`. Mailbox: `mailbox/README.md`.
