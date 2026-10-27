# Contributing to OnePass

Thank you for helping. Reviews of the cryptography, the threat model and the autofill heuristics are the most valuable contributions right now.

## Before you start

- Read [docs/security/README.md](docs/security/README.md), and the design spec for the area you want to touch in [docs/specs](docs/specs).
- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Found a vulnerability? Don't open an issue: follow [SECURITY.md](SECURITY.md).

## Building and testing

| Part | Check |
|---|---|
| Rust core and CLI | `make -C core check` (fmt, clippy `-D warnings`, tests, `cargo deny`) |
| Apple apps | `make -C apple core`, then `make -C apple test` and `make -C apple build-mac` |
| Browser extension | `cd extension && npm ci && npm run check` |

Requirements are listed in the [README](README.md#requirements). CI runs the core and extension checks on every pull request.

## Rules for changes

- New cryptography, storage or parsing code comes with tests. Code that parses untrusted input (imports, archives, records from the store, messages from the browser) also gets a `cargo-fuzz` target in `core/fuzz`.
- Secrets never cross the FFI or the extension bridge in clear unless the design says so. Keep them in zeroizing buffers.
- No new dependency in the core without a reason in the pull request. `cargo deny` must stay green.
- Keep pull requests focused: one change per pull request is easier to review.
- Write commit messages in the imperative, with a conventional prefix (`feat(core):`, `fix(extension):`, `docs:`).

## Contributor license agreement

Before we can merge your first pull request, you sign the [CLA](CLA.md) once by replying to the bot's comment on it. You keep the copyright in your work. The CLA lets Soma Labs ship OnePass through the App Store, whose terms aren't compatible with the AGPL on their own, and offer commercial licenses.

## License

By contributing, you agree that your contribution is licensed under the [GNU Affero General Public License v3.0](LICENSE) and the terms of the CLA.
