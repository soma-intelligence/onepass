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

For the edit and test loop, use the fast path and keep the full checks for the end:

- `. scripts/dev-env.sh` once per shell: a shared compile cache (`brew install sccache`) and 4 build jobs.
- `make -C core quick`: only the crates changed since `origin/main`, through `cargo-nextest`
  (`brew install cargo-nextest`), which kills a test still running after 5 minutes.
- `apple/scripts/build-core.sh dev`: the core for Mac, iOS Simulator and watchOS Simulator builds in a few
  minutes, so the iOS app builds with its Watch app as is. Device and visionOS builds need
  `apple/scripts/build-core.sh shipped`.

### One command: `scripts/verify.sh`

`scripts/verify.sh` reads `git diff --name-only` against the merge base with `origin/main` (committed,
uncommitted and untracked files) and runs only the checks the change touches, then prints one table of
steps, results and durations. It exits non-zero when a step fails and prints that step's last lines; full
logs land in `$TMPDIR/onepass-verify/`.

| Flag | Effect |
|---|---|
| `--base <ref>` | compare with `<ref>` instead of `origin/main` |
| `--all` | everything, for a release: whole workspace, every Swift package, both app builds |
| `--apple` | add the Apple steps when neither `apple/` nor `onepass-ffi` changed |
| `--dry-run` | print the plan and run nothing |
| `--no-queue` | skip the build queue (same as `ONEPASS_NO_QUEUE=1`) |

What it maps:

- A crate under `core/`: `cargo nextest run --profile verify` for that crate and every workspace crate that
  depends on it. `onepass-core`, a root manifest, `Cargo.lock` or the toolchain means the whole workspace. A
  change under a crate's `src/` adds `cargo test --doc`, since nextest skips doctests.
- `extension/`: `tsc`, then `vitest related` on the changed files when they all sit in `extension/src`
  (the whole suite otherwise), then the build.
- A Swift package in `apple/`: its `swift test` and those of the packages built on it. Tests tagged
  `.slow` (they wait on the main actor, the run loop or a real local network, and time out when the whole
  suite runs in parallel on a busy Mac) run on their own, serially, after the parallel run of the rest.
- `apple/` outside package tests, `onepass-ffi` or `build-core.sh`: the core for app builds and
  `xcodebuild` for the iOS Simulator and macOS.
- `android/`: the Gradle checks of CI when a JDK, an Android SDK and `cargo-ndk` exist; otherwise the
  table says why it was skipped.

Caches and the queue:

- **Build queue.** `scripts/heavy.sh <command>` runs one heavy step at a time on the Mac, whatever the
  checkout or session: workspace cargo runs, `build-core.sh`, `swift test`, `xcodebuild`. The lock is
  `~/Library/Caches/onepass-heavy.lock`; the kernel drops it when its holder dies, so it never goes stale.
  A waiting run prints who holds it. `verify.sh` queues its heavy steps; `ONEPASS_NO_QUEUE=1` opts out.
- **Compile cache.** `scripts/dev-env.sh` (sourced by `verify.sh`) starts the shared sccache server
  (`~/Library/Caches/onepass-sccache`) from a clean environment and keeps it running, so that no build
  starts one with a deployment target in its environment ("conflicting deployment targets").
- **Core XCFramework.** `build-core.sh` keeps a stamp next to each XCFramework (mode, profile, features,
  targets, rustc version, every file under `core/`, the script itself) and skips the build when it
  matches. A `test` build (`dev-fast-kdf`) is never taken for `dev` or `shipped`, and both of those check
  that `dev-fast-kdf` is absent even when the stamp matches.
- **Shared cargo target** (`ONEPASS_SHARED_TARGET=1`, or a directory; default
  `~/Library/Caches/onepass-target`): off by default. Two checkouts of the workspace build their own
  crates under the same file names, and cargo judges freshness by modification time, so one checkout can
  run the other's stale test binary. `verify.sh` makes it safe: it runs cargo only through the queue and,
  when another checkout used the directory last, removes the workspace crates' artifacts first. Builds
  from two checkouts then wait for each other.
- **Shared DerivedData** (`ONEPASS_SHARED_DERIVED=1`): `verify.sh` builds with one DerivedData per
  scheme and destination under `~/Library/Caches/onepass-derived`, shared by every checkout.

## Strings and translations

OnePass ships in French, English, Spanish and Italian. Every user-facing string gets a semantic key and all four languages in the same change, product terms come from the glossary, and sentences are never assembled from fragments. Read [docs/i18n.md](docs/i18n.md); `python3 -I scripts/i18n/i18n.py check` must pass.

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
