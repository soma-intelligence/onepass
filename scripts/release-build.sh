#!/usr/bin/env bash
# The release builds that do not need Apple signing, in one place, so that the
# release workflow and anyone checking a release run the same commands.
#
#   release-build.sh extension <version> <out-dir>
#       -> OnePass-<version>-chrome.zip, OnePass-<version>-firefox.zip
#   release-build.sh cli <version> <out-dir> <rust-target>
#       -> onepass-<version>-<rust-target>  (the `onepass` command line)
#
# Inputs that change the bytes, and how they are pinned:
#   - sources: the checked out commit; SOURCE_DATE_EPOCH defaults to its
#     commit time (git log -1 --format=%ct);
#   - Rust: core/rust-toolchain.toml, Cargo.lock (--locked), absolute paths
#     remapped (--remap-path-prefix, -ffile-prefix-map for C), symbols
#     stripped;
#   - extension: package-lock.json (npm ci), esbuild at an exact version,
#     zip written by scripts/deterministic-zip.py (sorted entries, fixed
#     time and modes).
# The caller installs the toolchains (rustup, Node) and the Rust target.
set -euo pipefail

usage() {
  echo "usage: $0 extension <version> <out-dir> | cli <version> <out-dir> <rust-target>" >&2
  exit 64
}

[ $# -ge 3 ] || usage
KIND=$1
VERSION=$2
OUT=$3

# A version is what a tag carries without its v: 1.2.3 or 1.2.3-rc.1.
if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  echo "not a release version: $VERSION" >&2
  exit 64
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct)"
fi
export SOURCE_DATE_EPOCH
export TZ=UTC LC_ALL=C

case "$KIND" in
  extension)
    [ $# -eq 3 ] || usage
    cd "$ROOT/extension"
    # The lockfile is the whole dependency set: npm ci refuses any drift.
    npm ci --ignore-scripts --no-audit --no-fund
    rm -rf dist
    node build.mjs chromium firefox
    python3 "$ROOT/scripts/deterministic-zip.py" "$OUT/OnePass-$VERSION-chrome.zip" dist/chromium
    python3 "$ROOT/scripts/deterministic-zip.py" "$OUT/OnePass-$VERSION-firefox.zip" dist/firefox
    ;;
  cli)
    [ $# -eq 4 ] || usage
    TARGET=$4
    cd "$ROOT/core"
    CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
    RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
    # --target is always given, so RUSTFLAGS reach the shipped binary and not
    # the build scripts or proc macros.
    RUSTFLAGS="-C strip=symbols --remap-path-prefix=$ROOT=/onepass --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$RUSTUP_HOME_DIR=/rustup"
    case "$TARGET" in
      # ld64 computes LC_UUID at link time, before rustc strips the symbols,
      # so the object file paths of the debug map (N_OSO) changed the UUID:
      # two checkouts at different paths gave two binaries 48 bytes apart
      # (UUID and code signature hashes). -S keeps the debug map out of the
      # link.
      *-apple-darwin) RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-S" ;;
    esac
    export RUSTFLAGS
    # C code built by build scripts (SQLite, aws-lc) records __FILE__.
    PREFIX_MAP="-ffile-prefix-map=$ROOT=/onepass -ffile-prefix-map=$CARGO_HOME_DIR=/cargo"
    export CFLAGS="${CFLAGS:+$CFLAGS }$PREFIX_MAP"
    export CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }$PREFIX_MAP"
    export CARGO_INCREMENTAL=0
    # -p only: the dev features of other workspace crates are not unified in.
    cargo build --locked --release -p onepass-cli --target "$TARGET"
    cp "target/$TARGET/release/onepass" "$OUT/onepass-$VERSION-$TARGET"
    chmod 755 "$OUT/onepass-$VERSION-$TARGET"
    ;;
  *)
    usage
    ;;
esac

(cd "$OUT" && shasum -a 256 -- *)
