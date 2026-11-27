# How to verify a Cleon download (checksums, provenance, reproducible builds)

Every GitHub release of Cleon ships a `SHA256SUMS` file and a SLSA build provenance attestation signed through Sigstore with the identity of the release workflow. Check the hashes with `shasum -a 256 -c SHA256SUMS`, then the provenance with `gh attestation verify`, and for the Mac app also its Developer ID signature and notarization. The browser extension zips and the CLI are built to be reproducible, so you can rebuild them from the tagged commit and compare the bytes.

## 1. Check the hashes

With the downloaded files and `SHA256SUMS` in the same folder:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing      # Linux: sha256sum -c SHA256SUMS --ignore-missing
```

## 2. Check the provenance (GitHub CLI 2.49 or later)

```bash
gh attestation verify Cleon-<version>-mac.zip \
  --repo soma-intelligence/onepass \
  --signer-workflow soma-intelligence/onepass/.github/workflows/release.yml
```

The output must say "Verification succeeded" and name `refs/tags/v<version>`. A file without an attestation, or attested by another workflow, did not come from this release chain. The attestation proves the bytes came out of `release.yml` on a GitHub-hosted runner from the tagged commit (SLSA Build L2). It does not prove that the commit or its dependencies are sound.

## 3. For the Mac app, check signature and notarization

```bash
ditto -x -k Cleon-<version>-mac.zip .
codesign --verify --deep --strict --verbose=2 OnePass.app
spctl --assess --type execute --verbose=2 OnePass.app     # "source=Notarized Developer ID"
xcrun stapler validate OnePass.app
```

The Mac app then updates itself from the latest release, and installs an update only with your approval, only if its archive and feed carry the release key's EdDSA signature, and only if the app is signed by the same Apple team.

## 4. Rebuild and compare (reproducible builds)

| Release file | Reproducible? |
|---|---|
| `Cleon-<v>-chrome.zip`, `Cleon-<v>-firefox.zip` | Yes, on the same system. CI rebuilds them on another runner at another path and blocks the release on any difference |
| `onepass-<v>-aarch64-apple-darwin` (CLI) | Yes, with the same Xcode and Rust toolchain; not yet compared across two machines |
| `onepass-<v>-x86_64-unknown-linux-gnu` (CLI) | Compared by the `rebuild` job at each release |
| `Cleon-<v>-mac.zip` | No: the Developer ID signature and notarization ticket cannot be reproduced by a third party |
| `Cleon-<v>-sbom.zip` | No: SBOM tools write a timestamp and random serial number |

With the tag checked out (`git checkout vX.Y.Z`), `rustup`, Node 22 and Python 3 installed:

```bash
scripts/release-build.sh extension X.Y.Z /tmp/rebuild
scripts/release-build.sh cli X.Y.Z /tmp/rebuild x86_64-unknown-linux-gnu    # or aarch64-apple-darwin
cd /tmp/rebuild && sha256sum -c /path/to/SHA256SUMS --ignore-missing
```

The script sets `SOURCE_DATE_EPOCH` to the commit date, `TZ=UTC`, `LC_ALL=C`, strips symbols and remaps paths. Any difference is a defect to report through [SECURITY.md](../../SECURITY.md). Full details, in French: [`docs/security/reproducible-builds.md`](../security/reproducible-builds.md) and [`docs/security/release-pipeline.md`](../security/release-pipeline.md).

## What the release workflow checks before building

`cargo deny check`, `cargo vet --locked`, `cargo audit`, and that every GitHub Action is pinned by commit SHA. The workflow uses no cache, persists no checkout credentials, and only creates a **draft** release: a person reviews it and clicks Publish.

## Related

- [Has Cleon been audited?](security-audit-status.md)
- [Cleon command line (CLI)](command-line-cli.md)
- [README: Install](../../README.md#install)
