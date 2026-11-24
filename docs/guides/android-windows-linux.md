# Is Kelid available on Android, Windows or Linux?

Not as an app, as of November 2026. Kelid ships apps for iPhone, iPad, Mac, Apple Watch and Vision Pro only. On other systems you get the Chrome and Firefox extension builds (which talk to the Kelid Mac app) and the development CLI for Linux, including a Wi-Fi sync agent for Windows and Linux. The repository's `android/` folder holds early groundwork; there is no app to install from it.

## Platform by platform

| Platform | Status in this repository |
|---|---|
| iPhone, iPad (iOS, iPadOS 26+) | App on the App Store |
| Mac (macOS 26+) | App on the App Store, or a notarized, self-updating build from GitHub Releases |
| Apple Watch (watchOS 26+) | Standalone, read-only companion app |
| Vision Pro (visionOS 26+) | Same app target with a visionOS layout |
| Chrome, Edge, Brave, Firefox | Extension built from a clone; it needs the Kelid Mac app. Chrome Web Store listing pending |
| Linux | Development CLI (`onepass-<v>-x86_64-unknown-linux-gnu` on Releases), Secret Key in the Secret Service |
| Windows | Development CLI built from source, used for Wi-Fi sync (`onepass wifi install-agent`); no app and no prebuilt binary |
| Android | Gradle project that builds the Rust core and Kotlin bindings, runs the core tests on an emulator in CI, and an automatic Wi-Fi module; no app |
| Web | Not available. A WASM web app is listed under "Later" on the roadmap |

## What is in `android/` today

Per its commit history: a Gradle project with generated Kotlin bindings for the core (`vaultkit-android`), a script that builds and tests the core for Android, a CI job that runs every core and FFI test binary on an emulator, and a `wifi` module that turns Router items into Android network suggestions (off by default). There is no vault UI, AutoFill service or store listing.

## Sync for non-Apple devices

The planned path for devices outside Apple's ecosystem is the Kelid mailbox, an end-to-end encrypted sync server in `mailbox/` that can also be self-hosted. It is work in progress; see [Can I self-host Kelid sync?](self-hosted-sync-server.md).

## If you need Android or Windows today

The README's own comparison suggests 1Password, NordPass, Dashlane or Keeper if you need Android, Windows or Linux apps now, and lists open source managers such as KeePassXC, Bitwarden and Proton Pass in its scoring table. See [How Kelid compares](../../README.md#how-onepass-compares).

## Related

- [Use Kelid in Chrome, Firefox and Safari](browser-extension.md)
- [Kelid command line (CLI)](command-line-cli.md)
- [Wi-Fi on Windows and Linux](../wifi-windows-linux.md) (in French)
- [Can I self-host Kelid sync?](self-hosted-sync-server.md)
- [README](../../README.md)
