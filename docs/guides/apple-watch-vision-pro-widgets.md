# Cleon on Apple Watch, Vision Pro, widgets and Shortcuts

Cleon has a standalone, **read-only Apple Watch app** with TOTP rings, complications and Smart Stack, carrying at most 50 items you mark "On Apple Watch" and never login passwords, CVVs, PINs or notes. On **Vision Pro**, the same app target runs with a visionOS layout and Optic ID. On iPhone and iPad there are **widgets** ("Codes" and "Favorites"), **Controls** (generate a password, search, lock) and **App Intents** for Shortcuts. All targets need iOS, iPadOS, watchOS or visionOS 26 or later.

## Apple Watch

- **Turn it on:** on the iPhone, Settings > Apple Watch > "Send to Apple Watch" (on by default), then mark items "On Apple Watch" in their editor. Only marked items are sent, 50 at most, sorted by title.
- **What goes to the watch:** a closed list of fields. The username of a Login, Wi-Fi (`ssid`, password, guest network), membership and loyalty, a bank card reduced to `•••• 1234`, access codes and ID documents, plus the first TOTP of the item.
- **What never goes:** a Login's password, CVV, PIN, full card number, notes. Items in the trash, archived, set to reprompt, or in vaults hidden on that device are skipped.
- **How it is sealed:** the iPhone's Rust core builds an `OPC1` payload, wraps a random key to the watch's public key with ML-KEM-1024 + X25519, and seals the content with AES-256-GCM. On the watch, the TOTP seeds live in a Rust `CompanionVault` that returns codes only, and exists only while the app is in the foreground. The sealed file uses `Complete` data protection.
- **Remove it:** "Remove from Apple Watch" wipes the keys and file on the watch and stops sending.

The watch app needs a passcode on the watch ("Unlock your Apple Watch to open Cleon"). Watches that run watchOS 26 only as `arm64_32` are not supported.

## Vision Pro

The `Cleon` app target with the visionOS destination: iPad layout (three-column split view), system glass window, ornaments for toolbars, hover effects. Optic ID goes through the same Secure Enclave key as Face ID. There is no camera access for the app, so the Emergency Kit QR cannot be scanned: type the Secret Key. No widgets, Controls or Watch on Vision Pro.

## Widgets and Controls (iPhone, iPad)

| Widget or Control | What it shows or does |
|---|---|
| "Codes" widget (small, medium, large, accessory rectangular) | TOTP codes precomputed by the app for 12 hours; after that, "Open Cleon to refresh" |
| "Favorites" widget (small, medium) | The first 8 favorites by title |
| "Generate Password" Control | Opens the generator |
| "Search Cleon" Control | Opens search |
| "Lock Cleon" Control | Locks the app immediately, or when it returns to the foreground |

Widgets receive only codes already computed, never seeds. Titles and codes are marked `.privacySensitive()`, and a locked device shows "Unlock your iPhone".

## Shortcuts and App Intents

On iPhone, iPad, Mac and Vision Pro: "Open Item", "Copy One-Time Code" (fresh authentication, copied through the Cleon clipboard, no code returned to the shortcut), "Generate Password" (8 to 64 characters, 20 by default, without opening the app) and "Lock Cleon". Item titles are never given to Siri's index: you pick the item in Shortcuts.

## Related

- [Store 2FA codes in Cleon](two-factor-codes-totp.md)
- [Master password, Secret Key and Emergency Kit](master-password-secret-key-emergency-kit.md)
- [Is Cleon on Android, Windows or Linux?](android-windows-linux.md)
- [README](../../README.md)
