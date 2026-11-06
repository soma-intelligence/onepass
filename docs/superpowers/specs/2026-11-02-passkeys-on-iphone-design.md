# Passkeys on iPhone, 2026-11-02

Founder feedback item 5: "there are still no passkeys". Milestone 3 shipped the passkey provider;
this spec records what the investigation found and the gaps closed on top of it.

## Findings (evidence)

- The AutoFill extension declares passkeys: `ProvidesPasskeys` in
  `ASCredentialProviderExtensionCapabilities` (`apple/AutoFill/Support/Info.plist`). The last
  personal build (`DerivedData-install-iphone`, Release-CloudKit, 2026-11-01) carries it, and its
  signature holds `autofill-credential-provider`, the App Group `group.me.quentincaron.onepass` and
  the keychain group. Nothing gates passkeys off in Release or on the personal team.
- The extension implements the list with request parameters (`prepareCredentialList(for:requestParameters:)`),
  the QuickType path (`prepareInterfaceToProvideCredential`), registration
  (`prepareInterface(forPasskeyRegistration:)`; conditional registration answers `failed`, ruling X21)
  and publishes `ASPasskeyCredentialIdentity` through `AutoFillIdentityBuilder`. The keys are created
  and used in Rust (`webauthn.rs`), stored as `Passkey` fields of a Login, synced like any item.
- The app shows a passkey only inside its Login's detail (`PasskeyRow`). No list, no count, no place
  to find "my passkeys": with none created yet, nothing in the app says passkeys exist.
- The founder's existing passkeys live in Apple Passwords. OnePass had no way to receive them: the
  system Credential Exchange (iOS 26 `ASCredentialImportManager`) was left out of milestone 3, and
  Passwords exports passkeys only through it (never into a file).

## What this adds

1. **Passkeys list.** `FfiItemSummary.passkey_count` (core), `ItemFilter.passkeys`,
   `ItemCounts.passkeys`, `EmptyListReason.noPasskeys` (VaultKit). iPhone Items tab: a "Passkeys"
   row under "Tous les éléments", always shown; Mac and iPad sidebar: a "Passkeys" row under Favoris.
   The empty list says how a passkey arrives (pick OnePass on a site, or export from Passwords).
2. **Credential Exchange import.** The extension declares `SupportsCredentialExchange` and
   `SupportedCredentialExchangeVersions` = ["1.0"], so OnePass appears in Passwords > Export Data
   to Another App. The system opens OnePass with an `ASCredentialExchangeActivity`; once unlocked,
   the Import sheet reads the credentials with the token (`CredentialExchangeImport.receive`),
   encodes them as CXF JSON (Apple's Codable names are CXF's; only the dates are re-encoded as Unix
   seconds) and runs the existing `cxf` preview and import. Passkeys keep their private key and sign
   like a passkey created by a site (VaultKit test checks the ECDSA signature).

## Rulings

- R1: the Passkeys row counts items, not passkeys (a Login with two passkeys counts once), like
  every other list. Cost if wrong: a label change.
- R2: the Passkeys row shows even at 0. Its whole point is discoverability. Cost if wrong: hide at 0.
- R3: Credential Exchange goes through the Import sheet (preview, vault choice) rather than a silent
  import: same review step as a file, same buffer wipe. Cost if wrong: one more tap.
- R4: no new record kind, no core format change: CXE data reuses the CXF reader, pinned by a core
  test on the exact JSON `ASExportedCredentialData` encodes.

## Still to verify on the founder's iPhone

- Settings > General > AutoFill & Passwords: OnePass on, and passkey creation in Safari offers
  "Save to OnePass" (a real site needs a real device: the Simulator has no signed associated domains
  for apps, Safari works).
- Passwords > select passkeys > Export Data to Another App > OnePass, then the Import sheet.
- Release-CloudKit sync of a passkey created in the extension (README limit R8).
