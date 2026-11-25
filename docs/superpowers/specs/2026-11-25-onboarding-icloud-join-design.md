# Onboarding: QR pairing fix, Secret Key in iCloud Keychain, shorter flow

Date: 2026-11-25. Status: approved by the owner (three parts, one branch `feat/onboarding-icloud`).

## Problems reported

1. "J'ai déjà OnePass sur un autre appareil" with a QR code does nothing.
2. A vault already in iCloud should be offered at first launch; the owner wants to type only the
   master password.
3. The onboarding has too many screens and choices.

## 1. QR pairing

Cause. Two QR formats exist. `OPPAIR1:` is the invite an unlocked device shows (Mac: Réglages >
Appareils > Ajouter, and Compte > Configurer un appareil). `OPPAIR2:` is the rendezvous code
(Mac: Fichier > Configurer un appareil…). The new iPhone's default method, "Scanner un QR code",
used a scanner that accepted `OPPAIR2:` only, so the Mac's invite was dropped without a word.

Fix.
- `PairingScanText.route(_:)` (VaultKit) sorts a scanned text: `.rendezvous` for `OPPAIR2:`,
  `.invite` for `OPPAIR1:`, `nil` otherwise. The onboarding scanner takes both and starts
  `joinPairing` or `joinInvite`.
- A QR that is not a OnePass pairing code shows a message under the scanner instead of nothing.
- The method subtitles no longer say "Sur ton Mac" when the device being set up is the Mac.

## 2. Secret Key in iCloud Keychain

Ruling: the owner chose iCloud Keychain. A copy of the Secret Key is written as a synchronizable
generic-password item, next to the device-only copy that stays the source for unlocks.

- Store: `SyncedSecretKeyStore` protocol; `ICloudKeychainSecretKeys` (service
  `me.somalabs.onepass.icloud`, account `secretkey.<accountID>`, shared access group,
  `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked`, data protection keychain);
  `InMemorySyncedSecretKeys` for tests. `VaultEnvironment.syncedSecretKeys` is nil in UI tests
  (custom keychain service) so they never touch the user's iCloud Keychain.
- Publish: after every successful master-password unlock, account creation and restore, on a
  personal device, when `VaultSettings.secretKeyInICloud` is on (default on). Best effort: a
  failure never blocks the unlock. Existing accounts therefore publish their key at their next
  unlock, which is what lets a second device join with the password only.
- Shared and public devices never publish.
- Join: at the Bienvenue step the app looks for an account in iCloud (`remoteHasAccount`, which
  fetches into the local store) and for that account's key in iCloud Keychain
  (`storeAccountId` + synced read). Both present: the main button becomes "Ouvrir mon coffre
  iCloud", and the next screen asks for the master password only
  (`VaultSession.restoreFromICloudKeychain(password:)`, which stores the key device-only as a
  restore does).
- Account in iCloud without a synced key: the welcome says so and offers the QR pairing first,
  the Emergency Kit second.
- Setting: Réglages > Sécurité "Secret Key dans le trousseau iCloud". Off deletes the synced copy.

Trade-off, written in the threat model: someone holding the Apple ID and the passcode of one of
the user's devices (which together open iCloud Keychain) needs only the master password. Without
the synced copy they also needed the Emergency Kit or a device holding the key. The master
password and its Argon2id cost are unchanged.

## 3. Shorter flow

| Path | Before | After |
|---|---|---|
| Vault in iCloud, key in iCloud Keychain | Bienvenue, Type, Emergency Kit (key + password), Face ID, AutoFill, Terminé | Bienvenue, Mot de passe maître, Réglages rapides, Terminé |
| Create | Bienvenue, Type, Mot de passe, Secret Key, Face ID, AutoFill, Terminé | Bienvenue, Mot de passe, Emergency Kit, Réglages rapides, Terminé |

- The "Type d'appareil" step leaves the default path: personal is assumed. "Appareil partagé"
  under the welcome choices brings the step back for that run. The sync choice link (mailbox
  builds) moves to the password step.
- The Emergency Kit step gets "Plus tard" when the key was published to iCloud Keychain.
- Face ID (Touch ID) and AutoFill become one step, "Réglages rapides", with one button per row
  and "Continuer".

## Tests

- VaultKit: route of scanned texts; synced key published on create and on unlock, never on a
  shared device, never when the setting is off; join with the synced key and the password;
  wrong password leaves no device-only key.
- App: onboarding step lists for the three paths.
- Manual: Mac app and iOS Simulator walk-through with screenshots; QR with injected text in the
  Simulator (no camera).
