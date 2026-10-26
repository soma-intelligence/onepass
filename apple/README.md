# OnePass pour Apple (iPhone, iPad, Mac)

Les applications Apple s'appuient sur le coeur Rust (`core/onepass-ffi`, exposé par UniFFI) via le paquet Swift `VaultKit`.

## Prérequis

- Xcode 27 (SDK iOS 27, cibles de déploiement iOS 26.0 et macOS 26.0), Swift 6.
- XcodeGen (`brew install xcodegen`).
- Toolchain Rust (`rustup`) avec les cibles `aarch64-apple-ios`, `aarch64-apple-ios-sim` et `aarch64-apple-darwin` :
  `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin`.

## Construire le coeur

```sh
make -C apple core
```

Produit `apple/build/OnePassFFI.xcframework` (tranches `ios-arm64`, `ios-arm64-simulator`, `macos-arm64`, profil `release`, jamais la fonctionnalité `dev-fast-kdf`) et génère les liaisons Swift dans `apple/VaultKit/Sources/OnePassCore/`. La commande est idempotente : rien n'est recompilé tant que les fichiers `.rs`, `Cargo.toml` et `Cargo.lock` sous `core/` n'ont pas changé (empreinte dans `apple/build/.core-stamp`).

## Tests

```sh
make -C apple test
```

Construit d'abord un XCFramework de test distinct (`make -C apple core-test`) : macOS arm64 seulement, profil `debug` avec `dev-fast-kdf`, dans `apple/build/test/OnePassFFI.xcframework`. Il abaisse le coût Argon2id pour que les tests créent des comptes rapidement. `VaultKit/Package.swift` le choisit grâce à la variable d'environnement `ONEPASS_FFI_XCFRAMEWORK` (chemin relatif au dossier du paquet, SwiftPM refuse les chemins absolus ; défaut : `../build/OnePassFFI.xcframework`). Ce XCFramework de test ne doit jamais être livré.

## Projet Xcode

```sh
make -C apple project
open apple/OnePass.xcodeproj
```

`make project` lance `xcodegen generate` depuis `project.yml` (le projet Xcode n'est pas versionné). Autres cibles : `build-ios`, `build-mac`, `uitest`, `screenshots`, `clean`.

## Build non signé ou signé

- Build non signé (local seulement) : sans équipe de développement ni droits iCloud, l'app tourne en stockage local. La synchronisation CloudKit est désactivée.
- Build signé : avec une équipe et les droits `iCloud.me.somalabs.onepass` et le groupe Keychain `me.somalabs.onepass.shared`, la synchronisation CloudKit est active.

## Simulateurs dédiés

Utiliser uniquement `OnePass M2 iPhone` (iPhone 18 Pro, iOS 27.0) et `OnePass M2 iPad` (iPad mini, iOS 27.0). Ne jamais démarrer, arrêter ou effacer un autre Simulateur : d'autres sessions s'en servent.
