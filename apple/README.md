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

Un clone neuf doit exécuter `make -C apple core` avant tout `swift build` ou ouverture du paquet : le XCFramework et les liaisons Swift générées ne sont pas versionnés.

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

Une seule cible `OnePass` (iPhone, iPad et Mac natif arm64). `make project` lance `xcodegen generate` depuis `project.yml` ; le projet généré est versionné, il faut le régénérer après toute modification de `project.yml`. La phase de script "Build Rust core" lance `make -C apple core` si l'XCFramework manque.

- `make -C apple build-ios` : build Simulateur non signé sur `OnePass M2 iPhone`.
- `make -C apple build-mac` : build Mac signé ad hoc (`CODE_SIGN_IDENTITY=-`), lançable localement.
- Autres cibles : `uitest`, `screenshots`, `clean`. Les builds vont dans `apple/DerivedData` (ignoré par git).

Configurations : `Debug` et `Release` (non signées, sans CloudKit) ; `Release-CloudKit` (condition `ONEPASS_CLOUDKIT`, droits iCloud, groupe Keychain partagé et notifications push, `DEVELOPMENT_TEAM` à renseigner).

Arguments de lancement (Debug seulement) : `-OnePassUITestReset YES` efface la base, les réglages et les éléments Keychain de l'app ; `-OnePassOnboardingStep device|password|restore` ouvre directement une étape de l'onboarding (captures d'écran).

## Build non signé ou signé

- Build non signé (local seulement) : sans équipe de développement ni droits iCloud, l'app tourne en stockage local. La synchronisation CloudKit est désactivée.
- Build signé : avec une équipe et les droits `iCloud.me.somalabs.onepass` et le groupe Keychain `me.somalabs.onepass.shared`, la synchronisation CloudKit est active.

## Simulateurs dédiés

Utiliser uniquement `OnePass M2 iPhone` (iPhone 18 Pro, iOS 27.0) et `OnePass M2 iPad` (iPad mini, iOS 27.0). Ne jamais démarrer, arrêter ou effacer un autre Simulateur : d'autres sessions s'en servent.
