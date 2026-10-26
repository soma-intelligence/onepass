# OnePass pour Apple (iPhone, iPad, Mac)

Les applications Apple s'appuient sur le coeur Rust (`core/onepass-ffi`, exposé par UniFFI) via le paquet Swift `VaultKit`. Ce dossier est le jalon 2 : création de compte, déverrouillage (mot de passe, Face ID, Touch ID, Apple Watch sur Mac), les 26 types d'items, vaults, recherche, synchronisation CloudKit et verrouillage automatique. Spec : `docs/superpowers/specs/2026-10-25-milestone-2-apps-design.md`. Sécurité : section "Jalon 2 : apps Apple" de [`docs/security/README.md`](../docs/security/README.md).

## Architecture

```
apple/
  project.yml               source du projet (XcodeGen)
  OnePass.xcodeproj         généré par `make project`, versionné
  Makefile                  core, test, project, build-ios, build-mac, uitest, screenshots
  scripts/build-core.sh     compile onepass-ffi, assemble l'XCFramework, génère les liaisons
  scripts/screenshots.sh    captures iPhone, iPad et Mac (données de démonstration)
  VaultKit/                 paquet Swift : liaisons UniFFI et logique Apple
  DesignKit/                paquet Swift : couleurs, icônes de catégorie, composants
  App/                      cible unique iOS, iPadOS et macOS natif (SwiftUI)
  AppUITests/               tests XCUITest (Simulateur iPhone)
```

Règle de frontière : seul le Rust manipule les clés. Swift reçoit des items déchiffrés pour l'affichage et l'édition, jamais une clé de vault, une clé d'item ni le keyset. Les seuls secrets côté Swift sont la Secret Key (Keychain) et l'AUK enveloppée par la Secure Enclave (Keychain).

**VaultKit** (`VaultKit/Sources/VaultKit`) :

- `OnePassFFI` (XCFramework) et `OnePassCore` (liaisons Swift générées) : ni l'un ni l'autre n'est versionné.
- `Session/` : `VaultSession`, la machine à états de l'app (`noAccount`, `locked`, `unlocking`, `unlocked`, `failed`), qui garde les vaults et les résumés d'items (aucun secret), charge un item complet à la demande et l'oublie au verrouillage ; recherche, filtres, verrouillage automatique (`AutoLock`), erreurs (`VaultError`, sans valeur de champ).
- `Keychain/` : `KeychainStore`, `SystemKeychain` (keychain à protection de données), `SecretKeyVault`, `InMemoryKeychain` pour les tests et la démonstration.
- `Biometrics/` : `BiometricUnlock` (AUK enveloppée par une clé P-256 de la Secure Enclave), politique des 14 jours et du redémarrage (`BiometricPolicy`).
- `Sync/` : protocole `RemoteRecordStore`, `SyncCoordinator` (acteur : envoi puis récupération, anti-rebond de 2 s), `CloudKitRemote` (base privée, zone `OnePass`), `InMemoryRemote` (faux serveur des tests, qui sait rejouer, retenir ou altérer).
- `Support/` : presse-papiers (90 s, local seulement), Emergency Kit (PDF avec QR code produit sur l'appareil), icônes de site, mode d'appareil, réglages locaux.
- `Editing/` : brouillon d'item (`ItemDraft`), saisie des nombres, force du mot de passe.

**DesignKit** : couleur d'accent, tuiles et symboles des 26 catégories, `ItemIcon`, `VaultBadge`, ligne de champ (Copier, Révéler, masquage après 30 s), jauge de force, compteur TOTP, bannière d'intégrité, états vides. Aucun élément de marque d'un autre gestionnaire.

**App** (`App/`) : `Root/` (`AppModel`, choix de l'écran, écran "Données refusées", vue de confidentialité), `Onboarding/`, `Lock/`, `Browse/` (Mac et iPad en `NavigationSplitView` 3 colonnes dans `Mac/`, onglets iPhone dans `Phone/`), `Item/` (détail et éditeur unique des 26 types, piloté par `template` et `menu_options` du core), `Vaults/`, `Settings/`. Textes en français dans `Resources/Localizable.xcstrings`.

Une seule fenêtre au jalon 2 : l'état de navigation et d'édition vit dans `AppModel`, unique par processus. Le Mac utilise une scène `Window`, l'iPad déclare `UIApplicationSupportsMultipleScenes` à `false`. Deux fenêtres de OnePass côte à côte (Stage Manager, Split View de l'app avec elle-même) attendent un état par scène.

## Prérequis

- Xcode 27 (SDK iOS 27, cibles de déploiement iOS 26.0 et macOS 26.0), Swift 6 en concurrence stricte.
- XcodeGen (`brew install xcodegen`).
- Toolchain Rust (`rustup`) avec les cibles `aarch64-apple-ios`, `aarch64-apple-ios-sim` et `aarch64-apple-darwin` :
  `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin`.

## Commandes

| Commande | Effet |
| --- | --- |
| `make -C apple core` | XCFramework livré et liaisons Swift (voir plus bas) |
| `make -C apple test` | tests Swift de `VaultKit` et `DesignKit` sur macOS, contre l'XCFramework de test |
| `make -C apple project` | régénère `OnePass.xcodeproj` depuis `project.yml` |
| `make -C apple build-ios` | build Simulateur non signé sur `OnePass M2 iPhone` |
| `make -C apple build-mac` | build Mac arm64 signé ad hoc (`CODE_SIGN_IDENTITY=-`), lançable localement |
| `make -C apple uitest` | tests XCUITest sur `OnePass M2 iPhone` (build signé ad hoc) |
| `make -C apple screenshots OUT=<dossier>` | captures iPhone, iPad et Mac dans `<dossier>` |
| `make -C apple simulators` | crée les deux Simulateurs dédiés s'ils manquent |
| `make -C apple clean` | supprime `build/`, `DerivedData/`, `.build` et les liaisons générées |

### Construire le coeur

```sh
make -C apple core
```

Produit `apple/build/OnePassFFI.xcframework` (tranches `ios-arm64`, `ios-arm64-simulator`, `macos-arm64`, profil `release`, jamais la fonctionnalité `dev-fast-kdf`) et génère les liaisons Swift dans `apple/VaultKit/Sources/OnePassCore/`. La commande est idempotente : rien n'est recompilé tant que les fichiers `.rs`, `Cargo.toml` et `Cargo.lock` sous `core/` n'ont pas changé (empreinte dans `apple/build/.core-stamp`).

Un clone neuf doit exécuter `make -C apple core` avant tout `swift build` ou ouverture du paquet : le XCFramework et les liaisons Swift générées ne sont pas versionnés.

### Tests Swift

```sh
make -C apple test
```

Construit d'abord un XCFramework de test distinct (`make -C apple core-test`) : macOS arm64 seulement, profil `debug` avec `dev-fast-kdf`, dans `apple/build/test/OnePassFFI.xcframework`. Il abaisse le coût Argon2id pour que les tests créent des comptes rapidement. `VaultKit/Package.swift` le choisit grâce à la variable d'environnement `ONEPASS_FFI_XCFRAMEWORK` (chemin relatif au dossier du paquet, SwiftPM refuse les chemins absolus ; défaut : `../build/OnePassFFI.xcframework`). Ce XCFramework de test ne doit jamais être livré.

Couverture : `VaultSession` (états, verrouillage automatique, verrouillage pendant un déverrouillage, filtres, recherche, mot de passe jamais rogné), `BiometricUnlock` contre une fausse Secure Enclave (14 jours, redémarrage, clé invalidée), `Clipboard`, `SyncCoordinator` à deux appareils contre `InMemoryRemote` (concurrence, conflit de manifeste, serveur qui retient un item ou altère un blob, réinitialisation de zone), `EmergencyKit` (PDF produit, QR décodable), `SiteIconLoader` (refus HTTP, taille maximale), `DesignKit`.

### Test UI

```sh
make -C apple uitest
```

`AppUITests/OnboardingAndItemUITests.swift`, sur `OnePass M2 iPhone` : lancement avec `-OnePassUITestReset YES`, création d'un compte avec le vrai Argon2id (256 Mio, aucun réglage rapide), Emergency Kit coché, biométrie "Plus tard" (étape absente sur un Simulateur sans Secure Enclave), ouverture ; nouvel élément Login "Exemple Atlas", identifiant `camille.durand@exemple.fr`, mot de passe généré ; la ligne apparaît, la recherche "atlas" la trouve ; verrouillage par le menu du compte, déverrouillage par le mot de passe maître, la ligne est toujours là. Les attentes liées à Argon2id vont jusqu'à 90 s. Le build du test est signé ad hoc (`CODE_SIGN_IDENTITY=-`) : une app iOS construite avec `CODE_SIGNING_ALLOWED=NO` n'a aucun accès au Keychain (`-34018`), sa Secret Key n'est pas enregistrée et le déverrouillage après verrouillage échoue. Le test ferme la feuille système "Enregistrer le mot de passe ?" que iOS peut afficher après l'enregistrement de l'item ("Not Now" ou "Pas maintenant"), limite du jalon 2 décrite plus bas. `AppUITests/ScreenshotUITests.swift` est ignoré (`XCTSkip`) hors du script de captures.

### Captures d'écran

```sh
make -C apple screenshots OUT=~/Desktop/onepass-captures
apple/scripts/screenshots.sh ~/Desktop/onepass-captures   # sans régénérer le projet
```

Le dossier de sortie est obligatoire et ne peut pas être dans le dépôt. Écrans : Bienvenue, verrouillé, liste, détail, édition, réglages, avec la base de démonstration (données fictives, mot de passe `demo-onepass-2026`).

- iPhone (`OnePass M2 iPhone`), clair et sombre ; iPad (`OnePass M2 iPad`) en paysage, clair et sombre : par `ScreenshotUITests`, qui tourne l'appareil et change l'apparence par XCUITest (`simctl` n'a pas de commande de rotation).
- Mac : `screencapture` est refusé sur la machine de développement, le script utilise le mode de capture Debug de l'app (`-OnePassSnapshot <dossier>`, `App/Root/Snapshot.swift`) qui dessine la fenêtre de l'app elle-même par `cacheDisplay`, sans permission d'enregistrement d'écran. L'app est sandboxée : les PNG arrivent dans `~/Library/Containers/me.somalabs.onepass/Data/tmp/OnePassSnapshot/`, puis le script les copie dans le dossier demandé.

## Projet Xcode

Sur un clone neuf, la première étape est toujours `make -C apple core` : Xcode résout les paquets Swift (qui lient l'XCFramework) dès l'ouverture du projet, avant toute phase de build.

```sh
make -C apple core
open apple/OnePass.xcodeproj
```

Une cible d'app `OnePass` (iPhone, iPad et Mac natif arm64, pas Catalyst) et une cible de tests UI `OnePassUITests` (iOS). `make project` lance `xcodegen generate` depuis `project.yml` ; le projet généré est versionné, il faut le régénérer après toute modification de `project.yml`. Une pré-action du schéma ("Build Rust core") lance `make -C apple core` si l'XCFramework manque. `build-ios`, `build-mac` et `uitest` utilisent le projet versionné sans le régénérer et créent les deux Simulateurs dédiés s'ils manquent. Les builds vont dans `apple/DerivedData` (ignoré par git).

Configurations : `Debug` et `Release` (non signées, sans CloudKit) ; `Release-CloudKit` (condition `ONEPASS_CLOUDKIT`, droits iCloud, groupe Keychain partagé et notifications push, `DEVELOPMENT_TEAM` à renseigner).

Conformité à l'export : l'app embarque sa propre cryptographie (`ITSAppUsesNonExemptEncryption` vaut `true`). La déclaration d'export (classification, éventuel document) est à régler par le fondateur avant toute soumission à l'App Store.

### Arguments de lancement (Debug seulement)

Compilés seulement en Debug (`#if DEBUG`), absents des builds Release.

- `-OnePassUITestReset YES` : efface la base, les réglages et les éléments Keychain de l'app avant tout.
- `-OnePassDemoData YES` : compte de démonstration dans une base temporaire (Camille Durand, mot de passe `demo-onepass-2026`), items fictifs des 26 types dans trois vaults (Personnel, Projet Atlas, Famille), Secret Key dans un Keychain en mémoire, réglages dans leur propre suite, aucune sync. Avec : `-OnePassDemoItem <titre>`, `-OnePassDebugEdit YES`, `-OnePassDemoLocked YES`, `-OnePassDemoTab items|watchtower|search`, `-OnePassDemoQuery <texte>`, `-OnePassDemoSettings YES` et `-OnePassDemoSettingsPage <page>`, `-OnePassDemoVaultEditor YES`, `-OnePassDemoSidebar YES` (iPad), `-OnePassDemoLandscape YES` (iPad, refusé par le système dans les modes de fenêtrage de iPadOS 26).
- `-OnePassSnapshot <dossier>` (Mac) : données de démonstration, PNG de la fenêtre en clair et en sombre, puis l'app quitte.
- `-OnePassOnboardingStep device|password|restore` : ouvre directement une étape de l'onboarding.
- `-OnePassDebugSeedAccount YES` : crée un compte fictif puis verrouille. `-OnePassDebugItem login|card|note|reward`, `-OnePassDebugAutoSave YES`, `-OnePassDebugGenerator YES` : voir `App/Root/DebugItems.swift`.

## Build non signé ou signé

- Build non signé (local seulement) : sans équipe de développement ni droits iCloud, l'app tourne en stockage local et l'affiche dans les réglages ("Non (build local)"). La synchronisation CloudKit est désactivée (ruling R8). Sur Mac, le Keychain sans droit d'accès (erreur `-34018`) se replie sur le trousseau classique, en Debug seulement. Sur le Simulateur iOS, un build sans aucune signature (`make build-ios`, `CODE_SIGNING_ALLOWED=NO`) n'a pas de Keychain du tout : la création de compte y est refusée ("Impossible de ranger la Secret Key dans le trousseau de cet appareil. Le coffre n'a pas été créé.") et la restauration annulée. Ce build sert à vérifier la compilation ; pour lancer l'app, la signer ad hoc (`CODE_SIGN_IDENTITY=-`), comme `make uitest` et le script de captures.
- Build signé (`Release-CloudKit`) : avec une équipe et les droits `iCloud.me.somalabs.onepass` et le groupe Keychain `me.somalabs.onepass.shared`, la synchronisation CloudKit est active. Sans compte iCloud connecté, la création et la restauration de compte s'arrêtent avec un message ("Connecte-toi à iCloud dans Réglages pour créer ton coffre.") au lieu de créer un compte local seulement.

## Simulateurs dédiés

Utiliser uniquement `OnePass M2 iPhone` (iPhone 18 Pro, iOS 27.0) et `OnePass M2 iPad` (iPad mini, iOS 27.0). Ne jamais démarrer, arrêter ou effacer un autre Simulateur : d'autres sessions s'en servent.

## Limites du jalon 2

Hors périmètre (spec, section 12) :

- AutoFill système, passkeys et TOTP dans le champ : jalon 3.
- Extension de navigateur : jalon 4.
- Watchtower (onglet présent avec un état vide), pack d'icônes de marques, import, export, sauvegarde, pièces jointes : jalon 5.
- Apple Watch (app), Vision Pro, widgets, Contrôles, Raccourcis, Spotlight, Handoff : jalon 6.
- MCP, agent SSH, génération de clés SSH, Travel Mode : jalon 7.
- Changement du mot de passe maître, suppression de vault, option Secret Key dans le trousseau iCloud.

Décisions qui limitent ce jalon (spec, section 13) :

- **R1** : pas de connexion par QR code entre appareils ("J'ai déjà OnePass sur un autre appareil" est grisé "Bientôt"). Un nouvel appareil passe par l'Emergency Kit. Reporté au jalon 2b "Appairage et appareils", avec la liste signée des appareils et la révocation.
- **R2** : pas de mode public (session déléguée), aussi au jalon 2b. Les modes personnel et partagé sont livrés.
- **R8** : CloudKit n'est compilé dans l'app que pour la configuration signée `Release-CloudKit`. Aucune équipe Apple n'était disponible : la sync réelle n'a pas été vérifiée, seulement la logique contre `InMemoryRemote` et les tests Rust à deux appareils. À vérifier en build signé avant le lancement.
- **R9** : pas de pièces jointes. Le champ fichier est en lecture seule ("Pièces jointes au jalon 5"). Un Document s'enregistre sans fichier : son champ fichier requis vide est stocké non requis, le jalon 5 devra rétablir l'exigence.
- **R12** : pas de changement du mot de passe maître (le core n'a pas encore de rotation du keyset et des paramètres signés). À livrer avant le lancement.
- **R14** : pas de suppression de vault, seulement création et renommage. Sans liste signée des vaults, un vault supprimé ressemblerait pour les autres appareils à un vault masqué par le serveur (`VaultMissing`).

Autres limites connues :

- Une seule fenêtre (voir Architecture).
- iOS peut proposer "Enregistrer le mot de passe ?" (mots de passe du système) après l'enregistrement d'un Login : il faut refuser. Corrigé au jalon 3, quand OnePass devient le fournisseur de remplissage automatique.
- Pas de liste "À proximité" ni de géofences sur l'Accueil (R11).
- Mac : pas de scan du QR de l'Emergency Kit, la Secret Key se tape (R19).
- Une modification locale d'un item supprimé sur un autre appareil le fait revenir (une suppression ne porte pas de date) ; un déplacement local concurrent d'une modification distante peut laisser l'item dans les deux vaults, sans perte.
- Une réinitialisation de la zone iCloud (zone supprimée) est réparée par le prochain appareil qui synchronise, qui renvoie tout son contenu : un effacement volontaire des données iCloud est donc défait. Un vrai réglage "Effacer les données iCloud" arrive au jalon 5.
