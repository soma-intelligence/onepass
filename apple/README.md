# OnePass pour Apple (iPhone, iPad, Mac, Apple Watch, Vision Pro)

Les applications Apple s'appuient sur le coeur Rust (`core/onepass-ffi`, exposé par UniFFI) via le paquet Swift `VaultKit`. Ce dossier est le jalon 2 : création de compte, déverrouillage (mot de passe, Face ID, Touch ID, Apple Watch sur Mac), les 26 types d'items, vaults, recherche, synchronisation CloudKit et verrouillage automatique. Spec : `docs/superpowers/specs/2026-10-25-milestone-2-apps-design.md`. Sécurité : section "Jalon 2 : apps Apple" de [`docs/security/README.md`](../docs/security/README.md).

Le jalon 6 ajoute l'app Apple Watch, l'app Vision Pro, les widgets, les Contrôles et les Raccourcis (voir "Jalon 6" plus bas). Spec : `docs/superpowers/specs/2026-10-26-milestone-6-watch-vision-design.md`. Sécurité : section 12 de [`docs/security/README.md`](../docs/security/README.md).

## Architecture

```
apple/
  project.yml               source du projet (XcodeGen)
  OnePass.xcodeproj         généré par `make project`, versionné
  Makefile                  core, test, project, build-ios, build-mac, build-watch, build-vision,
                            uitest, screenshots, screenshots-m6
  scripts/build-core.sh     compile onepass-ffi, assemble l'XCFramework, génère les liaisons
  scripts/screenshots.sh    captures iPhone, iPad et Mac (données de démonstration)
  scripts/screenshots-m6.sh captures Apple Watch et Vision Pro (données fictives)
  VaultKit/                 paquet Swift : liaisons UniFFI et logique Apple
  DesignKit/                paquet Swift : couleurs, icônes de catégorie, composants
  CompanionKit/             paquet Swift : widgets (GlanceKit) et lien iPhone-montre (CompanionLink)
  App/                      cible unique iOS, iPadOS, macOS natif et visionOS (SwiftUI)
  Watch/                    app watchOS (cible OnePassWatch)
  WatchWidgets/             complication et Smart Stack (cible OnePassWatchWidgets)
  Widgets/                  widgets et Contrôles iOS (cible OnePassWidgets)
  AppUITests/               tests XCUITest (Simulateur iPhone)
```

Règle de frontière : seul le Rust manipule les clés. Swift reçoit des items déchiffrés pour l'affichage et l'édition, jamais une clé de vault, une clé d'item ni le keyset. Les seuls secrets côté Swift sont la Secret Key (Keychain) et l'AUK enveloppée par la Secure Enclave (Keychain).

**VaultKit** (`VaultKit/Sources/VaultKit`) :

- `OnePassFFI` (XCFramework) et `OnePassCore` (liaisons Swift générées) : ni l'un ni l'autre n'est versionné.
- `Session/` : `VaultSession`, la machine à états de l'app (`noAccount`, `locked`, `unlocking`, `unlocked`, `failed` ; un compte connu de l'appareil mais disparu de la base donne `failed(.integrity("account_missing"))`, jamais `noAccount` ; `resetForRecovery()` en sort vers la restauration ou l'accueil), qui garde les vaults et les résumés d'items (aucun secret), charge un item complet à la demande et l'oublie au verrouillage ; recherche, filtres, verrouillage automatique (`AutoLock`), erreurs (`VaultError`, sans valeur de champ).
- `Keychain/` : `KeychainStore`, `SystemKeychain` (keychain à protection de données), `SecretKeyVault`, `InMemoryKeychain` pour les tests et la démonstration.
- `Biometrics/` : `BiometricUnlock` (AUK enveloppée par une clé P-256 de la Secure Enclave), politique des 14 jours et du redémarrage (`BiometricPolicy`).
- `Sync/` : protocole `RemoteRecordStore`, `SyncCoordinator` (acteur : envoi puis récupération, anti-rebond de 2 s ; la base est liée au compte iCloud du premier tour, un autre compte arrête la sync avec l'état "Le compte iCloud a changé" jusqu'à `acceptAccountChange()`, qui vérifie d'abord la zone ; identité revérifiée avant l'envoi seulement après `CKAccountChanged` ou 10 min ; nombre de suppressions refusées), `CloudKitRemote` (base privée, zone `OnePass`, identité par `userRecordID`, compteur de `CKAccountChanged`), `InMemoryRemote` (faux serveur des tests, qui sait rejouer, retenir, altérer, forger une suppression et changer de compte, y compris entre la récupération et l'envoi).
- `Support/` : presse-papiers (90 s, local seulement), Emergency Kit (PDF avec QR code produit sur l'appareil), icônes de site (noms locaux refusés, adresses résolues vérifiées par `HostResolver`), mode d'appareil, réglages locaux.
- `Editing/` : brouillon d'item (`ItemDraft`), saisie des nombres, force du mot de passe.

**DesignKit** : couleur d'accent, tuiles et symboles des 26 catégories, `ItemIcon`, `VaultBadge`, ligne de champ (Copier, Révéler, masquage après 30 s), jauge de force, compteur TOTP, bannière d'intégrité, états vides. Aucun élément de marque d'un autre gestionnaire.

**App** (`App/`) : `Root/` (`AppModel`, choix de l'écran, écran "Données refusées", vue de confidentialité), `Onboarding/`, `Lock/`, `Browse/` (Mac et iPad en `NavigationSplitView` 3 colonnes dans `Mac/`, onglets iPhone dans `Phone/`), `Item/` (détail et éditeur unique des 26 types, piloté par `template` et `menu_options` du core), `Vaults/`, `Settings/`. Textes en français dans `Resources/Localizable.xcstrings`.

Une seule fenêtre au jalon 2 : l'état de navigation et d'édition vit dans `AppModel`, unique par processus. Le Mac utilise une scène `Window`, l'iPad déclare `UIApplicationSupportsMultipleScenes` à `false`. Deux fenêtres de OnePass côte à côte (Stage Manager, Split View de l'app avec elle-même) attendent un état par scène.

## Prérequis

- Xcode 27 (SDK iOS 27, cibles de déploiement iOS 26.0, macOS 26.0, watchOS 26.0 et visionOS 26.0), Swift 6 en concurrence stricte. Pour la montre et le Vision Pro : runtimes Simulateur watchOS 27 et visionOS 27 (`xcodebuild -downloadPlatform visionOS`, environ 8 Go).
- XcodeGen (`brew install xcodegen`).
- Toolchain Rust (`rustup`) avec les cibles `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin`, `aarch64-apple-watchos`, `aarch64-apple-watchos-sim`, `aarch64-apple-visionos` et `aarch64-apple-visionos-sim` :
  `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-watchos aarch64-apple-watchos-sim aarch64-apple-visionos aarch64-apple-visionos-sim`.

## Commandes

| Commande | Effet |
| --- | --- |
| `make -C apple core` | XCFramework livré et liaisons Swift (voir plus bas) |
| `make -C apple test` | tests Swift de `VaultKit`, `DesignKit` et `CompanionKit` sur macOS, contre l'XCFramework de test |
| `make -C apple project` | régénère `OnePass.xcodeproj` depuis `project.yml` |
| `make -C apple build-ios` | build Simulateur non signé sur `OnePass M2 iPhone` |
| `make -C apple build-mac` | build Mac arm64 signé ad hoc (`CODE_SIGN_IDENTITY=-`), lançable localement |
| `make -C apple build-watch` | build Simulateur watchOS de l'app montre et de sa complication sur `OnePass M6 Watch`, signé ad hoc |
| `make -C apple build-vision` | build Simulateur visionOS de l'app sur `OnePass M6 Vision Pro` (destination générique si ce Simulateur n'existe pas), signé ad hoc |
| `make -C apple uitest` | tests XCUITest sur `OnePass M2 iPhone` (build signé ad hoc) |
| `make -C apple screenshots OUT=<dossier>` | captures iPhone, iPad et Mac dans `<dossier>` |
| `make -C apple screenshots-m6 OUT=<dossier>` | captures Apple Watch et Vision Pro dans `<dossier>` |
| `make -C apple simulators` | crée les deux Simulateurs dédiés s'ils manquent |
| `make -C apple simulators-m6` | crée `OnePass M6 Watch` et `OnePass M6 Vision Pro` s'ils manquent (le second seulement si le runtime visionOS 27 est installé) |
| `make -C apple clean` | supprime `build/`, `DerivedData/`, `.build` et les liaisons générées |

### Construire le coeur

```sh
make -C apple core
```

Produit `apple/build/OnePassFFI.xcframework` (tranches `ios-arm64`, `ios-arm64-simulator`, `macos-arm64`, `watchos-arm64`, `watchos-arm64-simulator`, `xros-arm64`, `xros-arm64-simulator`, profil `release`, jamais la fonctionnalité `dev-fast-kdf`) et génère les liaisons Swift dans `apple/VaultKit/Sources/OnePassCore/`. La commande est idempotente : rien n'est recompilé tant que les fichiers `.rs`, `Cargo.toml` et `Cargo.lock` sous `core/` n'ont pas changé (empreinte dans `apple/build/.core-stamp`).

Un clone neuf doit exécuter `make -C apple core` avant tout `swift build` ou ouverture du paquet : le XCFramework et les liaisons Swift générées ne sont pas versionnés.

### Tests Swift

```sh
make -C apple test
```

Construit d'abord un XCFramework de test distinct (`make -C apple core-test`) : macOS arm64 seulement, profil `debug` avec `dev-fast-kdf`, dans `apple/build/test/OnePassFFI.xcframework`. Il abaisse le coût Argon2id pour que les tests créent des comptes rapidement. `VaultKit/Package.swift` le choisit grâce à la variable d'environnement `ONEPASS_FFI_XCFRAMEWORK` (chemin relatif au dossier du paquet, SwiftPM refuse les chemins absolus ; défaut : `../build/OnePassFFI.xcframework`). Ce XCFramework de test ne doit jamais être livré.

Couverture : `VaultSession` (états, verrouillage automatique, verrouillage pendant un déverrouillage, filtres, recherche, mot de passe jamais rogné), `BiometricUnlock` contre une fausse Secure Enclave (14 jours, redémarrage, clé invalidée), `Clipboard`, `SyncCoordinator` à deux appareils contre `InMemoryRemote` (concurrence, conflit de manifeste, serveur qui retient un item ou altère un blob, réinitialisation de zone), `EmergencyKit` (PDF produit, QR décodable), `SiteIconLoader` (refus HTTP, taille maximale, noms locaux, adresses privées par un résolveur injecté), changement de compte iCloud (trois cas de zone, identité changée entre récupération et envoi), sortie du "compte disparu", journal des suppressions refusées, `DesignKit`.

### Test UI

```sh
make -C apple uitest
```

`AppUITests/OnboardingAndItemUITests.swift`, sur `OnePass M2 iPhone` : lancement avec `-OnePassTestIsolation YES -OnePassUITestReset YES` (base, réglages et service Keychain de test), création d'un compte avec le vrai Argon2id (256 Mio, aucun réglage rapide), Emergency Kit coché, biométrie "Plus tard" (étape absente sur un Simulateur sans Secure Enclave), ouverture ; nouvel élément Login "Exemple Atlas", identifiant `camille.durand@exemple.fr`, mot de passe généré ; la ligne apparaît, la recherche "atlas" la trouve ; verrouillage par le menu du compte : l'écran verrouillé n'a qu'un champ, le mot de passe maître (aucun champ Secret Key) ; déverrouillage, la ligne est toujours là ; puis l'app est relancée sur la même base de test : même écran à un seul champ, déverrouillage. Les attentes liées à Argon2id vont jusqu'à 90 s. Le build du test est signé ad hoc (`CODE_SIGN_IDENTITY=-`) : une app iOS construite avec `CODE_SIGNING_ALLOWED=NO` n'a aucun accès au Keychain (`-34018`), sa Secret Key n'est pas enregistrée et le déverrouillage après verrouillage échoue. Le test ferme la feuille système "Enregistrer le mot de passe ?" que iOS peut afficher après l'enregistrement de l'item ("Not Now" ou "Pas maintenant"), limite du jalon 2 décrite plus bas. `AppUITests/ScreenshotUITests.swift` est ignoré (`XCTSkip`) hors du script de captures.

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

- `-OnePassTestIsolation YES` : l'app utilise sa base de test (`<tmp>/OnePassUITest`), la suite de réglages `me.somalabs.onepass.uitest` et le service Keychain `me.somalabs.onepass.uitest`, jamais la base, les réglages ni les Secret Keys de l'utilisateur ; ni sync, ni widgets, ni montre. Les tests UI le passent toujours.
- `-OnePassUITestReset YES` (avec `-OnePassTestIsolation YES` seulement, ignoré sinon) : vide la base, la suite et le service Keychain de test avant tout. Les tests UI finissent par un lancement avec ce drapeau pour nettoyer.
- `-OnePassDemoData YES` : compte de démonstration dans une base temporaire (Camille Durand, mot de passe `demo-onepass-2026`), items fictifs des 26 types dans trois vaults (Personnel, Projet Atlas, Famille), Secret Key dans un Keychain en mémoire, réglages dans leur propre suite, aucune sync. Avec : `-OnePassDemoItem <titre>`, `-OnePassDebugEdit YES`, `-OnePassDemoLocked YES`, `-OnePassDemoAccountMissing YES` (écran "compte disparu" et ses actions), `-OnePassDemoAccountChanged YES` (bandeau "Le compte iCloud a changé"), `-OnePassDemoTab items|watchtower|search`, `-OnePassDemoQuery <texte>`, `-OnePassDemoSettings YES` et `-OnePassDemoSettingsPage <page>`, `-OnePassDemoVaultEditor YES`, `-OnePassDemoSidebar YES` (iPad), `-OnePassDemoLandscape YES` (iPad, refusé par le système dans les modes de fenêtrage de iPadOS 26).
- `-OnePassSnapshot <dossier>` (Mac) : données de démonstration, PNG de la fenêtre en clair et en sombre, puis l'app quitte.
- `-OnePassOnboardingStep device|password|restore` : ouvre directement une étape de l'onboarding.
- `-OnePassDebugSeedAccount YES` : crée un compte fictif dans la base de test (l'isolation est forcée) puis verrouille. `-OnePassDebugItem login|card|note|reward` et `-OnePassDebugNewItem <type>` (isolation forcée aussi), `-OnePassDebugAutoSave YES`, `-OnePassDebugGenerator YES` : voir `App/Root/DebugItems.swift`.

## Build non signé ou signé

- Build non signé (local seulement) : sans équipe de développement ni droits iCloud, l'app tourne en stockage local et l'affiche dans les réglages ("Non (build local)"). La synchronisation CloudKit est désactivée (ruling R8). Sur Mac, le Keychain sans droit d'accès refuse l'écriture (`-34018`) mais répond "introuvable" (`-25300`) aux lectures : en Debug seulement, l'écriture se replie sur le trousseau classique et chaque lecture qui ne trouve rien dans le Keychain à protection de données y regarde aussi. Après chaque nouveau build ad hoc, macOS peut demander l'autorisation de lire l'élément créé par le build précédent ("Toujours autoriser"). Sur le Simulateur iOS, un build sans aucune signature (`make build-ios`, `CODE_SIGNING_ALLOWED=NO`) n'a pas de Keychain du tout : la création de compte y est refusée ("Impossible de ranger la Secret Key dans le trousseau de cet appareil. Le coffre n'a pas été créé.") et la restauration annulée. Ce build sert à vérifier la compilation ; pour lancer l'app, la signer ad hoc (`CODE_SIGN_IDENTITY=-`), comme `make uitest` et le script de captures.
- Build signé (`Release-CloudKit`) : avec une équipe et les droits `iCloud.me.somalabs.onepass` et le groupe Keychain `me.somalabs.onepass.shared`, la synchronisation CloudKit est active. Sans compte iCloud connecté, la création et la restauration de compte s'arrêtent avec un message ("Connecte-toi à iCloud dans Réglages pour créer ton coffre.") au lieu de créer un compte local seulement.
- Build Mac signé sans CloudKit (`Release-Signed`) : un Mac Release distribué doit être signé avec une configuration provisionnée qui porte `keychain-access-groups` (`$(AppIdentifierPrefix)me.somalabs.onepass.shared`) : `Release-CloudKit`, ou `Release-Signed` (même groupe Keychain, sans iCloud ni push ; fichiers `App/Support/OnePass-Signed-macOS.entitlements` et `OnePass-Signed-iOS.entitlements`, `DEVELOPMENT_TEAM` à renseigner). Ce droit est restreint : un build ad hoc qui le porterait refuserait de se lancer, c'est pourquoi `OnePass.entitlements` (Debug et Release ad hoc) ne l'a pas. Sans lui, un build Release n'a pas de repli vers le trousseau classique : la création de compte y est refusée proprement.

## Simulateurs dédiés

Utiliser uniquement `OnePass M2 iPhone` (iPhone 18 Pro, iOS 27.0), `OnePass M2 iPad` (iPad mini, iOS 27.0), `OnePass M6 Watch` (Apple Watch Series 12 46 mm, watchOS 27.0) et `OnePass M6 Vision Pro` (Apple Vision Pro, visionOS 27.0, ruling W16). Ne jamais démarrer, arrêter ou effacer un autre Simulateur : d'autres sessions s'en servent.

## Limites du jalon 2

Hors périmètre (spec, section 12) :

- AutoFill système, passkeys et TOTP dans le champ : jalon 3.
- Extension de navigateur : jalon 4.
- Watchtower (onglet présent avec un état vide), pack d'icônes de marques, import, export, sauvegarde, pièces jointes : jalon 5.
- Apple Watch (app), Vision Pro, widgets, Contrôles, Raccourcis, Spotlight, Handoff : jalon 6 (Apple Watch, Vision Pro, widgets, Contrôles et Raccourcis livrés, voir Jalon 6).
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

- Changement de compte iCloud : la sync s'arrête ("Le compte iCloud a changé") jusqu'au retour du compte d'origine ou à "Utiliser ce compte iCloud" (bandeau et Réglages > Sync), refusé si ce compte contient déjà un autre coffre (ruling E23). Un changement non signalé par le système entre la récupération et l'envoi d'un même tour, dans les 10 min, n'est vu qu'au tour suivant (ruling E24).
- Icônes de site : la vérification des adresses précède la connexion, que le système résout de nouveau ; la fenêtre de DNS rebinding est acceptée (ruling E26).
- iOS : une app suspendue garde ses clés en mémoire jusqu'au retour au premier plan ou au prochain réveil par notification, si le délai de verrouillage dépasse le temps d'arrière-plan accordé par le système.

- Une seule fenêtre (voir Architecture).
- iOS peut proposer "Enregistrer le mot de passe ?" (mots de passe du système) après l'enregistrement d'un Login : il faut refuser. Corrigé au jalon 3, quand OnePass devient le fournisseur de remplissage automatique.
- Pas de liste "À proximité" ni de géofences sur l'Accueil (R11).
- Mac : pas de scan du QR de l'Emergency Kit, la Secret Key se tape (R19).
- Une modification locale d'un item supprimé sur un autre appareil le fait revenir (une suppression ne porte pas de date) ; un déplacement local concurrent d'une modification distante peut laisser l'item dans les deux vaults, sans perte.
- Une réinitialisation de la zone iCloud (zone supprimée) est réparée par le prochain appareil qui synchronise, qui renvoie tout son contenu : un effacement volontaire des données iCloud est donc défait. Un vrai réglage "Effacer les données iCloud" arrive au jalon 5.

## Jalon 6 : Apple Watch, Vision Pro, widgets, Contrôles et Raccourcis

Spec : `docs/superpowers/specs/2026-10-26-milestone-6-watch-vision-design.md` (décisions W1 à W18 en section 14, rulings d'exécution en section 15). Modèle de sécurité : section 12 de [`docs/security/README.md`](../docs/security/README.md).

### Cibles

| Cible | Plateforme | Identifiant | Contenu |
| --- | --- | --- | --- |
| `OnePass` | iOS, iPadOS, macOS, visionOS | `me.somalabs.onepass` | l'app ; sur iOS elle embarque la montre et les widgets |
| `OnePassWatch` | watchOS | `me.somalabs.onepass.watchkitapp` | app montre autonome en lecture (`Watch/`) |
| `OnePassWatchWidgets` | watchOS | `me.somalabs.onepass.watchkitapp.widgets` | complication (circulaire, coin, rectangulaire) et Smart Stack : symbole et nom, ouvrent l'app, jamais de secret |
| `OnePassWidgets` | iOS, iPadOS | `me.somalabs.onepass.widgets` | widgets "Codes" et "Favoris", Contrôles "Générer un mot de passe", "Rechercher dans OnePass", "Verrouiller OnePass" |

Les cibles watchOS ne construisent que `arm64` (Simulateur compris, ruling E8) : un Mac Intel ne peut pas construire l'app montre pour le Simulateur. Les montres dont watchOS 26 tourne en `arm64_32` seulement ne sont pas prises en charge (W3).

### Paquet `CompanionKit`

- **`GlanceKit`** (aucune dépendance, utilisé par l'app et l'extension de widgets) : `GlanceSnapshot` (favoris et codes TOTP précalculés, symboles et couleurs de catégorie), `GlanceStore` (fichier `Library/OnePass/glance.json` du conteneur App Group `group.me.somalabs.onepass`, écriture atomique en `completeFileProtection` ; `status(now:)` distingue "verrouillé", fichier présent mais illisible, de "périmé", absent, expiré ou corrompu, ruling E10), `OnePassLink` (`onepass://item?vault=<hex>&item=<hex>`, `onepass://generator`, `onepass://search`, tout le reste est refusé), `LockSignal` (notification Darwin `me.somalabs.onepass.lock-request` et horodatage dans les réglages partagés).
- **`CompanionLink`** (dépend de `OnePassCore`, les liaisons seules) : messages `CompanionMessage` (`watchKey`, `payload`, `wipe`, `refreshRequest`), protocole `CompanionTransport`, `WatchConnectivityTransport` (iOS et watchOS seulement, E6), `InMemoryTransport` (tests), `PhoneCompanion` (côté iPhone), `WatchVault` (côté montre), `WatchKeyStore` (Keychain système, service `me.somalabs.onepass.watch`, et version en mémoire).

`make -C apple test` lance `swift test` sur `CompanionKit` contre l'XCFramework de test : `GlanceStore` (écriture, lecture, périmé, illisible), `OnePassLink`, `LockSignal`, et `PhoneCompanion` avec `WatchVault` reliés par `InMemoryTransport` avec le vrai core (clé envoyée, envoi après changement, rejeu refusé, effacement, clé remplacée, clé effacée qui revient, montre sans code, montre verrouillée pendant un envoi).

### Apple Watch

- Côté iPhone, `App/Companion/CompanionCoordinator.swift` publie, 2 s après le dernier changement et seulement pendant que le coffre est déverrouillé (déverrouillage, écriture, changement distant, retour au premier plan), l'instantané des widgets puis la charge utile de la montre. Réglages > Apple Watch (iPhone) : "Envoyer à l'Apple Watch" (activé par défaut), état ("Prête", "Aucune Apple Watch appairée", "Installe OnePass sur ton Apple Watch"), "Dernier envoi", limite de 50 éléments (W18), liste des champs envoyés, "Retirer de l'Apple Watch". Sur iPad, la ligne affiche "Non disponible sur cet appareil" (E14). Un élément se marque « Sur l'Apple Watch » dans son éditeur.
- Côté montre : la clé secrète vit dans le Keychain de la montre, la charge utile scellée dans `Application Support/OnePass/companion.sealed` (protection `Complete`). L'objet Rust `CompanionVault`, seul détenteur des graines TOTP, n'existe que pendant que l'app est au premier plan. Écrans : liste ("Codes" avec compte à rebours, puis "Éléments"), détail (champ masqué révélé d'un toucher, remasqué après 30 s), messages "Active un code sur ton Apple Watch pour utiliser OnePass", "Déverrouille ton Apple Watch pour ouvrir OnePass." (E9) et l'état vide. Codes-barres affichés en texte (W8).

### Widgets, Contrôles et Raccourcis

- Widgets (iPhone et iPad seulement, W5) : "Codes" (petit, moyen, grand, accessoire rectangulaire ; une entrée par 30 s sur 1 h) et "Favoris" (petit, moyen), sur les 8 premiers favoris par titre (W6). Codes calculés pour 12 h par l'app (W4) ; au-delà, "Ouvre OnePass pour actualiser" ; appareil verrouillé, "Déverrouille ton iPhone". Titres et codes en `.privacySensitive()`.
- Contrôles : "Générer un mot de passe" et "Rechercher dans OnePass" ouvrent l'app par lien profond ; "Verrouiller OnePass" poste `LockSignal` depuis l'extension (W12) : l'app en cours verrouille tout de suite, sinon à son retour au premier plan.
- App Intents (`App/Intents/`, iPhone, iPad, Mac, Vision Pro) : "Ouvrir un élément", "Copier le code à usage unique" (authentification fraîche, copie par le presse-papiers OnePass, aucun code rendu au raccourci, W13 et E15), "Générer un mot de passe" (8 à 64 caractères, 20 par défaut, symboles ; sans ouvrir l'app, W14), "Verrouiller OnePass". Phrases Siri en français dans `OnePassShortcuts`. Les titres des éléments ne sont jamais donnés à l'index de Siri (E16) : il faut choisir l'élément dans Raccourcis.

### Vision Pro

La cible `OnePass` avec la destination visionOS (W15) : mise en page iPad (`NavigationSplitView` à trois colonnes), fenêtre en verre du système sans fond opaque, cartes de verrouillage et d'onboarding en `.glassBackgroundEffect()`, barres d'outils en ornements, `.hoverEffect()` sur les lignes et boutons, fenêtre par défaut 1280 × 820 points. Optic ID passe par la même clé de la Secure Enclave ; les styles de bouton `.glass` absents de visionOS sont remplacés par des styles bordés (`App/Root/VisionGlass.swift`, E19). Pas de scan du QR de l'Emergency Kit : la Secret Key se tape. Pas de widgets ni de Contrôles, pas de montre (aucune montre appairée à un Vision Pro).

### Arguments de lancement du jalon 6 (Debug seulement)

- Montre : `-OnePassWatchDemo YES` affiche des entrées fictives (Forge Atlas avec un TOTP, Wi-Fi Maison, Carte Bibliothèque, Banque Exemple) depuis une source Swift en mémoire, sans clé. Aucun argument n'ouvre un détail.
- App (Vision Pro compris) : `-OnePassDemoData YES`, et `-OnePassDemoItem <titre>` pour ouvrir un détail (par exemple `"Forge Atlas"`), comme au jalon 2. Le mode démonstration ne relie jamais la montre (E13).

### Captures du jalon 6

```sh
make -C apple screenshots-m6 OUT=~/Desktop/onepass-captures-m6
apple/scripts/screenshots-m6.sh ~/Desktop/onepass-captures-m6   # sans passer par make
```

Le dossier de sortie est obligatoire et ne peut pas être dans le dépôt. Le script construit l'app montre et l'app visionOS (Debug, signées ad hoc, dans `apple/DerivedData`), démarre seulement `OnePass M6 Watch` et `OnePass M6 Vision Pro` si besoin, installe, lance avec les arguments de démonstration, capture par `simctl io screenshot`, puis rend à chaque Simulateur son apparence et arrête ceux qu'il a démarrés. Fichiers : `watch-list.png` (watchOS n'a qu'une apparence, sombre, et refuse `simctl ui appearance`), `vision-list-light.png`, `vision-list-dark.png`, `vision-detail-light.png`, `vision-detail-dark.png` (visionOS accepte le réglage, mais la fenêtre en verre est identique dans les deux). Attentes réglables par `WATCH_WAIT` et `VISION_WAIT` (secondes).

### Ce qui demande un build signé ou un vrai appareil

Rien de ce qui suit n'a été vérifié au jalon 6 (spec, section 13) :

- WatchConnectivity entre une vraie montre et un iPhone : envoi de la clé, de la charge utile, de l'effacement, et la montre verrouillée pendant un envoi. La logique est couverte par les tests contre `InMemoryTransport`.
- App Group et protection de données des widgets : un build non signé n'a pas d'App Group, l'app ne publie alors aucun instantané et les widgets restent sur "Ouvre OnePass pour actualiser". La classe `NSFileProtectionComplete` n'a d'effet que sur un vrai appareil.
- Affichage des widgets et Contrôles sur l'écran d'accueil, l'écran verrouillé, en StandBy et sur le bouton Action ; masquage `.privacySensitive()`.
- Optic ID (le Simulateur visionOS n'a pas de Secure Enclave) ; l'invite système affiche le texte Face ID (E18).
- Phrases Siri et "Copier le code à usage unique" dans ses trois états (verrouillé, déverrouillé, sans code de l'appareil) : vérification à l'exécution non faite.
- Keychain de la montre en `WhenPasscodeSetThisDeviceOnly` et détection du poignet.
- Vision Pro : vue de confidentialité (opaque, E20) et icône sur l'écran d'accueil.
- Signature `Release-CloudKit` : sur iOS, le fichier de droits CloudKit porte aussi l'App Group (E11) ; à fusionner avec le jalon 3, qui utilise le même groupe (W17).
- Signature `Release-CloudKit` de l'app montre et de ses widgets (`OnePassWatch`, `OnePassWatchWidgets`) : signature automatique `Apple Development`, comme `OnePassWidgets`, pour que l'app iPhone signée n'embarque pas une app montre signée ad hoc ; `DEVELOPMENT_TEAM` à renseigner.

### Limites du jalon 6

- Montre : 50 éléments au plus, 1 Kio par valeur (W18) ; jamais le mot de passe d'un Login, le CVV, le PIN, le numéro complet d'une carte ni les notes (W9) ; codes-barres en texte (W8) ; aucun compteur des éléments marqués dans les réglages (E12). Verrouiller l'iPhone n'efface pas la montre. Sans détection du poignet, seul le code de la montre protège ses données.
- Items "redemander la biométrie" exclus de la montre et des widgets (W7). Coffres masqués exclus des deux.
- Widgets : seulement les 8 premiers favoris par titre ; un TOTP non favori n'y est pas (W6) ; codes valables 12 h (W4). Un widget peut afficher l'état verrouillé jusqu'à son prochain rafraîchissement après le déverrouillage.
- Pas de widgets Mac ni visionOS (W5), pas de Spotlight ni de Handoff (W10), pas de Contrôle "Scanner un QR TOTP" (W11), pas de widget "À proximité" (R11).
- Vision Pro : le titre de la colonne de liste est tronqué ("Tous les él...") quand la fenêtre est à sa taille par défaut.
