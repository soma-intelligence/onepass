# Jalon 6 : Apple Watch, Vision Pro, widgets, Contrôles et Raccourcis

Date : 2026-10-26
Statut : approuvée (auto-approbation, voir section 14)
Portée : section 13, point 6 de la spec d'architecture (`2026-10-25-onepass-architecture-design.md`, sections 7 et 4.6), sur la base du jalon 2 (`2026-10-25-milestone-2-apps-design.md`) et de la section 10 de `docs/security/README.md`.

## 1. Ce que l'utilisateur obtient

1. **Apple Watch.** Une app watchOS autonome en lecture. Sur l'iPhone, un item marqué "Sur l'Apple Watch" y est copié dès que l'app iPhone est déverrouillée. La montre affiche les codes TOTP (compte à rebours) et une petite liste d'items choisis (identifiant d'un Login, Wi-Fi, carte de membre, carte bancaire réduite aux 4 derniers chiffres, codes d'accès, pièces d'identité). L'envoi est chiffré de bout en bout vers une clé propre à la montre. Code de la montre obligatoire ; l'app oublie tout en mémoire dès qu'elle quitte le premier plan, et les données ne se lisent que montre déverrouillée (au poignet). Complication et Smart Stack : ouvrent l'app, n'affichent jamais de secret.
2. **Vision Pro.** La même app que l'iPad, compilée nativement pour visionOS : fenêtre en verre (Liquid Glass de visionOS), barre d'onglets et barres d'outils en ornements, effets de survol du regard, Optic ID par la même clé de la Secure Enclave.
3. **Widgets** (iPhone et iPad) : "Codes" (TOTP des favoris) et "Favoris" (ouvrir un favori). Rien n'est lisible sur un appareil verrouillé.
4. **Contrôles** (Centre de contrôle, écran verrouillé, bouton Action) : "Générer un mot de passe" (ouvre le générateur), "Rechercher dans OnePass" (ouvre la recherche), "Verrouiller OnePass".
5. **Raccourcis et App Intents** (iPhone, iPad, Mac, Vision Pro) : ouvrir un item, copier un code TOTP après authentification, générer un mot de passe, verrouiller. Phrases Siri en français.

Critère de réussite : tests Rust et Swift verts ; builds Simulateur watchOS, visionOS et iOS (app, widgets, Contrôles) ; captures de l'app montre et de l'app Vision Pro dans des Simulateurs dédiés avec des données fictives ; la logique d'appairage, de scellement, de rejeu et d'effacement est couverte par des tests sans montre réelle.

## 2. Vue d'ensemble

```
apple/
  CompanionKit/             nouveau paquet Swift
    GlanceKit               pur Swift : instantané des widgets, liens profonds, signal de verrouillage
    CompanionLink           protocole iPhone <-> montre, modèle de la montre (dépend de OnePassCore)
  Watch/                    app watchOS (cible OnePassWatch)
  WatchWidgets/             complication et Smart Stack (cible OnePassWatchWidgets)
  Widgets/                  widgets et Contrôles iOS (cible OnePassWidgets)
  App/Companion/            côté iPhone : coordinateur montre et widgets (nouveau dossier)
  App/Intents/              App Intents et App Shortcuts (nouveau dossier)
core/
  onepass-core/src/companion.rs   charge utile de la montre, instantané des widgets
  onepass-ffi/src/companion.rs    exposition UniFFI
```

Flux :

```
iPhone déverrouillé (VaultSession)
  ├─ Rust : companion_payload(clé publique de la montre, génération) ──► octets scellés
  │        └─ WatchConnectivity (applicationContext) ──► montre : fichier scellé (protection Complete)
  │                                                       └─ Rust : CompanionVault::open(clé de la montre)
  └─ Rust : glance_snapshot(maintenant, 12 h) ──► JSON dans le conteneur App Group (protection Complete)
                                                  └─ widgets : lecture seule, codes précalculés
App Intents (processus de l'app) ──► AppModel (route) ;  Contrôle "Verrouiller" (extension) ──► notification Darwin
```

Règle de frontière inchangée : seul le Rust manipule les clés et les graines TOTP. La montre et les widgets ne voient jamais une graine TOTP : la montre la garde dans un objet Rust (`CompanionVault`) qui ne rend que des codes, les widgets ne reçoivent que des codes déjà calculés.

## 3. Core (ajouts seulement)

Aucune signature publique existante ne change. Nouveaux modules `onepass-core/src/companion.rs` et `onepass-ffi/src/companion.rs` (une ligne `pub mod` / `mod` chacun), une variante ajoutée en fin d'enum, deux fonctions ajoutées dans `crypto/kem.rs`.

### 3.1 Enveloppe KEM étiquetée

`crypto/kem.rs` gagne `wrap_key_labeled(recipient, key, label, context)` et `unwrap_key_labeled(secret, envelope, label, context)`. Même construction que `wrap_key` (ML-KEM-1024 + X25519, combineur HKDF-SHA256 sur les deux secrets et la transcription), mais l'info HKDF vaut `label || u32_be(len(context)) || context`, comme le demande le commentaire de `KEM_INFO` pour toute deuxième famille de contextes. `wrap_key` et `unwrap_key` ne changent pas (même code interne, mêmes octets). Le blob interne garde `BlobKind::VaultKey` (il transporte une clé de 32 octets).

### 3.2 Charge utile de la montre

- `BlobKind::Companion = 11` (ajouté après `Archive = 9` du jalon 5 et `TravelState = 10` du jalon 7).
- `CompanionPayload { generation: u64, generated_at: i64, entries: Vec<CompanionEntry> }`, sérialisé en postcard.
- `CompanionEntry { item_id, vault_id, item_type, title, subtitle, totp: Option<TotpConfig>, fields: Vec<CompanionField> }`, `CompanionField { label, value, concealed: bool, kind: Text | Concealed | Barcode(format) }`.
- `build_payload(repo, generation, now, excluded_vaults) -> CompanionPayload` : items `on_watch`, ni à la corbeille, ni archivés, ni marqués "redemander la biométrie" (`reprompt`), hors vaults masqués de l'appareil ; triés par titre ; 50 entrées au plus ; une valeur de champ de plus de 1 Kio est omise. Champs copiés (liste fermée, tout le reste est exclu) :

| Type | Champs |
| --- | --- |
| Tous | premier champ TOTP rempli (graine dans `totp`, jamais dans `fields`) |
| Login | `username` |
| Wi-Fi (`Router`) | `ssid`, `wifi_password` (masqué), `guest_ssid`, `guest_password` (masqué) |
| Adhésion, Fidélité | `organization` ou `company`, `member_number` (masqué), `barcode` |
| Carte bancaire | `cardholder`, numéro réduit à `•••• 1234` (calculé, jamais le numéro), `expiry` |
| Code d'accès | `code` (masqué), `alarm_code` (masqué), `instructions` |
| Carte d'identité, Passeport | `last_name`, `first_names`, `number` (masqué), `expiry` |
| Permis | `full_name`, `number` (masqué), `expiry` |

Un item sans aucun de ces champs ni TOTP n'est pas envoyé. Mot de passe d'un Login, CVV, PIN, numéro complet de carte, notes : jamais.

- `seal_payload(payload, recipient: &HybridKemPublic) -> Vec<u8>` : clé de charge utile aléatoire de 32 octets, enveloppée par `wrap_key_labeled(recipient, K, "onepass/companion/v1", "watch" || SHA-256(clé publique du destinataire))`. Format : `"OPC1" || generation (u64 BE) || enveloppe KEM || blob`, où le blob scelle le postcard sous K avec `BlobKind::Companion` et un `Aad` dont `blob_id` = 16 premiers octets de `SHA-256("OPC1" || generation || empreinte du destinataire)`. La génération est donc authentifiée.
- `open_payload(secret, bytes) -> CompanionPayload` : refuse un format inconnu, une génération qui ne correspond pas au blob, une clé qui ne correspond pas, toute altération (erreurs du core, sans contenu).

### 3.3 Instantané des widgets

`glance_snapshot(repo, now, window_secs, excluded_vaults) -> GlanceSnapshot` :

- `favorites` : favoris vivants (ni corbeille, ni archive, ni `reprompt`, hors vaults masqués), triés par titre, 8 au plus : `item_id`, `vault_id`, `item_type`, `title`.
- `codes` : parmi ces favoris, ceux qui ont un TOTP rempli (8 au plus) : `item_id`, `vault_id`, `title`, `period`, et la liste des codes `(début, code)` pour chaque période qui recoupe `[now, now + window]`. Fenêtre plafonnée à 24 h.
- `generated_at`, `valid_until = now + window`.

### 3.4 FFI (`onepass-ffi/src/companion.rs`)

- `companion_generate_key() -> FfiCompanionKeyPair { secret: Vec<u8>, public: Vec<u8> }` (clé publique = `mlkem (1568) || x25519 (32)`).
- `Session::companion_payload(recipient_public, generation, now_unix, excluded_vault_ids) -> Vec<u8>`.
- `Session::glance_snapshot(now_unix, window_secs, excluded_vault_ids) -> FfiGlanceSnapshot`.
- Objet `CompanionVault` : constructeur `open(secret, sealed) -> CompanionVault`, méthodes `generation()`, `generated_at()`, `entries() -> Vec<FfiCompanionEntry>` (champs avec valeurs, `has_totp`, jamais la graine), `totp(item_id, unix) -> Option<TotpCode>`.
- Erreurs : variantes existantes de `OnePassError` (`InvalidInput`, `Integrity`, `Crypto`, `Locked`), aucune nouvelle.

## 4. XCFramework et paquets

- `scripts/build-core.sh shipped` ajoute les tranches `aarch64-apple-watchos`, `aarch64-apple-watchos-sim`, `aarch64-apple-visionos`, `aarch64-apple-visionos-sim` (cibles rustup niveau 2) avec `WATCHOS_DEPLOYMENT_TARGET=26.0` et `XROS_DEPLOYMENT_TARGET=26.0`. Le mode `test` ne change pas.
- `VaultKit/Package.swift` : plateformes `.watchOS("26.0")` et `.visionOS("26.0")`, nouveau produit `OnePassCore` (les liaisons seules) pour la montre. La cible `VaultKit` n'est jamais construite pour watchOS.
- Nouveau paquet `CompanionKit` (`swift test` sur macOS contre l'XCFramework de test, ajouté à `make test`) :
  - `GlanceKit` (aucune dépendance) : `GlanceSnapshot` (Codable), `GlanceStore` (fichier `Library/OnePass/glance.json` du conteneur App Group `group.me.somalabs.onepass`, écriture atomique en `completeFileProtection`, lecture qui rend `nil` si le fichier est illisible, périmé ou absent), `OnePassLink` (liens `onepass://item?vault=<hex>&item=<hex>`, `onepass://generator`, `onepass://search`), `LockSignal` (notification Darwin `me.somalabs.onepass.lock-request` et horodatage de la demande dans les réglages partagés).
  - `CompanionLink` (dépend de `OnePassCore`) : messages `CompanionMessage` (`watchKey(Data)`, `payload(Data)`, `wipe`, `refreshRequest`), protocole `CompanionTransport` et implémentation `WatchConnectivityTransport`, `PhoneCompanion` (côté iPhone : clé publique de la montre, génération, envoi), `WatchVault` (côté montre : clé, fichier scellé, état), `WatchKeyStore` (protocole, Keychain système et version en mémoire).

## 5. Apple Watch

### 5.1 Appairage et envoi

1. Au premier lancement, la montre crée sa paire de clés (`companion_generate_key`). La clé secrète va dans le Keychain de la montre en `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` : sans code sur la montre, l'enregistrement échoue et l'app affiche "Active un code sur ton Apple Watch pour utiliser OnePass". La clé publique part vers l'iPhone (`transferUserInfo`).
2. L'iPhone garde la clé publique (aucun secret) et le compteur de génération dans ses réglages. Réglage "Apple Watch" (activé par défaut ; il ne fait rien tant qu'aucun item n'est marqué).
3. Quand l'app iPhone est déverrouillée, après un déverrouillage, une écriture locale ou un changement distant (anti-rebond 2 s), si une montre appairée a l'app et a envoyé sa clé : génération + 1, `companion_payload`, envoi par `updateApplicationContext` (seul le dernier état compte). Une clé publique qui change (montre réinitialisée) remplace l'ancienne et déclenche un envoi.
4. La montre vérifie et range les octets scellés dans un fichier en `NSFileProtectionComplete`, puis l'ouvre. Elle refuse une génération inférieure ou égale à la dernière acceptée (rejeu), gardée avec la clé.
5. "Retirer de l'Apple Watch" (réglages iPhone) envoie `wipe` : la montre efface fichier, clé et génération, puis recrée une clé.
6. Un item décoché, mis à la corbeille ou archivé disparaît à l'envoi suivant. Verrouiller l'iPhone n'efface pas la montre (app autonome).

### 5.2 Verrouillage

- L'objet `CompanionVault` (seul détenteur des graines, dans le Rust) n'existe que pendant que l'app montre est au premier plan ; il est relâché à la sortie du premier plan. La réouverture relit la clé (Keychain : montre déverrouillée exigée) et le fichier.
- Montre retirée du poignet (détection du poignet active) : watchOS verrouille la montre, le Keychain et le fichier deviennent illisibles. Sans détection du poignet, la protection repose sur le code de la montre (limite affichée dans les réglages iPhone).

### 5.3 Écrans

- Liste : section "Codes" (entrées avec TOTP : titre, code en grand groupé par 3, anneau de compte à rebours), section "Éléments". Vide : "Marque des éléments « Sur l'Apple Watch » dans OnePass sur ton iPhone."
- Détail : code TOTP, champs ; un champ masqué se révèle d'un toucher et se remasque après 30 s ou à la sortie de l'écran ; code-barres affiché en grand texte à espacement fixe (rendu graphique reporté, ruling W8).
- Complication (circulaire, coin, rectangulaire) et Smart Stack : symbole OnePass et nom, ouvrent l'app.
- Debug seulement : `-OnePassWatchDemo YES` affiche des données fictives (source Swift en mémoire, aucune clé), pour les captures.

## 6. Vision Pro

- La cible `OnePass` gagne la destination visionOS. Mise en page : celle de l'iPad (`NavigationSplitView` à trois colonnes), jamais les onglets iPhone.
- Les blocs `#if os(iOS)` qui protègent du code UIKit deviennent `#if os(iOS) || os(visionOS)` ; ceux qui ne concernent que l'iPhone ou la caméra restent iOS.
- Verre : aucun fond opaque dessiné par l'app sur visionOS (la fenêtre porte le verre du système), `.glassBackgroundEffect()` pour les cartes flottantes (verrouillage, onboarding), barres d'outils et onglets en ornements du système, `.hoverEffect()` sur les lignes, tuiles et boutons personnalisés.
- Optic ID : même `SecureEnclaveBiometricUnlock` ; les libellés suivent `LABiometryType` ("Optic ID").
- Pas de scan du QR de l'Emergency Kit (la caméra n'est pas accessible aux apps), la Secret Key se tape comme sur Mac.
- Icône : pile d'images à trois couches dessinée à partir de l'icône existante.
- Fenêtre par défaut 1280 × 820 points, redimensionnable.

## 7. Widgets (iOS et iPadOS)

- Extension `OnePassWidgets` (dépend de `GlanceKit` seulement, aucun core Rust : extension légère), droits : App Group.
- L'app (iOS) écrit l'instantané au déverrouillage, à chaque changement de données pendant la session et au retour au premier plan déverrouillé, puis appelle `WidgetCenter.reloadAllTimelines()`. Fenêtre de codes : 12 h (ruling W4). Au-delà, le widget dit "Ouvre OnePass pour actualiser".
- Widget **Codes** (petit, moyen, grand ; accessoire rectangulaire) : titre et code des favoris à TOTP, compte à rebours (`Text(timerInterval:)`). Chronologie : une entrée par 30 s sur 1 h, puis rechargement.
- Widget **Favoris** (petit, moyen) : titres et symboles de catégorie, chaque ligne ouvre `onepass://item?...` (déverrouillage demandé par l'app).
- Appareil verrouillé : le fichier est en protection `Complete`, illisible ; le widget affiche l'état "Déverrouille ton iPhone" sans titre ni code. En plus, les codes et titres portent `.privacySensitive()` (masqués par le système en écran verrouillé et en StandBy) et l'extension déclare la protection de données `NSFileProtectionComplete`.
- L'instantané contient les symboles et couleurs de catégorie calculés par l'app (DesignKit), pour que l'extension n'ait pas de dépendance au core.

## 8. Contrôles (iOS 18+)

Dans l'extension `OnePassWidgets` :

- "Générer un mot de passe" : `OpenURLIntent(onepass://generator)`, l'app ouvre la feuille du générateur (copie possible dans l'app).
- "Rechercher dans OnePass" : `OpenURLIntent(onepass://search)`.
- "Verrouiller OnePass" : intent exécuté dans l'extension, qui poste `LockSignal`. L'app en cours d'exécution verrouille à réception ; à chaque retour au premier plan, l'app verrouille aussi si une demande est plus récente que son dernier déverrouillage. Si l'app ne tourne pas, rien n'est déverrouillé (les clés ne vivent qu'en mémoire de l'app).

## 9. App Intents et Raccourcis

Dans la cible de l'app (iOS, iPadOS, macOS, visionOS), exécutés dans le processus de l'app :

- `ItemEntity` (identifiant `"<vault>:<item>"`, titre, sous-titre). Requête : depuis la session déverrouillée ; verrouillée, depuis les favoris de l'instantané des widgets (titres seulement, iOS), sinon vide avec le message "Déverrouille OnePass pour choisir un élément".
- **Ouvrir un élément** (`OpenItemIntent`, ouvre l'app) : route vers le détail ; verrouillé, l'écran de verrouillage d'abord, puis le détail.
- **Copier le code à usage unique** (`CopyTotpIntent`, ouvre l'app) : authentification obligatoire, puis copie par le presse-papiers OnePass (90 s, local). Ne renvoie jamais le code au raccourci. Authentification : si l'app était verrouillée, le déverrouillage fait par l'utilisateur pour cette demande suffit ; si elle était déjà déverrouillée, `LAContext` `.deviceOwnerAuthentication` (biométrie ou code de l'appareil) ; si le système ne peut pas authentifier (aucun code), le mot de passe maître est redemandé.
- **Générer un mot de passe** (`GeneratePasswordIntent`, sans ouvrir l'app, sans déverrouillage) : longueur (8 à 64, 20 par défaut), symboles oui/non ; rend le texte. Ce n'est pas un secret du coffre (rien n'est enregistré).
- **Verrouiller OnePass** (`LockVaultIntent`, sans ouvrir l'app) : verrouille la session du processus.
- `OnePassShortcuts` (`AppShortcutsProvider`) : phrases françaises avec `\(.applicationName)`.
- Aucun intent ne rend un secret du coffre.

## 10. Erreurs

- Montre sans code : message et aucune clé créée. Charge utile illisible (clé changée, altération, rejeu) : ignorée, la montre garde la précédente et demande un nouvel envoi (`refreshRequest`) ; journal sans contenu.
- iPhone : échec du scellement ou de l'envoi journalisé, nouvel essai au prochain changement ; état dans Réglages > Apple Watch ("Dernier envoi", "Montre non appairée", "App absente de la montre").
- Widgets : instantané absent, périmé ou illisible : état neutre, jamais de données partielles.
- Intents : item introuvable ou sans TOTP : message en français (`IntentError`), aucune donnée.

## 11. Confidentialité et durcissement

- Graines TOTP : jamais en Swift côté montre ni dans les widgets. La montre a les valeurs des champs de la table 3.2 en mémoire pendant l'affichage (ruling R5 du jalon 2).
- Fichiers : charge utile scellée (montre) et instantané (iPhone) en `NSFileProtectionComplete`. Clé de la montre `WhenPasscodeSetThisDeviceOnly`, jamais sauvegardée ni synchronisée.
- Journaux `os.Logger` sans titre ni valeur.
- Spotlight, Handoff : rien n'est publié (reportés, ruling W10).

## 12. Tests

- Rust (`core/onepass-core` et `core/onepass-ffi`) : aller-retour scellé, mauvaise clé, altération de chaque partie, génération falsifiée, `wrap_key` inchangé (vecteur de non-régression), liste fermée des champs par type, exclusions (corbeille, archive, `reprompt`, vaults masqués, sans champ utile), limite de 50, carte réduite aux 4 derniers chiffres, codes de l'instantané égaux à `totp::code_at`, fenêtre plafonnée.
- Swift (`CompanionKit`) : `GlanceStore` (écriture, lecture, périmé, illisible), `OnePassLink` (aller-retour, liens refusés), `LockSignal`, `PhoneCompanion` et `WatchVault` contre un transport en mémoire (clé envoyée, envoi après changement, rejeu refusé, effacement, clé remplacée, montre sans code) avec le vrai core (XCFramework de test).
- Builds : `make -C apple build-watch`, `build-vision`, `build-ios` (avec widgets et Contrôles), `build-mac`.
- Captures : `make -C apple screenshots-m6 OUT=<dossier>` : montre (`OnePass M6 Watch`, données de démonstration) et Vision Pro (`OnePass M6 Vision Pro`, base de démonstration du jalon 2).

## 13. Hors périmètre et dépendances

- Vérifié seulement sur vrai matériel ou build signé : WatchConnectivity entre une vraie montre et un iPhone, App Group et protection de données des widgets en build signé, Optic ID, affichage des widgets et Contrôles sur l'écran d'accueil et l'écran verrouillé, phrases Siri.
- Reportés : widget "À proximité" et digicodes suggérés sur place (localisation, R11), rendu graphique des codes-barres sur la montre (W8), widgets Mac et visionOS (W5), Spotlight et Handoff (W10), contrôle "Scanner un QR TOTP" (W11).
- Fusion avec le jalon 3 : même App Group `group.me.somalabs.onepass` ; si le fichier de droits iOS du jalon 3 existe déjà, garder le sien.

## 14. Décisions

La consigne du fondateur est que les jalons avancent sans action de sa part : chaque point où le processus attendrait une validation humaine est tranché ici.

- Ruling: brainstorming classé architectural, questions, approches et sections validées par la session elle-même - consigne "décider tout, consigner" - une décision qui déplaît se reprend par une passe de spec et de plan sur la partie touchée.
- Ruling W1: la montre embarque le core Rust (tranches watchOS arm64 et simulateur) et ne fait que l'ouvrir et lire des codes ; la sélection des items, la liste des champs et le scellement se font dans le Rust de l'iPhone - garde la règle "seul le Rust manipule les clés et les graines", une seule implémentation TOTP - l'app montre pèse quelques Mo de plus.
- Ruling W2: chiffrement de bout en bout par l'enveloppe hybride ML-KEM-1024 + X25519 du core vers une clé propre à la montre, avec une étiquette `onepass/companion/v1` et un contexte préfixé par sa longueur ; aucune signature de l'iPhone - seule l'app iPhone associée peut écrire dans la session WatchConnectivity appairée, et la génération est authentifiée dans le blob - une app iPhone compromise pourrait pousser de fausses entrées, mais elle aurait déjà accès à tout le coffre.
- Ruling W3: les montres Apple Watch dont watchOS 26 tourne en `arm64_32` seulement ne sont pas prises en charge (Rust n'a pas de cible `arm64_32-apple-watchos` de niveau 2) - la toolchain stable épinglée suffit - certaines montres plus anciennes ne peuvent pas installer l'app ; un build `-Zbuild-std` est possible plus tard.
- Ruling W4: les widgets reçoivent des codes TOTP précalculés pour 12 h, jamais de graine - exposition minimale demandée, et l'extension n'embarque pas le core - un widget non rafraîchi depuis 12 h affiche "Ouvre OnePass pour actualiser" ; 12 h de codes valent la graine pendant 12 h pour qui lit le fichier (protection Complete, appareil déverrouillé).
- Ruling W5: widgets et Contrôles sur iPhone et iPad seulement ; pas de widgets Mac ni visionOS au jalon 6 - macOS n'a pas de protection de fichiers ni d'état "appareil verrouillé" pour un widget - le Mac et le Vision Pro n'ont que les App Intents.
- Ruling W6: widgets "Codes" et "Favoris" construits sur les favoris (8 au plus), pas sur un réglage par item - le favori existe déjà et sert d'opt-in - un TOTP non favori n'apparaît pas dans le widget.
- Ruling W7: les items `reprompt` (redemander la biométrie) ne vont ni sur la montre ni dans les widgets - ils demandent une biométrie à chaque ouverture, qu'une montre ou un widget ne peut pas imposer - un item protégé n'est consultable que dans l'app.
- Ruling W8: codes-barres affichés en texte sur la montre, rendu graphique reporté - CoreImage n'existe pas sur watchOS et un encodeur de codes-barres en Rust ajouterait une dépendance - la carte ne se scanne pas encore depuis la montre.
- Ruling W9: champs envoyés à la montre par liste fermée par type (table 3.2) ; jamais le mot de passe d'un Login, le CVV, le PIN ni le numéro complet d'une carte - exposition minimale - un utilisateur qui voulait son mot de passe sur la montre ne l'a pas (il ne pourrait pas le taper de toute façon).
- Ruling W10: Spotlight et Handoff reportés à un jalon 6b - la spec 7 les veut "rien d'indexé par défaut" et ce jalon est déjà large - aucune recherche système ni reprise d'activité.
- Ruling W11: pas de Contrôle "Scanner un QR TOTP" au jalon 6 - l'ajout d'un TOTP par caméra appartient au jalon 3 (TOTP) - le Contrôle s'ajoutera quand le scanner existera.
- Ruling W12: le Contrôle "Verrouiller" passe par une notification Darwin et un horodatage partagé, pas par un intent du processus de l'app - un Contrôle s'exécute dans l'extension - une app suspendue ne verrouille qu'à son réveil (déjà vrai pour le délai de verrouillage, section 10.3 de la sécurité).
- Ruling W13: "Copier le code" ne renvoie jamais le code au raccourci et demande une authentification fraîche (déverrouillage pour la demande, sinon `deviceOwnerAuthentication`, sinon mot de passe maître) - spec 7 "aucun secret renvoyé à un raccourci sans biométrie", appliquée plus strictement - le code ne peut pas être enchaîné dans un raccourci.
- Ruling W14: "Générer un mot de passe" rend le texte au raccourci sans déverrouillage - le mot de passe n'est pas dans le coffre - un raccourci peut produire des mots de passe sans Face ID.
- Ruling W15: Vision Pro = la cible multiplateforme existante avec la destination visionOS, mise en page iPad - un seul code SwiftUI (R15) - quelques blocs conditionnels de plus.
- Ruling W16: Simulateurs dédiés `OnePass M6 Watch` (Apple Watch Series 12 46 mm, watchOS 27) et `OnePass M6 Vision Pro` (visionOS 27), créés par `make simulators-m6` ; le runtime visionOS a été téléchargé par `xcodebuild -downloadPlatform visionOS` - captures demandées, et ne pas toucher aux Simulateurs des autres sessions - environ 8 Go de disque.
- Ruling W17: même App Group que le jalon 3 (`group.me.somalabs.onepass`) ; l'app iOS reçoit un fichier de droits iOS avec ce groupe - le jalon 3 le crée aussi, un seul groupe pour toutes les extensions - conflit de fusion trivial sur `project.yml` et ce fichier.
- Ruling W18: la montre garde au plus 50 entrées et 1 Kio par valeur - la petite liste demandée, et `applicationContext` doit rester petit - au-delà de 50 items marqués, les derniers par ordre alphabétique ne sont pas copiés (dit dans les réglages iPhone).
