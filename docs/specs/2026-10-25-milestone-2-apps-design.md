# Jalon 2 : VaultKit, sync CloudKit, apps iPhone, iPad et Mac

Date : 2026-10-25
Statut : approuvée (auto-approbation, voir section 13)
Portée : section 13, point 2 de la spec d'architecture (`2026-10-25-onepass-architecture-design.md`), plus le statut des sections 4.9 (connexion par QR) et 4.10 (modes d'appareil).

## 1. Ce que l'utilisateur obtient

À la fin du jalon, sur iPhone, iPad et Mac :

1. Créer un compte OnePass : mot de passe maître, Secret Key générée sur l'appareil, Emergency Kit (PDF avec QR code), vault "Personnel".
2. Ajouter un appareil avec l'Emergency Kit (Secret Key tapée ou QR scanné) et le mot de passe maître, les données arrivant par iCloud.
3. Déverrouiller avec le mot de passe maître, puis avec Face ID ou Touch ID (ou l'Apple Watch sur Mac). Mot de passe redemandé tous les 14 jours, après un redémarrage et si la biométrie change.
4. Créer et renommer des vaults (nom, icône, couleur).
5. Créer, voir, modifier, archiver, mettre à la corbeille, restaurer, supprimer et déplacer des items des 26 types, avec un éditeur unique piloté par les modèles du `core`.
6. Synchroniser par CloudKit (base privée de l'utilisateur), hors ligne d'abord, avec détection des données altérées.
7. Rechercher, filtrer par vault, catégorie, tag, favoris, archive et corbeille.
8. Copier un champ (presse-papiers effacé après 90 s, local seulement), révéler un secret, voir un code TOTP vivant, générer un mot de passe.
9. Verrouillage automatique, écran masqué dans le sélecteur d'apps.

Critère de réussite : les flux 1 à 9 fonctionnent sur le Simulateur iOS et sur macOS en build local, tous les tests Rust et Swift passent, un test UI parcourt la création de compte et la création d'un item. La sync CloudKit réelle demande un build signé avec une équipe Apple : elle est compilée, testée contre un faux serveur, et désactivée proprement dans un build non signé (section 13, rulings R7 et R8).

## 2. Vue d'ensemble

```
apple/
  OnePass.xcodeproj         généré par XcodeGen depuis project.yml, versionné
  project.yml
  Makefile                  core, bindings, test, build, screenshots
  scripts/build-core.sh     compile onepass-ffi, assemble l'XCFramework
  VaultKit/                 package Swift (bindings + logique Apple)
  DesignKit/                package Swift (couleurs, icônes, composants)
  App/                      cible app unique iOS + iPadOS + macOS (SwiftUI natif)
  AppUITests/
core/
  onepass-core/src/sync/    nouveau module : magasin local synchronisable, rebase
  onepass-ffi/              nouvelle crate : interface UniFFI
```

Règle de frontière inchangée : seul le Rust manipule les clés. Swift reçoit des items déchiffrés pour l'affichage et l'édition, et ne voit jamais une clé de vault, une clé d'item ni le keyset. Les seuls secrets cryptographiques côté Swift sont la Secret Key (Keychain) et l'AUK enveloppée par la Secure Enclave (Keychain), qui ne sont jamais déchiffrées hors des appels qui les consomment.

## 3. Ajouts au core (additifs)

Toutes les modifications de `onepass-core` sont des ajouts : aucune signature publique existante ne change. Les autres sessions (Watchtower, import, MCP, agent SSH) ajoutent leurs propres modules en parallèle.

### 3.1 Déverrouillage par AUK

- `Account::unlock_with_auk(auk, params_record, keyset_record, pinned)` : mêmes contrôles que `Account::unlock` (signature des paramètres, épinglage, plancher et plafond KDF, cohérence du keyset), sans dérivation Argon2id.
- `Account::unlock` est réécrit pour appeler une fonction interne commune : comportement et erreurs identiques.
- `Account::unlock_exporting_auk(...) -> (Account, Auk)` et `Repository::unlock_exporting_auk(...) -> (Repository, Auk)` : déverrouillage par mot de passe qui rend aussi l'AUK, pour l'enrôlement biométrique.
- `Repository::unlock_with_auk(store, auk, device)`.
- `Auk` : 32 octets dans un `Zeroizing`, `Debug` masqué, sérialisation seulement par `as_bytes()` et `from_bytes()`.

Un `Auk` ouvre le keyset tant que le mot de passe et la Secret Key ne changent pas. Le changement de mot de passe n'existe pas encore (R12), donc rien à invalider au jalon 2.

### 3.2 Métadonnées de vault

- `Repository::update_vault_meta(&mut self, vault: &Vault, meta: VaultMeta) -> Result<Vault>` : rescelle la méta avec la clé du vault, version incrémentée, écriture conditionnelle sur la version lue.

### 3.3 Options des menus

- `model::menu_options(item_type, field_id) -> &'static [&'static str]` : les choix des 35 champs `Menu` des modèles (moteurs de base de données, sécurité Wi-Fi, fréquences, etc.), en français, dans l'ordre de la spec 5.4. Les champs oui/non rendent `["oui", "non"]`. Un champ inconnu rend une liste vide (saisie libre). Partagé plus tard avec l'extension.

### 3.4 Encodage de l'état d'appareil

- `DeviceState::encode() -> Vec<u8>` et `DeviceState::decode(&[u8]) -> Result<DeviceState>` (postcard, octets en trop refusés).

### 3.5 Module `sync`

Le `Repository` reste synchrone et ignorant du réseau. La sync passe par un magasin local à couches, `SyncStore`, qui implémente `RecordStore`.

Tables SQLite (un seul fichier, transactions) :

- `base(kind, id, version, data, server_meta)` : dernier état connu du serveur. `server_meta` est opaque pour le Rust (les champs système `CKRecord` encodés par Swift).
- `pending(kind, id, version, data NULL)` : écritures locales pas encore confirmées par le serveur. `data NULL` = suppression.
- `staging(kind, id, version, data NULL, server_meta)` : changements reçus du serveur pendant une session de récupération, appliqués d'un coup.
- `ancestor(kind, id, data)` : pour un manifeste qui a une écriture locale en attente, la version `base` sur laquelle elle s'appuyait, gardée quand le serveur la remplace.
- `meta(key, value)` : état d'appareil (`DeviceState`), jeton de changement CloudKit.

Lecture par le `Repository` : `pending` masque `base` (une ligne `pending` avec `data NULL` cache la ligne de `base`). `put_if_version` compare à la version effective. Écriture : toujours dans `pending`.

Opérations (exposées par `onepass-ffi`) :

1. `pending_changes()` : les lignes `pending`, triées pour que les items passent avant le manifeste de leur vault. Le manifeste d'un vault dont le `base` a avancé depuis l'écriture locale est retenu : il doit d'abord être rebasé.
2. `mark_pushed(kind, id, version, server_meta)` : la ligne `pending` de cette version passe dans `base`.
3. `stage_remote(change)` puis `commit_remote()` : les changements reçus vont dans `staging`, puis dans `base` en une transaction à la fin de la récupération, pour qu'un manifeste n'apparaisse jamais sans ses items. Retourne les vaults dont le manifeste distant a changé.
4. `rebase(vault)` (déverrouillé seulement) : quand le manifeste du serveur a avancé alors que le manifeste local en attente part de l'ancien (son ancêtre, gardé dans `ancestor`), les intentions locales du vault sont recalculées par différence entre le manifeste local et l'ancêtre (items changés, items supprimés), les lignes `pending` du vault sont retirées, l'état "vu" du vault revient à l'ancêtre, le manifeste du serveur est vérifié contre lui (il doit s'y enchaîner), puis chaque intention est rejouée par `save_item` ou `delete_item`. Règle de fusion pour un même item modifié des deux côtés : le plus récent `updated_at` gagne, égalité tranchée par l'ordre des octets du hash de l'enregistrement (déterministe sur tous les appareils). Une suppression locale d'un item modifié ensuite à distance est abandonnée. À l'inverse, une modification locale d'un item supprimé à distance le fait revenir (une suppression ne porte pas de date). Si l'ancêtre manque (vault créé ici, envoi non confirmé, puis nouvelles écritures), l'ancêtre est vide : toutes les entrées locales sont des intentions et le manifeste du serveur est accepté sans historique pour ce vault. Le rebase d'un vault tient dans une transaction SQLite.
5. Un vault en attente de rebase n'envoie rien, ni manifeste ni items : un appareil ne voit jamais un item dont le manifeste n'est pas encore là. Un manifeste distant plus ancien que l'ancêtre reste un `ManifestRollback`.

Cas couverts par les tests Rust (deux appareils, un faux serveur, sans réseau) : écritures sans concurrence, deux appareils qui modifient des items différents d'un même vault, le même item, une suppression contre une modification, un appareil hors ligne longtemps, un serveur qui rejoue un vieux manifeste, un serveur qui sert un manifeste sans ses items (refusé tant que `commit_remote` n'a pas tout), coupure entre deux appels.

### 3.6 Crate `onepass-ffi`

UniFFI (proc-macros, sans fichier UDL). Bibliothèque statique (`staticlib`) pour `aarch64-apple-ios`, `aarch64-apple-ios-sim` et `aarch64-apple-darwin`. Ajoutée comme membre du workspace `core/`.

Fonctions libres :

- `create_account(db_path, password) -> CreatedAccount { session, secret_key, account_id }` : refuse un magasin qui contient déjà un compte.
- `unlock_with_password(db_path, password, secret_key) -> Unlocked { session, auk }`
- `unlock_with_auk(db_path, auk) -> Session`
- `has_account(db_path) -> bool`, `normalize_secret_key(text) -> String` (accepte minuscules, espaces, tirets oubliés).
- `generate(recipe) -> String`, `entropy_bits(recipe) -> f64`.
- `totp_now(secret_or_uri, unix_seconds) -> TotpCode { code, remaining, period }`.
- `item_types() -> Vec<ItemTypeInfo>` (ordre de la spec), `template(item_type) -> Vec<FfiSection>`, `menu_options(item_type, field_id)`.
- `card_brand(number)`, `validate(item) -> Option<FfiValidationError>`.

Objet `Session` (thread-safe, `Mutex` interne) :

- `vaults()`, `create_vault(meta)`, `update_vault(id, meta)`.
- `item_summaries(vault_id)` : titre, sous-titre, type, favori, tags, URL principale, archivé, en corbeille, dates. Aucune valeur secrète.
- `item(vault_id, item_id) -> FfiItem` : l'item complet, déchiffré.
- `new_item(vault_id, item_type, title) -> FfiItem`, `save_item(item)` (valide d'abord, gère l'historique des mots de passe), `trash_item`, `restore_item`, `archive_item`, `unarchive_item`, `delete_item`, `move_item`, `purge_trash(older_than_days)`.
- Sync : `pending_changes`, `mark_pushed`, `stage_remote`, `commit_remote`, `rebase_all`, `sync_meta(key)`, `set_sync_meta(key, value)`.
- `lock()` : vide la session, les clés sont effacées (`zeroize`).
- Les opérations de sync de base (`stage_remote`, `commit_remote`, `mark_pushed`, `pending_changes`) existent aussi sur un objet `SyncStoreHandle` ouvrable sans déverrouiller, pour que la récupération et l'envoi tournent même verrouillé (sauf le rebase).

Types : `FfiItem`, `FfiSection`, `FfiField`, `FfiFieldValue` (enum, les 21 variantes de `FieldValue`), `FfiUrl`, `FfiLocation`, `FfiLoginMethod`, `FfiVault`, `FfiVaultMeta`, `FfiRecordChange`. Les identifiants passent en texte hexadécimal de 32 caractères. Les dates passent en secondes Unix (`i64`) ou en `{year, month, day}`.

Erreurs : `OnePassError` avec `WrongPassword`, `NotFound`, `Conflict`, `Validation { field, reason }`, `Integrity { kind }` (les variantes de `IntegrityError`, sans contenu), `InvalidInput { what }`, `Store`, `Crypto`, `Locked`. Aucune erreur ne contient une valeur de champ.

## 4. VaultKit (package Swift)

Cibles :

- `OnePassFFI` : `binaryTarget` vers `apple/build/OnePassFFI.xcframework` (généré, non versionné).
- `OnePassCore` : bindings Swift générés par `uniffi-bindgen` (générés, non versionnés) et rien d'autre.
- `VaultKit` : l'API Swift utilisée par l'app.
- `VaultKitTests` : Swift Testing, lancés par `swift test` sur macOS.

Composants de `VaultKit` :

1. `KeychainStore` (protocole) et `SystemKeychain` : éléments génériques, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, keychain à protection de données, groupe d'accès partagé `$(AppIdentifierPrefix)me.somalabs.onepass.shared`. Sans l'entitlement (build local non signé, erreur `-34018`), repli sur le trousseau classique, en build Debug seulement.
2. `SecretKeyVault` : stocke et relit la Secret Key par compte.
3. `BiometricUnlock` (protocole) et `SecureEnclaveBiometricUnlock` :
   - clé P-256 de la Secure Enclave, contrôle d'accès `.privateKeyUsage` + `.biometryCurrentSet` (iOS) ou `.biometryCurrentSet` OR `.companion` (macOS, réglage "Accepter aussi l'Apple Watch") ;
   - l'AUK est chiffrée avec `SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM` vers la clé publique, le texte chiffré va dans le Keychain ;
   - à l'enrôlement et à chaque saisie du mot de passe, enregistre l'identifiant de la session de démarrage (`kern.bootsessionuuid`, un UUID par démarrage) ;
   - `unlock()` refuse sans biométrie si plus de 14 jours (réglable) depuis la dernière saisie du mot de passe, si l'identifiant de démarrage a changé (ou est illisible), ou si la clé a été invalidée (nouveau doigt ou visage) ; dans ces cas le mot de passe est demandé et la clé est recréée ;
   - sans Secure Enclave (Simulateur), `isAvailable` vaut `false` et l'option est masquée.
4. `DeviceMode` : `personal` ou `shared` (R3). `shared` désactive la biométrie, force le verrouillage après 5 min d'inactivité et masque les vaults choisis.
5. `VaultSession` (`@MainActor @Observable`) : la machine à états de l'app.
   - états : `noAccount`, `locked`, `unlocking`, `unlocked`, `failed(VaultError)` ;
   - les appels Rust lourds (Argon2id, déchiffrement) tournent hors du thread principal ;
   - garde en mémoire la liste des vaults et des résumés d'items (aucun secret), charge un item complet à la demande et l'oublie à la fermeture du détail et au verrouillage ;
   - recherche locale sur titre, sous-titre, URL et tags ;
   - filtres : tous les items, vault, catégorie, tag, favoris, archive, corbeille ;
   - verrouillage automatique (délai réglable : 1, 5, 15, 60 min, jamais en mode personnel ; en partagé, le plus court entre le délai choisi et 5 min), verrouillage en arrière-plan après le délai.
6. `Clipboard` : copie avec `localOnly`, marquage "concealed" (macOS : type `org.nspasteboard.ConcealedType`), effacement après 90 s si le contenu n'a pas changé.
7. Sync :
   - `RemoteRecordStore` (protocole) : `fetchChanges() async throws -> RemoteBatch`, `send(changes) async throws -> [SendResult]`, où `SendResult` est `saved(serverMeta)`, `conflict(serverRecord)` ou `failed` ;
   - `SyncCoordinator` (acteur) : boucle envoi puis récupération, déclenchée après chaque écriture (anti-rebond 2 s), au démarrage, au retour au premier plan, et sur notification push CloudKit ; applique `stage_remote` puis `commit_remote`, lance `rebase_all` si déverrouillé, publie un `SyncStatus` (désactivée, à jour, en cours, hors ligne, erreur, données refusées) ;
   - `CloudKitRemote` : base privée, zone `OnePass`, type d'enregistrement `OPRecord`, nom `"<code de type>.<id hex>"`, champs `kind`, `version` et `data` (dans `encryptedValues`). Envoi par `CKDatabase.modifyRecords(saving:deleting:savePolicy: .ifServerRecordUnchanged, atomically: true)`, récupération par `recordZoneChanges(inZoneWith:since:)`, jeton de changement sauvé par `set_sync_meta`, abonnement `CKDatabaseSubscription` pour les notifications push. Les champs système de chaque `CKRecord` sont gardés dans `server_meta`. Limite de 900 Kio par enregistrement, au-delà l'écriture est refusée côté Rust avant d'être faite ;
   - `InMemoryRemote` : faux serveur pour les tests, qui sait aussi rejouer, retenir ou altérer des enregistrements.
8. `EmergencyKit` : PDF une page (Secret Key en clair, QR code, identifiant du compte, instructions en français, emplacement pour noter le mot de passe à la main), produit localement (CoreGraphics + CoreImage), partagé par la feuille de partage système. Jamais écrit ailleurs que dans un fichier temporaire supprimé après partage.
9. `SiteIconLoader` : favicon et `apple-touch-icon` récupérés directement sur le site de l'URL principale, `URLSession` éphémère sans cookies, HTTPS seulement, 256 Kio maximum, cache local par hash du domaine (fichiers en `completeFileProtectionUnlessOpen` sur iOS, pour qu'une écriture commencée se termine écran verrouillé ; macOS : conteneur et FileVault), réglage pour désactiver. Pack de marques et cache chiffré au jalon 5 (R10).

## 5. DesignKit (package Swift)

- Couleur d'accent `#5856D6` (indigo de la maquette), couleurs système pour le reste, mode sombre et contraste élevé pris en charge.
- `ItemCategory` : pour chacun des 26 types, libellé au pluriel ("Connexions", "Notes sécurisées"...), couleur de tuile (valeurs de la maquette), symbole SF.
- `ItemIcon` : ordre de la spec 5.7, sans le pack intégré : icône du site si chargée, sinon tuile de catégorie, sinon lettre sur fond coloré.
- `VaultBadge` : lettre ou symbole sur rond coloré.
- Composants : ligne de champ (libellé, valeur, menu Copier / Révéler / Afficher en grand), jauge de force du mot de passe, compteur TOTP circulaire, bannière d'erreur d'intégrité, état vide.
- Liquid Glass : matériaux et styles système de iOS 26 / macOS 26 (`glassEffect`, barres d'outils et barres latérales natives), aucun flou recréé à la main. Barre latérale Mac transparente par défaut (`NavigationSplitView`).

Aucun élément de marque de 1Password : logo, nom, glyphes et couleurs propres à OnePass. Icône d'app : serrure ronde dessinée par nous (forme de la maquette), en symbole vectoriel.

## 6. Écrans

Structure reprise de la maquette approuvée (artefact `7XoCLnvsAXhKUFKJ5qzfQv`).

### 6.1 Mac

- Fenêtre `NavigationSplitView` à 3 colonnes.
  - Barre latérale : en-tête du compte (initiales, nom local), "Tous les éléments", Favoris, section COFFRES (chaque vault avec son badge et son compte d'items, "Nouveau coffre"), section CATÉGORIES (seulement les types présents), section TAGS, puis Archive et Supprimés récemment, Réglages en bas.
  - Liste : champ de recherche (⌘F), tri (titre, date de modification), groupes par mois pour le tri par date, bouton "Nouvel élément" (menu des 26 types, ⌘N).
  - Détail : en-tête (icône, titre, vault), champs par section, URL, tags, notes, dates (créé, modifié), menu (Favori, Déplacer vers..., Archiver, Mettre à la corbeille), bouton Modifier (⌘E).
- Édition dans la colonne de détail : Annuler / Enregistrer (⌘S).
- Onboarding plein écran : Bienvenue (Créer / J'ai mon Emergency Kit / J'ai déjà OnePass sur un autre appareil, ce dernier grisé "Bientôt"), Ce Mac est-il à toi ?, Mot de passe maître, Secret Key et Emergency Kit, Touch ID, Terminé.
- Écran verrouillé : badge du compte, champ mot de passe, bouton Touch ID.
- Réglages (fenêtre `Settings`) : Général (verrouillage auto, icônes des sites), Sécurité (Touch ID, Apple Watch, délai de redemande du mot de passe, mode d'appareil), Sync (statut iCloud), Coffres (renommer, icône, couleur), À propos (version, licence, code source).

### 6.2 iPhone

- Onglets (barre d'onglets Liquid Glass) : Accueil, Éléments, Watchtower, et Rechercher en onglet de recherche séparé (rôle `.search` de iOS 26).
  - Accueil : Favoris et Récents (items ouverts pendant la session, liste en mémoire seulement, vidée au verrouillage), bouton "Nouvel élément". "À proximité" vient avec la localisation (R11).
  - Éléments : blocs Coffres, Catégories, Tags (repliables), puis Archive et Supprimés récemment.
  - Watchtower : état vide qui annonce le jalon 5 (structure de la maquette conservée, aucune fausse donnée).
  - Rechercher : recherche sur tous les items, suggestions de catégories.
- Menu du compte (en-tête) : Réglages, Verrouiller.
- Détail et édition en pile de navigation, comme la maquette `PhoneItem`.
- Onboarding : mêmes étapes que le Mac, en pages, avec Face ID.

### 6.3 iPad

Même app que l'iPhone, mise en page Mac : `NavigationSplitView` 3 colonnes en largeur normale, repli sur la pile iPhone en largeur compacte (Split View, Slide Over). Raccourcis clavier identiques au Mac. Une seule fenêtre au jalon 2 (l'état de navigation est global au processus) ; Stage Manager accepté.

### 6.4 Éditeur des 26 types

Un seul éditeur, piloté par `template(item_type)` et `menu_options`. Chaque type de champ a son contrôle :

| Type de champ | Contrôle |
| --- | --- |
| texte, email, téléphone, URL | champ de texte avec le bon clavier |
| masqué, mot de passe, OTP, phrase mnémonique | champ sécurisé, bouton Révéler ; mot de passe : bouton Générer (feuille du générateur) et jauge de force ; OTP : accepte un secret base32 ou une URI `otpauth://`, aperçu du code |
| date, mois/année | sélecteur de date, sélecteur mois + année |
| nombre, montant | champ numérique, montant avec devise |
| adresse | six champs (ligne 1, ligne 2, ville, code postal, région, pays) |
| menu | liste des options, ou texte libre si aucune |
| lien vers un item | sélecteur d'item (recherche) |
| code-barres | valeur et format |
| localisation | étiquette, adresse, latitude, longitude, rayon (sans carte au jalon 2) |
| passkey | lecture seule (création au jalon 3) |
| clé SSH | clé privée collée (masquée), clé publique et empreinte affichées si présentes ; génération au jalon 7 |
| fichier | lecture seule, "Pièces jointes au jalon 5" (R9) |

Plus, pour tous les types : titre, vault, favori, tags, URL (répétables, règle de correspondance, principale), notes (texte multiligne, rendu Markdown en lecture), champs répétables ("+ ajouter"), section de champs perso ("+ ajouter un champ" : texte, masqué, mot de passe, date, URL, email, téléphone), suppression d'un champ ajouté. Les erreurs de `validate` (champ requis, carte, IBAN, BIP39, numéro national) s'affichent sous le champ concerné. Un mot de passe remplacé va dans `password_history` (fait par `save_item` côté Rust).

## 7. Flux principaux

Création de compte :

1. Si CloudKit est actif, récupération de la zone : si un compte existe déjà dans cet iCloud, la création est refusée ("Un compte OnePass existe déjà dans ton iCloud, utilise ton Emergency Kit") (R13).
2. `create_account` (Argon2id 256 Mio, environ 1 à 3 s, indicateur d'activité).
3. Secret Key dans le Keychain, affichée une fois, Emergency Kit proposé. Case "Je l'ai rangée hors ligne" obligatoire pour continuer.
4. Biométrie proposée (mode personnel seulement) : `unlock_with_password` a rendu l'AUK, enveloppée par la Secure Enclave.
5. Envoi initial vers CloudKit en arrière-plan.

Nouvel appareil avec Emergency Kit :

1. Saisie ou scan (caméra de l'app, `DataScannerViewController` sur iOS ; sur Mac, saisie seulement au jalon 2) de la Secret Key.
2. Récupération complète de la zone CloudKit dans `base`.
3. Mot de passe maître, `unlock_with_password` : épinglage à la première utilisation (TOFU, comme au jalon 1).
4. Biométrie proposée.

Sans CloudKit (build non signé), ce flux n'est utile que si le magasin local contient déjà le compte : il reste disponible pour les tests (R8).

Déverrouillage : biométrie si enrôlée et valide, sinon mot de passe. Après 5 échecs de mot de passe, attente croissante (30 s, 1 min, 5 min) avant un nouvel essai, comptée localement.

Écriture d'un item : `save_item` écrit dans `pending`, la liste se met à jour, la sync envoie après 2 s.

## 8. Erreurs

- Mot de passe faux : message sous le champ, compteur d'échecs.
- `Integrity` : écran "Données refusées" avec le type d'attaque détectée en clair ("Un vault a disparu du stockage", "Ancienne version rejouée"...), bouton Réessayer (relance une récupération complète) et lien vers la page sécurité. Aucune donnée affichée tant que l'erreur persiste. Le stockage n'est jamais "réparé" automatiquement.
- `Conflict` sur une écriture locale : relance automatique une fois, puis message "Réessaie".
- Sync hors ligne ou compte iCloud absent : statut dans les réglages et pastille discrète dans la barre latérale, l'app reste utilisable.
- Validation : sous le champ concerné, le bouton Enregistrer reste actif et ramène au premier champ fautif.

## 9. Confidentialité et durcissement

- Écran masqué (vue de confidentialité) dès que la scène passe inactive, sur iPhone et iPad.
- Champs révélés : retour au masquage après 30 s ou à la sortie de l'écran.
- Spotlight, Handoff, widgets : rien au jalon 2.
- Pas de journalisation de valeurs : `os.Logger` avec `privacy: .private` pour tout identifiant, jamais de valeur de champ.
- Données de l'app : base `SyncStore` dans le conteneur de l'app (`Application Support/OnePass/vault.sqlite`), `NSFileProtectionCompleteUntilFirstUserAuthentication` pour que la sync tourne verrouillé ; son contenu est déjà chiffré par le core.
- Secrets Swift : `String` seulement pour l'affichage et l'édition, l'item complet n'est gardé que par la vue de détail et vidé au verrouillage. Limite assumée (R5) : Swift ne peut pas garantir l'effacement des copies de `String`.

## 10. Tests

- Rust : tests unitaires des ajouts (AUK, méta de vault, menus, `DeviceState`), suite `sync` à deux appareils et faux serveur (section 3.5), tests de `onepass-ffi` (création, déverrouillage, cycle de vie des items, erreurs sans contenu), `cargo clippy -D warnings`, `cargo fmt --check`.
- Swift (`swift test` sur macOS, contre la tranche macOS de l'XCFramework) : `VaultSession` (états, verrouillage auto, filtres, recherche), `BiometricUnlock` avec une fausse Secure Enclave (14 jours, redémarrage, invalidation), `Clipboard`, `SyncCoordinator` à deux appareils contre `InMemoryRemote` (concurrence, conflit de manifeste, serveur qui retient un item, serveur qui altère un blob), `EmergencyKit` (PDF produit, QR décodable), `SiteIconLoader` (refus HTTP, taille maximale) avec un `URLProtocol` de test.
- App : build iOS Simulateur et macOS, test UI (XCUITest) sur un Simulateur dédié à cette session : création de compte, ajout d'un Login, recherche, verrouillage et déverrouillage par mot de passe. Captures d'écran iPhone, iPad et Mac pour la revue visuelle.
- Données de test : uniquement fictives (exemple.fr, noms inventés). Aucune donnée réelle.

## 11. Statut de 4.9 et 4.10

- 4.10 mode personnel : livré.
- 4.10 mode partagé : livré (pas de biométrie, verrouillage après 5 min, mot de passe à chaque déverrouillage, vaults masqués choisis à l'onboarding et modifiables dans les réglages).
- 4.10 mode public (session déléguée) : reporté.
- 4.9 connexion par QR, liste signée des appareils, révocation, délai de sécurité de 24 h : reportés.

Les deux reports forment un jalon dédié, appelé 2b "Appairage et appareils", à placer après le jalon 2 et avant le lancement (R1, R2).

## 12. Hors périmètre du jalon 2

AutoFill système, passkeys et TOTP dans le champ (jalon 3) ; extension (jalon 4) ; Watchtower, pack d'icônes, import, export, sauvegarde, pièces jointes (jalon 5) ; Apple Watch, Vision Pro, widgets, Contrôles, Raccourcis, Spotlight, Handoff (jalon 6) ; MCP, agent SSH, génération de clés SSH, Travel Mode (jalon 7) ; changement de mot de passe maître, suppression de vault, option Secret Key dans le trousseau iCloud.

## 13. Décisions

La consigne du fondateur est que les jalons avancent sans aucune action de sa part. Chaque point où le processus attendrait une validation humaine est tranché ici.

- Ruling: brainstorming classé architectural, questions, choix d'approche et validation des sections tranchés par la session elle-même - consigne explicite "décider tout, consigner" - si une décision déplaît, la reprendre coûte une passe de spec et de plan sur la partie touchée.
- Ruling R1: la connexion par QR (4.9) est reportée au jalon 2b - elle demande un nouveau protocole cryptographique (canal KEM éphémère, code de vérification sur la transcription), une zone de rendez-vous CloudKit, une preuve de proximité Bluetooth testable seulement sur de vrais appareils, et la liste signée des appareils dans le core : chacun mérite sa spec et sa revue adverse - si l'utilisateur la voulait au jalon 2, un nouvel appareil passe en attendant par l'Emergency Kit, qui est le chemin de secours prévu par la spec.
- Ruling R2: le mode public (4.10) est reporté au jalon 2b - il repose sur le même canal d'appairage que 4.9 - aucun appareil public ne peut être utilisé d'ici là.
- Ruling R3: modes personnel et partagé livrés au jalon 2, choisis à l'onboarding ("Cet appareil est-il à toi ?") avec deux réponses, modifiables dans les réglages - ce ne sont que des règles locales de verrouillage, peu coûteuses - si la règle des vaults masqués en mode partagé est jugée insuffisante, elle se renforce au jalon 2b sans migration.
- Ruling R4: la biométrie enveloppe l'AUK et non le keyset déchiffré - l'AUK ouvre le keyset avec exactement les mêmes contrôles que le mot de passe, sans sérialiser des clés privées hors du Rust, et seulement 32 octets sortent - même puissance pour un attaquant qui aurait la clé de la Secure Enclave ; changer de choix plus tard oblige seulement à réenrôler la biométrie.
- Ruling R5: les items passent du Rust au Swift en enregistrements UniFFI typés, valeurs secrètes en `String` - SwiftUI a besoin des valeurs pour les afficher et les éditer ; les listes ne portent jamais de secret et l'item complet est oublié au verrouillage - les copies de `String` ne sont pas effaçables de façon garantie ; un format à tampons effaçables est possible plus tard sans toucher au core.
- Ruling R6: sync "hors ligne d'abord" avec magasin à couches (`base`, `pending`, `staging`) et rebase des intentions locales dans le Rust - le Repository reste synchrone et testable sans réseau, la logique de conflit (la plus risquée) est testée en Rust à deux appareils - fusion au niveau de l'item, le plus récent gagne : une modification concurrente du même item sur deux appareils perd la version la plus ancienne (pas de fusion champ par champ au jalon 2).
- Ruling R7: CloudKit par les API asynchrones de `CKDatabase` (envoi atomique conditionnel, récupération par jeton de zone, abonnement push) plutôt que `CKSyncEngine` - le modèle "j'envoie un lot, je reçois saved ou conflit par enregistrement" correspond exactement au protocole `RemoteRecordStore` et se teste avec un faux serveur, alors que `CKSyncEngine` impose un flux par délégué et ses propres lots, incompatible avec l'envoi atomique d'un manifeste et de ses items - il faut gérer soi-même réessais, limites de débit et jetons expirés ; passer à `CKSyncEngine` plus tard se fait derrière le même protocole.
- Ruling R8: CloudKit est activé par une condition de compilation (`ONEPASS_CLOUDKIT`), présente seulement dans la configuration signée ; un build local non signé (Simulateur, tests) tourne en local seulement et l'affiche dans les réglages - sans équipe Apple, l'entitlement iCloud fait planter `CKContainer`, et aucune équipe n'est disponible pour cette session - la sync réelle n'est vérifiée qu'en build signé, par le fondateur ou une CI signée ; la logique de sync est couverte par les tests contre `InMemoryRemote`.
- Ruling R9: pas de pièces jointes au jalon 2 (champ fichier en lecture seule) - le stockage chiffré des pièces jointes et la limite de 1 Mo par enregistrement CloudKit demandent des `CKAsset` et un format de blob dédié, plus logiques avec l'import et la sauvegarde du jalon 5 - un Document ou un scan de passeport ne peut pas encore porter son fichier.
- Ruling R10: icônes de site récupérées directement sur le site, cache local protégé par la protection de fichiers du système, désactivable ; pack intégré de marques et cache chiffré au jalon 5 - c'est le "logo automatique" de la maquette sans service tiers - la récupération révèle au site qu'un item existe pour lui ; le réglage permet de la couper.
- Ruling R11: pas de liste "À proximité" ni de géofences au jalon 2, l'onglet Accueil montre Favoris et Récents - la localisation demande une permission et un calcul local qui méritent leur passe (et servent surtout la Watch et les widgets du jalon 6) - l'accueil est un peu plus pauvre que la maquette.
- Ruling R12: pas de changement du mot de passe maître au jalon 2 - le core n'a pas encore de rotation du keyset et des paramètres signés - un utilisateur ne peut pas encore changer son mot de passe ; à livrer avant le lancement.
- Ruling R13: la création de compte est refusée si l'iCloud contient déjà un compte OnePass - deux comptes dans une zone rendent `unlock` ambigu (`InvalidFormat("account params")`) - un utilisateur qui veut repartir de zéro devra effacer ses données iCloud OnePass (réglage "Effacer les données iCloud" au jalon 5).
- Ruling R14: pas de suppression de vault au jalon 2, seulement création et renommage - sans liste signée des vaults, un vault supprimé ressemble pour les autres appareils à un vault caché par le serveur (`VaultMissing`) - un vault créé par erreur reste (vide) jusqu'au jalon 2b.
- Ruling R15: une seule cible d'app multiplateforme (iOS, iPadOS, macOS natif, pas Catalyst), projet XcodeGen dont le `.xcodeproj` généré est versionné - un seul code SwiftUI, et le projet s'ouvre sans outil supplémentaire - les différences Mac et iPhone passent par des vues dédiées par plateforme dans le même dossier.
- Ruling R16: Mac en arm64 seulement, iOS 26 et macOS 26 minimum - Liquid Glass, macOS 27 abandonne Intel - les Mac Intel sous macOS 26 ne sont pas pris en charge.
- Ruling R17: XCFramework et bindings Swift générés à la demande par `make -C apple core`, non versionnés - ils dépendent de la toolchain et pèsent plusieurs dizaines de Mo - ouvrir le projet demande de lancer cette commande une fois (le build Xcode la lance aussi via une phase de script si l'XCFramework manque).
- Ruling R18: verrouillage automatique par défaut après 15 min en mode personnel, réglable (1, 5, 15, 60 min, jamais) ; mot de passe redemandé tous les 14 jours - valeurs de la spec et usage courant - un délai trop long se règle sans migration.
- Ruling R19: l'Emergency Kit est un PDF produit sur l'appareil, partagé par la feuille système, et le scan de son QR n'existe que sur iPhone et iPad au jalon 2 - le Mac n'a pas toujours de caméra adaptée et la saisie tolère les erreurs de format - sur Mac il faut taper la Secret Key.
- Ruling R20: l'onglet Watchtower est présent avec un état vide qui annonce le jalon 5 - garder la structure de navigation de la maquette évite de la refaire au jalon 5 - un onglet sans contenu pendant quelques jalons.
- Ruling R21: crate `onepass-ffi` (nom aligné sur `onepass-core` et `onepass-cli`, la spec d'architecture disait `core-ffi`) ; UniFFI en proc-macros, version 0.29 ou plus récente épinglée - pas de fichier UDL à tenir à jour - changer de version d'UniFFI régénère seulement les bindings.
- Ruling R22: textes de l'interface en français seulement au jalon 2, dans des catalogues de chaînes (`Localizable.xcstrings`) - l'anglais (spec 10) s'ajoute sans toucher au code - pas d'anglais avant un jalon ultérieur.

## 14. Rulings d'exécution

Décisions prises pendant l'implémentation (exécution par sous-agents, revues par tâche et revue finale). Format : décision - raison - coût si c'est faux.

- Ruling E1: comptes à KDF rapide pour les tests Swift par une fonction FFI publique `create_account_with_kdf`, et une XCFramework de test séparée (debug + `dev-fast-kdf`) - une seule surface de bindings, le plancher KDF reste imposé hors build de dev - une fonction de test fait partie de l'API publique (sans effet en release).
- Ruling E2: un vault est retenu si son manifeste local en attente s'appuie sur un ancêtre dont la version diffère de celle du `base` - la règle du plan (`pending <= base`) ratait une avance locale de plusieurs écritures - un vault pourrait rester retenu à tort (couvert par les tests).
- Ruling E3: les suppressions d'items en attente gardent l'id de leur vault, les suppressions partent par type décroissant - un vault retenu n'envoie jamais rien - une colonne de plus.
- Ruling E4: ancêtre manquant = ancêtre vide, le manifeste du serveur est accepté sans historique pour ce vault - sinon le vault reste bloqué - un serveur hostile peut servir une fois un manifeste plus ancien mais signé pour ce vault.
- Ruling E5: le rebase d'un vault tient dans une transaction SQLite, état d'appareil compris, et un vault en erreur ne bloque pas les autres - un arrêt brutal laisse soit l'état d'avant soit le rebase fini - une transaction plus grosse.
- Ruling E6: une modification locale fait revenir un item supprimé à distance ; un déplacement local contre une modification distante laisse l'item dans les deux vaults - déterministe et sans perte - un item supprimé peut revenir, un doublon peut apparaître.
- Ruling E7: RUSTSEC-2026-0374 (basic-toml) ignoré de façon ciblée, bindgen derrière la feature `bindgen` - dépendance de build seulement, toutes les versions d'UniFFI l'utilisent - une crate non maintenue reste dans le graphe de build.
- Ruling E8: l'enrôlement biométrique supprimé (redémarrage, 14 jours, biométrie changée) est recréé au déverrouillage suivant par mot de passe si l'utilisateur l'avait activé (`biometricsWanted`) - spec 4 point 3 - un réglage de plus.
- Ruling E9: redémarrage détecté par `kern.bootsessionuuid`, Apple Watch par `.companion` - pas de dérive d'horloge, `.watch` est déprécié - `.companion` accepte aussi d'autres appareils compagnons reconnus par le système.
- Ruling E10: en mode partagé, verrouillage après min(délai choisi, 5 min) ; les vaults masqués s'appliquent dans tous les modes - jamais plus long que la spec - aucun.
- Ruling E11: le coordinateur de sync possède le jeton de changement, commit systématique en fin de récupération, envois découpés seulement au-delà des limites CloudKit (400 enregistrements, 1,5 Mio), items toujours avant leur manifeste - aucune perte sur arrêt brutal ou enregistrement inconnu - en cas de découpage, un autre appareil peut voir un refus d'intégrité passager.
- Ruling E12: une zone CloudKit perdue ou effacée est renvoyée depuis cet appareil en deux temps (après une récupération complète, seuls les enregistrements absents du serveur repartent) ; toute récupération complète réconcilie la base - la copie locale peut être la seule complète, et un appareil en retard ne doit pas faire régresser le serveur - un effacement volontaire d'iCloud est défait par le prochain appareil qui synchronise (vrai flux d'effacement au jalon 5).
- Ruling E13: le stockage distant ne peut pas supprimer les paramètres de compte ni le keyset, ni retirer les lignes d'un vault déjà vu ; un compte épinglé mais absent est un échec d'intégrité, jamais "pas de compte", et la création refuse un magasin épinglé - le stockage hostile ne doit jamais effacer la copie locale ni mener à un second compte - un vault réellement supprimé ne peut pas disparaître localement (aucune suppression de vault au jalon 2).
- Ruling E14: changement de compte iCloud détecté (identifiant utilisateur CloudKit gardé à la première sync) : la sync s'arrête avec "Le compte iCloud a changé" - éviter d'envoyer le coffre dans l'iCloud de quelqu'un d'autre - il faut revenir au compte d'origine (pas d'action d'acceptation dans l'interface au jalon 2).
- Ruling E15: dans un build CloudKit sans compte iCloud, création et restauration s'arrêtent avec un message clair - éviter deux comptes dans une zone (R13) - le build signé exige iCloud pour démarrer.
- Ruling E16: "Réessayer" sur l'écran "Données refusées" relance une récupération complète - spec 8 - un téléchargement complet.
- Ruling E17: tant que les pièces jointes n'existent pas, un champ Fichier obligatoire vide ne bloque pas l'enregistrement (stocké non obligatoire) - sinon le type Document est inutilisable - le jalon 5 doit rétablir l'obligation.
- Ruling E18: une seule fenêtre au jalon 2 sur Mac et iPad - l'état de navigation et d'édition est global au processus - pas de deuxième fenêtre OnePass.
- Ruling E19: la création de compte est annulée si la Secret Key ne peut pas être rangée dans le trousseau (la base fraîche est vidée, aucune sync) ; une restauration est annulée sans toucher la base - éviter un compte impossible à rouvrir - un build iOS non signé sans trousseau ne peut pas créer de compte.
- Ruling E20: la feuille iOS "Enregistrer le mot de passe ?" après l'enregistrement d'un Login reste une limite du jalon 2, corrigée au jalon 3 (OnePass fournisseur AutoFill) - pas d'API publique fiable pour la supprimer sans dégrader la saisie sécurisée - un utilisateur peut copier un mot de passe du coffre dans Mots de passe d'Apple en touchant Enregistrer.
- Ruling E21: les modèles comptent 35 champs `Menu` (27 menus et 8 oui/non), et non 39 - erreur de la première version de cette spec - aucun.
- Ruling E22: sortie de l'écran "compte disparu" (`account_missing`) par trois actions, dans cet ordre : "Récupérer depuis iCloud" (build CloudKit, récupération complète existante), "Restaurer avec mon Emergency Kit" (confirmation : la copie locale illisible est effacée) et "Repartir de zéro" (rôle destructif, il faut taper EFFACER, rien n'est effacé dans iCloud). Les deux dernières passent par `reset_store_for_recovery` (toutes les tables vidées en une transaction, état d'appareil compris : épingle et derniers manifestes vus ; refusé tant qu'un compte est lisible), effacent l'identifiant du compte, le nom, l'attente après échecs, la Secret Key et l'enrôlement biométrique, puis ouvrent la restauration par l'Emergency Kit (données reprises d'iCloud) ou l'accueil - une perte réelle de la copie locale laissait l'utilisateur sans issue, et l'épingle effacée est reposée au déverrouillage suivant (TOFU, comme un nouvel appareil) - un stockage hostile qui efface le compte local peut amener l'utilisateur à faire confiance de nouveau à ce que sert iCloud ; la confirmation explicite et l'Emergency Kit limitent ce risque au cas où l'utilisateur choisit lui-même de repartir.
- Ruling E23: action "Utiliser ce compte iCloud" sur l'état "Le compte iCloud a changé" (Réglages > Sync et bandeau des vues principales sur iPhone, iPad et Mac). La zone du nouveau compte est lue d'abord, sans toucher la base : un autre compte OnePass (identifiant différent) est refusé ("Ce compte iCloud contient déjà un autre coffre OnePass. Reviens au compte iCloud d'origine pour synchroniser."), le même compte est accepté, une zone vide demande confirmation ("Ton coffre chiffré sera envoyé dans ce compte iCloud."). Accepter enregistre la nouvelle identité, oublie le jeton et lance une réinitialisation de zone (`begin_zone_reset`, puis `finish_full_fetch` en mode reset) avant de reprendre la sync. Remplace la limite de E14 - un changement de compte voulu bloquait la sync pour toujours - lire toute la zone pour la vérifier coûte un téléchargement complet de plus ; deux coffres dans une zone restent impossibles (R13).
- Ruling E24: identité iCloud revérifiée avant chaque envoi au moindre coût : l'identité vérifiée au début du tour est gardée en cache avec le compteur de `CKAccountChanged` (observé par `CloudKitRemote`) ; avant l'envoi, elle n'est redemandée que si ce compteur a bougé ou si la vérification date de plus de 10 min ; un écart arrête le tour avant tout envoi - aucun appel réseau de plus dans le cas normal - un changement de compte non signalé par le système dans les 10 min entre la récupération et l'envoi d'un même tour n'est vu qu'au tour suivant.
- Ruling E25: les suppressions refusées sont tracées. `commit_remote` (suppression ignorée) et `finish_full_fetch` en mode simple (ligne protégée que le serveur ne rend plus) ajoutent une entrée `{type, id, date Unix}` à un journal plafonné à 100 entrées dans la méta de la base (les plus anciennes partent), hors de portée des clés `sync.` du handle ; FFI `ignored_deletions()` et `clear_ignored_deletions()`. Réglages > Sync affiche "N suppressions refusées venant d'iCloud", la liste (type en français, identifiant court, date) et "Effacer le journal" ; `os.Logger` n'enregistre que le nombre - une attaque silencieuse du stockage devient visible - un incident iCloud bénin peut aussi remplir le journal ; une réinitialisation de zone renvoie ces lignes au lieu de les tracer.
- Ruling E26: `SiteIconLoader` refuse sans requête, en plus des adresses IP, de `localhost` et des noms sans point, les suffixes `.lan`, `.home.arpa`, `.internal`, `.localdomain`, `.home`, `.intranet`, `.corp`, `.private` et `.local` ; puis il résout le nom (`getaddrinfo` hors du thread principal, délai de 3 s, résolveur injectable pour les tests) et refuse si une seule adresse est privée, de bouclage, lien-local, CGNAT (100.64.0.0/10), unique-local IPv6 (fc00::/7), multicast ou réservée (IPv4 incluse dans IPv6 jugée comme IPv4) - une icône ne doit pas servir à sonder le réseau local - la fenêtre de DNS rebinding entre la résolution et la connexion est acceptée (section 7.4 de la sécurité).
- Point laissé ouvert (garé) : échec improbable de la remise à zéro après une création annulée seulement journalisé.
