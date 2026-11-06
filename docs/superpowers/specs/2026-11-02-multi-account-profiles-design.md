# Plusieurs comptes et profils dans une seule app : conception

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, agent `profiles`, rulings en section 11).
Points 8 et 10 du retour du fondateur du 2026-11-02 (`.superpowers/briefs/2026-11-02-ios-feedback.md`).
S'appuie sur la spec d'architecture (`2026-10-25-onepass-architecture-design.md` : compte, keyset, Secret Key, 2SKD, Emergency Kit), la spec entreprise (`2026-10-30-enterprise-design.md`, ruling E1 : compte géré distinct du compte personnel, sélecteur de compte dans l'app ; E9 : comptes gérés sur le serveur d'organisation) et la spec partage et familles (`2026-10-30-sharing-families-design.md`), sans en changer aucune règle.

## 1. But

Le fondateur a un compte personnel « Quentin Caron ». Quand il a un coffre avec son entreprise, il veut un compte professionnel dans la même app, sans se déconnecter, et que l'app soit intelligente avec ces profils :

1. changer de compte depuis le panneau de l'avatar (iPhone, iPad) et le menu du compte (Mac) ;
2. chaque compte a sa couleur, son avatar et son type (personnel, professionnel, géré par une organisation) ;
3. chaque compte a son verrouillage, sa Secret Key, son Emergency Kit, sa sync, son Watchtower ;
4. verrouiller un compte, ou tous ;
5. AutoFill propose les items du bon compte : le compte qui revendique le domaine de travail (`somalabs.me`), sinon le compte personnel ;
6. une recherche « Tous les comptes » existe, mais seulement quand l'utilisateur la choisit, et seulement sur les comptes déverrouillés.

Ce qui existe déjà : le noyau ouvre un compte par fichier de stockage (`SyncStore::open(db_path)`, un seul compte par fichier, `has_account`) ; les éléments du trousseau Apple sont déjà nommés par identifiant de compte (`secretkey.<id>`, `biometric.enrollment.<id>`, clé Secure Enclave `me.somalabs.onepass.auk.<id>`) ; `VaultSession` prend un `VaultEnvironment` (fichier, réglages, trousseau). Ce qui manque : l'annuaire des comptes de l'appareil, des réglages séparés par compte, une zone CloudKit par compte, un gestionnaire de sessions, et l'interface.

## 2. Modèle de sécurité

Règle centrale : **deux comptes ne partagent jamais une clé**. Ajouter un compte n'ajoute aucun lien cryptographique entre comptes.

| Objet | Par compte | Partagé entre comptes |
| --- | --- | --- |
| Fichier de stockage (`vault.sqlite`) | oui, un fichier par compte | non |
| Keyset, AUK, clés de coffre, clés d'appareil | oui (2SKD propre) | non |
| Mot de passe maître, Secret Key, Emergency Kit | oui | non, même si l'utilisateur choisit le même mot de passe (sel et Secret Key différents) |
| Entrées du trousseau | oui, nommées par identifiant de compte | le service et le groupe d'accès du trousseau |
| Clé Secure Enclave du déverrouillage biométrique | oui, une étiquette par compte | non |
| Réglages (verrouillage auto, mode d'appareil, coffres masqués, compteur d'échecs, profil) | oui | non |
| Zone CloudKit | oui (`OnePass` pour le compte principal, `OnePass.<id de compte>` pour les autres) | la base privée iCloud de l'utilisateur |
| Watchtower, récents, presse-papiers | oui (la session de chaque compte) | non |
| Annuaire des comptes (`accounts.json`) | non | oui, métadonnées non secrètes seulement |

Garanties :

- **M1 Isolation des clés.** Ouvrir le compte A ne donne rien du compte B. Déverrouiller A ne déverrouille pas B, même avec le même mot de passe ; la biométrie d'un compte ouvre ce compte seulement.
- **M2 Isolation des données.** Une liste, une recherche, une fiche, l'AutoFill, le Watchtower, les widgets ne montrent qu'un compte à la fois. La seule exception est la vue « Tous les comptes » (section 7), désactivée par défaut, choisie par l'utilisateur, limitée aux comptes déverrouillés, et chaque résultat y porte le nom de son compte.
- **M3 Verrouillage indépendant.** Chaque compte a son délai ; « Verrouiller » verrouille le compte affiché ; « Tout verrouiller », le Control « Verrouiller OnePass », l'intention Siri et le passage en arrière-plan (selon le délai de chaque compte) verrouillent tous les comptes concernés.
- **M4 Liaison fichier et compte.** L'annuaire lie chaque emplacement à l'identifiant du compte qu'il a créé ou restauré. Un fichier dont le compte ne correspond plus (fichier déplacé ou échangé à la main) est refusé à l'ouverture (« Données refusées »), comme une autre incohérence de stockage.
- **M5 Un compte, un emplacement.** Le même compte ne peut pas être ajouté deux fois sur l'appareil (deux copies divergentes du même compte).
- **M6 Annuaire sans secret.** L'annuaire ne contient ni clé, ni Secret Key, ni nom de coffre ou d'item. Il contient le libellé choisi, le type, la couleur et les domaines de travail : l'écran de verrouillage doit pouvoir montrer les comptes avant tout déverrouillage. Il vit dans le conteneur partagé de l'app (protégé par la protection de données iOS, `completeUntilFirstUserAuthentication`, comme le stockage).
- **M7 Pas de chemin choisi par le fichier.** Le chemin d'un compte se déduit de son emplacement (16 octets aléatoires en hexadécimal), jamais lu dans l'annuaire : un annuaire modifié ne peut pas faire ouvrir un fichier hors du dossier OnePass.
- **M8 Retrait d'un compte de l'appareil.** Verrouille la session, efface le fichier de stockage de cet emplacement (et ses `-wal`, `-shm`), la Secret Key, l'inscription biométrique et la clé Secure Enclave de ce compte sur cet appareil. Rien n'est effacé dans iCloud ni sur les autres appareils. Le compte principal ne se retire pas (on le réinitialise comme aujourd'hui).

Hors périmètre : un appareil compromis au niveau système (il lit tous les comptes déverrouillés) ; cacher qu'un compte existe à quelqu'un qui tient l'appareil déverrouillé au niveau système (l'annuaire montre les libellés, ruling P2).

## 3. Types de compte (profils)

| Type | Stockage | Déverrouillage | État |
| --- | --- | --- | --- |
| `personal` | CloudKit, zone propre | 2SKD | construit |
| `business` (compte professionnel tenu par l'utilisateur, par exemple « Soma Labs » sans serveur d'organisation) | CloudKit, zone propre | 2SKD | construit |
| `managed` (compte géré par une organisation, E1) | serveur d'organisation (E9) | SSO ou 2SKD selon la politique (E4, E7) | côté client seulement, voir 3.1 |

Le type change l'apparence (icône : personne, mallette, bâtiment), la couleur par défaut (bleu, orange, indigo), la règle AutoFill par défaut (un compte professionnel propose de revendiquer le domaine de l'adresse e-mail de son profil) et le texte de l'écran de verrouillage. Il ne change aucune règle cryptographique.

### 3.1 Compte géré : ce qui existe et ce qui reste

Le serveur d'organisation (jalons E0 à E5 de la spec entreprise) n'est pas construit. Le client sait :

- représenter un compte géré dans l'annuaire avec son descripteur d'organisation (`server_url` en `https`, `org_id` de 16 octets) ;
- refuser de le créer tant qu'aucun `RecordStore` d'organisation n'est branché (`AccountError::ServerUnavailable`, « Ce compte se connecte au serveur de ton organisation, qui n'est pas encore disponible dans cette version. ») ;
- tout le reste (session, verrouillage, AutoFill, sélecteur, couleur) ne dépend pas du stockage : quand E0 et E1 arriveront, un `RecordStore` serveur remplace CloudKit pour cet emplacement, derrière la même interface `RemoteRecordStore`.

Ce qui reste pour un compte géré : E0 (serveur), E1 (organisation, genèse `org`), E5 (SSO), l'épinglage de l'organisation à l'adhésion (E2 de la spec entreprise), l'adhésion par lien d'invitation.

## 4. Annuaire des comptes (noyau)

Module `onepass_core::profiles`. Fichier `accounts.json` dans le dossier du stockage principal, écrit en entier dans un fichier temporaire du même dossier puis renommé (écriture atomique), lu par l'app et l'extension AutoFill.

```text
AccountDirectory {
  version: 1,
  active: Slot,               // compte affiché au lancement
  unified_search: bool,       // vue "Tous les comptes" choisie (défaut false)
  entries: [AccountEntry],    // ordre d'affichage, le principal en tête
}
AccountEntry {
  slot: Slot,                 // "primary" ou 32 caractères hexadécimaux
  account_id: Option<Id>,     // lié à la création ou à la restauration
  kind: Personal | Business | Managed { server_url, org_id },
  label: String,              // 1 à 64 caractères, sans caractère de contrôle
  color: AccountColor,        // blue, green, orange, purple, pink, teal, indigo, graphite
  work_domains: [String],     // au plus 32, minuscules, ASCII (punycode), sans joker
  created_at: i64,
}
```

- Fichier absent : un annuaire implicite avec le seul compte principal (`slot = primary`, `personal`, libellé vide : l'app affiche le nom du profil). Aucun fichier n'est écrit tant que l'utilisateur n'ajoute pas de compte : un appareil à un compte reste exactement comme avant.
- Chemins : `primary` -> `<dossier>/vault.sqlite` (inchangé, aucune migration) ; autre emplacement -> `<dossier>/accounts/<slot>/vault.sqlite`.
- Validation au chargement : version connue, un seul `primary` en tête, emplacements uniques et bien formés, `account_id` uniques, libellés valides, domaines valides et revendiqués par un seul compte, `active` présent, au plus 8 comptes. Un annuaire invalide est une erreur (`IntegrityError::AccountDirectory`) : l'app ouvre alors le compte principal seul et le dit dans Réglages > Comptes, sans rien réécrire.
- Opérations : `add(kind, label, color)` (nouvel emplacement aléatoire), `bind(slot, account_id)` (refuse un compte déjà lié ailleurs, M5 ; refuse de changer un lien existant, M4), `update(slot, label, color, work_domains)`, `remove(slot)` (pas le principal ; l'actif retombe sur le principal), `set_active(slot)`, `set_unified_search(bool)`, `route(host)`.
- `route(host)` : le compte dont un domaine de travail est l'hôte ou l'un de ses parents sur une frontière de label (`mail.somalabs.me` correspond à `somalabs.me`, `evilsomalabs.me` non), le plus long domaine gagnant ; sinon le principal. Un hôte vide ou invalide va au principal.
- `check_binding(slot, store_account_id)` : M4.

## 5. FFI

Fonctions `uniffi` sur le chemin du dossier (`accounts.rs` dans `onepass-ffi`) : `account_directory_load`, `account_directory_add`, `account_directory_bind`, `account_directory_update`, `account_directory_remove`, `account_directory_set_active`, `account_directory_set_unified_search`, `account_directory_route`, `account_store_path`, et `store_account_id(db_path)` (identifiant du compte d'un fichier, sans déverrouiller, pour M4). Types `FfiAccountDirectory`, `FfiAccountEntry`, `FfiAccountKind`, `FfiAccountColor`. Erreurs existantes `OnePassError` (`InvalidInput`, `Integrity`, `NotFound`, `Conflict`).

## 6. VaultKit

- **Réglages par compte.** `VaultSettings(defaults:scope:)` : le compte principal garde ses clés (`onepass.*`, aucune migration) ; un autre compte préfixe chaque clé par `onepass.acct.<slot>.`. Toute propriété de `VaultSettings`, y compris celles qu'ajouteront d'autres chantiers, passe par ce préfixe (le stockage interne est un `ScopedDefaults` qui garde la même API que `UserDefaults`).
- **`AccountDirectoryStore`** : lecture et écriture de l'annuaire par la FFI, notification Darwin `me.somalabs.onepass.accounts-changed` après une écriture (l'extension relit).
- **`AccountSessions`** (`@Observable`, acteur principal) : une `VaultSession` par compte de l'annuaire, créée à la demande par une fabrique d'environnement fournie par l'app (fichier, réglages à portée, même trousseau). Expose `entries`, `active`, `activeSession`, `primarySession`, `switchTo(slot)`, `lock(slot)`, `lockAll()`, `beginAdding(kind:label:color:)` (crée l'emplacement et sa session vide, état `noAccount`), `cancelAdding(slot)`, `finishAdding(slot)` (lie l'identifiant de compte), `remove(slot)` (M8), `update(...)`, `route(host:)`, `unifiedResults(query:)` (vide si la vue n'est pas choisie ; sinon les comptes déverrouillés seulement, résultats étiquetés).
- **CloudKit** : `CloudKitRemote(containerIdentifier:zoneName:)`, zone `OnePass` par défaut, `OnePass.<id de compte>` pour un autre compte. Un autre appareil retrouve la zone d'un compte ajouté par la liste des zones `OnePass.*` (`CloudKitRemote.accountZones`).

## 7. Interface

- **Panneau de l'avatar (iPhone, iPad)** : section « Comptes » en tête du panneau : chaque compte avec son avatar coloré, son libellé, son type et un cadenas s'il est verrouillé ; le compte affiché est coché ; « Ajouter un compte… » ; « Tout verrouiller » quand plus d'un compte est ouvert. Elle suit le style du panneau tel que le chantier `ios-shell` le redessine.
- **Mac** : la même section dans le menu du compte de la barre latérale, plus Fenêtre > Comptes (⌃⌘1 à ⌃⌘8).
- **Avatar** : initiales sur la couleur du compte ; une petite pastille de type (mallette, bâtiment) pour un compte non personnel.
- **Écran de verrouillage** : avatar, libellé et type du compte ; s'il y a plusieurs comptes, un menu pour verrouiller ou déverrouiller un autre compte sans passer par l'app ouverte.
- **Ajouter un compte** : une feuille : type (Personnel, Professionnel, Organisation), nom du compte, couleur ; puis « Créer un compte » (le parcours d'inscription existant, son Emergency Kit) ou « Se connecter à un compte existant » (Emergency Kit ou Secret Key plus mot de passe, le parcours de restauration existant). Annuler à toute étape retire l'emplacement.
- **Réglages > Comptes** : liste, réordonner, renommer, couleur, domaines de travail (« Utiliser ce compte pour l'AutoFill sur… »), vue « Tous les comptes », retirer de cet appareil (confirmation qui dit ce qui est effacé et ce qui reste).
- **Recherche « Tous les comptes »** : quand la vue est choisie, le menu du compte ajoute « Rechercher dans tous les comptes », une feuille à part (la recherche de chaque liste reste limitée au compte affiché). Les résultats sont groupés par compte, les comptes verrouillés sont listés à part sans résultats ; toucher un résultat change de compte et ouvre l'item.
- **Écran de verrouillage** : avec plusieurs comptes, la capsule du compte devient un menu qui change de compte ; chaque compte garde son déverrouillage. Les vues verrouillée et ouverte sont recréées à chaque changement de compte (rien de saisi ou d'affiché ne passe d'un compte à l'autre).
- **Watchtower** : celui du compte affiché, recalculé au changement de compte.

## 8. AutoFill

- Extension AutoFill (iPhone, iPad, Mac) : à chaque requête, l'hôte du service passe par `route(host)` ; la session de la requête s'ouvre sur ce compte. Une requête sans hôte (saisie de texte, configuration, suggestion QuickType) ouvre le compte principal. Un emplacement dont le fichier n'existe pas encore, ou dont le fichier ne contient pas le compte lié (M4), n'est jamais ouvert : le compte principal répond. Une seule session par requête : l'extension ne montre jamais deux comptes à la fois.
- Suggestions QuickType : le magasin d'identités du système est unique par app et réécrit en entier : il ne reçoit que les identités du compte principal en v1 (ruling P6).
- Pont des navigateurs (Mac), agents SSH et MCP, téléphone approbateur, widgets et montre : restent sur le compte principal en v1 (ruling P7).

## 9. Ce que cette conception ne change pas

Aucun format de stockage, d'enregistrement, de keyset ou de lignée. Aucun `RecordKind`. Aucun appareil ne voit de changement tant qu'un seul compte existe (pas d'annuaire écrit, mêmes clés de réglages, même zone CloudKit, même fichier).

## 10. Tests

- Noyau : annuaire implicite, ajout, liaison (refus d'un compte lié ailleurs, refus d'un nouveau lien), retrait (refus du principal, actif qui retombe), validation (emplacement mal formé, `..`, doublons, libellés, domaines, plus de 8, version inconnue), chemins sans traversée, `route` (frontière de label, plus long domaine, majuscules, point final, hôte invalide), écriture atomique, deux comptes réels dans deux fichiers : un mot de passe et une Secret Key d'un compte n'ouvrent pas l'autre, même mot de passe des deux côtés.
- VaultKit : réglages à portée (le principal garde ses clés, deux portées ne se voient pas), `AccountSessions` (ajout, annulation, liaison, changement, verrouiller un ou tous, retrait qui efface fichier et Secret Key du seul compte retiré, vue unifiée vide par défaut puis limitée aux comptes déverrouillés, refus du compte géré sans serveur), routage AutoFill.
- App : compilations iPhone et Mac ; captures simulateur (panneau, ajout, écran de verrouillage, Réglages > Comptes) dans `~/Desktop/OnePass-test-videos/2026-11-02-feedback/profiles/`.

## 11. Rulings

Format : décision - raison - coût si c'est faux.

- **P1** Un compte = un fichier de stockage, un keyset, une Secret Key ; le compte principal garde son fichier, ses clés de réglages et sa zone - zéro migration pour les appareils existants, isolation par construction - deux chemins de code (principal et autres) à tester.
- **P2** Annuaire en clair (libellés, types, couleurs, domaines), pas de chiffrement - l'écran de verrouillage et l'AutoFill doivent choisir un compte avant tout déverrouillage, comme 1Password affiche ses comptes - quelqu'un qui lit le conteneur apprend qu'un compte « Soma Labs » existe.
- **P3** Trois types (personnel, professionnel, géré), le type ne change aucune règle cryptographique - les profils servent l'usage, la sécurité reste celle d'un compte - aucun.
- **P4** Vue « Tous les comptes » désactivée par défaut, recherche seulement, comptes déverrouillés seulement, jamais dans l'AutoFill - M2 - moins pratique pour qui veut tout mélanger.
- **P5** AutoFill par domaine de travail revendiqué par un seul compte, sinon le principal - une règle simple et prévisible, pas de fuite d'un compte vers un site de l'autre - un site pro non revendiqué tombe sur le compte personnel (l'utilisateur ajoute le domaine).
- **P6** QuickType ne reçoit que le compte principal en v1 - le magasin d'identités du système est remplacé en entier à chaque écriture, deux sessions s'écraseraient - les logins pro n'apparaissent pas dans la barre QuickType (ils restent dans la liste AutoFill par domaine).
- **P7** Pont des navigateurs Mac, SSH et MCP, approbations téléphone, widgets et montre restent sur le compte principal en v1 - ces services tiennent une seule session et des sockets ; les dédoubler sans plan dédié risquerait une fuite entre comptes - le Mac ne remplit pas un compte pro dans Safari ou Chrome par l'extension avant la v1.1 (l'AutoFill système le fait).
- **P8** Zone CloudKit `OnePass.<id de compte>` pour un compte ajouté - stable d'un appareil à l'autre, l'identifiant de compte est déjà visible d'Apple dans les noms d'enregistrements - la connexion sur un nouvel appareil choisit la zone d'après l'Emergency Kit : le QR code des kits (version 2) porte l'identifiant du compte ; un seul compte absent de l'appareil suffit sans lui ; avec plusieurs comptes absents et un kit sans identifiant (Secret Key tapée, kit version 1), l'étape demande l'identifiant imprimé sur le kit, jamais de choix au hasard ni d'essai de mot de passe zone par zone (le verrouillage après 5 essais ne doit pas compter des essais faits sur le mauvais compte) - un kit version 1 avec plusieurs comptes absents demande de taper 32 caractères.
- **P9** Au plus 8 comptes par appareil - interface et coût mémoire bornés - aucun cas connu au-delà.
- **P10** Retirer un compte de l'appareil efface ses données locales et ses entrées du trousseau, jamais iCloud - c'est « se déconnecter », pas « supprimer le compte » - un compte retiré par erreur se restaure avec son Emergency Kit.
- **P11** Compte géré représenté et refusé à la création sans serveur (`ServerUnavailable`) - le serveur E0 n'existe pas, rien ne doit faire croire qu'un compte d'organisation fonctionne - la feuille montre le type grisé avec son explication.
- **P12** Réglages d'un compte ajouté sous le préfixe `onepass.acct.<slot>.` dans la même suite partagée - l'extension les lit sans nouvelle suite ni nouveau droit - les clés d'un compte retiré sont effacées par préfixe.
- **P13** Changer de compte ne verrouille pas le précédent : il suit son propre délai - c'est ce que demande un usage pro et perso en alternance - plus de sessions ouvertes en mémoire (chaque délai s'applique).
