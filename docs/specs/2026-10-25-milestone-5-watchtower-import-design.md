# OnePass jalon 5 (côté core) : Watchtower, import, export, sauvegarde

Date : 2026-10-25
Statut : validée (auto-validation, voir "Mode de décision")
Portée : partie Rust du jalon 5 de la spec d'architecture (section 13, point 5 ; sections 8 et 10). L'interface, les notifications et le pack d'icônes appartiennent au jalon des apps.
Branche de travail, basée sur `feat/core-m1`.

## 0. Mode de décision

L'utilisateur a demandé que tous les jalons avancent en parallèle sans aucune action de sa part. Chaque point où le processus attend normalement une validation humaine est donc tranché ici, et consigné sous la forme :

`Ruling: <quoi> - <pourquoi> - <coût si c'est faux>`

La liste complète est en section 12.

## 1. Objectif et critères de réussite

Ce que l'utilisateur a demandé :

- Watchtower : mots de passe faibles, réutilisés et compromis (requêtes par plage en k-anonymity compatibles HIBP, mode hors ligne, aucun secret ne sort de l'appareil en clair), 2FA absente sur un site qui la propose, URL en HTTP, cartes et documents qui expirent, passkey disponible. Un rapport noté exposé par une API.
- Import avec correspondance vers les 26 types : 1Password (1PUX et CSV), Bitwarden (JSON et CSV), Chrome/Edge/Brave CSV, Safari/Apple Passwords CSV, Firefox CSV, KeePass XML (KDBX si peu coûteux), Dashlane, LastPass CSV, et l'export Wi-Fi du trousseau Apple vers des items Router.
- Export vers un format OnePass chiffré et documenté, et vers un CSV en clair avec un avertissement appuyé.
- Format de sauvegarde chiffrée et de restauration, versionné.
- Tout est exposé par l'API de `core` et par la CLI de dev (`onepass import`, `export`, `watchtower`, `backup`).

Contraintes :

- Code neuf dans des modules neufs ; pas de changement des API existantes de `core` (d'autres sessions travaillent dessus en parallèle).
- Tout parseur traite son entrée comme hostile : plafonds de taille, aucune panique, une cible de fuzzing par parseur.
- Fixtures de test synthétiques uniquement. Aucun réseau dans les tests (la source de plages HIBP est simulée).

Critères de réussite :

1. `make check` vert (fmt, clippy `-D warnings`, tests, `cargo deny`).
2. Chaque format d'import a des tests sur fixtures synthétiques et une cible de fuzzing, et produit des items qui passent `model::validate`.
3. Un export chiffré puis réimporté redonne les mêmes items, octet pour octet après encodage postcard.
4. Une sauvegarde modifiée d'un seul bit, tronquée, rejouée sous un autre compte, ou forgée avec la seule clé publique du compte, est refusée.
5. Le rapport Watchtower ne contient aucune valeur secrète (test qui cherche les mots de passe des fixtures dans `Debug` et dans le JSON de la CLI).
6. Seuls 5 caractères hexadécimaux du SHA-1 de chaque mot de passe quittent `core` vers la source de plages.

## 2. Vue d'ensemble

Quatre modules neufs dans `onepass-core`, plus des commandes neuves dans `onepass-cli` :

| Module | Rôle | Dépend de |
| --- | --- | --- |
| `watchtower` | analyse d'une liste d'items, rapport noté | `model`, `crypto` (SHA-1 via `aws-lc-rs`), `zxcvbn` |
| `import` | parseurs de formats tiers vers `Item` | `model`, `totp`, `csv`, `zip`, `quick-xml`, `serde_json` |
| `archive` | conteneur chiffré OnePass (export et sauvegarde) | `crypto`, `account`, `vault`, `model` |
| `export` | export CSV en clair | `model` |
| `icon` | candidats d'URL d'icône pour un item | `model`, `model::checks` |

Modifications de fichiers existants, toutes additives :

- `lib.rs` : les lignes `pub mod` des nouveaux modules.
- `crypto/aead.rs` : variante `BlobKind::Archive = 9`, ajoutée en fin d'enum.
- `repo.rs` : accesseur `Repository::account(&self) -> &Account`.
- `Cargo.toml` des deux crates, `Makefile` (cibles de fuzzing), `fuzz/`.
- `onepass-cli/src/main.rs` : quatre sous-commandes.

## 3. Watchtower

### 3.1 API

```rust
pub struct Options {
    pub today: time::Date,
    /// Jours avant échéance où une expiration devient un avertissement.
    pub expiry_warning_days: u16,        // défaut 30
    /// Âge (jours) au-delà duquel un mot de passe est "ancien".
    pub old_password_days: u16,          // défaut 365
}

pub struct Sources<'a> {
    /// `None` : vérification des fuites désactivée (mode hors ligne strict).
    pub pwned: Option<&'a mut dyn RangeSource>,
    pub sites: Option<&'a SiteDirectory>,     // 2FA et passkeys
    pub breaches: Option<&'a BreachCatalog>,  // sites piratés
}

pub fn analyze(items: &[Item], opts: &Options, sources: Sources<'_>) -> Report;
```

`analyze` ne fait aucune entrée-sortie elle-même : le réseau et les fichiers passent par `RangeSource` et par les catalogues déjà chargés. Les items à la corbeille ou archivés sont ignorés.

### 3.2 Contrôles

Chaque contrôle a un identifiant stable, utilisé dans le rapport et dans `Item::watchtower_exclusions` (un item qui liste l'identifiant n'est pas contrôlé pour lui).

| Id | Déclencheur | Gravité |
| --- | --- | --- |
| `compromised` | mot de passe présent dans la base de plages (compte > 0) | critique |
| `reused` | même mot de passe dans au moins deux champs `Password` d'items distincts | haute |
| `weak` | score `zxcvbn` < 3 (entrées utilisateur : titre, identifiant, hôte) | haute |
| `provider_exposed` | compte fournisseur (cible d'un `LoginMethod::Provider`) compromis, réutilisé, faible, ou sans TOTP ni passkey ; liste les items dépendants | critique |
| `breached_site` | domaine d'une URL présent dans le catalogue des fuites, et mot de passe pas changé depuis la fuite | haute |
| `insecure_url` | URL en `http://` (hors `localhost`, `127.0.0.1`, `[::1]`, `*.local`) | moyenne |
| `wifi_insecure` | Router avec sécurité WEP ou ouverte | moyenne |
| `ssh_weak` | clé SSH RSA de moins de 3072 bits, ou DSA | moyenne |
| `expired` | date d'expiration passée | haute |
| `expiring` | expiration dans les `expiry_warning_days` jours | moyenne |
| `missing_2fa` | le site propose la 2FA (TOTP ou clé) et le Login n'a pas de TOTP | basse |
| `passkey_available` | le site accepte les passkeys et le Login n'en a pas | info |
| `old_password` | mot de passe inchangé depuis `old_password_days` | basse |
| `duplicate` | deux Login avec le même hôte et le même identifiant | info |
| `wallet_no_backup` | Crypto Wallet sans emplacement de sauvegarde physique | basse |

Champs d'expiration lus : `Item::expires` pour tous les types, puis `CreditCard.expiry` (fin du mois), `IdCard.expiry`, `Passport.expiry`, `DriverLicense.expiry`, `Membership.expiry`, `Document.expiry`, `ApiCredential.expires_on`, `Insurance.renewal_date`, `SoftwareLicense.updates_until`, `RewardProgram.points_expiry`. L'échéance d'un abonnement (`Subscription.next_renewal`) n'est pas une expiration et n'est pas signalée.

Champs mot de passe : tout champ de valeur `FieldValue::Password`, dans toutes les sections. Un rapport désigne un champ par son id, jamais par sa valeur.

### 3.3 Fuites de mots de passe (k-anonymity)

```rust
pub trait RangeSource {
    /// Corps de la réponse pour un préfixe de 5 hex majuscules.
    fn range(&mut self, prefix: &str) -> Result<Vec<u8>>;
}
```

- Le SHA-1 de chaque mot de passe distinct est calculé en mémoire (`Zeroizing`). Seul le préfixe de 5 caractères est passé à la source ; le suffixe de 35 caractères est comparé en local.
- Un préfixe n'est demandé qu'une fois par analyse.
- Format de réponse (HIBP `range`) : lignes `SUFFIXE:COMPTE`, CRLF ou LF. Les lignes de compte 0 (bourrage `Add-Padding: true`) sont ignorées. Corps plafonné à 4 Mio ; une ligne mal formée rend la réponse invalide pour ce préfixe.
- Une source en erreur ne fait pas échouer l'analyse : `Report::pwned` passe à `Partial { failed_prefixes }` ou `Unavailable`.
- Sources fournies :
  - `DirRangeSource` : dossier de fichiers `ABCDE.txt` au format de PwnedPasswordsDownloader (mode hors ligne complet) ;
  - la CLI fournit une source HTTP qui appelle `https://api.pwnedpasswords.com/range/{préfixe}` avec l'en-tête `Add-Padding: true`, via `curl` ;
  - les apps fourniront la leur (URLSession) au jalon des apps.

### 3.4 Catalogues de sites

`SiteDirectory` agrège deux sources publiques, chacune chargée depuis des octets fournis par l'appelant :

- `SiteDirectory::from_2fa_directory(json)` : format `https://api.2fa.directory/v4/all.json`, objet `domaine -> { "methods": [...] }`. Un objet vide veut dire "pas de 2FA". TOTP disponible si `methods` contient `totp`, clé matérielle si `u2f`.
- `SiteDirectory::add_passkeys_directory(json)` : format `https://passkeys-api.2fa.directory/v1/all.json`, objet `domaine -> { "passwordless": "allowed", "mfa": "allowed" }`.

`BreachCatalog::from_hibp(json)` : format `https://haveibeenpwned.com/api/v3/breaches`, tableau d'objets `Domain`, `BreachDate`, `Name`, `IsVerified`. Seules les fuites vérifiées avec un domaine non vide sont retenues.

Correspondance d'un hôte : égal au domaine, ou se terminant par `.` + domaine. Pas de liste des suffixes publics. Plafonds : 16 Mio par document, 100 000 entrées, 253 octets par domaine.

### 3.5 Rapport et score

```rust
pub struct Report {
    pub score: u8,                    // global, 0 à 100
    pub vaults: Vec<VaultScore>,      // id de vault, score, nombre d'items
    pub findings: Vec<Finding>,
    pub counts: BTreeMap<Check, u32>,
    pub pwned: PwnedStatus,           // Checked | Partial { failed_prefixes } | Unavailable | Disabled
}

pub struct Finding {
    pub item_id: Id,
    pub vault_id: Id,
    pub check: Check,
    pub severity: Severity,           // Critical, High, Medium, Low, Info
    pub field_id: Option<String>,
    pub detail: Detail,               // jamais de valeur secrète
}
```

`Detail` porte des données non secrètes : nombre d'apparitions dans les fuites, id du groupe de réutilisation et nombre de membres, score zxcvbn, date d'expiration, nom de la fuite et sa date, items dépendants d'un compte fournisseur, taille de clé RSA.

Score : santé d'un item `h = max(0, 1 - somme des poids)`, poids par gravité critique 1,0 ; haute 0,5 ; moyenne 0,25 ; basse 0,1 ; info 0. Score d'un vault = `round(100 * moyenne(h))` sur ses items analysés ; vault vide = 100. Score global = même formule sur tous les items analysés (pas une moyenne des vaults).

`Report` et `Finding` implémentent `Serialize` pour la CLI et les bindings.

## 4. Import

### 4.1 API

```rust
pub enum Format {
    OnePasswordPux, OnePasswordCsv, BitwardenJson, BitwardenCsv, ChromeCsv,
    SafariCsv, FirefoxCsv, LastPassCsv, DashlaneCsv, DashlaneZip, ProtonPassCsv,
    KeePassXml, CredentialExchange, OtpAuthUris, WifiQr, OnePassArchive,
}

pub fn detect(file_name: &str, bytes: &[u8]) -> Option<Format>;
pub fn parse(format: Format, bytes: &[u8]) -> Result<Import>;

pub struct Import {
    pub items: Vec<ImportedItem>,
    pub warnings: Vec<Warning>,      // index d'entrée + code statique, aucune valeur
    pub skipped: u32,                // lignes vides ou entrées non prises en charge
}

pub struct ImportedItem {
    pub item: Item,                  // vault_id = Id([0; 16]) tant que la cible n'est pas choisie
    pub folder: Option<String>,      // vault, dossier ou groupe de la source
}
```

`OnePassArchive` passe par le module `archive` (section 5) et n'est pas accepté par `parse` : il demande une phrase de passe.

La CLI (et plus tard les apps) choisit le vault cible et appelle `Repository::save_item` pour chaque item.

### 4.2 Construction des items

Un constructeur commun (`import::build`) part de `templates::new_item`, remplit les champs par id de modèle, et range toute donnée sans champ prévu dans une section `imported` ("Importé") en champs personnalisés : `Concealed` si la source la marquait comme cachée ou si son nom évoque un secret, `Text` sinon. Aucune valeur n'est perdue en silence.

Règle de validité : chaque item rendu passe `model::validate`. Si la validation échoue :

1. un champ au format invalide (numéro de carte, IBAN, phrase BIP39, numéro national) est déplacé dans la section `imported` ;
2. un Login sans identifiant devient un item `Password` s'il a un mot de passe (URL, notes et TOTP conservés en section `imported`) ;
3. s'il manque encore un champ obligatoire, l'item devient une `SecureNote` : contenu = notes de la source, ou titre si elles sont vides ; toutes les valeurs en section `imported`.

Chaque repli ajoute un avertissement. Un titre vide devient l'hôte de la première URL, sinon "Sans titre".

TOTP : une valeur `otpauth://` est gardée telle quelle si `totp::parse_otpauth` l'accepte ; un secret base32 nu devient `otpauth://totp/<titre>?secret=<secret>` ; une valeur refusée part en section `imported` (caché).

### 4.3 Correspondances par format

| Format | Détection | Types produits |
| --- | --- | --- |
| 1Password 1PUX | zip avec `export.data` | les 22 catégories 1Password vers les types OnePass (table en annexe A) |
| 1Password CSV | en-tête `Title,Url,Username,Password,OTPAuth,...` | Login |
| Bitwarden JSON | objet avec `items`, `encrypted: false` | Login, SecureNote, CreditCard, Identity, SshKey |
| Bitwarden CSV | en-tête `folder,favorite,type,name,notes,fields,reprompt,login_uri,...` | Login, SecureNote |
| Chrome / Edge / Brave CSV | en-tête `name,url,username,password[,note]` | Login |
| Safari / Apple Passwords CSV | en-tête `Title,URL,Username,Password,Notes,OTPAuth` | Login |
| Firefox CSV | en-tête `url,username,password,httpRealm,...` | Login |
| LastPass CSV | en-tête `url,username,password,totp,extra,name,grouping,fav` | Login ; notes sécurisées `http://sn` : CreditCard, BankAccount, Router, Server, Database, SshKey, Passport, DriverLicense, SocialSecurityNumber, Email, SoftwareLicense, Membership, Insurance, sinon SecureNote |
| Dashlane | `credentials.csv`, `securenotes.csv`, `payments.csv`, `ids.csv`, `personalInfo.csv`, seuls ou dans un zip | Login, SecureNote, CreditCard, BankAccount, IdCard, Passport, DriverLicense, SocialSecurityNumber, Identity |
| Proton Pass CSV | en-tête `type,name,url,email,username,password,note,totp,...` | Login, SecureNote |
| KeePass 2 XML | racine `KeePassFile` | Login (titre, identifiant, mot de passe, URL, notes, `otp`), champs perso en section `imported`, expiration de l'entrée |
| Credential Exchange (CXF) | objet JSON avec `accounts[].items[].credentials` | Login (`basic-auth`, `totp`, `passkey`), Router (`wifi`), SecureNote (`note`), CreditCard (`credit-card`) |
| URI otpauth | lignes `otpauth://` ou `otpauth-migration://` (Google Authenticator) | Login (identifiant = compte, sinon émetteur) |
| QR Wi-Fi | lignes `WIFI:S:...;T:...;P:...;H:...;;` | Router |
| OnePass CSV (`onepass-csv`) | en-tête exact `title,type,vault,url,username,password,otpauth,notes,tags,extra` (export de la section 6) | Login (`vault` vers dossier, lignes `id=valeur` de `extra` en section `imported`, autre `type` gardé en `imported` avec les replis de 4.2) |

Wi-Fi du trousseau Apple : voir 4.5.

Les exports chiffrés (Bitwarden `encrypted: true`, Dashlane `.dash`, 1Password `.1pif` chiffré, KDBX) sont refusés avec un message qui dit quel export en clair produire.

### 4.4 Entrées hostiles

- Fichier d'entrée : 256 Mio au plus.
- Zip (1PUX, Dashlane) : 10 000 entrées au plus ; taille décompressée lue en flux, plafonnée à 512 Mio au total et 64 Mio pour `export.data` ; les noms d'entrée ne sont jamais utilisés comme chemins (aucune écriture disque) ; méthodes acceptées : stockée et deflate.
- CSV : UTF-8 strict (BOM UTF-8 retiré), 1 Mio par cellule, 1 000 000 de lignes.
- JSON : `serde_json` sur le document entier, profondeur limitée par le défaut de `serde_json` (128).
- XML : pas d'expansion d'entités hors entités prédéfinies (comportement de `quick-xml`), profondeur 256, 1 000 000 d'entrées.
- 1 000 000 d'items par import.
- Dans les nouveaux modules, hors tests : `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]`.

Toute violation donne `Error::InvalidFormat` avec une raison statique.

### 4.5 Wi-Fi du trousseau Apple

Aucune API publique ne lit les mots de passe Wi-Fi. Trois chemins dans ce jalon :

1. CLI sur Mac : `onepass import --wifi-keychain`. La CLI liste les réseaux connus par `networksetup -listpreferredwirelessnetworks <interface>` (interface trouvée par `networksetup -listallhardwareports`), puis lit chaque mot de passe par `security find-generic-password -D "AirPort network password" -a <SSID> -w`. macOS demande l'authentification administrateur. Le core fournit les parseurs des deux sorties (`import::wifi::parse_preferred_networks`, `parse_hardware_ports`) et la fabrique d'items Router ; la CLI fournit l'exécution, derrière un trait `CommandRunner` simulé dans les tests.
2. Credential Exchange : type `wifi` (section 4.3).
3. QR codes `WIFI:` collés ou scannés (section 4.3).

Sécurité Wi-Fi rangée dans le menu `security` : `WPA3`, `WPA2`, `WPA`, `WEP`, `ouvert`.

## 5. Archive OnePass (export chiffré et sauvegarde)

### 5.1 Principe

Un seul conteneur, `archive`, sert à l'export et à la sauvegarde. Extension `.onepass`. Il chiffre un instantané d'items sous une clé de contenu aléatoire, enveloppée pour un ou plusieurs destinataires :

- destinataire phrase de passe : export portable, restaurable dans n'importe quel compte ;
- destinataire compte : la clé est enveloppée vers la clé KEM publique hybride du compte (ML-KEM-1024 + X25519, `crypto::wrap_key`) ; l'archive est en plus signée par la clé de signature hybride du compte. C'est le mode des sauvegardes : il ne demande aucune saisie et seul ce compte peut les ouvrir.

### 5.2 Format

```
"OPARCH" (6 octets) || format (u8 = 1) || longueur de l'en-tête (u32 big-endian) || en-tête (postcard) || charge scellée
```

```rust
struct Header {
    archive_id: Id,
    kind: ArchiveKind,                 // Export | Backup
    created_at: i64,                   // secondes Unix
    payload_schema: u16,               // 1
    recipients: Vec<Recipient>,        // 1 à 8
    signature: Option<Signed>,         // obligatoire si un destinataire Account est présent
}
enum Recipient {
    Passphrase { kdf: KdfParams, wrapped_key: Vec<u8> },
    Account { account_id: Id, envelope: Vec<u8> },
}
struct Signed { account_id: Id, signature: HybridSignature }
```

- Clé de contenu `K` : 32 octets aléatoires.
- Charge : `aead::seal(K, BlobKind::Archive, Aad { blob_id: archive_id, vault_id: None, schema: payload_schema }, postcard(Payload))`.
- Destinataire phrase de passe : `KEK = derive(derive_auk(NFC(phrase), SecretKey zéro, kdf), "onepass/archive/kek/v1")` ; `wrapped_key = aead::seal(KEK, BlobKind::Archive, Aad { blob_id: archive_id, vault_id: None, schema: 0 }, K)`. La phrase de passe doit avoir un score zxcvbn d'au moins 3. Paramètres Argon2id : le plancher appliqué aux comptes à la création ; à l'ouverture, au plus le plafond des comptes (2 Gio, t 16, p 16).
- Destinataire compte : `envelope = wrap_key(kem_pub, K, "onepass/archive/v1" || archive_id)`.
- Signature (si destinataire compte) : `signing.sign(b"onepass/archive/v1", SHA-256(magic || format || en-tête sans signature || charge))`.
- La charge répète `archive_id`, `kind`, `created_at` et `payload_schema` ; l'ouverture vérifie qu'ils égalent ceux de l'en-tête.

```rust
struct Payload {
    archive_id: Id,
    kind: ArchiveKind,
    created_at: i64,
    payload_schema: u16,
    source_account: Option<Id>,
    vaults: Vec<ArchivedVault>,     // { id: Id, meta: VaultMeta, items: Vec<Item> }
}
```

`Item` et `VaultMeta` sont encodés par postcard avec le même encodage que le stockage (variantes en ajout seulement, déjà figées par `model::wire_tests`). Les pièces jointes ne sont pas incluses dans ce jalon (aucun producteur de `BlobKind::Attachment` n'existe encore).

### 5.3 Versionnement

- `format` (octet 7) : structure du conteneur. Un lecteur refuse un format inconnu.
- `payload_schema` : structure de `Payload`. Un lecteur accepte tout schéma de 1 à `CURRENT_SCHEMA` et refuse un schéma plus récent avec `InvalidFormat("archive from a newer version")`. Une évolution future ajoute une fonction de migration par schéma.
- Golden test : un en-tête et une charge de référence figés en hexadécimal dans les tests.

### 5.4 Ouverture et vérifications

`archive::open(bytes, Unlock::Passphrase(&str) | Unlock::Account(&Account)) -> Result<Opened>` vérifie dans l'ordre : magic, format, longueur et décodage de l'en-tête (64 Kio au plus, aucun octet en trop), nombre de destinataires, signature obligatoire si destinataire compte (vérifiée contre la clé de signature du compte qui ouvre, et son `account_id`), plafonds KDF, désenveloppement de `K`, ouverture de la charge, égalité des champs répétés, décodage de la charge (aucun octet en trop). Plafonds de charge : 1 Gio, 10 000 vaults, 1 000 000 d'items.

Erreurs : mauvaise phrase de passe ou mauvais compte : `Error::WrongPassword` ; signature absente ou fausse : `IntegrityError::Signature` ; tout autre défaut : `InvalidFormat` ou l'erreur d'intégrité de l'AEAD.

`archive::inspect(bytes)` rend l'en-tête seul (id, type, date, destinataires sans leurs octets) pour `onepass backup inspect`.

### 5.5 Sauvegarde et restauration

- `archive::backup(account, vaults: &[(Vault meta, Vec<Item>)]) -> Vec<u8>` : type `Backup`, destinataire compte, signée ; destinataire phrase de passe en plus si demandé.
- `archive::export(vaults, passphrase) -> Vec<u8>` : type `Export`, destinataire phrase de passe seul, non signée.
- Restauration (`archive::restore_plan`) : pour chaque vault de l'archive, réutilise le vault du même id s'il existe, sinon en crée un avec la même méta (nouvel id) ; chaque item garde son id, `vault_id` réécrit ; un item dont l'id existe déjà dans la cible est sauté et compté. Pas d'écrasement dans ce jalon.
- Corbeille et archivés : inclus dans la sauvegarde et restaurés tels quels.

## 6. Export CSV en clair

`export::csv_plaintext(vaults) -> Zeroizing<Vec<u8>>`. Colonnes : `title,type,vault,url,username,password,otpauth,notes,tags,extra`. `url` : URL principale ; `extra` : les autres champs non vides, `id=valeur` séparés par des retours à la ligne. Le format reste lisible par les importeurs CSV génériques (Login).

Avertissement : la CLI refuse sans `--plaintext`, affiche un avertissement sur stderr avant d'écrire, crée le fichier en mode 0600 et refuse d'écraser un fichier existant. La documentation de la fonction répète l'avertissement. Pas d'échappement des formules de tableur (voir ruling).

## 7. Icônes

`icon::hint(item) -> IconHint { host, candidates, card_brand, letter }` : hôte de l'URL principale, URLs candidates `https://<hôte>/apple-touch-icon.png` puis `https://<hôte>/favicon.ico` (jamais `http`, jamais un service tiers), marque de carte par le BIN pour une CreditCard, lettre de repli. Aucun réseau dans `core`.

## 8. CLI

| Commande | Effet |
| --- | --- |
| `onepass import <fichier> [--format F] [--vault V] [--dry-run]` | détecte ou force le format, importe dans le vault V (défaut : un vault par dossier source, sinon le premier vault), affiche le nombre d'items par type et les avertissements |
| `onepass import --wifi-keychain [--vault V]` | Mac seulement, section 4.5 |
| `onepass export --out F [--vault V] [--format onepass\|csv] [--plaintext]` | archive à phrase de passe (demandée deux fois, ou `--generate-passphrase`) ; CSV seulement avec `--plaintext` |
| `onepass watchtower [--vault V] [--offline] [--hibp-dir D] [--sites F] [--passkeys F] [--breaches F]` | rapport ; en ligne, la CLI télécharge plages, 2fa.directory et catalogue HIBP via `curl` ; `--offline` n'utilise que les fichiers donnés |
| `onepass backup create --out F [--passphrase]` | sauvegarde signée pour le compte |
| `onepass backup restore <F>` | restauration (section 5.5), passe aussi par la phrase de passe si l'archive n'a pas de destinataire compte |
| `onepass backup inspect <F>` | en-tête seul |

Sortie texte ou `--json`. Codes de sortie inchangés. La sortie de `watchtower` ne contient aucune valeur de champ.

## 9. Dépendances nouvelles

| Crate | Usage | Licence |
| --- | --- | --- |
| `zxcvbn` 3 | force des mots de passe | MIT |
| `csv` 1 | lecture et écriture CSV | MIT ou Unlicense |
| `zip` (deflate seul) | 1PUX, Dashlane | MIT |
| `quick-xml` | KeePass XML | MIT |
| `serde_json` (déjà en dev) | JSON des formats | MIT ou Apache-2.0 |

SHA-1 et SHA-256 viennent de `aws_lc_rs::digest`. Pas de client HTTP dans les crates.

## 10. Tests

- Unitaires par module ; fixtures synthétiques dans `onepass-core/tests/fixtures/import/` (noms et valeurs inventés, domaines `example.com`, `example.org`).
- `tests/watchtower.rs` : source de plages simulée qui enregistre les préfixes demandés ; assertion que rien d'autre que 5 hex n'est passé ; rapport sans secret.
- `tests/archive.rs` : aller-retour, bit retourné, troncature, schéma futur, mauvaise phrase, mauvais compte, archive forgée avec la seule clé publique (signature absente puis fausse), golden.
- `proptest` : `parse` de chaque format CSV ne panique sur aucune entrée ; aller-retour CSV export puis import générique.
- CLI : import, export, backup, watchtower `--offline` sur un dossier de plages synthétique.
- Fuzzing, une cible par parseur : `import_csv` (premier octet = format), `import_1pux`, `import_bitwarden_json`, `import_keepass_xml`, `import_cxf`, `import_text` (otpauth, QR Wi-Fi, sorties `networksetup`), `archive_open`, `hibp_range`, `site_directory` (2fa, passkeys, fuites).

## 11. Hors de ce jalon

KDBX ; Credential Exchange en export ; surveillance des adresses email par clé API HIBP ; notifications locales ; pack d'icônes et téléchargement des favicons ; pièces jointes dans les imports et archives ; sauvegarde hebdomadaire automatique (planification côté apps) ; Emergency Kit PDF ; listes 2fa.directory embarquées dans le binaire.

## 12. Rulings

1. Ruling: chemin "architectural" du brainstorming, spec et plan écrits, validés par moi - nouveau sous-système, l'utilisateur a demandé zéro action de sa part - un humain aurait pu choisir un périmètre plus étroit ; coût : du code en trop à relire.
2. Ruling: modules neufs dans `onepass-core` plutôt qu'un crate séparé - la spec d'architecture place Watchtower et les parseurs dans `core`, et l'archive a besoin de `BlobKind` et de l'accès au compte - dépendances plus lourdes pour `core` ; déplacement vers un crate dédié possible plus tard sans changer l'API.
3. Ruling: trois modifications additives de fichiers existants (`BlobKind::Archive = 9`, `Repository::account()`, lignes `pub mod`) - impossible de signer ou d'envelopper pour le compte sans accès à `Account`, et réutiliser un `BlobKind` existant brouillerait la séparation de domaine - conflit de fusion si une autre session prend le numéro 9 ou ajoute le même accesseur ; à renuméroter avant toute donnée réelle.
4. Ruling: un seul conteneur pour l'export et la sauvegarde, destinataires multiples - un format à documenter et auditer au lieu de deux - si les besoins divergent, un `format` 2.
5. Ruling: sauvegarde enveloppée vers la clé KEM publique du compte et signée, sans phrase de passe - permet la sauvegarde automatique sans saisie, seul le compte peut l'ouvrir, la signature empêche une archive forgée avec la clé publique - une perte du compte (mot de passe et Secret Key) rend les sauvegardes illisibles ; d'où l'option phrase de passe en destinataire supplémentaire.
6. Ruling: clé de la phrase de passe dérivée par `derive_auk` avec une Secret Key nulle puis `derive("onepass/archive/kek/v1")` - réutilise l'Argon2id existant (NFC, mémoire effacée) sans toucher `kdf.rs` - aucune faiblesse connue (séparation par HKDF) ; à remplacer par une fonction dédiée si `kdf.rs` en expose une.
7. Ruling: phrase de passe d'export avec score zxcvbn d'au moins 3 - une archive sort de l'appareil et ne bénéficie pas de la Secret Key - frustration utilisateur ; `--generate-passphrase` l'évite.
8. Ruling: client HTTP de la CLI de dev par `curl` en sous-processus, pas de crate HTTP - évite `rustls` et `webpki-roots` (licence CDLA hors liste blanche de `cargo deny`), `curl` est livré avec macOS ; seul le préfixe de 5 hex apparaît dans les arguments, il est public par construction - dépendance à un binaire système ; les apps utilisent URLSession.
9. Ruling: `RangeSource` en trait, `analyze` sans entrée-sortie - testable sans réseau, utilisable par UniFFI (interface de rappel) - aucun.
10. Ruling: mode hors ligne = soit pas de vérification des fuites, soit un dossier de plages au format PwnedPasswordsDownloader - compatible HIBP, aucun format maison - le jeu complet pèse des dizaines de Go ; un filtre de Bloom compact viendra plus tard si demandé.
11. Ruling: 2FA et passkeys lus depuis les formats publics 2fa.directory v4 et passkeys-api v1, fournis par l'appelant ; aucune liste embarquée dans ce jalon - formats vérifiés le 2026-10-25, les embarquer demande une vérification de licence et un circuit de mise à jour (jalon des apps) - sans fichier, les contrôles `missing_2fa` et `passkey_available` sont absents du rapport (indiqué dans le rapport).
12. Ruling: correspondance de domaine par suffixe, sans liste des suffixes publics - pas de dépendance lourde, faux positifs limités car les listes sont par domaine enregistrable - un domaine comme `github.io` dans une liste toucherait tous ses sous-domaines.
13. Ruling: items à la corbeille et archivés exclus de Watchtower - ils ne servent plus à se connecter - un mot de passe archivé réutilisé ailleurs n'est pas signalé.
14. Ruling: score par pénalités pondérées, défini en 3.5 - simple, explicable, stable - calibrage à revoir avec l'interface.
15. Ruling: zxcvbn seulement pour les mots de passe de 128 caractères ou moins ; au-delà, considéré fort - borne le temps de calcul sur une entrée hostile - un très long mot de passe répétitif n'est pas signalé faible.
16. Ruling: KDBX non pris en charge, KeePass XML oui - KDBX 4 demande AES-CBC, ChaCha20, HMAC par bloc, gzip et un flux interne protégé, puis des fixtures chiffrées : pas "peu coûteux" - l'utilisateur KeePass doit exporter en XML (fichier en clair sur disque).
17. Ruling: exports chiffrés tiers refusés (Bitwarden chiffré, Dashlane `.dash`) - mêmes raisons de coût et de surface - un utilisateur doit passer par un export en clair.
18. Ruling: tout item importé passe `validate`, avec replis Login vers Password puis vers SecureNote, et valeurs invalides rangées en section `imported` - `Repository::save_item` refuse un item invalide et l'import ne doit rien perdre - des items moins typés que la source ; avertissements à l'appui.
19. Ruling: pièces jointes (1PUX `files/`, KeePass binaires) ignorées avec avertissement - aucun flux de pièces jointes n'existe encore dans `core` - perte des fichiers joints à l'import, signalée.
20. Ruling: restauration sans écrasement (id existant sauté) - jamais de perte de données par une restauration - restaurer une version plus ancienne d'un item existant demande de le supprimer d'abord.
21. Ruling: CSV en clair sans échappement des formules (`=`, `+`, `-`, `@`) - un mot de passe commençant par `=` doit survivre à l'aller-retour - ouvrir le fichier dans un tableur peut exécuter une formule ; l'avertissement le dit.
22. Ruling: correspondances 1PUX, LastPass, Dashlane et CXF écrites d'après la documentation publique des formats, fixtures synthétiques - aucune donnée réelle autorisée - un champ réel inconnu atterrit en section `imported` au lieu de son champ typé ; aucune perte.
23. Ruling: Proton Pass CSV, URI otpauth (Google Authenticator) et CXF ajoutés bien que non listés dans la demande - la spec d'architecture les cite, coût faible car ils réutilisent le constructeur commun et `totp::parse_migration` - un peu de code en plus.
24. Ruling: les lints `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` refusés dans les nouveaux modules hors tests - "aucune panique" vérifié par l'outil, pas seulement par le fuzzing - code un peu plus verbeux.
25. Ruling: icônes réduites à `icon::hint` (aucun réseau) - le pack et la récupération relèvent du jalon des apps - aucun.
26. Ruling: plafonds numériques des sections 3.4, 4.4 et 5.4 - assez larges pour un vrai coffre (100 000 items en pratique), assez bas pour borner mémoire et temps - un export plus gros que 256 Mio est refusé ; à relever si besoin.
27. Ruling: nouveau `Format::OnePassCsv` (`onepass-csv`), ajouté en fin d'énumération, reconnu par l'en-tête exact de l'export CSV - l'export en clair doit se réimporter (aller-retour de la section 10) et aucun format existant n'a cet en-tête - chaque ligne redevient un Login (un autre type garde son nom et ses champs en section `imported`, puis suit les replis de 4.2) : un item non Login perd son typage à l'aller-retour.

## Annexe A : catégories 1PUX

| `categoryUuid` | Catégorie 1Password | Type OnePass |
| --- | --- | --- |
| 001 | Login | Login |
| 002 | Credit Card | CreditCard |
| 003 | Secure Note | SecureNote |
| 004 | Identity | Identity |
| 005 | Password | Password |
| 006 | Document | Document (sans fichier : repli SecureNote) |
| 100 | Software License | SoftwareLicense |
| 101 | Bank Account | BankAccount |
| 102 | Database | Database |
| 103 | Driver License | DriverLicense |
| 104 | Outdoor License | SecureNote |
| 105 | Membership | Membership |
| 106 | Passport | Passport |
| 107 | Reward Program | RewardProgram |
| 108 | Social Security Number | SocialSecurityNumber |
| 109 | Wireless Router | Router |
| 110 | Server | Server |
| 111 | Email Account | Email |
| 112 | API Credential | ApiCredential |
| 113 | Medical Record | MedicalRecord |
| 114 | SSH Key | SshKey |
| 115 | Crypto Wallet | CryptoWallet |

Les champs 1Password sont mis en correspondance par leur `id` de champ (par exemple `ccnum`, `cvv`, `expiry`, `network_name`, `wireless_password`) ; la table complète vit dans le code (`import::onepux::FIELD_MAP`) avec un test par catégorie.
