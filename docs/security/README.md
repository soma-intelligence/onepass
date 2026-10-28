# Sécurité de OnePass : jalon 1 (noyau)

Ce document décrit ce que fait le code de `core/onepass-core` au jalon 1 : le modèle de menace, la construction cryptographique exacte (labels, tailles, paramètres) et les attaques testées. Là où le code diffère de la spec d'architecture (`docs/specs/2026-10-25-onepass-architecture-design.md`), c'est le code qui est décrit, et l'écart est listé à la fin.

Le noyau n'a pas fait l'objet d'un audit externe. Il est prévu au jalon 8.

## 1. Modèle de menace

**Adversaire principal : un stockage malveillant.** Le stockage (CloudKit, le futur serveur, le réseau, un disque volé) peut modifier, rejouer, supprimer, réordonner ou injecter n'importe quel enregistrement. Le client doit le détecter et refuser les données, sans jamais déchiffrer quoi que ce soit de forgé. La référence est l'étude ETH Zurich / USI de 2026 sur les gestionnaires cloud : chaque classe d'attaque de cette étude est un test (section 5).

Le stockage voit en clair exactement ceci :

- pour tout enregistrement : son identifiant, son type, son numéro de version et la taille arrondie de ses blobs ;
- pour un enregistrement d'item : un identifiant de blob neuf à chaque version, la version de l'item, les 16 octets d'id du vault en préfixe, et dans l'`ItemRecord` encodé l'`item_id` (stable d'une version à l'autre : les versions d'un même item sont reliables) et la version. Le stockage connaît donc le nombre d'items de chaque vault et le vault de chaque item ;
- pour un manifeste : l'id du vault et le numéro de version de l'enregistrement, égal au `seq` du manifeste (nombre d'écritures du vault) ;
- pour les clés et métadonnées de vault : l'id du vault ;
- pour les paramètres de compte : les paramètres Argon2id, le sel et les clés publiques (aucun secret).

**Ce que le noyau garantit face à ce stockage :**

- confidentialité du contenu et des métadonnées des items (titres, URL, types, tags, nombre de champs) ;
- détection d'un item supprimé, injecté, rejoué dans une ancienne version, déplacé vers un autre vault ou interverti avec un autre ;
- détection d'un retour en arrière du vault et d'une bifurcation de l'historique du manifeste ;
- refus de paramètres Argon2id affaiblis ou non signés ;
- refus d'une clé de vault substituée : l'enveloppe KEM n'est pas authentifiée, mais un vault n'est listé que si son manifeste signé s'ouvre avec la clé reçue, et aucune écriture n'a lieu sans ce manifeste vérifié ;
- détection d'un vault entier masqué, pour un vault que l'appareil a déjà lu (`VaultMissing`) ;
- aucune perte silencieuse entre deux écritures concurrentes, sur des items différents comme sur le même item : l'écriture du manifeste est conditionnelle, le perdant reçoit `Conflict`, rien de ce qu'il a écrit n'est listé, et l'état du gagnant reste lisible (le noyau le garantit seul, sans le verrou de la CLI).

**Hors périmètre au jalon 1 :**

- un appareil déverrouillé et compromis au niveau système (root, jailbreak) ;
- un attaquant qui lit la mémoire du processus : les secrets sont effacés à la libération (`zeroize`) mais les pages ne sont pas verrouillées (`mlock` n'est pas implémenté) ;
- la CLI de développement, qui stocke la Secret Key en clair dans `device.bin` (voir `core/README.md`) ;
- l'analyse de trafic : la taille des blobs est arrondie par paliers, pas masquée ;
- la liste des vaults du compte n'est pas signée (limite connue du jalon 1) : un stockage peut masquer un vault entier à un appareil qui ne l'a jamais lu. Un appareil qui l'a déjà lu le détecte (`VaultMissing`), et un vault planté est refusé faute de manifeste signé. Une liste de vaults signée est prévue au jalon 2 ;
- l'appairage d'appareils, le partage entre membres, la révocation, les pièces jointes (le type de blob `Attachment` est réservé, sans flux associé), le modèle formel Tamarin ou ProVerif.

**Dépendances de confiance :** `aws-lc-rs` (AES-256-GCM-SIV, HMAC, HKDF, SHA-2, SHA-3, ML-KEM-1024, X25519, ML-DSA-87, Ed25519, générateur aléatoire du système), `argon2` (Argon2id), `slh-dsa` (SLH-DSA-SHA2-256s, version `=0.1.0`), `postcard` (encodage). `libcrux` sert uniquement de référence indépendante dans les tests différentiels.

## 2. Identifiants et encodage

- Tout identifiant (blob, item, vault, compte, appareil) est un UUIDv7 de 16 octets (`Id`).
- Tout encodage interne est `postcard`, déterministe. Aucun JSON dans les blobs.
- Dans le noyau, tout enregistrement ou clair structuré est décodé en entier (paramètres de compte, keyset, manifeste signé, manifeste, métadonnées de vault, contenu d'item, enregistrements d'item du dépôt) : des octets en trop après la valeur sont refusés (`InvalidFormat`, ou `ManifestUnexpectedItem` pour un enregistrement d'item du dépôt).

## 3. Construction cryptographique

### 3.1 Secret Key et AUK (`crypto/secret_key.rs`, `crypto/kdf.rs`)

- **Secret Key** : 256 bits tirés du générateur aléatoire du système, créés sur l'appareil.
- **Affichage** : base32 RFC 4648 sans padding en majuscules (52 caractères), plus un caractère de contrôle, groupés par 4 avec des tirets. Le caractère de contrôle est un Luhn mod N avec N = 32 sur les valeurs des 52 symboles (alphabet base32, `A` = 0 à `7` = 31) : en partant de la droite, une valeur sur deux est doublée et ses deux chiffres en base 32 additionnés, et le contrôle complète la somme à un multiple de 32. Il détecte toute substitution d'un caractère et toute transposition de deux caractères voisins différents, sauf l'échange `A` et `7` (valeurs 0 et 31), seul angle mort connu de Luhn mod N. La lecture ignore les espaces et les tirets, accepte les minuscules, lit `0` comme `O`, `1` comme `I` et `8` comme `B`, et refuse une longueur fausse, un caractère hors alphabet, un caractère de contrôle faux ou des bits de bourrage non nuls (encodage non canonique).
- **Argon2id** (version 0x13) : `m = 262144 KiB` (256 MiB), `t = 4`, `p = 4`, sortie 32 octets, sel de 32 octets aléatoires. Ce sont des planchers (`KDF_FLOOR`), imposés à la création et à chaque déverrouillage, avec ou sans épingle. Seuls les tests unitaires (`cfg(test)`) et les builds de développement avec assertions de debug et la feature `dev-fast-kdf` (CLI de développement, tests d'intégration) imposent à la place le plancher de développement `DEV_KDF_FLOOR` (`m = 8192 KiB`, `t = 1`, `p = 1`) ; un build release impose toujours `KDF_FLOOR`. Le mot de passe est normalisé en NFC avant l'entrée. La mémoire d'Argon2 est allouée par le noyau dans un tampon effacé à la libération.
- **AUK** (Account Unlock Key, 256 bits) : `HKDF-SHA256(salt = kdf.salt, ikm = argon2_out || secret_key, info = "onepass/auk/v1")`, 32 octets. Un mot de passe seul ne suffit donc pas : il faut aussi la Secret Key.

### 3.2 Chiffrement symétrique des blobs (`crypto/aead.rs`)

Chaque blob est scellé par AES-256-GCM-SIV avec un engagement de clé HMAC-SHA256.

**Sous-clés.** À partir de la clé du blob `K` (32 octets) : `K_enc = HKDF-SHA256(salt vide, ikm = K, info = "onepass/blob/enc/v1")` et `K_com = HKDF-SHA256(salt vide, ikm = K, info = "onepass/blob/commit/v1")`, 32 octets chacune.

**Format d'un blob** (`HEADER_LEN = 50`) :

| Octets | Contenu |
| --- | --- |
| 0 à 2 | magic `OPB` |
| 3 | version de format, `1` |
| 4 | algorithme, `1` (AES-256-GCM-SIV + HMAC-SHA256) |
| 5 | type de blob |
| 6 à 17 | nonce de 12 octets, aléatoire |
| 18 à 49 | engagement : HMAC-SHA256 de 32 octets |
| 50 à fin moins 16 | texte chiffré (plaintext paddé) |
| 16 derniers | tag GCM-SIV |

Types de blob : `Keyset` 1, `VaultKey` 2, `VaultMeta` 3, `ItemKey` 4, `Item` 5, `Manifest` 6, `Attachment` 7, `DeviceState` 8. `Attachment` et `DeviceState` sont réservés : rien ne les produit au jalon 1 (`device.bin` de la CLI est du postcard en clair), mais leurs numéros restent pris.

**Données associées.** `AAD_base = en-tête[0..18] || blob_id (16) || vault_id (16, ou 16 octets nuls s'il n'y en a pas) || schéma (u16 big-endian)`, soit 52 octets. L'engagement vaut `HMAC-SHA256(K_com, AAD_base)`. Les données associées passées à GCM-SIV sont `AAD_base || engagement` (84 octets). Elles lient donc le format, l'algorithme, le type, le nonce, l'id du blob, l'id du vault et la version de schéma.

**Padding.** Le texte en clair est préfixé de sa longueur (u32 big-endian) puis complété par des zéros jusqu'au palier : 256 octets minimum, puis la puissance de 2 supérieure jusqu'à 65536, puis le multiple de 65536 supérieur. Le préfixe de longueur compte dans la taille.

**Ouverture, dans cet ordre** : longueur minimale (66 octets), magic, format, algorithme, type (sinon `WrongKind`), engagement en temps constant (sinon `Commitment`), déchiffrement authentifié (sinon `Aead`), puis padding canonique : la longueur annoncée tient dans le blob, le palier correspond exactement et tous les octets de bourrage sont nuls (sinon `InvalidFormat("padding")`). L'engagement est vérifié avant tout déchiffrement : une mauvaise clé est détectée sans oracle de partition.

### 3.3 Chiffrement asymétrique : ML-KEM-1024 + X25519 (`crypto/kem.rs`)

Sert à envelopper une clé de vault pour le compte. Toutes les dérivations HKDF du noyau passent par une seule fonction (HKDF-SHA256, 32 octets écrits directement dans le tampon de clé). Clé publique : ML-KEM-1024 (1568 octets) et X25519 (32 octets). Clé secrète : 3168 octets ML-KEM (format FIPS 203) et 32 octets X25519. À l'import d'une clé secrète, le hash SHA3-256 de la clé d'encapsulation incluse est vérifié.

**Enveloppe** : `ct_mlkem (1568) || eph_x25519_pub (32) || blob`, où `blob` scelle la clé enveloppée (32 octets) avec la clé combinée ci-dessous.

**Combinaison** : `HKDF-SHA256(salt vide, ikm = ss_mlkem || ss_x25519 || ct_mlkem || eph_x25519_pub || x25519_destinataire, info = "onepass/kem/v1" || contexte)`, 32 octets. Les deux secrets partagés, le chiffré, la clé éphémère et la clé du destinataire entrent dans la dérivation : casser un seul des deux mécanismes ne suffit pas.

Le blob interne est de type `VaultKey`, de schéma 1, sans vault_id, avec pour id de blob les 16 premiers octets de `SHA-256(contexte)`. Le contexte d'un vault est `"vault:" || vault_id`. Le contexte suit le label sans préfixe de longueur : c'est sans ambiguïté tant qu'il n'existe qu'une famille de contextes de longueur fixe ; il faudra le préfixer de sa longueur, sous un nouveau label, avant d'en ajouter une seconde (appairage, partage). Une enveloppe n'est donc valide que pour son vault. Longueur attendue fixe : toute autre longueur est refusée.

L'enveloppe n'est pas authentifiée : la clé publique KEM du compte est en clair dans les paramètres, n'importe qui peut donc envelopper une clé de son choix pour le compte. La clé de vault est authentifiée par le manifeste signé du vault (section 3.7), scellé avec elle.

### 3.4 Signatures (`crypto/sign.rs`)

Tous les schémas signent le même message encadré : `"onepass/sig/v1" || len(domaine) (u16 big-endian) || domaine || message`. ML-DSA et SLH-DSA utilisent la variante pure avec un contexte FIPS vide.

- **Signatures courantes : ML-DSA-87 + Ed25519, les deux obligatoires.** Clé de signature : deux graines de 32 octets. Clé publique : ML-DSA de 2592 octets et Ed25519 de 32 octets. Signature : 4627 octets ML-DSA et 64 octets Ed25519. Une signature n'est valide que si les deux moitiés se vérifient (les deux sont calculées, sans court-circuit).
- **Identité racine : SLH-DSA-SHA2-256s** (FIPS 205). Clé secrète de 128 octets (`sk_seed || sk_prf || pk_seed || pk_root`), publique de 64 octets, signature de 29792 octets. Elle ne signe que des paramètres de compte (domaine `"account-params"`). La signature est randomisée (aléa frais à chaque signature). À l'import d'une clé, le `pk_root` est recalculé et doit correspondre.
- Domaines utilisés : `"account-params"` (identité) et `"manifest"` (signature hybride).

### 3.5 Compte et keyset (`account.rs`)

À la création : un `account_id`, une Secret Key, puis trois clés : paire KEM hybride, paire de signature hybride, clé d'identité SLH-DSA.

- **Paramètres de compte** (en clair, aucun secret) : `account_id`, paramètres Argon2id, clé d'identité publique, clé de signature publique, clé KEM publique, et `identity_sig`, signature SLH-DSA de `postcard(account_id, kdf, signing_pub, kem_pub)` sous le domaine `"account-params"`.
- **Keyset** : `postcard((kem_secret, signing_secret, identity_secret))` scellé par l'AUK, blob de type `Keyset`, schéma 1, id de blob `account_id`, sans vault.

**Déverrouillage, dans cet ordre** : décodage complet des paramètres, vérification de `identity_sig` avec la clé d'identité contenue ; si l'appareil a épinglé le compte, l'`account_id` et la clé d'identité doivent correspondre à l'épingle (sinon `ParamsUnsigned`) et les paramètres Argon2id doivent être au moins égaux au plancher épinglé (sinon `ParamsDowngrade`) ; avec ou sans épingle, ils doivent atteindre le plancher global (sinon `ParamsDowngrade`) ; plafond de coût Argon2id à 2 GiB, 16 passes, 16 voies (sinon `InvalidFormat`), avant tout calcul ; dérivation de l'AUK ; ouverture du keyset ; enfin les trois clés publiques déduites du keyset doivent égaler celles des paramètres signés (sinon `Signature`). Un échec d'engagement sur un blob bien formé devient `WrongPassword`. Au premier déverrouillage sur un appareil, le compte est épinglé (confiance au premier usage). Après chaque déverrouillage réussi, le plancher épinglé monte au maximum, composante par composante, de lui-même et des paramètres acceptés, et il est enregistré avec l'état de l'appareil : une fois des paramètres plus forts vus, un ancien jeu signé plus faible est refusé.

### 3.6 Vaults et items (`vault.rs`)

- **Clé de vault** : 256 bits aléatoires, enveloppée par la clé KEM du compte (contexte `"vault:" || vault_id`). Les métadonnées du vault (nom, icône, couleur, voyage, MCP) sont `postcard(VaultMeta)` scellé par la clé de vault, type `VaultMeta`, id de blob = id du vault.
- **Clé d'item** : 256 bits aléatoires par item et par écriture. Elle est scellée par la clé de vault (type `ItemKey`, 32 octets de clair), `blob_id = item_id`, `vault_id = vault`, schéma 1.
- **Contenu d'item** : `postcard((version, item))` scellé par la clé d'item (type `Item`), mêmes données associées. La version et l'item (avec son `vault_id`) sont dans le clair scellé. À l'ouverture, la version, l'id d'item et l'id de vault internes doivent égaler ceux de l'enregistrement et du vault, sinon `WrongContext`.
- **Déplacement** : la clé d'item est conservée, réenveloppée par le vault cible, et le blob d'item est rescellé (le `vault_id` est dans les données associées et dans le clair). Le manifeste du vault cible est écrit avant celui du vault source : une coupure entre les deux laisse l'item dans les deux vaults (dupliqué, jamais perdu), et déplacer l'item de nouveau répare l'état.
- **Liste des vaults** (`Repository::vaults`) : un vault n'est rendu que si son enveloppe s'ouvre, ses métadonnées s'ouvrent avec la clé obtenue, et son manifeste signé se vérifie avec la clé de signature du compte et s'ouvre avec cette même clé (sinon l'erreur de cette étape, par exemple `Commitment` pour une clé substituée, `Signature` pour un manifeste forgé, `ManifestMissingItem` sans manifeste). Un vault que l'appareil a déjà lu et dont la clé a disparu est `VaultMissing`. L'historique (retour en arrière, bifurcation) est vérifié à la lecture des items et avant chaque écriture.

### 3.7 Manifeste signé et intégrité (`manifest.rs`, `repo.rs`)

Chaque vault a un manifeste : `vault_id`, `seq`, `prev_hash`, entrées triées strictement par `item_id` (id, version, `SHA-256(postcard(ItemRecord))`) et racine de Merkle.

- **Merkle** : feuille `SHA-256(0x00 || postcard(entrée))`, nœud `SHA-256(0x01 || gauche || droite)`, un dernier nœud impair est remonté tel quel, la liste vide donne `SHA-256(0x02)`.
- **Chaînage** : `seq` commence à 1 et croît de 1, `prev_hash = SHA-256(postcard(manifeste précédent))` (32 zéros pour le premier).
- **Scellement** : `postcard(manifeste)` scellé par la clé de vault (type `Manifest`, `blob_id = vault_id`, schéma 1), puis la **signature hybride porte sur le blob scellé** (domaine `"manifest"`).
- **Vérification, dans cet ordre** : signature, ouverture avec la clé de vault, décodage, vault_id (`WrongContext`), tri strict (`InvalidFormat`), racine de Merkle (`ManifestItemMismatch`), puis historique contre le dernier manifeste vu par l'appareil (seq et hash) : un seq plus ancien est refusé, le même seq doit être exactement le même manifeste (sinon bifurcation), le seq suivant doit se chaîner par `prev_hash`, un écart plus grand est accepté (impossible à chaîner). Échec : `ManifestRollback`.
- **Enregistrements contre manifeste** (`check_records`) : chaque entrée doit avoir exactement un enregistrement de même version et même hash (`ManifestMissingItem`, `ManifestItemMismatch`), et aucun autre enregistrement ne doit exister (`ManifestUnexpectedItem`).
- **Écritures concurrentes** : le manifeste est écrit seulement si le manifeste stocké est encore celui qui a été chargé (`put_if_version`, la version de l'enregistrement est le `seq` ; en SQLite une seule instruction `UPDATE ... WHERE version = ?`, ou un `INSERT` sans remplacement pour le premier). Le perdant d'une course reçoit `Conflict` ("concurrent write, retry") et supprime l'enregistrement d'item qu'il vient d'écrire, et lui seul. Aucun enregistrement n'est supprimé avant que le manifeste soit écrit : un enregistrement ignoré au chargement peut être l'écriture en cours d'un autre écrivain sur le même item. Pour un déplacement, une course perdue sur le manifeste du vault cible ne change rien ; perdue sur celui du vault source, elle laisse l'item dans les deux vaults, comme une coupure (voir 3.6). La CLI prend en plus un verrou exclusif sur le dossier de données pour toute commande, mais le noyau ne compte pas dessus.
- **Écritures interrompues et restes** : l'enregistrement est écrit avant le manifeste, et l'ancienne version n'est supprimée qu'à la fin. Trois restes sont donc tolérés, jamais plus. (a) Écriture coupée avant le manifeste : un enregistrement qui s'ouvre avec la clé de vault et porte exactement la version suivante d'un item listé, ou la version 1 d'un item non listé, est ignoré. (b) Nettoyage coupé après le manifeste : une version plus ancienne d'un item listé est ignorée seulement si l'enregistrement exact du manifeste (même version, même hash) est présent à côté. (c) Perdant d'une course sur le même item arrêté avant de supprimer son enregistrement : la même version qu'un item listé, avec un autre hash, est ignorée seulement à côté de l'enregistrement exact du manifeste. Servis à la place de l'enregistrement courant, (b) et (c) restent une erreur (`ManifestItemMismatch`), et l'enregistrement courant servi deux fois aussi (`ManifestUnexpectedItem`). Tout autre écart est une erreur ; en particulier le reste d'un item supprimé (suppression coupée avant d'effacer l'enregistrement, ou écrivain qui perd contre la suppression de cet item puis s'arrête avant son nettoyage) bloque le chargement du vault (`ManifestUnexpectedItem`, refus par prudence), un outil de réparation est prévu plus tard.

### 3.8 Erreurs

Aucun message d'erreur ne contient de secret ni de contenu d'item (`Error`, `IntegrityError`, `ValidationError` ne portent que des libellés fixes ou un nom de champ). La CLI ramène toute erreur d'intégrité à un seul message générique. `Conflict` n'est pas une erreur d'intégrité : rien n'a été écrasé, il suffit de recommencer (code de sortie 5 de la CLI).

## 4. Validation des entrées

Les décodeurs qu'un stockage hostile atteint avant toute authentification sont fuzzés (`core/fuzz`) : ouverture de blob, enregistrement de manifeste signé (décodage puis signature), paramètres de compte (décodage puis `Account::unlock`), enregistrement d'item (préfixe de vault, `ItemRecord`, confrontation au manifeste), vérification des signatures hybride et d'identité sur des clés et signatures arbitraires, plus `parse_otpauth` et `parse_ref`. Au jalon 5 s'y ajoutent les parseurs d'import (CSV, 1PUX, Bitwarden JSON, KeePass XML, CXF, texte), l'ouverture d'archive (`inspect` et `open`), la réponse de plage HIBP et les catalogues de sites. Le décodage de `Manifest` n'est pas une cible : il ne lit qu'un clair déjà authentifié. Chaque cible exige seulement l'absence de panique. Les 7 cibles des jalons précédents ont tourné 60 s et les 9 du jalon 5 (parseurs d'import, `archive_open`, `hibp_range`, `site_directory`) 30 s, sans plantage, au moment de la livraison ; toutes tournent ensuite 30 s à chaque exécution de la CI.

## 5. Attaques testées

**Suite "stockage malveillant"** (`onepass-core/tests/malicious_store.rs`) : un magasin qui conserve les données honnêtement et ment en les servant. Chaque attaque doit être refusée avec son erreur exacte.

| Attaque | Erreur attendue |
| --- | --- |
| Paramètres Argon2id affaiblis, signés par une autre identité | `ParamsUnsigned` |
| Paramètres plus faibles, même identité, sous le plancher épinglé | `ParamsDowngrade` |
| Ancien manifeste servi à la place du courant (retour en arrière) | `ManifestRollback` |
| Autre manifeste valide au même `seq` (bifurcation) | `ManifestRollback` |
| Item masqué dans la liste | `ManifestMissingItem` |
| Item d'un autre compte injecté | `ManifestUnexpectedItem` |
| Ancienne version d'un item rejouée | `ManifestItemMismatch` |
| Item servi sous le préfixe d'un autre vault | `ManifestUnexpectedItem` |
| Contenus de deux items intervertis | `ManifestItemMismatch` |
| Enveloppe de clé de vault chiffrée pour la clé KEM de l'attaquant | `Commitment` (ouverture de l'enveloppe, au listage des vaults) |
| Clé de vault de l'attaquant enveloppée pour la clé KEM publique de la victime, métadonnées rescellées avec elle | `Commitment` (ouverture du manifeste, au listage des vaults) ; une écriture sur ce vault est refusée avant toute écriture dans le stockage |
| Vault déjà lu par l'appareil, masqué dans la liste | `VaultMissing` |
| Manifeste signé par une autre clé | `Signature` (au listage des vaults et à la lecture des items) |
| Blob d'item tronqué | `ManifestItemMismatch` |

**Autres tests de sécurité :**

- AEAD (`tests/aead_props.rs` et tests unitaires) : aller-retour aux bords des paliers de padding ; mauvais type, mauvais id de blob, mauvais vault ou mauvais schéma refusés ; une mauvaise clé échoue sur l'engagement avant le déchiffrement ; tout bit retourné, sur n'importe quel octet, est refusé (`proptest`).
- Enveloppe KEM : mauvais contexte, mauvais destinataire, enveloppe tronquée ou rallongée et chaque octet modifié sont refusés.
- Signatures : domaine ou message changé, une seule moitié altérée, moitiés mélangées entre deux signataires : refusés. Le message encadré est vérifié octet par octet.
- Comptes : mauvais mot de passe (`WrongPassword`), paramètres hors plafond, compte épinglé différent, keyset dont les clés publiques ne correspondent pas aux paramètres signés.
- Vaults : item d'un autre vault, version échangée, id d'item échangé, rejeu inter-vault.
- Formats figés : vecteur connu d'un blob scellé complet (clé, nonce, ids et clair fixés, calculé indépendamment en Python), vecteurs hexadécimaux fixes de la racine de Merkle, vecteur de Secret Key avec son caractère de contrôle, et encodage postcard des index de variantes de `FieldType`, `FieldValue`, `Provider` et `ItemType` (ces énumérations ne s'étendent qu'en ajoutant des variantes à la fin).
- Cryptographie : vecteurs officiels NIST ACVP (ML-KEM-1024, ML-DSA-87 génération et signature, SLH-DSA-SHA2-256s) et test différentiel `aws-lc-rs` contre `libcrux` (`tests/differential.rs`).
- Secrets : `Debug` n'affiche jamais d'octets de clé, et les messages d'erreur ne contiennent ni secret ni contenu (tests de rédaction).

## 6. Archive OnePass (jalon 5)

Un seul conteneur sert à l'export chiffré et à la sauvegarde (`archive/format.rs`, extension `.onepass`).

**Format.** `"OPARCH"` (6 octets), octet de format (1), longueur de l'en-tête (u32 big-endian), en-tête (postcard), charge scellée. L'en-tête porte `archive_id`, le type (`Export` ou `Backup`), la date, le schéma de charge, la liste des destinataires (1 à 8) et la signature éventuelle. Il fait 64 Kio au plus, sans octet en trop. La charge est scellée par une clé de contenu `K` de 32 octets aléatoires (AEAD de la section 3.2, type `Archive`, `blob_id = archive_id`, schéma de charge). Elle répète `archive_id`, le type, la date et le schéma : l'ouverture refuse toute différence avec l'en-tête.

**Destinataires.** `K` est enveloppée pour chaque destinataire :

- *phrase de passe* : `KEK = HKDF(derive_auk(NFC(phrase), Secret Key à zéro, kdf), "onepass/archive/kek/v1")`, puis `K` scellée sous `KEK`. La phrase doit avoir un score zxcvbn d'au moins 3, et les paramètres Argon2id respectent le plancher des comptes à la création. À l'ouverture seul le plafond des comptes (2 Gio, 16 passes, 16 voies) est imposé : un fichier hostile ne peut pas épuiser l'appareil, et un fichier ancien à paramètres plus faibles reste lisible. C'est le mode de l'export portable, restaurable dans n'importe quel compte ;
- *compte* : `K` enveloppée vers la clé KEM hybride publique du compte (ML-KEM-1024 + X25519, section 3.3), contexte `"onepass/archive/v1" || archive_id`. C'est le mode de la sauvegarde : aucune saisie, seul ce compte l'ouvre.

**Signature.** Une archive avec destinataire compte est signée par la clé de signature hybride du compte (section 3.4), domaine `"onepass/archive/v1"`, sur `SHA-256(magic || format || en-tête sans signature || charge scellée)`. La signature est obligatoire dans ce cas et vérifiée contre le compte qui ouvre : une archive d'un autre compte, ou sans signature, est refusée (`Signature`). Un export par phrase de passe seul n'est pas signé.

**Ce qui est authentifié.** La charge l'est toujours (AEAD, avec `archive_id` dans l'AAD). Pour une archive signée, l'en-tête l'est aussi, par la signature. Pour un export par phrase de passe, l'en-tête n'est pas authentifié séparément : un paramètre KDF ou un `archive_id` altéré change la clé dérivée ou l'AAD, l'engagement de clé échoue et l'altération se lit comme une mauvaise phrase de passe (`WrongPassword`), sans jamais livrer de contenu. Les champs répétés dans la charge sont comparés à l'en-tête après déchiffrement.

**Versionnement.** L'octet de format décrit le conteneur : un format inconnu est refusé. `payload_schema` décrit la charge : tout schéma de 1 à `CURRENT_SCHEMA` est accepté, un schéma plus récent est refusé (`archive from a newer version`). Une évolution ajoute une fonction de migration par schéma. L'en-tête et la charge de référence sont figés en hexadécimal dans `tests/archive.rs`.

**Plafonds à l'ouverture.** Charge de 1 Gio, 10 000 vaults, 1 000 000 d'items. `inspect` ne lit que l'en-tête clair, sans clé ni mot de passe.

**Restauration.** `restore_plan` réutilise le vault du même id s'il existe, sinon en crée un avec la même méta (nouvel id). Un item dont l'id existe déjà est sauté et compté, jamais écrasé. La corbeille et les archivés sont restaurés tels quels.

## 7. Watchtower et k-anonymity (jalon 5)

Watchtower analyse les items déverrouillés en mémoire (mots de passe faibles, réutilisés, anciens, 2FA ou passkey disponibles, sites compromis, fuites de mots de passe). Il ne persiste rien.

**Ce qui sort de l'appareil pour les fuites de mots de passe : 5 caractères hexadécimaux.** Le SHA-1 de chaque mot de passe distinct est calculé en mémoire (`Zeroizing`). Seul son préfixe de 5 caractères hexadécimaux majuscules est passé à la source de plages ; les 35 caractères restants sont comparés en local à la réponse. Ni le mot de passe, ni le hash complet, ni le suffixe, ni l'item ne quittent l'appareil. Un préfixe n'est demandé qu'une fois par analyse, et la source ne reçoit que le préfixe : la CLI le valide (5 hexadécimaux majuscules) avant de lancer la moindre commande, donc rien d'autre ne peut atteindre la ligne de `curl`.

- **Add-Padding.** La CLI appelle `https://api.pwnedpasswords.com/range/{préfixe}` avec l'en-tête `Add-Padding: true` : le serveur complète la réponse avec de fausses lignes de compte 0, ce qui masque sa taille. Ces lignes sont ignorées à la lecture.
- **Réponse hostile.** Le corps est plafonné à 4 Mio, une ligne mal formée invalide la réponse de ce préfixe. Une source en erreur ne fait pas échouer l'analyse : l'état des fuites passe à `Partial` ou `Unavailable`, sans conclure à tort qu'un mot de passe est sain.
- **Modes hors ligne.** `--offline` n'exécute aucune commande réseau. `--hibp-dir` lit un dossier de fichiers `ABCDE.txt` (PwnedPasswordsDownloader) : l'analyse des fuites est alors entièrement locale, sans aucun préfixe émis. Sans ces options, la CLI télécharge les plages.
- **Catalogues fournis par l'appelant.** Les catalogues 2fa.directory, passkeys et fuites HIBP (sites compromis) sont des documents que l'appelant fournit au noyau (fichier ou téléchargement de la CLI) ; le noyau ne fait aucun accès réseau lui-même. Chaque document est plafonné (16 Mio, 100 000 entrées, 253 octets par domaine). Seuls un JSON invalide, un document du mauvais type (objet ou tableau attendu) ou un plafond dépassé font refuser le document entier ; une entrée mal formée (domaine vide ou trop long, valeur qui n'est pas un objet, date illisible, fuite non vérifiée) est ignorée et le reste du document est lu. Un lien `documentation` n'est gardé que s'il commence par `https://`, ne contient que de l'ASCII imprimable sans espace et fait au plus 2 048 octets : il vient d'un document téléchargé et peut être affiché dans un terminal. Un hôte correspond à un domaine s'il lui est égal ou se termine par `.` + domaine (pas de liste des suffixes publics).

Limite : le préfixe de 5 caractères révèle à la source que l'appareil a testé un mot de passe dont le SHA-1 commence par ces caractères, parmi environ un million de mots de passe possibles par préfixe. Un observateur du réseau voit aussi la requête vers le service ; seul le mode hors ligne l'évite.

## 8. Import (jalon 5)

Un fichier d'import est une entrée hostile : un export altéré ou piégé ne doit ni faire paniquer le noyau, ni épuiser la mémoire ou le temps, ni écrire ailleurs que dans le coffre.

- **Plafonds.** Fichier de 256 Mio au plus ; CSV en UTF-8 strict (1 Mio par cellule, 1 000 000 de lignes) ; JSON de profondeur 128 (défaut de `serde_json`) ; XML sans expansion d'entités hors entités prédéfinies, profondeur 256 ; zip (1PUX, Dashlane) de 10 000 entrées au plus, lu en flux et plafonné à 512 Mio décompressés (64 Mio pour `export.data`), noms d'entrée jamais utilisés comme chemins (aucune écriture disque), méthodes stockée et deflate seulement ; 1 000 000 d'items par import. Toute violation donne `InvalidFormat` avec une raison statique, sans contenu du fichier.
- **Pas de panique.** Les modules d'import interdisent `unwrap`, `expect`, `panic` et l'indexation hors tests (`clippy`), et chaque parseur a une cible de fuzzing (section 4).
- **Exports chiffrés de tiers refusés.** Un export Bitwarden `encrypted: true` et un export Dashlane chiffré (`.dash`) sont refusés avec un message qui demande un export en clair (CSV pour Dashlane). KDBX est reconnu par sa signature (`03 D9 A2 9A 67 FB 4B B5`) et refusé avec `KeePass KDBX is not supported: export as KeePass 2 XML` : seul l'XML KeePass 2 est lu. Un `.1pif` chiffré de 1Password n'est pas géré : il est refusé comme format inconnu. OnePass ne déchiffre aucun format de tiers ; seules les archives OnePass sont ouvertes, avec leur phrase de passe, par le module `archive`.
- **Aucun secret dans les erreurs ni les avertissements.** Les avertissements d'import ne portent que des libellés fixes et des noms de champ.
- **Export en clair.** L'export CSV en clair est refusé sans `--plaintext`, avertit sur stderr, crée le fichier en mode `0600` et n'écrase jamais un fichier existant. Il n'échappe pas les formules de tableur : ouvrir ce CSV dans un tableur peut les interpréter. Il omet les clés privées des passkeys (seul `passkey:<rp_id>` est écrit) et les valeurs de type Location : ce n'est pas une sauvegarde complète, l'archive OnePass l'est. Il se réimporte avec le format `onepass-csv`.
- **Tampons du crate `csv`.** Le lecteur et l'écrivain CSV (`csv::Reader`, `csv::Writer`) gardent des tampons internes qui ne sont pas effacés à la libération : un fragment de secret lu à l'import ou écrit à l'export peut y rester jusqu'à réutilisation de la mémoire. Les cellules et le fichier produit, eux, sont en `Zeroizing`.
- **Sortie texte de la CLI.** Les titres, noms de vault, de dossier et de catalogue affichés en mode texte passent par un filtre qui remplace chaque caractère de contrôle par U+FFFD : une séquence d'échappement cachée dans un fichier importé ou un catalogue téléchargé ne pilote pas le terminal. La sortie JSON est échappée par `serde_json`.
- **Écritures partielles.** `import` et `backup restore` valident tous les items avant la première écriture et refusent l'ensemble si l'un est invalide (cas d'une archive forgée). Une erreur d'écriture en cours de route laisse les items déjà écrits et le message d'erreur indique `N of M items written`.
- **Hôtes privés.** `icon::hint` ne propose aucune URL d'icône pour un hôte privé (RFC 1918, 100.64/10, lien local, boucle locale, IPv6 `fe80::/10` et `fc00::/7`, nom sans point, suffixes `.lan`, `.home`, `.internal`, `.local`, `.localhost`, `.home.arpa`) : un client qui suivrait les candidats ne sonde pas le réseau local.
- **Outils système par chemin absolu.** La CLI lance `/usr/sbin/networksetup`, `/usr/bin/security` et `/usr/bin/curl` par leur chemin absolu : un `PATH` modifié ne substitue pas un autre programme.

## 9. Écarts entre le code et la spec

1. **Secret Key** : la spec et les contraintes du jalon parlent de 52 caractères. Le code affiche 52 caractères de base32 plus un caractère de contrôle (53 au total, en 14 groupes de 4, le dernier de 1). Les 256 bits de clé sont inchangés.
2. **`mlock`** : la section 4.7 de la spec prévoit le verrouillage des pages sensibles en mémoire. Le code efface les secrets à la libération (`zeroize`) mais n'appelle pas `mlock`.
3. **Pièces jointes** : la section 4.2 prévoit une clé par pièce jointe enveloppée par la clé d'item. Le jalon 1 réserve le type de blob `Attachment` sans implémenter ce flux.
4. **Dernier manifeste vu** : la spec mentionne le dernier numéro de séquence. Le code retient le `seq` et le hash du manifeste, ce qui détecte en plus une bifurcation au même `seq`.
5. **Plafond Argon2id** : le code borne les paramètres venant du stockage à 2 GiB, 16 passes, 16 voies avant de calculer, pour qu'un serveur hostile ne puisse pas épuiser l'appareil. La spec ne le mentionne pas.
6. **Modèle formel** : la spec prévoit un modèle Tamarin ou ProVerif vérifié en CI. Il n'existe pas encore.
7. **CLI** : la section 9.1 de la spec prévoit un passage par l'app Mac avec Touch ID. Au jalon 1 la CLI est en mode développement autonome (Secret Key en clair dans `device.bin`), écart assumé.
8. **Liste des vaults non signée** : la spec (4.4) protège chaque vault par son manifeste, pas la liste des vaults du compte. Au jalon 1 cette liste n'est pas authentifiée : un vault planté est refusé (pas de manifeste signé valide), un vault déjà lu par l'appareil puis masqué est détecté (`VaultMissing`), mais un vault jamais lu par l'appareil peut être masqué sans détection. Liste signée prévue au jalon 2, reportée au jalon 2b avec la liste signée des appareils (section 10.7).
9. **Fuzzing** : la spec dit "tous les parseurs". Le jalon 1 fuzze les sept points d'entrée listés en section 4, pas les parseurs d'import et d'export, qui n'existent pas encore. Le jalon 5 ajoute une cible par parseur d'import, d'archive et de réponse externe (section 4).

## 10. Jalon 2 : apps Apple

Cette section décrit ce qu'ajoutent les apps iPhone, iPad et Mac (`apple/`, paquet `VaultKit`) et la crate `onepass-ffi` au jalon 2. La cryptographie des sections 2 à 5 est inchangée : toutes les clés restent dans le Rust. Swift ne voit jamais une clé de vault, une clé d'item ni le keyset ; il reçoit des items déchiffrés pour l'affichage et l'édition. Les seuls secrets cryptographiques côté Swift sont la Secret Key et l'AUK enveloppée par la Secure Enclave, tous deux dans le Keychain.

### 10.1 Déverrouillage biométrique

- **Ce qui est enveloppé : l'AUK** (32 octets, section 3.1), pas le keyset déchiffré (ruling R4). `unlock_with_password` rend l'AUK au moment de l'enrôlement ; `unlock_with_auk` ouvre ensuite le keyset avec exactement les mêmes contrôles que le mot de passe (signature des paramètres, épingle, plancher et plafond Argon2id, cohérence du keyset), sans dérivation Argon2id. Aucune clé privée du compte ne sort du Rust.
- **Clé de la Secure Enclave** : une clé P-256 par compte (étiquette `me.somalabs.onepass.auk.<id du compte>`), créée dans la Secure Enclave, jamais exportable, contrôle d'accès `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` avec `.privateKeyUsage` et `.biometryCurrentSet`. Sur Mac, avec le réglage "Accepter aussi l'Apple Watch", `.biometryCurrentSet` OU `.companion`. L'AUK est chiffrée vers la clé publique par `eciesEncryptionCofactorVariableIVX963SHA256AESGCM` ; le texte chiffré est rangé dans le Keychain. Le déchiffrer demande Face ID, Touch ID (ou la montre) à chaque fois.
- **`.biometryCurrentSet`** : ajouter ou retirer un doigt ou un visage invalide la clé. Le déchiffrement échoue, l'enrôlement est supprimé et le mot de passe maître est demandé.
- **Redémarrage** : à l'enrôlement et à chaque saisie du mot de passe, l'app enregistre l'identifiant de la session de démarrage (`kern.bootsessionuuid`, un UUID par démarrage, sans tolérance d'horloge). S'il a changé, ou s'il est illisible, la biométrie est refusée et l'enrôlement supprimé.
- **14 jours** : le mot de passe maître est redemandé si la dernière saisie date de plus de 14 jours (paramètre de politique), ou si l'horloge a reculé de plus de 5 min depuis.
- Après un de ces refus, la clé est recréée automatiquement au prochain déverrouillage réussi par mot de passe si l'utilisateur avait activé la biométrie. L'utilisateur qui choisit "Saisir le mot de passe" dans la feuille système, ou une biométrie bloquée temporairement par le système, garde son enrôlement.
- Sans Secure Enclave (Simulateur) ou en mode partagé, la biométrie n'est pas proposée. Aucun cas n'est une impasse : le mot de passe maître reste toujours possible.
- Mot de passe faux : après 5 échecs, attente de 30 s, puis 1 min, puis 5 min à chaque nouvel échec, comptée localement (un attaquant qui copie la base hors de l'appareil n'est pas freiné par ce compteur, seulement par Argon2id).

### 10.2 Keychain

Éléments génériques du keychain à protection de données (`kSecUseDataProtectionKeychain`, y compris sur Mac), service `me.somalabs.onepass`, groupe d'accès partagé `$(AppIdentifierPrefix)me.somalabs.onepass.shared` dans un build signé :

| Élément | Contenu | Classe |
| --- | --- | --- |
| `secretkey.<id du compte>` | Secret Key en clair | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| `biometric.enrollment.<id du compte>` | AUK chiffrée par la Secure Enclave, dates d'enrôlement et de dernière saisie du mot de passe, identifiant de démarrage | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| clé privée `me.somalabs.onepass.auk.<id>` | clé P-256 de la Secure Enclave (référence seulement) | `WhenUnlockedThisDeviceOnly` + biométrie |
| `prefix-probe` (service `me.somalabs.onepass.prefix-probe`) | aucun secret, sert à lire le préfixe d'équipe | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |

Si la Secret Key ne peut pas être rangée dans le Keychain (par exemple un build iOS sans aucune signature, erreur `-34018`), la création du compte est annulée : la session est verrouillée, la base locale vidée (`reset_store` : toutes les tables effacées en une transaction, le fichier reste en place pour que la connexion du coordinateur de sync, ouverte au lancement, continue de travailler sur le même fichier ; supprimer les fichiers d'une base SQLite en WAL ouverte peut la corrompre), aucune sync ne démarre, et l'app affiche "Impossible de ranger la Secret Key dans le trousseau de cet appareil. Le coffre n'a pas été créé." À la restauration par l'Emergency Kit, la connexion est annulée de la même façon mais la base est gardée (elle peut être la seule copie locale).

`ThisDeviceOnly` : rien n'est copié dans une sauvegarde restaurable sur un autre appareil ni dans le trousseau iCloud (l'option "Secret Key dans le trousseau iCloud" est hors périmètre). Un build local non signé n'a pas le droit d'accès au keychain à protection de données (erreur `-34018`) : en Debug seulement, l'app se replie alors sur le trousseau classique sans groupe d'accès ; un build Release ne se replie jamais.

### 10.3 Presse-papiers, écran, journaux

- **Presse-papiers** : copie locale seulement, jamais par le presse-papiers universel (iOS : option `localOnly` et date d'expiration système ; macOS : `currentHostOnly` et type `org.nspasteboard.ConcealedType` pour que les gestionnaires de presse-papiers l'ignorent). Effacé après 90 s, seulement si rien d'autre n'a été copié entre-temps.
- **Écran** : sur iPhone et iPad, une fenêtre de confidentialité couvre l'app dès que la scène devient inactive (sélecteur d'apps, centre de contrôle), au-dessus des feuilles et alertes. Les champs révélés repassent masqués après 30 s ou à la sortie de l'écran. Les champs secrets sont marqués `privacySensitive`.
- **Journaux** : `os.Logger`, identifiants en `privacy: .private`, jamais de valeur de champ. Les erreurs (`OnePassError` du Rust, `VaultError` côté Swift) ne contiennent jamais de valeur de champ.
- **Mémoire** : l'item complet n'est gardé que par la vue de détail et l'éditeur, et oublié au verrouillage ; les listes ne portent que des résumés sans secret ; la liste des récents vit en mémoire et est vidée au verrouillage. Limite assumée (R5) : Swift ne garantit pas l'effacement des copies de `String`.
- **Verrouillage automatique** : 15 min par défaut en mode personnel (1, 5, 15, 60 min ou jamais) ; en mode partagé, le plus court entre le délai choisi et 5 min, sans biométrie, avec des vaults masqués au choix. Un verrouillage (bouton, arrière-plan, délai) pendant un déverrouillage ou un enregistrement finit toujours verrouillé, sans item en mémoire. Sur iOS, le délai est vérifié chaque seconde tant que le système accorde du temps en arrière-plan, puis à chaque réveil par notification push et au retour au premier plan : une app suspendue garde ses clés jusqu'à l'un de ces moments (limite du système). Sur Mac, l'app se verrouille aussi à la mise en veille, au verrouillage de l'écran et en quittant (fermer la fenêtre quitte l'app) ; ce verrouillage efface aussi la valeur copiée par OnePass, que macOS garderait sinon après la fin du processus. Un verrouillage pendant l'accueil (après la création du compte) efface de la mémoire la Secret Key affichée et le mot de passe maître, supprime le PDF de l'Emergency Kit et affiche l'écran de verrouillage.
- **Vérifications ponctuelles du mot de passe** (redemande pour un item protégé, enrôlement biométrique depuis les réglages) : `verify_password` vérifie le mot de passe et la Secret Key et rend l'AUK sans ouvrir de session et sans écrire l'état de l'appareil. Une vérification qui réécrirait l'état lu avant Argon2id pourrait faire reculer `last_seen` pendant que la session ouverte enregistre, et un rejeu des manifestes écrits entre-temps ne serait plus détecté.

### 10.4 Stockage local

- **Base** : `Application Support/OnePass/vault.sqlite` dans le conteneur de l'app (sandbox sur Mac). Elle contient les tables du module `sync` (`base`, `pending`, `staging`, `ancestor`, `meta`) : les enregistrements y sont les blobs déjà chiffrés et signés par le core (section 3), exactement ce que voit le serveur. S'y ajoutent l'état de l'appareil (`DeviceState` : épingle du compte, derniers manifestes vus), le jeton de changement CloudKit et, par enregistrement, les champs système CloudKit (`server_meta`, nom et étiquette de version de l'enregistrement). Aucun secret en clair : sans la Secret Key (Keychain) et le mot de passe maître, la base ne s'ouvre pas.
- **Protection de fichiers** (iOS et iPadOS) : le dossier est en `NSFileProtectionCompleteUntilFirstUserAuthentication`, pour que la récupération et l'envoi tournent appareil verrouillé. Le contenu étant déjà chiffré par le core, la classe `Complete` n'apporterait qu'une défense en profondeur au prix de la sync en arrière-plan. macOS n'a pas de classes de protection de fichiers : la base repose sur le conteneur sandboxé et FileVault.
- **Réglages** (`UserDefaults`, en clair) : nom affiché, identifiant du compte, mode d'appareil, délais, vaults masqués, compteur et fin d'attente des échecs de mot de passe, souhait de biométrie. Aucun secret, mais le nom affiché et l'identifiant du compte sont lisibles par qui lit le conteneur.
- **Icônes de site** : récupérées directement sur le site de l'URL principale (HTTPS seulement, nom de domaine public seulement : jamais une adresse IP v4 ou v6, `localhost`, un nom sans point ou un suffixe de réseau local (`.local`, `.lan`, `.home.arpa`, `.internal`, `.localdomain`, `.home`, `.intranet`, `.corp`, `.private`), pour ne pas sonder le réseau local ; le nom est ensuite résolu hors du thread principal (délai de 3 s) et refusé si une seule adresse est privée, de bouclage, lien-local, CGNAT `100.64.0.0/10`, unique-local `fc00::/7`, multicast ou réservée, avant toute requête ; session éphémère sans cookies, 256 Kio au plus ; une image qui annonce plus de 4096 pixels de côté est refusée avant tout décodage, contre les bombes de décompression), cache local nommé par hash du domaine, fichiers en `completeFileProtectionUnlessOpen`. La récupération révèle au site qu'un item existe pour lui ; un réglage la coupe (ruling R10). Quelqu'un qui lit le cache peut tester si un domaine connu y figure. Limite acceptée (ruling E26) : le système résout de nouveau le nom à la connexion ; un serveur DNS qui répond une adresse publique à la vérification puis une adresse privée juste après (DNS rebinding) obtient encore une requête HTTPS vers l'adresse privée, sans cookie et sans rien en lire en retour.
- **Emergency Kit** : PDF produit sur l'appareil (Secret Key en clair et QR code), écrit dans un dossier temporaire (`NSFileProtectionComplete` sur iOS), partagé par la feuille système, supprimé quand l'étape disparaît, et les restes d'une exécution interrompue sont supprimés au lancement suivant.

### 10.5 Ce que voit iCloud

Base privée CloudKit de l'utilisateur, zone `OnePass`, type d'enregistrement `OPRecord`. Pour chaque enregistrement du core :

- **nom** : `"<code de type>.<id hex>"` (type de 1 à 6 et identifiant UUIDv7 de 16 octets, opaque) ;
- **champs en clair** : `kind` (le même code) et `version` ;
- **`data`** : le blob du core dans `encryptedValues`, donc chiffré une seconde fois par CloudKit ; cette couche d'Apple n'est pas comptée dans le modèle de menace ;
- les champs système de CloudKit : dates de création et de modification, appareil, étiquette de version.

Le serveur apprend donc ce que décrit la section 1 (nombre d'items par vault, vault de chaque item, tailles arrondies, versions, numéros de séquence des manifestes), plus les dates et le rythme des écritures. Il ne lit ni titre, ni URL, ni type d'item, ni tag, ni contenu. Un enregistrement de plus de 900 Kio est refusé par le Rust avant d'être écrit.

### 10.6 Sync, rebase et vaults retenus

- **Écriture** : toujours dans `pending`, jamais directement dans `base`. L'envoi est conditionnel (`savePolicy: .ifServerRecordUnchanged`, atomique) et ordonné pour qu'un manifeste n'arrive jamais avant ses items. Un lot qui dépasse les limites de CloudKit (400 enregistrements, 1,5 Mio) est découpé dans cet ordre ; dans ce cas rare, un autre appareil qui récupère entre deux lots peut voir un refus d'intégrité transitoire jusqu'à la récupération suivante.
- **Récupération** : les changements reçus vont dans `staging` puis dans `base` en une transaction à la fin de la récupération : un manifeste n'apparaît jamais sans ses items. Le jeton de changement est enregistré juste après chaque page.
- **Rebase** : quand le manifeste du serveur a avancé alors qu'un manifeste local en attente part de l'ancien, le vault est **retenu** : il n'envoie rien, ni items ni manifeste, tant qu'il n'a pas été rebasé. La récupération continue appareil verrouillé, mais le rebase demande la session déverrouillée. Le rebase vérifie le manifeste du serveur contre l'ancêtre gardé (il doit s'y enchaîner, sinon `ManifestRollback`), recalcule les intentions locales et les rejoue, dans une transaction SQLite par vault. Fusion au niveau de l'item : le `updated_at` le plus récent gagne, égalité tranchée par l'ordre des octets du hash. Une suppression locale d'un item modifié ensuite ailleurs est abandonnée ; une modification locale d'un item supprimé ailleurs le fait revenir.
- **Vault créé ici sans envoi confirmé** : l'ancêtre manque, le manifeste du serveur est accepté sans historique pour ce vault (confiance au premier usage, toujours vérifié par sa signature). Pour ce vault seulement, un serveur hostile pourrait servir une fois un ancien manifeste valide.
- **Récupération complète et réconciliation** : un jeton expiré, le bouton "Réessayer" de l'écran "Données refusées" ou une réinitialisation de zone relancent une récupération depuis zéro. À la fin, seuls les items d'un vault dont le serveur a rendu le manifeste suivent le serveur (un item qu'il n'a pas rendu est supprimé de `base`). Rien d'autre n'est supprimé : ni le compte, ni le keyset, ni les clés, métas et manifestes de vault, ni les items d'un vault que le serveur n'a pas rendu. Une zone vide ou partielle (serveur hostile, mauvais compte iCloud) ne peut donc pas effacer la copie locale ; un vault caché par le serveur reste lisible localement et la vérification des manifestes signale toute incohérence. Les écritures locales en attente ne sont jamais touchées.
- **Suppressions refusées** : une suppression venue du serveur pour les paramètres du compte ou le keyset (aucun client n'en fait au jalon 2), ou pour la clé, la méta ou le manifeste d'un vault déjà lu par l'appareil (`last_seen`, pas de suppression de vault au jalon 2, R14), est ignorée par `commit_remote`. Le stockage ne peut ni faire disparaître le compte ni faire oublier un vault. Chaque refus (et chaque ligne protégée qu'une récupération complète ne rend plus) est noté dans un journal plafonné à 100 entrées (type, identifiant, date) dans la méta de la base, hors de portée des clés écrites par Swift ; Réglages > Sync affiche "N suppressions refusées venant d'iCloud" avec le détail et "Effacer le journal" ; les journaux système ne contiennent que le nombre (ruling E25).
- **Compte disparu** : si l'appareil a épinglé un compte (ou connaît son identifiant dans ses réglages) et que la base n'en contient plus les paramètres, l'app affiche "Données refusées : Le compte a disparu du stockage." (`account_missing`), jamais l'accueil de création de compte. Le core refuse aussi de créer un compte dans une base dont l'état de l'appareil porte une épingle : un stockage hostile ne peut pas amener l'utilisateur à créer un second compte par-dessus le premier. Sorties proposées (ruling E22) : "Récupérer depuis iCloud" (build CloudKit), puis "Restaurer avec mon Emergency Kit" après confirmation, puis "Repartir de zéro" après avoir tapé EFFACER. Les deux dernières vident la base par `reset_store_for_recovery` (une transaction, état d'appareil compris, refusée tant qu'un compte est lisible) et suppriment la Secret Key et l'enrôlement biométrique ; rien n'est effacé dans iCloud. L'épingle effacée est reposée au déverrouillage suivant : comme pour un nouvel appareil, cette confiance au premier usage n'arrive que sur une action explicite de l'utilisateur.
- **Changement de compte iCloud** : au premier tour de sync, le coordinateur enregistre dans la base l'identifiant de l'utilisateur CloudKit (`userRecordID`). Si un autre compte iCloud est connecté ensuite, la sync s'arrête sans rien récupérer ni envoyer et affiche "Le compte iCloud a changé" (Réglages > Sync explique la situation), jusqu'à une action explicite : se reconnecter au compte d'origine, ou "Utiliser ce compte iCloud" (Réglages > Sync et bandeau des vues principales, ruling E23). Cette action lit d'abord la zone du nouveau compte sans toucher la base : un autre coffre OnePass y est refusé, le même coffre (même identifiant de compte) est accepté, une zone vide demande confirmation avant l'envoi ; accepter enregistre la nouvelle identité et repart comme après une réinitialisation de zone. L'identité vérifiée au début du tour est gardée ; avant l'envoi, elle n'est redemandée que si CloudKit a signalé un changement (`CKAccountChanged`) ou si la vérification a plus de 10 min (ruling E24). Limite : un changement non signalé dans ces 10 min n'est vu qu'au tour suivant. Sans cette garde, le jeton et les métadonnées d'un compte rencontreraient la zone d'un autre, et toute la base pourrait partir dans l'iCloud d'une autre personne.
- **Enregistrement illisible** : un enregistrement que CloudKit ne peut pas rendre bloque la récupération (le jeton n'avance jamais au-delà) ; après 5 tours de suite, l'état le dit clairement ("Un enregistrement iCloud reste illisible") au lieu de "momentanément indisponible". Une réponse qui annonce d'autres pages sans jeton termine le tour (nouvel essai plus tard) au lieu de boucler.
- **Réinitialisation de zone** (zone supprimée par l'utilisateur, ou recréée après `zoneNotFound`) : l'appareil efface ses métadonnées serveur et son jeton, récupère tout, puis renvoie seulement ce que le serveur n'a plus (pour un vault, seulement si son manifeste manque aussi), pour qu'un appareil en retard ne fasse pas régresser le serveur. La copie locale est la seule copie complète : elle n'est pas perdue en silence. Conséquence : un effacement volontaire des données iCloud est défait par le prochain appareil qui synchronise, et un vault supprimé pourrait être ressuscité par un appareil en retard (un réglage "Effacer les données iCloud" arrive au jalon 5).
- **Données altérées** : toute erreur d'intégrité du core affiche l'écran "Données refusées" avec le type d'attaque, sans aucune donnée tant qu'elle persiste ; le stockage n'est jamais réparé automatiquement. Un refus pendant le rebase (données locales encore lisibles, mais le vault ne se synchronise plus) s'affiche dans la barre latérale (Mac, iPad) et en bandeau en haut d'Accueil et d'Éléments sur iPhone.
- **Détail ouvert pendant une sync** : le détail d'un item se recharge quand un changement distant arrive ; si l'éditeur est ouvert et que l'item stocké a changé, l'app prévient avant que l'enregistrement n'écrase la nouvelle version (recharger ou continuer).

### 10.7 Limites du jalon 2

- **R1** : pas de connexion par QR code, ni de liste signée des appareils ou de révocation ; un nouvel appareil passe par l'Emergency Kit. Reporté au jalon 2b.
- **R2** : pas de mode public (session déléguée). Reporté au jalon 2b.
- **R8** : la sync CloudKit réelle n'est compilée que dans la configuration signée `Release-CloudKit` et n'a pas été vérifiée faute d'équipe Apple. Les builds non signés tournent en local seulement. La logique de sync est couverte par les tests Rust à deux appareils et par les tests Swift contre `InMemoryRemote` (rejeu, rétention, altération).
- **R9** : pas de pièces jointes ; le type de blob `Attachment` reste réservé.
- **R12** : pas de changement du mot de passe maître. Une AUK enveloppée reste valable tant que le mot de passe et la Secret Key ne changent pas ; rien à invalider au jalon 2.
- **R14** : pas de suppression de vault. La liste des vaults du compte n'est toujours pas signée (section 9, écart 8) : elle n'est pas livrée au jalon 2 et passe au jalon 2b.
- iOS peut afficher sa feuille "Enregistrer le mot de passe ?" (vers les mots de passe du système) après l'enregistrement d'un Login. Accepter ferait sortir la valeur du chiffrement de OnePass. Les champs de l'éditeur ne sont plus marqués `.password` ni `.oneTimeCode`, et les invites du mot de passe maître non plus (iOS ne doit jamais proposer d'enregistrer le mot de passe maître), mais l'heuristique du système se déclenche encore sur un champ sécurisé. Limite du jalon 2, **corrigée au jalon 3 quand OnePass est le fournisseur de remplissage automatique (iOS 26.2 et plus)** : la demande d'enregistrement arrive alors à l'extension, qui reconnaît qu'elle vient de OnePass lui-même (service de type app égal à l'identifiant de OnePass) et la referme sans interface ni écriture (section 14.7). La feuille reste possible quand un autre fournisseur est actif, et sur iOS 26.0 et 26.1, où l'API de demande d'enregistrement n'existe pas.
- Mode partagé : des vaults masqués ne sont qu'une règle d'affichage locale, pas une frontière cryptographique (le keyset ouvre tous les vaults).
- Aucun audit externe des apps.

## 11. Jalon 7 : MCP, agent SSH, Travel Mode

Ajouts du jalon 7 (`onepass-guard`, `onepass-mcp`, `onepass-ssh-agent`, `core/onepass-core/src/repo/travel.rs`). Ils ne changent aucun format du noyau (un type de blob, `TravelState = 10`, est ajouté en fin d'énumération). Le détail d'usage est dans `core/README.md`.

### 11.1 Modèle de menace MCP

L'adversaire est un agent IA, ou un contenu qu'il lit (injection de prompt), qui tente d'obtenir un secret, d'étendre ses droits ou de faire approuver une action trompeuse. Un programme local qui écrit dans le dossier de données est aussi considéré.

- **Contrôles, dans cet ordre** : arguments, visibilité (seuls les vaults `mcp_access` existent, hors corbeille), scope, approbation, action. Un accès hors d'atteinte répond comme un introuvable, et l'approbateur n'est pas appelé pour une requête refusée par la politique.
- **Politique signée** par la clé du compte (domaine `local:mcp-policy`) : un fichier altéré ou d'un autre compte empêche le démarrage. Les options `--vault` (répétable) et `--scopes` ne font que restreindre. Par défaut : `metadata` et `use`.
- **Données du coffre** renvoyées sous `untrusted_vault_data` avec une mention explicite ; tout texte affiché sur le terminal est nettoyé (caractères de contrôle remplacés par `?`, 200 caractères au plus), donc un titre ou un nom de client piégé ne réécrit pas l'invite.
- **Masquage** : valeurs exactes de 4 caractères ou plus, plus formes base64 et hexadécimale. C'est une réduction de risque : une commande approuvée peut transformer un secret. La barrière est l'approbation, qui montre la commande exacte.
- **Intégrité** : un échec de vérification met le vault en quarantaine pour la session, avec une erreur générique.
- **Audit** : chaîne de hachages SHA-256, tête `audit.log.head` signée (domaine `local:audit-head`), pas de titre ni de valeur. Modification, insertion, suppression et troncature sont détectées. Limites : une dernière ligne non scellée est tolérée (reste d'un plantage), ce qui permet à qui écrit le fichier d'ajouter une entrée finale forgée ; un ancien journal remis avec sa tête authentique n'est pas détecté. Même limite pour la politique : supprimer `mcp-policy.json` rétablit les valeurs par défaut, et un processus du même uid peut remettre une ancienne politique authentique (une autorisation retirée depuis revient) ; l'approbation de chaque requête secrète reste exigée.
- **Audit fermé pour les secrets** : avant un outil secret (`run_with_secrets`, `fill_template`, `create_login`, `totp_code`, `reveal_secret`) et avant une signature SSH, `AuditSink::ready` vérifie sans rien écrire (verrou, dernière ligne et tête) que le journal peut être prolongé ; sinon l'action est refusée. Une écriture qui échoue après l'action rend quand même le résultat (l'action a eu lieu) et le signale sur stderr. Les outils de métadonnées restent ouverts en cas d'échec du journal, faute de secret en jeu. L'ajout ne lit que la fin du fichier ; `verify_log` lit tout sous un verrou partagé, donc jamais un ajout à moitié fait. Une dernière ligne coupée ne se répare que par `onepass mcp audit --rotate`, qui archive le journal et sa tête (`audit.log.<date UTC>.bad`) et en ouvre un vide.
- **Approbation sur le terminal** : `/dev/tty` n'est ouvert que le temps d'une question, l'entrée en attente est vidée (`tcflush`), puis un code aléatoire de 2 lettres (alphabet `abcdefghjkmnpqrstuvwxyz`, tiré par `aws-lc-rs`) doit être retapé : le code pour une fois, le code suivi de ` s`, ` s15` ou ` s60` pour 5, 15 ou 60 minutes. Une injection de frappes (`TIOCSTI`) faite d'avance est vidée et ne peut pas deviner le code. Risque résiduel : un injecteur qui lit aussi l'écran du terminal voit le code et peut le retaper. Les approbations partagent le terminal du client ; aucune lecture n'est en cours entre deux questions.
- **Flags de vault** (`mcp_access`, `travel_safe`) fixés à la création : le meta de vault n'est pas versionné, le rendre modifiable permettrait à un stockage hostile de rejouer un ancien meta.
- **Déverrouillage** : mot de passe sur `/dev/tty` ; en mode développement, la Secret Key reste en clair dans `device.bin` (voir `core/README.md`).

### 11.2 Modèle de menace agent SSH

- La clé privée est relue dans le coffre à chaque signature, utilisée, puis effacée (`zeroize`) ; elle ne quitte jamais le processus.
- Une approbation à chaque signature, avec le processus demandeur identifié par le noyau du système (`LOCAL_PEERPID` sur macOS, `SO_PEERCRED` sur Linux). La mémorisation est bornée à (clé, exécutable) et 1 h, et annulée par `LOCK`. Un pair d'un autre uid, ou dont l'uid est inconnu, est refusé. Un socket existant qui répond n'est jamais remplacé (un autre agent le sert).
- Transfert d'agent refusé par défaut ; `session-bind@openssh.com` est vérifié et une fausse signature d'hôte ferme la connexion. RSA en SHA-1 refusé, RSA 3072 minimum à la génération.
- Messages bornés à 256 KiB, décodage strict, erreur de décodage = connexion fermée. La crate `rsa` (RUSTSEC-2023-0071) n'est pas utilisée : `aws-lc-rs` signe et génère.
- Limites : l'approbation affiche l'exécutable déclaré par le système, pas ce qu'il va faire de la signature ; le nom d'hôte n'est connu qu'indirectement par `known_hosts`, donc les marque-pages guident sans bloquer.

### 11.3 Construction du TravelState

- Entrée : chaque vault sans `travel_safe` est chargé par le chemin vérifié, l'amont doit contenir octet pour octet chaque enregistrement de cet état vérifié (clé, meta, manifeste et les items que le manifeste liste) avant toute suppression. Les restes que l'amont garde en plus (anciennes versions, items supprimés, car `push` ne fait qu'ajouter) sont ignorés. Puis les enregistrements locaux sont effacés et le `last_seen` du vault passe dans le `TravelState`.
- `TravelState` : clé symétrique fraîche, enveloppée pour la paire KEM hybride du compte (contexte `travel:` + id du compte), état chiffré en AES-256-GCM-SIV (`BlobKind::TravelState`), le tout signé par la clé du compte (domaine `local:travel-state`), rempli à 65536 octets fixes (`travel.bin`). Ni lisible ni falsifiable sans le compte déverrouillé.
- Sortie : les enregistrements sont recopiés depuis l'amont, qui n'est pas de confiance : clé, meta, manifeste, et seulement les items dont l'id et la version figurent dans le manifeste amont (décodé pour choisir, sans lui faire confiance ; les restes ne sont jamais recopiés), le `last_seen` est remis dans l'état d'appareil, puis `vaults()` et `items()` s'exécutent comme en usage normal. Un manifeste de séquence inférieure, une fourche ou un item retiré sont refusés ; en cas d'échec, les copies sont retirées et l'état d'appareil restauré à l'identique.
- Le mode ne touche ni au compte ni aux vaults `travel_safe`.

### 11.4 Limites du Travel Mode

- La présence de `travel.bin` révèle que le mode est actif ; sa taille fixe cache le nombre de vaults.
- Supprimer `travel.bin` fait perdre les `last_seen` mis de côté : `off` exige alors `--accept-unpinned`, et un ancien manifeste authentique serait accepté (la signature du compte reste exigée).
- Un vault local périmé ou bifurqué (seq inférieur, ou même seq avec un autre hash) planté à la place d'un vault caché fait refuser `off` ; il doit être retiré.
- Serveurs longs : `onepass mcp` et `onepass ssh-agent` gardent en mémoire les derniers manifestes vus et les réécrivent dans `device.bin`. Ils tiennent donc un verrou partagé sur `servers.lock`, et `travel on`, `travel off` et `backup restore` prennent ce verrou en exclusif sans attendre, ou refusent. En seconde ligne, un serveur qui voit `travel.bin` changer depuis son déverrouillage refuse la requête et s'arrête.
- Un `travel.bin` resté ou rejoué alors que les vaults sont revenus est signalé incohérent (`status` et `on`, code 3) ; `off` vérifie et fusionne. `backup restore` est refusé pendant le mode et `backup create` prévient que les vaults cachés n'y sont pas.
- Pendant le voyage, `audit.log` et `mcp-policy.json` nomment encore en clair les ids des vaults cachés (des identifiants opaques, sans nom ni contenu).
- L'espace libre de la base est compacté (`VACUUM`), mais les instantanés du système de fichiers et Time Machine peuvent garder d'anciennes copies : hors de portée.
- L'amont est un fichier SQLite de développement ; la synchro réelle vient au jalon 2.

### 11.5 Fuzzing

Deux cibles s'ajoutent : `mcp_line` (une ligne JSON-RPC arbitraire sur un hôte factice) et `ssh_agent_frame` (messages de l'agent et blobs de signature arbitraires).

## 12. Extension navigateur (jalon 4)

Cette section décrit la sécurité de l'extension et de son pont vers l'app. Spec : `docs/specs/2026-10-25-milestone-4-extension-design.md`. Code : `core/onepass-bridge` (protocole, correspondance d'origine), `core/onepass-native-host` (hôte natif de développement), `extension/`. Les sections 1 à 11 ci-dessus ne changent pas.

### 12.1 Modèle de menace de l'extension

Acteurs hostiles, du plus probable au moins probable :

1. **La page web.** Elle contrôle son DOM, peut créer des champs invisibles, superposer des éléments (clickjacking), envoyer des événements synthétiques et des `postMessage`, naviguer à tout moment, s'afficher sous un domaine sosie, embarquer des iframes d'autres sites.
2. **Le processus de rendu compromis.** Le script de contenu tourne dans le processus de la page : un exploit du moteur le contrôle. Le service worker traite donc chaque message d'un script de contenu comme non fiable et ne croit que l'origine fournie par le navigateur (`sender`), jamais une origine écrite dans le message.
3. **Une autre extension ou un processus local** qui parle à l'hôte natif ou le lance lui-même. L'hôte ne sert qu'un pair qui détient une clé d'appairage.
4. **Un intermédiaire sur le canal** entre l'extension et l'app (binaire d'hôte remplacé). Couvert par la comparaison de code à l'appairage et par l'authentification mutuelle de chaque session.

Hors périmètre : appareil compromis au niveau système. Un logiciel qui lit le profil du navigateur obtient la clé d'appairage et peut demander des secrets pour des origines précises, comme l'extension elle-même. Limite documentée, pas résolue en v1 (R-17 : signature de code de l'appelant et relais XPC au jalon 2).

### 12.2 Protocole du pont

Version `1`, trames JSON, plafond de 1 MiB (1 048 576 octets). Chaque trame porte `"v": 1`, toute autre version donne `{"t":"error","code":"version"}`.

**Primitives.** KEM hybride ML-KEM-1024 + X25519 combinés par HKDF-SHA256 (libellé propre au pont `onepass/bridge/kem/v1`, distinct de `onepass/kem/v1` du `core`), SHA-256, HMAC-SHA256, HKDF-SHA256, AES-256-GCM. Rust : `aws-lc-rs` ; TypeScript : WebCrypto pour le symétrique, `@noble/post-quantum` et `@noble/curves` (versions exactes) pour les KEM. Les vecteurs croisés (`core/onepass-bridge/tests/vectors/`, vérifiés des deux côtés) détectent toute divergence entre les deux implémentations.

**Transcript.** Concaténation, pour chaque champ dans l'ordre fixé par la spec, de `u32` grand-boutiste (longueur) et des octets, précédée du libellé `onepass/bridge/transcript/v1`. Jamais le JSON lui-même (sérialisation non canonique).

**Appairage (une fois par navigateur, spec 6.4).**

1. L'extension tire une paire KEM éphémère et un nonce `n_E`, et envoie un **engagement** `commit = SHA-256("onepass/bridge/commit/v1" || pk_E || n_E)` avant de voir quoi que ce soit de l'hôte.
2. L'hôte répond avec `pairing_id`, sa propre clé KEM et son nonce. L'extension révèle `pk_E`, `n_E` et un encapsulé `ct_E`. L'hôte vérifie l'engagement.
3. Les deux côtés calculent le transcript `T`, un **code à 6 chiffres** (`SAS`, 4 premiers octets d'un HKDF sur `T` modulo 1 000 000, affiché `123 456`) et la clé d'appairage `PK` (32 octets).
4. L'utilisateur compare le code sur les deux écrans. Après l'approbation côté app, l'hôte envoie un MAC (`HMAC(K_c, "host" || T)`), l'extension le vérifie, attend la confirmation de l'utilisateur ("Les codes sont identiques"), répond par son MAC (`"ext"`). L'hôte n'enregistre l'appairage qu'à réception d'un MAC valide.
5. Refus, délai de 120 s dépassé ou MAC invalide : les deux côtés effacent l'état.

L'engagement empêche un intermédiaire de choisir ses valeurs après avoir vu celles de l'autre côté : chaque code vu par l'utilisateur est uniforme pour lui, une chance sur un million par tentative, et chaque tentative demande une action de l'utilisateur. Pas de code tapé (R-06) : un code de faible entropie utilisé comme clé de MAC se retrouve par force brute hors ligne.

**Ouverture de session (à chaque connexion, spec 6.5).** `hello` (`pairing_id`, KEM éphémère, nonce), `welcome` (encapsulé, nonce, `session_id`, MAC hôte), `finish` (MAC extension). Clés : `HKDF(salt = T, ikm = ss_e || PK)`, étendue avec `onepass/bridge/session/e2h/v1`, `…/h2e/v1`, `…/confirm/v1`. Authentification mutuelle (seul un détenteur de `PK` dérive les clés), confidentialité persistante (`ss_e` éphémère), post-quantique (ML-KEM) avec X25519 en filet. MAC vérifiés en temps constant. Un `pairing_id` inconnu donne `unknown_pairing`.

**Messages chiffrés et rejeu (spec 6.6).** `{"t":"msg","c":<compteur>,"d":...}`, AES-256-GCM, une clé par sens, nonce de 96 bits = 4 octets nuls puis compteur `u64` grand-boutiste, données associées `session_id || sens (0 extension vers hôte, 1 hôte vers extension) || compteur`. Chaque sens a son compteur, qui commence à 0 ; le récepteur exige exactement la valeur attendue. Un compteur rejoué ou sauté, une trame modifiée, réfléchie dans l'autre sens ou d'une autre session, ou un compteur qui atteindrait 2^32 ferme la session. Un `id` de requête déjà vu est refusé. Session inactive 10 minutes : l'hôte la ferme. Pas de rejeu entre sessions : un `hello` rejoué donne d'autres clés, et un attaquant sans `PK` ne peut pas répondre `finish`.

### 12.3 Ce qui n'arrive jamais à l'extension

Mot de passe maître, Secret Key, clés de compte, de vault ou d'item, secret TOTP (seul le code du moment sort), clés privées de passkeys et de clés SSH, phrases de récupération, notes, pièces jointes, historique des mots de passe, items qui ne correspondent pas à l'origine demandée, liste complète du coffre avec secrets. Les résumés envoyés au menu et à l'overlay ne contiennent aucun secret (S16).

### 12.4 Politique de divulgation

Chaque décision de correspondance est **refaite par l'hôte** ; l'extension ne fait que transmettre l'origine que le navigateur lui a donnée.

- **Correspondance d'origine.** HTTPS obligatoire, sans exception de développement (R-18) : `insecure_origin` sinon. Domaine enregistrable par la Public Suffix List (crate `psl` en Rust, `tldts` en TypeScript, vecteurs communs). Règles `Domain`, `ExactHost`, `ExactUrl`, `Never`. Un port explicite dans l'URL de l'item doit être égal. Comparaison sur la forme ASCII (punycode) : un sosie IDN ne correspond jamais. `origin_mismatch` en cas d'écart.
- **Items exclus de l'autofill.** Archivés, à la corbeille, `hide_from_autofill`, Crypto Wallet, champs dont `autofill = false`.
- **Contexte (`ctx`).** Chaque requête dit d'où vient l'action (`popup`, `menu`, `overlay`, `save_prompt`, `chain`). `search` et `reveal` sont réservés à `popup` (`not_allowed` sinon), `reveal` aux champs autorisés à l'autofill.
- **Limite de débit.** 60 requêtes par minute et par session parmi `fill_*`, `totp`, `reveal`, `check_credentials`, `update_password` et `link_provider` (`save_login` n'est pas compté) ; au-delà `rate_limited`.
- **Nouvelle authentification (`reprompt`).** Les items qui l'exigent sont refusés par l'hôte de développement avec `reprompt_required` sauf configuration contraire ; l'app réelle redemande Touch ID. Les écritures sur ces items sont soumises à la même règle.
- **Journal d'audit.** Chaque réponse contenant un secret est journalisée localement (opération, item, origine, contexte, horodatage), sans la valeur.

### 12.5 Stockage de la clé d'appairage

L'extension garde `PK` dans l'**IndexedDB de l'origine de l'extension** (`extension/src/background/store.ts`), pas dans `storage.local`. Les scripts de contenu et les pages web n'ont aucun accès à cette base (origine d'extension). Côté hôte de développement : `pairings.json` en 0600 dans le dossier de données (l'app réelle utilisera le trousseau). Un logiciel qui lit le profil du navigateur y accède : limite hors périmètre (section 12.1, R-17).

### 12.6 Défenses dans la page

- **Racine fantôme fermée** : l'icône du champ vit dans une racine fantôme fermée que la page ne peut pas atteindre.
- **Iframes de l'extension** : le menu, l'overlay et la proposition d'enregistrement sont des pages de l'extension (origine différente de la page), jamais du DOM de la page. Aucun écouteur `message` sur ces pages, pas de lecture de la page parente, pas de `innerHTML` avec des données (test statique).
- **Garde de clic de 300 ms** : une page peut animer un élément sous le curseur. Chaque contenu affiché ignore les clics pendant 300 ms, ré-armée à chaque nouvelle apparition (retour dans la fenêtre visible, `IntersectionObserver` v2 quand le navigateur le fournit, fermeture si le cadre sort de la vue).
- **Événements de confiance et activation utilisateur** : seuls les événements `isTrusted` comptent (icône, menu, clavier, boutons fournisseur) ; une soumission n'est reportée à la proposition d'enregistrement qu'après un clic ou une touche de confiance dans ce même formulaire depuis moins de 5 s, et sous activation utilisateur (`navigator.userActivation`) quand le navigateur la fournit ; jamais pour un script de la page seul (l'activation seule vaut pour toute la page).
- **Épingles d'origine et `documentId`** : chaque jeton de menu, d'overlay ou de proposition est lié à l'onglet, au cadre et au document ; une navigation tue le jeton. Le remplissage et la proposition ciblent le `documentId` vérifié, à défaut le `frameId` plus une épingle d'origine que le script de contenu revérifie. Une navigation entre la demande et le remplissage annule tout (S9), sans valeur envoyée.
- **Ressources non devinables** : sur Chromium, `use_dynamic_url` : l'URL d'une page de l'extension est différente par session (S17).
- **Cadres d'autres sites** : aucun remplissage dans une iframe d'un autre site, sans exception (R-10, S6).
- **Formulaires re-rendus** : quand la page remplace un formulaire pendant le remplissage ou avant la soumission, la ref morte est résolue à nouveau, dans le même document et le même cadre seulement (le message reste épinglé à l'origine et au `documentId`), vers la seule copie de même identité (balise, attributs `id` et `name`, type de formulaire, rôles des champs) et le champ visible de même rôle. Un champ remplacé par une copie vide est rempli une seconde fois, une seule. Si deux formulaires ont la même identité, rien n'est rempli. Une page qui remplace son formulaire par un sosie de sa fabrication ne gagne rien : les valeurs vont à cette même page, qui pouvait déjà lire celles de son propre formulaire.

### 12.7 Garde-fous de la chaîne "Connexion en un clic"

Machine à états dans le service worker, une chaîne par onglet, état en mémoire de session (`storage.session`), sans secret. Démarrage seulement par un clic de l'utilisateur. À chaque analyse, le service worker revérifie le domaine fourni par `sender` contre une liste autorisée (domaine du site, plus les hôtes officiels du fournisseur pour une chaîne fournisseur ; R-11). Elle s'arrête et rend la main (`handoff`) sur : domaine hors liste (aussi sur chaque commit du cadre principal, avant toute analyse), HTTP, CAPTCHA détecté, validation push, champ de code sans TOTP, page inconnue (aucun champ reconnu 4 s après le chargement ou après le dernier changement de la page), échéance de 60 s, bouton "Arrêter", même étape répétée (mot de passe refusé). Un formulaire que la page re-rend (copie neuve) avant que la soumission l'atteigne n'est pas une étape répétée : la soumission vise sa copie, une seule fois ; le remplissage retrouve de même la copie du formulaire (même identité, même rôle) et remplit une seconde fois, une seule, un champ remplacé par une copie vide. Retour sur le site sans formulaire : terminé au plus tôt 4 s après le chargement, le temps qu'un formulaire tardif apparaisse. Un faux domaine de fournisseur n'est jamais traité comme le fournisseur (S11). Formulaire de connexion dans une iframe : la chaîne et l'overlay ne comptent que les cadres dont l'origine est **exactement** celle du cadre principal (pas seulement le même site : un sous-domaine peut être un autre service), origine et document relus dans `webNavigation` avant d'agir ; le remplissage, le clic et la soumission visent ce cadre et ce document, et la vérification avant livraison exige de nouveau la même origine que le cadre principal. L'overlay reste dans le cadre principal. Un cadre d'un autre site reste exclu (R-10).

### 12.8 Tests de sécurité S1 à S17

Les tests de bout en bout sont dans `extension/e2e/security.spec.ts` (Chromium, hôte natif réel, nom de test préfixé `Sn_`). Chaque ligne cite en plus les tests unitaires qui épinglent la défense.

| # | Attaque | Tests |
| --- | --- | --- |
| S1 | La page lit le DOM du menu ou de l'overlay | e2e `S1_page_cannot_read_menu_or_overlay` ; `test/content/content.test.ts` (racine fantôme fermée) ; `test/ui/safety.test.ts` |
| S2 | Clic synthétique sur l'icône | e2e `S2_synthetic_click_on_icon_is_ignored` ; `content.test.ts` (`icon_ignores_untrusted_click`) |
| S3 | `postMessage` vers le menu | e2e `S3_postmessage_to_menu_is_ignored` ; `test/ui/safety.test.ts` (`no_message_listener_on_window`) |
| S4 | Domaine sosie | e2e `S4_lookalike_*` ; `test/domain.test.ts` ; `core/onepass-bridge/tests/psl_vectors.rs` ; `core/onepass-bridge/tests/service.rs` (`fill_login_mismatch_origin`) |
| S5 | Page `http:` | e2e `S5_http_page_gets_nothing` ; `test/background/fill.test.ts` (`fill_refused_http`) ; `core/onepass-bridge/tests/service.rs` (`fill_login_http_rejected`) |
| S6 | Formulaire dans une iframe d'un autre site | e2e `S6_no_fill_in_cross_site_iframe` ; `fill.test.ts` (`fill_refused_cross_site_frame`) |
| S7 | Formulaire invisible | e2e `S7_invisible_form_stays_empty` ; `content.test.ts` (`invisible_field_not_filled`) ; `test/detect/visibility.test.ts` |
| S8 | Remplissage au chargement | e2e `S8_nothing_filled_on_load` |
| S9 | Navigation entre la demande et le remplissage | e2e `S9_navigation_between_request_and_fill_is_refused` ; `fill.test.ts` (`fill_refused_after_navigation`) |
| S10 | Chaîne redirigée vers un autre domaine | e2e `S10_chain_redirected_to_other_domain_stops` ; `test/background/chain/machine.test.ts`, `driver.test.ts` |
| S11 | Faux domaine de fournisseur | e2e `S11_fake_provider_domain_is_not_google` ; `machine.test.ts`, `provider-flow.test.ts` ; `core/onepass-bridge/tests/service.rs` (`fill_provider_requires_official_host`) |
| S12 | CAPTCHA pendant la chaîne | e2e `S12_captcha_during_chain_stops` ; `test/detect/captcha.test.ts`, `machine.test.ts` |
| S13 | Client sans appairage, `PK` faux, trame rejouée ou modifiée | `core/onepass-bridge/tests/session.rs`, `pairing.rs` ; `core/onepass-native-host/tests/host.rs` (`unknown_pairing_error`, `tampered_session_frame_closes`, `wrong_finish_mac_closes`) ; `test/bridge/session.test.ts`, `client.test.ts`, `pairing.test.ts` |
| S14 | Script de contenu compromis qui demande un item d'un autre site | e2e `S14_compromised_content_script_cannot_get_other_site_item` ; `test/background/router.test.ts` (`origin_taken_from_sender_not_message`) ; `core/onepass-bridge/tests/service.rs` (`fill_login_mismatch_origin`) |
| S15 | `reveal` ou `search` hors de la popup | e2e `S15_reveal_and_search_refused_outside_popup` ; `core/onepass-bridge/tests/service.rs` (`reveal_only_from_popup`, `search_only_from_popup`) ; `router.test.ts` |
| S16 | Secret dans les résumés | e2e `S16_menu_summaries_hold_no_secret` ; `core/onepass-bridge/tests/service.rs` (`summaries_contain_no_secret`) |
| S17 | URL fixe d'une ressource de l'extension | e2e `S17_fixed_extension_url_not_reachable` ; `test/manifest.test.ts` (`chromium: service worker and dynamic url`) |

Le laboratoire d'autofill (`extension/lab/`, `npm run lab`) ajoute un oracle de fuite sur des centaines de sites générés : tout secret du coffre fictif reçu par un hôte qui n'en est pas le propriétaire, ou écrit dans un champ piège (honeypot), est un verdict `leak`, compté à part des échecs. Une seule fuite rend le passage rouge (code de sortie 1). Le rapport ne contient aucune valeur secrète.

Lancer : `cd extension && npm run check && npm run e2e`, puis `cd core && cargo test -p onepass-bridge -p onepass-native-host` et `cargo test -p onepass-bridge --features vectors --test vectors`.

### 12.9 Limites connues de l'extension

- La clé d'appairage est lisible par un logiciel qui lit le profil du navigateur (R-17). Le pont de production vérifie la signature du relais et de l'appex (12.10), pas celle du navigateur qui lance le relais.
- L'hôte de développement n'est pas pour de vrais secrets : le coffre est chargé en mémoire (R-14), la clé d'appairage est dans un fichier en 0600, la fixture est refusée par un build release.
- Pas de passkeys (R-16), pas d'apprentissage des étapes (R-13), aucune exception aux iframes d'autres sites (R-10), chaîne arrêtée hors domaines autorisés (R-11).
- Les tests de bout en bout ne couvrent que Chromium (R-08).
- Les jetons du menu, de l'overlay et de la proposition d'enregistrement sont liés à l'identifiant de l'onglet ; chaque action revérifie l'origine et le `documentId` du cadre visé. Un moteur de rendu compromis du même site (qui partage le processus de la page) est hors périmètre.

### 12.10 Pont de production vers l'app Mac

Spec : `docs/specs/2026-10-27-release-bridge-design.md`. Code : `core/onepass-bridge/src/host.rs` (boucle de connexion commune à l'hôte de dev et à l'app), `core/onepass-relay` (rendez-vous, politique de signature, écoute, relais Chrome et Firefox), `core/onepass-ffi/src/bridge.rs` (`BridgeServer` dans l'app), `apple/SafariExtension/SafariRelay/Sources/SafariRelay/AppSocket.swift`, `apple/VaultKit/Sources/VaultKit/Bridge/BrowserBridge.swift`.

- **Transport.** Socket Unix `bridge.sock` (0600) à la racine du conteneur App Group `<équipe>.me.somalabs.onepass`, servi par l'app elle-même tant qu'elle tourne. Protocole, appairage, session, enveloppe chiffrée et politique de divulgation (sections 12.2 à 12.4) inchangés : le relais et l'appex recopient les trames sans les lire, 1 MiB au plus.
- **Signature des deux côtés.** Chaque côté identifie l'autre par le jeton d'audit du noyau (`LOCAL_PEERTOKEN`, jamais par pid) : cdhash du noyau, exigence `anchor apple generic`, équipe et identifiant exacts (`onepass-peer`, et `SecCodeCheckValidity` côté Safari). L'app n'admet que `me.somalabs.onepass.safari` et `me.somalabs.onepass.relay` signés par sa propre équipe ; un client refusé est fermé avant que l'app ne lise un octet. Le relais n'accepte que `me.somalabs.onepass` de son équipe. Un build signé ad hoc ne sert ni ne joint le pont.
- **Limite côté Safari (mesurée).** Dans un bundle d'app, le bac à sable refuse à un processus sandboxé (EPERM) la lecture de la signature du processus qui écoute ; l'extension Safari, toujours sandboxée, vérifie l'app quand le système le permet, refuse un pair identifié comme autre chose, et sinon s'appuie sur le conteneur de groupe (créer le socket demande d'être de l'équipe ou d'avoir l'accord de l'utilisateur pour lire les données d'autres apps) et sur le protocole : sans `PK`, un faux serveur n'ouvre aucune session ; il ne peut obtenir qu'un nouvel appairage, que l'utilisateur doit confirmer sans la feuille Touch ID de la vraie app, et seulement quand l'app ne tourne pas (sinon le socket est pris).
- **Ce que la signature ne prouve pas.** Elle prouve que le pair est notre relais, pas quel navigateur l'a lancé : tout processus local peut lancer `onepass-relay` avec un faux identifiant d'extension. L'identifiant reste un contrôle informatif (liste `OnePassBrowserExtensions` de l'app) ; la garde est l'appairage, comme en 12.1. La clé d'appairage reste lisible dans le profil du navigateur (12.5) : limite inchangée.
- **Coffre.** Le pont sert la `Session` déverrouillée de l'app, relue à chaque requête : verrouiller l'app verrouille le pont. Les coffres masqués dans l'app le sont aussi pour l'extension. Une écriture (enregistrement d'un login) recharge l'app et part en sync. `unlock` ne fait que mettre l'app au premier plan.
- **Approbations.** Appairage : feuille avec le code, l'extension et le navigateur (déclarés par l'extension, affichés comme tels), "Approuver" exige Touch ID (ou la montre) sur un coffre déverrouillé, sinon refus. Items `reprompt` : Touch ID à chaque fois, sinon `reprompt_required`.
- **Clés d'appairage.** Dans le trousseau (élément `me.somalabs.onepass.bridge`, `WhenUnlockedThisDeviceOnly`, groupe partagé de l'app comme la Secret Key), écrites avant que l'extension ne reçoive `pair_ok`. Elles passent par Swift (32 octets, clé de canal, jamais une clé de coffre). "Oublier" (Réglages > Remplissage automatique > Navigateurs) efface la clé : la session suivante reçoit `unknown_pairing`.
- **Bac à sable.** L'app et l'appex restent sandboxées. Le relais ne l'est pas, pour pouvoir vérifier l'app (P-09 bis) : runtime renforcé, seul l'App Group en entitlement, aucun état, aucune écriture, il ne lit pas les trames. Une distribution Mac App Store demanderait un relais sandboxé, sans cette vérification. Au plus 8 connexions simultanées, délai de 5 s pour la trame d'ouverture.
- **Journal.** Les divulgations sont journalisées sans valeur dans `bridge-audit.jsonl` (0600) du dossier de la base, comme pour l'hôte de dev.
- **Manifeste Chrome et Firefox.** Installé par `extension/scripts/install-app-host.mjs` (hôte `me.somalabs.onepass`), pas par l'app sandboxée (P-11).

## 13. Jalon 6 : Apple Watch, widgets, Raccourcis, Vision Pro

Cette section décrit ce qui sort de l'app au jalon 6 : une charge utile chiffrée vers la montre, un instantané lisible par les widgets, des App Intents et un signal de verrouillage. Spec : `docs/specs/2026-10-26-milestone-6-watch-vision-design.md`. La règle de frontière tient : seul le Rust manipule les clés et les graines TOTP. La montre garde ses graines dans un objet Rust (`CompanionVault`) qui ne rend que des codes ; les widgets ne reçoivent que des codes déjà calculés.

### 13.1 Charge utile de la montre

- **Construction** (`onepass-core/src/companion.rs`, `build_payload`, dans le Rust de l'iPhone) : items marqués `on_watch`, ni à la corbeille, ni archivés, ni `reprompt`, hors vaults masqués de l'appareil, triés par titre, 50 au plus ; une valeur de plus de 1 Kio est omise ; un item sans champ autorisé ni TOTP n'est pas envoyé. Champs par liste fermée (spec, table 3.2) : identifiant d'un Login, Wi-Fi (`ssid`, mot de passe, réseau invité), adhésion et fidélité, carte bancaire réduite à `•••• 1234` (calculé, jamais le numéro), codes d'accès, pièces d'identité. Jamais : mot de passe d'un Login, CVV, PIN, numéro complet de carte, notes. Le premier TOTP rempli voyage dans un champ à part, jamais dans la liste des champs.
- **Format** : `"OPC1" || génération (u64 big-endian) || enveloppe KEM || blob`. Une clé de charge utile aléatoire de 32 octets est enveloppée par `wrap_key_labeled` (ML-KEM-1024 + X25519, combineur HKDF-SHA256 de la section 3.3) avec l'étiquette `onepass/companion/v1` et le contexte `"watch" || SHA-256(clé publique de la montre)`, préfixé par sa longueur dans l'info HKDF. Le blob scelle le postcard sous cette clé (`BlobKind::Companion = 11`, AES-256-GCM de la section 3.2) avec un `blob_id` égal aux 16 premiers octets de `SHA-256("OPC1" || génération || empreinte du destinataire)` : la génération en clair est authentifiée. Le texte clair est écrit dans un tampon effacé à la libération (`Zeroizing`).
- **Ouverture** (`open_payload`, `CompanionVault::open`) : refus d'un format inconnu, d'une mauvaise clé, de toute altération, d'une génération qui ne correspond pas au blob et de plus de 50 entrées. Erreurs du core sans contenu.
- **Aucune signature de l'iPhone** (ruling W2) : seule l'app iPhone associée peut écrire dans la session WatchConnectivity appairée. Une app iPhone compromise pourrait pousser de fausses entrées, mais elle aurait déjà tout le coffre.
- **Transport** : la charge utile par `updateApplicationContext` (seul le dernier état compte) ; la clé publique de la montre et `refreshRequest` par `transferUserInfo` (file d'attente) ; l'effacement par les deux. WatchConnectivity ajoute son propre chiffrement, non compté dans le modèle de menace.

### 13.2 Clés, Keychain et fichiers

| Où | Élément | Protection |
| --- | --- | --- |
| Montre | clé secrète hybride, clé publique, plancher de génération (Keychain, service `me.somalabs.onepass.watch`) | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, keychain à protection de données |
| Montre | `Application Support/OnePass/companion.sealed` (charge utile scellée) | `NSFileProtectionComplete` |
| iPhone | clé publique de la montre, génération, date du dernier envoi, empreinte de la clé effacée (`UserDefaults`) | aucun secret |
| iPhone | `Library/OnePass/glance.json` du conteneur App Group `group.me.somalabs.onepass` | `NSFileProtectionComplete`, écriture atomique |

Sans code sur la montre, la clé ne peut pas être enregistrée : aucune clé n'est créée et l'app affiche "Active un code sur ton Apple Watch pour utiliser OnePass" (attendu d'après la classe Keychain, non vérifié sur vraie montre, 12.8). `ThisDeviceOnly` : ni sauvegarde ni trousseau iCloud. L'objet `CompanionVault` n'existe que pendant que l'app montre est au premier plan ; il est relâché à la sortie, et la réouverture relit le Keychain et le fichier, ce qui devrait exiger une montre déverrouillée (attendu, non vérifié sur appareil). Avec la détection du poignet, watchOS verrouille la montre retirée du poignet (attendu, non vérifié sur appareil) ; sans elle, seul le code de la montre protège les données (dit dans les réglages iPhone). L'app ne sait pas elle-même si la montre est au poignet.

### 13.3 Rejeu, clé changée, effacement

- La montre refuse une génération inférieure ou égale à son plancher (rangé dans le Keychain avec la clé). Le plancher est relevé avant l'écriture du fichier : un échec d'écriture ne laisse jamais revenir une charge utile plus ancienne. Un plancher illisible refuse tout.
- Charge utile illisible (clé changée, altération, rejeu) : ignorée, la montre garde la précédente et envoie une seule `refreshRequest` jusqu'à la prochaine charge utile acceptée (pas de va-et-vient avec un iPhone bloqué sur une mauvaise clé). Une charge utile reçue montre verrouillée (Keychain illisible) est notée par un marqueur sans secret, et un nouvel envoi est demandé au retour au premier plan.
- L'iPhone n'enregistre qu'une clé publique de 1600 octets (ML-KEM-1024 + X25519) ; une clé d'une autre longueur est ignorée. Il prend comme génération le plus grand de "génération + 1" et de l'heure en millisecondes depuis 1970 (un iPhone qui a perdu son compteur repasse au-dessus du plancher de la montre), et ne l'enregistre qu'après un envoi réussi ; une clé publique qui change (montre réinitialisée) remplace l'ancienne et déclenche un envoi.
- "Retirer de l'Apple Watch" envoie `wipe` par les deux canaux et coupe l'envoi sur l'iPhone (E22) : sinon l'iPhone déverrouillé scellerait de nouveau les mêmes éléments pour la clé neuve quelques secondes plus tard. Réactiver "Envoyer à l'Apple Watch" reprend les envois. La montre efface d'abord les clés et le plancher (sans la clé secrète, le fichier scellé est illisible), puis le fichier, et recrée une clé. Si l'effacement des clés échoue, un marqueur sans secret reste : la montre n'ouvre plus l'ancienne charge utile, ne renvoie pas l'ancienne clé et refait l'effacement à chaque démarrage ou retour au premier plan jusqu'à ce qu'il réussisse. L'iPhone oublie la clé et garde son empreinte SHA-256 : une copie ancienne de cette clé qui arrive plus tard est ignorée, seule une nouvelle clé reprend les envois. Un échec d'envoi de l'effacement est affiché ("la montre garde peut-être ses données").
- Journaux `os.Logger` sans titre ni valeur, des deux côtés.

### 13.4 Widgets

- L'app écrit l'instantané (8 favoris au plus, mêmes exclusions que la montre) au déverrouillage, à chaque changement pendant la session et au retour au premier plan déverrouillé, jamais coffre verrouillé. L'extension `OnePassWidgets` ne lie pas le core et n'a que le droit App Group et la protection de données `NSFileProtectionComplete`.
- **Exposition** (ruling W4) : pour chaque favori à TOTP, les codes de chaque période qui recoupe les 12 prochaines heures (fenêtre plafonnée à 24 h et 2880 codes par item dans le core). Ces codes valent la graine pendant 12 h pour qui lit le fichier, appareil déverrouillé ; jamais de graine. Au-delà de la fenêtre, ou pour une date sans code, le widget dit "Ouvre OnePass pour actualiser".
- Appareil verrouillé : le fichier devrait être illisible (`NSFileProtectionComplete`, attendu, non vérifié sur appareil, 12.8) et le widget affiche alors "Déverrouille ton iPhone" sans titre ni code ; titres et codes portent en plus `.privacySensitive()`, qui doit les masquer en écran verrouillé et en StandBy (non vérifié sur appareil). Un instantané absent, périmé ou corrompu donne un état neutre, jamais des données partielles.
- Pas de widgets sur Mac ni sur Vision Pro (W5) : macOS n'a pas de protection de fichiers ni d'état "appareil verrouillé" pour un widget.

### 13.5 Contrôles et signal de verrouillage

Le Contrôle "Verrouiller OnePass" s'exécute dans l'extension, qui n'a aucune clé : il écrit un horodatage dans les réglages partagés et poste la notification Darwin `me.somalabs.onepass.lock-request` (ruling W12). L'app en cours verrouille à réception ; à chaque retour au premier plan, elle verrouille aussi si une demande est plus récente que son dernier déverrouillage et que son lancement. Une demande antérieure au lancement est périmée (une app qui ne tournait pas n'avait aucune clé), pour qu'un vieux signal ne défasse jamais le premier déverrouillage après un relancement. Une app suspendue ne verrouille qu'à son réveil, comme pour le délai de verrouillage (10.3). Les Contrôles "Générer un mot de passe" et "Rechercher dans OnePass" ne font qu'ouvrir l'app par lien profond (`OnePassLink` refuse tout autre lien).

### 13.6 App Intents et Raccourcis

- Aucun intent ne rend un secret du coffre. "Générer un mot de passe" rend un mot de passe neuf, qui n'est pas dans le coffre (W14).
- "Copier le code à usage unique" ouvre l'app, exige une authentification fraîche et copie par le presse-papiers OnePass (local, 90 s) ; le code n'est jamais rendu au raccourci (W13). Si l'app était verrouillée, le déverrouillage fait pour cette demande suffit ; si elle était déjà déverrouillée, `VaultSession.confirmUserPresence` demande, quand le déverrouillage biométrique est activé, un contrôle `LAContext` `.deviceOwnerAuthentication` (Face ID, Touch ID, Optic ID ou le code de l'appareil, aucune clé en jeu : qui connaît le code de l'appareil peut copier un code depuis l'app déverrouillée) ; sans biométrie activée, ou si ce contrôle échoue, le mot de passe maître (ruling E15). Une demande en file n'hérite jamais du déverrouillage fait pour une autre.
- `ItemEntity` : depuis la session déverrouillée ; verrouillée, depuis les favoris de l'instantané (titres seulement, iOS), sinon vide avec "Déverrouille OnePass pour choisir un élément". Les titres ne sont jamais donnés à l'index de Siri (`updateAppShortcutParameters()` n'est pas appelé, E16). En revanche, un élément choisi dans un raccourci y est enregistré avec son titre et son sous-titre (l'identifiant d'un Login) : la définition du raccourci les garde hors du chiffrement du coffre, et Raccourcis la synchronise par iCloud (spec, section 9).

### 13.7 Vision Pro

- Optic ID utilise la même clé P-256 de la Secure Enclave et la même politique que Face ID (10.1). La clé `NSFaceIDUsageDescription` sert aussi à Optic ID : l'invite système dit "Face ID" (E18).
- Pas d'accès à la caméra pour les apps : pas de scan du QR de l'Emergency Kit, la Secret Key se tape.
- La vue de confidentialité reste opaque (E20). Pas de widgets, pas de Contrôles, pas de lien montre.

### 13.8 Limites du jalon 6

- Rien n'a été vérifié sur vrai matériel ni en build signé : WatchConnectivity réel, App Group et protection de données des widgets, Optic ID, widgets et Contrôles sur l'écran verrouillé, phrases Siri (spec, section 13). La logique d'appairage, de scellement, de rejeu et d'effacement est couverte par les tests Rust et `CompanionKit` sans montre.
- Codes de 12 h dans le fichier des widgets (W4) ; un widget peut afficher l'état verrouillé jusqu'à son prochain rafraîchissement.
- La montre garde en mémoire, pendant l'affichage, les valeurs des champs autorisés (R5 : Swift ne garantit pas l'effacement des `String`).
- Montres `arm64_32` seulement non prises en charge (W3).
- Aucun audit externe.

## 14. Jalon 3 : AutoFill et passkeys

Cette section décrit ce qu'ajoutent l'extension `OnePassAutoFill` (fournisseur de remplissage automatique, iOS, iPadOS et macOS), le conteneur partagé et les passkeys. La règle de frontière du jalon 2 est inchangée : toutes les clés restent dans le Rust. Spec : `docs/specs/2026-10-26-milestone-3-autofill-design.md`.

### 14.1 Ce que voit le système

OnePass publie des identités dans `ASCredentialIdentityStore`, le magasin du système qui alimente la barre QuickType. Ce magasin est lu par le système en dehors du chiffrement de OnePass. Il reçoit :

- les **hôtes** des URL des Logins (jamais l'URL complète) et les **noms d'utilisateur** ;
- pour les passkeys, le **`rp_id`**, le nom d'utilisateur, l'**identifiant du credential** et la **user handle** (que le site reçoit déjà à chaque connexion, ce n'est pas un secret) ;
- des **identifiants d'enregistrement opaques** (`"<vault hex>:<item hex>"`) et l'état favori.

Il ne reçoit jamais un mot de passe, un code à usage unique, une clé ni un titre d'item. Sont exclus : la corbeille, l'archive, les Logins marqués `hide_from_autofill` et les vaults masqués sur l'appareil (mode partagé). Le réglage **Réglages > Remplissage automatique > Suggestions au-dessus du clavier** coupe la publication et vide le magasin ; le magasin est aussi vidé à la réinitialisation du compte ("Restaurer avec mon Emergency Kit" et "Repartir de zéro" après un compte disparu, test `resetForRecoveryEmptiesStore`, et la réinitialisation de debug). Une écriture de l'extension (passkey, Login enregistré) publie les identités **avant** que sa session se verrouille, sans l'anti-rebond : la suggestion est là dès la requête suivante, sans attendre un déverrouillage de l'app. Quelqu'un qui lit le magasin du système apprend donc quels sites et quels identifiants l'utilisateur a dans OnePass (ruling A5).

### 14.2 Extension, session par requête, conteneur partagé

- **Un second processus.** L'extension a sa propre session. Chaque requête ouvre une session neuve, demande un déverrouillage frais (Face ID ou mot de passe maître), sert la requête, puis **verrouille à la fin** (réussite, échec ou annulation) : les clés sont effacées. Le système peut aussi écarter l'interface (glissement, changement d'app) : le **renvoi de l'interface** verrouille la session et abandonne la requête en cours. L'extension n'est jamais déverrouillée hors requête : les variantes "sans interaction" répondent `userInteractionRequired`, sauf l'enregistrement conditionnel d'une passkey, qui répond `failed` (section 14.5), et les demandes d'enregistrement de OnePass lui-même (section 14.7).
- **Pas de reprompt supplémentaire.** Les items `reprompt` sont remplis sans seconde question : le déverrouillage de la requête est déjà une vérification fraîche.
- **Conteneur App Group.** La base (`vault.sqlite`) et les réglages (`UserDefaults`) vivent dans le conteneur partagé : `group.me.somalabs.onepass` sur iOS, `<préfixe d'équipe>me.somalabs.onepass` sur macOS. Sur iOS le dossier de la base est en `completeUntilFirstUserAuthentication`. Le contenu reste le blob chiffré et signé du core : le conteneur partagé n'ajoute aucun secret en clair. Sans conteneur (build Mac signé ad hoc), l'app retombe sur les emplacements du jalon 2 et l'extension n'a rien à lire.
- **Groupe Keychain partagé.** La Secret Key et l'enrôlement biométrique sont dans le groupe `$(AppIdentifierPrefix)me.somalabs.onepass.shared` (déjà prévu au jalon 2, section 10.2), pour que l'extension ouvre le coffre sans l'app. Si un build signé refusait le groupe, l'extension ne verrait pas le coffre et le dirait ("Ouvre OnePass pour configurer ton coffre") ; l'app, elle, resterait fonctionnelle (ruling A1).
- **Notification Darwin.** `me.somalabs.onepass.store-changed` ne transporte aucune donnée. L'extension la poste après une écriture ; l'app recharge ses résumés et pousse les lignes `pending` (même verrouillée). L'extension n'envoie rien à CloudKit. Une notification perdue (app suspendue) est rattrapée au retour au premier plan : l'app déverrouillée recharge alors ses résumés.
- **Éditeur ouvert pendant une écriture de l'extension.** Si l'éditeur d'un Login est ouvert dans l'app pendant que l'extension y ajoute une passkey, le rechargement déclenché par la notification (ou par le retour au premier plan) passe par la même garde que la sync (section 10.6, "Détail ouvert pendant une sync") : l'app prévient avant que l'enregistrement n'écrase la nouvelle version ("Élément modifié entre-temps", recharger ou continuer). Continuer puis enregistrer écrase la passkey : c'est un choix explicite.
- **Base WAL dans le conteneur partagé (à vérifier sur appareil).** Sur iOS, un processus suspendu qui garde un verrou sur un fichier SQLite d'un conteneur App Group peut être tué par le système (code `0xdead10cc`). L'app garde des connexions longues (session, sync) sur la base WAL partagée avec l'extension. Le risque n'est pas observable dans le Simulateur et n'est pas mesuré. Mitigation prévue : tâche d'arrière-plan (`beginBackgroundTask`) autour des écritures et de la sync, ou point de contrôle WAL et fermeture des connexions au passage en arrière-plan.

### 14.3 État de l'appareil entre deux processus

L'app et l'extension tiennent chacune un `Repository` avec son `DeviceState` en mémoire (épingle du compte, dernier manifeste vu par vault). Une écriture aveugle de l'un ferait reculer le `last_seen` écrit par l'autre et affaiblirait la détection de rejeu. `Repository<SyncStore>::persist_device_state` **fusionne** donc avant d'écrire, dans une seule transaction, avec la règle de `adopt_device_state` du jalon 7 : par vault l'entrée de plus grand `seq` gagne ; un même `seq` avec un autre hash est une fourche, refusée (`ManifestRollback`) avant toute écriture, ce qui laisse le stockage et la mémoire tels qu'ils étaient (test `merge_refuses_a_forked_entry_and_changes_nothing`) ; l'épingle est celle de la mémoire (ou celle du stockage si la mémoire n'en a pas), et quand les deux épinglent le même compte son plancher Argon2id est le maximum, composante par composante, des deux (il ne fait que monter, test `merge_keeps_the_higher_kdf_floor`). Le résultat est adopté en mémoire. Les écritures d'items sont déjà sûres entre processus : `commit_manifest` est conditionnel et SQLite sérialise les transactions.

**Seule l'app rebase.** Un rebase renumérote un vault et peut finir sous le `seq` de manifestes locaux abandonnés, que le stockage a déjà vus. Le rebase persiste donc avec `force` : pour chaque vault rebasé, dans la transaction de son rebase, l'entrée de la mémoire s'impose, quoi que le stockage contienne. La persistance finale de `rebase()` est une fusion ordinaire : elle garde un `last_seen` que l'extension aurait écrit entre-temps. L'extension ne rebase jamais et ouvre une session neuve par requête, qui est verrouillée à la fin : aucun processus longue durée ne garde en mémoire un `seq` abandonné (ruling X2). Une future surface qui garderait une session longue et rebaserait ailleurs devrait revoir cette hypothèse : un processus périmé pourrait réécrire un `seq` mort et bloquer un vault jusqu'au prochain verrouillage.

**Travel Mode (jalon 7).** `enter_travel` retire volontairement de la mémoire l'entrée des vaults mis de côté. Ces vaults sont notés comme retirés jusqu'à la persistance suivante, qui les force comme un rebase : la fusion ne reprend pas l'entrée encore stockée, et le vault ne revient dans l'état de l'appareil qu'avec `exit_travel` (test `merge_does_not_resurrect_a_vault_parked_by_travel_mode`). Le Travel Mode tourne aujourd'hui **dans la CLI seulement**, qui garde son état dans `device.bin` et le fusionne par `adopt_device_state` (même règle, plus grand `seq`) ; la correction vaut pour un `Repository<SyncStore>`. Quand le Travel Mode arrivera dans les apps, l'entrée en voyage devra vider ou republier le magasin d'identités du système (section 14.1) : sinon les hôtes et identifiants des vaults mis de côté resteraient proposés au-dessus du clavier. Limite : un autre processus qui garderait en mémoire l'entrée du vault mis de côté la réécrirait à sa propre persistance ; l'extension ouvre une session neuve par requête, qui relit l'état stocké.

### 14.4 Mémoire : Argon2id dans l'extension

Le mot de passe maître demande une dérivation Argon2id de 256 Mio. Une extension d'AutoFill a une limite mémoire inférieure à celle d'une app, et le système peut la tuer pendant la dérivation sur un appareil réel. L'extension propose donc **Face ID d'abord** (l'AUK enveloppée par la Secure Enclave ne coûte presque pas de mémoire) et garde le mot de passe maître en second, car sans lui un appareil sans biométrie, ou dont l'enrôlement a expiré (14 jours, redémarrage, `.biometryCurrentSet`), n'aurait aucun remplissage (ruling A2). Le risque est **non mesuré** : il demande un appareil réel (section 10.7 de la spec, limites du jalon 3 de `apple/README.md`). Plan B prévu : enveloppe de l'AUK par une clé Secure Enclave `.userPresence`. Le compteur d'échecs du mot de passe est partagé avec l'app (réglages partagés).

### 14.5 Passkeys

- **Génération et stockage dans le Rust.** `onepass-core::webauthn` crée une paire ECDSA P-256 par `aws-lc-rs` (`EcdsaKeyPair::generate_pkcs8`). La clé privée est rangée en **PKCS#8 DER** dans le champ `passkeys` du Login, chiffrée comme toute valeur d'item. **Elle ne traverse jamais vers Swift** : Swift reçoit un `attestationObject`, des `authenticatorData` et une signature. `FfiPasskey` reste sans user handle ; la `user_handle` ne traverse que dans les identités et l'assertion, là où l'API Apple l'exige (ruling A8).
- **Format.** Compteur de signature toujours **0**, flags **UP, UV, BE, BS** (et AT à l'enregistrement) : la passkey est sauvegardée et synchronisée, un compteur ne pouvant pas rester monotone entre appareils (ruling A6). **AAGUID** propre à OnePass, attestation **`none`** (ruling A7) : les sites affichent un authentificateur inconnu. UV est vrai parce que toute requête passe par un déverrouillage frais.
- **Garde-fous.** Identifiant de credential de 16 octets aléatoires ; `rp_id` vide ou de plus de 253 octets, `user_handle` de plus de 64 octets, nom d'utilisateur de plus de 1024 octets, `client_data_hash` qui ne fait pas 32 octets : refusés. Une clé qui ne se relit pas en PKCS#8 P-256 (passkey importée d'un autre algorithme) donne une erreur, jamais une signature.
- **Qui signe quoi.** Une requête passkey directe doit porter l'identifiant du credential de l'identité choisie : sans lui elle est **refusée** au lieu de signer avec la première passkey du Login (ruling X13). Une passkey ne peut pas être créée dans un item archivé ni dans un vault masqué. La création est refusée si une passkey de la liste `excluded` du site existe déjà (`PasskeyExcluded`). Un nom d'utilisateur vide ne peut pas créer de nouveau Login (ruling X6).
- **Pas de création silencieuse.** L'enregistrement conditionnel (`performWithoutUserInteractionIfPossible(passkeyRegistration:)`, mise à niveau automatique d'un site vers une passkey) répond toujours `failed` : l'extension n'est jamais déverrouillée hors requête et une passkey n'est créée qu'après un choix explicite (rulings A9 et X21).
- **Passkey supprimée.** Une passkey supprimée dans OnePass reste connue du site : le jalon 3 n'envoie pas `reportUnknownPublicKeyCredential`.

### 14.6 Hameçonnage : correspondance de domaine

La correspondance est calculée dans `onepass-ffi` (`autofill.rs`) avec la Public Suffix List (crate `psl`) et `url`, et non dans Swift :

- Hôtes comparés en ASCII minuscule (punycode). Même hôte d'abord, puis même domaine enregistrable (PSL) ; `examp1e.com` ne correspond pas à `example.com`, `co.uk` est un suffixe public et non un domaine. Les ports sont ignorés (ruling X5).
- **`http` n'est jamais proposé pour un domaine public** (un site `https` seulement, sauf hôte local). Une **adresse IP ne correspond qu'à elle-même**.
- Les Logins `hide_from_autofill` ne sont **jamais** proposés, même par le choix manuel (`include_all`), et aucun item caché de l'AutoFill, quel que soit son type, n'est listé par l'insertion de texte : "caché de l'AutoFill" signifie jamais offert par l'extension (ruling X3). Seuls les Logins vivants sont proposés (ni corbeille ni archive) ; les items **Crypto Wallet** ne le sont jamais, y compris par l'insertion de texte, pas plus que ceux d'un vault masqué sur l'appareil.
- Le choix hors correspondance demande un geste explicite : rubrique "Autres éléments" ou recherche. Là seulement, un Login `http` peut apparaître, c'est un choix volontaire (ruling X4).
- Pour les passkeys, le `rp_id` est vérifié par le système (domaine de la page ou domaines associés de l'app) ; l'extension ne le re-valide pas, elle ne propose que les passkeys du `rp_id` demandé. Un Login vivant et non caché qui porte une passkey dont le `rp_id` est l'hôte demandé (même normalisation, casse ignorée) est un candidat "même hôte" même sans URL correspondante (ruling X22).
- **Suggestion QuickType périmée.** Une identité publiée reste dans le magasin du système jusqu'à la publication suivante. Avant de remplir directement un mot de passe ou un code, l'extension vérifie que le Login correspond encore à l'hôte de l'identité choisie ; sinon elle revient à la liste du site.
- L'app hôte de test `AutoFillHost` n'a pas de domaine associé : le test UI ne prouve pas la correspondance, que les tests Rust couvrent (ruling A16).

### 14.7 Données hostiles venues du web

- **Règles de mot de passe.** Les règles `passwordrules` d'un champ viennent d'une page web : c'est une entrée hostile. `password_from_rules` borne la longueur générée à **64** dans tous les cas (un `minlength` supérieur donne le repli, 20 caractères aléatoires), ignore les propriétés inconnues, retombe sur la recette de repli quand les règles sont illisibles (valeur mal formée) ou contradictoires, et efface ses tampons (`zeroize`). Une page ne peut donc pas faire allouer ou générer sans borne dans l'extension (ruling X7). `required` seul restreint l'ensemble aux classes requises et `special` inclut l'espace (sémantique d'Apple, ruling X8) : un site qui refuse l'espace peut rejeter le mot de passe généré, l'utilisateur en génère un autre. Aucune donnée du coffre n'est lue pour générer.
- **Demandes d'enregistrement venant de OnePass lui-même** (iOS 26.2 et plus). Après l'enregistrement d'un Login dans l'app, iOS propose d'enregistrer la valeur dans le fournisseur actif. L'extension reconnaît la demande venant de l'app (service de type app dont l'identifiant est celui de OnePass) et la referme sans interface ni écriture ; un mot de passe généré rempli (`generatedPasswordFilled`) se referme de même, sans interface ni écriture. Une valeur identique à un Login existant (même hôte, même identifiant à la casse près, même mot de passe) ne peut être reconnue qu'après le déchiffrement : elle se referme **juste après le déverrouillage**, sans feuille ni écriture. Toute autre demande passe par un déverrouillage et la feuille Enregistrer ou Mettre à jour (le Login du même site est trouvé quel que soit la casse de l'identifiant). Les écritures de l'extension (enregistrement, passkey) ne sont acceptées que vers une cible affichée à l'écran et un vault non masqué (le modèle refuse les identifiants fournis par l'appelant sans les vérifier).

### 14.8 Migration vers le conteneur partagé

Au lancement, avant toute ouverture de la base, `SharedContainerMigration` déplace `vault.sqlite`, `-wal` et `-shm` de l'ancien conteneur vers le conteneur partagé, dans l'ordre `-shm`, `-wal`, base, pour qu'un arrêt au milieu laisse l'ancienne base complète. Garde-fous :

- **Retour en arrière.** Une migration qui échoue en route **remet en place** les fichiers déjà déplacés avant de retomber sur l'ancien conteneur : ouvrir une base sans son WAL perdrait des écritures (ruling X17).
- **Double échec.** Si le retour en arrière échoue aussi, la base est coupée en deux (base d'un côté, fichiers annexes de l'autre). La migration le signale par une erreur distincte (`SharedContainerMigrationError.rollbackFailed`) et l'app **n'ouvre aucune base** pour ce lancement : ni l'ancienne sans son WAL, ni la partagée sans base (qui mènerait à l'accueil de création de compte). L'écran "Données refusées" explique de relancer OnePass ; au lancement suivant, la migration ramène les fichiers annexes égarés vers l'ancienne base puis reprend le déplacement (ruling X23).
- **Rien n'est supprimé.** Si la base partagée existe mais ne contient aucun compte alors qu'une base ancienne existe, la base partagée est **mise de côté** (renommée, jamais supprimée) et l'ancienne est migrée. Un fichier supplémentaire reste à côté du magasin après un tel lancement.
- **L'extension ne crée jamais le magasin.** Si le fichier partagé manque, elle répond "Ouvre OnePass pour configurer ton coffre" : une base vide créée avant la migration aurait écarté la vraie (ruling X16).
- Les clés `onepass.*` de `UserDefaults.standard` sont copiées une fois dans la suite partagée.

### 14.9 Limites du jalon 3

Voir la section "Limites du jalon 3" de [`apple/README.md`](../apple/README.md). En résumé : l'icône dans le champ n'existe pas (le système n'en permet pas aux fournisseurs), la mémoire d'Argon2id dans l'extension, Face ID dans l'extension et le risque `0xdead10cc` de la base partagée (section 14.2) ne sont vérifiés que sur un appareil, la sync CloudKit d'une passkey demande un build `Release-CloudKit`, et l'import et l'export de passkeys par le flux système (FIDO Credential Exchange) sont reportés avec le jalon 5. Aucun audit externe.
