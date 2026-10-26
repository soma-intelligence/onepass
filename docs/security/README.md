# Sécurité de OnePass : jalon 1 (noyau)

Ce document décrit ce que fait le code de `core/onepass-core` au jalon 1 : le modèle de menace, la construction cryptographique exacte (labels, tailles, paramètres) et les attaques testées. Là où le code diffère de la spec d'architecture (`docs/superpowers/specs/2026-10-25-onepass-architecture-design.md`), c'est le code qui est décrit, et l'écart est listé à la fin.

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
- iOS peut afficher sa feuille "Enregistrer le mot de passe ?" (vers les mots de passe du système) après l'enregistrement d'un Login. Accepter ferait sortir la valeur du chiffrement de OnePass. Les champs de l'éditeur ne sont plus marqués `.password` ni `.oneTimeCode`, et les invites du mot de passe maître non plus (iOS ne doit jamais proposer d'enregistrer le mot de passe maître), mais l'heuristique du système se déclenche encore sur un champ sécurisé. Limite du jalon 2, corrigée au jalon 3 quand OnePass devient le fournisseur de remplissage automatique.
- Mode partagé : des vaults masqués ne sont qu'une règle d'affichage locale, pas une frontière cryptographique (le keyset ouvre tous les vaults).
- Aucun audit externe des apps.
