# Revue des primitives cryptographiques

Revue du 2026-10-26 (spec de durcissement, section 8 et Ruling 13). Chaque affirmation renvoie au code qui la porte ; la construction complète est décrite dans `docs/security/README.md`, section 3 (cœur), sections 6 et 7 (archive, Watchtower) et section 12.2 (pont de l'extension). Les chemins sont relatifs à la racine du dépôt.

## 0. Implémentations et versions

Versions lues dans `core/Cargo.lock` et `extension/package-lock.json` le jour de la revue.

| Composant | Version | Rôle |
| --- | --- | --- |
| `aws-lc-rs` (sur `aws-lc-sys`) | 1.18.2 (0.46.0) | HKDF, HMAC, AES-256-GCM-SIV, AES-256-GCM, SHA-256, SHA-3-256, SHA-1, X25519, Ed25519, ML-KEM-1024, ML-DSA-87, générateur aléatoire. Build non-FIPS (feature par défaut `aws-lc-sys`, pas `aws-lc-fips-sys`). |
| `argon2` (RustCrypto, sur `blake2` 0.11.0) | 0.6.0 | Argon2id. Features `alloc` et `zeroize`, sans `parallel`. |
| `slh-dsa` (RustCrypto, sur `sha2` 0.10.9) | 0.1.0 | SLH-DSA-SHA2-256s. Impose `signature = "=2.3.0-pre.4"` (`core/onepass-core/Cargo.toml`). |
| `libcrux-ml-kem`, `libcrux-ml-dsa` | 0.0.11 | Tests différentiels seulement (dépendances de développement du cœur ; dépendance optionnelle `vectors` du pont, jamais dans un build livré). |
| `slh-dsa` (alias `slh-dsa-next`) | 0.2.0-rc.5 | Test différentiel seulement (`core/onepass-core/tests/slh_dsa_differential.rs`). |
| `zxcvbn` | 3.x | Force des phrases de passe d'archive. |
| `@noble/post-quantum` | 0.5.4 | ML-KEM-1024 dans l'extension (embarque ses propres `@noble/curves` et `@noble/hashes` 2.0.1). |
| `@noble/curves` | 1.9.7 | X25519 dans l'extension. |
| `@noble/hashes` | 1.8.0 | Dépendance déclarée, non importée par `extension/src/bridge`. |
| WebCrypto (navigateur) | | SHA-256, HKDF, HMAC, AES-256-GCM, aléa (`crypto.getRandomValues`) dans l'extension. |

## 1. Argon2id (dérivation du mot de passe)

- **Rôle.** Première moitié de la dérivation à deux secrets : `AUK = HKDF-SHA256(salt = kdf.salt, ikm = Argon2id(NFC(mot de passe)) || Secret Key, info = "onepass/auk/v1")` (`core/onepass-core/src/crypto/kdf.rs`, `derive_auk`). Sert aussi à la clé d'export par phrase de passe (section 10).
- **Paramètres.** Argon2id version 0x13, sortie 32 octets, sel de 32 octets aléatoires. Plancher `KDF_FLOOR = (262144 KiB, 4 passes, 4 voies)`, soit 256 MiB (`kdf.rs`). Plancher de développement `DEV_KDF_FLOOR = (8192, 1, 1)`, appliqué seulement sous `cfg(test)` ou avec la feature `dev-fast-kdf` dans un build à assertions de debug (`core/onepass-core/src/account.rs`, `enforced_floor`) : un build release impose toujours `KDF_FLOOR`. Plafond `KDF_CEILING = (2097152 KiB, 16, 16)` (2 GiB) vérifié avant tout calcul, dans `account.rs` (`verify_params`) et `core/onepass-core/src/archive/format.rs` (`within_ceiling`). Plancher épinglé par appareil, qui ne fait que monter (`account.rs`).
- **Niveau visé.** Le coût Argon2 ne protège que le mot de passe. Sans la Secret Key (256 bits, `crypto/secret_key.rs`), l'AUK reste à 256 bits d'entropie : une attaque hors ligne sur les données du cloud seules est infaisable quel que soit le mot de passe. Argon2 compte quand la Secret Key a fui (appareil volé, kit de secours).
- **Pourquoi.** Fonction gagnante de la PHC et recommandée par la RFC 9106 ; résistance mémoire contre les GPU et ASIC. Les paramètres dépassent la seconde recommandation de la RFC 9106 (64 MiB, t = 3, p = 4) et le minimum OWASP (19 MiB, t = 2, p = 1).
- **Écartés.** PBKDF2 (pas de coût mémoire), scrypt (correct, mais moins de marge d'analyse et pas de normalisation récente), bcrypt (72 octets, coût mémoire fixe et faible).
- **Limites connues.** Sans la feature `parallel`, les 4 voies sont calculées l'une après l'autre : la latence de déverrouillage est celle d'un calcul séquentiel, l'attaquant parallélise. Ce n'est pas une perte de sécurité (le travail total reste le même), seulement de temps pour l'utilisateur. La mémoire de travail est allouée par l'appelant et effacée à la libération (`kdf.rs`) ; les copies internes du crate ne le sont pas toutes. Le mot de passe est normalisé en NFC dans un tampon effacé.
- **Preuves.** `core/onepass-core/tests/kdf_vectors.rs`, `auk_matches_independent_vector` : AUK recalculée indépendamment avec `argon2-cffi` 25.1.0 et HKDF de Python. Tests de plancher et de plafond dans `account.rs` (`kdf_ceiling_bounds_each_cost`, `signed_params_above_the_kdf_ceiling_are_refused_before_argon2`) et `tests/malicious_store.rs`. Pas de vecteur de la RFC 9106 dans le dépôt : le vecteur croisé avec `argon2-cffi` le remplace.

## 2. HKDF-SHA256

- **Rôle.** Toutes les dérivations de clés du cœur passent par `hkdf32` (`core/onepass-core/src/crypto/key.rs`) : AUK, sous-clés de blob (`onepass/blob/enc/v1`, `onepass/blob/commit/v1`), combinateur KEM, clé d'archive. Le pont a sa propre fonction (`core/onepass-bridge/src/kdf.rs`, `try_expand`), l'extension passe par WebCrypto (`extension/src/bridge/kdf.ts`).
- **Niveau visé.** 256 bits comme PRF ; sortie fixe de 32 octets.
- **Pourquoi.** RFC 5869, analysé (Krawczyk 2010), disponible partout (aws-lc, WebCrypto, Python), ce qui permet les vecteurs croisés. Chaque usage a un libellé `info` propre et versionné.
- **Écartés.** KMAC et le mode KDF de BLAKE3 (absents de WebCrypto et d'aws-lc-rs).
- **Limites connues.** La clé dérivée est écrite directement dans un emplacement verrouillé (`crypto/locked.rs`), mais la PRK intermédiaire d'aws-lc ne l'est pas.
- **Preuves.** `key.rs`, `derive_matches_independent_hkdf_vector` ; vecteurs croisés du pont (`core/onepass-bridge/tests/vectors/*.json`, vérifiés en Rust par `core/onepass-bridge/tests/vectors.rs` et en TypeScript par `extension/test/bridge/vectors.ts`).

## 3. AES-256-GCM-SIV, engagement HMAC-SHA256 et padding

- **Rôle.** Chiffrement de tous les blobs stockés : keyset, clés et métadonnées de vault, clés et contenus d'item, manifestes, archives, état Travel, charge de la montre (`core/onepass-core/src/crypto/aead.rs`).
- **Construction.** `K_enc` et `K_com` dérivées de la clé du blob par HKDF. Engagement `HMAC-SHA256(K_com, AAD_base)`, où `AAD_base` contient l'en-tête (format, algorithme, type, nonce), l'id du blob, l'id du vault et le schéma. L'engagement est vérifié en temps constant (`verify_slices_are_equal`) avant tout déchiffrement, puis passé à GCM-SIV avec `AAD_base`. Nonce aléatoire de 96 bits par blob. Padding : préfixe de longueur u32 puis zéros jusqu'au palier (256 octets minimum, puissance de 2 jusqu'à 64 KiB, puis multiples de 64 KiB), vérifié canonique à l'ouverture (`unpad`).
- **Niveau visé.** 256 bits de clé (environ 128 bits contre un adversaire quantique, Grover). L'engagement de clé repose sur la résistance aux collisions de HMAC-SHA256 : 128 bits.
- **Pourquoi.** GCM-SIV (RFC 8452) résiste à la réutilisation de nonce : une collision de nonces aléatoires ne révèle que l'égalité de deux clairs, au lieu de casser l'authentification comme avec GCM. AES est accéléré en matériel sur toutes les plateformes visées. GCM-SIV n'est pas engageant : l'engagement HMAC empêche qu'un même chiffré s'ouvre sous deux clés (attaques de partitionnement et « invisible salamanders »), et il est vérifié en premier, donc une mauvaise clé ne donne aucun oracle. Comme la clé, le nonce et les données associées sont engagés et que le déchiffrement est déterministe, le clair est lui aussi fixé.
- **Écartés.** AES-256-GCM (catastrophique en cas de nonce répété, limite de 2^32 messages par clé avec des nonces aléatoires), XChaCha20-Poly1305 (aws-lc-rs n'a que ChaCha20-Poly1305 à nonce de 96 bits, non engageant lui aussi), AEGIS-256 (absent d'aws-lc-rs 1.18.2), constructions engageantes génériques plus lourdes (CTX, UtC/HtE) : l'engagement HMAC sur la clé et l'AAD suffit pour ce modèle.
- **Limites connues.** Taille maximale d'un clair d'environ 4 GiB (préfixe u32). Le padding ne cache la taille qu'au palier près. Les clés de vault scellent beaucoup de blobs avec des nonces aléatoires : les bornes de GCM-SIV (de l'ordre de 2^48 messages par clé) restent très loin de l'usage réel, les clés d'item changeant à chaque écriture.
- **Preuves.** `aead.rs`, `wire_format_known_answer` : blob complet recalculé indépendamment avec `cryptography` 49 (`AESGCMSIV`) et HKDF de Python. `core/onepass-core/tests/aead_props.rs` : inversion de chaque bit refusée (proptest), mauvaise clé refusée à l'engagement avant l'AEAD, mauvais type, vault, id ou schéma refusés. Ordre des vérifications : `header_checks_run_in_order`, `open_detailed_names_the_failing_stage`. Fuzzing de `blob_open` (`core/Makefile`, `FUZZ_TARGETS`).

## 4. ML-KEM-1024 + X25519 (enveloppes de clés)

- **Rôle.** Envelopper une clé symétrique vers la clé publique du compte : clés de vault (`core/onepass-core/src/vault.rs`), sauvegarde vers le compte (`archive/format.rs`), état Travel (`core/onepass-core/src/repo/travel.rs`), charge de la montre en variante étiquetée (`core/onepass-core/src/companion.rs`). Code : `core/onepass-core/src/crypto/kem.rs`.
- **Combinateur.** `HKDF-SHA256(salt vide, ikm = ss_mlkem || ss_x25519 || ct_mlkem || eph_x25519 || x25519_destinataire, info = "onepass/kem/v1" || contexte)`. Tous les champs sont de longueur fixe, la concaténation est donc sans ambiguïté. Le chiffré ML-KEM et les deux clés X25519 entrent dans la dérivation, comme dans X-Wing (qui n'y met que la partie X25519, ML-KEM liant déjà sa clé publique et son chiffré). La variante étiquetée (`wrap_key_labeled`) préfixe le contexte de sa longueur.
- **Niveau visé.** ML-KEM-1024 : catégorie NIST 5. X25519 : environ 128 bits classiques. La clé reste sûre tant que l'un des deux tient (« récolter maintenant, déchiffrer plus tard » couvert par ML-KEM ; défaut éventuel de ML-KEM ou de son implémentation couvert par X25519).
- **Pourquoi.** ML-KEM est la norme FIPS 203 ; le niveau 5 est retenu parce que ces enveloppes protègent des clés de vault à très longue durée de vie. L'hybride reste exigé par la spec (section 8).
- **Écartés.** ML-KEM seul (aucun filet si un défaut apparaît), X-Wing tel quel (ML-KEM-768, catégorie 3, et brouillon IETF non figé au moment du choix), Classic McEliece (clés publiques de plusieurs centaines de Kio), HQC (pas encore normalisé), HPKE (RFC 9180, absent d'aws-lc-rs 1.18.2 et sans suite post-quantique normalisée).
- **Limites connues.** L'enveloppe n'authentifie pas l'émetteur : n'importe qui peut envelopper une clé vers la clé publique du compte ; la clé de vault est authentifiée par le manifeste signé (README, section 3.4 à 3.7). La clé secrète ML-KEM importée est vérifiée contre son hash SHA3-256 (FIPS 203), la clé publique ne passe que par le contrôle d'aws-lc à `EncapsulationKey::new` ; les clés publiques du compte sont de toute façon signées. Voir aussi la faiblesse F1 (section 13).
- **Preuves.** `core/onepass-core/tests/differential.rs` : vecteurs NIST ACVP ML-KEM-1024 (`mlkem1024_acvp_decapsulation_vectors`, 25 cas AFT et 10 cas VAL de rejet implicite, `core/onepass-core/tests/vectors/SOURCES.md`) ; 100 échanges croisés aws-lc et libcrux dans les deux sens (`mlkem1024_awslc_and_libcrux_interoperate`). `kem.rs`, `wrap_key_golden_vector` : une enveloppe figée (`tests/vectors/kem_wrap_key_v1.hex`) doit toujours s'ouvrir. Tests de contexte, de destinataire, de longueur et d'altération dans `kem.rs`.

## 5. ML-DSA-87 + Ed25519 (signatures courantes)

- **Rôle.** Manifestes de vault (domaine `"manifest"`), archives signées (`"onepass/archive/v1"`), époque de restauration (`"onepass/restore-epoch/v1"`, `core/onepass-core/src/epoch.rs`). Code : `core/onepass-core/src/crypto/sign.rs` (`HybridSigningKey`, `HybridVerifyingKey`).
- **Construction.** Les deux schémas signent le même message encadré `"onepass/sig/v1" || u16_be(len(domaine)) || domaine || message`. ML-DSA en variante pure, contexte FIPS vide ; la signature ML-DSA d'aws-lc est randomisée (mldsa-native tire l'aléa par `RAND_bytes`). La vérification calcule les deux moitiés sans court-circuit et exige les deux. Clé secrète stockée sous forme de deux graines de 32 octets, clés aws-lc reconstruites à l'usage (`PqdsaKeyPair::from_seed`, `Ed25519KeyPair::from_seed_unchecked`).
- **Niveau visé.** ML-DSA-87 : catégorie NIST 5. Ed25519 : environ 128 bits classiques. Une contrefaçon exige de casser les deux.
- **Pourquoi.** ML-DSA est la norme FIPS 204, rapide, avec des signatures de 4627 octets acceptables pour des manifestes. Ed25519 couvre un défaut de ML-DSA ou de sa jeune implémentation.
- **Écartés.** Signatures composites IETF (brouillon non figé), FN-DSA/Falcon (FIPS 206 pas encore publiée, arithmétique flottante délicate en temps constant), SLH-DSA pour l'usage courant (signatures de 29792 octets et signature lente), ECDSA P-256 (nonces fragiles, aucun avantage sur Ed25519 ici).
- **Limites connues.** Les deux moitiés ne sont pas liées l'une à l'autre (pas d'étiquette composite dans le message signé) : sans conséquence ici, la vérification exige toujours les deux et ces clés ne servent à rien d'autre. La dérivation graine vers clé n'est figée par aucun vecteur : voir la faiblesse F2 (section 13).
- **Preuves.** `tests/differential.rs` : vecteurs NIST ACVP ML-DSA-87 de vérification (15 cas, interface externe pure) et de génération (3 signatures attendues qui doivent se vérifier) ; 50 signatures croisées aws-lc et libcrux dans les deux sens (`mldsa87_awslc_and_libcrux_interoperate`). `sign.rs` : rejet si l'une des moitiés est fausse, cadrage exact du message, longueurs et entrées malformées. Fuzzing de `signature_verify`.

## 6. SLH-DSA-SHA2-256s (identité racine)

- **Rôle.** Clé d'identité du compte : elle ne signe que les paramètres du compte (domaine `"account-params"` : `account_id`, paramètres Argon2id, clés publiques de signature et KEM), vérifiés à chaque déverrouillage et épinglés par appareil (`account.rs`, `verify_params`). Code : `sign.rs` (`IdentityKey`, `IdentityVerifyingKey`).
- **Construction.** FIPS 205, variante pure, contexte vide, même message encadré que la section 5. Signature randomisée (`opt_rand` de 32 octets frais à chaque signature). Clé secrète stockée dans son encodage FIPS 205 (`sk_seed || sk_prf || pk_seed || pk_root`), reconstruite à l'usage par `slh_keygen_internal` ; à l'import, `pk_root` est recalculé et doit correspondre (`IdentityKey::from_bytes`). Le type de clé du crate n'implémente pas `Zeroize` : la clé reconstruite est écrasée par une clé nulle à la libération (`SlhKeyGuard`, au mieux).
- **Niveau visé.** Catégorie NIST 5. La sécurité ne repose que sur les propriétés de SHA-256 et SHA-512 : aucune hypothèse de réseau euclidien. C'est l'hypothèse la plus prudente pour la racine de confiance du compte.
- **Pourquoi la variante « s ».** Peu de signatures (une par changement de paramètres) : la variante « s » donne des signatures plus courtes (29792 contre 49856 octets) au prix d'une signature lente, sans importance ici. SHA2 plutôt que SHAKE : SHA-256 accéléré en matériel sur Apple Silicon, et vecteurs ACVP disponibles pour les deux.
- **Écartés.** XMSS et LMS (à état : un état réutilisé entre deux appareils casse le schéma, inacceptable pour un compte multi-appareils), ML-DSA comme racine (même hypothèse que les signatures courantes : une rupture des réseaux euclidiens toucherait les deux niveaux).
- **Limites connues.** Implémentation unique dans l'écosystème Rust mûr (section 12). Seule la vérification est couverte par des vecteurs ACVP ; voir la faiblesse F2.
- **Preuves.** `tests/differential.rs`, `slhdsa_sha2_256s_acvp_verification_vectors` : 14 cas externes purs avec contexte et 14 cas internes (ACVP-Server, commit `975de31e`). `sign.rs` : `identity_sign_verify`, `identity_key_bytes_and_malformed_inputs`, `identity_signature_is_bound_to_domain_key_and_bytes`. `core/onepass-core/tests/slh_dsa_differential.rs` (section 12.3).

## 7. SHA-256

- **Rôle.** Racine de Merkle et chaînage des manifestes (`core/onepass-core/src/manifest.rs`), empreinte signée des archives (`archive/format.rs`), id de blob des enveloppes KEM (`kem.rs`, `blob_aad`), transcript, engagement et combinateur du pont (`core/onepass-bridge/src/transcript.rs`, `pairing.rs`, `kem.rs`). Aussi interne à HKDF, HMAC et SLH-DSA.
- **Niveau visé.** 128 bits contre les collisions, 256 bits contre les préimages.
- **Pourquoi.** Norme, accélérée en matériel, disponible dans WebCrypto (pont). Les hachages de Merkle séparent feuilles (`0x00`), nœuds (`0x01`) et liste vide (`0x02`).
- **Écartés.** SHA-3 et BLAKE3 : aucun gain de sécurité utile ici, et BLAKE3 est absent de WebCrypto.
- **Limites connues.** Aucune pour ces usages (pas d'extension de longueur exploitable : les entrées sont encadrées ou de longueur fixe, et les MAC passent par HMAC).
- **Preuves.** Couvert indirectement par les vecteurs croisés du pont et les vecteurs figés des manifestes et archives (`tests/archive.rs`, `golden_header`).

## 8. SHA-1 (k-anonymity HIBP uniquement)

- **Rôle.** Seul usage : le préfixe de 5 caractères hexadécimaux du SHA-1 d'un mot de passe, envoyé à l'API Pwned Passwords ; les 35 autres caractères sont comparés en local (`core/onepass-core/src/watchtower/pwned.rs`, `sha1_hex`, avec `SHA1_FOR_LEGACY_USE_ONLY` d'aws-lc). La CLI ajoute `Add-Padding: true` (`core/onepass-cli/src/commands/watchtower.rs`).
- **Niveau visé.** Aucune propriété cryptographique n'est demandée à SHA-1 : c'est l'identifiant imposé par l'API et par le corpus HIBP. Les collisions connues de SHA-1 sont sans objet (on ne s'en sert ni pour authentifier ni pour lier).
- **Écartés.** Le mode NTLM de l'API (même rôle, aucun avantage). Le mode hors ligne (`--hibp-dir`) évite tout envoi.
- **Limites connues.** Le préfixe révèle à la source qu'un des environ un million de mots de passe de ce préfixe a été testé (README, section 7). Le hex est dans un tampon effacé, mais le condensat brut rendu par aws-lc (`Digest`) reste sur la pile sans effacement : voir F4.
- **Preuves.** Tests de `pwned.rs` et `core/onepass-core/tests/watchtower.rs` ; fuzzing de `hibp_range`.

## 9. Générateur aléatoire

- **Rôle.** Toutes les clés, graines, sels et nonces du cœur : `fill_random` et `random_array` (`core/onepass-core/src/crypto/random.rs`) sur `aws_lc_rs::rand::fill` ; le pont appelle `aws_lc_rs::rand::fill` directement (`session.rs`, `pairing.rs`) ; l'extension `crypto.getRandomValues` (`extension/src/bridge/bytes.ts`, `randomBytes`). Les clés ML-KEM, ML-DSA et X25519 générées par aws-lc tirent leur aléa du même générateur.
- **Niveau visé.** 256 bits ; générateur déterministe d'aws-lc (à base de CTR-DRBG) alimenté par l'entropie du système, ou aléa du navigateur.
- **Pourquoi.** Un seul générateur, celui de la bibliothèque crypto déjà utilisée, sans repli maison. Une erreur du générateur remonte en `Error::Crypto`, jamais en clé nulle.
- **Écartés.** Le crate `rand` (couche de plus sans gain), un générateur propre au projet.
- **Limites connues.** `random_array` rend une copie non effacée : réservée aux valeurs publiques ou recopiées aussitôt dans un tampon effacé (documenté dans `random.rs`). Les clés `SymmetricKey` sont tirées directement dans leur emplacement verrouillé (`key.rs`, `generate`).
- **Preuves.** `random.rs`, tests unitaires (tirages distincts et non nuls). Pas de test statistique : il n'en prouverait rien.

## 10. Clé de chiffrement d'archive (KEK)

- **Rôle.** Envelopper la clé de contenu `K` d'une archive `.onepass` pour une phrase de passe (`archive/format.rs`, `passphrase_kek`). Le destinataire compte passe par la section 4 (contexte `"onepass/archive/v1" || archive_id`).
- **Construction.** `KEK = HKDF(derive_auk(NFC(phrase), Secret Key nulle, kdf), "onepass/archive/kek/v1")`, puis `K` scellée sous `KEK` par la section 3 (type `Archive`, `blob_id = archive_id`, schéma `KEY_SCHEMA = 0`). Phrase de score zxcvbn au moins 3 (sur ses 128 premiers caractères) et paramètres Argon2id au moins au plancher des comptes à la création ; à l'ouverture, seul le plafond est imposé.
- **Niveau visé.** Celui de la phrase de passe multipliée par le coût Argon2id : sans Secret Key, une archive par phrase de passe peut être attaquée hors ligne, c'est le prix d'un export restaurable n'importe où.
- **Pourquoi.** Réutilise la dérivation et l'AEAD déjà revus, avec un libellé propre (`KEK_INFO`) qui sépare la KEK d'une AUK.
- **Écartés.** `age` avec scrypt (format externe, scrypt plutôt qu'Argon2id), PBKDF2.
- **Limites connues.** Un fichier dont les paramètres Argon2id sont abaissés reste lisible (refus d'un plancher à l'ouverture impossible sans casser les anciens fichiers) ; seul son auteur s'affaiblit. Un en-tête altéré d'export non signé se lit comme une mauvaise phrase de passe, sans livrer de contenu (README, section 6).
- **Preuves.** `core/onepass-core/tests/archive.rs` (aller-retour, phrase faible refusée, plafond, altérations, en-tête et charge figés) ; fuzzing de `archive_open`.

## 11. Pont de l'extension : appairage et session

- **Rôle.** Canal entre l'extension et l'hôte natif (README, section 12.2). Rust : `core/onepass-bridge/src` (`kem.rs`, `kdf.rs`, `pairing.rs`, `session.rs`, `channel.rs`, `transcript.rs`), sur aws-lc-rs seulement. TypeScript : `extension/src/bridge` (`kem.ts` sur `@noble/post-quantum` et `@noble/curves`, `kdf.ts` et `channel.ts` sur WebCrypto).
- **Primitives.** KEM hybride propre au pont : `HKDF-SHA256(salt = "onepass/bridge/kem/v1", ikm = ss_mlkem || ss_x25519, info = SHA-256(ct || pk_x25519))`, où `ct` contient le chiffré ML-KEM et la clé éphémère X25519. Transcript : libellé puis champs préfixés de leur longueur u32, haché par SHA-256. Appairage : engagement `SHA-256("onepass/bridge/commit/v1" || pk_E || n_E)` envoyé avant de voir l'hôte, code à 6 chiffres (4 octets d'un HKDF sur le transcript, modulo 10^6), clé d'appairage et MAC de confirmation par HKDF à libellés distincts, MAC HMAC-SHA256 vérifiés en temps constant. Session : `HKDF(salt = T, ikm = ss_e || PK)` étendu en clés e2h, h2e et confirm. Messages : AES-256-GCM, une clé par sens, nonce `0^32 || compteur u64`, compteur strict, session fermée à 2^32 messages.
- **Niveau visé.** Confidentialité post-quantique et persistante (KEM éphémère par session), authentification mutuelle par la clé d'appairage. Appairage : une chance sur un million par tentative contre un intermédiaire actif, chaque tentative demandant une action de l'utilisateur.
- **Pourquoi.** WebCrypto n'a ni ML-KEM ni AES-GCM-SIV : ML-KEM vient de noble, et les nonces par compteur rendent GCM sûr ici (jamais de réutilisation, clé par sens et par session). Le code comparé plutôt que tapé évite qu'un code de faible entropie serve de clé de MAC (README, section 12.2, R-06).
- **Écartés.** Noise (pas de motif post-quantique normalisé dans les bibliothèques disponibles des deux côtés), TLS local (gestion de certificats dans le navigateur), PAKE à code tapé (le code serait cassable hors ligne s'il servait de clé).
- **Limites connues.** `@noble/post-quantum` n'est ni vérifié formellement ni validé FIPS ; les vecteurs croisés détectent une divergence avec aws-lc, pas un défaut commun aux deux. L'effacement des secrets en JavaScript est au mieux (copies du ramasse-miettes). La réduction modulo 10^6 de 32 bits a un biais de l'ordre de 2^-12, négligeable. Le même libellé de transcript sert à l'appairage et à la session : la séparation tient aux libellés HKDF distincts et au nombre de champs, ce qui suffit.
- **Preuves.** Vecteurs croisés `core/onepass-bridge/tests/vectors/{kem,pairing,session}.json`, générés par `core/onepass-bridge/tests/vectors.rs` (étapes ML-KEM déterministes par libcrux, feature `vectors`) et vérifiés par `extension/test/bridge/vectors.ts`. Tests de protocole `core/onepass-bridge/tests/pairing.rs`, `session.rs`, `service.rs` ; tests S1 à S17 (README, section 12.8).

## 12. Évaluation de `slh-dsa` et Ruling 13

### 12.1 Candidats

| Implémentation | État au 2026-10-26 | Constat |
| --- | --- | --- |
| `slh-dsa` 0.1.0 (RustCrypto) | Dernière version stable (2024-08-18). | Utilisée. FIPS 205 final (contexte, `slh_sign_internal`). Passe les vecteurs ACVP de vérification. Impose le prérelease `signature = "=2.3.0-pre.4"` et `rand_core` 0.6. Types de clé sans `Zeroize`. `SigningKey::try_from` ne vérifie pas que `pk_root` correspond aux graines : OnePass le fait lui-même (`IdentityKey::from_bytes`). Pas d'audit publié. |
| `slh-dsa` 0.2.0-rc.5 (RustCrypto) | Candidate (2026-04-28), série rc depuis 2025-09. | Passe sur `signature` 3, `rand_core` 0.10, `sha2` 0.11, `hybrid-array` 0.4. Ajoute `ZeroizeOnDrop` (feature `zeroize`), les messages en plusieurs morceaux et PKCS#8. Même lignée de code que la 0.1.0. Se compile à côté de la 0.1.0 (section 12.3). |
| `slh-dsa` 0.0.3 | Publiée en 2025-04, après la 0.1.0. | Branche antérieure, sans intérêt. |
| `aws-lc-rs` 1.18.2 | | Pas de SLH-DSA : ni API Rust, ni module dans `aws-lc-sys` 0.46.0 (`crypto/fipsmodule` n'a que `ml_dsa`, `ml_kem` et `pqdsa`). |
| libcrux | | Pas de SLH-DSA (seulement ML-KEM et ML-DSA). |
| `fips205` 0.5.0 (IntegrityChain) | Stable, pur Rust. | Implémentation indépendante de FIPS 205, peu répandue et sans audit publié. Pas de raison de quitter RustCrypto pour elle, mais c'est le meilleur candidat pour un test différentiel vraiment indépendant (recommandation R1, section 13). |
| `pqcrypto-sphincsplus` 0.7.2 | | Liaison C de PQClean décrite comme SPHINCS+ ; l'alignement sur l'interface FIPS 205 finale (contexte, encodage du message) n'est pas établi. Écarté. |

### 12.2 Ruling

Garder `slh-dsa =0.1.0` : seule version stable, vecteurs NIST ACVP vérifiés en test, aucune autre implémentation mûre (aws-lc-rs et libcrux n'ont pas SLH-DSA, la 0.2 est encore candidate). Passage à la 0.2 derrière la même API interne (`IdentityKey`, `IdentityVerifyingKey`, `IdentitySignature` dans `core/onepass-core/src/crypto/sign.rs`) quand elle sera stable. Un défaut de la 0.1 toucherait la clé d'identité, qui ne signe que des clés et des paramètres.

Le changement de version est sans migration de données : le test différentiel montre que les mêmes graines donnent les mêmes clés et que les signatures sont identiques octet pour octet. Au passage, retirer l'épinglage `signature = "=2.3.0-pre.4"` (commentaire de `core/onepass-core/Cargo.toml`) et remplacer `SlhKeyGuard` par la feature `zeroize` de la 0.2.

### 12.3 Test différentiel 0.1.0 contre 0.2.0-rc.5

Faisable : `slh-dsa-next = { package = "slh-dsa", version = "=0.2.0-rc.5" }` en dépendance de développement de `onepass-core` se résout sans conflit (`signature` 3.0.0 et 2.3.0-pre.4 coexistent, ce sont deux versions majeures distinctes). `cargo deny check` passe.

`core/onepass-core/tests/slh_dsa_differential.rs` vérifie :

- **Clés.** Pour trois triplets de graines, `slh_keygen_internal` donne la même clé publique et le même encodage de clé secrète dans les deux versions, et chaque encodage se relit dans l'autre version.
- **Signatures.** Avec le même aléa (signature randomisée, comme OnePass) et sans aléa (déterministe), les deux versions produisent des signatures identiques octet pour octet ; chaque signature se vérifie avec l'autre version (pure, contexte vide) et est refusée sur un autre message.
- **API interne.** Une clé produite par la 0.2 s'importe comme `IdentityKey` (recalcul de `pk_root` par la 0.1) ; une signature `IdentityKey::sign` se vérifie par la 0.2 sur le message encadré, et une signature de la 0.2 sur ce message est acceptée par `IdentityVerifyingKey::verify`, sous le bon domaine seulement.

Exécution : `cd core && cargo test -p onepass-core --test slh_dsa_differential --release` (environ 4 s ; environ une minute en debug, dans `make test`).

Limite : les deux versions viennent du même code. Le test détecte une régression entre elles, pas un défaut commun ; seuls des vecteurs ACVP ou une implémentation indépendante le feraient (F2, R1).

## 13. Faiblesses et recommandations

Aucune faiblesse exploitable n'a été trouvée. Les points suivants sont réels et corrigibles ; aucun code crypto n'a été modifié par cette revue.

- **F1 (faible, conception).** Le commentaire de `KEM_INFO` (`core/onepass-core/src/crypto/kem.rs`) interdit une seconde famille de contextes dans `wrap_key` sans préfixe de longueur, or trois familles l'utilisent : `"vault:" || id` (22 octets, `vault.rs`), `"travel:" || id` (23 octets, `repo/travel.rs`) et `"onepass/archive/v1" || id` (34 octets, `archive/format.rs`). Aucune collision n'est possible aujourd'hui (longueurs et préfixes distincts, et l'id de blob interne est `SHA-256(contexte)`), mais l'invariant documenté est faux et une quatrième famille pourrait le casser. Correction : faire passer archive et Travel par `wrap_key_labeled` sous un nouveau libellé avec migration de format, ou au minimum ajouter un test qui énumère les familles et vérifie qu'aucune n'est préfixe d'une autre, et corriger le commentaire.
- **F2 (moyenne, couverture de tests).** La dérivation graine vers clé n'est figée par aucun vecteur pour ML-DSA-87 (`PqdsaKeyPair::from_seed`), Ed25519 (`from_seed_unchecked`) et SLH-DSA (`slh_keygen_internal`, avant le test différentiel de cette tâche). Le keyset ne stocke que les graines : si une mise à jour d'aws-lc-rs ou de `slh-dsa` changeait cette dérivation, les clés publiques recalculées ne correspondraient plus aux paramètres signés et chaque déverrouillage échouerait en `Signature` (`account.rs`, `open_keyset`). Il manque aussi un vecteur de génération de signature SLH-DSA (seule la vérification est testée). Correction : ajouter les groupes ACVP `ML-DSA-keyGen-FIPS204` (ML-DSA-87) et `SLH-DSA-keyGen-FIPS205` et `SLH-DSA-sigGen-FIPS205` (SHA2-256s, pur, déterministe) à `core/onepass-core/tests/vectors/`, comparer `from_seed` d'aws-lc à `generate_key_pair` de libcrux, et figer un compte complet (paramètres et keyset) qui doit toujours se déverrouiller.
- **F3 (info, dette).** `slh-dsa` 0.1.0 impose un prérelease de `signature` et n'efface pas ses clés ; traité par le Ruling 13 au passage à la 0.2.
- **F4 (faible, hygiène mémoire).** `sha1_hex` (`core/onepass-core/src/watchtower/pwned.rs`) laisse le condensat SHA-1 brut du mot de passe (`Digest` d'aws-lc) sur la pile sans l'effacer ; seul le hex est en `Zeroizing`. Un SHA-1 non salé d'un mot de passe est aussi utile à un attaquant que le hex. Correction : copier le condensat dans un tampon `Zeroizing` et effacer la valeur `Digest` (ou passer par un `digest::Context` dont la sortie est écrite directement dans le tampon effacé).
- **R1 (recommandation).** Ajouter `fips205` en dépendance de développement pour un second test différentiel SLH-DSA, indépendant de RustCrypto.
- **R2 (recommandation).** aws-lc-rs est utilisé hors mode FIPS. Ce n'est pas une faiblesse, mais aucune affirmation de module validé FIPS 140-3 ne doit être faite tant que la feature `fips` n'est pas activée.
