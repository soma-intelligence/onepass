# OnePass core

Noyau Rust de OnePass, un gestionnaire de mots de passe open source à cryptographie post-quantique. Ce dossier est le jalon 1 : crypto, modèle des items, base locale et CLI de développement. Aucune interface, aucune synchronisation.

Le modèle de menace et la construction cryptographique exacte sont décrits dans [`docs/security/README.md`](../docs/security/README.md).

## Contenu

Workspace Cargo (`core/Cargo.toml`) :

- `onepass-core` : bibliothèque (crypto, comptes, vaults, items, manifestes signés, dépôt, stockage SQLite et mémoire, TOTP, générateur, références `onepass://`).
- `onepass-cli` : binaire `onepass`, CLI de développement au-dessus de `onepass-core`.
- `fuzz` : cibles `cargo-fuzz`, crate à part, hors du workspace.

## Prérequis

- Rust via `rustup`. La version est fixée par `rust-toolchain.toml` (1.99.1, avec `clippy` et `rustfmt`) : `cargo` l'installe tout seul au premier lancement dans `core/`.
- Pour le fuzzing : la toolchain `nightly` et `cargo-fuzz` (`rustup toolchain install nightly`, `cargo install --locked cargo-fuzz`).
- Pour `make deny` et `make audit` : `cargo install --locked cargo-deny cargo-audit`.

## Build

```sh
cd core
cargo build --workspace
cargo build --release -p onepass-cli   # binaire : target/release/onepass
```

Le profil release utilise `lto`, `codegen-units = 1` et `panic = "abort"`.

## Tests

```sh
cd core
make check    # fmt --check, clippy -D warnings, cargo test --workspace, cargo deny check
make test     # tests seuls
make audit    # cargo audit (base RustSec)
```

La suite couvre :

- les vecteurs officiels NIST ACVP (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256s) et un test différentiel entre `aws-lc-rs` et `libcrux` (`tests/differential.rs`, à lancer aussi en release : `cargo test --release -p onepass-core --test differential`) ;
- des tests property-based (`proptest`) sur l'AEAD : tout bit retourné est refusé (`tests/aead_props.rs`) ;
- la dérivation de l'AUK (`tests/kdf_vectors.rs`) ;
- la suite "stockage malveillant" (`tests/malicious_store.rs`), une attaque par test ;
- les tests de la CLI (`onepass-cli/tests/cli.rs`) ;
- les formats d'import, un fichier synthétique par format (`tests/import_formats.rs`) ;
- Watchtower : contrôles, k-anonymity, catalogues et score (`tests/watchtower.rs`) ;
- l'archive OnePass : aller-retour, refus, encodage figé (`tests/archive.rs`, feature `dev-fast-kdf`) ;
- les commandes du jalon 5 de la CLI : import, export, watchtower, backup (`onepass-cli/tests/m5.rs`).

La suite "stockage malveillant" déverrouille des comptes créés avec des paramètres Argon2id rapides : elle demande la feature `dev-fast-kdf` de `onepass-core`, que `onepass-cli` active, donc `cargo test --workspace` (et `make test`) la lance. Seule : `cargo test -p onepass-core --features dev-fast-kdf --test malicious_store`. Cette feature n'abaisse le plancher Argon2id que dans un build avec assertions de debug ; un build release impose toujours le plancher de la spec.

La signature SLH-DSA est lente (environ 15 s en optimisé, plus en debug). Le profil `dev` compile donc `sha2` avec `opt-level = 3`.

## Fuzzing

Seize cibles, chacune exige seulement l'absence de panique. Elles visent ce qu'un stockage hostile, un fichier d'import ou d'archive hostile, ou un serveur de réponses hostile atteint avant toute authentification :

| Cible | Entrée |
| --- | --- |
| `blob_open` | octets arbitraires passés à `open`, avec une clé fixe, bruts, derrière un en-tête valide, puis en mutation d'un blob valide |
| `signed_manifest` | enregistrement de manifeste : `SignedManifest::decode`, puis vérification de la signature avec une clé fixe |
| `account_params` | enregistrement de paramètres de compte : `AccountParams::decode`, puis `Account::unlock` jusqu'à la vérification de la signature d'identité (des octets aléatoires ne la passent jamais : le plancher, le plafond et Argon2 ne sont pas atteints) |
| `item_record` | enregistrement d'item : `split_item_record`, `ItemRecord::decode`, hash et confrontation à un manifeste |
| `signature_verify` | `HybridVerifyingKey::verify` et `IdentityVerifyingKey::verify` sur des clés et signatures arbitraires, encodées (postcard) et aux longueurs exactes |
| `otpauth_parse` | texte UTF-8 passé à `parse_otpauth` |
| `reference_parse` | texte UTF-8 passé à `parse_ref` |
| `import_csv` | le premier octet choisit l'un des neuf formats CSV (dont LastPass et Dashlane, et le zip Dashlane), le reste est l'entrée de `import::parse` |
| `import_1pux` | `import::parse(OnePasswordPux, ..)` (zip) et `detect` |
| `import_bitwarden_json` | `import::parse(BitwardenJson, ..)` et `detect` |
| `import_keepass_xml` | `import::parse(KeePassXml, ..)` et `detect` |
| `import_cxf` | `import::parse(CredentialExchange, ..)` et `detect` |
| `import_text` | le premier octet choisit `OtpAuthUris`, `WifiQr` (avec `parse_wifi_qr`), `parse_hardware_ports` ou `parse_preferred_networks` |
| `archive_open` | octets arbitraires, puis mutation d'une sauvegarde valide : `archive::inspect`, `open` par phrase de passe et `open` par compte (compte fixe créé une fois, paramètres Argon2id du plancher dev) |
| `hibp_range` | `watchtower::parse_range` sur une réponse de plage HIBP |
| `site_directory` | le premier octet choisit 2fa.directory, passkeys ou le catalogue HIBP des fuites |

```sh
cd core
make fuzz                      # 60 s par cible
make fuzz FUZZ_SECONDS=300     # durée au choix
cargo +nightly fuzz run blob_open -- -max_total_time=60
cargo +nightly fuzz run archive_open -- -max_total_time=60 -rss_limit_mb=4096
```

`archive_open` est lente (quelques centaines d'exécutions par seconde : Argon2id sur des paramètres mutés) et peut dépasser la limite mémoire par défaut de libFuzzer : passez `-rss_limit_mb=4096` (la CI le fait pour toutes les cibles).

`archive_open` demande la feature `dev-fast-kdf` de `onepass-core` (activée dans `fuzz/Cargo.toml`) pour créer son compte fixe en quelques secondes. Elle ne joue que dans un build avec assertions de debug : `cargo fuzz` en active par défaut (`-a`), ne passez donc pas `-O` pour cette cible, sinon le plancher de production s'applique et la cible échoue à son initialisation.

Le fuzzing demande la toolchain `nightly` : la toolchain épinglée ne le supporte pas. Le corpus et les plantages restent dans `fuzz/corpus` et `fuzz/artifacts`, ignorés par git.

## CI

`.github/workflows/core.yml` : sur `macos-latest` et `ubuntu-latest`, formatage, `clippy`, tests, test différentiel en release, `cargo deny check` et `cargo audit`. `cargo audit` est informatif (`continue-on-error`) : une nouvelle alerte RustSec peut le faire échouer sans aucun changement de code, il ne doit pas bloquer une fusion. Un job séparé fuzze chaque cible 30 s.

## CLI de développement

```sh
cargo run -p onepass-cli -- --help
onepass account create
onepass vault list
onepass vault create "Travail"
onepass item create login --title "Exemple" --field username=alice --field password=...
onepass item list
onepass item get "Exemple" --reveal
onepass read "onepass://Personnel/Exemple/password"
onepass totp "Exemple"
onepass generate --words 5
```

### Jalon 5 : import, export, Watchtower, sauvegarde

```sh
# Import : le format est détecté (ou forcé avec --format) ; --dry-run n'écrit rien
onepass import export.1pux --dry-run
onepass import bitwarden.json --vault Personnel
onepass import --wifi-keychain          # réseaux Wi-Fi du trousseau (macOS)

# Export : archive chiffrée par phrase de passe, ou CSV en clair (refusé sans --plaintext)
onepass export --out coffre.onepass --generate-passphrase
onepass export --out coffre.csv --format csv --plaintext

# Watchtower : analyse du coffre (mots de passe faibles, réutilisés, fuites, 2FA, passkeys)
onepass watchtower
onepass watchtower --offline --hibp-dir ./pwned --sites 2fa.json --passkeys passkeys.json --breaches breaches.json

# Sauvegarde signée du compte, restauration des items manquants, lecture de l'en-tête
onepass backup create --out sauvegarde.onepass --passphrase
onepass backup restore sauvegarde.onepass
onepass backup inspect sauvegarde.onepass
```

Les fichiers créés (`export`, `backup create`) le sont en mode `0600`, jamais par-dessus un fichier existant. `watchtower` n'envoie que les 5 premiers caractères hexadécimaux du SHA-1 de chaque mot de passe (voir `docs/security/README.md`) ; `--offline` n'exécute aucune commande réseau.

Références `onepass://` (commande `read`) : sans section, un nom de champ qui désigne plusieurs champs de l'item est refusé (`ambiguous field, add the section`) plutôt que de livrer le premier à un script ; `totp` désigne l'unique champ OTP rempli de l'item (`onepass totp` choisit le même) ; un secret OTP nu est décodé en base32 tel quel, jamais recopié dans une URI.

Si la sortie standard est fermée par son lecteur (`onepass read ... | head -c1`), la commande s'arrête sans message avec le code 0, sans panique. Seule une écriture sur la sortie standard est traitée ainsi : toute autre erreur d'entrée-sortie reste une erreur. Exception : `account create` échoue (code 1, message sur stderr) s'il ne peut pas afficher la Secret Key, et supprime le compte qu'il venait de créer, pour ne jamais laisser un compte dont personne n'a vu la clé.

Options globales : `--data-dir <dossier>` (défaut `~/.onepass-dev`) et `--json`. Codes de sortie : 0 succès, 1 erreur d'usage, 2 mauvais mot de passe, 3 échec d'intégrité (données stockées altérées), 4 introuvable, 5 écriture concurrente (`concurrent write, retry` : rien n'a été enregistré, relancez la commande).

Chaque commande qui ouvre le dossier de données prend un verrou exclusif sur `<data-dir>/lock` (droits `0600`) de la première lecture de `device.bin` jusqu'à l'enregistrement de l'état, lectures comprises. Le mot de passe est demandé avant de prendre le verrou : une invite en attente ne bloque pas les autres commandes : deux commandes lancées en parallèle s'exécutent l'une après l'autre. Le code 5 ne sort donc que si un autre programme écrit dans la base sans ce verrou ; le noyau refuse alors l'écriture perdante au lieu de perdre un item en silence.

### Mode développement : limites

Au jalon 1 la CLI fonctionne en **mode développement autonome**. C'est un écart assumé avec la section 9.1 de la spec, où la CLI passe par l'app Mac et Touch ID (jalon 2).

- La Secret Key est écrite **en clair** dans `<data-dir>/device.bin` (droits `0600`, dossier en `0700`). Quiconque lit ce fichier et connaît le mot de passe maître déverrouille le compte, et la Secret Key ne protège plus contre une fuite du mot de passe.
- Chaque commande qui touche au dossier de données affiche la bannière `DEV MODE` sur stderr.
- Le mot de passe est lu sur le terminal, masqué. Il n'existe pas de mode non interactif réel. Pour les tests seulement, `ONEPASS_DEV_ALLOW_ENV_PASSWORD=1` autorise `ONEPASS_PASSWORD`, et `ONEPASS_DEV_FAST_KDF=1` abaisse le coût d'Argon2id (refusé dans un build release).
- Pas de verrouillage automatique, pas de biométrie, pas de synchronisation, pas de `mlock` des pages secrètes.
- Ne mettez pas de vrais secrets dans un compte de développement.

## Crate `onepass-ffi` (jalon 2)

Interface UniFFI du noyau pour les apps Apple (`apple/`), membre du workspace. UniFFI `=0.32.2` en proc-macros, sans fichier UDL. La crate se compile en `staticlib` pour `aarch64-apple-ios`, `aarch64-apple-ios-sim` et `aarch64-apple-darwin`, assemblée en XCFramework par `make -C apple core` (`apple/scripts/build-core.sh`), qui génère aussi les liaisons Swift :

```sh
cd core
cargo test -p onepass-ffi
cargo run -p onepass-ffi --features bindgen --bin uniffi-bindgen -- --help
```

- Fonctions libres : `create_account` (refuse un magasin qui contient déjà un compte, et un magasin dont l'appareil a épinglé un compte disparu : `Integrity { kind: "account_missing" }`), `create_account_with_kdf` (paramètres Argon2id explicites ; sous le plancher, refusé sauf build debug avec `dev-fast-kdf`), `unlock_with_password` (rend la session et l'AUK, pour l'enrôlement biométrique), `verify_password` (vérifie mot de passe et Secret Key et rend l'AUK sans ouvrir de session ni écrire l'état de l'appareil : pour les vérifications jetables, redemande de mot de passe et enrôlement biométrique), `unlock_with_auk`, `has_account`, `store_state` (`Empty`, `Account` ou `PinnedButMissing` : l'appareil a épinglé un compte dont les enregistrements ont disparu, une faute d'intégrité et jamais un magasin vide), `reset_store` (vide toutes les tables en une transaction sans supprimer le fichier, pour annuler une création de compte pendant que d'autres connexions restent ouvertes), `open_sync_store`, `normalize_secret_key`, `generate_password`, `password_entropy_bits`, `totp_now`, `item_types`, `template`, `menu_options`, `card_brand`, `validate_item`.
- Objet `Session` (thread-safe, `Mutex` interne) : vaults (`vaults`, `create_vault`, `update_vault`), items (`item_summaries` sans aucune valeur secrète, `item`, `new_item`, `save_item` qui valide d'abord et tient l'historique des mots de passe, corbeille, archive, favori, déplacement, suppression, `purge_trash`, `password_history`), `rebase_all`, `lock` (clés effacées par `zeroize`, tout appel suivant rend `Locked`).
- Objet `SyncStoreHandle`, ouvrable sans déverrouiller : `pending_changes`, `mark_pushed`, `stage_remote`, `commit_remote`, `server_meta`, `meta` et `set_meta`, `begin_full_fetch`, `begin_zone_reset`, `finish_full_fetch`, `has_account`, `store_state`. La récupération et l'envoi tournent donc appareil verrouillé ; seul le rebase demande une session. Il ne peut pas toucher à l'état de l'appareil (`DeviceState`). Il écrit des lignes `pending` dans un seul cas : `finish_full_fetch` après une réinitialisation de zone remet en file les lignes perdues par le serveur. Le rebase lit ses lignes `pending` avant d'ouvrir sa transaction : il ne doit donc jamais tourner en même temps qu'une telle réconciliation. Le coordinateur Swift le garantit en sérialisant les tours de sync (un seul à la fois, le rebase dans le tour).
- Identifiants en hexadécimal de 32 caractères, dates en secondes Unix ou `{year, month, day}`.
- Erreurs : `OnePassError` (`WrongPassword`, `NotFound`, `Conflict`, `Validation { field, reason }`, `Integrity { kind }`, `InvalidInput { what }`, `Store`, `Crypto`, `Locked`). Aucune ne contient de valeur de champ ; les erreurs SQLite ne portent que leur code.
- Feature `bindgen` : le générateur de liaisons (`uniffi/cli`), seulement à la construction (voir l'entrée `advisories.ignore` de `deny.toml`). Feature `dev-fast-kdf` : abaisse le plancher Argon2id dans un build debug, pour les tests Rust et l'XCFramework de test des apps (`make -C apple core-test`), jamais pour un build livré.

Tests (`onepass-ffi/tests/ffi.rs`) : création puis déverrouillage par mot de passe et par AUK, accents composés et décomposés, refus d'un compte existant et d'un KDF sous le plancher, aller-retour des 26 types, historique des mots de passe, erreurs de validation qui nomment le champ sans sa valeur, Document sans fichier, cycle de vie des items, résumés sans secret, session verrouillée, sync par `SyncStoreHandle` verrouillé et réinitialisation de zone.

## Module `sync` de `onepass-core` (jalon 2)

`onepass-core/src/sync/` : synchronisation "hors ligne d'abord". Le `Repository` reste synchrone et ignore le réseau ; il travaille sur `SyncStore`, un magasin SQLite à couches qui implémente `RecordStore`. Le transport (CloudKit) vit côté Swift.

Tables (un seul fichier, transactions) :

| Table | Rôle |
| --- | --- |
| `base` | dernier état connu du serveur, avec `server_meta` (champs système CloudKit encodés par Swift, opaques pour le Rust) |
| `pending` | écritures locales pas encore confirmées ; `data NULL` est une suppression |
| `staging` | changements reçus pendant une récupération, appliqués d'un coup |
| `ancestor` | pour un manifeste en attente, la version `base` sur laquelle il s'appuyait |
| `meta` | état de l'appareil, jeton de changement, mode de récupération |

Lecture : `pending` masque `base`. Écriture : toujours dans `pending` ; `put_if_version` compare à la version effective. Un enregistrement de plus de 900 Kio (`MAX_RECORD_BYTES`) est refusé.

Opérations :

1. `pending_changes` : les écritures à envoyer, items avant le manifeste de leur vault, suppressions après. Un vault dont le `base` a avancé depuis l'écriture locale est **retenu** (`vaults_needing_rebase`) : il n'envoie rien, ni items ni manifeste.
2. `mark_pushed` : la version confirmée passe de `pending` à `base`.
3. `stage_remote` puis `commit_remote` : les changements reçus entrent dans `base` en une transaction à la fin de la récupération, pour qu'un manifeste n'apparaisse jamais sans ses items. `commit_remote` tourne à chaque fin de récupération complète. Il ignore les suppressions que le serveur n'a pas le droit de faire (aucun client ne les fait en M2) : paramètres de compte, keyset, et clé, méta ou manifeste d'un vault présent dans `last_seen` de l'appareil. Le stockage n'est pas fiable : il ne peut ni effacer le compte ni faire oublier un vault déjà lu.
4. `Repository::rebase` (déverrouillé) : par vault retenu, vérifie le manifeste du serveur contre l'ancêtre, recalcule les intentions locales par différence, les rejoue par `save_item` ou `delete_item`, dans une transaction par vault. Le plus récent `updated_at` gagne, égalité tranchée par l'ordre des octets du hash. Un vault en échec n'empêche pas les autres.
5. `begin_full_fetch`, `begin_zone_reset`, `finish_full_fetch` : récupération depuis zéro (jeton expiré, "Réessayer" après un refus d'intégrité) et réinitialisation de zone. Dans les deux modes, seul un item absent du serveur dans un vault dont le serveur a rendu le manifeste est supprimé de `base`. Une récupération ordinaire ne supprime rien d'autre : ni les genres stables (compte, keyset, clés et métas de vault), ni les manifestes, ni les items d'un vault que le serveur n'a pas rendu ; une zone vide ne peut donc pas effacer la copie locale. Après une réinitialisation, ces lignes absentes du serveur repartent dans `pending`, sans jamais toucher une écriture en attente.
6. `account_state` : `Empty`, `Present` ou `PinnedButMissing` (compte épinglé par l'appareil mais disparu du magasin). `reset` : vide toutes les tables en une transaction.

Tests : `onepass-core/tests/sync_two_devices.rs`, deux appareils et un faux serveur sans réseau (écritures dans les deux sens, items différents ou identiques modifiés en même temps, suppression contre modification, vault retenu qui n'envoie rien, rejeu d'un vieux manifeste, item retenu par le serveur, coupures entre l'envoi et la confirmation, appareil longtemps hors ligne, déplacement contre modification, suppressions forgées du compte et d'un vault déjà lu, zone vide ou vault caché lors d'une récupération depuis zéro), plus les tests unitaires de `sync/store.rs` et `sync/rebase.rs`. Ils tournent avec `cargo test --workspace`.

Les règles de sécurité de la sync (ce que voit le serveur, rebase, réinitialisation de zone) sont dans la section 7 de [`docs/security/README.md`](../docs/security/README.md).
