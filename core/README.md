# OnePass core

Noyau Rust de OnePass, un gestionnaire de mots de passe open source à cryptographie post-quantique. Ce dossier est le jalon 1 : crypto, modèle des items, base locale et CLI de développement. Aucune interface, aucune synchronisation.

Le modèle de menace et la construction cryptographique exacte sont décrits dans [`docs/security/README.md`](../docs/security/README.md).

## Contenu

Workspace Cargo (`core/Cargo.toml`) :

- `onepass-core` : bibliothèque (crypto, comptes, vaults, items, manifestes signés, dépôt, stockage SQLite et mémoire, TOTP, générateur, références `onepass://`).
- `onepass-cli` : binaire `onepass`, CLI de développement au-dessus de `onepass-core`.
- `onepass-guard` : approbation, journal d'audit chaîné, configuration signée, nettoyage d'affichage.
- `onepass-mcp` : serveur MCP (JSON-RPC sur stdio, outils, politique, exécution masquée).
- `onepass-ssh-agent` : agent SSH (protocole, clés, socket Unix, marque-pages).
- `onepass-bridge` : protocole du pont entre l'extension navigateur et l'app (appairage, session, correspondance d'origine, service), sans E/S.
- `onepass-native-host` : hôte natif de développement (stdio) au-dessus du pont, pour l'extension. Voir [`extension/README.md`](../extension/README.md).
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

## Pont de l'extension navigateur

Les crates `onepass-bridge` et `onepass-native-host` (jalon 4) ne modifient pas l'API de `onepass-core`. Leurs tests :

```sh
cd core
cargo test -p onepass-bridge -p onepass-native-host
cargo test -p onepass-bridge --features vectors --test vectors   # vecteurs croisés Rust/TypeScript à jour
```

La feature `vectors` ajoute des aides KEM déterministes réservées aux vecteurs de test : ne jamais l'activer dans un build livré. Le protocole et son modèle de menace sont décrits dans la section "Extension navigateur" de [`docs/security/README.md`](../docs/security/README.md).

## Fuzzing

Dix-neuf cibles, chacune exige seulement l'absence de panique. Elles visent ce qu'un stockage hostile, un fichier d'import ou d'archive hostile, un serveur de réponses hostile, un client MCP ou un client de l'agent SSH hostile atteint avant toute authentification :

| Cible | Entrée |
| --- | --- |
| `blob_open` | octets arbitraires passés à `open`, avec une clé fixe, bruts, derrière un en-tête valide, puis en mutation d'un blob valide |
| `signed_manifest` | enregistrement de manifeste : `SignedManifest::decode`, puis vérification de la signature avec une clé fixe |
| `account_params` | enregistrement de paramètres de compte : `AccountParams::decode`, puis `Account::unlock` jusqu'à la vérification de la signature d'identité (des octets aléatoires ne la passent jamais : le plancher, le plafond et Argon2 ne sont pas atteints) |
| `item_record` | enregistrement d'item : `split_item_record`, `ItemRecord::decode`, hash et confrontation à un manifeste |
| `signature_verify` | `HybridVerifyingKey::verify` et `IdentityVerifyingKey::verify` sur des clés et signatures arbitraires, encodées (postcard) et aux longueurs exactes |
| `otpauth_parse` | texte UTF-8 passé à `parse_otpauth` |
| `reference_parse` | texte UTF-8 passé à `parse_ref` |
| `import_csv` | le premier octet choisit l'un des treize formats CSV (dont LastPass, Dashlane, NordPass, Keeper, RoboForm, et le zip Dashlane), le reste est l'entrée de `import::parse` |
| `import_1pux` | `import::parse(OnePasswordPux, ..)` (zip) et `detect` |
| `import_bitwarden_json` | `import::parse(BitwardenJson, ..)` et `detect` |
| `import_enpass_json` | `import::parse(EnpassJson, ..)` et `detect` |
| `import_keepass_xml` | `import::parse(KeePassXml, ..)` et `detect` |
| `import_cxf` | `import::parse(CredentialExchange, ..)` et `detect` |
| `import_text` | le premier octet choisit `OtpAuthUris`, `WifiQr` (avec `parse_wifi_qr`), `parse_hardware_ports` ou `parse_preferred_networks` |
| `archive_open` | octets arbitraires, puis mutation d'une sauvegarde valide : `archive::inspect`, `open` par phrase de passe et `open` par compte (compte fixe créé une fois, paramètres Argon2id du plancher dev) |
| `hibp_range` | `watchtower::parse_range` sur une réponse de plage HIBP |
| `site_directory` | le premier octet choisit 2fa.directory, passkeys ou le catalogue HIBP des fuites |
| `mcp_line` | ligne JSON-RPC passée à `onepass_mcp::handle_line` avec un hôte factice sans coffre, sur une session neuve puis sur une session initialisée |
| `ssh_agent_frame` | message de l'agent SSH passé à `decode_request`, puis l'entrée découpée en clé publique, message et signature pour `verify_signature` |

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
- Variables de développement du jalon 7, acceptées seulement dans un build avec assertions de debug : `ONEPASS_DEV_AUTO_APPROVE=once|session|deny` (approbateur à réponse fixe, pour les tests de bout en bout ; refusé dans un build release), `ONEPASS_DEV_NO_TTY=1` (se comporte comme s'il n'y avait pas de terminal), `ONEPASS_DEV_SSH_PASSPHRASE` (phrase de passe d'une clé importée par `ssh-key import`, lue seulement avec `ONEPASS_DEV_ALLOW_ENV_PASSWORD=1`).
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

## Serveur MCP

`onepass mcp` lance un serveur MCP local (JSON-RPC 2.0 sur stdio, un message JSON par ligne) qui laisse un agent IA utiliser des vaults sans voir les secrets. Versions du protocole acceptées : `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`. Une ligne de plus de 1 MiB est ignorée (`-32700`).

```sh
onepass vault create "Agents" --mcp-access      # seuls les vaults créés ainsi existent pour le serveur
onepass mcp                                     # serveur, mot de passe demandé sur /dev/tty
onepass mcp --vault Agents --vault Outils --scopes metadata,use   # --vault se répète
onepass mcp policy show
onepass mcp policy set --vault Agents --scopes metadata,use,totp --allow-generate true
onepass mcp audit [--verify]
onepass mcp audit --rotate                      # archive un journal inutilisable, en ouvre un neuf
```

### Outils et scopes

| Scope | Outils | Approbation |
| --- | --- | --- |
| `metadata` | `list_vaults`, `list_items`, `search_items` (50 résultats au plus), `get_item` | aucune : jamais de valeur, de notes ni de sous-titre |
| `use` | `run_with_secrets`, `fill_template` | à chaque requête ; le code suivi de ` s` (5 min), ` s15` ou ` s60` mémorise la même requête exacte pour cette durée |
| `write` | `create_login` | à chaque requête |
| `totp` | `totp_code` | à chaque appel, jamais mémorisée |
| `reveal` | `reveal_secret` | à chaque appel, jamais mémorisée |
| `allow_generate` (global) | `generate_password` | aucune : la valeur n'existe pas dans le coffre |

Un item avec `reprompt` exige une approbation à chaque usage. Les items à la corbeille n'existent pas pour le serveur.

### Politique

- Trois couches, un accès doit passer les trois : le vault (`mcp_access`), la politique signée `<data-dir>/mcp-policy.json`, puis les options de lancement `--vault` et `--scopes`, qui ne peuvent que restreindre.
- Sans fichier, la politique par défaut vaut pour chaque vault MCP : `metadata` et `use`, `allow_generate` vrai. Supprimer le fichier rétablit donc ces valeurs par défaut, et un processus du même utilisateur peut remettre une ancienne politique authentique (une autorisation plus large retirée depuis) : la signature ne protège pas contre ce retour en arrière. L'approbation de chaque requête secrète reste exigée dans tous les cas.
- La politique est signée par la clé du compte. Un fichier altéré ou d'un autre compte empêche le serveur de démarrer (code 3). `policy set` demande le mot de passe maître et re-signe. Un serveur en cours garde sa politique : les changements s'appliquent au démarrage suivant.
- `--vault` (répétable, un vault par occurrence) rend les autres vaults invisibles : ni listés, ni résolus, et un vault ou un item hors d'atteinte répond exactement comme un introuvable (pas d'oracle d'existence).
- Ordre des contrôles : arguments, visibilité (vault MCP, hors corbeille), scope, approbation, action. L'approbateur n'est jamais appelé pour une requête que la politique refuse.
- Les drapeaux `--mcp-access` et `--travel-safe` se fixent à la création du vault (`onepass vault create`) et ne se modifient pas au jalon 7. Pour exposer un vault existant, créez un vault MCP et déplacez-y les items.
- Un échec d'intégrité du noyau met le vault en quarantaine pour la session : réponse générique (`stored data failed verification`), journalisée, et les requêtes suivantes sur ce vault restent refusées.

### Exécution masquée

`run_with_secrets` lance `argv` directement (pas de shell implicite), sans entrée standard, avec l'environnement du serveur moins les variables `ONEPASS_*`, délai de 60 s par défaut (600 s au plus). Stdout et stderr sont tronqués à 64 KiB et chaque valeur secrète de 4 caractères ou plus est remplacée par `<concealed:NOM>`, ainsi que ses formes base64 (standard et URL) et hexadécimale.

**Le masquage réduit un risque, il ne garantit rien** : une commande approuvée peut transformer ou exfiltrer un secret (`rev`, envoi réseau). La vraie barrière est l'approbation, qui affiche la commande exacte. Un accord pour la session lie le texte de `argv`, pas le contenu d'un script : `sh deploy.sh` reste accordé si le contenu de `deploy.sh` change ensuite. Toute donnée du coffre revient sous la clé `untrusted_vault_data`, avec la mention que c'est une donnée et non une instruction.

### Approbation sur le terminal

L'approbation s'affiche sur `/dev/tty`, le terminal partagé avec le client qui a lancé le serveur. Le terminal n'est ouvert que le temps d'une question : l'entrée en attente est vidée, la demande s'affiche avec un code de 2 lettres tiré au hasard (alphabet sans `i`, `l` ni `o`), puis une ligne est lue avec un délai de 60 s. Taper le code autorise une fois ; le code suivi de ` s` (par exemple `kq s`) autorise la même requête pendant 5 minutes, ` s15` pendant 15 minutes et ` s60` pendant 60 minutes (le plafond) quand c'est permis ; toute autre réponse, le délai dépassé ou une erreur refusent. Entre deux questions, aucune lecture n'est en cours : les frappes vont au client.

Limites de débit et de fatigue (par client, en mémoire du serveur) : 6 invites par minute, 30 requêtes à secret par minute pour MCP et 60 signatures par minute pour SSH, puis 3 refus d'affilée bloquent le client 10 minutes. Ces seuils se règlent par variables d'environnement, seulement dans le sens le plus strict (une valeur plus permissive est ramenée au seuil par défaut, une valeur qui n'est pas un entier positif est une erreur) : `ONEPASS_LIMIT_PROMPTS_PER_MIN`, `ONEPASS_LIMIT_SECRETS_PER_MIN`, `ONEPASS_LIMIT_DENIALS` (valeurs plus basses) et `ONEPASS_LIMIT_COOLDOWN_SECS` (valeur plus longue, 24 h au plus). Une requête identique à une invite en attente attend son résultat : un refus ou une autorisation de quelques minutes lui est appliqué sans nouvelle invite (journalisé `joined`), une autorisation pour une fois ne vaut que pour la première requête et la suivante est de nouveau soumise.

### Déverrouillage et inscription dans un client

Le protocole occupe stdin et stdout : le mot de passe est lu sur `/dev/tty`. Un client MCP de bureau qui lance le serveur sans terminal ne peut donc pas le déverrouiller en mode développement ; l'app Mac (jalon 2) lèvera cette limite. OnePass n'inscrit jamais le serveur dans la configuration d'un client. Exemple à adapter vous-même (non appliqué, le chemin et le dossier de données sont à remplacer) :

```json
{
  "mcpServers": {
    "onepass": {
      "command": "/chemin/vers/onepass",
      "args": ["--data-dir", "/chemin/vers/dossier", "mcp", "--vault", "Agents"]
    }
  }
}
```

### Journal d'audit

`<data-dir>/audit.log` (JSON lignes, `0600`) et sa tête signée `audit.log.head` sont partagés par le serveur MCP et l'agent SSH. Pas de titre ni de valeur, seulement des ids opaques. `onepass mcp audit` vérifie toujours la chaîne et la tête (`--verify` n'affiche que le verdict) puis traduit les ids après déverrouillage. Une entrée modifiée, insérée, supprimée ou une troncature sont détectées. Limites : une seule dernière ligne non scellée est tolérée (reste d'un plantage), donc un attaquant qui peut écrire le fichier peut ajouter une entrée finale forgée qui ressemble à ce reste ; et remettre un ancien journal avec son ancienne tête authentique n'est pas détecté.

Le journal se ferme en cas de doute pour les secrets : avant chaque outil secret (`run_with_secrets`, `fill_template`, `create_login`, `totp_code`, `reveal_secret`) et chaque signature SSH, le serveur vérifie, sans rien écrire, que le journal peut être prolongé (dernière ligne cohérente avec la tête signée). Sinon l'action est refusée (`audit log unusable; run onepass mcp audit --rotate` côté MCP, `FAILURE` côté SSH). Si l'écriture échoue après une action déjà faite, le résultat est rendu et l'échec part sur stderr. Les outils de métadonnées ne bloquent pas sur le journal (aucun secret en jeu). `onepass mcp audit --rotate` renomme `audit.log` et sa tête en `audit.log.<date UTC>.bad` et `audit.log.<date UTC>.bad.head`, puis ouvre un journal vide ; c'est aussi la seule réparation d'une dernière ligne coupée.

## Agent SSH

```sh
onepass ssh-key generate --title "Github" --type ed25519 --host github.com --agent
onepass ssh-key import ~/cle_de_test --title "Serveur" --agent --confirm-each-use
onepass ssh-key public Github
onepass ssh-key bookmark add Github "*.example.com"
onepass ssh-key config --out ~/.onepass-ssh
onepass ssh-agent [--socket <chemin>] [--allow-forwarded] [--known-hosts <fichier>]
```

- `ssh-agent` tourne au premier plan, demande le mot de passe sur `/dev/tty`, parle le protocole ssh-agent sur un socket Unix (défaut `<data-dir>/ssh-agent.sock`, dossier `0700`, socket `0600`) et affiche `SSH_AUTH_SOCK=<chemin>` sur stderr. `SIGINT` et `SIGTERM` retirent le socket. Pour l'utiliser : `export SSH_AUTH_SOCK=<chemin>`. Un socket existant n'est remplacé que s'il ne répond plus (reste d'un agent arrêté) ; si un agent y répond, le démarrage est refusé.
- Il sert les items SSH Key dont `use_in_agent` vaut oui, hors corbeille et hors archives, relus à chaque demande. Types : `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-3072`, `rsa-4096` (génération). Signatures RSA : `rsa-sha2-256` et `rsa-sha2-512` seulement, SHA-1 (`ssh-rsa`) refusé. RSA 2048 est refusé à la génération (3072 minimum) mais accepté à l'import.
- Import : OpenSSH (non chiffré, ou chiffré par AES en CTR, CBC ou GCM avec bcrypt-pbkdf) et PEM PKCS#8, PKCS#1 ou SEC1 non chiffrés. La phrase de passe est demandée sur le terminal et jamais conservée ; la clé est stockée non chiffrée dans le vault (le vault la chiffre). Non pris en charge : clés OpenSSH chiffrées en `chacha20-poly1305@openssh.com`, PEM chiffré.
- Chaque signature passe par une approbation affichant le titre et l'empreinte SHA-256 de la clé, le processus demandeur (pid et exécutable), la destination si la connexion est liée, le transfert oui/non, et l'espace de noms pour une signature `SSHSIG` (`git`, `file`...). Le code suivi de ` s` (5 min), ` s15` ou ` s60` mémorise l'accord pour le couple (clé, exécutable) pendant cette durée, 1 h au plus, ou jusqu'à `LOCK` ou l'arrêt ; `--confirm-each-use` l'interdit pour la clé. Un pair d'un autre utilisateur, ou dont le système ne donne pas l'uid, est refusé.
- Le transfert d'agent est refusé par défaut ; `--allow-forwarded` l'autorise avec une approbation à chaque signature.
- L'extension `session-bind@openssh.com` est vérifiée (signature de l'hôte sur l'identifiant de session) ; une signature fausse ferme la connexion. `ADD_IDENTITY`, `REMOVE_IDENTITY` et variantes répondent `FAILURE` : les clés viennent du coffre. `LOCK`/`UNLOCK` verrouillent l'agent. Messages de 256 KiB au plus ; toute erreur de décodage ferme la connexion.
- Marque-pages : le champ `hosts` de l'item (un nom d'hôte ou un motif `Host` d'OpenSSH). `ssh-key config --out <dossier>` écrit `<dossier>/config` (`Host`, `IdentityFile`, `IdentitiesOnly yes`, `IdentityAgent`) et les clés publiques, puis affiche la ligne `Include` à ajouter. **La commande ne touche jamais à `~/.ssh/config`** : vous ajoutez la ligne vous-même. Dans l'approbation, un hôte lié qui correspond à un marque-page (via `known_hosts`, y compris hachés, lu en lecture seule) est signalé, et une destination hors marque-pages donne un avertissement. Les marque-pages guident, ils ne bloquent pas.

## Travel Mode

Les vaults sans `travel_safe` quittent l'appareil et reviennent vérifiés. Le dépôt amont est un fichier SQLite explicite qui tient lieu de CloudKit (jalon 2).

```sh
onepass vault create "Voyage" --travel-safe
onepass travel push   --upstream amont.db   # copie tous les enregistrements, ne supprime rien en amont
onepass travel on     --upstream amont.db   # exige que l'amont contienne octet pour octet les vaults à cacher
onepass travel status                       # mode actif ou non, nombre de vaults cachés
onepass travel off    --upstream amont.db [--accept-unpinned]
```

- `on` vérifie chaque vault, contrôle l'amont avant toute suppression (la seule copie n'est jamais effacée), efface les enregistrements locaux, écrit l'état scellé dans `<data-dir>/travel.bin` (`0600`, taille fixe de 64 KiB) puis compacte la base (`VACUUM`) pour que les lignes effacées ne restent pas dans les pages libres. Si la compaction échoue, `on` indique de le relancer pour la rejouer.
- `push` ne fait qu'ajouter : l'amont garde les anciennes versions et les items supprimés. `on` n'exige que ce que la vérification locale utilise (clé, meta, manifeste et les items qu'il liste) et ignore ces restes ; `off` ne recopie que les items dont l'id et la version figurent dans le manifeste amont.
- `on`, `off` et `backup restore` refusent de tourner pendant qu'un serveur (`onepass mcp` ou `onepass ssh-agent`) est actif sur le même dossier (`a long-running onepass server (mcp or ssh-agent) is running; stop it first`) : chaque serveur tient un verrou partagé sur `<data-dir>/servers.lock`. En seconde ligne, un serveur qui voit `travel.bin` apparaître ou disparaître refuse la requête et s'arrête (code 1).
- `status` et `on` signalent un état incohérent (code 3) quand `travel.bin` est présent alors qu'un vault caché a sa clé sur l'appareil ou qu'un vault sans `travel_safe` est listé (fichier resté ou rejoué, vault créé pendant le voyage) : `onepass travel off --upstream <fichier>` vérifie et fusionne, ou supprimez `travel.bin` s'il est périmé.
- `backup restore` est refusé pendant le Travel Mode ; `backup create` prévient sur stderr que les vaults cachés ne sont pas dans la sauvegarde.
- `off` recopie les vaults depuis l'amont et les charge avec la vérification normale : un amont qui rejoue un ancien manifeste ou retire un item est refusé (code 3), l'état local est restauré et `travel.bin` reste valable. `travel.bin` n'est supprimé qu'une fois les épinglages réécrits dans `device.bin`.
- Limites : la présence de `travel.bin` révèle que le mode est actif (sa taille fixe cache le nombre de vaults). Supprimer `travel.bin` fait perdre la protection anti-rejeu à la sortie : `off` refuse alors, sauf `--accept-unpinned`, qui accepte les vaults comme jamais vus (un ancien manifeste authentique passerait). Un vault local périmé ou bifurqué (seq inférieur, ou même seq avec un autre hash) planté à la place d'un vault caché fait refuser `off` : il faut le retirer. Pendant le voyage, `audit.log` et `mcp-policy.json` nomment encore en clair les ids des vaults cachés. Les instantanés du système de fichiers et Time Machine peuvent garder d'anciennes copies de la base : hors de portée d'un logiciel.

## Limites connues du jalon 7

- Pas de Touch ID ni de déverrouillage sans terminal : l'approbation et le mot de passe passent par `/dev/tty`, le terminal partagé avec le client (jalon 2 pour l'app Mac).
- Pas de clés OpenSSH `chacha20-poly1305@openssh.com`, pas de PEM chiffré, pas de certificats SSH, pas de clés FIDO (`sk-*`), pas de `restrict-destination`.
- MCP : outils seulement (ni ressources ni prompts), stdio seulement.
- La branche Linux de lecture du pair (`SO_PEERCRED`) n'est pas compilée dans les tests locaux (macOS).
- Les drapeaux d'un vault existant ne se modifient pas.
- Le Travel Mode utilise un fichier amont de développement, pas la synchro.
- Le masquage des sorties est une réduction de risque, pas une garantie.

## Module `companion` de `onepass-core` (jalon 6)

`onepass-core/src/companion.rs` : ce qui sort du coffre pour l'Apple Watch et les widgets iOS. Spec : `docs/specs/2026-10-26-milestone-6-watch-vision-design.md`, sécurité : section 12 de [`docs/security/README.md`](../docs/security/README.md).

- `build_payload(repo, generation, now, excluded_vaults)` : items `on_watch` vivants (ni corbeille, ni archive, ni `reprompt`, hors vaults exclus), triés par titre, 50 au plus (`MAX_ENTRIES`), champs par liste fermée selon le type, valeur de plus de 1 Kio omise (`MAX_VALUE_BYTES`), carte bancaire réduite à `•••• 1234`. Jamais le mot de passe d'un Login, le CVV, le PIN, le numéro complet ni les notes.
- `seal_payload(payload, recipient)` et `open_payload(secret, sealed)` : format `"OPC1" || génération (u64 BE) || enveloppe KEM || blob`, enveloppe `wrap_key_labeled` (étiquette `onepass/companion/v1`, contexte `"watch" || SHA-256(clé publique)`), blob `BlobKind::Companion` lié à la génération et au destinataire.
- `glance_snapshot(repo, now_unix, window_secs, excluded_vaults)` : 8 favoris au plus (`MAX_GLANCE_ITEMS`) et, pour ceux qui ont un TOTP, les codes `(début, code)` de chaque période qui recoupe la fenêtre (plafonnée à 24 h, 2880 codes par item).
- `crypto/kem.rs` gagne `wrap_key_labeled` et `unwrap_key_labeled` (info HKDF `label || u32_be(len(context)) || context`) ; `wrap_key` et `unwrap_key` produisent les mêmes octets qu'avant.

Côté FFI (`onepass-ffi/src/companion.rs`) : `companion_generate_key()`, `Session::companion_payload`, `Session::glance_snapshot`, objet `CompanionVault` (`open(secret, sealed)`, `generation`, `generated_at`, `entries` sans graine, `totp(item_id, unix)`). L'XCFramework livré gagne les tranches `aarch64-apple-watchos`, `aarch64-apple-watchos-sim`, `aarch64-apple-visionos` et `aarch64-apple-visionos-sim` (cibles rustup de niveau 2) ; les montres `arm64_32` seulement ne sont pas prises en charge.

Tests : unitaires dans `companion.rs` (aller-retour, mauvaise clé, altération de chaque octet, génération authentifiée, liste fermée par type, exclusions, limites, carte à 4 chiffres, codes de l'instantané égaux à `totp::code_at`, plafond de codes) et `onepass-ffi/tests/companion.rs`. Ils tournent avec `make check`.

## Module `webauthn` et surface FFI AutoFill (jalon 3)

`onepass-core/src/webauthn.rs` (une ligne `pub mod webauthn;` dans `lib.rs`, aucune nouvelle dépendance : ECDSA P-256 et SHA-256 par `aws-lc-rs`, CBOR écrit à la main). Authentificateur WebAuthn logiciel pour les passkeys : `new_credential` (paire P-256, clé privée en PKCS#8 DER, identifiant de credential de 16 octets), `public_key_cose` (clé publique COSE ES256 en CBOR canonique), `registration` (`authenticatorData` avec AAGUID `AAGUID` et `attestationObject` de format `none`) et `assertion` (`authenticatorData` et signature ECDSA en DER de `authenticatorData` suivi du hash des données client). Flags UP, UV, BE, BS (AT à l'enregistrement), compteur toujours 0. Les entrées hors limites (`rp_id`, `user_handle`, nom d'utilisateur, hash qui ne fait pas 32 octets) et une clé qui ne se relit pas en P-256 sont refusées (`InvalidFormat`). Tests unitaires : octets du CBOR, flags, signature vérifiée par `aws_lc_rs::signature`.

Le `Repository<SyncStore>` fusionne aussi l'état de l'appareil écrit par un autre processus sur le même fichier (`persist_device_state` : plus grand `seq` par vault ; un rebase impose sa propre entrée). Test : `onepass-core/tests/sync_two_processes.rs`.

Dans `onepass-ffi`, nouveau fichier `src/autofill.rs` (ajouts seulement ; `PasskeyExcluded` en fin de `OnePassError`) :

- `Session::autofill_identities(excluded_vault_ids)` : identités des Logins vivants et non cachés de l'AutoFill (mot de passe par hôte d'URL, code à usage unique si `totp`, passkey par credential), dédoublonnées ; aucune valeur secrète.
- `Session::autofill_candidates(service, include_all, excluded_vault_ids)` : Logins qui correspondent à un domaine ou une URL, classés (même hôte, ou passkey dont le `rp_id` est cet hôte même sans URL, puis même domaine enregistrable par la Public Suffix List) ; `include_all` ajoute les autres Logins vivants non cachés comme "Autres". `http` jamais pour un domaine public, une IP ne correspond qu'à elle-même, ports ignorés.
- `Session::create_passkey(request)` : crée la passkey dans un Login existant ou un nouveau et rend l'`attestationObject` ; refuse un credential déjà listé par le site (`PasskeyExcluded`), un item archivé ou en corbeille et un nom d'utilisateur vide pour un nouveau Login.
- `Session::passkey_assertion(vault_id, item_id, credential_id, client_data_hash)` : signe dans le Rust, la clé privée ne sort jamais.
- `password_from_rules(rules, fallback)` (`src/rules.rs`) : applique le langage `passwordrules` d'Apple (longueur plafonnée à 64, repli sur la recette `fallback` pour des règles illisibles ou contradictoires).

Les types `FfiAutofill*`, `FfiPasskey*` sont dans `src/types.rs`. Dépendances `psl` 2 et `url` 2 : `onepass-ffi` seulement (`onepass-core` n'en gagne aucune). Tests : `onepass-ffi/tests/autofill.rs` et `onepass-ffi/tests/rules.rs`. Sécurité : section 14 de [`docs/security/README.md`](../docs/security/README.md).
