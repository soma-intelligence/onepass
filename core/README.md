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
- les tests de la CLI (`onepass-cli/tests/cli.rs`).

La suite "stockage malveillant" déverrouille des comptes créés avec des paramètres Argon2id rapides : elle demande la feature `dev-fast-kdf` de `onepass-core`, que `onepass-cli` active, donc `cargo test --workspace` (et `make test`) la lance. Seule : `cargo test -p onepass-core --features dev-fast-kdf --test malicious_store`. Cette feature n'abaisse le plancher Argon2id que dans un build avec assertions de debug ; un build release impose toujours le plancher de la spec.

La signature SLH-DSA est lente (environ 15 s en optimisé, plus en debug). Le profil `dev` compile donc `sha2` avec `opt-level = 3`.

## Fuzzing

Quatre cibles, chacune exige seulement l'absence de panique :

| Cible | Entrée |
| --- | --- |
| `blob_open` | octets arbitraires passés à `open`, avec une clé fixe, bruts puis derrière un en-tête valide |
| `manifest_decode` | octets arbitraires décodés en `Manifest` (postcard) |
| `otpauth_parse` | texte UTF-8 passé à `parse_otpauth` |
| `reference_parse` | texte UTF-8 passé à `parse_ref` |

```sh
cd core
make fuzz                      # 60 s par cible
make fuzz FUZZ_SECONDS=300     # durée au choix
cargo +nightly fuzz run blob_open -- -max_total_time=60
```

Le fuzzing demande la toolchain `nightly` : la toolchain épinglée ne le supporte pas. Le corpus et les plantages restent dans `fuzz/corpus` et `fuzz/artifacts`, ignorés par git.

## CI

`.github/workflows/core.yml` : sur `macos-latest` et `ubuntu-latest`, formatage, `clippy`, tests, test différentiel en release, `cargo deny check` et `cargo audit`. Un job séparé fuzze chaque cible 30 s.

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

Références `onepass://` (commande `read`) : sans section, un nom de champ qui désigne plusieurs champs de l'item est refusé (`ambiguous field, add the section`) plutôt que de livrer le premier à un script ; `totp` désigne l'unique champ OTP rempli de l'item (`onepass totp` choisit le même) ; un secret OTP nu est décodé en base32 tel quel, jamais recopié dans une URI.

Si la sortie standard est fermée par son lecteur (`onepass read ... | head -c1`), la commande s'arrête sans message avec le code 0, sans panique.

Options globales : `--data-dir <dossier>` (défaut `~/.onepass-dev`) et `--json`. Codes de sortie : 0 succès, 1 erreur d'usage, 2 mauvais mot de passe, 3 échec d'intégrité (données stockées altérées), 4 introuvable, 5 écriture concurrente (`concurrent write, retry` : rien n'a été enregistré, relancez la commande).

Chaque commande qui ouvre le dossier de données prend un verrou exclusif sur `<data-dir>/lock` (droits `0600`) pendant toute son exécution, lectures comprises : deux commandes lancées en parallèle s'exécutent l'une après l'autre. Le code 5 ne sort donc que si un autre programme écrit dans la base sans ce verrou ; le noyau refuse alors l'écriture perdante au lieu de perdre un item en silence.

### Mode développement : limites

Au jalon 1 la CLI fonctionne en **mode développement autonome**. C'est un écart assumé avec la section 9.1 de la spec, où la CLI passe par l'app Mac et Touch ID (jalon 2).

- La Secret Key est écrite **en clair** dans `<data-dir>/device.bin` (droits `0600`, dossier en `0700`). Quiconque lit ce fichier et connaît le mot de passe maître déverrouille le compte, et la Secret Key ne protège plus contre une fuite du mot de passe.
- Chaque commande qui touche au dossier de données affiche la bannière `DEV MODE` sur stderr.
- Le mot de passe est lu sur le terminal, masqué. Il n'existe pas de mode non interactif réel. Pour les tests seulement, `ONEPASS_DEV_ALLOW_ENV_PASSWORD=1` autorise `ONEPASS_PASSWORD`, et `ONEPASS_DEV_FAST_KDF=1` abaisse le coût d'Argon2id (refusé dans un build release).
- Pas de verrouillage automatique, pas de biométrie, pas de synchronisation, pas de `mlock` des pages secrètes.
- Ne mettez pas de vrais secrets dans un compte de développement.
