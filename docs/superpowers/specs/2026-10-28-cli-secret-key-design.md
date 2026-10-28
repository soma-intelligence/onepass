# CLI : Secret Key hors de `device.bin`, plancher KDF de développement sur demande

Date : 2026-10-28
Statut : validée (auto-validation, rulings ci-dessous)
Branche : `fix/cli-secret-key`, créée depuis la `main` privée (889284d).
Origine : constat F2 (moyen) de l'audit du 2026-10-28.

## 1. Constat

1. La CLI (seule surface sous Linux, hôte du serveur MCP et de l'agent SSH de la CLI) écrit la Secret Key en clair dans `<data-dir>/device.bin` (`session.rs`, `DeviceFile`). Qui lit ce fichier (sauvegarde, Time Machine, dossier synchronisé, logiciel malveillant) n'a plus besoin que du mot de passe : la garantie à deux secrets disparaît.
2. `onepass-cli/Cargo.toml` active toujours la feature `dev-fast-kdf` de `onepass-core` : un build debug de la CLI accepte le plancher Argon2id de développement (8 Mio, t = 1).

## 2. Objectif et critères de réussite

- Un compte créé par la CLI n'écrit jamais sa Secret Key dans `device.bin` : elle va dans le magasin de secrets du système, sous une entrée nommée par l'id du compte. Test : les octets de `device.bin` ne contiennent la clé sous aucune forme (affichée, sans tirets).
- Un `device.bin` existant qui porte la clé en clair la verse dans le magasin au déverrouillage suivant, puis la copie en clair est écrasée. Test de migration.
- Sans magasin, la CLI refuse, sauf choix explicite `--insecure-file-secret-key`, rappelé à chaque commande.
- `cargo build -p onepass-cli` ne lie pas le plancher de développement ; les tests le gardent.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check` et `cargo vet` passent.

## 3. Magasin de secrets

Trait `SecretStore` (`onepass-cli/src/secret_store.rs`) : `get`, `set`, `delete` sur une entrée `secretkey.<id du compte>` (le nom de l'app, section 10.2 de `docs/security/README.md`), service `me.somalabs.onepass.cli`. Erreurs : `Unavailable` (pas de magasin joignable) ou `Failed` (magasin présent, refus ou panne).

Implémentations :

| Implémentation | Où | Quand |
| --- | --- | --- |
| `MacKeychain` | macOS | par défaut |
| `SecretService` | Linux | par défaut |
| `NoStore` | autres systèmes | par défaut, toujours `Unavailable` |
| `DevDirStore` | partout | build debug, `ONEPASS_DEV_SECRET_STORE=dir:<dossier>` (tests de bout en bout) |
| `NoStore` | partout | build debug, `ONEPASS_DEV_SECRET_STORE=none` (simule une machine sans magasin) |
| `MemoryStore` | tests unitaires | `cfg(test)` |

`ONEPASS_DEV_SECRET_STORE` est refusée dans un build release, comme les autres variables de développement.

Ruling: macOS = trousseau de session (`login.keychain`), élément générique écrit par `security-framework` (déjà dans l'arbre par `onepass-peer`), pas le trousseau à protection de données de l'app - ce dernier exige l'entitlement `keychain-access-groups`, qu'un binaire CLI non signé ou ad hoc ne peut pas porter (erreur `-34018`) - coût si faux : pas de classe `ThisDeviceOnly` ; le fichier du trousseau de session est chiffré par le mot de passe de session macOS, n'est jamais copié dans iCloud, mais entre dans Time Machine. Un voleur de sauvegarde qui connaît aussi le mot de passe de session macOS retrouve la Secret Key. Écart avec l'app, documenté.

Ruling: Linux = Secret Service (GNOME Keyring, KWallet, KeePassXC) par la crate `dbus-secret-service` 4.1.0 (liaison à `libdbus-1`, même mainteneur que `keyring`), collection par défaut, attributs `service` et `account` - trois crates nouvelles (`dbus-secret-service`, `dbus`, `libdbus-sys`, MIT ou Apache-2.0) contre environ 270 lignes d'arbre pour `secret-service` (zbus, exécuteur asynchrone) et une pile de sous-crates pour `keyring` 4 - coût si faux : construire la CLI sous Linux demande `libdbus-1-dev` et `pkg-config` (ajoutés à la CI).

Ruling: session Secret Service en clair (`EncryptionType::Plain`, aucune feature de chiffrement) - le transport est le bus de session de l'utilisateur, un socket local du même uid, et tout processus de ce uid peut de toute façon demander l'entrée au magasin ; le chiffrement Diffie-Hellman ajouterait `aes`, `cbc`, `hkdf`, `num` et consorts à l'audit - coût si faux : un processus du même uid qui écoute le bus voit passer la clé, ce qu'il obtient déjà en la demandant.

Ruling: aucun magasin joignable = refus (code 1), sauf `--insecure-file-secret-key` - c'est la seule option qui ne ment pas : écrire la clé en clair sans le dire est exactement F2 - coût si faux : un serveur Linux sans bus de session doit passer l'option à la création (le message le dit).

Ruling: pas d'enveloppe de la Secret Key sous une clé dérivée du mot de passe - cela ramène le compte à un seul secret : qui détient `device.bin` détient aussi `vault.sqlite` (même dossier) et attaque le mot de passe hors ligne au coût d'Argon2id, exactement comme avec la clé en clair ; le seul gain (fuite de `device.bin` seul) coûterait un second Argon2id par déverrouillage et un format de plus - coût si faux : une fuite isolée de `device.bin` en mode `--insecure-file-secret-key` livre la clé.

## 4. Format de `device.bin`

Version 3 : en-tête `ODF\x03`, puis postcard de `{ state: DeviceState::encode, secret_key: Store { account_id } | File { secret_key } }`. L'état vient en premier : un lecteur qui ne veut que l'état (tests) n'a pas à connaître la suite. Les deux anciens formats (clé puis état en ligne v1, clé puis état versionné) restent lisibles et ne sont plus jamais écrits. Un ancien format commence par la longueur de la clé (53 caractères, octet `0x35`), jamais par `O` (`0x4F`) : pas de confusion avec l'en-tête.

## 5. Création, déverrouillage, migration

- **`account create`** : la clé est écrite dans le magasin, relue et comparée, puis `device.bin` est écrit avec `Store { account_id }`. Tout échec après l'écriture dans le magasin retire l'entrée et le compte. Avec `--insecure-file-secret-key` : `File`, le magasin n'est pas touché, et un avertissement sort sur stderr.
- **Déverrouillage, `Store`** : la clé est lue dans le magasin. Entrée absente (dossier copié sur une autre machine) : refus, code 1, message qui nomme l'entrée. Ressaisir la clé depuis l'Emergency Kit n'est pas proposé ici (suite possible).
- **Déverrouillage, clé en clair (`File` ou ancien format)** : sans l'option, une fois le déverrouillage réussi (la clé est donc juste), la clé est écrite dans le magasin, relue et comparée, puis `device.bin` est réécrit en `Store` et l'ancien contenu est écrasé. Un message sur stderr dit que les copies antérieures de `device.bin` (sauvegardes, instantanés, dossiers synchronisés) gardent la clé.
- **Magasin indisponible ou en échec pendant la migration** : ancien format, refus (code 1), fichier intact, le message cite l'option ; format `File` (choix explicite antérieur), la commande continue avec l'avertissement.
- **Avec l'option** : un ancien format devient `File` ; un `File` reste `File` ; un `Store` reste `Store` (une clé n'est jamais sortie du magasin vers un fichier).
- **Serveurs longs** (`mcp`, `ssh-agent`) : à chaque requête ils relisent `device.bin` ; s'il est passé en `Store` entre-temps, ils l'adoptent et n'y réécrivent jamais la clé.

Ruling: écrasement de l'ancien inode par un descripteur gardé ouvert à travers le `rename` (le nouveau fichier est en place avant que l'ancien soit mis à zéro) - à aucun moment `device.bin` n'est illisible, une coupure de courant laisse l'ancien ou le nouveau fichier entier - coût si faux : sur APFS, btrfs ou un SSD, les anciens blocs peuvent survivre à l'écrasement, et les instantanés les gardent ; c'est dit à l'utilisateur. Le remède complet est la rotation de la Secret Key (autre session en cours dans le cœur).

Ruling: migration seulement après un déverrouillage réussi, avec relecture du magasin avant de toucher au fichier - une clé fausse ou mal écrite ne remplace jamais la seule copie qui marche - coût si faux : aucun.

## 6. Feature `dev-fast-kdf`

`onepass-cli` déclare sa propre feature `dev-fast-kdf = ["onepass-core/dev-fast-kdf"]`, désactivée par défaut, et une dépendance de développement sur `onepass-core` avec la feature : ses tests (unitaires et de bout en bout, qui lancent le binaire construit pour les tests) gardent le plancher rapide, un `cargo build -p onepass-cli` ne l'a pas. `ONEPASS_DEV_FAST_KDF=1` dans un build sans la feature est refusé avec un message qui nomme la feature, au lieu d'échouer plus loin sur le plancher. Usage manuel : `cargo run -p onepass-cli --features dev-fast-kdf`.

Ruling: dépendance de développement plutôt que `required-features` sur les tests - les tests de la CLI lancent le binaire, qui doit être construit avec le plancher rapide quand `cargo test` le construit ; c'est déjà le schéma de `onepass-mcp` et `onepass-ssh-agent` - coût si faux : aucun en dehors des tests.

Limite connue, hors périmètre : `onepass-native-host` active encore `dev-fast-kdf` dans ses dépendances normales (source de démonstration). Un `cargo build --workspace` en debug unifie donc la feature dans tous les binaires du workspace ; `cargo build -p onepass-cli` et tout build release ne sont pas concernés.

## 7. Tests

- Unitaires (`session.rs`, `MemoryStore`) : `device.bin` d'un compte créé ne contient pas la clé ; migration d'un ancien format (clé au magasin, fichier sans clé, nouveau déverrouillage) ; ancien format sans magasin refusé, fichier intact ; ancien format avec l'option devient `File` ; magasin en échec pendant la migration refusé ; entrée absente refusée ; choix de magasin par `ONEPASS_DEV_SECRET_STORE` refusé en release ; `ONEPASS_DEV_FAST_KDF` refusé sans la feature.
- De bout en bout (`tests/cli.rs`, `DevDirStore`) : `account create` laisse un `device.bin` sans la clé ; sans magasin, création refusée sans rien laisser ; avec l'option, clé dans le fichier et avertissement ; puis migration au déverrouillage suivant avec un magasin.
- Trousseau macOS réel : un test `#[ignore]` (aller-retour sur une entrée de test, supprimée à la fin), lancé à la main.

## 8. Hors périmètre

Rotation de la Secret Key (autre session, `repo.rs`, `devices.rs`, `account.rs` du cœur), ressaisie de la clé depuis l'Emergency Kit dans la CLI, `onepass-native-host` et sa feature.
