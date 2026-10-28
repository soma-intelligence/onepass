# Constructions reproductibles

Objectif : qu'un tiers puisse reconstruire OnePass à partir d'un commit et retrouver des fichiers identiques bit à bit, hors signature. Ce document dit ce qui est démontré, ce qui ne l'est pas et comment vérifier. La chaîne de publication elle-même (workflow, secrets, attestations) est décrite dans `docs/security/release-pipeline.md`.

## État au 2026-10-28

| Fichier publié | Reproductible ? | Comment c'est établi |
| --- | --- | --- |
| `OnePass-<v>-chrome.zip`, `OnePass-<v>-firefox.zip` | **Oui**, à système identique | Deux constructions depuis deux copies du commit à des chemins différents (macOS, Node 22) donnent les mêmes octets. Le contenu du zip Chrome est identique fichier par fichier à celui de la version 0.2.0 publiée à la main. En CI, le job `rebuild` refait la construction sur un autre runner, à un autre chemin, et bloque la release en cas d'écart. |
| `onepass-<v>-aarch64-apple-darwin` (CLI) | **Oui**, à Xcode et chaîne Rust identiques | Deux constructions à des chemins différents donnent les mêmes octets, une fois l'option `-Wl,-S` ajoutée (voir plus bas). Pas encore comparé entre deux machines. |
| `onepass-<v>-x86_64-unknown-linux-gnu` (CLI) | **À confirmer** | Mêmes réglages ; le job `rebuild` le compare à chaque release. Aucun run n'a encore eu lieu à la date de ce document. |
| `OnePass-<v>-mac.zip` (app notarisée) | **Non** | Voir plus bas. |
| `OnePass-<v>-sbom.zip` | **Non** | `cargo cyclonedx` et `npm sbom` écrivent un horodatage et un numéro de série aléatoire dans chaque SBOM. Le contenu (liste des composants) est stable ; le fichier ne l'est pas. Il est attesté comme les autres. |

"À système identique" : le zip est écrit par `scripts/deterministic-zip.py` avec la zlib de Python ; deux versions différentes de zlib peuvent compresser différemment. La comparaison de référence se fait sur `ubuntu-24.04`, comme le build de release.

## Comment c'est fixé

Toutes les constructions de release qui n'ont pas besoin de la signature Apple passent par un seul script, `scripts/release-build.sh`, que le workflow appelle et que chacun peut relancer.

### Commun

- `SOURCE_DATE_EPOCH` vaut la date du commit construit (`git log -1 --format=%ct`), fournie par le job `meta` du workflow ou calculée par le script. Aucun horodatage ne vient de l'horloge.
- `TZ=UTC`, `LC_ALL=C`.
- Workflow sans cache : chaque build part des sources et des verrous.

### Rust (CLI)

- Chaîne d'outils épinglée par `core/rust-toolchain.toml` (`channel = "1.99.1"`).
- `Cargo.lock` versionné, `cargo build --locked` ; sources limitées à crates.io (`cargo deny`, section `[sources]`).
- `cargo build -p onepass-cli` uniquement : les fonctionnalités de développement des autres crates du workspace ne sont pas unifiées dans le binaire.
- `--target` toujours explicite, donc `RUSTFLAGS` s'applique au binaire livré et pas aux scripts de build ni aux macros.
- `RUSTFLAGS` : `-C strip=symbols` et `--remap-path-prefix` pour le dépôt (`/onepass`), `CARGO_HOME` (`/cargo`) et `RUSTUP_HOME` (`/rustup`). Le code C compilé par les scripts de build (SQLite, aws-lc) reçoit `-ffile-prefix-map` pour les mêmes chemins via `CFLAGS` et `CXXFLAGS`.
- macOS : `-C link-arg=-Wl,-S`. Sans elle, deux copies à des chemins différents donnaient deux binaires différents de 48 octets : `ld64` calcule `LC_UUID` au moment de l'édition de liens, quand la table de débogage (entrées `N_OSO`, chemins des fichiers objets) est encore là, et `rustc` ne retire les symboles qu'après. L'UUID et les condensats de la signature ad hoc changeaient donc avec le chemin. `-S` tient cette table hors de l'édition de liens.
- `CARGO_INCREMENTAL=0`.

Le profil `release` du workspace (`lto = true`, `codegen-units = 1`, `panic = "abort"`) aide aussi : un seul module de génération de code, pas de dépendance à l'ordre de compilation parallèle.

### Extension

- `package-lock.json` en `lockfileVersion` 3, versions exactes dans `package.json`.
- `npm ci --ignore-scripts` : aucun script d'installation de dépendance ne tourne, et l'installation échoue si le verrou et `package.json` divergent.
- `esbuild` à une version exacte, appelé par `build.mjs` sans carte de source ni minification.
- Zip par `scripts/deterministic-zip.py` : entrées triées par octets du chemin, toutes datées de `SOURCE_DATE_EPOCH` (UTC), mode 0644 (0755 si exécutable), pas d'entrée de dossier, pas de champ supplémentaire, deflate niveau 9, lien symbolique refusé.

### Applications Apple

- Le noyau est compilé par `apple/scripts/build-core.sh shipped` (release, sans `dev-fast-kdf`, `cargo build -p onepass-ffi`), avec `--remap-path-prefix` dans le workflow, puis assemblé en XCFramework. Le workflow vérifie avant le build que `Cargo.lock` est complet (`cargo metadata --locked`) et après qu'il n'a pas changé.
- L'archive est faite par `xcodebuild archive` sur `apple/OnePass.xcodeproj` (projet généré par XcodeGen depuis `apple/project.yml` et versionné), configuration `Release-CloudKit`, avec la version de Xcode fixée par `XCODE_APP` dans `.github/workflows/release.yml` et le runner `macos-26`.

## Pourquoi l'app Mac publiée n'est pas reproductible

L'app est signée Developer ID, notarisée et porte son ticket agrafé. Ni la signature (certificat de l'équipe, horodatage du serveur d'Apple), ni le ticket de notarisation ne peuvent être reproduits par un tiers ; l'archive Xcode contient en plus des horodatages et des UUID. Le zip `OnePass-<v>-mac.zip` n'est donc pas reproductible et ce document ne le présente pas comme tel. Ce qui le rattache aux sources est l'attestation de provenance : elle dit quel workflow, quel commit et quel tag l'ont produit (`release-pipeline.md`, "Vérifier un téléchargement").

Une comparaison du contenu non signé (binaires de l'app et des extensions, sans `_CodeSignature` ni ticket) entre deux constructions n'a pas encore été faite. Elle supposerait de retirer les signatures (`codesign --remove-signature`) puis de comparer avec `diffoscope`. Écarts connus à attendre : UUID et horodatages de l'archive, chemins de la machine dans les parties Swift, ordre de liaison selon la version de l'éditeur de liens.

## Comment vérifier soi-même

Avec le commit du tag extrait (`git checkout vX.Y.Z`), les outils installés (`rustup`, Node 22, Python 3) et la version publiée `X.Y.Z` :

```sh
scripts/release-build.sh extension X.Y.Z /tmp/rebuild
scripts/release-build.sh cli X.Y.Z /tmp/rebuild x86_64-unknown-linux-gnu    # ou aarch64-apple-darwin
cd /tmp/rebuild && sha256sum -c /chemin/vers/SHA256SUMS --ignore-missing
```

Le script prend la date du commit pour `SOURCE_DATE_EPOCH` ; un dossier sans historique git doit l'exporter lui-même (la valeur est dans le résumé du job `meta` du run de release). Toute différence est un défaut à signaler (`SECURITY.md`) ou à documenter ici. `diffoscope` sur les deux fichiers montre où elle se trouve.

## Ce qui reste à faire

- Voir passer le job `rebuild` sur un premier run (essai à blanc ou tag), et consigner ici le résultat de la CLI Linux.
- Comparer la CLI macOS et les zips de l'extension entre deux machines différentes, pas seulement deux chemins.
- Comparer le contenu non signé de l'app Mac entre deux constructions et consigner les écarts.
- Rendre les SBOM stables (horodatage depuis `SOURCE_DATE_EPOCH`, numéro de série dérivé du contenu) si les outils le permettent.
