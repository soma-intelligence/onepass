# Constructions reproductibles

Objectif : qu'un tiers puisse reconstruire OnePass à partir d'un commit et retrouver des binaires identiques bit à bit, hors signature. État actuel : **non démontré**. Ce document liste ce qui est déjà fixé, ce qui reste à faire et comment vérifier.

## Ce qui est déjà fixé

### Rust (`core/`)

- Chaîne d'outils épinglée par `core/rust-toolchain.toml` : `channel = "1.99.1"`, avec `clippy` et `rustfmt`. `rustup` l'installe à l'identique partout.
- `Cargo.lock` est versionné ; toutes les constructions de release utilisent `--locked` (le build échoue si le verrou doit changer).
- Les sources de dépendances sont limitées au registre crates.io (`cargo deny`, section `[sources]`).
- Les chemins absolus de la machine entrent dans les binaires (messages de panique, informations de débogage). Pour les retirer, construire avec :

  ```sh
  export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  cargo build --release --locked
  ```

  `SOURCE_DATE_EPOCH` fixe tout horodatage que des outils de la chaîne intégreraient.

### Extension (`extension/`)

- `package-lock.json` en `lockfileVersion` 3, versions exactes dans `package.json` (aucune plage).
- Installation par `npm ci` uniquement (jamais `npm install`) : elle échoue si le verrou et `package.json` divergent.
- L'empaquetage passe par `esbuild` (version exacte) via `build.mjs` ; la sortie est dans `extension/dist`.

### Applications Apple (`apple/`)

- Le noyau est compilé par `apple/scripts/build-core.sh shipped` (release, sans `dev-fast-kdf`), puis assemblé en XCFramework.
- Les constructions Xcode utilisent `xcodebuild -project OnePass.xcodeproj -scheme OnePass` avec le projet généré par XcodeGen depuis `apple/project.yml`. Fixer la version de Xcode et du SDK (affichées par `xcodebuild -version`) et construire avec `SOURCE_DATE_EPOCH` exporté.
- Les workflows GitHub Actions sont épinglés par SHA de commit (`scripts/check-pinned-actions.sh` le vérifie en CI).

## État actuel

Aucune comparaison de deux constructions indépendantes n'a encore été faite. Les points connus qui peuvent différer : horodatages et UUID de l'archive Xcode, chemins de la machine, ordre de liaison selon la version de l'éditeur de liens, signature de code. Tant qu'une comparaison n'a pas réussi, il ne faut pas présenter les constructions comme reproductibles.

## Comment vérifier

1. Cloner le dépôt dans deux répertoires de même chemin logique (ou utiliser `--remap-path-prefix` comme ci-dessus), sur deux machines ou deux sessions propres.
2. Dans chacun : `rustup show` (doit afficher 1.99.1), exporter `RUSTFLAGS` et `SOURCE_DATE_EPOCH` comme plus haut, puis `cargo build --release --locked` dans `core/`, et `npm ci && npm run build` dans `extension/`.
3. Comparer les sorties :

   ```sh
   shasum -a 256 core/target/release/onepass core/target/release/onepass-native-host
   diffoscope build-a/core/target/release/onepass build-b/core/target/release/onepass
   diff -r build-a/extension/dist build-b/extension/dist
   ```

   Pour les applications, comparer le contenu des `.app` non signées (`diffoscope` sur les deux dossiers).
4. Toute différence est un défaut à corriger ou à documenter ici.

Les SBOM CycloneDX (`make -C core sbom`, `npm run sbom` dans `extension/`) sont publiés comme artefacts de CI pour comparer l'inventaire des dépendances.

## Ce qui reste à faire

- Exécuter la vérification ci-dessus et consigner le résultat (identique, ou liste des écarts).
- Figer et documenter la version de Xcode et du SDK de release.
- Signature de code Apple et notarisation : la signature (certificat développeur, horodatage du serveur d'Apple) et le ticket de notarisation ne sont pas reproductibles. La comparaison se fait sur le contenu avant signature ; la publication devra inclure les condensats des artefacts non signés.
- Publier les condensats et les SBOM avec chaque version.
