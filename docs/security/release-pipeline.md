# Chaîne de publication

Comment une version de OnePass est construite, signée, attestée et publiée, ce qu'il faut configurer une fois sur GitHub et comment quiconque vérifie un téléchargement. Le workflow est `.github/workflows/release.yml` ; les constructions qui n'ont pas besoin de la signature Apple passent par `scripts/release-build.sh`, que tout le monde peut relancer (`docs/security/reproducible-builds.md`).

## Ce que fait le workflow

Déclenché par le push d'un tag `v*` (par exemple `v0.2.1`, ou `v0.3.0-rc.1` pour une préversion), sur les runners de GitHub :

| Job | Runner | Produit | Permissions |
| --- | --- | --- | --- |
| `meta` | ubuntu-24.04 | version (le tag sans `v`, refusé s'il ne correspond pas à `core/Cargo.toml`, `extension/package.json`, `extension/manifests/base.json` et `MARKETING_VERSION`), `SOURCE_DATE_EPOCH` = date du commit | `contents: read` |
| `preflight` | ubuntu-24.04 | `cargo deny check`, `cargo vet --locked`, `cargo audit`, actions épinglées | `contents: read` |
| `extension` | ubuntu-24.04 | `OnePass-<v>-chrome.zip`, `OnePass-<v>-firefox.zip` | `contents: read` |
| `cli` | macos-26, ubuntu-24.04 | `onepass-<v>-aarch64-apple-darwin`, `onepass-<v>-x86_64-unknown-linux-gnu` | `contents: read` |
| `rebuild` | ubuntu-24.04 | reconstruit l'extension et la CLI Linux depuis un second checkout, à un autre chemin, et exige les mêmes octets | `contents: read` |
| `sbom` | ubuntu-24.04 | `OnePass-<v>-sbom.zip` (CycloneDX de chaque crate et de l'extension) | `contents: read` |
| `mac` | macos-26, Xcode épinglé (`XCODE_APP`) | `OnePass-<v>-mac.zip` : app signée Developer ID, notarisée, ticket agrafé, `CFBundleVersion` = cœur numérique du tag, clé publique de mise à jour dans l'Info.plist | `contents: read`, environnement `release` |
| `appcast` | ubuntu-24.04 | `appcast.xml` : flux Sparkle signé (zip et flux signés Ed25519), après contrôle de la clé et des numéros de l'app | `contents: read`, environnement `release` |
| `attest` | ubuntu-24.04 | `SHA256SUMS` et une attestation de provenance SLSA (`actions/attest-build-provenance`) dont les sujets sont tous les fichiers, `SHA256SUMS` compris | `contents: read`, `id-token: write`, `attestations: write` |
| `release` | ubuntu-24.04 | release GitHub en **brouillon** avec tous les fichiers ; elle est marquée préversion seulement si la version porte un suffixe (`-rc.1`) | `contents: write` |

Rien n'est publié automatiquement : une personne relit le brouillon, écrit les notes et clique sur Publish.

Lancé à la main (`workflow_dispatch`, onglet Actions, "Run workflow" sur une branche ou un tag), le workflow fait un essai à blanc : mêmes constructions avec la version `<version>-dryrun.<commit>`, fichiers déposés comme artefacts du run, ni attestation ni release. L'app Mac n'y est construite que si les secrets sont accessibles depuis cette référence.

Règles tenues par le fichier : chaque action est épinglée par SHA de commit (`scripts/check-pinned-actions.sh`), pas de `pull_request_target`, aucun cache (un cache empoisonné finirait dans un artefact signé), checkout sans identifiants persistés, permissions par job, secrets exposés aux seules étapes qui s'en servent, nom du tag lu par variable d'environnement et validé avant usage.

## Secrets à créer (une fois)

Tous dans l'environnement GitHub `release` du dépôt public (Settings, Environments, New environment `release`), jamais en clair dans le dépôt. L'identifiant d'équipe Apple n'apparaît que dans le secret `APPLE_TEAM_ID`.

| Secret | Contenu |
| --- | --- |
| `MACOS_CERTIFICATE_P12_BASE64` | certificat "Developer ID Application" de l'équipe et sa clé privée, export `.p12`, encodé en base64 |
| `MACOS_CERTIFICATE_PASSWORD` | mot de passe de ce `.p12` |
| `APPLE_TEAM_ID` | identifiant d'équipe Apple (10 caractères) |
| `MACOS_PROFILE_APP_BASE64` | profil de provisionnement Developer ID de `me.somalabs.onepass`, en base64 |
| `MACOS_PROFILE_AUTOFILL_BASE64` | profil de provisionnement Developer ID de `me.somalabs.onepass.autofill`, en base64 |
| `ASC_API_KEY_P8_BASE64` | clé d'API App Store Connect (`AuthKey_XXXX.p8`), en base64 |
| `ASC_API_KEY_ID` | identifiant de cette clé |
| `ASC_API_ISSUER_ID` | identifiant d'émetteur (Issuer ID) de l'équipe |
| `SPARKLE_ED_PRIVATE_KEY` | clé privée de signature des mises à jour de l'app Mac (graine Ed25519 de 32 octets en base64), voir [Mises à jour de l'app Mac](#mises-à-jour-de-lapp-mac) |

Une seule variable, elle aussi dans l'environnement `release` (Settings, Environments, `release`, Environment variables) : `SPARKLE_ED_PUBLIC_KEY`, la clé publique qui correspond à `SPARKLE_ED_PRIVATE_KEY`. Elle n'est pas secrète : elle finit dans l'Info.plist de l'app (`SUPublicEDKey`). La version de Xcode (`XCODE_APP`) et le label du runner macOS sont écrits dans le workflow : les changer est une modification relue, pas un réglage. Si le runner n'a pas cette version, le job s'arrête et liste les Xcode installés.

Réglages de l'environnement `release` conseillés : un relecteur obligatoire (le job Mac attend son accord avant de toucher aux secrets) et des références de déploiement limitées aux tags `v*` (ajouter `main` pour pouvoir faire un essai à blanc signé).

Si un secret manque, le job Mac s'arrête proprement avec la liste des secrets absents : en erreur pour un tag du dépôt `soma-intelligence/onepass` (une version sans app signée ne doit pas partir), en simple avertissement pour un fork ou un essai à blanc, qui continuent sans l'app Mac.

### Certificat Developer ID (`.p12`)

1. Sur un Mac de l'équipe, Trousseau d'accès, Assistant de certification, "Demander un certificat à une autorité de certification", enregistré sur le disque.
2. developer.apple.com, Certificates, `+`, "Developer ID Application" (G2), envoyer la demande, télécharger le `.cer` et l'ouvrir (il rejoint le trousseau avec sa clé privée). Seul le titulaire du compte (Account Holder) peut créer ce type de certificat.
3. Dans Trousseau d'accès, sélectionner le certificat et sa clé, Exporter, format `.p12`, avec un mot de passe long et aléatoire.
4. `base64 -i developer-id.p12 | gh secret set MACOS_CERTIFICATE_P12_BASE64 --env release --repo soma-intelligence/onepass`, puis `gh secret set MACOS_CERTIFICATE_PASSWORD --env release --repo soma-intelligence/onepass` (saisie interactive). Effacer le `.p12` exporté.

Le workflow importe ce certificat dans un trousseau temporaire au mot de passe aléatoire, avec l'intermédiaire "Developer ID Certification Authority" d'Apple téléchargé puis vérifié par son empreinte SHA-256, et supprime le trousseau, la clé d'API et les profils à la fin du job, même en cas d'échec.

### Profils de provisionnement Developer ID

L'app et son extension AutoFill portent des droits restreints (CloudKit, App Group, trousseau partagé, fournisseur AutoFill) : il leur faut un profil. L'extension Safari n'en porte pas et n'en a pas besoin.

1. developer.apple.com, Profiles, `+`, "Developer ID" (macOS), App ID `me.somalabs.onepass`, le certificat Developer ID ci-dessus. Nommer le profil, le télécharger.
2. Même chose pour `me.somalabs.onepass.autofill`.
3. Les App IDs doivent porter les capacités que demandent `apple/App/Support/OnePass-CloudKit-macOS.entitlements` et `apple/AutoFill/Support/OnePassAutoFill-macOS-CloudKit.entitlements` (iCloud avec le conteneur `iCloud.me.somalabs.onepass`, App Groups, Push, AutoFill Credential Provider). Après tout changement de capacité, régénérer les deux profils et mettre à jour les secrets.
4. `base64 -i OnePass_DeveloperID.provisionprofile | gh secret set MACOS_PROFILE_APP_BASE64 --env release --repo soma-intelligence/onepass`, et de même pour `MACOS_PROFILE_AUTOFILL_BASE64`.

Le workflow vérifie que chaque profil est bien celui de son App ID avant de l'installer. La signature est manuelle (`CODE_SIGN_STYLE = Manual` dans un xcconfig écrit au moment du build) : le CI ne crée ni certificat ni profil sur le portail.

### Clé d'API App Store Connect (notarisation)

1. appstoreconnect.apple.com, Users and Access, Integrations, App Store Connect API, Team Keys, `+`. Rôle : Developer, le plus faible qui permet de notariser.
2. Télécharger `AuthKey_<ID>.p8` (une seule fois possible), noter le Key ID et l'Issuer ID affichés en haut de la page.
3. `base64 -i AuthKey_<ID>.p8 | gh secret set ASC_API_KEY_P8_BASE64 --env release --repo soma-intelligence/onepass`, puis `ASC_API_KEY_ID`, `ASC_API_ISSUER_ID` et `APPLE_TEAM_ID` de la même façon. Effacer le `.p8` local ou le ranger dans le gestionnaire de mots de passe de l'équipe.

La notarisation passe par `xcrun notarytool submit --wait` ; si Apple refuse, le job affiche le journal de notarisation et s'arrête. Puis `xcrun stapler staple`, `stapler validate` et `spctl --assess` sur l'app avant de la zipper.

### Mises à jour de l'app Mac

L'app Mac se met à jour par Sparkle (conception : `docs/superpowers/specs/2026-11-02-mac-updater-design.md`). Elle lit `https://github.com/soma-intelligence/onepass/releases/latest/download/appcast.xml`, le flux de la release marquée *Latest*, et n'installe une mise à jour que si le flux et le zip sont signés par la clé Ed25519 dont la clé publique est dans son Info.plist, si la nouvelle app est signée Developer ID par la même équipe, et si sa version est strictement plus récente. La clé est créée une fois, par le fondateur, jamais par le dépôt ni par un agent :

1. Récupérer l'outil `generate_keys` de Sparkle 2.10.1 : `swift package resolve --package-path apple/UpdateKit`, puis l'outil est dans `apple/UpdateKit/.build/artifacts/sparkle/Sparkle/bin/generate_keys` (ou dans l'archive `Sparkle-2.10.1.tar.xz` de github.com/sparkle-project/Sparkle, dossier `bin`).
2. `generate_keys` : crée la clé dans le trousseau de session (élément `https://sparkle-project.org`, compte `ed25519`) et affiche la clé publique. Sauvegarder ce trousseau (ou exporter la clé dans le gestionnaire de mots de passe de l'équipe) : **une clé perdue empêche toute mise à jour des apps déjà installées**, qui ne font confiance qu'à elle.
3. `gh variable set SPARKLE_ED_PUBLIC_KEY --env release --repo soma-intelligence/onepass --body '<clé publique>'`.
4. `generate_keys -x sparkle-private.txt`, puis `gh secret set SPARKLE_ED_PRIVATE_KEY --env release --repo soma-intelligence/onepass < sparkle-private.txt`, puis effacer `sparkle-private.txt`.
5. Vérifier la paire : `python3 -I scripts/appcast.py public-key` (lit le trousseau) doit afficher la même clé publique. OpenSSL 3 ou plus récent est nécessaire (`brew install openssl`) : le LibreSSL de macOS ne signe pas en Ed25519.

Faire le même jeu de secrets dans `onepass-dev` permet un essai à blanc signé complet.

Chaque version : le job `mac` passe la clé publique et `CFBundleVersion` à `xcodebuild` ; la phase `Check update key` (`apple/scripts/check-update-key.sh`) fait échouer un build Developer ID sans clé valide. Le job `appcast` relance les tests de `scripts/appcast.py`, vérifie que l'app du zip fait confiance à la clé de signature et porte les numéros de la version, signe le zip et le flux, revérifie les deux signatures. `appcast.xml` rejoint `SHA256SUMS`, l'attestation et le brouillon. Signer à la main, depuis un Mac qui a la clé dans son trousseau :

```sh
python3 -I scripts/appcast.py build --version 0.3.0 --archive OnePass-0.3.0-mac.zip \
  --download-url https://github.com/soma-intelligence/onepass/releases/download/v0.3.0/OnePass-0.3.0-mac.zip \
  --release-url https://github.com/soma-intelligence/onepass/releases/tag/v0.3.0 --out appcast.xml
python3 -I scripts/appcast.py verify --appcast appcast.xml --archive OnePass-0.3.0-mac.zip
```

Ce que la vérification envoie : une requête HTTPS GET vers `github.com`, redirigée vers le stockage des releases de GitHub, avec l'en-tête User-Agent habituel (nom et version de l'app, version de Sparkle). Aucun identifiant de compte, d'appareil ou d'installation, aucun profil système, aucun cookie posé par OnePass. Le réglage « Rechercher automatiquement les mises à jour » (Réglages, À propos) coupe toute requête automatique ; le menu OnePass, « Rechercher les mises à jour… », reste disponible.

Points à connaître :

- Seule la release *Latest* compte. Une préversion (tag avec suffixe) n'est jamais *Latest* et n'est proposée à personne ; cocher *Pre-release* à la main sur une version la retire aussi des mises à jour. Une release *Latest* sans `appcast.xml` coupe les mises à jour jusqu'à la suivante.
- Rotation de clé : une app ne fait confiance qu'à la clé de son Info.plist. Pour changer de clé, publier d'abord une version signée par l'ancienne clé qui embarque la nouvelle clé publique, puis signer les suivantes avec la nouvelle.
- iPhone, iPad, Apple Watch et Vision Pro se mettent à jour par l'App Store ; les extensions Chrome et Firefox par leurs magasins.

## Routine de publication

1. Pousser `main` sur le dépôt public et attendre que le CI `core` soit vert.
2. Facultatif mais conseillé avant une version qui touche au build : lancer `release` à la main sur `main` (essai à blanc) et lire le job `rebuild`.
3. Pousser le tag `vX.Y.Z` sur le commit vérifié.
4. Approuver le job `mac` quand l'environnement le demande.
5. Relire le brouillon de release : fichiers attendus (dont `appcast.xml`), `SHA256SUMS`, attestation listée dans le résumé du run. Écrire les notes, publier en laissant *Set as the latest release* coché : c'est ce qui propose la version aux apps Mac installées.

Un échec de `rebuild` (un fichier dont les octets changent d'un build à l'autre) bloque la release : corriger la cause, ou la documenter dans `reproducible-builds.md` et retirer ce fichier de la comparaison, par une modification relue.

## Vérifier un téléchargement

Avec les fichiers et `SHA256SUMS` dans le même dossier :

```sh
sha256sum -c SHA256SUMS --ignore-missing      # macOS : shasum -a 256 -c SHA256SUMS --ignore-missing
```

Provenance (GitHub CLI 2.49 ou plus récent) : l'attestation lie le condensat du fichier au dépôt, au workflow, au tag et au commit qui l'ont construit, signée par Sigstore avec l'identité du workflow.

```sh
gh attestation verify OnePass-0.2.1-mac.zip \
  --repo soma-intelligence/onepass \
  --signer-workflow soma-intelligence/onepass/.github/workflows/release.yml
```

La sortie doit être "Verification succeeded" et nommer `refs/tags/v0.2.1`. Un fichier sans attestation, ou attesté par un autre workflow, ne vient pas de cette chaîne.

Pour l'app Mac, en plus :

```sh
ditto -x -k OnePass-0.2.1-mac.zip .
codesign --verify --deep --strict --verbose=2 OnePass.app
spctl --assess --type execute --verbose=2 OnePass.app     # "source=Notarized Developer ID"
xcrun stapler validate OnePass.app
```

Les binaires `onepass-<v>-<cible>` sont la CLI de développement (`core/onepass-cli`) : elle garde la Secret Key dans le trousseau macOS ou le Secret Service Linux (voir `core/README.md`), mais reste un outil de développement en préversion. Le binaire Linux a besoin de `libdbus-1` à l'exécution. Le binaire macOS n'est signé qu'ad hoc (par l'éditeur de liens) et n'est pas notarisé : après un téléchargement par navigateur, `xattr -d com.apple.quarantine` et `chmod +x` sont nécessaires.

## Ce que l'attestation prouve, et ce qu'elle ne prouve pas

Elle prouve que les octets publiés sortent de `release.yml`, exécuté sur un runner hébergé par GitHub, à partir du commit du tag. Cela correspond au niveau Build L2 de SLSA (service de build hébergé, provenance signée par ce service). Elle ne prouve pas que ce commit est sain, ni que les dépendances le sont : c'est le rôle de la revue de code et des contrôles de dépendances ci-dessous. Le niveau L3 demanderait d'isoler la génération de provenance dans un workflow réutilisable que les jobs de build ne peuvent pas influencer ; ce n'est pas fait.

## Dépendances Rust : où en est `cargo vet`

`cargo vet --locked` tourne en CI (workflow `core`) et dans `preflight` ; `cargo audit` est bloquant, avec les mêmes avis ignorés que `deny.toml`, chacun avec une raison et une date de revue (`core/.cargo/audit.toml`).

Exemptions (`core/supply-chain/config.toml`), sur 333 paquets dans `Cargo.lock` :

| Étape (2026-10-28) | Entièrement audités | Exemptés |
| --- | --- | --- |
| Avant : 6 jeux importés (google, mozilla, bytecode-alliance, zcash, isrg, embark-studios) | 85 | 237 |
| Imports complétés avec les 3 autres jeux du registre de cargo-vet (actix, ariel-os, fermyon) | 85 | 237 |
| Confiance accordée aux éditeurs qu'au moins deux organisations importées approuvent déjà, puis `cargo vet prune` | 168 | 154 |

La troisième ligne vient de 82 entrées `[[trusted]]` dans `core/supply-chain/audits.toml` (critère `safe-to-deploy`, fin au 2027-04-28) : dtolnay, epage, BurntSushi, cuviper, kennykerr, robertbastian, rust-lang-owner, Darksonn, alexcrichton, sunfishcode, Amanieu, uniquement pour des crates dont ils ont publié la version exacte utilisée, et uniquement quand `cargo vet suggest` indique qu'au moins deux des organisations importées leur font déjà confiance. Chaque entrée le dit dans ses notes. C'est une décision de confiance, pas une relecture de code : la retirer est un `git revert` du commit `chore(supply-chain): trust publishers that two imported sets trust`. Aucune entrée `cargo vet certify` n'a été ajoutée ; `audits.toml` ne contient aucun audit propre au projet.

### Crates critiques encore exemptées : audit humain requis

Ces crates touchent la cryptographie, le stockage du coffre, la sérialisation ou les frontières du système. Aucune n'est couverte par un audit importé à la version utilisée ; chacune attend une relecture humaine (`cargo vet inspect <crate> <version>` puis `cargo vet certify` par la personne qui a lu le code) :

- Primitives et constructions : `slh-dsa` 0.1.0 et 0.2.0-rc.5, `libcrux-ml-kem`, `libcrux-ml-dsa`, `libcrux-sha3`, `libcrux-intrinsics`, `libcrux-secrets`, `libcrux-platform`, `libcrux-traits`, `libcrux-macros`, `aws-lc-rs`, `aws-lc-sys`, `argon2`, `password-hash`, `phc`, `pbkdf2`, `hmac`, `blake2`, `sha2` 0.11, `sha3`, `keccak`, `digest`, `cipher`, `inout`, `blowfish`, `bcrypt-pbkdf`, `crypto-bigint`, `crypto-common`, `signature`, `ctutils`, `cmov`, `cpufeatures`, `getrandom` 0.4, `zeroize_derive`, `hybrid-array`, `generic-array`, `typenum`.
- Encodages de clés : `der`, `spki`, `pkcs8`, `const-oid`, `base64ct`, `base16ct`, `serdect`, `data-encoding`, `tls_codec`.
- Stockage et formats lus depuis l'extérieur : `rusqlite`, `libsqlite3-sys`, `rsqlite-vfs`, `hashlink`, `zip`, `flate2`, `zlib-rs`, `quick-xml`, `psl`, `url`, `uuid`, `zxcvbn`.
- Frontières du système : `security-framework`, `security-framework-sys`, `core-foundation`, `objc2-local-authentication`, `rpassword`, `nix`, `libc`.

`postcard` (format du coffre) est couvert par l'audit `safe-to-deploy` de bytecode-alliance (1.0.8, puis le delta jusqu'à 1.1.3) et `zeroize` par ceux de bytecode-alliance et mozilla. La liste complète des exemptions restantes est dans `core/supply-chain/config.toml`.
