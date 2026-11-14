# OnePass pour Windows (Tauri 2)

L'app de bureau du jalon X2 de la spec `docs/superpowers/specs/2026-10-30-cross-platform-clients-design.md` (décision 4 du fondateur : Tauri 2). Windows d'abord ; Linux suivra avec le même code, une fois son stockage sûr écrit (section 6.4).

## Ce que fait cette première version

- Création d'un compte sur ce PC : mot de passe maître, Secret Key affichée une fois, clés d'appareil de la rotation v2 (moitié post-quantique logicielle, section 6.1), appareil de type `Windows`.
- Déverrouillage par mot de passe, verrouillage manuel, verrouillage automatique après 10 minutes sans action et à la fermeture.
- Coffres, liste des éléments, recherche, favoris, corbeille.
- Détail d'un élément : les champs secrets arrivent dans l'interface **sans valeur** ; « Afficher » demande la valeur au backend, « Copier » copie côté Rust (la valeur ne traverse pas l'IPC), hors de l'historique `Win+V` et du presse-papiers cloud, effacée au bout de 90 s.
- Codes TOTP en direct, générateur (caractères ou mots français).
- Création d'un élément des 26 types et modification de ses champs texte (identifiant, mot de passe, URL, e-mail, téléphone, notes, etc.).

Pas encore : sync par la boîte aux lettres, appairage depuis un iPhone, Windows Hello, TPM, éditeurs des champs structurés (dates, montants, adresses), import et export, pont navigateur, MSIX.

## Sécurité

- Le backend lie `onepass-ffi` comme une crate Rust : la même API que les apps Apple, sans FFI. Le moteur web ne reçoit jamais de clé ni de blob.
- `device.bin` (Secret Key, clés d'appareil, graine de l'aléa) est scellé par **DPAPI** pour l'utilisateur Windows courant, avec l'identifiant du compte comme entropie. C'est le repli documenté de la section 6.3 ; la clé TPM du Microsoft Platform Crypto Provider viendra derrière le même trait `Sealer`. L'app affiche la protection en cours sur l'écran de déverrouillage.
- Chaque commande IPC est déclarée dans `src-tauri/build.rs` et autorisée dans `src-tauri/capabilities/main.json` ; le motif d'isolation (`isolation/`) laisse passer ces commandes seulement. Aucun plugin (fichiers, shell, http).
- CSP stricte : `default-src 'self'`, pas de script ni de style en ligne, aucune ressource distante. Tout texte venu d'un élément est posé par `textContent`.
- La fenêtre est exclue des captures d'écran et du partage d'écran (`WDA_EXCLUDEFROMCAPTURE`).

## Construire

Prérequis sur Windows 11 :

- Visual Studio Build Tools 2022 avec la charge « Développement Desktop en C++ » (MSVC, SDK Windows 11) ;
- Rust par rustup (la version est épinglée dans `src-tauri/rust-toolchain.toml`, comme `core/`) ;
- CMake et NASM (pour `aws-lc-sys`) ;
- Node 22.

```powershell
cd desktop
npm ci
npm run check          # typecheck + bundle de l'interface
npm run dev            # lance l'app
npm run bundle         # installeurs MSI et NSIS dans src-tauri/target/release/bundle
```

Les tests du backend :

```powershell
cargo test --manifest-path desktop/src-tauri/Cargo.toml
```

Les données vont dans `%LOCALAPPDATA%\me.somalabs.onepass\` (`vault.db`, `device.bin`).
