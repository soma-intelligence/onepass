# OnePass hors Apple : clients Windows, Linux et Android

Date : 2026-10-30
Statut : brouillon pour la revue du fondateur. Rien n'est implémenté.
Branche : `docs/cross-platform-clients`, depuis le `main` privé (`88468668`).
Portée : amener OnePass sur Windows, Linux et Android avec la même crypto, le même modèle de menace et le même core Rust. Répond à l'idée "Transfert sans fil vers un appareil hors écosystème Apple" de `docs/backlog.md`, reprend le point "serveur self-host plus tard" de la spec d'architecture (sections 1 et 14) et l'écart R-15 de l'extension (mode autonome Windows et Linux).
Dépend de : jalon 2b (appairage, listes signées, `2026-10-26-milestone-2b-pairing-design.md`) et rotation v2 (clés d'appareil, `2026-10-28-key-rotation-v2-design.md` sur la branche `docs/key-rotation-v2`, en cours de construction).

## 1. Le problème en une page

Aujourd'hui :

- La sync passe uniquement par CloudKit (base privée iCloud, zone `OnePass`, type `OPRecord`). Le transport vit côté Swift (`CKSyncEngine`) ; le core Rust ne connaît que `SyncStore` et le trait `RecordStore` (`core/onepass-core/src/store/mod.rs`, `core/onepass-core/src/sync/`).
- Les apps sont en Swift (iOS, iPadOS, macOS, watchOS, visionOS). Le core Rust détient toute la crypto : 2SKD (Argon2id + Secret Key), ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, identité SLH-DSA, AES-256-GCM-SIV avec engagement de clé, manifestes signés.
- L'interface du core vers les apps est `onepass-ffi` (UniFFI `=0.32.2`, proc-macros, sans UDL), compilée seulement pour les cibles Apple.
- `onepass-relay` n'est **pas** un serveur de sync : c'est l'hôte de native messaging que Chrome et Firefox lancent sur Mac, qui recopie des trames vers le socket `bridge.sock` de l'app. `onepass-native-host` est son équivalent de développement, `onepass-peer` identifie un pair local (jeton d'audit sur macOS, `SO_PEERCRED` sur Linux).

Ce qui manque pour sortir d'Apple :

1. **Un backend de sync joignable sans compte Apple** qui reste une boîte aux lettres aveugle. La rotation v2 traite déjà le serveur comme hostile (attaquants T1 et T2) ; le nouveau backend ne doit rien affaiblir de ce qui est prouvé.
2. **Des clients** : une pile par plateforme, le stockage sûr des secrets de l'appareil, le déverrouillage biométrique, l'autofill.
3. **Un chemin d'appairage** entre un iPhone et un appareil qui n'a ni Bonjour ni AWDL.

Critère de réussite global : un utilisateur qui a un iPhone ajoute un PC Windows, une machine Linux et un téléphone Android par QR et code court, voit les mêmes coffres partout, édite partout, et retire un appareil avec la même coupure cryptographique que sur Apple (rotation v2). Aucun de ces appareils ne fait confiance au serveur.

## 2. Décisions en bref

| Sujet | Recommandation |
| --- | --- |
| Android | Kotlin + Jetpack Compose, core par UniFFI (liaisons Kotlin), `AutofillService` + `CredentialProviderService` |
| Bureau Windows et Linux | Tauri 2, core Rust lié directement (sans FFI), interface web locale verrouillée ; aides natives Rust pour Windows Hello et le plugin passkeys |
| Paquets Linux | `.deb` et `.rpm` signés (dépôts apt et dnf), AppImage en second ; Flatpak plus tard |
| Paquets Windows | MSIX signé (identité de paquet obligatoire pour Windows Hello et le plugin passkeys), winget |
| Backend de sync | Nouveau service `onepass-mailbox` (boîte aux lettres aveugle, self-hostable, hébergé aussi par Soma) ; un seul backend par compte |
| Moteur de sync | La boucle de sync passe en Rust (`SyncDriver`), partagée par tous les clients ; CloudKit reste un transport Swift pour les comptes qui ne quittent pas Apple |
| Appairage | Protocole 2b + `ConfirmedWithKey` / `FullV2` de la rotation v2, inchangés ; nouveaux transports : TCP sur le réseau local annoncé en DNS-SD, et rendez-vous chiffré par la boîte aux lettres |
| Stockage sûr | Android Keystore (StrongBox si présent), Windows TPM par CNG (Platform Crypto Provider), Linux Secret Service + scellement TPM2 quand il existe |
| Déverrouillage biométrique | Android `BiometricPrompt` + clé Keystore par usage ; Windows Hello par WebAuthn PRF ; Linux : pas de biométrie, clé FIDO2 en option |
| Autofill | Android : Autofill Framework + Credential Manager ; Windows : extension + plugin passkeys de Windows 11 + Quick Access ; Linux : extension + Quick Access |
| Ordre | Portabilité du core, boîte aux lettres, bureau, intégrations bureau, Android, autofill Android, appareils hors Apple approbateurs |

Chaque décision est détaillée avec ses alternatives dans les sections 3 à 9.

## 3. Pile client par plateforme

### 3.1 Android

| Option | Pour | Contre |
| --- | --- | --- |
| **A. Kotlin + Jetpack Compose, core par UniFFI** | Les composants système (service d'autofill, fournisseur Credential Manager, Keystore, `BiometricPrompt`) sont des API Java/Kotlin : une app native les sert sans pont. UniFFI génère déjà les liaisons Swift ; les liaisons Kotlin sortent du même `onepass-ffi`. | Une deuxième interface à écrire et à tenir (après SwiftUI). Compétence Kotlin à acquérir. |
| B. Kotlin Multiplatform + Compose Multiplatform (Android et bureau) | Une interface pour Android et le bureau. | Compose Desktop sur JVM : démarrage lent, mémoire, et une JVM à durcir dans un gestionnaire de mots de passe. Les intégrations Windows (Hello, plugin passkeys) restent natives. |
| C. Flutter ou Tauri mobile | Une interface pour tout. | Les services d'autofill et de Credential Manager restent à écrire en Kotlin ; le moteur de rendu tiers ajoute de la surface. |

**Recommandation : A.** Le cœur de la valeur sur Android, c'est l'autofill, et il ne se fait bien qu'en natif.

Détails :

- `onepass-ffi` gagne les cibles `aarch64-linux-android`, `x86_64-linux-android` (émulateur) et, si le fondateur le veut, `armv7-linux-androideabi`. Construction par `cargo-ndk` en `cdylib`, copie dans `jniLibs`, génération par `uniffi-bindgen generate --language kotlin` (le binaire `uniffi-bindgen` existe déjà dans la crate). Version UniFFI inchangée (`=0.32.2`) : une montée de version touche les deux plateformes en même temps.
- Les objets FFI existants (`Session`, `SyncStoreHandle`, appairage, appareils) servent tels quels. Les besoins propres à Android (Keystore, biométrie) passent par des interfaces de rappel UniFFI (`callback_interface`) implémentées en Kotlin : le Rust demande "enveloppe ces 32 octets", Kotlin répond avec le chiffré, jamais l'inverse.
- Version minimale : Android 10 (API 29) pour l'app et l'Autofill Framework ; les fonctions Credential Manager côté fournisseur demandent Android 14 (API 34) et s'activent seulement là (section 7.1). Question 11.
- Modules Gradle : `app` (Compose), `vaultkit-android` (liaisons, sync, Keystore, équivalent de `VaultKit`), `autofill` (service), `credentials` (fournisseur), `design`.
- Règles reprises des apps Apple : aucun secret gardé dans une `String` au-delà de l'affichage (tableaux de caractères effacés), `FLAG_SECURE` sur toutes les fenêtres qui montrent un secret, presse-papiers marqué sensible (`ClipDescription.EXTRA_IS_SENSITIVE`, Android 13+) et effacé après 90 s.

### 3.2 Bureau (Windows et Linux)

| Option | Pour | Contre |
| --- | --- | --- |
| **A. Tauri 2** | Le backend est du Rust : il lie `onepass-core` directement, sans FFI ni bindgen. Une interface pour Windows et Linux (et un jour Mac si besoin). Capacités refusées par défaut, liste d'autorisation par fenêtre, motif d'isolation. Stable depuis octobre 2024, 2.10 en 2026. | Un moteur web dans le processus d'affichage (WebView2 sur Windows, WebKitGTK sur Linux), mis à jour hors de notre contrôle. Une faille XSS dans l'interface verrait ce qui est affiché. |
| B. Natif par OS (WinUI 3 en C# sur Windows, GTK4/libadwaita en Rust sur Linux) | Meilleure intégration (WinUI est ce que montre l'exemple Microsoft du plugin passkeys), pas de moteur web. | Deux interfaces de plus (quatre en tout avec SwiftUI et Compose). C# demande une FFI de plus. |
| C. Rust + toolkit natif Rust (Slint, iced) | Un binaire Rust, pas de JavaScript du tout. | Accessibilité (lecteurs d'écran, Narrator, Orca), saisie IME et rendu du texte moins mûrs ; peu de composants. |

**Recommandation : A, avec des règles strictes.** C'est le seul choix où le bureau coûte une interface pour deux OS sans FFI. Le risque du moteur web se traite par construction :

- Aucune ressource distante : tout est embarqué, CSP `default-src 'self'`, pas de `unsafe-inline`, pas de `eval`, aucune URL externe chargée (les icônes de sites passent par le Rust, section 5.7 de l'architecture).
- Motif d'isolation activé ; une seule fenêtre a des capacités ; chaque commande IPC est déclarée et typée. Aucune commande générique ("lire un fichier", "lancer un processus").
- Le moteur web ne reçoit jamais de clé ni de blob : seulement les résumés d'items (sans secret, comme `item_summaries`) et la valeur d'un champ au moment où l'utilisateur la révèle ou la copie. La copie et la saisie se font côté Rust : le secret ne traverse pas l'IPC pour une copie.
- Notes Markdown : rendues en Rust vers un HTML assaini par liste blanche, insérées comme texte structuré, jamais par `innerHTML` d'une chaîne venue d'un item.
- Le code d'interface peut reprendre les composants TypeScript de `extension/` (même licence AGPL, même langage), pas leur logique de sécurité.

Repli documenté : si la revue de sécurité refuse le moteur web, l'interface passe à C (Slint) sans toucher au backend Rust. Question 4.

Intégrations natives, en Rust dans le même binaire ou un service à part :

- **Windows** : crate `windows` (windows-rs) pour CNG/NCrypt, WebAuthn (`webauthn.dll`), le serveur COM du plugin passkeys (`IPluginAuthenticator`, `WebAuthNPluginAddAuthenticator`), les canaux nommés de l'agent SSH et du pont navigateur.
- **Linux** : D-Bus (Secret Service, portails XDG `GlobalShortcuts` et `Secret`), TPM2 par `tss-esapi`.

### 3.3 Paquets Linux

| Option | Pour | Contre |
| --- | --- | --- |
| **A. `.deb` et `.rpm` signés, dépôts apt et dnf** | Accès normal à l'hôte : native messaging des navigateurs (manifeste dans `~/.config/google-chrome/NativeMessagingHosts`, `~/.mozilla/native-messaging-hosts`), agent SSH, Secret Service, TPM. Chemin du binaire possédé par root, ce que `onepass-peer` peut vérifier (`LINUX_LAUNCHER_PATHS`). | Une famille de paquets par distribution ; signature des dépôts à tenir. |
| B. Flatpak (Flathub) | Bac à sable, mises à jour, toutes distributions. | Le native messaging depuis un navigateur en Flatpak, ou vers une app en Flatpak, n'a pas de portail livré (proposition xdg-desktop-portal #655, encore ouverte) : l'extension ne joint pas l'app. Le portail `Secret` existe et suffirait pour le stockage. |
| C. Snap | Mises à jour, confinement. | Même problème de native messaging ; écosystème plus étroit. |

**Recommandation : A**, AppImage en plus pour les autres distributions (avec avertissement : pas de mise à jour automatique signée), Flatpak quand le portail de native messaging sera livré. Question 5.

### 3.4 Paquets Windows

MSIX signé, obligatoire en pratique : les API `KeyCredentialManager` échouent sans identité de paquet (`0x80073D54`), et le plugin passkeys s'enregistre comme serveur COM d'une app empaquetée. Signature par un certificat de signature de code (Azure Trusted Signing ou équivalent). Distribution : téléchargement direct + `winget`, Microsoft Store ensuite. Windows 11 seulement (Windows 10 est hors support depuis octobre 2025 et n'a ni le plugin passkeys ni le PRF de Windows Hello). Question 6 et 11.

## 4. Backend de sync

### 4.1 Contraintes

- Le serveur est hostile (architecture section 2, rotation v2 section 2). Il ne voit que des blobs chiffrés et signés, des identifiants opaques, des tailles arrondies, des versions et des horodatages. Tout ce qu'il pourrait faire (rejeu, retrait, réordonnancement, injection, retour en arrière) est déjà détecté par le core (manifestes, listes signées, époques, lignée de rotation).
- Le core attend un magasin qui sait faire une écriture conditionnelle sur la version (`put_if_version`, `put_all_if_version`), un flux de changements avec curseur, et une récupération complète.
- Les clients hors Apple n'ont pas de compte iCloud, ou ne veulent pas en dépendre.

### 4.2 Options

| Option | Pour | Contre |
| --- | --- | --- |
| A. CloudKit Web Services (ou CloudKit JS) depuis Windows, Linux, Android | Pas de serveur à opérer ; même zone que les apps Apple. | La base privée demande une connexion Apple ID dans un navigateur et un `ckWebAuthToken` à usage unique renouvelé à chaque aller-retour ; les clés serveur à serveur ne donnent que la base publique. Un utilisateur avec Advanced Data Protection doit activer "Accéder aux données iCloud sur le web", ce qui affaiblit sa protection côté Apple. Expérience pénible sur Android, dépendance totale à Apple. |
| B. Blob store générique (WebDAV, S3 compatible, Nextcloud) fourni par l'utilisateur | Self-host avec ce qu'on a déjà ; zéro service à nous. | Écritures conditionnelles inégales (S3 a `If-Match`/`If-None-Match` depuis 2024, beaucoup de WebDAV non fiables), pas de flux de changements (lister tout le préfixe à chaque tour), pas de lot atomique, pas de notification. Réalisable comme adaptateur, pas comme base. |
| **C. Service `onepass-mailbox` : boîte aux lettres aveugle, self-hostable, hébergée aussi par Soma** | Fait exactement ce que `RecordStore` attend : écriture conditionnelle, lots atomiques sans limite de 400 enregistrements, flux de changements par séquence serveur, notifications, rendez-vous d'appairage. Code public, image Docker, SQLite pour un self-host, Postgres pour l'hébergé. | Un service à opérer, à surveiller et à protéger contre l'abus ; adresses IP et rythme visibles par l'opérateur. |
| D. Pair à pair seulement (réseau local, l'appareil Apple sert de hub) | Aucun serveur. | Pas de sync continue quand les appareils ne sont pas ensemble ; un téléphone Android loin de l'iPhone ne voit rien. Garde son intérêt pour le premier transfert (instantané de l'autorisation, 2b section 5.4). |

**Recommandation : C**, avec D pour le premier transfert (déjà dans le protocole 2b) et B comme adaptateur possible plus tard derrière le même protocole. A est écarté. Questions 1 et 13.

### 4.3 Un backend par compte

| Option | Pour | Contre |
| --- | --- | --- |
| **A. Un seul backend par compte** : un compte vit soit sur CloudKit, soit sur une boîte aux lettres. Ajouter un premier appareil hors Apple propose de passer le compte sur la boîte aux lettres ; les apps Apple suivent. | Une seule vérité serveur, un seul `base` dans `SyncStore`, la même logique de rebase. La migration est une réinitialisation de zone déjà écrite (`begin_zone_reset`, `finish_full_fetch` renvoie ce que le serveur n'a pas). | Un utilisateur Apple qui ajoute un PC quitte iCloud pour ce compte. |
| B. Double attache : les appareils Apple synchronisent CloudKit et la boîte aux lettres | L'utilisateur garde iCloud. | Deux serveurs hostiles à réconcilier, deux `base`, des conflits entre stockages ; les appareils Apple deviennent des ponts et tout s'arrête quand ils dorment. |
| C. Un appareil Apple fait le pont (CloudKit vers la boîte aux lettres) | Rien ne change pour les autres appareils Apple. | Sync hors Apple seulement quand ce pont tourne ; un point unique de panne. |

**Recommandation : A.** Question 2.

Migration d'un compte (sur un appareil Apple déverrouillé) : choix du serveur (hébergé ou URL self-host), création de la boîte, inscription de l'appareil, envoi complet de `base` et `pending` (réinitialisation de zone vers le nouveau transport), écriture d'un nouvel enregistrement signé `SyncHome` (4.6) dans les deux backends, puis chaque autre appareil Apple lit `SyncHome` dans CloudKit, vérifie la signature, et bascule avec confirmation de l'utilisateur ("Ton coffre se synchronise maintenant avec <serveur>"). CloudKit garde la zone en lecture seule 30 jours, puis l'app propose de l'effacer.

### 4.4 Protocole de la boîte aux lettres

Transport : HTTPS (TLS 1.3, échange hybride `X25519MLKEM768` quand le client et le serveur l'offrent, par `rustls`), corps en postcard versionné, HTTP/2. Le chiffrement de bout en bout ne dépend pas de TLS ; TLS protège les métadonnées et l'authentification des requêtes contre un tiers réseau.

Ressources (version `v1`) :

| Requête | Rôle |
| --- | --- |
| `POST /v1/mailboxes` | Crée une boîte. Hébergé : demande un jeton d'invitation ou un quota (champ `plan` du compte). Rend `mailbox_id` (128 bits aléatoires, sans lien avec l'id du compte) |
| `POST /v1/mailboxes/{m}/credentials` | Inscrit l'identifiant d'un nouvel appareil, sur présentation d'un ticket signé par un identifiant déjà inscrit (4.5) |
| `DELETE /v1/mailboxes/{m}/credentials/{c}` | Retire un identifiant (confort : la coupure réelle est la rotation v2) |
| `GET /v1/mailboxes/{m}/changes?after=<seq>` | Flux de changements : `(server_seq, kind, id, version, size, data)` par pages, `server_seq` strictement croissant par boîte |
| `POST /v1/mailboxes/{m}/commit` | Lot atomique d'écritures conditionnelles : `[(kind, id, expected_version, data | delete)]`. Tout ou rien ; conflit = liste des clés en conflit, rien d'écrit |
| `GET /v1/mailboxes/{m}/records/{kind}/{id}` | Lecture d'un enregistrement |
| `GET /v1/mailboxes/{m}/events` | Flux de notifications (WebSocket ou SSE) : seulement "il y a du nouveau après `seq`" |
| `PUT/GET /v1/rendezvous/{session_id}/{direction}/{n}` | Relais d'appairage (4.7), trames opaques, durée de vie 2 min, sans authentification de boîte |

Authentification des requêtes : chaque appareil a un **identifiant de boîte**, une paire Ed25519 créée sur l'appareil, distincte de ses clés d'appareil de la rotation v2. Chaque requête porte une signature HTTP (RFC 9421) sur la méthode, le chemin, l'empreinte du corps, un horodatage et un nonce ; le serveur refuse au-delà de 5 min de décalage et tout nonce revu. Ce n'est pas une garantie de sécurité des données (le serveur est hostile de toute façon) : c'est ce qui empêche un tiers qui connaît un `mailbox_id` de lire les blobs ou de remplir la boîte. Pourquoi une clé distincte : un identifiant de boîte volé (fichier de configuration, sauvegarde) ne signe ni rotation, ni intro, ni liste ; et le serveur n'apprend aucune clé d'appareil.

Ce que le serveur stocke : boîtes, identifiants (clé publique, date, libellé opaque choisi par le client), enregistrements (`kind`, `id`, `version`, `server_seq`, taille, octets), nonces récents, trames de rendez-vous. Ce qu'il fait respecter : comparaison de version, taille maximale par enregistrement (900 Kio comme aujourd'hui, `MAX_RECORD_BYTES`, pour garder la parité avec CloudKit), quota, débit. Ce qu'il ne fait jamais : interpréter un blob.

Notifications de réveil :

- Bureau : WebSocket tant que l'app tourne.
- Android : message FCM sans contenu ("réveille-toi") envoyé par la boîte hébergée, et UnifiedPush pour les builds sans Google ; repli en interrogation périodique par WorkManager. Question 12.
- Apple sur boîte aux lettres : APNs silencieux sans contenu, repli en récupération à l'ouverture.

Le jeton de notification (FCM, APNs) est une donnée que l'opérateur voit et relie à une boîte. Documenté en 8.

### 4.5 Inscription d'un appareil dans la boîte

Le ticket d'inscription est produit par un appareil déjà inscrit et transmis au nouvel appareil dans le canal d'appairage authentifié par le code court (4.7) :

`EnrollTicket { mailbox_url, mailbox_id, new_credential_pub, expires_at, nonce }`, signé par l'identifiant de boîte de l'approbateur. Le nouvel appareil crée sa paire, envoie sa clé publique dans `ConfirmedWithKey` (champ ajouté en fin de message, voir 5.2), reçoit le ticket dans l'autorisation, et l'utilise une fois. Le serveur vérifie la signature contre un identifiant inscrit et refuse un ticket expiré ou déjà utilisé.

Retrait : l'appareil qui retire un autre appareil (liste signée, puis rotation v2) supprime aussi son identifiant de la boîte. Un serveur hostile peut l'ignorer ; ce n'est pas grave, la rotation v2 a déjà rendu inutile tout ce que l'appareil retiré pourrait lire ensuite (objectif G1).

### 4.6 Quels enregistrements, et comment

Tous les enregistrements synchronisés aujourd'hui par CloudKit passent tels quels, octet pour octet, par la boîte aux lettres :

| Enregistrement | Code | Synchronisé | Remarque |
| --- | --- | --- | --- |
| `AccountParams` (v2, époque signée) | 1 | oui | jamais supprimable par le serveur (refusé par `commit_remote`) |
| `Keyset` | 2 | oui | idem |
| `VaultKey`, `VaultMeta`, `Manifest` | 3, 4, 6 | oui | suppression acceptée seulement pour un coffre marqué supprimé dans la liste signée |
| `Item` | 5 | oui | items avant leur manifeste dans un même lot |
| `RestoreEpoch` | 7 | oui | |
| `DeviceList`, `VaultList` | 8, 9 | oui | contenus en clair (noms d'appareils lisibles par le serveur, limite 2b) |
| Enregistrements de la rotation v2 (lignée, `Intro`, livraison scellée de la Secret Key, accusé de suivi, enregistrements par identité) | nouveaux codes | oui | définis par la spec rotation v2 section 6 ; rien de spécial côté boîte |
| **Nouveau** `SyncHome` | nouveau code | oui, dans l'ancien et le nouveau backend | `{account_id, backend: CloudKit | Mailbox{url, mailbox_id}, seq, prev_hash}`, signé par la clé de signature hybride du compte, chaîné comme les listes ; dit aux appareils où vit le compte, pour qu'un serveur ne puisse pas rediriger un appareil vers une autre boîte sans signature |

Jamais synchronisés : Secret Key, clés d'appareil, identifiant de boîte, `DeviceState`, `ChainState`, `TrustState`, enveloppe biométrique, clés d'appairage du pont navigateur, journaux d'audit, cache d'icônes, charge utile de la montre, état du Travel Mode côté appareil.

Avantage net sur CloudKit : le lot atomique sans limite de 400 enregistrements ou 1,5 Mio supprime le refus d'intégrité transitoire décrit en 10.6 de `docs/security/README.md` (un appareil qui récupère entre deux lots).

### 4.7 Moteur de sync en Rust

Aujourd'hui le tour de sync (récupérer, `stage_remote`, `commit_remote`, rebase si déverrouillé, `pending_changes`, envoi, `mark_pushed`) est orchestré par le coordinateur Swift. Pour ne pas l'écrire trois fois (Swift, Kotlin, Tauri), il passe en Rust :

- Nouvelle crate `onepass-sync` : `SyncDriver` qui fait un tour complet sur un trait `Transport { fetch_changes, commit, ... }`, un tour à la fois (la règle "le rebase ne tourne jamais en même temps qu'une réconciliation" reste garantie à un seul endroit). Implémentation `MailboxTransport` en Rust (`hyper` + `rustls`).
- Exposé par `onepass-ffi` (`SyncDriver`, `run_round`, état et erreurs) pour Swift et Kotlin, utilisé directement par le bureau.
- CloudKit reste un transport Swift : soit le coordinateur actuel inchangé, soit, plus tard, un `Transport` implémenté par Swift en interface de rappel. Pas de réécriture imposée aux apps Apple tant que le compte reste sur CloudKit.
- Nouvelle crate serveur `onepass-mailbox` (`axum`, `sqlx`, SQLite ou Postgres), AGPL comme le reste, image Docker, sans dépendance au core autre que les types du protocole (`onepass-mailbox-proto`, partagé avec le client).

### 4.8 Ce que voit la boîte aux lettres

Comme CloudKit (10.5 de la doc sécurité) : nombre d'enregistrements par genre, versions, tailles arrondies, numéros de séquence des manifestes, dates et rythme des écritures, noms d'appareils de la liste signée. En plus : adresses IP des clients, identifiants de boîte, jetons de notification, `mailbox_id`. En moins : aucun identifiant Apple.

Masquer le genre des enregistrements (nom chiffré) est possible mais casse l'ordre "items avant manifeste" que le serveur n'a pas besoin de connaître ; la parité avec CloudKit est gardée en v1. Question 14.

## 5. Appairage d'un appareil hors Apple

### 5.1 Ce qui ne change pas

Le protocole du jalon 2b (section 5) est indépendant de l'OS et du transport par construction (ruling B9 et 5.3 "préparation hors Apple") : QR `OPPAIR1:` avec le hash de la clé éphémère hybride, `Hello`, `KeyExchange`, code court à 6 chiffres dérivé de toute la transcription, `Confirmed`, `Grant`, trames scellées avec compteurs par sens. La rotation v2 y ajoute `ConfirmedWithKey` (clé publique d'appareil + preuve de possession) et `Grant::FullV2` (instantané de confiance : lignée, roster, approbateur), puis l'écriture d'un `Intro`. Tout cela vit dans le Rust et sert tel quel sur Android, Windows et Linux.

### 5.2 Ajouts au protocole

- `ConfirmedWithKey` gagne, en fin de message, `mailbox_credential: Option<Ed25519Public>` (absent pour un compte sur CloudKit).
- `FullGrantV2` gagne, en fin de structure, `sync: Option<SyncHomeRecord>` et `enroll: Option<EnrollTicket>`. Le nouvel appareil vérifie `SyncHome` contre la clé de signature du compte reçue dans l'instantané, avant de contacter le serveur.
- `DeviceEntry.kind` gagne `Android`, `Windows`, `Linux` (variantes en fin d'enum) pour l'affichage et la politique (par exemple : pas d'approbation depuis un bureau sans caméra).

Aucun message existant ne change de forme ; un approbateur ancien qui ne connaît pas ces champs reste un pair "legacy" au sens de la rotation v2 section 15, et l'app lui demande de se mettre à jour avant d'ajouter un appareil hors Apple.

### 5.3 Transports

Bonjour avec AWDL n'existe que sur Apple. Trois transports, tous porteurs des mêmes trames opaques :

| Transport | Où | Limites |
| --- | --- | --- |
| **T-LAN : TCP sur le réseau local, annoncé en DNS-SD** `_onepass-pair._tcp`, nom = `session_id` en hexadécimal (déjà le cas en 2b) | iPhone (Network.framework sans AWDL vers un pair non Apple), Android (`NsdManager`), Windows et Linux (crate `mdns-sd`, ou Avahi) | Échoue sur les réseaux qui isolent les clients (Wi-Fi d'hôtel, de bureau, invité) ; pare-feu Windows à ouvrir pour le port éphémère (règle posée par l'installateur MSIX) |
| **T-RDV : rendez-vous par la boîte aux lettres** (`/v1/rendezvous/{session_id}`) | Partout où l'un des deux a Internet | Le serveur voit deux adresses IP et le moment de l'appairage ; il ne peut rien lire ni substituer (clé engagée par le QR, code court) |
| T-BLE : Bluetooth LE | Plus tard | Demande des permissions de plus ; utile comme preuve de proximité (architecture 4.9 point 6), pas avant |

Ordre d'essai : T-LAN pendant 5 s, puis T-RDV si un serveur est connu (compte sur boîte aux lettres, ou serveur hébergé par défaut pour le seul rendez-vous). Le `session_id` est déjà dans le QR : le QR ne change pas. Ajouter T-RDV à un compte CloudKit (premier appareil hors Apple) utilise le serveur hébergé pour le seul rendez-vous ; question 1.

Proximité : avec T-RDV, la proximité n'est plus garantie par le transport. La défense contre "scanne ce QR qu'on t'a envoyé" reste celle du 2b : le QR est scanné par l'app (jamais l'appareil photo du système), l'écran d'approbation affiche type, nom et mode, l'avertissement, et le code court doit être lu sur l'écran du nouvel appareil. Ajout pour T-RDV : l'écran d'approbation dit "Cet appareil n'est pas sur ton réseau" quand T-LAN a échoué, et demande de taper les 6 chiffres lus sur l'autre écran (au lieu d'un simple "identiques") : un attaquant à distance doit alors aussi faire lire son écran à l'utilisateur.

### 5.4 Déroulés

1. **PC Windows ou Linux, compte sur l'iPhone.** Le PC affiche le QR. L'iPhone (Réglages > Appareils > Ajouter) scanne, Face ID, code court, seconde présence. Si le compte est encore sur CloudKit, l'iPhone propose d'abord la migration (4.3) ; sans migration, le PC reçoit un instantané unique (transfert sans sync, mode "lecture hors ligne", question 3 du backlog tranchée en 5.5). Le PC reçoit Secret Key, instantané, roster et lignée, `SyncHome` et ticket, range ses secrets (section 6), demande le mot de passe maître.
2. **Téléphone Android.** Même chose, Android affiche le QR (l'iPhone reste l'approbateur, ruling B13). À partir du jalon X6 (section 10), un Android déverrouillé peut aussi approuver (il a un scanner).
3. **Session publique** (architecture 4.10) depuis un PC public : le PC n'a pas besoin d'être inscrit ; il faut seulement une app OnePass installée, ou plus tard l'extension autonome. T-LAN ou T-RDV, aucune clé de coffre ne part, rien sur le disque.

### 5.5 Transfert unique ou sync continue

Les deux, à des niveaux différents : l'instantané de l'autorisation (50 Mio au plus, ruling B10) donne un coffre utilisable tout de suite et hors ligne ; la sync continue arrive avec la boîte aux lettres. Un appareil hors Apple sur un compte resté sur CloudKit est en lecture seule et l'affiche ("Synchronisation impossible : ton compte est sur iCloud") : il ne peut pas écrire sans backend commun, et une écriture locale jamais envoyée serait une perte silencieuse plus tard (objectif G4 de la rotation v2).

## 6. Stockage sûr par OS

### 6.1 Ce qu'il faut protéger sur l'appareil

| Secret | Usage | Biométrie |
| --- | --- | --- |
| Secret Key | dérivation 2SKD à chaque déverrouillage par mot de passe | non |
| Clés d'appareil (signature et KEM hybrides) | appairage, rotation, suivi, intro | non (présence déjà exigée par chaque flux) |
| Enveloppe biométrique du keyset (AUK ou keyset déverrouillé) | déverrouillage rapide | oui, à chaque usage |
| Identifiant de boîte (Ed25519) | requêtes à la boîte aux lettres | non, et utilisable appareil verrouillé pour la sync en arrière-plan |
| Clés d'appairage du pont navigateur | sessions avec l'extension | non |

Règle commune : une abstraction Rust `DeviceSecrets` (lire, écrire, effacer, envelopper, désenvelopper) dans une nouvelle crate `onepass-platform`, implémentée en Rust sur Windows et Linux et par interface de rappel Kotlin sur Android. Le Rust ne reçoit jamais une clé matérielle, seulement le résultat d'une opération.

Clés d'appareil post-quantiques : sur Apple, la moitié ML-DSA-87 et ML-KEM-1024 vit dans la Secure Enclave (rotation v2, ruling O3). Ailleurs :

- Android 17 expose ML-DSA-65 et ML-DSA-87 dans le Keystore (clés en matériel sécurisé) ; ML-KEM n'est pas exposé aux apps. Sur Android 17+, la moitié ML-DSA-87 est une clé Keystore ; la moitié ML-KEM-1024, Ed25519 et X25519 sont des clés logicielles enveloppées par une clé AES Keystore.
- Windows : CNG offre ML-KEM et ML-DSA depuis novembre 2025, mais en logiciel ; le TPM n'en a pas. Les moitiés post-quantiques sont logicielles, enveloppées par une clé TPM.
- Linux : logicielles, enveloppées (6.4).

Le format sur le fil ne change pas (un vérificateur ne distingue pas une clé matérielle d'une clé logicielle, rotation v2 5.1). La faiblesse relative est documentée en 8.

### 6.2 Android

- **Clé d'enveloppe de l'appareil** (Secret Key, clés d'appareil, identifiant de boîte) : AES-256-GCM dans l'Android Keystore, `setIsStrongBoxBacked(true)` et repli TEE sur `StrongBoxUnavailableException`, `setUnlockedDeviceRequired(true)` sauf pour l'identifiant de boîte (la sync tourne écran verrouillé, comme `SyncStoreHandle` aujourd'hui). Non exportable. Chiffrés rangés dans `noBackupFilesDir`, `android:allowBackup="false"` et règles d'extraction qui excluent tout.
- **Clé biométrique** : AES-256-GCM, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` (authentification à chaque usage, ouverte par un `CryptoObject` passé à `BiometricPrompt`), `setInvalidatedByBiometricEnrollment(true)` : un nouveau doigt invalide la clé et le mot de passe maître est redemandé, comme `.biometryCurrentSet` sur Apple. Classe 3 seulement (biométrie forte).
- **Attestation de clé** : lue et journalisée localement (StrongBox ou TEE, état du démarrage vérifié), affichée dans Réglages > Sécurité ; pas de refus sur un appareil non certifié (le fondateur peut le décider : question 15).
- Mot de passe maître redemandé tous les 14 jours et après redémarrage, comme sur Apple.

### 6.3 Windows

| Option pour le stockage des secrets | Verdict |
| --- | --- |
| DPAPI utilisateur (`CryptProtectData`) | Tout processus de la même session peut déchiffrer ; ne lie pas à la machine de façon matérielle. Refusé seul. |
| **Clé RSA ou ECC non exportable dans le TPM par le Microsoft Platform Crypto Provider (NCrypt), qui enveloppe une clé AES de fichier** | Liée à la machine : le fichier copié ailleurs ne s'ouvre pas. Un logiciel malveillant de la même session peut encore demander une opération (hors périmètre : appareil compromis). Retenu, avec DPAPI en repli sur une machine sans TPM utilisable (affiché). |
| Credential Locker (`PasswordVault`) | Itinérant selon la configuration du compte Microsoft ; refusé pour la Secret Key. |

Déverrouillage par Windows Hello :

| Option | Verdict |
| --- | --- |
| **A. WebAuthn PRF (`hmac-secret`) avec l'authentificateur de plateforme Windows Hello** : une sortie PRF déterministe par identifiant et sel, sous geste Hello, enveloppe l'AUK | Retenue. Signalée comme fonctionnelle depuis Windows 11 25H2 (WebAuthn API version 8) ; à prouver sur matériel au jalon X3, avec test que la sortie est stable entre deux gestes. |
| B. `KeyCredentialManager` : signer un défi fixe et dériver une clé de la signature | Seulement si la signature est déterministe : la documentation annonce du RSA-PSS, qui est aléatoire par nature. Test d'acceptation au jalon X3 ; abandon si deux signatures diffèrent. |
| C. `UserConsentVerifier` + DPAPI | Le geste n'est pas lié cryptographiquement à la clé : refusé. |

Sans A ni B : mot de passe maître seulement, et l'app le dit.

### 6.4 Linux

- **Secret Service** (GNOME Keyring, KWallet, KeePassXC) par D-Bus, déjà utilisé par la CLI (`dbus-secret-service`). Limite connue : une collection déverrouillée est lisible par tout processus de la session.
- **Scellement TPM2** quand `/dev/tpmrm0` est accessible : une clé AES scellée au TPM (`tss-esapi`, sans politique PCR en v1 pour survivre aux mises à jour du noyau, avec `authValue` tiré du Secret Service). La Secret Key et les clés d'appareil sont chiffrées par cette clé, le chiffré est dans `~/.local/share/onepass` (0600). Un vol du dossier personnel ou de la base du Secret Service ne suffit plus : il faut aussi la machine.
- Sans TPM : Secret Service seul, affiché dans Réglages > Sécurité.
- Sans Secret Service (session sans bus, serveur) : refus, comme la CLI ; l'option "Secret Key en clair" n'existe pas dans l'app de bureau.
- **Biométrie** : pas de fprintd (polkit ne lie aucune clé au geste). Option "clé de sécurité" : sortie `hmac-secret` d'une clé FIDO2 par `libfido2` (même idée que le coffre YubiKey du backlog), qui enveloppe l'AUK. Question 9.
- Flatpak plus tard : le portail `org.freedesktop.portal.Secret` fournit un secret maître par app, à passer dans une KDF ; c'est le remplaçant du Secret Service dans le bac à sable.

## 7. Autofill

### 7.1 Android

- **Autofill Framework** (`AutofillService`, API 26+, servi à partir d'Android 10) : formulaires des apps et des navigateurs. Suggestions en ligne dans le clavier (`InlineSuggestionsRequest`, API 30+) ; à défaut, liste déroulante. Les données servies : seulement identifiants et titres tant que l'utilisateur n'a pas choisi ; le secret part dans le `Dataset` après authentification (`setAuthentication` avec un `IntentSender` vers l'activité de déverrouillage).
- **Chrome** : depuis Chrome 135 (avril 2025), Chrome sur Android 14+ remplit par un service tiers quand l'utilisateur choisit "Remplissage automatique avec un autre service" ; le mode de compatibilité a disparu à l'été 2025. Chrome 142 a introduit un nouveau modèle de permission pour ces services, à étudier au jalon X5. Firefox et les autres navigateurs fournissent `webDomain` dans la structure.
- **Credential Manager, côté fournisseur** (`CredentialProviderService`, Android 14+) : mots de passe et passkeys dans la feuille système, création et connexion. Le service répond aux requêtes "Begin" avec des entrées sans secret ; l'activité ouverte par le `PendingIntent` (`FLAG_MUTABLE`, jamais `FLAG_ONE_SHOT`) déverrouille, signe ou crée la passkey dans le core (module `webauthn` existant) et rend la réponse. Extension PRF des passkeys servie par le core quand l'appelant la demande.
- **Credential Exchange** (FIDO CXP/CXF) : import et export de bout en bout avec les autres gestionnaires par `ProviderEventsManager` (`registerExport`, `importCredentials`), livré par Google Play services 26.21 depuis juin 2026. Même format que l'import Credential Exchange déjà prévu sur Apple.
- **Hameçonnage** (reprise de 14.6 de la doc sécurité) :
  - App : correspondance par nom de paquet **et** empreinte du certificat de signature, vérifiée contre le `assetlinks.json` du domaine (Digital Asset Links), cache chiffré local. Un nom de paquet seul ne suffit jamais (un autre développeur peut publier un paquet au nom proche, pas avec la même signature).
  - Navigateur : `webDomain` accepté seulement si l'app appelante est un navigateur connu par sa signature (liste embarquée, comme le font les gestionnaires existants) ; sinon traité comme une app.
  - Public Suffix List, jamais de remplissage dans un champ d'un autre domaine, jamais en HTTP.
- **Écrans** : `setFilterTouchesWhenObscured(true)` sur les boutons d'approbation (contre le recouvrement), `FLAG_SECURE`, mot de passe maître en `textPassword` avec `IME_FLAG_NO_PERSONALIZED_LEARNING`.

### 7.2 Windows

- **Navigateurs** : l'extension existante (AGPL, `extension/`) en mode "app", comme sur Mac : native messaging vers l'app de bureau. Hôte `onepass-relay` porté sur Windows : manifeste déclaré dans le registre (`HKCU\Software\Google\Chrome\NativeMessagingHosts\me.somalabs.onepass` et équivalents Edge, Firefox), connexion à l'app par un canal nommé dont l'ACL n'admet que l'utilisateur courant. Vérification du pair des deux côtés : `GetNamedPipeClientProcessId` puis chemin de l'image et signature Authenticode de notre éditeur (`WinVerifyTrust`), équivalent Windows du jeton d'audit de `onepass-peer`. Protocole du pont (appairage, session chiffrée, politique de divulgation) inchangé.
- **Passkeys système** : plugin d'authentificateur WebAuthn de Windows 11 (`IPluginAuthenticator`, `WebAuthNPluginAddAuthenticator`), disponible pour tous depuis la mise à jour de sécurité de novembre 2025 (1Password et Bitwarden au lancement). Les requêtes WebAuthn de Windows (navigateurs, apps) arrivent au serveur COM de l'app, qui ouvre la session et signe dans le core ; Windows Hello protège le geste.
- **Apps de bureau** : Quick Access, raccourci global (`RegisterHotKey`, par défaut `Ctrl+Alt+Espace`), recherche, copie, ou saisie dans l'app au premier plan par `SendInput` avec confirmation de la fenêtre cible (titre et exécutable affichés). Pas d'API système d'autofill de mots de passe pour les tiers sur Windows.
- **Agent SSH** : canal nommé `\\.\pipe\openssh-ssh-agent` (agent OpenSSH de Windows), après arrêt du service `ssh-agent` système avec l'accord de l'utilisateur, ou canal propre déclaré par `IdentityAgent`. Mêmes règles que 9.3 de l'architecture.

### 7.3 Linux

- **Navigateurs** : extension + native messaging, manifestes dans les dossiers de Chrome, Chromium, Brave, Firefox ; app jointe par socket Unix (0600) dans `$XDG_RUNTIME_DIR/onepass/`, pair vérifié par `SO_PEERCRED` puis `/proc/<pid>/exe` contre le chemin installé par le paquet (déjà la branche Linux de `onepass-peer`, non compilée dans les tests macOS aujourd'hui).
- **Passkeys** : pas d'API système ; l'extension intercepte WebAuthn dans la page (comme prévu en 6.3 de l'architecture).
- **Quick Access** : portail `org.freedesktop.portal.GlobalShortcuts` sous Wayland, raccourci X11 sinon. Copie plutôt que saisie : la saisie synthétique sous Wayland passe par le portail `RemoteDesktop`, trop large pour cet usage. Presse-papiers marqué `x-kde-passwordManagerHint: secret` pour que les gestionnaires d'historique l'ignorent, effacé après 90 s.
- **Agent SSH** : socket Unix, `SSH_AUTH_SOCK` ou `IdentityAgent`.

### 7.4 Extension en mode autonome (R-15)

Le mode autonome prévu (core en WASM, CloudKit JS) est remplacé : sur une machine où l'app de bureau est installée, l'extension passe toujours par l'app. Le mode autonome reste utile pour un poste où l'on ne peut rien installer ; il se refera plus tard sur la boîte aux lettres (sans CloudKit JS), en session publique déléguée d'abord. Hors des jalons de cette spec.

## 8. Modèle de menace : ce qui change

Inchangé : T1 (appareil retiré + serveur hostile) et T2 (serveur seul) de la rotation v2, pages web hostiles, agents MCP peu fiables, appareil compromis au niveau système hors périmètre.

| Nouveau risque | Défense | Reste |
| --- | --- | --- |
| La boîte aux lettres hébergée par Soma devient une cible (fuite de la base, contrainte légale) | Elle ne détient que des blobs chiffrés et signés ; rien de ce qu'elle a ne déchiffre ni ne forge (T2) | Adresses IP, rythme d'usage, jetons FCM/APNs, nombre d'items par coffre ; rétention minimale à écrire dans la politique de confidentialité |
| Redirection vers une autre boîte (serveur ou réseau qui sert une fausse URL) | `SyncHome` signé par le compte, chaîné ; changement confirmé par l'utilisateur | Déni de service (retenir tout), comme aujourd'hui |
| Rendez-vous d'appairage à distance (T-RDV) | Clé éphémère engagée par le QR, code court tapé (5.3) | Ingénierie sociale d'un utilisateur qui lit et tape un code venu d'un écran inconnu |
| Usurpation DNS-SD sur le réseau local | Même défense : le transport n'est jamais de confiance | Aucun |
| Moitiés post-quantiques des clés d'appareil en logiciel (Windows, Linux, Android < 17) | Enveloppées par une clé matérielle (TPM, Keystore) quand elle existe | Un logiciel malveillant sur l'appareil déverrouillé peut s'en servir ; un fichier copié ailleurs ne sert à rien seulement si la clé d'enveloppe est matérielle |
| Android : app qui se fait passer pour un site, superposition, service d'accessibilité malveillant, clavier tiers | Digital Asset Links avec certificat, filtre des touches masquées, `FLAG_SECURE`, apprentissage du clavier désactivé | Un service d'accessibilité accordé par l'utilisateur voit l'écran : documenté comme appareil compromis |
| Windows et Linux : processus de la même session | TPM pour lier à la machine, pair vérifié par signature (Windows) ou chemin root (Linux) | Un processus de la même session peut demander une opération au TPM ou lire le Secret Service déverrouillé ; X11 permet l'espionnage du clavier (Wayland recommandé) |
| Moteur web de l'app de bureau (WebView2, WebKitGTK) | CSP stricte, isolation, aucune ressource distante, secrets jamais dans le moteur web sauf affichage | Une faille du moteur avec du contenu d'item malveillant (notes) : surface réduite, pas nulle |
| Chaîne de livraison : paquets Linux, MSIX, APK | Builds reproductibles (core déjà vérifié en CI), signatures, dépôts signés | Compromission d'une clé de signature |
| Notifications FCM | Messages sans contenu | Google voit qu'une boîte se réveille |
| Rotation v2 sur un appareil qui n'a pas de Secure Enclave | Aucune règle de la rotation ne dépend du matériel (vérification identique) | Clé d'appareil volée = signature possible en son nom tant que l'appareil n'est pas retiré (inchangé dans son principe) |

La doc `docs/security/README.md` gagnera une section par jalon livré, comme pour les jalons Apple.

## 9. Ce que deviennent les crates

| Crate | Changement |
| --- | --- |
| `onepass-core` | `RecordKind::SyncHome` ; nouveaux genres de `DeviceEntry.kind` ; aucun changement de crypto |
| `onepass-ffi` | Cibles Android ; `SyncDriver` ; interfaces de rappel `DeviceSecrets` et biométrie ; champs ajoutés à l'appairage |
| `onepass-sync` (nouvelle) | Boucle de sync, trait `Transport`, `MailboxTransport` |
| `onepass-mailbox-proto` (nouvelle) | Messages du protocole, décodage strict, cibles de fuzzing |
| `onepass-mailbox` (nouvelle, binaire serveur) | `axum`, SQLite ou Postgres, image Docker |
| `onepass-platform` (nouvelle) | `DeviceSecrets` Windows (NCrypt, DPAPI) et Linux (Secret Service, TPM2), Windows Hello PRF, FIDO2 `hmac-secret` |
| `onepass-relay` | Port Windows (canal nommé, Authenticode) et Linux (socket Unix, `SO_PEERCRED`) ; son rôle ne change pas (native messaging seulement) |
| `onepass-peer` | Branche Windows ; tests Linux en CI Linux |
| `onepass-ssh-agent` | Canal nommé Windows |
| `desktop/` (nouveau dossier) | App Tauri 2 (backend Rust, interface TypeScript) |
| `android/` (nouveau dossier) | Projet Gradle |

## 10. Jalons

Chaque jalon a sa propre spec détaillée, son plan, sa revue de sécurité et un red team avant la revue finale. Chacun est livrable seul et apporte quelque chose à un utilisateur.

| Jalon | Contenu | Ce qu'on livre | Dépend de |
| --- | --- | --- | --- |
| **X0. Core portable** | CI qui construit et teste le workspace sur Windows (x86_64 et aarch64 MSVC), Linux (x86_64 et aarch64 gnu) et Android (cargo-ndk, tests sur émulateur) ; `aws-lc-rs` construit partout (CMake, NASM sur Windows) ; `VirtualLock` à côté de `mlock` ; liaisons Kotlin générées et testées sur JVM ; `DeviceSecrets` Linux et Windows | CLI de développement publiée pour Windows et Linux (coffre local, sans sync), comme la CLI Mac actuelle | rien |
| **X1. Boîte aux lettres** | `onepass-mailbox`, `-proto`, `onepass-sync`, `SyncHome`, migration d'un compte Apple de CloudKit vers une boîte, transport mailbox dans les apps Apple, notifications APNs | Apple uniquement : sync self-hostée, sans iCloud, pour qui le veut | rotation v2 livrée (pour ne pas migrer deux fois les enregistrements de compte) |
| **X2. App de bureau** | Tauri 2 sur Windows et Linux : création de compte, déverrouillage par mot de passe, coffres, éditeurs des 26 types, sync par boîte aux lettres, appairage comme nouvel appareil (T-LAN, T-RDV) depuis un iPhone, retrait, suivi de rotation, MSIX, `.deb`, `.rpm`, AppImage | Un utilisateur iPhone a son coffre sur son PC | X1 |
| **X3. Intégrations bureau** | Pont navigateur Windows et Linux, Windows Hello (PRF), plugin passkeys Windows, Quick Access, agent SSH, CLI qui passe par l'app, clé FIDO2 sur Linux | L'extension Chrome, Edge et Firefox remplit sur Windows et Linux ; passkeys système sur Windows | X2 |
| **X4. App Android** | Kotlin + Compose : compte, déverrouillage, biométrie, coffres, éditeurs, sync, appairage comme nouvel appareil, Keystore/StrongBox | Coffre complet sur Android, sans autofill | X1 (X2 pas nécessaire) |
| **X5. Autofill Android** | `AutofillService`, suggestions en ligne, Credential Manager (mots de passe et passkeys), CXP, Digital Asset Links | Remplissage dans Chrome et les apps, passkeys | X4 |
| **X6. Appareils hors Apple de plein droit** | Android approbateur (scanner), session publique servie depuis Android, rotation lancée depuis un appareil hors Apple, compte créé hors Apple (sans aucun appareil Apple) | OnePass sans Apple du tout | X3, X5 |

Ordre recommandé : X0, X1, X2, X3, X4, X5, X6 (bureau avant Android), parce que le bureau lie le core sans FFI (coût le plus bas), débloque l'extension sur Windows et Linux (le cas le plus demandé par un utilisateur d'iPhone avec un PC), et qu'Android demande une nouvelle compétence et l'autofill le plus délicat. X4 peut démarrer en parallèle de X2 dès X1 livré si une deuxième personne est disponible. Question 3.

## 11. Stratégie de test

- **Core sur chaque cible** : `cargo test --workspace` sur les runners Windows et Linux ; sur Android, tests du core exécutés dans l'émulateur (binaires de test poussés par `cargo-ndk`) pour les parties qui dépendent de l'OS (aléa, mémoire verrouillée, horloge). Vecteurs NIST et test différentiel `aws-lc-rs` contre `libcrux` sur chaque cible (même sortie exigée).
- **Boîte aux lettres hostile** : la suite `sync_two_devices` rejouée contre un vrai serveur `onepass-mailbox` en HTTP, avec un mandataire hostile entre le client et le serveur qui rejoue, retient, réordonne, injecte, coupe entre l'envoi et la confirmation, sert un vieux `SyncHome`, une autre boîte, un lot partiel. Chaque classe d'attaque de l'étude ETH Zurich / USI reste un test (architecture section 12). Tests de propriétés sur le serveur (atomicité des lots, monotonie de `server_seq`, conflits). Fuzzing de tous les décodeurs du protocole et des tickets.
- **Appairage croisé** : en mémoire dans le Rust (inchangé), puis deux processus sur T-LAN et sur T-RDV, puis une matrice sur matériel réel avant chaque livraison : iPhone vers Pixel, iPhone vers Windows 11, iPhone vers Ubuntu et Fedora, réseau qui isole les clients (T-RDV seul), QR expiré, code faux, homme du milieu sur le relais.
- **Modèle formel** : le modèle ProVerif de l'appairage (`bridge.pv`) et de la rotation (`rotation.pv`) ne change pas de propriétés ; ajouter le relais T-RDV comme canal public contrôlé par l'attaquant, `SyncHome`, et le ticket d'inscription (le serveur ne doit pas pouvoir inscrire un identifiant sans ticket signé), avec un contrôle négatif (ticket non signé).
- **Android** : JUnit et Robolectric pour la logique Kotlin ; tests instrumentés pour le Keystore (StrongBox sur un Pixel réel, TEE sur émulateur), l'invalidation par nouvelle empreinte, le refus de la biométrie faible ; autofill testé par une app cible et des pages piégées dans une WebView et dans Chrome (domaine sosie, iframe d'un autre site, page HTTP, app au nom de paquet proche avec une autre signature) ; Credential Manager testé par une app "partie de confiance" de test et webauthn.io.
- **Bureau** : tests Rust des commandes IPC (aucune commande ne rend un secret sans geste), tests de bout en bout par `tauri-driver` (WebDriver) sur Windows et Linux ; CSP vérifiée par un test qui injecte un item avec du HTML et du JavaScript dans toutes les vues. Secret Service en CI par `gnome-keyring-daemon` dans `dbus-run-session` ; TPM par `swtpm`. Windows Hello, plugin passkeys et TPM réel : liste de vérification manuelle sur machine physique, résultats consignés dans la spec du jalon.
- **Extension** : la suite Playwright existante rejouée contre l'app de bureau sur Windows et Linux (pont réel au lieu de l'hôte de dev).
- **Builds** : reproductibles pour le core et l'APK (vérification par un second build en CI), `cargo-deny`, `cargo-audit`, `cargo-vet` (déjà en place) étendus aux nouvelles crates et aux dépendances Tauri.

## 12. Hors périmètre

Web app ; extension autonome sans app (7.4) ; partage entre personnes ; iPad ou Mac comme approbateurs (ruling B13 inchangé) ; Wear OS ; ChromeOS au-delà de ce que donne l'app Android ; masquer le genre des enregistrements au serveur (question 14) ; adaptateur WebDAV/S3 (4.2 B) ; Bluetooth LE.

## 13. Risques

- **Windows Hello PRF** : signalé par des tests d'utilisateurs et des notes de navigateurs, pas encore par une documentation Microsoft claire. Si X3 ne le prouve pas sur matériel, Windows n'a que le mot de passe maître.
- **WebKitGTK** : versions en retard sur certaines distributions LTS ; une faille non corrigée vise directement l'app. Version minimale exigée au démarrage.
- **Chrome Android** : le nouveau modèle de permission (Chrome 142) peut changer ce qu'un service tiers reçoit.
- **Exploitation de la boîte hébergée** : coût, abus, disponibilité ; il faut un tableau de bord et une astreinte légère avant d'ouvrir l'inscription.
- **Marque** : "OnePass" sur le Play Store et le Microsoft Store expose plus encore la proximité avec 1Password (section 15 de l'architecture).
- **Licence** : AGPL-3.0 avec CLA sur le Play Store et le Microsoft Store, à confirmer comme pour l'App Store.

## 14. Questions ouvertes pour le fondateur

1. **Qui héberge la boîte aux lettres ?** Soma héberge une instance (gratuite avec quota, champ `plan`) et le code reste self-hostable, ou self-host seulement. Je prendrais : les deux, instance Soma par défaut, URL self-host en option à la création de la boîte.
2. **Un backend par compte ou double attache ?** Je prendrais : un seul backend par compte ; ajouter un appareil hors Apple propose de passer le compte entier sur la boîte aux lettres (4.3 A).
3. **Bureau ou Android d'abord ?** Je prendrais : bureau (X2, X3) puis Android (X4, X5), Android en parallèle si une deuxième personne arrive.
4. **Interface de bureau : Tauri 2 ou Slint ?** Je prendrais : Tauri 2 avec les règles de 3.2, Slint en repli si la revue de sécurité refuse le moteur web.
5. **Premiers paquets Linux ?** Je prendrais : `.deb` et `.rpm` signés avec dépôts, AppImage en plus, Flatpak quand le portail de native messaging sera livré.
6. **Distribution Windows ?** Je prendrais : MSIX signé en téléchargement direct et winget d'abord, Microsoft Store ensuite.
7. **Distribution Android ?** Je prendrais : Play Store et APK signé sur GitHub ; F-Droid ensuite, avec UnifiedPush à la place de FCM.
8. **Un appareil hors Apple peut-il approuver un nouvel appareil et lancer une rotation ?** Je prendrais : oui, au jalon X6, Android d'abord (il a un scanner) ; un bureau ne fait qu'être ajouté.
9. **Biométrie sur Linux ?** Je prendrais : aucune (pas de fprintd), clé FIDO2 `hmac-secret` en option.
10. **Licence AGPL + CLA sur le Play Store et le Microsoft Store** : je prendrais : garder AGPL-3.0-or-later avec le CLA déjà en place, après le même avis juridique que pour l'App Store.
11. **Versions minimales ?** Je prendrais : Android 10 (API 29) pour l'app, fonctions Credential Manager sur Android 14+ ; Windows 11 seulement ; Ubuntu 24.04, Debian 13 et Fedora 42 ou plus récents.
12. **Réveil de la sync sur Android ?** Je prendrais : FCM sans contenu sur le Play Store, UnifiedPush sur F-Droid, interrogation périodique en repli.
13. **CloudKit Web Services comme solution d'attente pour Windows et Linux ?** Je prendrais : non (connexion Apple ID dans un navigateur, ADP affaibli, jeton par aller-retour).
14. **Masquer au serveur le genre des enregistrements ?** Je prendrais : parité avec CloudKit en v1, à revoir après l'audit externe.
15. **Refuser un appareil Android sans attestation matérielle valable ?** Je prendrais : non, afficher l'état dans Réglages > Sécurité sans bloquer.
16. **Rendez-vous d'appairage pour un compte encore sur CloudKit** (premier appareil hors Apple) : passer par l'instance Soma même si le compte n'y vit pas ? Je prendrais : oui, pour le seul rendez-vous (trames opaques, 2 min), avec mention à l'écran.

## Sources

Consultées le 2026-10-30.

- Android, fournisseur Credential Manager : https://developer.android.com/identity/sign-in/credential-provider
- Android, Credential Manager : https://developer.android.com/identity/sign-in
- Android, `BiometricPrompt.CryptoObject` et clés par usage : https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject
- Android 17 et ML-DSA dans le Keystore (blog Google) : https://blog.google/security/security-for-the-quantum-era-implementing-post-quantum-cryptography-in-android/
- Android 17, CXP/CXF et `ProviderEventsManager` : https://www.corbado.com/blog/android-17-passkeys
- Bitwarden, portabilité des passkeys (CXP) : https://bitwarden.com/de-de/blog/security-vendors-join-forces-to-make-passkeys-more-portable-for-everyone/
- Chrome Android et services d'autofill tiers (Chrome 135) : https://9to5google.com/2025/02/07/chrome-autofill-password-manager/
- Windows, gestionnaires de passkeys tiers (documentation) : https://learn.microsoft.com/windows/apps/develop/security/third-party
- Windows, exemple Passkey Manager (`IPluginAuthenticator`) : https://learn.microsoft.com/es-es/samples/microsoft/windows-classic-samples/passkeymanager
- Windows, disponibilité générale en novembre 2025 : https://www.heise.de/en/news/Microsoft-enables-external-passkey-management-in-Windows-11-11075433.html et https://petri.com/windows-11-1password-bitwarden-passkey-support/
- Windows, `KeyCredentialManager` : https://learn.microsoft.com/en-us/uwp/api/Windows.Security.Credentials.KeyCredentialManager
- Windows, identité de paquet et `RequestDeriveSharedSecretAsync` : https://learn.microsoft.com/en-us/answers/questions/6016919/how-do-i-construct-encryptedrequest-for-keycredent
- Windows Hello et PRF (rapports de tests, 25H2) : https://community.bitwarden.com/t/encryption-prf-via-windows-hello-passkey/94236 et https://www.corbado.com/blog/passkeys-prf-webauthn
- Windows, ML-KEM et ML-DSA dans CNG : https://strathweb.com/2025/08/ml-kem-and-ml-dsa-post-quantum-cryptography-in-windows/ et https://www.encryptionconsulting.com/microsoft-pqc-roadmap-windows-11-windows-server-2025/
- CloudKit Web Services, authentification : https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/CloudKitWebServicesReference/SettingUpWebServices.html et https://developer.apple.com/forums/thread/119159
- Tauri 2, motif d'isolation : https://v2.tauri.app/de/concept/inter-process-communication/isolation/
- Tauri, versions : https://en.wikipedia.org/wiki/Tauri_(software_framework)
- Linux, portail Secret : https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html
- Linux, native messaging en Flatpak (proposition de portail) : https://github.com/flatpak/xdg-desktop-portal/issues/655
- Linux, `systemd-creds` et TPM2 : https://www.man7.org/linux/man-pages/man1/systemd-creds.1.html
- UniFFI et Android (cargo-ndk, liaisons Kotlin) : https://docs.jans.io/stable/cedarling/uniffi/cedarling-android

## Décisions du fondateur (2026-10-30)

Réponses du fondateur marquées **(fondateur)**. Les autres sont une première passe de Claude, à confirmer, marquées **(première passe)**. Une décision ici prime sur le texte de la spec ; les sections touchées sont à réécrire au prochain passage.

1. **Hébergement de la boîte aux lettres : Supabase (fondateur).** L'instance Soma tourne sur Supabase : Postgres pour les enregistrements opaques et les curseurs, Storage pour les gros blobs, Realtime pour le réveil des appareils. Le serveur reste une boîte aux lettres aveugle : aucune clé, aucun contenu en clair, les requêtes sont authentifiées par signature d'appareil (clés de la rotation v2), pas par Supabase Auth comme preuve d'accès aux données ; les règles RLS ne servent que de défense en profondeur. Le self-host reste possible puisque Supabase est auto-hébergeable. La section 4 est à réécrire autour de ce choix (schéma, RLS, quotas, réveil).
2. **Un seul backend par compte (première passe).** Ajouter un appareil hors Apple propose de passer tout le compte sur la boîte aux lettres.
3. **Android d'abord (fondateur).** Ordre des jalons : X0, X1, X4, X5, puis X2, X3, X6.
4. **Tauri 2 (fondateur).** Slint en repli si la revue de sécurité refuse le moteur web.
5. **Linux : `.deb` et `.rpm` signés avec dépôts, AppImage en plus (fondateur).** Flatpak plus tard.
6. **Windows : MSIX signé et winget, Store ensuite (fondateur).**
7. **Android : Play Store et APK signé sur GitHub, F-Droid ensuite (fondateur).**
8. **Un PC peut aussi approuver un nouvel appareil et lancer une rotation (fondateur).** Pas seulement Android. Sur un PC sans caméra, l'appairage passe par le QR affiché par le PC et scanné par le nouvel appareil quand c'est possible, sinon par la saisie d'un code court ; le code de comparaison (SAS) reste obligatoire dans les deux cas. X6 couvre Android et bureau.
9. **Linux : pas de biométrie, clé FIDO2 `hmac-secret` en option (fondateur).**
10. **AGPL-3.0-or-later + CLA sur les stores, après avis juridique (fondateur).**
11. **Versions minimales : Android 10, passkeys sur Android 14+, Windows 11, Ubuntu 24.04, Debian 13, Fedora 42 (fondateur).**
12. **Réveil Android : FCM sans contenu sur le Play Store, UnifiedPush sur F-Droid, interrogation en repli (fondateur).** Avec Supabase, Realtime sert de réveil quand l'app est ouverte.
13. **Pas de CloudKit Web Services comme solution d'attente (première passe).**
14. **Genre des enregistrements visible du serveur en v1, comme CloudKit (première passe).** À revoir après l'audit externe.
15. **Android sans attestation matérielle : pas bloqué, état affiché (première passe).**
16. **Rendez-vous d'appairage par l'instance Soma même pour un compte encore sur CloudKit (première passe).** Trames opaques, 2 minutes, mention à l'écran.
