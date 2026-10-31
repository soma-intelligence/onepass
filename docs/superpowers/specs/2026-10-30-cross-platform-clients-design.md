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
| Backend de sync | Boîte aux lettres aveugle sur Supabase (Postgres, Storage, Realtime, une fonction edge qui vérifie des requêtes signées), self-hostable, hébergée aussi par Soma (décision 1) ; un seul backend par compte |
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
| **C. Service `onepass-mailbox` : boîte aux lettres aveugle, self-hostable, hébergée aussi par Soma** | Fait exactement ce que `RecordStore` attend : écriture conditionnelle, lots atomiques sans limite de 400 enregistrements, flux de changements par séquence serveur, notifications, rendez-vous d'appairage. Code public ; hébergé sur Supabase, self-host sur Supabase auto-hébergé (4.4, 4.16). | Un service à opérer, à surveiller et à protéger contre l'abus ; adresses IP et rythme visibles par l'opérateur. |
| D. Pair à pair seulement (réseau local, l'appareil Apple sert de hub) | Aucun serveur. | Pas de sync continue quand les appareils ne sont pas ensemble ; un téléphone Android loin de l'iPhone ne voit rien. Garde son intérêt pour le premier transfert (instantané de l'autorisation, 2b section 5.4). |

**Recommandation : C**, avec D pour le premier transfert (déjà dans le protocole 2b) et B comme adaptateur possible plus tard derrière le même protocole. A est écarté. Questions 1 et 13.

### 4.3 Un backend par compte

| Option | Pour | Contre |
| --- | --- | --- |
| **A. Un seul backend par compte** : un compte vit soit sur CloudKit, soit sur une boîte aux lettres. Ajouter un premier appareil hors Apple propose de passer le compte sur la boîte aux lettres ; les apps Apple suivent. | Une seule vérité serveur, un seul `base` dans `SyncStore`, la même logique de rebase. La migration est une réinitialisation de zone déjà écrite (`begin_zone_reset`, `finish_full_fetch` renvoie ce que le serveur n'a pas). | Un utilisateur Apple qui ajoute un PC quitte iCloud pour ce compte. |
| B. Double attache : les appareils Apple synchronisent CloudKit et la boîte aux lettres | L'utilisateur garde iCloud. | Deux serveurs hostiles à réconcilier, deux `base`, des conflits entre stockages ; les appareils Apple deviennent des ponts et tout s'arrête quand ils dorment. |
| C. Un appareil Apple fait le pont (CloudKit vers la boîte aux lettres) | Rien ne change pour les autres appareils Apple. | Sync hors Apple seulement quand ce pont tourne ; un point unique de panne. |

**Recommandation : A.** Question 2.

Migration d'un compte (sur un appareil Apple déverrouillé) : choix du serveur (hébergé ou URL self-host), création de la boîte, inscription de l'appareil, envoi complet de `base` et `pending` (réinitialisation de zone vers le nouveau transport), écriture d'un nouvel enregistrement signé `SyncHome` (4.13) dans les deux backends, puis chaque autre appareil Apple lit `SyncHome` dans CloudKit, vérifie la signature, et bascule avec confirmation de l'utilisateur ("Ton coffre se synchronise maintenant avec <serveur>"). CloudKit garde la zone en lecture seule 30 jours, puis l'app propose de l'effacer.

### 4.4 Hébergement sur Supabase (décision P1)

Réécrit le 2026-10-31 après la décision 1 du fondateur. La boîte aux lettres n'est plus un binaire `axum` : c'est un projet Supabase dont chaque brique a un rôle borné.

| Brique Supabase | Rôle | Ce qu'elle ne fait jamais |
| --- | --- | --- |
| Postgres (schéma `onepass_mailbox`) | Boîtes, identifiants, enregistrements opaques, curseurs (`seq`), nonces, quotas, trames de rendez-vous | Interpréter un blob ; être joint par PostgREST (schéma non exposé) |
| Fonction edge `mailbox` (Deno) | Seule porte d'entrée HTTP : vérifie la signature de chaque requête, décode strictement le corps, appelle une fonction SQL, encode la réponse | Tenir une clé de données ; écrire en SQL hors des fonctions `api_*` |
| Storage (bucket privé `onepass-mailbox`) | Corps d'enregistrement au-dessus de 16 Kio (900 Kio au plus) | Servir un objet sans URL signée de 60 s émise après vérification |
| Realtime (Broadcast depuis la base) | Réveil "il y a du nouveau" quand l'app est ouverte | Porter un `seq`, un genre ou un identifiant |
| `pg_cron` | Purges (nonces, rendez-vous, pierres tombales), file des notifications | |

Supabase Auth n'intervient pas : aucune session, aucun JWT d'utilisateur. La preuve d'accès est la signature de requête (4.7). La passerelle de la fonction est ouverte (`verify_jwt = false`) puisque l'authentification est la nôtre.

Le modèle de serveur hostile ne change pas : l'opérateur (Soma), Supabase comme sous-traitant, ou un attaquant qui lit la base voient ce que liste 4.15 et rien d'autre. Toute garantie de confidentialité et d'intégrité reste dans le core (manifestes, listes signées, époques, lignée de rotation, `SyncHome`).

Pile client : un seul code Rust (`onepass-mailbox`, 4.14) en HTTP/1.1 ou HTTP/2 sur TLS 1.3 seulement (`rustls` avec le fournisseur `aws-lc-rs`, échange hybride `X25519MLKEM768` quand le serveur l'offre, racines `webpki-roots`, certificat d'autorité en plus pour un self-host). Corps en postcard versionné, type `application/vnd.onepass.mailbox.v1+postcard`.

### 4.5 Schéma Postgres

Schéma `onepass_mailbox`, propriété du rôle `onepass_mailbox_owner` (4.8). Identifiants binaires de taille fixe vérifiée par contrainte.

| Table | Colonnes | Clé et index |
| --- | --- | --- |
| `plans` | `plan text`, `max_bytes bigint`, `max_records int`, `max_credentials int`, `req_per_min int`, `max_commit_ops int` | PK `plan`. Lignes `free` (256 Mio, 100 000 enregistrements, 16 identifiants, 120 requêtes par minute, 20 000 opérations par lot) et `selfhost` (limites hautes : 1 Tio, 10 000 000 enregistrements, 256 identifiants, 6 000 requêtes par minute, 20 000 opérations par lot) |
| `invites` | `token_hash bytea(32)`, `plan`, `uses_left int`, `expires_at` | PK `token_hash` |
| `mailboxes` | `id bytea(16)` (aléatoire, `gen_random_bytes(16)`), `incarnation bigint` (aléatoire, change seulement si l'opérateur restaure une sauvegarde), `plan`, `wake_topic bytea(16)` (aléatoire), `next_seq bigint` (1 au départ), `min_cursor bigint` (0 au départ), `bytes_used bigint`, `records_count int`, `frozen bool`, `created_at`, `last_write_at` | PK `id`, unique `wake_topic` |
| `credentials` | `id bytea(16)` = `SHA-256("onepass/mailbox-credential-id/v1" ‖ public_key)[..16]`, `mailbox_id`, `public_key bytea(32)`, `label bytea` (64 octets au plus, chiffré par le client), `enrolled_by bytea(16) null`, `push_kind smallint null`, `push_token bytea null`, `created_at`, `last_used_at`, `revoked_at null` | PK `id`, index `(mailbox_id)` |
| `records` | `mailbox_id`, `kind smallint` (1 à 255), `id bytea(16)`, `version bigint` (celle du client), `seq bigint` (séquence serveur de la dernière écriture), `deleted bool`, `deleted_at timestamptz null` (posé quand la ligne devient pierre tombale, NULL pour une ligne vivante ; la purge de 90 jours vieillit sur lui), `size int`, `data bytea null` (16 Kio au plus), `blob_sha256 bytea(32) null` | PK `(mailbox_id, kind, id)`, unique `(mailbox_id, seq)` pour le flux de changements. Contrainte : une pierre tombale n'a ni `data` ni `blob_sha256`, un enregistrement vivant a exactement l'un des deux ; `deleted_at` non NULL si et seulement si `deleted`. Index partiel `(deleted_at) where deleted` pour la purge |
| `blobs` | `mailbox_id`, `sha256 bytea(32)`, `size int`, `state smallint` (annoncé, présent, orphelin), `refs int`, `orphaned_at null` | PK `(mailbox_id, sha256)` |
| `nonces` | `credential_id`, `mailbox_id`, `nonce bytea(16)`, `seen_at` | PK `(credential_id, nonce)`, index `(seen_at)` |
| `used_tickets` | `ticket_hash bytea(32)`, `mailbox_id`, `used_at` | PK `ticket_hash` |
| `rate` | `key bytea(32)`, `window_start timestamptz`, `count int` | PK `(key, window_start)` |
| `push_queue` | `mailbox_id`, `exclude_credential bytea(16) null`, `enqueued_at` | PK `mailbox_id` (une entrée par boîte, regroupe les réveils) |
| `rdv_sessions` | `session_id bytea(16)`, `created_at`, `bytes bigint`, `closed_at null` | PK `session_id` |
| `rdv_chunks` | `session_id`, `dir smallint` (0 nouveau vers approbateur, 1 inverse), `n int`, `data bytea` (1 Mio au plus), `written_at` | PK `(session_id, dir, n)` |

Sémantique des enregistrements, calquée sur ce que le coordinateur Swift attend de CloudKit (`RemoteRecordStore`) :

- **Écriture conditionnelle** : une écriture porte `expected: Option<seq>`. `None` passe seulement s'il n'y a pas de ligne ou une pierre tombale ; `Some(s)` passe seulement si la ligne est vivante avec `seq = s`. Le `seq` rendu est rangé côté client comme `server_meta` (8 octets gros-boutistes), exactement comme l'étiquette de changement de CloudKit : `SyncStore` ne change pas.
- **Suppression** : sans condition (comme CloudKit), idempotente ; une ligne vivante devient pierre tombale avec un nouveau `seq`, une ligne absente ne bouge pas.
- **Flux** : `seq` strictement croissant par boîte, sans trou visible au client. Chaque page porte `head`, le dernier `seq` écrit de la boîte. Deux modes :
  - **Récupération complète** (`full=1`) : lignes vivantes seulement, `seq > after`, pierres tombales sautées et `min_cursor` ignoré, pour qu'une purge entre deux pages ne casse jamais la récupération. Le client garde `full=1` sur toutes les pages, retient le `head` de la **première** page, puis, après `finish_full_fetch`, passe en incrémental à partir de ce `head` : tout ce qui a changé pendant la récupération (lignes déplacées, pierres tombales) a un `seq` au-dessus, et `min_cursor` ne le dépasse jamais (la purge ne prend que des pierres tombales de 90 jours).
  - **Incrémental** (`full=0`) : toutes les lignes de `seq > after`, pierres tombales comprises. Une pierre tombale vit 90 jours ; `after < min_cursor` reçoit `410 cursor_expired` et le client refait une récupération complète.
- **Perte de données côté serveur** : `incarnation` change ; le client qui voit une autre incarnation que celle rangée fait `begin_zone_reset`, comme pour une zone CloudKit recréée.

### 4.6 API : la fonction edge et les fonctions SQL

Ressources (`v1`, chemins relatifs à l'URL de base de la boîte, par exemple `https://<projet>.supabase.co/functions/v1/mailbox`) :

| Requête | Signée par | Fonction SQL | Rôle |
| --- | --- | --- | --- |
| `GET /v1/config` | personne | aucune | Limites publiques, URL Realtime, clé publiable (publique par nature) |
| `POST /v1/mailboxes` | la nouvelle clé (preuve de possession) | `api_create_mailbox` | Crée la boîte ; hébergé : jeton d'invitation exigé, 5 créations par jour et par adresse IP |
| `GET /v1/mailboxes/{m}` | un identifiant inscrit | `api_mailbox_info` | Incarnation, sujet de réveil, `min_cursor`, limites, usage |
| `POST /v1/mailboxes/{m}/credentials` | la nouvelle clé, ticket signé par un identifiant inscrit dans le corps | `api_enroll` | Inscription (4.12) |
| `DELETE /v1/mailboxes/{m}/credentials/{c}` | un identifiant inscrit | `api_revoke_credential` | Retrait de confort (la coupure réelle est la rotation v2) |
| `PUT /v1/mailboxes/{m}/push` | un identifiant inscrit | `api_set_push` | Jeton FCM, APNs ou UnifiedPush de cet identifiant |
| `GET /v1/mailboxes/{m}/changes?after=<seq>&limit=<n>&full=<0\|1>` | un identifiant inscrit | `api_changes` | Page de changements (1 000 au plus, 4 Mio au plus), récupération complète ou incrémentale (4.5) |
| `POST /v1/mailboxes/{m}/commit` | un identifiant inscrit | `api_commit` | Lot atomique (corps de 4 Mio au plus, 20 000 opérations au plus) |
| `GET /v1/mailboxes/{m}/records/{kind}/{id}` | un identifiant inscrit | `api_record` | Lecture d'un enregistrement |
| `POST /v1/mailboxes/{m}/blobs/uploads` | un identifiant inscrit | `api_blob_announce` | URL signées d'envoi pour les corps au-dessus de 16 Kio (4.11) |
| `POST /v1/mailboxes/{m}/blobs/downloads` | un identifiant inscrit | `api_blob_lookup` | URL signées de lecture (60 s) |
| `PUT /v1/rendezvous/{s}/{dir}/{n}` | personne | `rdv_put` | Trame de rendez-vous, écrite une seule fois |
| `GET /v1/rendezvous/{s}/{dir}/{n}?wait=25` | personne | `rdv_get` | Lecture avec attente longue (25 s au plus) |
| `DELETE /v1/rendezvous/{s}` | personne | `rdv_close` | Fin de session |

Le lot de `commit` : `[(kind, id, version, op)]` où `op` est `Put { expected, body: Inline(octets) | Blob { sha256, size } }` ou `Delete`. Tout ou rien : la fonction verrouille la ligne de la boîte (`FOR UPDATE`, un lot à la fois par boîte), compare chaque `expected`, et en cas de conflit n'écrit rien et rend, pour chaque clé en conflit, la ligne serveur courante (que le client met en attente comme le fait le coordinateur Swift). Sinon chaque opération reçoit le `seq` suivant, les compteurs et quotas sont mis à jour dans la même transaction, puis le réveil part (4.10). Un lot qui dépasse les limites est refusé entier (`413`), le client le coupe comme il coupe aujourd'hui pour CloudKit (items avant manifestes).

Codes d'erreur (corps postcard `ErrorBody { code, retry_after }`) : `400 malformed`, `401 bad_signature`, `401 stale_request` (décalage), `401 replay`, `403 unknown_credential`, `403 revoked_credential`, `403 frozen`, `404 not_found`, `409 conflict` (rendu dans le corps du commit, pas en erreur), `410 cursor_expired`, `413 too_large`, `422 quota`, `429 rate_limited` avec `retry_after`, `503 retry`.

Chaque route qui touche la base appelle une seule fonction SQL `api_*` ou `rdv_*` dans une seule transaction. Une fonction `api_*` reçoit l'identifiant, le nonce et l'horodatage déjà vérifiés par la fonction edge et fait elle-même, dans cet ordre : écrasement de tous les réglages `onepass.*` de la requête puis `set_config('onepass.mailbox', <id du chemin>, true)` pour la RLS (4.8), avant tout accès à une table (le rôle de l'API pourrait les poser d'avance) ; contrôle de l'identifiant (inscrit dans la boîte du chemin, non retiré, boîte non gelée) ; insertion du nonce (une clé déjà vue est un `replay`) ; débit ; puis le travail. `credential_key(boîte, identifiant)` ne cherche la clé que dans la boîte du chemin.

Contrat entre la fonction edge et les fonctions SQL :

- **Refus levé** (`SQLSTATE 'OP' || <statut HTTP>`, message égal au nom du code en snake case) : la requête n'est pas authentifiée (`malformed` sur la forme, `stale_request`, `unknown_credential`, `revoked_credential`, `frozen`, `replay` pour une route signée ; clé d'adresse IP malformée pour la création et l'inscription). Rien n'est enregistré, la transaction est annulée. Tout autre `SQLSTATE` est un bogue : `503 retry`.
- **Réponse dans le résultat** : toute autre issue. Chaque fonction rend des lignes dont les deux premières colonnes sont `status text, retry_after int` : `ok` avec les données, ou une seule ligne portant le code (`not_found`, `rate_limited`, `cursor_expired`, `quota`, `malformed`, ...) et des données NULL ; `retry_after` (secondes) seulement pour `rate_limited`. La fonction edge **valide** la transaction : le nonce, le débit et `last_used_at` d'une requête signée, le débit par adresse IP de la création et de l'inscription, restent comptés même quand la requête échoue (une requête refusée après authentification n'est pas rejouable, et 500 lectures en échec dans la minute sont limitées comme 500 lectures réussies). Une écriture refusée ne laisse que ces compteurs : le travail qui peut encore échouer après sa première écriture tourne dans une sous-transaction annulée avant la réponse.
- Une clé déjà inscrite dans une autre boîte donne `malformed` à la création et à l'inscription (seul le détenteur de la clé, qui a signé, l'apprend) ; une clé déjà inscrite dans la même boîte donne `replay` à l'inscription. `api_set_push` reçoit l'indice de `PushKind` sur le fil (0 aucun, 1 FCM, 2 APNs, 3 UnifiedPush) ; un type sans jeton est `malformed`.

Le décodage strict des corps et la construction de la base de signature viennent du même code Rust que le client : la crate `onepass-mailbox-proto` compilée en WebAssembly (`wasm-bindgen`, cible Deno) et embarquée dans la fonction. Un seul décodeur, fuzzé, et une seule canonicalisation pour les deux côtés.

### 4.7 Requêtes signées

Chaque appareil a un **identifiant de boîte** : une paire Ed25519 créée sur l'appareil, rangée par `DeviceSecrets` (section 6), utilisable appareil verrouillé pour la sync en arrière-plan. Elle est distincte des clés d'appareil de la rotation v2 ; voir "Écart avec la décision 1" plus bas.

Format, inspiré de RFC 9421 (HTTP Message Signatures) et RFC 9530 (`Content-Digest`), restreint à une seule forme :

```
Content-Digest: sha-256=:<base64 du SHA-256 du corps, corps vide compris>:
Signature-Input: sig1=("@method" "@onepass-target" "content-digest");created=<unix>;nonce="<base64url, 16 octets>";keyid="<id de l'identifiant, 32 hex>";alg="ed25519";tag="onepass-mailbox/v1"
Signature: sig1=:<base64 de la signature Ed25519, 64 octets>:
```

Base signée (RFC 9421 section 2.5), octets UTF-8, sans saut de ligne final :

```
"@method": POST
"@onepass-target": /v1/mailboxes/<m hex>/commit?after=12
"content-digest": sha-256=:...:
"@signature-params": ("@method" "@onepass-target" "content-digest");created=...;nonce="...";keyid="...";alg="ed25519";tag="onepass-mailbox/v1"
```

`@onepass-target` est le composant dérivé propre à OnePass : chemin et requête relatifs à l'URL de base de la boîte, tels que le client les a envoyés. Il remplace `@path` parce que la passerelle Supabase préfixe le chemin (`/functions/v1/mailbox`). L'autorité n'est pas signée : le `mailbox_id` dans le chemin, l'identifiant propre à une boîte et le nonce suffisent contre le rejeu vers un autre serveur.

Vérification, dans cet ordre, par la fonction edge :

1. Analyse stricte : exactement une étiquette `sig1`, exactement ces trois composants dans cet ordre, exactement ces paramètres dans cet ordre, `tag` et `alg` égaux aux valeurs ci-dessus. Tout écart : `401 bad_signature`.
2. `|maintenant - created| <= 300` secondes, sinon `401 stale_request`.
3. `Content-Digest` recalculé sur le corps reçu.
4. Clé publique de `keyid` lue par `credential_key` (pour `POST /v1/mailboxes` et l'inscription : la clé du corps, dont `keyid` doit être l'empreinte). Signature vérifiée par WebCrypto (`Ed25519`).
5. Seulement alors, la fonction `api_*` insère le nonce : une requête non signée ne peut pas remplir la table des nonces. Les nonces vivent 10 minutes (deux fois la fenêtre de décalage) et sont purgés par `pg_cron`.

Le serveur ne signe pas ses réponses : il est hostile de toute façon, TLS protège contre un tiers réseau, et le core vérifie tout ce qu'il lit.

**Écart avec la décision 1.** La décision dit "signature d'appareil (clés de la rotation v2)". Cette réécriture garde une clé de requête distincte, créée et gardée sur l'appareil, pour quatre raisons : (a) la clé d'appareil de la rotation v2 est hybride, et vérifier ML-DSA-87 dans la fonction edge ajouterait une implémentation post-quantique côté serveur sans rien protéger de plus, puisque ces signatures n'authentifient que l'accès à des blobs déjà chiffrés ; (b) sur Apple la clé d'appareil n'est lisible qu'appareil déverrouillé (`WhenUnlockedThisDeviceOnly`) et sa moitié post-quantique vit dans la Secure Enclave, alors que la sync tourne écran verrouillé ; (c) le serveur apprendrait les clés publiques d'appareil et pourrait relier le roster aux adresses IP ; (d) une clé de requête volée (sauvegarde, fichier de configuration) ne signe ni rotation, ni intro, ni liste. Le lien avec la rotation v2 reste : le ticket d'inscription passe dans le canal d'appairage authentifié par le code court, où la clé d'appareil est épinglée en même temps. À confirmer par le fondateur.

### 4.8 Rôles, RLS et défense en profondeur

La RLS n'est pas la frontière de sécurité (la signature l'est), mais elle limite ce qu'un bogue dans une fonction SQL ou dans la fonction edge peut atteindre.

- **`onepass_mailbox_owner`** (`NOLOGIN`, `NOBYPASSRLS`) possède les tables et les fonctions `api_*` et `rdv_*` (`SECURITY DEFINER`, `search_path = ''`). Toutes les tables ont `ENABLE` et `FORCE ROW LEVEL SECURITY` : le propriétaire lui-même y est soumis.
- **Politiques** : chaque table qui porte `mailbox_id` n'est lisible et modifiable par le propriétaire que pour `mailbox_id = onepass_mailbox.current_mailbox()`, qui lit `current_setting('onepass.mailbox', true)` posé par la fonction après l'authentification de la requête. `rdv_*` : même chose avec `onepass.rdv` (le `session_id`). `invites` : seulement pendant `api_create_mailbox` (`onepass.invite`). `plans` : lecture seule. Une fonction qui oublierait un `WHERE mailbox_id = ...` ne voit quand même que la boîte authentifiée.
- **Storage** : politique sur `storage.objects` pour `onepass_mailbox_owner`, lecture seule, `bucket_id = 'onepass-mailbox'` et nom préfixé par la boîte courante en hexadécimal. Les URL signées sont émises par la fonction edge avec la clé de service, utilisée pour Storage seulement, jamais pour la base.
- **`onepass_mailbox_api`** (`LOGIN`, `NOBYPASSRLS`, mot de passe dans les secrets de la fonction) : `USAGE` sur le schéma, `EXECUTE` sur `credential_key`, `api_*` et `rdv_*`, aucun droit sur une table. C'est le seul rôle de la fonction edge pour la base, par le pooler en mode transaction.
- **`anon`, `authenticated`** : aucun droit sur le schéma, schéma absent des schémas exposés par l'API REST et GraphQL. `service_role` n'est jamais utilisé pour la base.
- **Maintenance** : `onepass_mailbox.maintenance()` tourne par `pg_cron` sous le rôle `postgres`, hors chemin de requête.

### 4.9 Quotas et abus

- **Par boîte**, dans la transaction du commit : octets (inline + blobs), nombre d'enregistrements vivants, nombre d'identifiants actifs, opérations par lot ; dépassement : `422 quota`, rien d'écrit.
- **Par identifiant** : `req_per_min` en fenêtre d'une minute (table `rate`), `429` avec `retry_after`. Chaque requête authentifiée compte, qu'elle réussisse ou non (4.6).
- **Par adresse IP** pour les routes sans identifiant (création, inscription, rendez-vous, config) : clé `HMAC-SHA-256(secret du jour, ip)`, pour ne garder aucune adresse en clair. Un seul compteur de 60 tentatives par minute sur la clé brute, partagé par la création, l'inscription et le rendez-vous ; chaque tentative compte, échouée comprise (deviner une invitation ou un ticket est donc limité). En plus, 5 créations par jour sur un second compteur de clé `SHA-256(clé IP)` (pour ne jamais partager une ligne avec la minute de minuit), compté une fois l'invitation vérifiée ; 200 Mio de rendez-vous par heure. Les fenêtres sont découpées en UTC.
- **Rendez-vous** : 66 Mio par session et par sens (un instantané de 50 Mio en trames d'au plus 1 Mio), trame écrite une seule fois (`PUT` sur un `n` existant : `409`), lisible 2 minutes après son écriture, session fermée 10 minutes après sa création.
- **Gel** : `mailboxes.frozen` coupe une boîte qui abuse (lecture et écriture refusées, `403 frozen`) sans rien effacer ; geste d'opérateur, journalisé.
- **Hébergé** : création sur invitation (`invites`), plan `free` par défaut. **Self-host** : `OPEN_SIGNUP=true` et plan `selfhost`.

### 4.10 Réveil

- **App ouverte** (tous clients) : le commit appelle `realtime.send('{}', 'wake', 'mbx:' || hex(wake_topic), false)`. Le client suit le canal public `mbx:<wake_topic>` par le WebSocket Realtime avec la clé publiable. Le message est vide : il dit seulement "récupère". Le sujet, 128 bits aléatoires, n'est donné qu'aux identifiants inscrits (`api_mailbox_info`) ; qui le connaîtrait verrait seulement le rythme des écritures. Un canal privé demanderait un JWT Supabase Auth, ce que la décision 1 exclut comme preuve d'accès.
- **App fermée** : le commit insère ou rafraîchit `push_queue` (une ligne par boîte, l'auteur exclu). `pg_cron` appelle toutes les 10 secondes la fonction edge `mailbox-push`, qui envoie un message sans contenu : FCM (Android Play Store), UnifiedPush (F-Droid), APNs silencieux (Apple sur boîte aux lettres). Repli : interrogation périodique (WorkManager sur Android, récupération à l'ouverture ailleurs).
- Le jeton de notification est une donnée que l'opérateur voit et relie à une boîte (4.15).

### 4.11 Storage pour les gros corps

Un corps de plus de 16 Kio ne passe pas dans `records.data` : le client calcule son SHA-256, l'annonce (`blobs/uploads`), reçoit une URL signée d'envoi pour `onepass-mailbox/<boîte hex>/<sha256 hex>` (sauf si le blob est déjà présent), l'envoie, puis le référence dans le commit par `Blob { sha256, size }`. Le commit vérifie que l'objet existe dans `storage.objects` avec cette taille et incrémente `refs` ; une ligne remplacée ou supprimée décrémente. Un blob à `refs = 0` depuis 24 heures est supprimé par la fonction edge `mailbox-gc` (par l'API Storage, appelée par `pg_cron` et `pg_net`). En lecture, le client demande des URL signées de 60 s et vérifie le SHA-256 avant de remettre les octets au core.

Effet : un lot de commit reste petit (une référence fait une centaine d'octets), donc un lot atomique de 20 000 enregistrements tient dans 4 Mio quelle que soit la taille des items.

### 4.12 Inscription d'un appareil dans la boîte

Le ticket est produit par un appareil déjà inscrit et transmis au nouvel appareil dans le canal d'appairage authentifié par le code court (section 5) :

```
EnrollTicket { version: 1, mailbox_url: String (256 octets au plus), mailbox_id: [u8; 16], new_credential_pub: [u8; 32], expires_at: i64, nonce: [u8; 16] }
SignedEnrollTicket { ticket, approver_credential: [u8; 16], sig: [u8; 64] }
```

`sig` = Ed25519 de l'identifiant de l'approbateur sur `"onepass/mailbox-enroll/v1" ‖ postcard(ticket)`. Durée de vie : 10 minutes au plus ; le serveur ne voit que `expires_at` et refuse (`malformed`) une échéance à plus de 900 s (600 s plus le décalage de 300 s de l'horloge de l'approbateur), donc `used_tickets` garde chaque ticket au moins 900 s. Le nouvel appareil crée sa paire, envoie sa clé publique dans `ConfirmedWithKey` (champ `mailbox_credential`, 5.2), reçoit le ticket dans `FullGrantV2.enroll`, et l'utilise une fois par `POST /v1/mailboxes/{m}/credentials`, requête signée par sa nouvelle clé. Le serveur vérifie la signature du ticket contre un identifiant actif de la même boîte, la clé du ticket contre celle qui signe la requête, l'échéance, et l'unicité (`used_tickets`).

Retrait : l'appareil qui retire un autre appareil (liste signée, puis rotation v2) supprime aussi son identifiant. Un serveur hostile peut l'ignorer ; la rotation v2 a déjà rendu inutile ce que l'appareil retiré pourrait lire ensuite (objectif G1).

### 4.13 Quels enregistrements, et comment

Tous les enregistrements synchronisés aujourd'hui par CloudKit passent tels quels, octet pour octet, par la boîte aux lettres :

| Enregistrement | Code | Synchronisé | Remarque |
| --- | --- | --- | --- |
| `AccountParams` (v2, époque signée) | 1 | oui | jamais supprimable par le serveur (refusé par `commit_remote`) |
| `Keyset` | 2 | oui | idem |
| `VaultKey`, `VaultMeta`, `Manifest` | 3, 4, 6 | oui | suppression acceptée seulement pour un coffre marqué supprimé dans la liste signée |
| `Item` | 5 | oui | items avant leur manifeste dans un même lot |
| `RestoreEpoch` | 7 | oui | |
| `DeviceList`, `VaultList` | 8, 9 | oui | contenus en clair (noms d'appareils lisibles par le serveur, limite 2b) |
| `Lineage`, `DeviceIntro`, `KeyDelivery` (rotation v2) | 10, 11, 12 | oui | immuables ; rien de spécial côté boîte |
| **Nouveau** `SyncHome` | 13 (ou le premier code libre quand X1 est fusionné) | oui, dans l'ancien et le nouveau backend | id = `account_record_id` de l'identité courante, version = `seq`. Corps `{account_id, seq, prev_hash, backend: CloudKit | Mailbox{url, mailbox_id}, issued_at}`, signé par la clé de signature hybride du compte sous le domaine `onepass/sync-home/v1`, chaîné comme les listes (`Seen` dans `ChainState`). Une rotation le signe à nouveau sous la nouvelle identité (phase 1). Il dit aux appareils où vit le compte, pour qu'un serveur ne puisse pas rediriger un appareil vers une autre boîte sans signature |

Jamais synchronisés : Secret Key, clés d'appareil, identifiant de boîte, `DeviceState`, `ChainState`, `TrustState`, enveloppe biométrique, clés d'appairage du pont navigateur, journaux d'audit, cache d'icônes, charge utile de la montre, état du Travel Mode côté appareil.

Avantage net sur CloudKit : un lot atomique de 20 000 enregistrements au lieu de 400 ou 1,5 Mio supprime en pratique le refus d'intégrité transitoire décrit en 10.6 de `docs/security/README.md` (un appareil qui récupère entre deux lots). Au-delà de 20 000 opérations (première migration d'un très gros compte), le client coupe en plusieurs lots comme aujourd'hui.

### 4.14 Code : crates, moteur de sync et dossier Supabase

Le tour de sync (récupérer, `stage_remote`, `commit_remote`, `finish_full_fetch`, rebase si déverrouillé, `pending_changes`, envoi, `mark_pushed`, phases de rotation) est aujourd'hui orchestré par le coordinateur Swift. Pour ne pas l'écrire trois fois, il passe en Rust :

- **`onepass-mailbox-proto`** : messages, décodage strict, base de signature, ticket. Sans dépendance au core ; seul SHA-256 (`sha2`, Rust pur) est interne, Ed25519 vient de l'appelant (`aws-lc-rs` côté client, WebCrypto côté fonction edge). Compilée aussi en WebAssembly pour la fonction edge. Cibles de fuzzing.
- **`onepass-mailbox`** (client, plus de binaire serveur) : `MailboxClient` bloquant (`ureq` + `rustls`), signature des requêtes, blobs, rendez-vous, écoute Realtime (`tungstenite`). Un modèle en mémoire de la boîte (`FakeMailbox`, derrière la fonctionnalité `testing`) et une suite de conformité jouée contre ce modèle et contre un vrai Supabase local.
- **`onepass-sync`** : trait `Transport`, `SyncDriver` (un tour à la fois : la règle "le rebase ne tourne jamais en même temps qu'une réconciliation" reste garantie à un seul endroit), `MailboxTransport`. Exposé par `onepass-ffi` pour Swift et Kotlin, utilisé directement par le bureau.
- **`onepass-pairnet`** : transports d'appairage en Rust (T-LAN par TCP et DNS-SD, T-RDV par la boîte), pour la CLI, le bureau et les tests croisés.
- **`mailbox/supabase/`** : `config.toml`, migrations SQL, fonctions edge `mailbox`, `mailbox-push`, `mailbox-gc`, tests SQL. AGPL comme le reste.

CloudKit reste un transport Swift : le coordinateur actuel ne change pas tant que le compte reste sur CloudKit.

### 4.15 Ce que voit la boîte aux lettres

Comme CloudKit (10.5 de la doc sécurité) : nombre d'enregistrements par genre, versions, tailles des corps (arrondies par le rembourrage du core), numéros de séquence des manifestes, dates et rythme des écritures, noms d'appareils de la liste signée. En plus : adresses IP des clients (journaux de Supabase et de la fonction ; aucune adresse rangée par OnePass, seulement des clés HMAC du jour pour le débit), identifiants de boîte et leurs clés publiques, jetons de notification, `mailbox_id`, sujet de réveil. Supabase, comme sous-traitant, voit la même chose que l'opérateur. En moins : aucun identifiant Apple.

Masquer le genre des enregistrements (nom chiffré) est possible mais casse l'ordre "items avant manifeste" que le serveur n'a pas besoin de connaître ; la parité avec CloudKit est gardée en v1. Question 14.

### 4.16 Self-host

Le self-host est un projet Supabase auto-hébergé (pile Docker officielle : Postgres, Kong, Realtime, Storage, edge runtime) avec les mêmes migrations et les mêmes fonctions : `supabase db push` puis `supabase functions deploy`. L'option "SQLite pour un self-host" de la première version de cette spec disparaît : un seul schéma, une seule implémentation du serveur, testée une fois. Le client accepte une URL de base quelconque et, pour un certificat privé, une autorité en PEM.

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
| `onepass-mailbox` (nouvelle) | Client de la boîte : requêtes signées, blobs, rendez-vous, réveil Realtime ; modèle en mémoire et suite de conformité (4.14) |
| `onepass-pairnet` (nouvelle) | Transports d'appairage T-LAN et T-RDV en Rust (CLI, bureau, tests) |
| `mailbox/supabase/` (nouveau dossier) | Migrations SQL, fonctions edge `mailbox`, `mailbox-push`, `mailbox-gc`, tests SQL (4.14) |
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
- **Boîte aux lettres hostile** : la suite `sync_two_devices` rejouée contre une vraie boîte (Supabase local : `supabase start` et la fonction `mailbox` servie) en HTTP, avec un mandataire hostile entre le client et le serveur qui rejoue, retient, réordonne, injecte, coupe entre l'envoi et la confirmation, sert un vieux `SyncHome`, une autre boîte, un lot partiel. Chaque classe d'attaque de l'étude ETH Zurich / USI reste un test (architecture section 12). Tests SQL sur Postgres 17 (atomicité des lots, monotonie de `seq`, conflits, quotas, RLS : une fonction qui oublie le filtre de boîte ne voit rien d'une autre boîte). Suite de conformité jouée à la fois contre le modèle en mémoire et contre Supabase local, pour que les tests rapides du client ne mentent pas sur le serveur. Fuzzing de tous les décodeurs du protocole et des tickets.
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
- **Limites de Supabase** : taille des corps et durée des fonctions edge, quotas Realtime, pooler en mode transaction. Les limites de 4.6 et 4.9 sont choisies en dessous ; à revoir sur le plan Supabase choisi au moment du déploiement.
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

1. **Hébergement de la boîte aux lettres : Supabase (fondateur).** L'instance Soma tourne sur Supabase : Postgres pour les enregistrements opaques et les curseurs, Storage pour les gros blobs, Realtime pour le réveil des appareils. Le serveur reste une boîte aux lettres aveugle : aucune clé, aucun contenu en clair, les requêtes sont authentifiées par signature d'appareil (clés de la rotation v2), pas par Supabase Auth comme preuve d'accès aux données ; les règles RLS ne servent que de défense en profondeur. Le self-host reste possible puisque Supabase est auto-hébergeable. La section 4 est à réécrire autour de ce choix (schéma, RLS, quotas, réveil). Section 4 réécrite le 2026-10-31 (4.4 à 4.16) ; une différence avec cette décision y est signalée (4.7, "Écart avec la décision 1") : la clé qui signe les requêtes est une clé d'appareil propre à la boîte, pas la clé d'appareil de la rotation v2.
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
