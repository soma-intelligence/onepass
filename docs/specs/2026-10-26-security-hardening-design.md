# OnePass : durcissement sécurité (état de l'art, sans couper de fonction)

Date : 2026-10-26
Statut : validée (auto-validation, voir section 0)
Branche : `feat/security-hardening`, créée depuis la `main` locale.
Brief : `.superpowers/briefs/hardening.md` (consigne du fondateur : garder toutes les fonctions et les durcir ; le PDF Emergency Kit reste).

## 0. Mode de décision

Personne ne valide en cours de route. Chaque décision est notée `Ruling: <quoi> - <pourquoi> - <coût si c'est faux>` ; la liste complète est en section 11.

Hors périmètre (autres sessions) : MCP et agent SSH (jalon 7), appairage QR, listes signées des appareils et des coffres, changement du mot de passe maître (jalon 2b), modèle formel, banc d'essai autofill, fin du jalon 3. Toute modification d'API du cœur est additive.

## 1. Objectif et critères de réussite

1. Une restauration (kit, sauvegarde chiffrée, choix explicite d'une version) ne déclenche jamais de fausse alerte de retour en arrière ou de bifurcation, et ne permet jamais de contourner la détection. Test sur deux appareils simulés.
2. Les comportements normaux de CloudKit (retard, nouvelle tentative, récupération partielle, remise à zéro de zone, lecture d'un instantané plus ancien) ne bloquent jamais un coffre. Si une alerte se déclenche quand même, l'utilisateur a une sortie sûre.
3. L'Emergency Kit est durci : avertissements, « imprimer seulement », exclusion des sauvegardes, message clair « kit plus mot de passe maître égale accès complet ».
4. Hygiène mémoire : tampons effaçables en Swift et TypeScript là où c'est faisable, pages verrouillées pour les clés du cœur.
5. Format du coffre versionné, avec un chemin de migration testé.
6. Chaîne d'approvisionnement : `SECURITY.md`, licence, builds reproductibles documentés, `cargo deny` resserré, `cargo vet`, audit npm, actions épinglées par SHA, SBOM.
7. Revue de la crypto écrite, primitive par primitive.
8. Revue adverse indépendante (4 attaquants), tout ce qu'elle trouve est corrigé.

Fini quand `cd core && make check`, `make -C apple test` et `cd extension && npm run check` passent, et que `docs/security/README.md` décrit exactement le code.

## 2. Restauration et détection de retour en arrière : l'époque de restauration signée

### 2.1 Constat

Aujourd'hui un appareil retient, par vault, le dernier manifeste accepté (`DeviceState.last_seen`). Un manifeste plus ancien est un retour en arrière (`ManifestRollback`), un manifeste de même numéro mais d'empreinte différente est une bifurcation, un vault connu qui disparaît est `VaultMissing`. Ces règles sont justes face à un stockage hostile, mais elles n'ont aucun moyen de reconnaître une remise en arrière voulue par le propriétaire :

- une restauration qui recrée un vault (nouvel id) fait lever `VaultMissing` sur les autres appareils ;
- une restauration qui réécrit un vault à partir d'un état ancien sans connaître la dernière tête (zone effacée, appareil seul) repart à un numéro plus petit : `ManifestRollback` sur les autres appareils ;
- la seule sortie actuelle d'une alerte est « Réessayer », qui relance l'alerte.

### 2.2 Construction

Nouvel enregistrement du cœur, `RecordKind::RestoreEpoch` (code 7, ajouté en fin), un seul par compte (id = id du compte), contenu en clair et signé :

```rust
pub struct RestoreEpoch {
    pub account_id: Id,
    pub epoch: u64,                              // strictement croissant, 1 pour la première
    pub issued_at: i64,                          // secondes Unix, information seulement
    pub heads: BTreeMap<Id, SeenManifest>,       // têtes de manifeste après la restauration, par vault
    pub reason: EpochReason,                     // Restore | KeepThisDevice | TakeServer
}
pub struct SignedRestoreEpoch { pub epoch: RestoreEpoch, pub signature: HybridSignature }
```

- Signature hybride ML-DSA-87 + Ed25519 du compte (la même clé que les manifestes), domaine `b"onepass/restore-epoch/v1"`, message = postcard de `RestoreEpoch`. Seul un détenteur du mot de passe maître et de la Secret Key peut en produire une.
- L'appareil retient `epoch` (nouveau champ de `DeviceState`, voir section 5).
- Règles à chaque chargement (`vaults()`, `items()`, écritures, rebase) :
  1. pas d'enregistrement et époque retenue 0 : comportement actuel ;
  2. enregistrement valide avec `epoch` supérieure à l'époque retenue : l'appareil remplace `last_seen` par `heads` (les vaults absents de `heads` sont oubliés, donc plus de `VaultMissing` pour eux), retient la nouvelle époque, puis applique les règles habituelles ;
  3. même époque : règles habituelles ;
  4. époque inférieure à l'époque retenue, enregistrement absent alors qu'une époque est retenue, signature fausse, compte différent : `IntegrityError::EpochRollback` (nouvelle variante, ajoutée en fin) ou `Signature`.
- Écrire une époque : `Repository::issue_restore_epoch(reason) -> Result<RestoreEpoch>`. Elle prend comme `heads` les manifestes courants de tous les vaults (après la restauration), `epoch = max(époque retenue, époque stockée) + 1`, écrit l'enregistrement de façon conditionnelle (`put_if_version` sur l'époque précédente), puis retient l'époque.
- Restauration d'une archive (`backup restore`) : elle écrit en avant (`save_item`, `create_vault`) puis émet une époque `Restore`. Une restauration additive ne rend pas l'époque nécessaire pour l'appareil qui restaure, mais elle l'est pour les autres dès qu'un vault a été recréé ou qu'une tête a été recalculée sans connaître la précédente.
- Restauration par l'Emergency Kit sur un nouvel appareil : rien ne change. L'appareil n'a pas d'historique, il fait confiance au premier état vu (limite déjà documentée), et retient l'époque stockée.

### 2.3 Pourquoi ce n'est pas un contournement

- Forger une époque demande la clé de signature du compte.
- Rejouer une ancienne époque avec d'anciennes données échoue : l'appareil a retenu une époque plus grande.
- Cacher l'enregistrement d'époque à un appareil qui en a retenu une : `EpochRollback`.
- Un appareil qui n'a jamais vu d'époque et à qui le stockage cache une époque récente : il voit l'ancien historique, et ses propres règles (`last_seen`) détectent tout retour en arrière par rapport à ce qu'il a déjà vu. La protection reste au moins celle d'aujourd'hui.
- Un appareil compromis du propriétaire peut émettre une époque : hors modèle (section 1 de la spec d'architecture).

### 2.4 Test

`core/onepass-core/tests/restore_epoch.rs`, sur le faux serveur des tests `sync_two_devices.rs` : deux appareils, restauration d'une sauvegarde ancienne avec un vault recréé et un vault rembobiné, l'autre appareil lit sans alerte ; un stockage qui rejoue l'ancien état après l'époque, cache l'époque, rejoue une époque plus ancienne ou forge une signature est refusé.

## 3. CloudKit : jamais de coffre bloqué par un comportement normal

### 3.1 Règle

Un appareil qui détient une copie vérifiée d'un vault au moins aussi récente que `last_seen` ne bloque jamais ce vault. Quand le serveur sert un état plus ancien (instantané en retard, zone remise à zéro, lot partiel), l'appareil :

1. garde et sert sa copie locale vérifiée ;
2. marque le vault « en retard côté serveur » (état de sync, pas une erreur d'intégrité) ;
3. remet en file l'envoi de sa copie plus récente, comme pour une remise à zéro de zone ;
4. ne lève une alerte que si l'état persiste après `STALE_ALERT_ROUNDS = 5` tours de sync complets et au moins `STALE_ALERT_SECONDS = 600` secondes, ou si le serveur sert une bifurcation (même numéro, autre empreinte) que le rebase ne peut pas résoudre.

Le cœur expose l'état par vault (`VaultSyncHealth { Ok, ServerBehind { since, rounds }, Alert(IntegrityError) }`) ; Swift ne fait que l'afficher.

### 3.2 Cas couverts par des tests (Rust, faux serveur ; Swift, `InMemoryRemote`)

- retard de propagation (le serveur sert la tête N-1 après que l'appareil a vu N) ;
- nouvelle tentative après échec d'envoi partiel ;
- récupération partielle (`moreComing`, page coupée) ;
- jeton expiré, récupération complète ;
- zone supprimée par l'utilisateur, zone recréée vide ;
- lot coupé en deux (manifeste en dernier) vu entre les deux lots par l'autre appareil.

Chacun : le vault reste lisible et inscriptible, aucune alerte, convergence après le tour suivant.

### 3.3 Sortie sûre quand une alerte se déclenche quand même

L'écran « Données refusées » propose, en plus de « Réessayer » :

1. **Exporter une sauvegarde chiffrée de ce que l'appareil a** (archive OnePass, phrase de passe) : toujours proposé en premier.
2. **Garder la version de cet appareil** : réenvoie la copie locale et émet une époque `KeepThisDevice` (demande le mot de passe maître).
3. **Prendre la version d'iCloud** : accepte l'état servi par le serveur et émet une époque `TakeServer` (demande le mot de passe maître, avertit que les changements locaux plus récents seront perdus s'ils n'ont pas été exportés).

Les deux dernières passent par la section 2 : elles sont signées, tracées dans le journal local, et elles ne désactivent jamais la détection pour la suite.

## 4. Emergency Kit durci

- **Kit plus mot de passe maître égale accès complet** : écrit en tête du PDF et dans l'écran qui le propose.
- **Imprimer seulement** : action principale « Imprimer le kit » (impression depuis la mémoire, `UIPrintInteractionController` / `NSPrintOperation`, aucun fichier écrit). Le PDF ne dit plus « ne l'imprime pas » ; il dit d'imprimer et de ranger la feuille hors ligne, de n'écrire le mot de passe maître qu'à la main si on veut le noter.
- **Enregistrer un fichier** : action secondaire, derrière une feuille d'avertissement (iCloud Drive, Photos, messageries et captures d'écran synchronisent la Secret Key hors de l'appareil). Partage via un contrôleur qui exclut Photos, presse-papiers, contacts et liste de lecture. Sur Mac, enregistrement par panneau ; une destination dans iCloud Drive (`isUbiquitousItem` ou chemin `Mobile Documents`) redemande confirmation.
- **Exclu des sauvegardes** : le fichier temporaire porte `isExcludedFromBackup`, protection `complete` (iOS, visionOS), il est supprimé à la fermeture de l'écran et au démarrage.
- **Capture d'écran** : pendant que la Secret Key est affichée, une capture (`userDidTakeScreenshotNotification`) déclenche un avertissement ; un enregistrement ou une recopie d'écran (`isCaptured`) masque la Secret Key.
- **Phrase de passe sur le kit** : non (Ruling 8).

## 5. Format du coffre versionné

- Document `docs/security/README.md` : table de tous les formats persistés avec leur version (blobs `OPB` format 1 et schéma, manifeste, items postcard, archive `OPARCH`, `DeviceState`, `RestoreEpoch`, base SQLite de sync).
- `DeviceState` passe à un encodage versionné : `b"ODS" || version u8 || postcard`. Version 2 = `{ pinned, last_seen, epoch }`. `decode` lit la version 2 et, sans en-tête, l'ancien encodage (version 1) qu'il migre (`epoch = 0`). Une version inconnue plus récente : `InvalidFormat("device state from a newer version")`.
- Module `onepass_core::format` : constantes de version, `migrate_item(schema, bytes) -> Item` (aujourd'hui : schéma 1 seulement, identité) et règle écrite pour une migration future. Tests : golden v1 de `DeviceState`, aller-retour v2, version future refusée, item schéma 1 lu, schéma 2 refusé.
- Base SQLite de sync : `PRAGMA user_version` lu à l'ouverture ; version connue = migrations en place ; version plus récente = refus clair.

## 6. Hygiène mémoire

### 6.1 Cœur Rust

- Module `crypto::locked` : réserve de pages verrouillées (`mlock` sur Unix, aucune autre plateforme cible) découpées en emplacements de 32 octets ; les pages ne sont jamais déverrouillées (elles sont réutilisées), un emplacement libéré est effacé. Échec de `mlock` (limite du système) : on continue sans verrou et un compteur l'expose.
- `SymmetricKey` stocke ses 32 octets dans un emplacement verrouillé (représentation interne, API inchangée). Couvre les clés de vault, d'item, l'AUK dérivée et les clés de contenu d'archive.
- Seul `crypto::locked` contient de l'`unsafe`, `#![deny(unsafe_code)]` partout ailleurs dans `onepass-core` et `onepass-ffi`. Tests sous Miri pour `crypto::locked`.
- FFI : variantes additives qui prennent les secrets en octets (`unlock_with_password_bytes`, `create_account_bytes`, `verify_password_bytes`), effacées côté Rust.

### 6.2 Swift

- Type `SecretBytes` (VaultKit) : tampon d'octets effacé par `memset_s` à la libération, sans `Equatable` ni `description` qui le révèlent.
- Mot de passe maître et Secret Key : convertis en `SecretBytes` dès la validation, passés aux variantes en octets de la FFI, le `@State` texte est vidé aussitôt.
- Valeurs révélées et TOTP : la révélation est annulée au passage en arrière-plan et au verrouillage.
- Presse-papiers : déjà local et expirant ; ajout de l'effacement au verrouillage et au passage en arrière-plan quand la valeur copiée est un secret.
- Vues : la Secret Key et les valeurs révélées sont masquées pendant une capture vidéo (`isCaptured`).

### 6.3 Extension

- L'historique du générateur ne va plus dans `chrome.storage.session` : il reste en mémoire du service worker et est vidé au verrouillage.
- Tous les `Uint8Array` de clés et de secrets sont effacés après usage (`wipe`), y compris les chemins d'erreur.
- Le mot de passe de la proposition d'enregistrement est effacé dès l'enregistrement ou le refus, plus seulement après 2 minutes.
- Limite assumée et documentée : les chaînes JavaScript ne peuvent pas être effacées.

## 7. Chaîne d'approvisionnement et transparence

- `SECURITY.md` à la racine : périmètre, canal de signalement (adresse à remplir, marquée `TODO-CONTACT`), délais (accusé de réception sous 72 h, correctif ou plan sous 90 jours), divulgation coordonnée, pas de poursuites contre la recherche de bonne foi.
- Licence : GPL-3.0-or-later pour tout le dépôt (Ruling 11). Fichier `LICENSE`, champs `license` des crates, de `package.json`. Remplacé le 2026-10-26 par AGPL-3.0-or-later, avec un CLA (`CLA.md`), au choix du propriétaire pour la publication.
- `docs/security/reproducible-builds.md` : toolchain épinglée, `Cargo.lock` et `npm ci`, chemins à neutraliser (`--remap-path-prefix`), état actuel (non reproductible prouvé), étapes pour le vérifier.
- `cargo deny` resserré : `yanked = "deny"`, `unused-allowed-license = "deny"` avec la liste réduite aux licences utilisées, `multiple-versions = "warn"`, sources inchangées.
- `cargo vet` : initialisé dans `core/supply-chain/`, audits importés de sources publiques reconnues, exemptions pour le reste, vérifié en CI.
- npm : `npm audit` en CI (bloquant pour les dépendances livrées, informatif pour le développement), mise à jour des dépendances de développement vulnérables quand une version corrigée existe.
- GitHub Actions : chaque `uses:` épinglé par SHA de commit, version en commentaire, `permissions: contents: read` par défaut.
- SBOM CycloneDX : `make sbom` (Rust par `cargo cyclonedx`, extension par `npm sbom`), généré en CI comme artefact.

## 8. Revue de la crypto

Section « Justification des primitives » dans `docs/security/README.md` : pour chaque primitive (Argon2id, HKDF-SHA256, AES-256-GCM-SIV avec engagement HMAC, ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, SLH-DSA-SHA2-256s, SHA-256, SHA-1 de HIBP), le rôle, le niveau de sécurité visé, l'implémentation, l'alternative écartée.

- L'enveloppe hybride ML-KEM reste (protection contre « récolter maintenant, déchiffrer plus tard »).
- `slh-dsa =0.1.0` : évalué en section 11 (Ruling 13). Ajout d'un test différentiel contre la version candidate `0.2.0-rc.5` si les deux versions se compilent ensemble.

## 9. Revue adverse

Avant la revue finale, un red team sur le modèle le plus puissant, avec 4 attaquants : stockage hostile, page web hostile, client MCP hostile, attaquant local avec les droits de l'utilisateur. Chaque constat confirmé est corrigé dans une tâche dédiée, avec un test.

## 10. Tests

- Rust : `restore_epoch.rs`, cas CloudKit dans `sync_two_devices.rs`, `format` (golden, migration), `crypto::locked` (unitaires et Miri).
- Swift : `SyncCoordinatorTests` (cas de la section 3.2, sortie sûre), `EmergencyKitTests` (texte, exclusion des sauvegardes), `SecretBytes`.
- Extension : vitest pour l'historique du générateur et les effacements.
- Aucun test n'écrit dans `~/Library/Containers/me.somalabs.onepass` ni dans les defaults réels de l'app. Données synthétiques seulement.

## 11. Rulings

1. Ruling: voie architecturale, spec et plan validés par moi - consigne de travailler sans action de l'utilisateur - un périmètre plus étroit aurait pu suffire.
2. Ruling: une époque de restauration signée par le compte, un enregistrement par compte, strictement croissante et retenue par chaque appareil - seule façon de distinguer une remise en arrière voulue d'une attaque sans tiers de confiance - un appareil compromis du propriétaire peut émettre une époque (hors modèle).
3. Ruling: l'époque remplace tout `last_seen` par ses têtes - une règle simple, vérifiable et testée, plutôt qu'une fusion vault par vault - une écriture d'un autre appareil faite pendant la restauration peut être refusée et devoir être rebasée.
4. Ruling: un état serveur plus ancien que la copie locale vérifiée n'est jamais une erreur bloquante ; l'appareil sert sa copie et réenvoie - un stockage qui rembobine est simplement réécrit, et CloudKit ne bloque plus personne - une attaque de rembobinage n'est signalée qu'après 5 tours et 10 minutes.
5. Ruling: seuils d'alerte 5 tours et 600 secondes - au-delà des délais de propagation observés de CloudKit et des reprises 30 s, 2 min, 10 min - à recalibrer sur appareil.
6. Ruling: la sortie sûre propose d'abord l'export chiffré, puis « garder cet appareil » ou « prendre iCloud », toutes deux par époque signée et mot de passe maître - aucune donnée ne se perd sans choix explicite - deux boutons de plus à expliquer.
7. Ruling: le kit invite à imprimer et l'action principale est « Imprimer », l'enregistrement de fichier passe derrière un avertissement - consigne du fondateur, la feuille papier ne quitte pas l'appareil par le cloud - un utilisateur sans imprimante doit passer par l'avertissement.
8. Ruling: pas de phrase de passe sur le kit - le kit seul n'ouvre rien sans le mot de passe maître, une troisième chose à retenir ferait perdre plus de comptes qu'elle n'en protège - un voleur qui a le kit n'a plus qu'un secret à trouver (déjà le cas avec 1Password).
9. Ruling: `DeviceState` versionné par un en-tête `ODS` et migré depuis l'ancien encodage - le nouveau champ `epoch` l'impose et les appareils existants ne doivent rien perdre - un état très ancien illisible ferait repartir l'appareil en confiance au premier usage.
10. Ruling: réserve de pages verrouillées jamais déverrouillées, emplacements de 32 octets, pour `SymmetricKey` - `mlock` par clé partage les pages et un `munlock` en libérerait d'autres - quelques pages restent verrouillées jusqu'à la fin du processus ; les grands clairs (`Zeroizing<Vec<u8>>`) ne sont pas verrouillés.
11. Ruling: GPL-3.0-or-later pour tout le dépôt - la spec d'architecture fixe GPL-3.0 pour les clients, `core` en fait partie ; les champs `MIT OR Apache-2.0` étaient une valeur par défaut - un tiers ne pourra pas réutiliser `core` dans un logiciel fermé ; la publication App Store demande la CLA prévue. Remplacé le 2026-10-26 : AGPL-3.0-or-later et CLA.
12. Ruling: actions GitHub épinglées par SHA de commit, version en commentaire - une étiquette peut être déplacée par un compte compromis - mises à jour manuelles.
13. Ruling: garder `slh-dsa =0.1.0` - seule version stable, vecteurs NIST ACVP déjà vérifiés en test, aucune autre implémentation mûre (aws-lc-rs et libcrux n'ont pas SLH-DSA, la 0.2 est encore candidate) ; passage à la 0.2 derrière la même API quand elle sera stable - un défaut de la 0.1 toucherait la clé d'identité (qui ne signe que des clés et des paramètres).
14. Ruling: `cargo vet` avec audits importés et exemptions explicites - mieux que rien et révisable - les exemptions ne prouvent rien tant qu'elles ne sont pas auditées.
15. Ruling: l'historique du générateur de l'extension reste en mémoire seulement - `chrome.storage.session` survit à la mise en veille du service worker et contenait des mots de passe - l'historique se perd quand le navigateur suspend le service worker.
