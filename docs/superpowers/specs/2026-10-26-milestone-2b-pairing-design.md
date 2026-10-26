# Jalon 2b : appairage, appareils, listes signées, mot de passe maître

Date : 2026-10-26
Statut : approuvée (auto-approbation, voir section 13)
Portée : sections 4.9 (connexion par QR) et 4.10 (modes d'appareil) de la spec d'architecture (`2026-10-25-onepass-architecture-design.md`), reports R1, R2, R12 et R14 du jalon 2 (`2026-10-25-milestone-2-apps-design.md`), écart 8 de `docs/security/README.md` (liste des coffres non signée), et préparation du transfert sans fil vers un appareil hors Apple (`docs/backlog.md`, sans le construire).

## 1. Ce que l'utilisateur obtient

1. **Ajouter un appareil par QR.** Sur le nouvel appareil : "J'ai déjà OnePass sur un autre appareil", choix du mode (personnel, partagé, public), un QR s'affiche. Sur un iPhone ou un iPad déjà déverrouillé : Réglages > Appareils > "Ajouter un appareil", Face ID (ou mot de passe maître), scan du QR avec le scanner de OnePass, puis les deux écrans affichent le même code à 6 chiffres ; l'utilisateur confirme des deux côtés. Le nouvel appareil reçoit la Secret Key et une copie chiffrée du coffre, puis demande le mot de passe maître.
2. **Mode public.** Le nouvel appareil (ordinateur ou tablette d'un tiers avec OnePass) reçoit seulement les éléments choisis sur le téléphone, pour 15 min par défaut (1 h au plus), en lecture seule, en mémoire seulement. Le téléphone affiche le temps restant et le journal (élément ouvert, champ copié), et peut terminer la session à tout moment. Jamais de Secret Key, de keyset ni de clé de coffre.
3. **Liste des appareils.** Réglages > Appareils : nom, type, mode, date d'ajout, appareil courant. "Retirer cet appareil" : l'appareil retiré efface ses données locales dès qu'il voit la liste.
4. **Liste signée des coffres.** Un coffre masqué par le serveur est détecté même si l'appareil ne l'a jamais ouvert.
5. **Supprimer un coffre** vide (R14).
6. **Changer le mot de passe maître** (R12). Les autres appareils demandent le nouveau mot de passe à leur prochain déverrouillage, sans perte de leurs modifications en attente. L'Emergency Kit reste valable (la Secret Key ne change pas).

Critère de réussite : tous les tests Rust et Swift passent, builds iOS et Mac ; l'appairage complet (QR, code, transfert, mot de passe) et la session publique sont prouvés par des tests à deux appareils sur un transport en mémoire et par un test de bout en bout sur le transport réseau local (deux processus sur la même machine) ; un red team a attaqué l'appairage avant la revue finale.

## 2. Vue d'ensemble

```
core/onepass-core/src/
  chain.rs        état local épinglé : époque des paramètres, listes vues, identifiant d'appareil
  account.rs      paramètres v2 (époque signée), changement de mot de passe
  devices.rs      liste signée des appareils
  vaultlist.rs    liste signée des coffres, suppression de coffre
  pairing/        protocole d'appairage (QR, canal hybride, code court, autorisations, instantané)
core/onepass-ffi/src/ pairing.rs, devices.rs (ajouts)
apple/VaultKit/Sources/VaultKit/Pairing/   transport réseau local, coordinateurs approbateur et nouvel appareil
apple/App/Pairing/                          écrans : QR, code, choix du mode, session publique
apple/App/Settings/DevicesSettings.swift    liste des appareils, ajout, retrait
```

Règle de frontière inchangée : seul le Rust manipule les clés. Le canal d'appairage, le code court, les autorisations et l'instantané sont produits et vérifiés dans le Rust ; Swift transporte des octets opaques et affiche.

## 3. Paramètres de compte v2 et changement du mot de passe maître

### 3.1 Format

- Nouveau format de l'enregistrement `AccountParams` : préfixe `"OPP2"` puis postcard de `{account_id, kdf, identity_pub, signing_pub, kem_pub, epoch: u64, identity_sig}`. Message signé : `postcard((account_id, kdf, signing_pub, kem_pub, epoch))`, domaine `account-params/v2`, clé d'identité SLH-DSA. Un enregistrement sans préfixe est un v1 : époque 0, vérifié exactement comme avant.
- Keyset v2 : même contenu, enregistrement `"OPK2" || epoch_be (8 octets) || hash (32 octets) || blob`, où `hash` est le SHA-256 du message signé des paramètres. Le blob est scellé sous l'AUK avec `Aad{blob_id: account_id XOR epoch_be sur les 8 derniers octets, vault_id: 16 premiers octets du hash, schema: 2}` : l'en-tête en clair permet de refuser avant toute clé, le contexte scellé le rend contraignant. Un keyset v1 (schéma 1, blob nu) n'est accepté qu'avec des paramètres v1. Une récupération déchirée (paramètres et keyset de deux époques, ou de deux changements différents à la même époque) échoue avec `IntegrityError::WrongContext`, distinct de `WrongPassword`.
- `AccountParams` n'implémente plus `Serialize`/`Deserialize` : l'enregistrement se lit et s'écrit par `decode`/`encode` (une forme serde serait un troisième format ambigu).
- Les comptes créés à partir de ce jalon écrivent directement le v2, époque 1.

### 3.2 État épinglé (`chain`)

Nouvel état local, à côté de `DeviceState` (dont l'encodage ne change pas), rangé dans la table `meta` de la base sous la clé `chain`, postcard versionné : `ChainState{params_epoch: u64, device_list: Option<Seen>, vault_list: Option<Seen>, device_id: Option<Id>}` où `Seen{seq, hash}`. Chaque déverrouillage réussi relève `params_epoch` ; des paramètres d'époque inférieure à l'époque épinglée sont refusés (`IntegrityError::ParamsRollback`, nouvelle variante ajoutée en fin d'enum). Un appareil qui n'a jamais vu le compte épingle au premier usage, comme pour `PinnedAccount`.

### 3.3 Changement

`Repository::change_password(current: &str, secret_key: &SecretKey, new: &str) -> Result<Auk>` (session ouverte) :

1. Vérifie le mot de passe actuel (Argon2id, mêmes contrôles que `verify_password`).
2. Nouveaux `KdfParams` : sel neuf, coûts = max(coûts actuels, plancher).
3. Nouvelle AUK = dérivation(nouveau mot de passe, Secret Key inchangée, nouveaux paramètres).
4. Paramètres v2 d'époque + 1 signés par la clé d'identité ; keyset (mêmes clés) rescellé sous la nouvelle AUK au schéma 2.
5. Écriture conditionnelle des deux enregistrements en une seule transaction (`RecordStore::put_all_if_version`, keyset puis paramètres) : un conflit, une erreur ou un arrêt brutal laisse l'ancienne paire intacte ; épinglage de la nouvelle époque. Rend la nouvelle AUK pour réenrôler la biométrie.

Les clés du keyset, les clés de coffre et les manifestes ne changent pas : les écritures en attente des autres appareils restent valables. Un autre appareil voit l'époque monter à la récupération ; son AUK biométrique échoue (`WrongPassword` sur le keyset) ; l'app supprime l'enrôlement et affiche "Ton mot de passe maître a changé sur un autre appareil. Saisis le nouveau." Le rejeu des anciens paramètres par le serveur est refusé (`ParamsRollback`) par tout appareil qui a vu la nouvelle époque. Deux changements concurrents : le second envoi échoue au conflit de version. À la récupération suivante, `commit_remote` voit des paramètres serveur d'époque au moins égale à ceux en attente : il retire ensemble les paramètres et le keyset en attente et lève l'indicateur `password_change_superseded` (`SyncStore::take_password_change_superseded`) ; l'app ferme la session et demande le mot de passe en vigueur, l'utilisateur recommence avec l'époque la plus récente. `pending_changes` n'envoie les paramètres et le keyset qu'ensemble, et jamais des paramètres d'époque inférieure ou égale à celle du serveur.

## 4. Listes signées

### 4.1 Format commun

Deux nouveaux types d'enregistrement : `RecordKind::DeviceList = 7` et `RecordKind::VaultList = 8`, un enregistrement chacun, id = id du compte, version = `seq`. Contenu : postcard de `SignedList{body, sig}` où `body = postcard(ListBody{account_id, seq, prev_hash, entries})`, signé par la clé de signature hybride du compte (ML-DSA-87 + Ed25519), domaines `device-list` et `vault-list`. Contenu en clair (aucun secret, mais noms d'appareils et identifiants de coffres lisibles par le serveur, voir 11). Chaînage comme les manifestes : `seq` croissant, `prev_hash` = SHA-256 du corps précédent ; l'état `chain` retient `Seen{seq, hash}` ; un `seq` inférieur, ou égal avec un autre hash, est refusé (`DeviceListRollback`, `VaultListRollback`).

### 4.2 Fusion

Les deux listes sont des ensembles monotones : une entrée ne disparaît jamais, elle ne fait que passer à l'état retiré ou supprimé. Quand la liste du serveur a avancé pendant qu'une liste locale attend l'envoi, la liste locale est refaite par union (par id ; retrait ou suppression gagnent, date la plus ancienne gardée), signée au `seq` du serveur + 1 avec son hash. La fusion est commutative : deux appareils convergent.

### 4.3 Liste des appareils

`DeviceEntry{device_id, name (64 caractères au plus), kind: Phone|Tablet|Mac|Vision|Other, mode: Personal|Shared|Public, added_at, added_by: Option<Id>, revoked_at: Option<i64>}`.

- Création de compte : la liste contient l'appareil créateur.
- Migration : un compte du jalon 2 n'a pas de liste ; le premier appareil déverrouillé la crée avec lui-même ; chaque autre appareil déverrouillé s'y ajoute (auto-inscription). Un id déjà retiré ne peut pas se réinscrire.
- Appairage : l'approbateur ajoute le nouvel appareil (mode personnel ou partagé). Une session publique n'ajoute rien (4.10 de l'architecture).
- Retrait : l'entrée passe à `revoked_at`. Un appareil qui se voit retiré efface sa base, sa Secret Key et son enrôlement biométrique, et revient à l'accueil avec "Cet appareil a été retiré de ton compte OnePass." Limite (11) : le retrait n'est pas une coupure cryptographique.

### 4.4 Liste des coffres

`VaultListEntry{vault_id, created_at, deleted_at: Option<i64>}`.

- `vaults()` vérifie : tout coffre vivant de la liste doit être présent (sinon `VaultMissing`, même jamais ouvert : ferme l'écart 8) ; un coffre supprimé n'est plus attendu.
- Un coffre présent mais absent de la liste : s'il a une clé, une méta et un manifeste valides (signés par le compte, donc venus d'un appareil légitime, par exemple un client du jalon 2), il est accepté et ajouté à la liste par le prochain appareil déverrouillé (adoption) ; sinon il est refusé comme avant.
- Migration : liste créée au premier déverrouillage avec les coffres présents, confiance au premier usage (comme E4 du jalon 2).
- `create_vault` ajoute l'entrée dans la même opération.

### 4.5 Suppression de coffre (R14)

`Repository::delete_vault(vault)` : refusée si le coffre contient un élément vivant ou archivé (`InvalidInput("vault not empty")`) ; sinon supprime les éléments à la corbeille, marque `deleted_at` dans la liste, supprime clé, méta et manifeste, retire l'entrée de `last_seen`. Côté sync, `commit_remote` et `finish_full_fetch` acceptent les suppressions de clé, méta, manifeste et éléments d'un coffre que la liste signée (déjà en base ou dans le même lot) marque supprimé ; elles restent refusées pour tout autre coffre. Le dernier coffre vivant ne peut pas être supprimé. Une écriture locale en attente dans un coffre supprimé ailleurs est abandonnée au rebase (journalisée).

## 5. Protocole d'appairage

### 5.1 Rôles et messages

N = nouvel appareil, A = appareil approbateur (déverrouillé). Messages opaques, indépendants du transport (5.5), chacun en postcard avec une version.

1. **N** crée une paire hybride éphémère ML-KEM-1024 + X25519, un `session_id` (16 octets aléatoires) et affiche le QR : `OPPAIR1:` suivi du base32 de `{version: 1, session_id, key_hash: SHA-256(clé publique éphémère), expires_at}`. Le QR ne porte jamais de clé publique complète ni d'URL (le scanner système ne doit pas proposer d'ouvrir l'app). QR renouvelé toutes les 30 s (nouvelle paire), valable 2 min.
2. **N → A, `Hello`** : `{session_id, ephemeral_public, device: {device_id, name, kind}, requested_mode}`.
3. **A** vérifie `SHA-256(ephemeral_public) == key_hash`, l'expiration et le `session_id`, puis tire une clé de session de 32 octets et l'enveloppe : `wrap_key_labeled(ephemeral_public, K, "onepass/pairing/v1", transcript)` où `transcript = SHA-256(contenu du QR || Hello)`.
4. **A → N, `KeyExchange`** : l'enveloppe.
5. Les deux côtés calculent le **code court** : 6 chiffres décimaux = `HKDF-SHA256(K, info = "onepass/pairing/sas/v1" || transcript)` réduit modulo 10^6 (sur 8 octets, sans biais mesurable). Chaque écran l'affiche ; chaque utilisateur confirme "Les codes sont identiques". Sans les deux confirmations, rien d'autre ne part.
6. **N → A, `Confirmed`** (scellé sous K) : N a confirmé.
7. **A → N, `Grant`** (scellé sous K), après la confirmation sur A et une seconde vérification de présence (Face ID, sinon mot de passe maître) :
   - `Full{account_id, secret_key, mode, device_id_assigned, snapshot}` (personnel ou partagé), où `snapshot` est la liste de tous les enregistrements du magasin tels que les voit le serveur (blobs déjà chiffrés et signés), 50 Mio au plus ;
   - `Public{session_id, expires_at, items: Vec<Item>, read_only: true}` (mode public).
8. **N → A, `Ack`** ; puis, en session publique, des `AuditEvent{at, item_id, action: Opened|Copied(field label)}` ; **A → N, `End`** termine.

### 5.2 Canal

Trames scellées sous K avec `BlobKind::Pairing = 12`, `Aad{blob_id: session_id XOR compteur, vault_id: None, schema: 1}` et un sens (A vers N, N vers A) lié dans la clé : deux sous-clés `HKDF(K, "a2n")` et `HKDF(K, "n2a")`. Compteur strictement croissant par sens : un rejeu, une réorganisation ou une trame d'un autre sens échouent. Aucune trame n'est acceptée après `End` ou après l'expiration.

### 5.3 Ce que le protocole garantit

- **Homme du milieu sur le transport** : la clé publique éphémère est engagée par le QR (photographiée sur l'écran de N) ; seul N peut décapsuler K ; le code court lié à toute la transcription ferait apparaître toute substitution.
- **QR photographié ou envoyé à distance** (l'attaque principale : "scanne ce QR pour te connecter") : celui qui scanne est A ; un attaquant qui montre son propre QR obtient K seulement si l'utilisateur confirme un code qu'il ne peut voir que sur l'écran de l'attaquant. Défense : l'écran d'approbation affiche le type et le nom de l'appareil, le mode, l'avertissement "Ne scanne jamais un QR code qu'on t'a envoyé", et le transport réseau local exige la proximité (5.5).
- **Rejeu** : session à usage unique, `session_id` neuf, expiration 2 min, compteurs par sens.
- **Appareil volé** : approuver demande A déverrouillé plus une présence fraîche ; le nouvel appareil demande toujours le mot de passe maître (personnel, partagé) ; une session publique ne donne aucune clé.
- **Préparation hors Apple** : messages et cryptographie indépendants de l'OS et du transport, `snapshot` utilisable sans iCloud.

### 5.4 Après l'autorisation

- **Personnel ou partagé** : N range la Secret Key (Keychain), importe l'instantané comme une récupération distante (`stage_remote` puis `commit_remote` : toutes les vérifications du magasin hostile s'appliquent), enregistre son `device_id`, demande le mot de passe maître et déverrouille. A ajoute N à la liste des appareils avant d'envoyer l'autorisation. La sync CloudKit prend le relais dans un build signé.
- **Public** : N n'écrit rien sur le disque ; éléments en mémoire, presse-papiers effacé après 30 s, fin à l'expiration, sur `End`, à la fermeture de la connexion (fail-closed), après 5 min sans activité, ou en quittant l'app. Le téléphone garde le journal en mémoire et l'affiche jusqu'à la fin de la session.

### 5.5 Transport

Réseau local, sans serveur : N publie un service Bonjour `_onepass-pair._tcp` nommé par le `session_id` en hexadécimal (Network.framework, `includePeerToPeer = true` : Wi-Fi ou AWDL quand les deux appareils sont proches) ; A le trouve par le `session_id` du QR et s'y connecte en TCP ; trames préfixées par leur longueur (4 octets, 64 Mio au plus). Le chiffrement de bout en bout ne dépend pas du transport. Implémentation en mémoire pour les tests. Le protocole reste servi plus tard par un autre transport (relais chiffré, appareils hors Apple) sans changement des messages.

## 6. Modes d'appareil

Personnel et partagé : comme au jalon 2, le mode est inscrit dans la liste des appareils. Public : session déléguée (5.4), sans inscription ni stockage. Le choix est la première question de "J'ai déjà OnePass sur un autre appareil".

## 7. Apple

- **VaultKit** : `PairingTransport` (protocole ; `LocalNetworkPairingTransport` sur Network.framework ; `InMemoryPairingTransport`), `PairingNewcomer` (N : QR, code, confirmation, réception) et `PairingApprover` (A : scan, code, confirmations, envoi), `PublicSession` (N public, minuterie et fin), `VaultSession` : `changePassword(current:new:)`, `devices`, `revokeDevice(id:)`, `renameDevice`, `deleteVault(id:)`, `importGrant`, état `revoked` qui efface et revient à l'accueil.
- **App** :
  - Accueil : "J'ai déjà OnePass sur un autre appareil" devient actif (R1 levé) ; écrans mode, QR renouvelé, code, attente, mot de passe.
  - Réglages > Appareils (iPhone, iPad, Mac) : liste, "Ajouter un appareil" (iPhone et iPad : scanner ; Mac et Vision Pro : texte "Utilise ton iPhone ou ton iPad pour approuver un nouvel appareil."), retrait avec confirmation, journal de la session publique en cours.
  - Réglages > Sécurité : "Changer le mot de passe maître".
  - Réglages > Coffres : "Supprimer le coffre" (vide seulement).
  - Session publique côté N : bandeau "Session invitée, se termine dans 14 min", éléments en lecture seule, bouton "Terminer".
- `Info.plist` : `NSLocalNetworkUsageDescription` ("OnePass utilise le réseau local pour ajouter un appareil à ton compte, sans passer par un serveur.") et `NSBonjourServices` `_onepass-pair._tcp`.

## 8. Erreurs

Messages en français, sans contenu secret : QR expiré ("Le code a expiré. Un nouveau s'affiche."), code refusé par l'utilisateur ("Appairage annulé. Rien n'a été envoyé."), appareil introuvable sur le réseau ("Rapproche les deux appareils et vérifie qu'ils sont sur le même Wi-Fi."), instantané trop gros, mot de passe actuel faux, coffre non vide, dernier coffre, appareil retiré, mot de passe changé ailleurs.

## 9. Sécurité (mise à jour de `docs/security/README.md`)

Nouvelle section "Jalon 2b" : format v2 des paramètres et époque, changement de mot de passe et ce qu'il ne coupe pas, listes signées et fusion, suppression de coffre et règles de suppression distante, protocole d'appairage complet avec la table des attaques (homme du milieu, rejeu, QR photographié, appareil volé, appareil retiré), transport local, mode public. L'écart 8 devient fermé.

## 10. Tests

- **Rust** : paramètres v2 (signature, époque, rejeu refusé, récupération déchirée, compatibilité v1) ; changement de mot de passe à deux appareils sur le faux serveur (l'autre appareil suit, ses écritures en attente survivent, l'ancien mot de passe et l'ancienne AUK échouent) ; listes (signature, chaînage, rejeu, fusion concurrente à deux appareils, migration, auto-inscription, retrait, id retiré refusé) ; coffre masqué jamais ouvert détecté ; adoption d'un coffre non listé ; suppression de coffre propagée, refusée hors liste, coffre non vide refusé, dernier coffre refusé ; protocole d'appairage complet en mémoire (personnel et public), QR expiré, mauvais hash, homme du milieu qui substitue la clé, rejeu de trame, trame de l'autre sens, code différent si la transcription change, instantané importé avec les vérifications du magasin hostile, plafond de taille.
- **Swift** : coordinateurs sur le transport en mémoire (deux sessions VaultKit), session publique (expiration, inactivité, fin, connexion perdue), changement de mot de passe et réenrôlement, appareil retiré qui s'efface, transport réseau local entre deux connexions de la même machine.
- **Builds** : iOS et Mac.

## 11. Limites

- Le retrait d'un appareil n'est pas une coupure cryptographique : un appareil retiré qui garde ses données et sa Secret Key, ou un attaquant qui a extrait son keyset, peut encore déchiffrer ce que le serveur lui donne. La coupure demande la rotation complète du keyset et de la Secret Key (jalon ultérieur). Conseil affiché après un retrait : changer le mot de passe maître.
- Le changement de mot de passe ne change pas les clés : qui détenait l'ancien keyset et l'ancien mot de passe garde l'accès aux clés.
- Les noms d'appareils et les identifiants de coffres de la liste sont lisibles par le serveur.
- La preuve de proximité est celle du réseau local (même Wi-Fi ou AWDL), pas Bluetooth LE ni UWB.
- Session publique : un appareil public compromis voit ce qui est ouvert pendant la session.
- Vérifiés seulement sur du vrai matériel : Bonjour et AWDL entre deux appareils, autorisation "Réseau local" de iOS, caméra.

## 12. Hors périmètre

Rotation complète des clés et de la Secret Key ; relais distant ; transfert vers un appareil hors Apple (le protocole est prêt) ; écriture depuis une session publique ; preuve de proximité Bluetooth ou UWB.

## 13. Décisions

- Ruling: brainstorming architectural, questions et validations tranchées par la session - consigne "aller au bout sans demander" - une décision qui déplaît se reprend par une passe de spec et de plan.
- Ruling B1: le changement de mot de passe rescelle le même keyset sous une nouvelle AUK, avec des paramètres signés d'époque + 1, sans changer les clés - c'est ce qui permet aux autres appareils de suivre sans perte (clés de coffre, manifestes et écritures en attente inchangés) et sans casser les archives et l'état de voyage signés - quelqu'un qui détenait l'ancien keyset et l'ancien mot de passe garde les clés ; la rotation complète vient plus tard.
- Ruling B2: époque des paramètres dans un format v2 préfixé `OPP2`, v1 lu comme époque 0 - ajout compatible sans migration forcée - deux formats à lire.
- Ruling B3: nouvel état local `chain` dans la table `meta`, `DeviceState` inchangé - une autre session durcit la sécurité en parallèle et touche l'état d'appareil - deux états à garder cohérents.
- Ruling B4: listes des appareils et des coffres signées par la clé de signature hybride du compte, pas par la clé d'identité SLH-DSA - signature rapide et petite à chaque création de coffre et appairage - une rotation future de la clé de signature devra resigner les listes (comme les manifestes).
- Ruling B5: listes en ensembles monotones fusionnés par union - convergence sans ancêtre ni conflit insoluble - un appareil retiré ou un coffre supprimé ne reviennent jamais.
- Ruling B6: le retrait d'un appareil est un ordre signé que le client honnête applique (effacement), pas une coupure cryptographique - la coupure demande la rotation complète du keyset et de la Secret Key, hors de ce jalon - un appareil volé non effacé et déjà ouvert peut lire ce que le serveur lui sert ; documenté.
- Ruling B7: coffre non listé mais valablement signé adopté par le prochain appareil déverrouillé - un client du jalon 2 peut créer un coffre sans connaître la liste - un coffre créé par un appareil retiré qui garde ses clés serait adopté.
- Ruling B8: suppression de coffre seulement sans élément vivant ni archivé (les éléments à la corbeille sont purgés avec lui), jamais le dernier - évite la perte silencieuse d'éléments et un compte sans coffre - l'utilisateur vide d'abord le coffre.
- Ruling B9: transport d'appairage en réseau local (Bonjour, Network.framework, pair à pair), pas de rendez-vous CloudKit ni de Bluetooth LE - aucun serveur, utilisable sans iCloud (mode public, futur hors Apple), testable entre deux processus, proximité de fait - deux appareils éloignés ne peuvent pas s'appairer ; un attaquant sur le même Wi-Fi peut tenter un homme du milieu, que le QR et le code court arrêtent.
- Ruling B10: l'autorisation transporte un instantané chiffré de tout le magasin (50 Mio au plus) - le nouvel appareil s'ouvre tout de suite, même sans iCloud ni build signé, et le même chemin servira hors Apple - un coffre plus gros que 50 Mio doit attendre la sync CloudKit.
- Ruling B11: le QR ne porte que le hash de la clé éphémère et un préfixe `OPPAIR1:` (pas d'URL) - la clé complète passe par le transport, le QR reste petit, et l'appareil photo du système n'ouvre pas l'app - aucun.
- Ruling B12: code court de 6 chiffres confirmé des deux côtés, et seconde présence (Face ID, sinon mot de passe maître) sur l'approbateur avant l'envoi - spec 4.9 points 5 et 7 - deux gestes de plus.
- Ruling B13: approbation depuis un iPhone ou un iPad seulement (scanner) ; Mac et Vision Pro ne font qu'être ajoutés - le scanner n'existe que là (R19 du jalon 2) - on ne peut pas ajouter un appareil depuis un Mac.
- Ruling B14: session publique en lecture seule, éléments déchiffrés envoyés dans le canal, en mémoire seulement, fin aussi à la perte de connexion - aucun keyset ni clé de coffre ne quitte le téléphone (spec 4.10), fermeture sûre - le téléphone doit rester proche pendant la session.
- Ruling B15: journal de la session publique en mémoire sur le téléphone, non conservé après la fin - pas de nouveau stockage de métadonnées - l'historique disparaît à la fin de la session.
- Ruling B16: QR renouvelé toutes les 30 s, valable 2 min - spec 4.9 point 1 - aucun.
- Ruling B17: appareils du jalon 2 inscrits par auto-inscription au premier déverrouillage, id retiré jamais réinscrit - migration sans action - un appareil retiré qui garde ses clés pourrait signer une liste où il revient, mais pas avec le même id.
- Ruling B18: Simulateurs dédiés `OnePass M2b iPhone` et `OnePass M2b iPad` - consigne "utilise ton propre Simulateur" - aucun.
