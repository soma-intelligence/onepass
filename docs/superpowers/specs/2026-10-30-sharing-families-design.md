# Partage, familles et base des équipes

Date : 2026-10-30
Statut : brouillon pour la revue du fondateur. Rien n'est implémenté. Décisions proposées S1 à S30 (section 18), questions ouvertes en section 21.
Branche : `docs/sharing-families`, depuis `origin/main` (`88468668`).
Dépend de : la rotation v2 (`docs/superpowers/specs/2026-10-28-key-rotation-v2-design.md`, branche `feat/key-rotation-v2`, en cours de construction). Ce document en reprend le vocabulaire (clés d'appareil, lignée, `identity_id`, serveur = boîte aux lettres hostile, retrait = vraie rotation) et ne se livre qu'après elle (S1).
Portée : coffres partagés entre comptes, partage d'un item, offre Famille (organisateur, membres, aide à la récupération), et les briques qu'une offre Équipe reprendra. Hors portée : facturation, serveur self-host, web app, SSO et SCIM.

## 1. Pourquoi maintenant, et ce qui existe déjà

Aujourd'hui un compte = une personne. La spec d'architecture (1, 4.2) a prévu le partage dès la v1 : une clé par coffre, enveloppée par la paire KEM hybride de chaque membre, et "en v1 le seul membre est le propriétaire". Le code suit cette forme :

- `Vault::create` enveloppe la clé du coffre pour `account.params.kem_pub`, contexte `"vault:" || vault_id` (`vault.rs`). La README de sécurité (3.3) impose qu'un second usage du KEM (appairage, partage) passe par `wrap_key_labeled` sous un label à lui, avec un contexte préfixé de sa longueur. L'appairage le fait déjà (`onepass/pairing/v1`) ; le partage fera de même.
- Le manifeste d'un coffre est signé par la clé de signature hybride du compte (`manifest.rs`, domaine `"manifest"`), chaîné par `seq` et `prev_hash`, avec l'extension `ManifestExt` (meta lié, historique de 64). Dans un coffre partagé, plusieurs comptes signent : il faut nommer le signataire et vérifier son droit.
- Les listes signées (`lists.rs`) sont des ensembles monotones chaînés, fusionnés par union, signés par le compte. La liste des membres d'un coffre reprendra ce moule, avec un signataire qui change.
- La rotation v2 donne à chaque appareil une clé d'appareil épinglée par le canal SAS, et au compte une lignée publique (genèse, rotations signées par un appareil du roster et par la nouvelle identité). C'est ce qui permet à un autre compte de suivre, de façon vérifiable, les changements d'identité d'un membre.
- L'appairage (jalon 2b, `pairing/`) fournit un canal hybride authentifié par un code court (SAS), en réseau local, dans les deux sens (QR du nouvel appareil ou invitation de l'approbateur, `pairing/invite.rs`). La vérification d'un contact le réutilise.

Le travail de ce document est donc surtout de protocole : qui reçoit quelle clé, d'après quelle clé publique, et comment chacun sait qui a le droit de faire quoi, face à un serveur qui ment.

## 2. Modèle de menace

Repris de la rotation v2 (section 2), élargi à plusieurs comptes.

**T2, le serveur seul** (CloudKit aujourd'hui, un relais aveugle plus tard) : lit, retient, retarde, rejoue, réordonne, forge n'importe quel enregistrement et accepte toute écriture. Il voit les Apple ID des participants d'un partage. Il peut proposer n'importe quelle clé publique pour n'importe quel compte. C'est l'attaquant de l'étude ETH Zurich / USI de 2026 (section 15).

**T1, un appareil retiré d'un membre plus le serveur** : ce qu'il garde est décrit par la rotation v2, plus les clés des coffres partagés que ce membre lisait.

**T3, un ancien membre** retiré d'un coffre ou de la famille : il garde tout ce qu'il a lu et toutes les clés de génération qu'il a reçues ; il fait tourner un client modifié ; il peut s'allier au serveur.

**T4, un membre malveillant toujours membre** : un lecteur qui veut écrire, un rédacteur qui veut gérer, un gestionnaire qui veut lire les coffres privés des autres.

**T5, l'organisateur de la famille** : il gère la famille mais ne doit jamais lire les coffres privés d'un membre, ni prendre son compte, sans l'accord de ce membre et sans un délai visible.

**De confiance** : les appareils de chaque membre (code, trousseau, état épinglé local), la comparaison SAS en face à face ou à la voix, la mémoire de l'utilisateur sur ce qu'il a fait.

**Hors périmètre** : un appareil compromis au niveau système ; ce qu'un membre a lu avant son retrait (on ne reprend pas un secret vu) ; un gestionnaire qui ajoute volontairement un attaquant (c'est son droit, l'historique le montre) ; le déni de service par le serveur ; l'analyse de trafic ; le fait qu'Apple sache qui partage avec qui.

## 3. Objectifs

- **P1 Aucune clé publique venue du serveur n'est utilisée en silence.** Une clé de coffre n'est enveloppée que pour une clé publique épinglée après une vérification faite par un humain (QR et SAS, numéro de sécurité, code de rotation), ou reçue signée par un gestionnaire que l'appareil a lui-même vérifié.
- **P2 Retrait = coupure cryptographique.** Rien de ce qui est écrit dans un coffre après le retrait d'un membre ne s'ouvre avec ce que ce membre détient.
- **P3 Droits vérifiés par chaque client.** Un manifeste n'est accepté que signé par un membre qui a le droit d'écrire ; une liste de membres que signée par un gestionnaire ; tout le reste est refusé, quoi que dise le serveur.
- **P4 Organisateur sans connaissance.** L'organisateur ne lit aucun coffre privé ; l'aide à la récupération demande l'inscription volontaire du membre, la part stockée chez le membre, un délai annulable et une rencontre (section 11).
- **P5 Suivi de la rotation v2.** Le changement d'identité d'un membre retire aussitôt l'ancienne identité chez les autres ; la nouvelle n'est adoptée qu'après une confirmation humaine (section 12).
- **P6 Jamais de perte silencieuse**, comme G4 de la rotation v2 : un retrait, une rotation de clé de coffre ou une course entre gestionnaires ne fait perdre aucune écriture locale.
- **P7 Transport interchangeable** : CloudKit (CKShare) aujourd'hui, relais aveugle demain, mêmes enregistrements, même vérification.

Non-objectifs : effacer à distance ce qu'un ancien membre a gardé ; cacher à Apple le graphe des partages ; partage public d'un coffre entier par lien.

## 4. Vue d'ensemble

1. **Contacts vérifiés.** Avant tout partage, deux comptes se vérifient une fois (QR et SAS en face à face, ou lien d'invitation puis numéro de sécurité comparé à la voix). Chaque appareil épingle la carte de l'autre compte (identité, clés, tête de lignée) dans le carnet de contacts, liste signée et synchronisée du compte (section 5).
2. **Coffre partagé = coffre + liste des membres signée.** Chaque coffre partagé porte une liste chaînée de membres avec leur rôle (Lire, Modifier, Gérer), signée par un gestionnaire, qui engage la génération courante de la clé du coffre (section 7).
3. **La clé du coffre** de génération `g` est enveloppée pour la clé KEM du compte de chaque membre, sous le label `onepass/share/vault-key/v1` (section 6).
4. **Les manifestes** d'un coffre partagé nomment leur signataire et pointent la liste des membres sous laquelle ils sont écrits : les deux chaînes se tiennent (section 8).
5. **Retirer un membre** fait tourner la clé du coffre (génération `g+1`) et rescelle chaque item, comme le passage par coffre de la rotation v2 (section 9).
6. **Les rôles** : lire est cryptographique (avoir la clé) ; modifier et gérer sont des vérifications de signature faites par chaque client, doublées des permissions CKShare (section 10).
7. **La famille** est un groupe signé avec des organisateurs et un coffre Famille ; l'aide à la récupération partage une clé de secours en deux moitiés, l'une chez l'organisateur, l'autre dans le stockage privé du membre (section 11).
8. **Transport** : une zone CloudKit par coffre partagé, partagée par CKShare ; une petite zone par paire de contacts sert de boîte aux lettres (section 13).

## 5. Annuaire des clés publiques et vérification des contacts

### 5.1 Approches

| Approche | Principe | Pour | Contre |
| --- | --- | --- | --- |
| A. Annuaire du serveur | le client demande la clé d'un email au serveur et l'utilise | aucune friction (1Password, Bitwarden par défaut) | un serveur hostile substitue sa clé et lit le coffre ; exactement ce que la rotation v2 refuse |
| B. Transparence des clés | le serveur publie les clés dans un journal en ajout seul, audité (Proton Key Transparency) | peu de friction, détection après coup | exige un serveur, des auditeurs et des preuves d'inclusion ; CloudKit n'en offre pas ; détecte, n'empêche pas |
| C. Contacts vérifiés par l'humain | chaque paire de comptes se vérifie une fois par QR et SAS, ou par numéro de sécurité ; la carte épinglée est la seule source de clés | aucun serveur de confiance, même posture que la rotation v2, prouvable | un geste par paire ; il faut refaire un geste quand l'identité d'un membre change (section 12) |

**Recommandation : C, avec B comme défense en profondeur quand le relais existera** (S2). Le relais pourra publier les cartes dans un journal transparent ; le client continuera de n'utiliser que les cartes vérifiées et se servira du journal pour lever une alerte.

### 5.2 Carte de contact

```
ContactCard {
  format: 1,
  account_id: Id,
  genesis: [u8; 32],              // hash de lignée de la genèse du compte (rotation v2, 6.2)
  head: LineageHead,              // génération et hash de la tête au moment de la carte
  identity_pub: IdentityPublic,   // SLH-DSA de l'identité de `head`
  params: Vec<u8>,                // enregistrement AccountParams de cette identité, signé par elle
  lineage: Vec<LineageRecord>,    // genèse, rotations et intros depuis la genèse (publics)
  name: String,                   // nom affiché choisi par le titulaire, 64 caractères au plus
  issued_at: i64,
}
SignedContactCard { card, identity_sig }   // identité, domaine onepass/contact-card/v1
```

Les clés KEM et de signature du compte viennent des paramètres, signés par l'identité (README 3.5) : la carte n'ajoute aucune clé nouvelle. Un changement de mot de passe ne change pas les clés (ruling B1 du jalon 2b) et ne demande rien aux contacts.

**Empreinte d'un compte** : `SHA-256("onepass/contact-fpr/v1" || account_id || genesis || identity_id)`. **Numéro de sécurité d'une paire** : les deux empreintes triées, concaténées, hachées, affichées en 12 groupes de 5 chiffres, identiques sur les deux téléphones (à la Signal). Il change quand l'une des deux identités tourne.

### 5.3 Vérification

Trois niveaux, stockés dans le carnet (5.4) :

- **Vérifié** : QR et SAS en face à face, ou numéro de sécurité comparé à la voix (appel, FaceTime) puis confirmé sur les deux appareils.
- **Lien** : la carte est arrivée par un lien d'invitation à usage unique (5.3.2), authentifiée par le secret du lien, sans comparaison humaine. Suffit pour Lire et Modifier (question 1), jamais pour Gérer ni pour l'aide à la récupération.
- Aucun niveau "serveur" : une carte trouvée sur le serveur sans l'un des deux chemins n'est jamais utilisée.

#### 5.3.1 En face à face

Réutilise le canal du jalon 2b sans changer sa cryptographie : QR de l'un, scan dans l'app de l'autre, transport Bonjour local, enveloppe `wrap_key_labeled` sous un nouveau label `onepass/contact/v1` (transcription liée), SAS à 6 chiffres confirmé des deux côtés. Dans le canal, chacun envoie `Message::ContactCard(SignedContactCard)` et une preuve de possession signée par sa clé d'appareil sur la transcription (domaine `onepass/device-pop/v1` de la rotation v2). Chaque côté vérifie la lignée de la carte jusqu'à sa tête (5.5), puis épingle. Aucune Secret Key, aucun instantané ne passe : ce n'est pas un appairage, et un nouveau variant de message le dit (`Hello` porte `purpose: Contact`).

#### 5.3.2 À distance

1. Alice crée une invitation : `invite_id` (16 octets) et `invite_secret` (32 octets), envoyés dans un lien `onepass://contact#<base32(invite_id || invite_secret)>` par le canal de son choix (iMessage, Signal). Le fragment ne part jamais vers un serveur. Valable 72 h, usage unique.
2. Bob ouvre le lien, écrit sa carte scellée sous `K_inv = HKDF(invite_secret, "onepass/contact-invite/v1" || invite_id)` dans la zone publique de rendez-vous (13.4), avec une clé KEM éphémère.
3. Alice ouvre la réponse, vérifie la carte de Bob, renvoie la sienne scellée pour la clé éphémère de Bob, liée à la transcription.
4. Les deux sont au niveau **Lien**. L'écran propose aussitôt "Comparer le numéro de sécurité" (appel ou FaceTime) pour passer à **Vérifié**.

Ce que vaut le niveau Lien : un serveur seul (T2) ne peut pas s'interposer, il ne voit pas le secret ; celui qui a lu le lien en transit (le service de messagerie, un téléphone volé) le peut. D'où la règle de 5.3 sur Gérer.

### 5.4 Carnet de contacts

Nouvelle liste signée `ContactBook` (même moule que `DeviceList` et `VaultList` : monotone, chaînée, `RecordKind::ContactBook`), signée par la clé de signature de l'identité courante du compte, clé d'enregistrement `identity_id` comme les listes de la rotation v2 (6.6 là-bas). Entrée :

```
ContactEntry {
  account_id, genesis, pinned_head: LineageHead, identity_pub, sign_pub, kem_pub,
  level: Verified | Link, verified_at: i64, verified_on: Id (appareil), transcript_hash,
  name_local: String,     // nom choisi par moi, jamais celui de la carte
  state: Active | KeysChanged { child: [u8; 32], seen_at } | Removed { at },
  incarnation: u64,       // 0 au premier ajout, +1 à chaque réajout (en fin d'encodage)
}
```

Fusion : deux genèses pour un même compte, l'entrée la plus ancienne reste entière et le carnet lève une alerte (la genèse est comparée avant tout : une genèse forgée ne gagne jamais en montant son compteur, et son retrait ne touche pas l'entrée gardée) ; à genèse égale, l'incarnation la plus haute gagne entière ; dans une incarnation, `Removed` gagne ; `Verified` gagne sur `Link` à identité égale ; une identité plus récente (lignée plus longue validée et confirmée) remplace l'ancienne.

Réajout (arbitrage du plan, 2026-10-31) : un contact retiré ne revient que par une nouvelle vérification en face à face (QR et SAS), au niveau `Verified`, qui écrit l'incarnation suivante ; un réajout au niveau `Link` est refusé, donc une invitation à distance ne le ramène pas, et le numéro de sécurité ne s'applique pas à un contact retiré (il ne fait passer à `Verified` qu'un contact actif au niveau `Link`, après comparaison du numéro affiché, recalculé au moment de confirmer). Un retrait vaut pour son incarnation et n'atteint jamais une incarnation plus haute. Un appareil retiré du compte (T1) pourrait, avant son retrait, signer une entrée forgée : c'est un appareil légitime jusque-là (hors périmètre de la rotation v2 aussi) ; après la rotation, ses signatures sous l'ancienne identité ne sont plus acceptées.

Les noms affichés viennent toujours du carnet local, jamais d'une carte ou du serveur (même règle que la rotation v2, section 9).

### 5.5 Vérifier la lignée d'un autre compte

Bob a épinglé `genesis` et `pinned_head` d'Alice. Il vérifie une tête plus récente comme un appareil restauré de la rotation v2 vérifie un roster : chaque rotation est signée par un appareil présent dans le roster de son parent (roster de la genèse ou de la rotation, plus les intros signées acceptées sous ce parent) et par la nouvelle identité. Ce contrôle prouve qu'un appareil d'Alice a fait la rotation ; il ne dit pas lequel était honnête (section 12).

## 6. Clé du coffre et enveloppes

### 6.1 Approches

| Approche | Destinataire de l'enveloppe | Pour | Contre |
| --- | --- | --- | --- |
| A. Clé KEM du compte du membre | la paire hybride ML-KEM-1024 + X25519 de l'identité courante | rien de neuf à gérer ; la rotation v2 la change déjà et garde les anciennes dans `retired_kem` | toute rotation d'identité d'un membre demande une nouvelle enveloppe (la sienne : il la fait lui-même, 12.2) |
| B. Clé par membre et par coffre | une paire dédiée publiée par le membre pour ce coffre | isole les coffres | une clé de plus par coffre et par membre, à authentifier aussi |
| C. Clés d'appareil de chaque membre (façon MLS) | chaque appareil de chaque membre | retrait d'appareil sans toucher au compte | la liste des appareils d'un autre compte devient un annuaire à suivre ; coût en n x m |

**Recommandation : A** (S3). C reste la piste pour de très grosses équipes.

### 6.2 Format

```
MemberKey {   // RecordKind::MemberKey, id = SHA-256("onepass/member-key-id/v1" || vault_id || g || account_id || identity_id)[..16]
  vault_id, generation: u32, account_id, identity_id,
  envelope: wrap_key_labeled(member.kem_pub, vault_key_g, "onepass/share/vault-key/v1", ctx),
}
ctx = postcard((vault_id, generation, account_id, identity_id))   // longueurs préfixées par postcard
```

L'enveloppe n'est pas authentifiée (README 3.3). La liste des membres signée engage la clé : `key_commit = HMAC-SHA256(vault_key_g, "onepass/vault-key-commit/v1" || vault_id || g)`. Une enveloppe qui s'ouvre sur une autre clé est refusée avant toute lecture (P1, attaque A15). Le coffre personnel d'aujourd'hui garde son enveloppe actuelle (contexte `"vault:"`) tant qu'il n'est pas partagé ; partager un coffre existant le passe à la génération 1 sous ce format (9.5).

## 7. Liste des membres signée

### 7.1 Format

```
MembershipBody {
  format: 1,
  vault_id: Id,
  seq: u64,                     // 1 à la création du partage, +1 à chaque changement
  prev_hash: [u8; 32],          // SHA-256 du corps précédent, zéros pour seq 1
  generation: u32,              // génération courante de la clé du coffre
  key_commit: [u8; 32],         // 6.2
  members: Vec<Member>,         // triés par account_id, 64 au plus (question 12)
  removed: Vec<Removed>,        // monotone : account_id, identity_id, removed_at, by
  signer: MemberRef,            // account_id + identity_id
  reason: Create | Add | Remove | Leave | Role | Rekey | IdentityUpdate | Meta,
  history: Vec<(u64, [u8; 32])>,// 64 ancêtres au plus, comme ManifestExt
  issued_at: i64,
}
Member {
  account_id, identity_id, identity_pub_hash, sign_pub, kem_pub,
  role: Read | Write | Manage, owner: bool,
  level: Verified | Link, added_by: MemberRef, added_at: i64,
  key_pending: bool,            // pas d'enveloppe à cette génération (12.3)
}
SignedMembership { body, sig }  // signature hybride du compte signataire, domaine onepass/membership/v1
```

Enregistrement `RecordKind::Membership`, id = vault_id, version = seq, écrit par `put_if_version` comme un manifeste.

### 7.2 Règles d'acceptation

Un appareil accepte le corps `n+1` si, dans cet ordre :

1. décodage strict, listes triées et uniques, au plus 64 membres, `seq` et `prev_hash` chaînés à sa tête épinglée (ou retrouvés dans `history`, comme 3.7 de la README) ;
2. `signer` est membre de la tête avec le rôle Gérer, sa clé de signature vient du corps épinglé (jamais du corps reçu), la signature se vérifie ; seule exception, `reason = Leave` signé par le membre qui part, qui ne peut que se retirer lui-même ;
3. aucun `removed` ne disparaît ; un compte présent dans `removed` n'est plus dans `members` pour cette identité ;
4. le propriétaire (`owner`) ne peut être retiré ni rétrogradé que par lui-même (question 7) ; il reste toujours au moins un gestionnaire ;
5. une hausse de `generation` va avec un `key_commit` neuf et une `reason` Remove, Leave, Rekey ou IdentityUpdate ;
6. un nouveau membre au rôle Gérer doit avoir le niveau Vérifié dans le corps.

Le même `seq` avec un autre hash est une bifurcation (`MembershipFork`), comme pour les manifestes.

### 7.3 Ajouter un membre

Seul un gestionnaire ajoute, et seulement un contact de son carnet (jamais une adresse email résolue par le serveur). Il recopie dans `Member` les clés de son carnet, écrit l'enveloppe de la génération courante, signe le corps `n+1`, ajoute le participant CKShare (13.2) et dépose dans la zone du contact (13.3) une **invitation** : `ShareInvite { vault_id, membership: SignedMembership (le corps n+1), share_url }`, signée par le gestionnaire. Le nouveau membre vérifie que le signataire est un contact de son carnet avec le rôle Gérer dans ce corps, épingle ce corps comme tête de départ (il ne peut pas vérifier l'historique d'avant, il fait confiance au gestionnaire qu'il a vérifié, comme un appareil appairé fait confiance à son approbateur), puis accepte le partage CKShare.

### 7.4 Courses entre gestionnaires

Deux gestionnaires écrivent `n+1` en même temps : l'écriture conditionnelle n'en garde qu'un, l'autre reçoit `Conflict`, relit et refait son changement par-dessus (fusion monotone : retrait gagne, le rôle le plus bas gagne sur une même modification concurrente, la date la plus ancienne gardée). Une rotation de clé perdante est refaite à la génération suivante. Un serveur qui montre deux `n+1` différents à deux membres est vu dès que l'un écrit un manifeste qui pointe sa branche (8.2).

## 8. Manifestes d'un coffre partagé

### 8.1 Format

Le manifeste garde ses champs. Deux ajouts :

- `ManifestExt` version 2 (octet `2`) : `meta_hash`, `history` et `membership: Seen { seq, hash }`, `generation: u32`. Un client d'avant le refuse (`InvalidFormat`), ce qui est voulu : un coffre partagé ne s'ouvre que chez un client qui sait le vérifier.
- `SharedSignedManifest { blob, signer: MemberRef, sig }`, domaine `onepass/shared-manifest/v1` (un domaine distinct de `"manifest"` : une signature de coffre personnel ne vaut jamais dans un coffre partagé et inversement).

### 8.2 Vérification

En plus de 3.7 de la README :

1. le corps de membres pointé par `ext.membership` est la tête épinglée de l'appareil, ou un ancêtre tel qu'entre lui et la tête aucun corps ne change le rôle du signataire ni la génération ;
2. le signataire a le rôle Modifier ou Gérer dans ce corps, sa clé de signature vient de ce corps ;
3. `ext.generation` est la génération de ce corps, et le blob s'ouvre avec la clé de cette génération ;
4. un changement de `meta_hash` par rapport au manifeste précédent exige le rôle Gérer (renommer, changer les options voyage et MCP) ;
5. un manifeste qui pointe un corps de membres inconnu est mis de côté ; s'il pointe un `seq` déjà connu avec un autre hash, c'est une bifurcation de la liste (`MembershipFork`, alerte).

La règle 1 est le lien entre les deux chaînes : un manifeste dit sous quelle liste il a été écrit, une liste engage la génération de clé. Un membre retiré ne peut plus écrire (règle 2 contre la tête), un manifeste d'avant le retrait reste lisible dans l'historique.

### 8.3 Ce que la signature révèle

Le serveur peut vérifier les signatures avec les clés publiques des membres, qui sont dans la liste en clair : il apprend qui écrit quand. CloudKit l'apprend déjà par l'Apple ID de l'auteur de chaque écriture. Limite documentée (section 16).

## 9. Retrait d'un membre

### 9.1 Approches

| Approche | Principe | Ce que garde le retiré | Coût |
| --- | --- | --- | --- |
| A. Rotation paresseuse | nouvelle clé à la prochaine écriture (Keybase, des systèmes de fichiers chiffrés) | lit tout ce qui est écrit jusqu'à la prochaine écriture, dont celle qui l'a retiré si elle tarde | quasi nul ; viole P2 entre deux écritures |
| B. Nouvelle clé, items réenveloppés | génération `g+1`, chaque clé d'item réenveloppée par la nouvelle clé de coffre, contenus inchangés | les clés d'item des items inchangés (il les avait), rien de ce qui est écrit après | une écriture par item, contenu intact |
| C. Nouvelle clé, items rescellés | génération `g+1`, chaque item rescellé sous une clé d'item neuve, comme le passage par coffre de la rotation v2 (K3, `repo/rotation.rs`) | ce qu'il a lu avant ; aucun chiffré écrit après ne s'ouvre avec ses clés | une écriture complète par item ; même code que la rotation v2 |

**Recommandation : C** (S10). B suffit en théorie, puisque le retiré avait déjà les contenus inchangés, mais C donne un invariant simple à tester et à prouver ("aucun chiffré écrit après le retrait ne s'ouvre avec ce que détient le retiré"), réutilise le code de la rotation v2 et ne coûte qu'à la taille d'un coffre de famille.

### 9.2 Déroulé (sur l'appareil du gestionnaire M)

Préconditions, sinon rien n'est écrit : session déverrouillée, présence fraîche, sync complète, coffre chargé par le chemin vérifié (comme R22 de la rotation v2), M a le rôle Gérer, le retiré n'est pas le dernier gestionnaire ni le propriétaire (sauf lui-même).

1. Nouvelle clé de coffre `g+1`, `key_commit`.
2. Une enveloppe `MemberKey` par membre restant dont l'identité est confirmée ; les membres en `KeysChanged` (12.3) passent à `key_pending: true`, sans enveloppe.
3. Chaque item listé (vivant, archivé, corbeille) rescellé sous une clé d'item neuve à version + 1 ; meta rescellé ; manifeste suivant signé par M, `ext.generation = g+1`, `ext.membership` = le corps `n+1`.
4. Corps `n+1` : `reason = Remove`, retiré dans `removed`, `generation = g+1`.
5. **Une transaction locale** (`put_all_if_version_and_delete`), puis envoi en trois phases comme la rotation v2 (7.1 là-bas) : (a) retrait du participant CKShare, enveloppes, items neufs ; (b) corps de membres puis manifeste, conditionnels ; (c) suppression des anciens items et des enveloppes de la génération `g`, après confirmation de (b).

Les écritures concurrentes d'un autre membre perdent sur le manifeste (`Conflict`), relisent, reçoivent leur enveloppe `g+1` et se rejouent par le rebase normal : rien n'est perdu (P6).

### 9.3 Ce que garde le retiré, et ce qu'on lui dit

Il garde ce qu'il a lu : sa copie locale, ce qu'il a copié ailleurs, les mots de passe qu'il connaît. Son client honnête efface la copie locale du coffre quand il lit son retrait (pas de quarantaine ici : rien de son compte n'est en jeu). L'écran du gestionnaire dit : "Bob ne verra plus rien de nouveau dans Maison. Il a pu garder ce qu'il a déjà vu : 23 mots de passe. Les changer ?" et ouvre la liste dans Watchtower ("Vus par un ancien membre").

### 9.4 Départ volontaire

Tout membre peut se retirer : corps `reason = Leave` signé par lui. Il ne détient pas le droit de faire tourner la clé ; il écrit aussi une `RekeyRequest` (12.2). Le premier client d'un gestionnaire qui la lit fait la rotation `Rekey` automatiquement, sans question : faire tourner une clé n'accorde rien à personne (S12).

### 9.5 Partager un coffre existant, transférer, arrêter

- **Partager un coffre personnel** : le coffre passe dans une zone partagée neuve (13.2) à la génération 1, rescellé (C), premier corps de membres signé par le propriétaire. Le coffre garde son id.
- **Le propriétaire part** : la zone CloudKit est la sienne et ne change pas de main. Un autre gestionnaire crée une zone neuve, y recopie le coffre à la génération suivante, puis le corps `Rekey` final dans l'ancienne zone pointe la nouvelle. Question 7.
- **Arrêter le partage** : rotation vers un coffre à un seul membre, puis retour au format personnel au choix.

## 10. Rôles

### 10.1 Approches

| Approche | Lire | Modifier | Gérer |
| --- | --- | --- | --- |
| A. Signatures vérifiées par chaque client | avoir la clé (crypto) | manifeste signé par un membre Modifier, vérifié | liste signée par un membre Gérer, vérifiée |
| B. Clés séparées par rôle | clé de contenu | une clé de signature de coffre donnée aux seuls rédacteurs | une clé de signature de liste donnée aux seuls gestionnaires |
| C. Contrôle d'accès du serveur seul | permissions CKShare | permissions CKShare | propriétaire de la zone |

Ce qu'aucune approche ne peut changer : celui qui a la clé de contenu peut produire des chiffrés valides. L'écriture n'est donc jamais "cryptographiquement impossible" pour un lecteur ; elle est **refusée par tous les clients honnêtes**, parce que seuls les manifestes comptent (`check_records` refuse tout enregistrement non listé). B ne fait que déplacer la vérification (on vérifie la signature d'une clé de rôle au lieu de celle d'un membre) et ajoute des clés à faire tourner à chaque rétrogradation. C seul est ce que font les produits du marché, et c'est ce que l'étude ETH attaque.

**Recommandation : A, doublé de C comme défense en profondeur** (S13) : la permission CKShare suit le rôle (Lire = `readOnly`, Modifier et Gérer = `readWrite`), ce qui empêche Apple de servir les écritures d'un lecteur, mais aucun client ne s'y fie.

### 10.2 Tableau des droits

| Action | Lire | Modifier | Gérer | Propriétaire |
| --- | --- | --- | --- | --- |
| Voir et remplir les items | oui | oui | oui | oui |
| Créer, modifier, archiver, mettre à la corbeille un item | non | oui | oui | oui |
| Renommer, options voyage et MCP | non | non | oui | oui |
| Ajouter, retirer, changer un rôle | non | non | oui (sauf propriétaire) | oui |
| Faire tourner la clé | non | non | oui | oui |
| Se retirer | oui | oui | oui (sauf dernier gestionnaire) | non, il transfère |

Le MCP et l'agent SSH ne voient un coffre partagé que si son option MCP est vraie, ce qu'un gestionnaire décide pour tous. Question ouverte implicite tranchée : un membre peut aussi masquer localement un coffre partagé au MCP (réglage local, plus strict seulement).

## 11. Offre Famille

### 11.1 Objet

```
FamilyBody {
  format: 1, family_id, seq, prev_hash,
  members: Vec<FamilyMember { account_id, identity_id, sign_pub, kem_pub, role: Organizer | Member, level, added_at }>,
  removed: Vec<Removed>,
  vaults: Vec<Id>,              // coffres de la famille (le coffre "Famille" créé au départ)
  signer: MemberRef, issued_at,
}
SignedFamily { body, sig }      // domaine onepass/family/v1
```

Même règles que 7.2 (Organizer tient le rôle de Gérer, au moins un organisateur, organisateurs au niveau Vérifié). La famille vit dans une zone CloudKit de l'organisateur créateur, partagée avec tous les membres. Six comptes au plus (question 2).

### 11.2 Ce que peut l'organisateur

- inviter et retirer des membres (retirer de la famille = retirer de chaque coffre de la famille, avec rotation, 9.2) ;
- créer des coffres de famille et y fixer les rôles ;
- aider à la récupération d'un membre **inscrit** (11.4) ;
- porter l'abonnement (champ `plan` du compte, spec d'architecture 1) ; la facturation n'entre dans aucune décision cryptographique.

Ce qu'il ne peut pas : lire un coffre privé d'un membre, changer son mot de passe, l'inscrire à la récupération, récupérer sans délai ni rencontre, voir les items d'un coffre de famille où il n'est pas membre (il peut s'y ajouter, l'historique le montre).

### 11.3 Récupération : approches

| Approche | Principe | Risque |
| --- | --- | --- |
| A. Aucune | Emergency Kit seulement, comme aujourd'hui | une personne qui oublie son mot de passe et perd son kit perd tout ; fréquent en famille |
| B. Dépôt chez l'organisateur | le keyset du membre (ou une clé qui l'ouvre) est enveloppé pour l'organisateur (Bitwarden "account recovery", groupe de récupération de 1Password) | l'organisateur seul prend le compte en silence ; un serveur qui substitue la clé de l'organisateur ou inscrit d'office le membre récupère tout (attaques de l'étude ETH) |
| C. Aide à la récupération en deux moitiés, avec délai et rencontre | une clé de secours RK ouvre le keyset ; RK = HKDF(moitié organisateur, moitié stockée dans la base privée du membre) ; la moitié de l'organisateur n'est remise qu'après un délai annulable, en face à face, à un appareil connecté au compte iCloud du membre | organisateur et serveur alliés (ou organisateur plus celui qui a pris l'Apple ID du membre) récupèrent ; voir 11.6 |

**Recommandation : C** (S17 à S21), désactivée par défaut, choisie par le membre.

### 11.4 Inscription (sur un appareil du membre, avec son mot de passe)

1. RK aléatoire de 32 octets ; `S_org` et `S_store` aléatoires ; `RK = HKDF-SHA256(ikm = S_org || S_store, info = "onepass/recovery/rk/v1" || postcard((account_id, identity_id, enrollment_id)))`.
2. Le keyset est scellé une seconde fois sous une clé dérivée de RK : enregistrement `RecoverySlot` (clé = `identity_id`, comme les autres enregistrements par identité de la rotation v2), dans la base privée du membre.
3. `S_store` est écrit en clair dans un enregistrement `RecoveryHalf` de la base privée du membre. Il ne protège que face à quelqu'un qui n'a pas accès à cette base.
4. `S_org` est enveloppé pour la clé KEM de l'organisateur **telle qu'épinglée dans le carnet du membre, au niveau Vérifié** : `wrap_key_labeled(org.kem_pub, S_org, "onepass/recovery/share/v1", ctx(member account, member identity_id, organizer account, organizer identity_id, enrollment_id))`, déposé dans la zone de contact membre-organisateur (13.3) avec un `RecoveryEnrollment` signé par le membre (organisateur, date, délai choisi).
5. L'organisateur reçoit "Léa t'a choisi pour l'aider à récupérer son compte."

Aucune inscription ne vient du serveur, d'une politique de la famille ou de l'organisateur : seul l'écran du membre, après son mot de passe, l'écrit (attaque A9). Une nouvelle identité du membre (rotation v2) ou de l'organisateur annule l'inscription ; le membre est invité à la refaire.

### 11.5 Récupération

1. Le membre, sur un nouvel appareil connecté à son iCloud, choisit "J'ai perdu mon mot de passe ou ma Secret Key", puis "Demander l'aide de Quentin".
2. L'organisateur lance la récupération sur son appareil (présence, mot de passe). Il écrit un `RecoveryRequest` signé dans la zone de contact.
3. Les appareils encore en vie du membre affichent "Quentin a demandé à récupérer ton compte. Ce sera possible le 2 nov. à 14:02. Si ce n'est pas toi, annule." ; "Annuler" écrit un `RecoveryCancel` signé par une clé d'appareil du membre (roster de sa lignée, que l'organisateur vérifie depuis la carte du membre).
4. Après le délai (72 h par défaut, question 3) et sans annulation lue, l'organisateur et le membre se retrouvent : canal du jalon 2b (QR du nouvel appareil du membre, scan par l'organisateur, SAS). L'organisateur ouvre `S_org` et l'envoie dans le canal, scellé pour la clé éphémère du nouvel appareil.
5. Le nouvel appareil lit `S_store` dans la base privée du membre, dérive RK, ouvre le keyset, puis **fait aussitôt une rotation v2** de raison `Recover` (nouvelle Secret Key, nouveau mot de passe, nouvelle identité, nouvel Emergency Kit), roster réduit à lui-même, ses anciens appareils devant suivre par confirmation comme toute rotation. RK, `S_org` et `S_store` sont détruits ; l'inscription est à refaire.
6. Les contacts du membre voient une rotation d'identité et la confirment (section 12) ; l'organisateur, qui était là, la confirme sur place.

### 11.6 Risques de l'aide à la récupération

- **Organisateur et stockage alliés** : l'organisateur a `S_org`, Apple (ou un relais hostile, ou quiconque a pris l'Apple ID du membre) a `S_store` et le `RecoverySlot`. Ensemble, ils ouvrent le keyset. Le délai et la notification n'aident que si le serveur ne les retient pas. C'est le prix de C, écrit tel quel à l'inscription : "Quentin et quelqu'un qui aurait accès à ton compte iCloud pourraient ensemble ouvrir ton coffre."
- **Organisateur seul** : ne peut rien, il lui manque `S_store`. Le formel le prouve (14.2).
- **Serveur seul** : ne peut rien, il lui manque `S_org`.
- **Clé de l'organisateur substituée** : impossible, l'enveloppe vise la clé épinglée Vérifiée (A10).
- **Organisateur qui récupère puis garde l'accès** : la rotation obligatoire de l'étape 5 coupe l'ancienne identité ; l'organisateur n'a jamais vu RK ni le keyset, il n'a vu que `S_org`.
- **Ingénierie sociale de l'organisateur** ("je suis Léa, j'ai perdu mon téléphone") : le délai, la notification sur les appareils de Léa et la rencontre en personne ; à distance, question 4.

## 12. Interaction avec la rotation v2 quand l'identité d'un membre change

### 12.1 Le problème

Alice retire son iPad perdu B : sa rotation v2 change son identité (nouvelles clés KEM, de signature et d'identité). B garde l'ancienne identité d'Alice et la clé de chaque coffre partagé qu'Alice lisait. B allié au serveur (T1) peut aussi forger une rotation "B retire iPhone", vers une identité X à lui. Bob, autre membre, ne peut pas savoir laquelle des deux est honnête : il n'a épinglé que des appareils d'Alice, et B en est un (même raisonnement que `rotation_account_anchor.pv` et `rotation_autofollow.pv`).

### 12.2 Ce que fait Alice (le membre qui tourne)

Dans la même transaction que sa rotation v2 (7.1 de la rotation v2, nouvelle étape 3 bis) :

- pour chaque coffre partagé dont elle est membre, elle écrit une enveloppe `MemberKey` de la génération courante pour sa **nouvelle** identité (elle tient la clé du coffre, personne n'a à lui faire confiance pour ça) ;
- elle publie dans chaque zone partagée et chaque zone de contact ses enregistrements de lignée publics (`MemberLineage` : la rotation, ses signatures, les intros utiles) ;
- si la rotation retire un appareil (`reason = Revoke`), elle écrit une `RekeyRequest { vault_id, account_id, lineage_hash }` dans chaque coffre partagé, car l'appareil retiré tient la clé du coffre ;
- si elle est gestionnaire, elle fait elle-même la rotation de clé des coffres concernés après l'adoption de sa nouvelle identité par les autres gestionnaires (12.4), sinon un autre gestionnaire la fait à la lecture de la demande.

### 12.3 Ce que fait Bob (un autre membre)

Approches :

| Approche | Principe | Problème |
| --- | --- | --- |
| A. Suivi automatique de la lignée | Bob adopte toute rotation valide d'Alice | un appareil retiré d'Alice fait adopter son identité X à Bob, qui lui enveloppera la prochaine clé : fuite (contrôle négatif `sharing_member_autofollow.pv`) |
| B. Tout re-vérifier en face à face | Alice repasse par QR et SAS avec chacun | sûr mais lourd : chaque retrait d'appareil, fréquent, coûte une rencontre par contact |
| C. Retrait automatique, adoption confirmée par le code de rotation | l'ancienne identité d'Alice est retirée aussitôt ; la nouvelle attend qu'un gestionnaire la confirme avec le code de rotation à 6 chiffres qu'Alice lui lit (appel, message), ou par QR | un geste par gestionnaire et par rotation ; Alice perd l'accès aux nouvelles générations de clé tant que personne n'a confirmé |

**Recommandation : C** (S22 à S25). Détail :

1. **Retrait automatique.** Dès qu'un appareil de Bob lit une rotation valide d'Alice (5.5), il n'accepte plus aucune signature de l'ancienne identité d'Alice écrite après ce point (manifeste, corps de membres) et passe l'entrée de son carnet à `KeysChanged`. Que la rotation soit honnête ou forgée, l'ancienne identité est entre les mains d'un appareil retiré : la refuser est toujours juste. Le pire qu'un faux puisse faire est un déni de service sur les écritures d'Alice.
2. **Pendant l'attente**, Alice lit toujours (elle a réenveloppé la clé pour elle-même) ; ses écritures sous la nouvelle identité sont gardées chez elle en attente ("En attente de confirmation par Quentin") et ne sont pas acceptées par les autres ; à la prochaine génération de clé, elle passe à `key_pending` et ne reçoit pas d'enveloppe.
3. **Adoption.** Un gestionnaire voit "Les clés de Alice ont changé le 28 oct. (iPhone de Alice a retiré iPad de Alice). Demande-lui le code affiché sur son iPhone." Il tape le code ; s'il correspond au code de la rotation (HKDF du hash de lignée, rotation v2 6.3), il signe un corps de membres `reason = IdentityUpdate` qui remplace l'identité d'Alice, et écrit les enveloppes manquantes. Les autres membres suivent ce corps signé par un gestionnaire qu'ils ont vérifié : un seul geste par coffre, pas un par membre.
4. **Bifurcation.** Si Bob voit deux rotations sœurs d'Alice, il n'en confirme aucune sans la question de la rotation v2 (8.3 là-bas) posée au gestionnaire : "Deux appareils de Alice se sont retirés l'un l'autre. Lequel a-t-elle encore en main ?"

Ce que le code de rotation vaut : 20 bits comparés par un humain, comme le SAS de l'appairage. Un attaquant qui contrôle B connaît le code de sa propre fausse rotation ; il doit encore se faire passer pour Alice auprès du gestionnaire, à la voix ou par message. Le QR et SAS en personne reste disponible et est requis pour un gestionnaire (12.4).

### 12.4 Quand c'est un gestionnaire ou l'organisateur qui tourne

- **Avec un autre gestionnaire** : l'autre gestionnaire confirme par code ou QR, comme 12.3. C'est pourquoi une famille devrait avoir deux organisateurs (question 13).
- **Seul gestionnaire** : chaque membre doit confirmer lui-même (code ou QR). Jusque-là, les membres gardent la dernière liste signée par l'ancienne identité, refusent toute liste signée après la rotation et lisent normalement ; aucun ajout ni retrait n'est possible. Le propriétaire voit "3 membres doivent encore confirmer tes nouvelles clés".
- **Rotation `Recover` (11.5)** : identique ; l'organisateur présent confirme sur place.

### 12.5 Quand c'est le contact qui tourne, hors coffre

Une entrée de carnet en `KeysChanged` sans coffre partagé ne demande rien tout de suite : elle redevient utilisable après une confirmation par code ou QR, demandée au moment du prochain partage.

## 13. Transport

### 13.1 Approches

| Approche | Pour | Contre |
| --- | --- | --- |
| A. CKShare d'une zone par coffre partagé | natif, permissions Apple, notifications, pas de serveur à nous | Apple seulement ; Apple voit les Apple ID et qui partage avec qui ; la zone reste celle de son propriétaire ; quota du propriétaire |
| B. Base publique CloudKit comme boîte aux lettres pour tout | une seule zone, simple | n'importe qui écrit, pas de permissions, pas de suppression contrôlée |
| C. Relais aveugle à nous | multiplateforme, contrôle des métadonnées, transparence des clés possible | à construire et exploiter |

**Recommandation : A pour les coffres, la famille et les contacts ; B seulement pour le rendez-vous d'invitation (5.3.2) ; C plus tard derrière le même `RecordStore`** (S26 à S28).

### 13.2 Coffre partagé sur CloudKit

- Une zone par coffre partagé (`share.<vault_id>`) dans la base privée du propriétaire, partagée par un `CKShare` de zone (iOS et macOS 15 et plus), participants ajoutés par leur Apple ID ou leur numéro, avec `readOnly` ou `readWrite` selon le rôle (10.1).
- Côté participant, `CKSyncEngine` sur la base partagée ; le `RecordStore` du noyau expose une zone par coffre partagé, avec les mêmes vérifications de magasin hostile (`stage_remote`, `commit_remote`).
- Seul le propriétaire de la zone gère les participants Apple, sauf si le rôle administrateur de CKShare est disponible et fiable sur les versions visées (à vérifier sur appareil, plan Swift) ; sinon un gestionnaire non propriétaire publie le corps signé et le client du propriétaire, à sa prochaine ouverture, applique le changement de participants. La coupure cryptographique ne dépend pas de ce délai (9.2).
- Un participant `readWrite` peut supprimer des enregistrements de la zone : c'est un déni de service, vu par le manifeste (`ManifestMissingItem`) ; tout rédacteur peut réécrire depuis sa copie locale ("Réparer le coffre partagé", outil à prévoir, A19).

### 13.3 Zone de contact

À la vérification d'un contact, l'un des deux crée une petite zone `contact.<pair_id>` partagée avec l'autre. Elle porte les invitations de partage, les lignées publiées, les envois d'items (13.5), l'inscription et les demandes de récupération. Elle ne porte jamais de clé de coffre.

### 13.4 Rendez-vous d'invitation

Base publique CloudKit, enregistrement d'id `SHA-256("onepass/invite-rdv/v1" || invite_id)`, contenu scellé sous `K_inv`, supprimé après usage ou 72 h. Le serveur voit qu'une invitation a eu lieu, pas entre qui (sinon par l'Apple ID de l'écrivain).

### 13.5 Relais futur

Mêmes enregistrements, mêmes ids, mêmes vérifications. Le relais tient pour chaque zone une liste de capacités (jetons par participant) comme défense en profondeur, et peut publier les cartes de contact dans un journal transparent (5.1, B). Aucun client ne lui demande une clé publique pour l'utiliser.

## 14. Partage d'un item

### 14.1 Approches

| Approche | Principe | Pour | Contre |
| --- | --- | --- | --- |
| A. Lien de partage (fragment) | copie de l'item scellée sous une clé tirée au hasard, la clé dans le fragment du lien, la copie hébergée ; expiration, nombre de vues, email optionnel (1Password, Bitwarden Send) | marche pour quelqu'un sans OnePass | expiration et nombre de vues tenus par l'hébergeur seul ; la page web qui déchiffre est un code servi par nous ; qui a le lien a l'item |
| B. Envoi à un contact | copie scellée pour la clé KEM du contact vérifié, déposée dans la zone de contact, signée par l'expéditeur | aucune confiance dans l'hébergeur, garantie P1 | destinataire OnePass seulement ; copie figée, pas de suivi |
| C. Item vivant partagé seul | la clé d'item partagée avec un autre compte (Proton Pass) | suit les changements | nos clés d'item changent à chaque écriture : il faudrait réenvelopper à chaque version ; double modèle de droits |

**Recommandation : B d'abord, A ensuite avec ses limites écrites, jamais C** (S29, S30). Pour un item vivant, on le déplace dans un coffre partagé (éventuellement à deux).

### 14.2 Envoi à un contact (B)

`ItemSend { send_id, from: MemberRef, to: account_id, envelope: wrap_key_labeled(to.kem_pub, K_send, "onepass/share/item-send/v1", ctx), blob: seal(K_send, Item), expires_at, sig }`. Le destinataire vérifie la signature contre son carnet, ouvre, choisit le coffre où ranger la copie. Supprimé de la zone après acceptation ou à `expires_at`.

### 14.3 Lien (A), plus tard

Copie scellée sous `K_link` (32 octets), lien `https://<domaine du projet>/s#<base32(link_id || K_link)>` ; option phrase de passe (Argon2id mêlé à `K_link`) ; une seule vue ou expiration (1 h à 7 jours) ; hébergement en base publique CloudKit, effacement à l'expiration par le client et par le serveur. L'écran dit : "Le lien peut être lu par quiconque l'obtient avant son expiration. L'expiration dépend du serveur." La page de lecture est statique, versionnée, avec son hash publié (question 5).

## 15. Comparaison avec 1Password, Bitwarden et Proton Pass

Sources consultées le 2026-10-30 (liens en fin de section). Ce qui suit résume leurs documents publics, pas un audit.

| Point | 1Password | Bitwarden | Proton Pass | OnePass (ce document) |
| --- | --- | --- | --- | --- |
| Origine de la clé publique d'un membre | serveur ; le livre blanc a une annexe "No Public Key Verification" et reconnaît qu'un serveur qui ment peut substituer une clé [1][2] | serveur ; phrase d'empreinte à comparer par l'admin à l'ajout d'un membre, optionnelle dans les faits [3] | serveur, adresses publiées dans Key Transparency [7][8] | jamais le serveur : contact vérifié (QR et SAS, numéro de sécurité) ou corps signé par un gestionnaire vérifié |
| Retrait d'un membre | pas de rotation de clé de coffre décrite à notre connaissance [1] | la clé d'organisation n'est pas changée au retrait ; les copies hors ligne restent lisibles un temps [4][5] | révocation d'accès décrite, pas de rotation décrite dans le billet de modèle de sécurité [7] | nouvelle génération de clé et rescellement de chaque item, à chaque retrait (P2) |
| Rôles | Lire, Modifier, Gérer, appliqués par le serveur et le client | collections et rôles appliqués par le serveur | Lecture, Modification, Admin | Lire par la clé ; Modifier et Gérer vérifiés par chaque client sur des signatures, CKShare en plus |
| Récupération | organisateur de famille, groupe de récupération qui détient des clés de coffre ; codes de récupération ajoutés ensuite [9][10] | "Account recovery" : l'admin réinitialise ; inscription automatique possible par politique [6] ; l'étude ETH montre l'injection d'une clé d'organisation et l'inscription forcée [11][12] | pas de récupération par un tiers décrite | inscription volontaire du membre seulement, deux moitiés (organisateur, stockage du membre), délai annulable, rencontre, rotation obligatoire après |
| Partage d'un item | lien avec secret côté client, email vérifié optionnel [13] | Send : clé dans le fragment, expiration, nombre d'accès, mot de passe optionnel [14] | partage par clé d'item [7] | envoi signé à un contact vérifié ; lien plus tard, limites écrites |
| Algorithmes d'enveloppe | RSA-OAEP 2048 selon le livre blanc [1] | RSA-2048 OAEP pour la clé d'organisation | OpenPGP (Curve25519) | hybride ML-KEM-1024 + X25519, signatures ML-DSA-87 + Ed25519, identité SLH-DSA |
| Preuve formelle | non publiée pour le partage | non | non | modèle ProVerif avec contrôles négatifs (16) |

Où OnePass fait mieux, et à quel prix :

1. **Aucune clé du serveur** : la classe d'attaques "le serveur substitue une clé" (étude ETH) n'a pas de prise. Prix : un geste de vérification par paire et par changement d'identité.
2. **Le retrait coupe vraiment** : Bitwarden ne change pas la clé d'organisation ; OnePass change la clé et rescelle. Prix : une réécriture du coffre à chaque retrait.
3. **Récupération sans dépôt unilatéral** : ni l'organisateur seul ni le serveur seul ne peut ouvrir un compte, et rien ne s'inscrit sans le membre. Prix : la récupération demande une rencontre et un délai.
4. **Post-quantique de bout en bout**, y compris pour les enveloppes de partage, là où les trois autres reposent sur RSA ou courbes elliptiques d'après leurs documents.
5. **Prouvé** : chaque propriété a sa requête ProVerif et chaque raccourci son contrôle négatif.

Où ils font mieux aujourd'hui : multiplateforme et web (nous : Apple d'abord), partage à une adresse email sans vérification préalable (nous l'interdisons exprès), Key Transparency chez Proton (nous l'ajouterons avec le relais), grosses organisations (SCIM, SSO).

Sources :
[1] 1Password Security Design White Paper, https://1password.com/files/1password-white-paper.pdf
[2] Fil 1Password Community sur l'étude ETH Zurich, https://1password.community/discussions/1password/eth-z%C3%BCrich-paper-concerns/167496
[3] Bitwarden, phrase d'empreinte, https://bitwarden.com/help/fingerprint-phrase/
[4] Bitwarden, retrait et révocation des membres, https://bitwarden.com/help/remove-users/
[5] Bitwarden Community, membre compromis, https://community.bitwarden.com/t/what-to-do-if-organization-member-is-compromised/86107
[6] Bitwarden, Account recovery, https://bitwarden.com/help/account-recovery/
[7] Proton, modèle de sécurité de Proton Pass, https://proton.me/blog/proton-pass-security-model
[8] Proton, Key Transparency, https://proton.me/support/key-transparency
[9] 1Password, récupérer un membre de la famille, https://support.1password.com/recovery
[10] 1Password, codes de récupération, https://1password.com/blog/introducing-1password-recovery-codes
[11] ETH Zurich et USI, étude des gestionnaires de mots de passe face à un serveur malveillant (2026), ePrint 2026/058 selon des résumés secondaires, https://eprint.iacr.org/2026/058
[12] The Hacker News, résumé de l'étude, https://thehackernews.com/2026/02/study-uncovers-25-password-recovery.html
[13] 1Password, sécurité du partage d'items par lien, https://support.1password.com/share-items-security/
[14] Bitwarden, fonctionnement de Send, https://bitwarden.com/blog/bitwarden-send-how-it-works/

La référence exacte de [11] et le détail des algorithmes de Bitwarden et Proton sont à relire contre les documents primaires avant toute publication externe de ce tableau.

## 16. Catalogue des attaques

| # | Attaque | Attaquant | Défense | Test |
| --- | --- | --- | --- | --- |
| A1 | le serveur donne sa propre clé pour un futur membre | T2 | clés du carnet seulement (5.4) | `a1_server_key_never_used` |
| A2 | le serveur ajoute un membre à la liste | T2 | signature d'un gestionnaire épinglé (7.2) | `a2_injected_member_refused` |
| A3 | le serveur rejoue une liste d'avant un retrait pour qu'un gestionnaire enveloppe la nouvelle clé au retiré | T2, T3 | tête épinglée, `seq` et `prev_hash`, bifurcation (7.2) | `a3_membership_rollback` |
| A4 | le retiré lit ce qui est écrit après | T3 | génération `g+1`, rescellement (9) | `a4_removed_reads_nothing_new` |
| A5 | le retiré écrit après son retrait | T3 | signataire contre la tête, génération (8.2) | `a5_removed_write_refused` |
| A6 | un lecteur écrit | T4 | rôle Modifier exigé, `check_records` | `a6_reader_manifest_refused` |
| A7 | un rédacteur renomme ou change les options du coffre | T4 | `meta_hash` changé exige Gérer (8.2) | `a7_writer_meta_refused` |
| A8 | le serveur montre deux listes différentes à deux membres | T2 | manifestes qui pointent la liste, `MembershipFork` | `a8_membership_fork_detected` |
| A9 | le serveur ou une politique inscrit un membre à la récupération | T2, T5 | inscription seulement par l'écran du membre (11.4) | `a9_no_auto_enrollment` |
| A10 | clé de l'organisateur substituée à l'inscription | T2 | clé épinglée Vérifiée | `a10_enrollment_to_pinned_key` |
| A11 | l'appareil retiré d'Alice forge sa rotation pour faire adopter X | T1 | retrait automatique, adoption confirmée par code ou QR (12.3) | `a11_forged_member_rotation_not_adopted` |
| A12 | l'appareil retiré d'Alice lit les coffres partagés après sa rotation | T1 | `RekeyRequest`, rotation par un gestionnaire (12.2) | `a12_revoked_device_after_rekey` |
| A13 | le lien d'invitation est lu en transit | messagerie | niveau Lien sans Gérer ni récupération, SAS proposé (5.3) | `a13_link_level_cannot_manage` |
| A14 | l'hébergeur garde un lien expiré | T2 | limite écrite ; clé dans le fragment | documenté |
| A15 | enveloppe d'une autre clé de coffre | T2 | `key_commit` signé (6.2) | `a15_substituted_envelope` |
| A16 | enveloppe d'un coffre rejouée pour un autre, ou pour une autre génération | T2 | label et contexte (vault, génération, compte, identité) | `a16_envelope_context` |
| A17 | URL CKShare transférée à un inconnu | tiers | il n'a que des chiffrés, aucune enveloppe | `a17_participant_without_envelope` |
| A18 | organisateur seul tente une récupération | T5 | il lui manque `S_store` (11.6) | `a18_organizer_alone` |
| A19 | rédacteur malveillant supprime des enregistrements de la zone | T4 | détecté par le manifeste ; réparation depuis une copie locale | `a19_record_deletion_detected` |
| A20 | course entre deux gestionnaires, l'un retire, l'autre ajoute | honnête | écriture conditionnelle, fusion où le retrait gagne (7.4) | `a20_concurrent_managers` |
| A21 | ancienne signature de coffre personnel rejouée dans un coffre partagé | T2 | domaines distincts (8.1) | `a21_domain_separation` |
| A22 | récupération annulée mais l'annulation retenue par le serveur | T2 + T5 | limite écrite (11.6) | documenté |

## 17. Modèle formel

Nouveaux fichiers dans `formal/proverif/`, lancés par `make formal`, attendus dans `formal/expected.txt` :

- `sharing_core.pvl` : comptes Alice (propriétaire, Gérer), Bob (Modifier), Carol (retirée) ; vérification de contact par canal privé (le SAS, F-02 du modèle formel) ; carnet ; liste des membres signée ; enveloppes vers les clés épinglées ; manifestes partagés avec signataire et pointeur de liste ; retrait avec génération `g+1`. L'attaquant tient le serveur et, après son retrait, tout l'état de Carol.
- `sharing.pv`, requêtes :
  - secret des items écrits après le retrait, face à Carol et au serveur : `not (event(ItemSealedAfterRemoval(m)) && attacker(m))` ;
  - secret de chaque clé de génération face au serveur ;
  - `ManifestAccepted(d, v, w, g) ==> MemberRole(v, w, Write, g)` ;
  - `MembershipAccepted(d, v, n) ==> MembershipSigned(v, n, mgr) && Manager(v, mgr)` ;
  - `EnvelopeAccepted ==> GenerationCreated` (avec `key_commit`) ;
  - sanité : ajout, écriture, retrait, lecture vont au bout.
- `sharing_member_rotation.pv` : Alice tourne, son appareil retiré forge une rotation ; requête `not AdoptIdentity(bob_side, alice, X_attaquant)` vraie avec la confirmation par code (modélisée comme la table privée de ce que l'utilisateur a vraiment fait, comme `rotation.pv`).
- `recovery.pv` : inscription, demande, annulation, remise en face à face ; requêtes : l'organisateur seul n'obtient pas le keyset (vrai) ; le serveur seul non plus (vrai) ; `Recovered(m) ==> Enrolled(m) && Released(org, m)` (vrai) ; organisateur et serveur alliés obtiennent le keyset (faux, limite documentée F-03).
- **Contrôles négatifs**, attendus faux : `sharing_server_directory.pv` (la clé du membre vient du serveur : le secret du coffre tombe), `sharing_no_rekey.pv` (retrait sans nouvelle génération : Carol lit l'item écrit après), `sharing_member_autofollow.pv` (adoption sans confirmation : Bob enveloppe pour X), `recovery_autoenroll.pv` (inscription décidée par le serveur vers une clé non épinglée : le keyset tombe).

Non modélisé : fusion monotone et courses (test de propriété), délais et horloges, CKShare, liens de partage (construction classique, la limite est l'hébergeur).

Budget : moins de 300 s par fichier comme les autres ; `sharing.pv` sera le plus lourd (trois comptes, deux générations).

## 18. Décisions proposées

Format : décision - pourquoi - coût si c'est faux.

- **S1** Le partage se livre après la rotation v2 et s'appuie sur sa lignée, ses clés d'appareil et ses enregistrements par identité - sans elle, retirer un appareil ne coupe rien et un membre ne peut pas suivre l'identité d'un autre - le partage attend la fin de la rotation v2.
- **S2** Annuaire = contacts vérifiés par un humain (QR et SAS, numéro de sécurité), jamais une clé du serveur ; transparence des clés seulement en alerte, avec le relais - même posture que R1 de la rotation v2, ferme A1 et les attaques de l'étude ETH - un geste par paire de comptes.
- **S3** La clé du coffre est enveloppée pour la clé KEM du compte du membre, sous `onepass/share/vault-key/v1` avec un contexte complet - aucune clé nouvelle, `retired_kem` couvre les anciennes enveloppes - chaque rotation d'identité d'un membre demande une enveloppe (il la fait lui-même).
- **S4** La liste des membres signée engage la clé de chaque génération (`key_commit`) - une enveloppe substituée est refusée avant lecture - un HMAC de plus par génération.
- **S5** Niveau Lien autorisé pour Lire et Modifier, jamais pour Gérer ni pour la récupération - un partage à distance doit rester possible, un gestionnaire décide pour tous - un lien lu en transit donne la lecture d'un coffre (question 1).
- **S6** Carnet de contacts = liste signée monotone, synchronisée, noms locaux seulement - les autres appareils du compte partagent sans revérifier - un appareil retiré avant sa rotation a pu écrire une entrée (hors périmètre, comme dans la rotation v2).
- **S7** Liste des membres chaînée, signée par un gestionnaire, acceptée seulement contre une tête épinglée ; un nouveau membre épingle le corps reçu d'un gestionnaire vérifié - même modèle que les manifestes et les listes - il ne vérifie pas l'histoire d'avant son arrivée.
- **S8** Manifestes partagés : signataire nommé, domaine distinct, pointeur vers la liste des membres et la génération - les deux chaînes se tiennent et une bifurcation de liste devient visible - format v2 de `ManifestExt`, refusé par les anciens clients.
- **S9** Propriétaire impossible à retirer par un autre gestionnaire ; au moins un gestionnaire toujours - la zone CloudKit lui appartient - un propriétaire absent bloque son propre retrait (question 7).
- **S10** Retrait = nouvelle génération de clé et rescellement de chaque item, code de la rotation v2 réutilisé - invariant simple, prouvable - une réécriture du coffre à chaque retrait.
- **S11** Le client du retiré efface la copie locale du coffre à la lecture de son retrait, sans quarantaine - rien de son compte n'est en jeu - un faux retrait par le serveur est impossible (signature d'un gestionnaire), un vrai efface tout de suite.
- **S12** Une `RekeyRequest` (départ, rotation d'un membre) est exécutée automatiquement par le premier gestionnaire qui la lit - faire tourner une clé n'accorde rien - un serveur peut provoquer des rotations inutiles (coût, pas fuite).
- **S13** Lire = posséder la clé ; Modifier et Gérer = signatures vérifiées par chaque client ; permissions CKShare en défense en profondeur - c'est ce qui est vraiment possible ; une clé par rôle ne change rien au fond - un client modifié d'un lecteur peut écrire des chiffrés que personne n'accepte.
- **S14** Un changement de meta exige Gérer - les options voyage et MCP valent pour tous - un rédacteur ne peut pas renommer.
- **S15** Famille = groupe signé, organisateurs Vérifiés, six comptes, coffre Famille créé au départ - même moule que la liste des membres - plafond à revoir (question 2).
- **S16** L'organisateur ne lit aucun coffre privé et n'inscrit personne à la récupération - zéro connaissance (P4) - pas de "reprise de compte" à la demande.
- **S17** Récupération par clé de secours en deux moitiés : `S_org` chez l'organisateur (enveloppé pour sa clé épinglée), `S_store` dans la base privée du membre - ni l'organisateur seul ni le serveur seul - organisateur et stockage alliés récupèrent (11.6).
- **S18** Inscription seulement par le membre, avec son mot de passe, jamais par politique ou serveur - ferme l'inscription forcée de l'étude ETH - les familles doivent l'activer membre par membre.
- **S19** Délai de 72 h annulable depuis tout appareil du membre - laisse au membre le temps de refuser - une vraie urgence attend trois jours (question 3).
- **S20** Remise de `S_org` en face à face, par le canal du jalon 2b - bloque l'ingénierie sociale à distance - l'organisateur et le membre doivent se voir (question 4).
- **S21** Une récupération finit toujours par une rotation v2 `Recover` - l'organisateur ne garde rien, les moitiés sont détruites - les contacts du membre confirment une rotation de plus.
- **S22** Une rotation valide d'un membre retire aussitôt son ancienne identité chez les autres - elle est entre les mains d'un appareil retiré, quelle que soit la vérité - un faux bloque les écritures du membre jusqu'à confirmation.
- **S23** La nouvelle identité d'un membre n'est adoptée qu'après la confirmation d'un gestionnaire, par le code de rotation dit par le membre ou par QR - sans elle, une rotation forgée fait envelopper la clé à l'attaquant (`sharing_member_autofollow.pv`) - un geste par coffre et par rotation.
- **S24** En attente, le membre lit mais ses écritures restent chez lui et il ne reçoit pas les nouvelles générations - rien de neuf ne part vers une identité non confirmée - il peut perdre l'accès aux nouveautés jusqu'à la confirmation.
- **S25** La rotation d'un gestionnaire seul est confirmée par chaque membre ; avec deux gestionnaires, par l'autre - pas d'auto-confirmation - d'où la recommandation de deux organisateurs.
- **S26** Une zone CloudKit par coffre partagé, CKShare de zone, permissions selon le rôle - natif, notifications, quotas d'Apple - Apple voit le graphe des partages.
- **S27** Une zone par paire de contacts comme boîte aux lettres, la base publique seulement pour le rendez-vous d'invitation - aucune écriture anonyme dans les zones utiles - une zone de plus par contact.
- **S28** Le relais futur garde les mêmes enregistrements et ne fournit jamais de clé publique utilisée telle quelle - P7 - aucun.
- **S29** Partage d'un item d'abord par envoi signé à un contact vérifié ; pas de partage vivant d'un item seul - P1 tenu, un seul modèle de droits (le coffre) - un item vivant demande un coffre à deux.
- **S30** Liens de partage pour des personnes sans OnePass plus tard, avec leurs limites écrites (hébergeur, page web) - utile mais en dehors de P1 - jalon S5.

## 19. Jalons et tests

Chaque jalon a sa spec de plan TDD, comme la rotation v2. Tâches indicatives.

| Jalon | Contenu | Tests principaux |
| --- | --- | --- |
| S0 Formats et modèle | `contact.rs` (carte, empreinte, numéro de sécurité), `membership.rs` (corps, signature, règles 7.2, fusion), `ManifestExt` v2, `SharedSignedManifest`, enveloppes `MemberKey`, labels de 19.1 ; modèles ProVerif de la section 17 avant tout code d'app | vecteurs dorés, domaines séparés (une signature d'un domaine échoue dans tous les autres), décodage strict, fuzz de chaque décodeur, `make formal` |
| S1 Contacts | vérification en face à face (canal 2b, `purpose: Contact`), invitation à distance et rendez-vous, carnet signé, vérification de lignée d'un autre compte (5.5), numéro de sécurité | MITM sur le transport refusé, carte d'une autre identité refusée, lien rejoué refusé, carnet fusionné dans les deux ordres |
| S2 Coffres partagés | `Repository::share_vault`, `add_member`, `set_role`, `remove_member`, `leave`; magasin multi-zones dans `RecordStore` (mémoire, SQLite, CloudKit) ; vérification 8.2 ; rotation de retrait (port du passage par coffre) ; Swift : CKShare de zone, `CKSyncEngine` sur la base partagée, écrans | suite `tests/sharing_attacks.rs` A1 à A8, A15 à A17, A19 à A21 ; test de propriété des courses entre gestionnaires (convergence, retrait qui gagne) ; deux comptes et trois appareils contre `InMemoryRemote` multi-zones ; CKShare vérifié sur vrais appareils (deux Apple ID) |
| S3 Lien avec la rotation v2 | étape 3 bis de la rotation, `MemberLineage`, `RekeyRequest`, retrait automatique et adoption par code, `key_pending`, écritures en attente | A11, A12 ; Alice tourne pendant qu'un gestionnaire retire Carol ; gestionnaire seul qui tourne ; bifurcation de lignée d'un membre |
| S4 Famille | `FamilyBody`, invitation, coffre Famille, retrait de la famille, abonnement par le champ `plan` ; aide à la récupération (inscription, demande, annulation, remise, rotation `Recover`) | A9, A10, A18, A22 ; récupération qui va au bout ; annulation vue ; organisateur qui tourne pendant une inscription |
| S5 Items | envoi signé à un contact ; puis liens de partage | expiration, signature de l'expéditeur, refus d'un expéditeur hors carnet |
| S6 Base Équipe | groupes comme membres (une paire KEM de groupe enveloppée pour ses membres, à la 1Password), politiques signées (obligation de vérification, durée de délai), journal d'audit signé et chaîné, plus de 64 membres | conçu ici, spec à part |

Ce que l'offre Équipe reprend sans changement : carnet et vérification, liste des membres et ses règles, manifestes partagés, retrait avec rotation, suivi des rotations d'identité, aide à la récupération (avec un administrateur à la place de l'organisateur, toujours avec l'inscription volontaire). Ce qu'elle ajoute : le membre "groupe" (une entrée `Member` dont la clé KEM est celle d'un groupe, la clé privée du groupe enveloppée pour chacun de ses membres et tournée à chaque retrait du groupe), des politiques signées par les administrateurs et un annuaire d'entreprise branché sur la transparence des clés du relais.

### 19.1 Labels ajoutés

| Label | Sorte | Clé | Porte sur |
| --- | --- | --- | --- |
| `onepass/contact/v1` | `wrap_key_labeled` | éphémère | clé de canal de la vérification en face à face ; clé de la réponse d'Alice à l'invitation à distance (contexte `SHA-256(rdv_id \|\| reply_bytes)`, arbitrage A-5) |
| `onepass/contact-card/v1` | domaine de signature | identité (SLH-DSA) | `ContactCard` |
| `onepass/contact-fpr/v1` | préfixe de hash | | empreinte d'un compte |
| `onepass/contact-invite/v1` | info HKDF ; label `wrap_key_labeled` | `invite_secret` ; KEM du compte | `K_inv` ; copie locale du secret d'invitation sur l'appareil émetteur (contexte `invite_id`, jamais synchronisée) |
| `onepass/invite-rdv/v1` | préfixe de hash | | id du rendez-vous public |
| `onepass/share/vault-key/v1` | `wrap_key_labeled` | KEM du membre | clé de coffre de génération `g` |
| `onepass/member-key-id/v1` | préfixe de hash | | id d'enveloppe |
| `onepass/vault-key-commit/v1` | HMAC | clé du coffre | engagement de génération |
| `onepass/membership/v1` | domaine de signature | signature hybride du gestionnaire | `MembershipBody` |
| `onepass/shared-manifest/v1` | domaine de signature | signature hybride du rédacteur | blob du manifeste partagé |
| `onepass/family/v1` | domaine de signature | signature hybride de l'organisateur | `FamilyBody` |
| `onepass/recovery/rk/v1` | info HKDF | | RK |
| `onepass/recovery/share/v1` | `wrap_key_labeled` | KEM de l'organisateur | `S_org` |
| `onepass/recovery/request/v1`, `.../cancel/v1`, `.../enroll/v1` | domaines de signature | organisateur, appareil du membre, membre | demandes et inscription |
| `onepass/share/item-send/v1` | `wrap_key_labeled` | KEM du destinataire | `K_send` |

Nouveaux types d'enregistrement, ajoutés à la fin de `RecordKind` après ceux de la rotation v2 (10 à 12) : `ContactBook` 13, `Membership` 14, `MemberKey` 15, `MemberLineage` 16, `RekeyRequest` 17, `Family` 18, `RecoverySlot` 19, `RecoveryHalf` 20, `RecoveryMessage` 21, `ItemSend` 22, `ShareInvite` 23. Tous décodés strictement et fuzzés ; `commit_remote` refuse la suppression par le serveur de `Membership`, `Family` et `MemberLineage`.

### 19.2 Taille

S0 et S1 : environ 6 jours avec revues. S2 : le plus gros (magasin multi-zones et CKShare), 8 à 10 jours dont la partie Swift sur vrais appareils. S3 : 4 jours. S4 : 6 jours. S5 : 3 jours pour l'envoi, liens à part. Environ un mois et demi de travail après la rotation v2.

## 20. Limites

- Ce qu'un membre a lu avant son retrait reste à lui ; OnePass propose de changer les mots de passe concernés.
- Apple voit qui partage avec qui (Apple ID des participants), combien d'items et quand chacun écrit ; un relais futur verra moins, jamais rien de déchiffré.
- Le niveau Lien fait confiance au canal qui a porté le lien.
- Après la rotation d'un membre, il faut un geste humain par coffre (ou par membre si le gestionnaire est seul).
- Aide à la récupération : organisateur et stockage alliés récupèrent ; une annulation retenue par le serveur n'est pas vue.
- Un rédacteur malveillant peut supprimer des enregistrements de la zone (déni de service détecté, réparable).
- Un nouveau membre ne vérifie pas l'histoire de la liste d'avant son arrivée.
- Les liens de partage dépendent de l'hébergeur pour l'expiration.

## 21. Questions ouvertes pour le fondateur

1. **Niveau Lien** (invitation à distance sans comparaison du numéro de sécurité) : autorisé pour Lire et Modifier, ou toujours exiger Vérifié ? Je choisirais : autorisé pour Lire et Modifier, Vérifié exigé pour Gérer et la récupération, avec un badge "Non vérifié" et un rappel.
2. **Taille de la famille** : 6 comptes (Bitwarden), 5 (1Password), ou plus ? Je choisirais 6.
3. **Délai de récupération** : 72 h fixe, réglable par le membre entre 24 h et 7 jours, ou réglable par l'organisateur ? Je choisirais 72 h par défaut, réglable par le membre seulement (24 h à 7 jours).
4. **Remise de la moitié de l'organisateur** : en personne seulement, ou aussi à distance avec le numéro de sécurité comparé en FaceTime ? Je choisirais en personne seulement dans la première version, la distance plus tard si le besoin est réel.
5. **Liens de partage pour des personnes sans OnePass** : dans ce chantier ou plus tard ? Où héberger la page de lecture (domaine du projet) ? Je choisirais plus tard (jalon S5), page statique sur le domaine du projet avec son hash publié.
6. **Confirmation d'une rotation de membre** : le code à 6 chiffres dit à la voix ou par message suffit, ou exiger le QR en personne ? Je choisirais le code pour Lire et Modifier, le QR pour un gestionnaire ou un organisateur.
7. **Propriétaire d'un coffre partagé** : impossible à retirer par un autre gestionnaire (proposé), ou gestionnaires tous égaux avec transfert de zone automatique ? Je choisirais propriétaire protégé, transfert explicite par recopie dans une zone neuve.
8. **Carnet de contacts** : synchronisé entre mes appareils (proposé) ou propre à chaque appareil (plus strict, plus de gestes) ? Je choisirais synchronisé.
9. **Envoi d'un item à un contact** (copie figée) : à livrer avec les coffres partagés ou après ? Je choisirais juste après les coffres partagés (S5), il réutilise la zone de contact.
10. **Abonnement Famille** : payé par l'organisateur dans l'App Store (champ `plan`), ou par le Partage familial d'Apple ? Je choisirais l'abonnement de l'organisateur, sans lien avec le Partage familial d'Apple, qui ne recouvre pas forcément la même famille.
11. **Rotation automatique de la clé d'un coffre** à la lecture d'une `RekeyRequest`, sans question au gestionnaire ? Je choisirais oui, avec une simple notification après coup.
12. **Membres par coffre partagé** : 64 (proposé) ou moins pour borner le coût d'une rotation ? Je choisirais 64 maintenant, l'offre Équipe passera par les groupes.
13. **Deux organisateurs** : simple recommandation à la création de la famille, ou obligatoire au-delà de deux membres ? Je choisirais une forte recommandation, avec un rappel tant qu'il n'y en a qu'un.
14. **Ordre de livraison** : attendre la fin de la rotation v2 avant de commencer S0 (proposé), ou commencer les formats et le modèle ProVerif en parallèle ? Je choisirais de faire S0 (formats et modèle) en parallèle, et de ne rien brancher dans l'app avant la fusion de la rotation v2.

## Décisions du fondateur (2026-10-30)

Réponses du fondateur marquées **(fondateur)**. Les autres sont une première passe de Claude, à confirmer, marquées **(première passe)**. Une décision ici prime sur le texte de la spec ; les sections touchées sont à réécrire au prochain passage.

1. **Invitation à distance sans vérification (niveau Lien) : Lire seulement (fondateur).** Modifier, Gérer et la récupération exigent un contact Vérifié (QR ou numéro de sécurité comparé).
2. **Famille de 6 comptes (fondateur).**
3. **Délai de récupération : 72 h par défaut, réglable par le membre seul entre 24 h et 7 jours (première passe).** Le fondateur n'a pas encore répondu.
4. **Remise de la moitié de l'organisateur en personne seulement en v1 (première passe).**
5. **Liens de partage pour non-utilisateurs plus tard (S5), page statique sur somalabs.me avec hash publié (première passe).**
6. **Confirmation d'une rotation de membre : code à 6 chiffres pour Lire, QR en personne pour Modifier, Gérer et organisateur (première passe).** Aligné sur la décision 1 : tout ce qui écrit exige le niveau Vérifié.
7. **Propriétaire protégé, transfert explicite (première passe).**
8. **Carnet de contacts synchronisé entre mes appareils (première passe).**
9. **Envoi d'une copie figée juste après les coffres partagés (S5) (première passe).**
10. **Abonnement Famille payé par l'organisateur, sans lien avec le Partage familial d'Apple (première passe).**
11. **Rotation automatique de la clé d'un coffre sur `RekeyRequest`, notification après coup (première passe).**
12. **64 membres par coffre partagé (première passe).**
13. **Deux organisateurs fortement recommandés, rappel tant qu'il n'y en a qu'un (première passe).**
14. **S0 (formats, modèle ProVerif) en parallèle de la rotation v2 ; rien dans l'app avant sa fusion (première passe).**
15. **Transport (première passe, conséquence de la décision Supabase de la spec multi-plateforme).** CloudKit `CKShare` reste le transport tant qu'un compte vit sur CloudKit ; un compte passé sur la boîte aux lettres Supabase partage par elle. Un coffre partagé entre un compte CloudKit et un compte boîte aux lettres passe par la boîte aux lettres.
