# OnePass Business : SSO, console d'administration, SCIM, politiques, journaux d'audit

Date : 2026-10-30
Statut : brouillon pour revue du fondateur (rulings E1 à E30 proposés, questions ouvertes en fin de document). Rien n'est implémenté.
Branche : `docs/enterprise`, depuis la `main` privée (`88468668`).
Portée : tout ce qu'il faut pour vendre OnePass à une organisation : déverrouillage par SSO (OIDC, SAML) sans donner les clés au fournisseur d'identité ni à notre serveur, le serveur qu'il faut ajouter, la console d'administration, le provisionnement SCIM 2.0, les politiques, les journaux d'audit, la récupération d'un compte par les administrateurs, les paliers de fonctions, le modèle de menace, le modèle formel, les jalons et les tests.

## 0. Dépendances

Cette spec s'appuie sur trois autres, dont deux sont écrites en parallèle. Elle nomme chaque point où elle en dépend.

| Réf. | Spec | Ce que cette spec suppose |
| --- | --- | --- |
| [ROT] | `2026-10-28-key-rotation-v2-design.md` (en construction) | Clés d'appareil hybrides (ML-DSA-87 + Ed25519, ML-KEM-1024 + X25519, moitié post-quantique dans la Secure Enclave sur Apple), épinglées par le canal SAS ; lignée signée du compte ; serveur = boîte aux lettres hostile ; vraie rotation des clés au retrait d'un appareil ; livraison de la Secret Key scellée pour la clé KEM d'un appareil (`KeyDelivery`) ; quarantaine avant effacement. |
| [PART] | spec partage et familles (en cours) | Coffres partagés : clé de coffre enveloppée pour la clé KEM de chaque membre, **liste de membres signée** et chaînée, rôles par coffre (lecture, écriture, gestion), rotation de la clé du coffre quand un membre sort, invitation d'une personne par empreinte vérifiée. |
| [RELAIS] | spec clients multiplateformes et sync par relais aveugle (en cours) | Implémentation `RecordStore` sur un relais HTTP qui ne voit que des blobs chiffrés et signés ; clients Windows, Linux, extension autonome ; stockage des clés d'appareil hors Apple (TPM, Windows Hello, Secret Service, WebAuthn PRF). |

Si [PART] ou [RELAIS] décident autrement sur un point cité ici, le point de cette spec est à reprendre ; la section 17 liste les points de contact.

## 1. Pourquoi et ce qui change

Aujourd'hui OnePass n'a pas de serveur : chaque compte vit dans la base CloudKit privée de son propriétaire, le déverrouillage est 2SKD (mot de passe maître + Secret Key de 256 bits, Argon2id puis HKDF, `docs/security/README.md` 3.1), la crypto est hybride post-quantique. Rien de cela ne suffit à une organisation, qui veut :

1. que ses membres se connectent avec le compte de l'entreprise (Okta, Entra ID, Google Workspace), sans un mot de passe de plus à retenir ;
2. créer et couper les accès depuis son annuaire (SCIM), et qu'un départ coupe vraiment l'accès aux coffres partagés ;
3. imposer des règles (verrouillage, biométrie, nombre d'appareils, voyage, export) ;
4. voir qui a fait quoi, avec un journal qu'on ne peut pas réécrire en silence ;
5. récupérer le compte d'un membre qui a tout perdu.

Chacun de ces besoins tire vers un serveur qui sait et peut beaucoup. Le principe de cette spec : **le serveur gagne des pouvoirs de service, jamais des pouvoirs cryptographiques**. Il peut refuser, retarder, voir des métadonnées ; il ne peut ni lire un item, ni ajouter un membre à un coffre, ni assouplir une politique, ni effacer une ligne d'audit sans que cela se voie. Les pouvoirs cryptographiques (lire, ajouter, retirer, récupérer) restent sur des appareils, signés par des clés d'appareil épinglées, comme dans [ROT].

## 2. Faits et contraintes de départ

- Noyau Rust partagé (`core/onepass-core`), crates `onepass-guard` (approbations, configuration signée localement, journal haché en chaîne), `onepass-peer` (identité de code d'un pair local), `onepass-relay` (hôte de messagerie native, ne lit rien), `onepass-mcp` (serveur MCP sous politique signée). Le journal d'audit et la politique signée du MCP (`docs/security/README.md` 11.1) sont les ancêtres directs des sections 10 et 11.
- Licence AGPL-3.0-or-later pour tout le dépôt, avec CLA (décision du 2026-10-26). Le serveur sera donc public et auto-hébergeable par construction.
- L'architecture prévoyait déjà un serveur `axum` (Postgres + stockage objet S3) derrière le trait `RecordStore` (spec d'architecture, section 3) et un champ `plan` sur le compte.
- [ROT] interdit déjà de faire confiance à une clé de compte ou au serveur pour une décision de confiance. Cette spec étend la même règle à l'organisation.

## 3. Modèle de menace

### 3.1 Adversaires

- **T-SRV, notre serveur ou celui du client, hostile.** Il lit, retient, retarde, rejoue, réordonne, forge tout ce qu'il stocke ; il voit chaque requête ; il peut servir n'importe quelle réponse SCIM, OIDC ou SAML qu'il prétend avoir reçue ; il sert la console web (section 8.2). Il n'a aucune clé d'appareil.
- **T-IDP, le fournisseur d'identité compromis**, ou un compte IdP volé (hameçonnage, jeton de session volé, administrateur IdP malveillant). Il fait passer n'importe qui pour n'importe quel membre auprès du serveur. Il n'a aucune clé d'appareil.
- **T-SRV+IDP**, les deux ensemble.
- **T-ADM, un administrateur OnePass malveillant** (ou dont l'appareil est compromis). Il a les pouvoirs que lui donne son rôle signé, pas plus.
- **T-DEP, un membre parti**, qui garde ses appareils, leurs clés, ses caches locaux et tout ce qu'il a déjà déchiffré.
- **T-VOL, un voleur d'appareil**, verrouillé ou non.
- **T-CLI, un client modifié** (le code est public) : il ignore toute règle qui n'est pas cryptographique.

### 3.2 Confiance

Les appareils honnêtes (code, Keychain, Secure Enclave, état épinglé), l'épinglage de l'identité de l'organisation à l'adhésion (section 5.3), la comparaison SAS des appairages ([ROT] 5.2), la mémoire des utilisateurs et des administrateurs, les détenteurs de la clé de récupération de l'organisation en dessous du seuil (section 12).

### 3.3 Hors périmètre

Appareil déverrouillé et compromis au niveau système ; déni de service par le serveur ou l'IdP (ils peuvent toujours tout bloquer) ; analyse de trafic ; un seuil d'officiers de récupération qui s'entendent (c'est le pouvoir qu'on leur donne) ; ce qu'un membre parti a déjà déchiffré ou copié.

### 3.4 Objectifs

- **B1** Ni T-SRV, ni T-IDP, ni les deux ensemble ne déchiffrent un item, sans un appareil enrôlé déverrouillé par son utilisateur.
- **B2** Ni T-SRV ni T-IDP ne font entrer un appareil, un membre, un administrateur ou un officier de récupération ; il faut une signature d'appareil épinglé autorisé par son rôle.
- **B3** Une politique ne s'assouplit jamais sans la signature d'un administrateur ; le serveur peut la retenir, pas la rejouer en arrière.
- **B4** Après le départ d'un membre et la rotation des coffres qu'il voyait, rien de ce qui est écrit ensuite ne s'ouvre avec ce qu'il garde ([ROT] G1 étendu aux coffres partagés, via [PART]).
- **B5** Toute suppression, modification, insertion ou troncature d'une ligne d'audit d'un appareil est détectée dès qu'un autre appareil ou l'auditeur voit une tête plus récente.
- **B6** Une récupération de compte par l'organisation n'arrive jamais en silence : le membre en est prévenu sur ses appareils, peut s'y opposer pendant un délai, et elle laisse une trace d'audit signée.
- **B7** Le serveur est auto-hébergeable, et le client a les mêmes garanties contre notre instance que contre celle du client.

## 4. Vue d'ensemble

```
            IdP (OIDC / SAML, SCIM)
               |            |
          jetons OIDC    SCIM 2.0 (Bearer)
               v            v
   +-----------------------------------------+
   | onepass-server (axum, Postgres, S3)      |
   |  annuaire, config SSO, boîte aux lettres, |
   |  parts de déverrouillage, relais [RELAIS],|
   |  segments d'audit chiffrés, politiques    |
   +-----------------------------------------+
        ^              ^                ^
   appareils      console native     agent de provisionnement
   des membres    (admins, officiers)  (appareil sans coffre)
```

Composants nouveaux :

1. **`onepass-server`** (nouvelle crate, AGPL) : HTTP `axum`, Postgres, stockage objet S3 compatible. Image Docker unique, mode hébergé par nous ou auto-hébergé. Section 7.
2. **Organisation** dans `onepass-core` : identité d'organisation, lignée d'organisation, rôles signés, politiques signées, segments d'audit. Section 5.
3. **Déverrouillage SSO** dans `onepass-core` et VaultKit : clé racine du compte (ARK), enveloppes par appareil, part serveur. Section 6.
4. **Console d'administration** : dans l'app Mac et iPad (actions cryptographiques), plus une console web pour ce qui ne touche aucune clé. Section 8.
5. **Agent de provisionnement** (`onepass-provisioner`, binaire Rust sur `onepass-core`) : un appareil sans aucun accès aux coffres, qui signe les retraits venus de SCIM. Section 9.

## 5. Organisation : identité, lignée, rôles

### 5.1 Comptes gérés

Un membre d'une organisation a un **compte géré** : un compte OnePass ordinaire (keyset, lignée, clés d'appareil de [ROT]) dont la genèse nomme l'organisation (`GenesisBody.org = Some(org_id)`, champ ajouté en fin, format 2). Un compte géré :

- ne peut pas quitter l'organisation (il est clos au départ, section 9.4) ;
- se déverrouille par SSO ou par 2SKD selon la politique (section 11) ;
- peut être récupéré par l'organisation si la politique l'active et que le membre a été prévenu à l'adhésion (section 12) ;
- vit dans le stockage de l'organisation (serveur), pas dans la base CloudKit personnelle du membre.

Un membre peut garder à côté un **compte personnel** (2SKD, CloudKit), jamais visible de l'organisation, jamais couvert par la récupération. L'app sait ouvrir les deux (sélecteur de compte). Ruling E1.

### 5.2 Identité de l'organisation

À la création, l'appareil du premier propriétaire crée :

- `org_id` (16 octets aléatoires) ;
- **clé d'identité d'organisation** SLH-DSA-SHA2-256s (même schéma que l'identité de compte, `docs/security/README.md` 3.4), qui ne signe que la lignée d'organisation ;
- **clé KEM d'audit** hybride ML-KEM-1024 + X25519, pour chiffrer les segments d'audit (section 10) ;
- **clé KEM de récupération** hybride, si la récupération est activée (section 12).

La clé d'identité d'organisation est scellée dans un `OrgKeyset` enveloppé pour la clé KEM du compte de chaque propriétaire (au moins deux propriétaires recommandés, au plus 8). Elle n'est utilisée que pour : la genèse, les changements de propriétaires, le changement de la clé d'audit ou de récupération. Tout le reste est signé par des clés d'appareil d'administrateurs.

Empreinte d'organisation : `SHA-256("onepass/org-fpr/v1" || postcard(OrgIdentityPublic))`, affichée en 4 groupes de 5 mots (liste EFF) dans la console.

### 5.3 Épinglage de l'organisation par un appareil membre

Le point dur : un nouveau membre doit apprendre l'identité de l'organisation par un canal que ni le serveur ni l'IdP ne contrôlent seuls. Trois sources, par force décroissante :

1. **Configuration gérée (MDM)** : `ManagedAppConfig` (Apple), politique de registre (Windows), fichier système (Linux) avec `org_fpr` et l'URL du serveur. L'app la lit avant toute requête. Recommandé pour toute flotte gérée.
2. **DNS du domaine vérifié** : enregistrement `TXT _onepass.<domaine>` = `v=op1; org=<empreinte base32>`, lu par le client directement (résolveur du système, DNSSEC validé quand il existe). Le serveur ne sert pas cette valeur.
3. **Confiance au premier usage avec vérification** : à défaut, le client épingle ce que sert le serveur, marque l'organisation `Tofu`, et la console de l'administrateur affiche l'empreinte à comparer ("Vérifier avec ton administrateur"). Une politique peut interdire ce mode (`require_pinned_org`).

Une empreinte qui change ensuite n'est jamais suivie : seule la lignée d'organisation signée par l'identité épinglée fait évoluer quoi que ce soit (5.4). Ruling E2.

### 5.4 Lignée d'organisation

Même construction que la lignée de compte de [ROT] (6.2, 6.3), sur un autre domaine :

```
OrgGenesisBody { format: 1, org_id, name, org_identity_pub, audit_kem_pub,
                 recovery: Option<RecoveryConfig>, owners: Vec<MemberRef>, created_at }
OrgChangeBody  { format: 1, org_id, generation, parent, kind, ..., issued_at }
  kind = OwnersChanged { owners } | AuditKeyRotated { audit_kem_pub }
       | RecoveryConfigured { config } | RecoveryDisabled
SignedOrgRecord { body, identity_sig, owner_sigs: Vec<(device_id, HybridSignature)> }
MemberRef { account_id, account_identity_pub, devices: Vec<DevicePublic> }
```

Un `OrgChange` doit porter la signature de l'identité d'organisation **et** celles des appareils d'au moins `ceil(n/2)` propriétaires (n = propriétaires de la génération parente, au moins 1). Une seule identité volée ne suffit donc pas à changer les propriétaires ni la clé de récupération dès qu'il y a deux propriétaires. Enregistrement `RecordKind::OrgLineage`, immuable, jamais supprimé.

### 5.5 Rôles signés : la liste des membres

```
RosterBody { format: 1, org_id, seq, prev_hash, org_head: [u8; 32],
             members: Vec<OrgMember> }       // trié par account_id
OrgMember  { account_id, account_identity_pub, scim_id_hash: [u8; 32],
             roles: RoleSet, state: Invited | Active | Suspended | Removed { at, by },
             devices: Vec<DevicePublic> }
RoleSet    = sous-ensemble de { Owner, Admin, UserManager, PolicyManager, Auditor,
                                RecoveryOfficer, Provisioner }
SignedRoster { body, signer: device_id, sig: HybridSignature }
```

- Signée par l'appareil d'un membre qui a `Owner`, `Admin` ou `UserManager` dans la liste précédente (un `Provisioner` ne peut que passer un membre en `Suspended` ou `Removed`, section 9). Chaînée (`seq`, `prev_hash`) et monotone comme les listes signées de 2b : un membre ne disparaît jamais, il passe à `Removed`.
- Personne ne se donne un rôle qu'il n'a pas : un `UserManager` ne donne ni `Admin`, ni `Owner`, ni `RecoveryOfficer`. `Owner` ne change que par la lignée d'organisation (5.4). `RecoveryOfficer` ne change que par `RecoveryConfigured`.
- Le serveur garde la liste ; chaque client vérifie la chaîne, refuse un `seq` ancien ou une bifurcation (`OrgRosterRollback`), et refuse une liste dont le signataire n'avait pas le rôle dans la liste précédente.
- `scim_id_hash = SHA-256("onepass/scim-id/v1" || org_id || externalId)` : le lien avec l'annuaire, sans donner l'identifiant SCIM en clair au client.

La liste des membres de l'organisation n'est pas la liste des membres d'un coffre : l'accès à un coffre reste la liste signée de [PART]. La liste d'organisation sert à savoir **qui a le droit de signer quoi** (inviter, retirer, publier une politique) et à afficher l'annuaire.

### 5.6 Coffres de l'organisation

Les coffres partagés de l'organisation sont des coffres de [PART] dont la liste de membres porte `org_id`. Règle ajoutée : un coffre d'organisation n'accepte comme membre qu'un compte `Active` de la liste d'organisation, et un `Admin` peut retirer n'importe quel membre d'un coffre d'organisation (sans pouvoir le lire s'il n'en est pas membre : retirer ne demande pas la clé, la rotation si, section 9.4). Un administrateur n'est **pas** membre de tous les coffres par défaut (ruling E3) : contrairement à beaucoup d'offres, voir le contenu d'un coffre demande d'en être membre, et l'ajout d'un admin à un coffre est une ligne d'audit visible des gestionnaires du coffre.

## 6. Déverrouillage par SSO

### 6.1 Ce qu'on cherche

Un membre ouvre OnePass avec son compte d'entreprise, sans mot de passe maître, et :

- l'IdP seul, le serveur seul, ou les deux ensemble ne peuvent pas déchiffrer (B1) ;
- un nouvel appareil n'entre que s'il est approuvé par un appareil déjà enrôlé du membre, ou par une récupération d'organisation (section 12) ;
- le retrait d'un membre dans l'IdP ferme l'accès en ligne tout de suite.

### 6.2 Ce que font les autres

| Produit | Mécanisme | Qui peut déchiffrer en plus du membre | Source |
| --- | --- | --- | --- |
| 1Password, Unlock with SSO | Clé d'appareil créée sur chaque appareil ; après l'accord de l'IdP, le serveur envoie un "credential bundle" chiffré que l'appareil ouvre avec sa clé d'appareil ; nouvel appareil lié depuis un appareil déjà lié avec un code de vérification. Sans biométrie, clé d'appareil "obfuscated" sur disque sur certaines plateformes ; 1Password juge alors le risque plus élevé que mot de passe + Secret Key. | Personne sans une clé d'appareil (selon 1Password) ; le Recovery Group d'un compte Business peut récupérer. | [1P-SSO], [1P-OIDC], [1P-WP] |
| Bitwarden, SSO with trusted devices | Clé d'appareil symétrique jamais envoyée ; paire RSA-2048 d'appareil ; le serveur garde la clé de compte chiffrée pour la clé publique d'appareil et la clé privée chiffrée par la clé d'appareil. Nouvel appareil : approbation par un autre appareil, par le mot de passe maître, ou par un administrateur, ce qui exige l'inscription à la récupération de compte (clé de compte chiffrée pour la clé publique de l'organisation). | Les administrateurs via la récupération. | [BW-TDE] |
| Bitwarden, Key Connector | Service auto-hébergé qui garde les clés de compte chiffrées par une paire RSA tenue dans un KMS ou HSM du client ; le membre n'a plus de mot de passe maître. L'exploitant du service peut tout déchiffrer. | L'exploitant du Key Connector (le client). | [BW-KC] |
| Keeper, SSO Connect Cloud | Paire EC par appareil ; nouvel appareil approuvé par push sur un appareil existant, par un administrateur qui déchiffre la clé de données du membre pendant l'approbation, ou par un service "Automator" du client. | Les administrateurs approbateurs, l'Automator. | [KEEPER] |
| Dashlane, Confidential SSO | La partie sensible tourne dans une enclave AWS Nitro ; confiance dans l'attestation de l'enclave et dans AWS. | Qui contrôle l'enclave ou son code attesté. | [DASH] |

Constat commun : **"approbation par un administrateur" est toujours une récupération déguisée**. Pour qu'un administrateur fasse entrer un appareil sans aucun appareil du membre, il faut qu'une clé de l'organisation puisse ouvrir la clé du compte. Cette spec le dit tel quel (section 12) au lieu de l'appeler approbation.

### 6.3 Approches

**A. Serveur de clés (type Key Connector).** Un service de l'organisation garde l'ARK de chaque membre, enveloppée par une clé de KMS ou HSM, et la rend après un jeton IdP valide.
- Pour : aucun appareil existant requis, aucun cas bloqué, simple pour l'utilisateur.
- Contre : l'exploitant du service (ou qui le compromet) + l'IdP = tout déchiffrer, en ligne et en masse. Ce n'est plus du zéro connaissance vis-à-vis de l'organisation, et si nous l'hébergeons, vis-à-vis de nous. Casse B1.

**B. Appareils de confiance avec part serveur liée à l'IdP (recommandée).** Chaque appareil enrôlé garde une part locale protégée par la Secure Enclave et la présence de l'utilisateur ; le serveur garde une deuxième part par appareil, qu'il ne rend qu'après un jeton IdP valide et une requête signée par la clé de l'appareil. L'ARK n'est ouvrable qu'avec les deux. Un nouvel appareil reçoit l'ARK d'un appareil enrôlé du membre, par l'appairage SAS de [ROT] ; sans aucun appareil, seule la récupération d'organisation (section 12) aide.
- Pour : ni l'IdP, ni le serveur, ni les deux ne déchiffrent ; le retrait dans l'IdP coupe l'accès en ligne ; réutilise les clés d'appareil et l'appairage de [ROT].
- Contre : la part serveur n'est pas un facteur cryptographique contre un serveur hostile (il peut la rendre sans IdP) ; perdre tous ses appareils sans récupération activée = compte perdu ; déverrouillage hors ligne borné par la politique.

**C. Enclave de confiance (type Dashlane).** Le secret de déverrouillage vit dans une enclave attestée (Nitro, SGX, SEV-SNP), qui ne le rend qu'après l'IdP.
- Pour : pas d'appareil existant requis, et l'opérateur ne lit pas la mémoire de l'enclave en théorie.
- Contre : confiance déplacée vers le vendeur du matériel et sa chaîne d'attestation (attaques par canaux auxiliaires répétées sur SGX), auto-hébergement difficile, et l'enclave + l'IdP restent capables de tout ouvrir. Contraire à B7.

**Recommandation : B** (ruling E4). A est proposée seulement comme option Entreprise explicitement nommée "séquestre des clés" (section 6.10), désactivée par défaut, affichée au membre à l'adhésion. C est rejetée.

### 6.4 Clés du déverrouillage SSO

- **ARK (Account Root Key)** : 256 bits aléatoires créés à la création du compte géré. Elle remplace l'AUK : le keyset (`OPK3` de [ROT]) est scellé sous `HKDF-SHA256(ARK, info "onepass/ark-auk/v1")`. Les paramètres de compte signés portent `unlock: Sso` au lieu des paramètres Argon2id (format `OPP3`, champ ajouté en fin).
- **Part locale `k_loc`** : 32 octets par appareil, dans le Keychain de l'app (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), enveloppée par une clé Secure Enclave avec contrôle d'accès `.biometryCurrentSet` **ou** `.devicePasscode` selon la politique (section 11). Hors Apple : TPM ou Windows Hello, Secret Service, ou WebAuthn PRF ([RELAIS]).
- **Part serveur `k_srv`** : 32 octets par appareil, tirés par l'appareil à l'enrôlement, envoyés au serveur scellés pour la clé de transport du serveur (TLS suffit, le serveur doit la connaître), jamais gardés en clair sur l'appareil au-delà d'un cache hors ligne (6.7).
- **Enveloppe d'appareil** : `ArkEnvelope = AEAD(K_dev, ARK)` avec `K_dev = HKDF-SHA256(ikm = k_loc || k_srv, salt = device_id, info = "onepass/sso-unlock/v1" || account_id)`, gardée localement et copiée sur le serveur (elle ne lui sert à rien sans `k_loc`).
- **Facteur matériel optionnel** : si la politique `require_hardware_key` est active, `K_dev` prend aussi la sortie PRF d'une passkey ou clé FIDO2 (`hmac-secret`), comme le 3e facteur prévu par la spec d'architecture (4.1). C'est le seul moyen de faire d'un second facteur un vrai facteur cryptographique contre un serveur hostile.

### 6.5 Déverrouillage, pas à pas

1. L'app lance le flux OIDC (code + PKCE, `ASWebAuthenticationSession` sur Apple) vers l'IdP configuré pour l'organisation épinglée.
2. L'IdP rend un code au serveur (redirection vers le serveur) ou à l'app (redirection vers un schéma de l'app, puis l'app transmet le code au serveur) : choix de 6.8.
3. Le serveur échange le code, vérifie le jeton d'identité (émetteur, audience, signature JWKS, `nonce`, `exp`, et le lien `sub` ou `email` vers le membre de l'annuaire), vérifie que le membre est actif et que l'appareil n'est pas retiré.
4. L'app signe avec sa clé d'appareil un `UnlockRequest { org_id, account_id, device_id, nonce_srv, oidc_session_hash, at }` (domaine `onepass/sso-unlock-req/v1`). Le serveur vérifie la signature contre la clé d'appareil de la liste d'organisation, puis rend `k_srv` et l'`ArkEnvelope`.
5. L'app demande la présence (Face ID ou code de l'appareil) pour lire `k_loc`, dérive `K_dev`, ouvre l'ARK, ouvre le keyset, vérifie ses clés publiques contre les paramètres signés du compte (chemin existant de `unlock`), puis efface `k_srv` de la mémoire.

Le serveur ne voit jamais `k_loc`, l'ARK ni le keyset en clair. L'IdP ne voit que l'authentification.

### 6.6 Enrôlement d'un appareil

- **Premier appareil** (création du compte géré à l'invitation) : l'appareil crée ARK, keyset, `k_loc`, `k_srv`, sa clé d'appareil, la genèse du compte ([ROT] 6.2, avec `org`), et un `JoinRequest` signé. Un administrateur l'accepte en signant la liste d'organisation (5.5) ; jusque-là le compte existe mais n'a accès à aucun coffre d'organisation.
- **Appareil suivant, avec un appareil enrôlé du membre** : appairage QR + SAS de [ROT] 5.2. Le `Grant::FullV2` porte l'ARK au lieu de la Secret Key (`Grant::SsoV1`, variante ajoutée en fin), le nouvel appareil crée ses propres `k_loc` et `k_srv` et son enveloppe. L'appareil approbateur écrit l'`Intro` de [ROT] 6.4 et met à jour la liste d'organisation s'il en a le droit, sinon il dépose une demande que le serveur ne peut pas forger (signée par l'approbateur, contresignée par un `UserManager` ou acceptée automatiquement si la politique `auto_accept_member_devices` est active, ce qui ne donne rien de plus que ce que le membre a déjà fait). La politique `max_devices` est vérifiée par l'approbateur (11.3).
- **Sans aucun appareil enrôlé** : récupération d'organisation (section 12), avec délai et prévenance. Il n'existe pas d'"approbation administrateur" plus légère (ruling E5).

### 6.7 Hors ligne et sessions

- Après un déverrouillage SSO réussi, la politique `offline_unlock_hours` (0 à 168, défaut 24) permet de garder `k_srv` dans le Keychain, enveloppé par la même clé Secure Enclave que `k_loc` et horodaté. Pendant cette fenêtre, Face ID suffit sans réseau. À 0, chaque déverrouillage demande l'IdP. Ce cache est, pendant sa durée, la limite de la coupure par l'IdP : un appareil hors ligne retiré de l'IdP reste ouvrable jusqu'à son expiration.
- Le verrouillage biométrique rapide de la spec d'architecture (4.6) reste : entre deux déverrouillages complets, l'app garde le keyset déverrouillé enveloppé par la Secure Enclave, avec les mêmes délais. La politique `sso_reauth_hours` (défaut 12) force un passage par l'IdP.
- Navigateurs et CLI : pas de cache hors ligne en mode autonome ([RELAIS]) ; la CLI d'un compte géré se déverrouille par l'app Mac (socket existant) ou par un compte de service (hors portée de cette spec, question 9).

### 6.8 OIDC et SAML

- **OIDC** : code + PKCE, client public par organisation, `nonce` lié à l'`UnlockRequest`. Le jeton d'identité est vérifié **par le serveur** ; l'app vérifie aussi, directement auprès de l'IdP, l'émetteur épinglé dans la politique signée (`idp_issuer`) et la signature JWKS, pour que le serveur ne puisse pas rediriger le membre vers un faux IdP de son choix sans que la politique signée le dise. Ruling E6.
- **SAML 2.0** : l'assertion est consommée par le serveur (ACS), qui émet ensuite une session interne. L'app ne peut pas vérifier l'assertion elle-même de façon fiable ; le serveur est donc seul juge pour SAML. C'est acceptable parce que l'IdP n'est pas un facteur cryptographique (6.9) ; OIDC reste recommandé et la console le dit.
- **Un IdP par organisation** en v1, plusieurs domaines vérifiés possibles. Plusieurs IdP : option Entreprise plus tard.
- Domaine vérifié : `TXT _onepass-verify.<domaine>` lu par le serveur. Sans domaine vérifié, pas de SSO ni de SCIM.

### 6.9 Le compromis honnête face à 2SKD

| Attaque | 2SKD (mot de passe + Secret Key) | SSO, approche B |
| --- | --- | --- |
| Fuite complète du serveur (ou de CloudKit), attaque hors ligne | Impossible : il faut la Secret Key de 256 bits. | Impossible : il faut `k_loc`, qui ne quitte pas l'appareil. |
| Serveur hostile seul | Rien. | Rien : il a `k_srv` et l'enveloppe, pas `k_loc`. |
| IdP compromis seul | Sans objet. | Ouvre l'accès en ligne, ne déchiffre rien, ne fait entrer aucun appareil sans un appareil du membre (SAS) ou une récupération. |
| Hameçonnage du membre | Il faut le mot de passe **et** la Secret Key (l'Emergency Kit). | Il faut les identifiants IdP **et** que le membre approuve un appareil de l'attaquant, en comparant un code SAS et en présence Bluetooth ([ROT], spec d'architecture 4.9). |
| Vol d'un appareil verrouillé | Il faut le mot de passe maître (Argon2id, hors ligne possible sur la base locale si le voleur extrait la Secret Key du Keychain). | Il faut la biométrie ou le code de l'appareil (Secure Enclave, limité en essais) **et** les identifiants IdP, sauf pendant la fenêtre hors ligne (6.7) où le code de l'appareil suffit. |
| Vol d'appareil + serveur hostile | Mot de passe maître. | Le code de l'appareil suffit : le serveur rend `k_srv` sans IdP. |
| Appareil compromis au niveau système | Perdu (hors périmètre). | Perdu (hors périmètre). |
| Perte de tous les appareils | Emergency Kit + mot de passe. | Récupération d'organisation si activée, sinon compte perdu. |

Conclusion à afficher dans la console et dans le livre blanc : **le SSO remplace un secret que le membre connaît (mot de passe maître de haute entropie) par un secret que l'appareil garde (Secure Enclave) et un portail en ligne (l'IdP)**. Contre un vol d'appareil avec un serveur hostile, la protection tombe au code de l'appareil, qui est court mais limité en essais par le matériel. Contre une fuite de serveur, rien ne change. Les propriétaires gardent 2SKD obligatoirement (ruling E7) : ce sont eux qui tiennent l'identité de l'organisation, et un compte de propriétaire ne doit dépendre ni de l'IdP ni de la récupération. La politique `require_hardware_key` (6.4) relève le vol d'appareil au niveau d'une clé FIDO2 en plus.

### 6.10 Option séquestre (approche A), si le fondateur la garde

Pour les organisations qui exigent la reprise des données sans aucun appareil et sans délai (conformité, conservation légale) : l'ARK de chaque membre est enveloppée en plus pour une clé KEM tenue par un service de l'organisation (`onepass-escrow`, dans son infrastructure, clé dans son HSM ou KMS). Mêmes enregistrements que la récupération (section 12) avec un seuil de 1 et sans délai. Affiché au membre à l'adhésion ("Ton organisation peut ouvrir ton compte sans toi, à tout moment"), visible dans la liste des membres, journalisé à chaque ouverture. Jamais hébergé par nous (ruling E8). Question 2.

## 7. Le serveur

### 7.1 Approches

**S1. Serveur minimal : annuaire, boîte aux lettres, parts, relais (recommandée).** Il garde ce que le zéro connaissance permet et rien de plus ; les données des coffres passent par le relais aveugle de [RELAIS], qu'il héberge.
**S2. Rester sur CloudKit pour les données, serveur seulement pour IdP et SCIM.** Les coffres partagés entre comptes Apple différents passeraient par `CKShare`. Rejeté : pas de clients hors Apple, chaque membre dépend de son propre iCloud (quota, compte personnel mélangé à l'entreprise), l'organisation ne peut pas couper le stockage d'un parti, et il faut de toute façon un serveur pour SCIM.
**S3. Serveur riche (recherche, partage par lien, rapports Watchtower côté serveur).** Rejeté : chaque fonction de ce type demande de voir du clair.

Ruling E9 : S1. Les comptes personnels restent sur CloudKit ; les comptes gérés et les coffres d'organisation vivent sur le serveur de l'organisation.

### 7.2 Ce qu'il stocke

| Donnée | En clair pour le serveur ? | Pourquoi il l'a |
| --- | --- | --- |
| Domaines vérifiés, config IdP (émetteur, client id, certificats SAML) | oui | Faire le SSO |
| Jetons SCIM (hachés, Argon2id) | haché | Authentifier l'IdP |
| Annuaire SCIM : `externalId`, `userName`, email, nom, groupes, `active` | oui | SCIM l'exige ; c'est la donnée de l'IdP, pas du coffre |
| Lien membre SCIM vers `account_id` | oui | Router |
| Lignée d'organisation, listes de membres signées, politiques signées | oui (signées, sans secret) | Les servir aux clients |
| Lignées de compte, intros, livraisons, accusés ([ROT]) | blobs signés ou scellés | Boîte aux lettres |
| `k_srv` par appareil | **oui** | Portail lié à l'IdP (6.4) |
| `ArkEnvelope` par appareil | scellée | Restauration d'un appareil sans perte locale |
| Enregistrements des coffres ([RELAIS]) | scellés et signés | Sync |
| Enveloppes de récupération (section 12) | scellées pour la clé de récupération | Récupération |
| Segments d'audit des appareils | scellés pour la clé d'audit, en-tête signé en clair | Conservation, témoin (10.5) |
| Journal d'accès du serveur | oui, signé par la clé du serveur | Défense en profondeur, rapprochement (10.6) |
| Métadonnées : qui touche quel enregistrement, quand, d'où (IP), tailles | oui | Inévitable ; voir 7.4 |

Il ne stocke jamais : mot de passe, Secret Key, ARK, `k_loc`, keyset, clé de coffre, clé d'identité d'organisation, clé privée d'audit ou de récupération, contenu d'item, nom de coffre ou d'item.

### 7.3 Ce qu'il peut et ne peut pas faire s'il est hostile

Peut : bloquer tout le monde ; retenir une politique, une liste, une rotation ou un segment d'audit (détecté comme retard, pas comme contenu, voir 11.5 et 10.5) ; rendre `k_srv` sans IdP (6.9) ; voir le graphe d'accès (qui ouvre quel coffre, à quelle heure, depuis quelle IP) ; mentir sur l'état SCIM à la console web ; servir du JavaScript piégé à la console web (8.2) ; refuser un retrait (le membre parti garde l'accès en ligne au relais, mais la rotation signée par un gestionnaire coupe tout ce qui est écrit ensuite, B4) ; garder des copies d'anciens blobs (le passé n'est pas protégé, comme dans [ROT]).

Ne peut pas : déchiffrer ; ajouter un membre, un appareil, un admin, un officier ; changer un rôle ; assouplir ou rejouer une ancienne politique ; déclencher une récupération ; modifier, insérer ou supprimer une ligne d'audit d'un appareil sans détection ; faire suivre une rotation de compte ou de coffre ; faire passer un IdP non épinglé auprès d'un client en OIDC (6.8).

### 7.4 Métadonnées et vie privée

Le serveur voit des emails et le graphe d'accès. Réductions : identifiants d'enregistrement opaques ([RELAIS]) ; pas de nom de coffre ni d'item en clair ; journal d'accès du serveur conservé 30 jours par défaut, réglable ; IP tronquées (/24, /48) dans ce journal sauf politique contraire ; aucune télémétrie produit sur l'instance auto-hébergée. Le livre blanc liste exactement ces champs, comme `docs/security/README.md` 10.5 le fait pour iCloud.

### 7.5 Auto-hébergement

- Une image Docker, Postgres 16 ou plus, un stockage objet S3 compatible (MinIO accepté), TLS terminé devant. Variables d'environnement documentées, migration de schéma au démarrage.
- La clé de signature du serveur (journal d'accès, reçus de témoin 10.5) est une Ed25519 + ML-DSA-87 créée au premier démarrage, son empreinte affichée dans la console et épinglée par les clients comme simple témoin (jamais comme racine de confiance).
- Le client a exactement les mêmes vérifications contre notre instance que contre une instance du client (B7). L'URL du serveur vient de la config MDM, du DNS (`_onepass-server.<domaine>`) ou de l'invitation.
- Pas de dépendance à un service à nous depuis une instance auto-hébergée (licences comprises : question 8).

### 7.6 API

REST JSON pour l'administration et SCIM, binaire (postcard) pour les enregistrements du relais. Authentification : session issue de l'IdP pour les membres ; **chaque requête qui change un état cryptographique porte une signature d'appareil** vérifiée par les autres clients, pas seulement par le serveur. Limites de débit par IP et par organisation. Toutes les entrées décodées strictement, avec cibles de fuzzing (SCIM JSON, SAML XML via une bibliothèque sans entités externes, postcard).

## 8. Console d'administration

### 8.1 Périmètre

| Domaine | Actions | Signature d'appareil ? |
| --- | --- | --- |
| Membres | inviter, accepter une adhésion, suspendre, retirer, voir appareils et état "à jour" ([ROT] 6.8) | oui |
| Rôles | donner ou retirer `Admin`, `UserManager`, `PolicyManager`, `Auditor` | oui |
| Propriétaires, officiers, clé d'audit | changer (lignée d'organisation, 5.4) | oui, identité + quorum |
| Coffres d'organisation | créer, voir les membres, retirer un membre, suivre les rotations en attente | oui |
| Politiques | éditer, publier, voir quels appareils l'appliquent | oui |
| Audit | lire, filtrer, exporter (SIEM), vérifier les chaînes | déchiffrement local |
| Récupération | ouvrir une demande, approuver (officiers), suivre le délai | oui |
| SSO | config IdP, domaines, test de connexion | non (serveur seul) |
| SCIM | jetons, état de synchro, journal des requêtes, agent de provisionnement | non, sauf enrôlement de l'agent |
| Rapports | Watchtower agrégé (scores par membre, jamais d'item), adoption | déchiffrement local |
| Facturation, plan | sièges, factures | non |

Hors périmètre v1 : voir le contenu des coffres d'un membre (n'existe pas, sauf récupération), partage par lien public, délégation fine par groupe (Entreprise plus tard).

### 8.2 Où vit la console

**C1. Web seulement** (comme la plupart des offres). Rejeté pour les actions cryptographiques : la page est servie par le serveur, donc un serveur hostile sert un script qui vole la clé d'appareil de l'administrateur dans le navigateur ou lui fait signer autre chose que ce qu'il voit. C'est le défaut connu de toute "web vault".
**C2. Native seulement.** Sûr, mais un administrateur IT sous Windows ou Linux attend [RELAIS], et SSO et SCIM se règlent mieux dans un navigateur.
**C3. Hybride (recommandée).** Toute action qui signe ou déchiffre se fait dans l'app native (Mac, iPad, puis Windows et Linux de [RELAIS]) : section "Organisation" de l'app, visible pour les rôles concernés. La console web ne fait que ce qui ne touche aucune clé : SSO, domaines, SCIM, facturation, état. Elle affiche pour chaque action signée "Ouvre OnePass pour le faire" avec un lien `onepass://org/...`. Ruling E10.

Toute action sensible dans l'app native demande la présence, montre un résumé construit à partir de l'état local épinglé (jamais à partir de ce que dit le serveur), et écrit une ligne d'audit.

### 8.3 Écrans principaux (textes de l'app en français)

- "Membres" : liste, filtre par état, appareils de chacun avec "à jour" ou "en attente", bouton "Retirer de l'organisation" (présence, résumé "Retirer Marie Dupont : 3 appareils, 7 coffres partagés à faire tourner").
- "Coffres" : pour chaque coffre d'organisation, membres, gestionnaires, "Rotation en attente depuis 2 h" avec le gestionnaire attendu.
- "Politiques" : formulaire, différence avec la version publiée, "Publier" (présence).
- "Audit" : chronologie, filtres (membre, appareil, coffre, type), état de vérification de chaque chaîne ("Vérifiée jusqu'au 30 oct. 14:02", "Trou détecté : appareil iPad de Marie, lignes 812 à 830 manquantes").
- "Récupération" : demandes, approbations, délai restant, opposition du membre.

## 9. Provisionnement SCIM 2.0

### 9.1 Ce que fait le serveur

Points d'accès SCIM 2.0 (RFC 7643, RFC 7644) : `/scim/v2/Users`, `/scim/v2/Groups`, `ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `PATCH` et filtres `eq` sur `userName` et `externalId`. Jeton Bearer par organisation, haché, révocable, tourné depuis la console web. Testé contre les validateurs d'Okta et d'Entra ID.

SCIM fait vivre **l'annuaire du serveur** (qui existe, son email, ses groupes, `active`). Il ne fait rien de cryptographique tout seul : une requête SCIM est une affirmation de l'IdP, relayée par un serveur non fiable.

### 9.2 Approches pour relier SCIM aux clés

**R1. Chaque événement SCIM attend un administrateur**, qui l'applique dans la console native. Sûr, mais un départ un vendredi soir attend lundi : inacceptable pour la coupure.
**R2. Agent de provisionnement (recommandée).** Un appareil sans aucun coffre, `onepass-provisioner`, tourne chez le client (conteneur, VM, Mac mini). Il a une clé d'appareil, le rôle `Provisioner` dans la liste d'organisation, et ne peut signer que des passages à `Suspended` ou `Removed` et des invitations. Il lit les événements SCIM au serveur, les rapproche de l'annuaire, et signe. Il n'a ni ARK, ni clé de coffre, ni clé d'audit : le compromettre permet de retirer ou d'inviter, pas de lire ni d'ajouter à un coffre.
**R3. Le serveur signe lui-même.** Rejeté : redonne au serveur le pouvoir de B2.

Ruling E11 : R2, avec R1 comme repli quand aucun agent n'est déployé (la console native montre la file "Événements SCIM à appliquer").

### 9.3 Création et invitation

1. `POST /Users` : le serveur crée l'entrée d'annuaire, l'agent signe un `Invited` dans la liste d'organisation (ou un `UserManager` le fait).
2. L'email d'invitation porte l'URL du serveur et l'empreinte de l'organisation. Le membre installe l'app, l'épinglage suit 5.3 (MDM, DNS ou vérification).
3. Le premier appareil crée le compte géré (6.6) ; l'adhésion passe `Active` par la signature d'un `UserManager` ou automatiquement par l'agent si la politique `auto_activate_scim_members` est active (l'agent vérifie que la demande vient du membre invité, liée par l'`externalId` haché et le jeton d'invitation).
4. Les groupes SCIM peuvent pré-remplir l'accès aux coffres : un groupe relié à un coffre produit une **proposition** d'ajout, que le premier gestionnaire du coffre en ligne signe ([PART]) ; ajouter à un coffre demande la clé du coffre, que ni le serveur ni l'agent n'ont.

### 9.4 Départ : retrait, rotation, effacement

`PATCH active=false` ou `DELETE /Users/{id}` :

1. **Tout de suite, serveur (honnête)** : sessions du membre fermées, `k_srv` de ses appareils refusés, accès au relais coupé.
2. **En quelques secondes, agent** : liste d'organisation signée, membre `Removed { at, by: agent }`. Tous les clients honnêtes le voient.
3. **Rotation des coffres partagés** ([PART]) : pour chaque coffre d'organisation dont il était membre, le premier appareil d'un gestionnaire en ligne retire le membre de la liste signée du coffre et fait tourner la clé du coffre (nouvelle clé enveloppée pour les membres restants, contenu rescellé selon la règle de [PART]). La console suit "rotation en attente". Politique `rotation_deadline_hours` (défaut 24) : passé ce délai, le coffre passe en lecture seule pour tous ses membres jusqu'à la rotation, avec une alerte aux gestionnaires. Un coffre sans aucun gestionnaire actif reste en alerte jusqu'à ce qu'un admin membre du coffre le reprenne.
4. **Le compte géré du parti** : il n'est pas tourné (personne d'autre n'en a les clés, sauf récupération). Ses appareils, dès qu'ils lisent la liste signée qui les retire, passent dans l'état `Quarantined` de [ROT] 8.4 adapté : verrou, enrôlement biométrique supprimé, cache hors ligne de `k_srv` effacé, puis effacement des données de l'organisation **au prochain lancement** (pas de délai de 7 jours ici : la signature vient d'un rôle de l'organisation sur un compte qu'elle gère ; ruling E12). Un client modifié n'efface rien : B4 ne compte pas sur l'effacement, seulement sur la rotation.
5. **Suspension** (`Suspended`) : comme 1 et 2, sans rotation ni effacement ; réactivable.

Le parti garde ce qu'il a déjà vu, et ce que ses appareils peuvent encore ouvrir dans leur cache local tant qu'ils ne sont pas effacés (avec un client modifié, pour toujours). C'est la limite de toute solution ; la rotation garantit que rien de nouveau ne s'ouvre.

### 9.5 SCIM falsifié

- Un serveur hostile qui invente un `DELETE` : l'agent l'applique (il fait confiance à ce que dit l'annuaire du serveur). Effet : déni de service ciblé, visible dans l'audit et dans la console de l'IdP (qui n'a rien envoyé). Défense optionnelle : l'agent vérifie l'état du membre directement auprès de l'IdP (API Graph, Okta API) avant de signer un retrait, si un jeton de lecture d'annuaire lui est donné (question 6).
- Un serveur hostile qui invente un `POST` : au pire une invitation signée par l'agent pour un inconnu, qui ne peut devenir `Active` que par un `UserManager` ou par l'auto-activation liée à l'IdP ; et même actif, il n'est dans aucun coffre sans la signature d'un gestionnaire. Politique `auto_activate_scim_members` désactivée par défaut.

## 10. Journaux d'audit infalsifiables

### 10.1 Approches

**L1. Journal côté serveur seulement.** Facile, mais le serveur le réécrit à volonté et ne voit pas ce qui se passe hors ligne (copie d'un mot de passe, autofill). Rejeté comme source principale, gardé en complément (10.6).
**L2. Chaînes par appareil, signées par la clé d'appareil, chiffrées pour la clé d'audit, avec reçus de témoin (recommandée).** Généralise le journal de `onepass-guard` (chaîne SHA-256, tête signée, `docs/security/README.md` 11.1) à tous les événements et à plusieurs appareils.
**L3. Journal de transparence public (Merkle, comme Certificate Transparency) avec cosignature de témoins externes.** Plus fort contre un serveur qui montre deux versions à deux auditeurs, mais lourd. Gardé pour plus tard : les points de contrôle de L2 sont déjà au bon format pour être publiés.

Ruling E13 : L2.

### 10.2 Construction

Chaque appareil d'un compte géré tient sa propre chaîne :

```
AuditEntry  { seq: u64, prev: [u8; 32], at: i64, kind: AuditKind, subject: Subject,
              detail: Sealed }                  // detail scellé pour la clé d'audit
AuditSegment { org_id, account_id, device_id, from_seq, to_seq,
               entries: Vec<AuditEntryWire>, head: [u8; 32], sig: HybridSignature }
```

- `prev` = `SHA-256("onepass/audit-entry/v1" || postcard(entrée précédente))`, `seq` croît de 1, la première entrée suit la genèse de l'appareil dans l'organisation.
- L'entrée en clair pour le serveur ne porte que `seq`, `prev`, `at` arrondi à la minute, `kind` (code numérique) et des identifiants opaques ; tout le reste (nom de coffre, titre d'item, champ, IP vue par l'appareil, nom de client MCP) est dans `detail`, scellé pour la clé KEM d'audit de l'organisation avec `wrap_key_labeled` (label `onepass/audit-detail/v1`, contexte `(org_id, device_id, seq)`).
- Un segment (au plus 256 entrées ou 5 minutes) est signé par la clé d'appareil (domaine `onepass/audit-segment/v1`) et envoyé au serveur. L'appareil garde les entrées non confirmées dans sa base locale ; il ne les efface qu'après le reçu (10.5).
- Écriture fermée pour les secrets, comme `AuditSink::ready` : un appareil qui ne peut plus prolonger sa chaîne locale refuse les actions qui révèlent un secret (copie, révélation, export, MCP secret), selon la politique `audit_fail_closed` (défaut activé).

### 10.3 Événements

| Catégorie | Événements | Détail scellé |
| --- | --- | --- |
| Compte et appareil | déverrouillage (SSO, 2SKD, biométrie), échec, verrouillage, appareil ajouté, retiré, quarantaine | méthode, nom d'appareil |
| Coffres | ouverture d'un coffre d'organisation, membre ajouté ou retiré, rôle changé, rotation | nom du coffre, membres |
| Items (coffres d'organisation) | création, modification, suppression, restauration, déplacement, partage | titre, champ touché (jamais la valeur) |
| Usage de secret | révélation, copie, autofill, TOTP, export, impression, `run_with_secrets`, signature SSH | domaine du site, client MCP, processus |
| Organisation | liste signée, politique publiée, rôles, propriétaires, clé d'audit | différence |
| Récupération | demande, approbation, opposition, exécution | demandeur, officiers |
| Intégrité | échec de vérification (manifeste, liste, politique), chaîne d'un autre appareil incohérente | code d'erreur |

### 10.4 Vie privée

- **Coffre privé du membre dans un compte géré** : seuls les événements de compte et d'appareil sont journalisés, jamais les événements d'item (ruling E14). La politique peut l'étendre (`audit_private_vault_items`), et le membre le voit à l'adhésion et dans Réglages.
- **Compte personnel lié** : jamais journalisé pour l'organisation.
- Le détail est lisible seulement par les détenteurs de la clé d'audit (rôle `Auditor`, dont la clé privée d'audit est enveloppée pour leurs comptes, comme `OrgKeyset`). Le serveur ne lit que le squelette.
- Conservation réglable (défaut 1 an), purge par segments entiers avec un point de contrôle signé qui garde la tête (la chaîne reste vérifiable après purge).
- Le membre peut lire sa propre chaîne en clair sur ses appareils ("Ce que voit ton organisation").

### 10.5 Témoin et détection

- **Reçu du serveur** : à chaque segment, le serveur rend `WitnessReceipt { device_id, to_seq, head, received_at, server_sig }`. L'appareil garde le dernier reçu. Si le serveur supprime ou réécrit un segment, l'appareil (ou l'auditeur) a une preuve signée de ce qu'il a reçu.
- **Témoin croisé** : chaque appareil inclut dans ses propres segments, en entrée `Checkpoint`, les têtes des autres appareils du même compte et de l'organisation qu'il a vues (au plus 64, par tirage). Un serveur qui montre une version tronquée de la chaîne de l'appareil X à l'auditeur est contredit par un `Checkpoint` signé par Y.
- **Vérification par l'auditeur** : la console native vérifie chaque chaîne (signature des segments par la clé d'appareil épinglée dans la liste d'organisation, continuité de `seq` et `prev`, cohérence avec les reçus et les points de contrôle croisés) et affiche les trous. Un trou n'est pas forcément une attaque (appareil hors ligne, perdu) : il est daté et attribué.
- **Export** : vers un SIEM (JSON, syslog, Splunk HEC) depuis la console native, ou par un **exporteur** auto-hébergé qui détient la clé d'audit (rôle `Auditor`, appareil sans coffre), à recommander avec un stockage WORM (S3 Object Lock) chez le client.

### 10.6 Journal d'accès du serveur

Le serveur journalise ce qu'il voit (connexions, IdP, SCIM, accès aux enregistrements par appareil) dans sa propre chaîne signée par sa clé. Il ne prouve rien contre un serveur hostile, mais il complète L2 contre un **client** modifié qui ne journalise pas : un appareil qui télécharge un coffre sans jamais envoyer de segment est visible. La console rapproche les deux et signale "accès sans journal d'appareil".

### 10.7 Limites

Un client modifié n'écrit rien de ce qu'il fait hors ligne ; un appareil détruit emporte ses entrées non envoyées ; un serveur qui montre deux versions cohérentes à deux auditeurs qui ne se parlent pas n'est détecté que par les points de contrôle croisés (L3 le fermerait). Le livre blanc le dit.

## 11. Politiques

### 11.1 Approches

**P1. Côté serveur seulement.** Le serveur refuse ce qui viole la politique. Ne couvre ni le hors ligne ni ce qui se passe sur l'appareil (biométrie, verrou, export), et un serveur hostile l'assouplit.
**P2. Enregistrements de politique signés, appliqués par le client, doublés côté serveur quand c'est possible (recommandée).**
**P3. P2 plus attestation d'app (App Attest, Play Integrity, TPM)** pour refuser les clients modifiés. Gardé comme option `require_attested_client` plus tard (question 7) : utile, mais contraire à l'esprit open source (un build reproductible du client n'est pas attestable) et sans effet sur la crypto.

Ruling E15 : P2.

### 11.2 Enregistrement

```
PolicyBody { format: 1, org_id, seq, prev_hash, roster_head: [u8; 32],
             issued_at, valid_until, scope: Org | Group(group_id) | Member(account_id),
             rules: Rules }
SignedPolicy { body, signer: device_id, sig }   // domaine onepass/org-policy/v1
```

- Signée par un appareil de `Owner`, `Admin` ou `PolicyManager` de la liste d'organisation. Chaînée, monotone en `seq` : un ancien `seq` est refusé (`PolicyRollback`).
- `valid_until` (défaut 30 jours, republication automatique par la console native quand un admin l'ouvre, ou par l'agent si on lui donne le rôle `PolicyManager` restreint à la republication à l'identique) : un client qui n'a pas reçu de politique valide garde la dernière, **ne l'assouplit jamais**, et après `valid_until` + 7 jours passe en mode restreint (politique la plus stricte entre la dernière et le plancher intégré : verrou 5 min, biométrie requise, pas d'export) avec un bandeau "Ta politique d'organisation n'a pas pu être mise à jour". Ruling E16.
- Résolution : `Member` puis `Group` puis `Org`, et pour chaque règle la valeur la plus stricte gagne quand plusieurs s'appliquent.

### 11.3 Règles et où elles sont appliquées

| Règle | Valeurs | Client | Serveur | Cryptographique ? |
| --- | --- | --- | --- | --- |
| `unlock_methods` | SSO, 2SKD, les deux | oui | oui (refuse `k_srv` si SSO interdit) | en partie (choix des paramètres du compte) |
| `password_rules` (2SKD) | longueur min, zxcvbn min, interdiction des fuites HIBP | oui, au choix et au changement | non | non |
| `require_biometrics` | oui, non | oui (contrôle d'accès de `k_loc`, 6.4) | non | oui pour le SSO (clé SE `.biometryCurrentSet`) |
| `require_hardware_key` | oui, non | oui | non | oui (PRF dans `K_dev`) |
| `auto_lock_minutes`, `sso_reauth_hours`, `offline_unlock_hours` | nombres | oui | `sso_reauth` et `offline` oui | `offline` oui (cache borné) |
| `max_devices` | 1 à 20 | oui, par l'approbateur | oui, au dépôt de `k_srv` | non |
| `device_kinds` | personnel, partagé, public autorisés | oui | oui (sessions publiques refusées) | non |
| `travel_mode` | interdit, autorisé, imposé pendant des dates ou par pays | oui | non | non |
| `travel_safe_vaults` | liste fixée par l'admin | oui | non | non |
| `export` | interdit, archive chiffrée seulement, autorisé | oui | non | non |
| `share_outside_org` | interdit, autorisé | oui | oui (refuse un membre externe dans un coffre d'organisation) | non |
| `mcp`, `ssh_agent`, `cli` | interdit, métadonnées, autorisé | oui | non | non |
| `clipboard_seconds` | 10 à 300 | oui | non | non |
| `require_pinned_org` | oui, non | oui | non | oui (épinglage 5.3) |
| `audit_fail_closed`, `audit_private_vault_items` | oui, non | oui | non | non |
| `rotation_deadline_hours` | nombre | oui (lecture seule après délai) | oui | non |
| `allowed_networks` | plages IP | non | oui | non |
| `recovery` | désactivée, activée avec seuil et délai | oui | oui | oui (section 12) |

La console affiche cette colonne "Cryptographique ?" telle quelle. Toute règle marquée "non" ne lie qu'un client honnête (T-CLI l'ignore) ; la doc le dit sans détour (ruling E17).

### 11.4 Mode voyage imposé

`travel_mode: Enforced { from, to }` : à l'entrée dans la fenêtre, chaque appareil honnête applique le Travel Mode existant (`repo/travel.rs`) aux coffres hors `travel_safe_vaults`, sans que le membre puisse le couper avant `to`. Un administrateur peut le lever plus tôt en publiant une politique. Rotation de compte refusée pendant le voyage (K8 de [ROT] gardé).

### 11.5 Politique retenue par le serveur

Le serveur peut ne pas servir une nouvelle politique (plus stricte). Détection : la console native montre, pour chaque appareil, le `seq` de politique qu'il applique (champ dans ses segments d'audit et dans l'accusé de [ROT] 6.8 étendu) ; un appareil en retard est "en attente". La politique plus stricte ne peut pas être forcée par un serveur hostile, mais le retard est visible.

## 12. Récupération du compte d'un membre par l'organisation

### 12.1 Approches

**K1. Aucune récupération.** Pur zéro connaissance : un membre en SSO qui perd tous ses appareils perd son compte (et les coffres d'organisation restent lisibles par les autres membres). Simple et sûr, mais beaucoup d'organisations ne l'accepteront pas.
**K2. Groupe de récupération à la 1Password** : les officiers reçoivent les clés de tous les coffres. Rejeté : un officier lit tout, en permanence, sans trace avant usage.
**K3. Clé de récupération à seuil, avec délai et prévenance (recommandée).** L'ARK (SSO) ou un équivalent (2SKD, voir 12.3) de chaque membre est enveloppée pour une clé KEM de récupération de l'organisation, dont la clé privée est partagée entre `n` officiers par un partage à seuil `k`-sur-`n`. Une récupération demande `k` approbations signées, un délai, et prévient le membre.

Ruling E18 : K3, désactivée par défaut, `k` au moins 2 (défaut 2 sur 3), délai par défaut 48 h.

### 12.2 Construction

- **Clé de récupération** : paire KEM hybride ML-KEM-1024 + X25519 créée par l'appareil d'un propriétaire lors de `RecoveryConfigured` (lignée d'organisation, quorum de propriétaires). Sa graine de 32 octets est partagée par Shamir sur GF(2^8) en `n` parts (`k` au moins 2, `n` au plus 9) ; chaque part est scellée pour la clé KEM du compte d'un officier, avec `wrap_key_labeled` (label `onepass/recovery-share/v1`, contexte `(org_id, recovery_gen, officer_account_id)`). La graine entière est effacée de l'appareil créateur.
- **Enveloppe de récupération du membre** : à l'adhésion (et à chaque rotation de son compte), l'appareil du membre écrit `RecoveryEnvelope = wrap_key_labeled(recovery_kem_pub, "onepass/recovery-ark/v1", (org_id, account_id, lineage_head), ARK)`, signée par la clé d'appareil. Le membre voit avant d'adhérer : "Ton organisation peut récupérer ton compte si tu perds tous tes appareils : il faut 2 administrateurs sur 3 et tu es prévenu 48 h avant."
- **Demande** : un `RecoveryRequest { org_id, account_id, new_device: DevicePublic, reason, requested_at }` signé par un officier ou un `UserManager`. Le nouvel appareil du membre (qui a la clé d'appareil `new_device`, créée après une connexion IdP) est le seul destinataire possible.
- **Prévenance** : tout appareil du membre encore en ligne affiche "Une récupération de ton compte a été demandée par Paul Martin le 30 oct. à 9:12. Elle aura lieu le 1 nov. à 9:12. Ce n'est pas toi ? Oppose-toi." Opposition = enregistrement signé par une clé d'appareil du membre, qui annule la demande (le membre a donc encore un appareil, la récupération n'a pas lieu d'être). Email aussi, via le serveur.
- **Approbation** : après le délai, chaque officier approuvant ouvre sa part dans l'app native (présence), la rescelle pour la clé KEM de `new_device` avec le contexte de la demande, et signe. Le nouvel appareil recombine les `k` parts, ouvre l'enveloppe, obtient l'ARK, efface la graine de récupération. **Aucun officier ne voit jamais la graine entière ni l'ARK** : la recombinaison se fait sur l'appareil du membre.
- **Après** : le nouvel appareil fait immédiatement une rotation de compte [ROT] 7.1 (`reason = Revoke` pour les appareils que le membre déclare perdus, sinon `Rotate`), avec nouvelle ARK et nouvelle enveloppe de récupération : la récupération ne laisse pas une ARK connue de personne d'autre en service. Ligne d'audit signée par chaque officier et par le nouvel appareil.

### 12.3 Membres en 2SKD

Pour un membre qui se déverrouille par mot de passe et Secret Key, l'enveloppe de récupération porte la Secret Key et un **keyset de secours** scellé sous une clé aléatoire que l'enveloppe porte aussi (sinon il faudrait le mot de passe). Récupérer redonne l'accès et force un nouveau mot de passe, puis une rotation. Les propriétaires ne sont jamais couverts (ruling E7) : ils gardent leur Emergency Kit.

### 12.4 Risques, dits tels quels

- `k` officiers qui s'entendent peuvent, après le délai et si le membre ne s'oppose pas (parce qu'il dort, est en vacances, ou n'a plus d'appareil), prendre le compte, y compris le coffre privé du compte géré. C'est le pouvoir donné ; le délai, la prévenance, la rotation immédiate et la trace d'audit le rendent visible, pas impossible.
- Un serveur hostile peut retenir la prévenance vers les appareils du membre (déni de service). Atténuation : l'email part aussi, et le membre voit après coup la rotation faite par un appareil qu'il ne connaît pas ([ROT] 9 : "Ce n'était pas moi").
- La compromission d'un officier ne suffit pas (seuil). Celle de `k` officiers sur `n`, si.
- Le partage de Shamir n'est pas vérifiable : un officier malveillant peut rendre une part fausse et faire échouer la recombinaison. Détection : le nouvel appareil vérifie la clé publique recalculée contre `recovery_kem_pub` de la lignée ; en cas d'échec, il essaie les combinaisons de parts reçues (au plus `C(n,k)`, petit) et nomme la part fautive. Un schéma vérifiable (Feldman ou Pedersen) est noté pour plus tard.
- Le coffre privé d'un compte géré n'est donc pas privé vis-à-vis de l'organisation si la récupération est activée. L'app le dit dans l'en-tête du coffre ("Récupérable par ton organisation").

## 13. Paliers de fonctions (neutres sur le prix)

Principe (ruling E19) : **aucune protection cryptographique et aucun correctif de sécurité ne dépend d'un palier**. Le code est le même (AGPL) ; les paliers ne règlent que ce que l'instance hébergée active et ce que nous supportons.

| Fonction | Communauté (auto-hébergé, sans support) | Équipe | Business | Entreprise |
| --- | --- | --- | --- | --- |
| Coffres partagés, liste signée, rotation au départ | oui | oui | oui | oui |
| Console native, rôles, liste d'organisation | oui | oui | oui | oui |
| Politiques de base (verrou, biométrie, appareils, export) | oui | oui | oui | oui |
| Journal d'audit signé, consultation dans l'app | oui | oui (90 jours hébergés) | oui (1 an) | oui (réglable) |
| SSO OIDC | oui | non | oui | oui |
| SSO SAML | oui | non | oui | oui |
| SCIM et agent de provisionnement | oui | non | oui | oui |
| Politiques avancées (voyage imposé, réseaux, MCP, groupes) | oui | non | oui | oui |
| Export SIEM, exporteur WORM | oui | non | oui | oui |
| Récupération à seuil | oui | oui | oui | oui |
| Plusieurs IdP, administration déléguée par groupe | oui | non | non | oui |
| Option séquestre (6.10) | si gardée | non | non | oui |
| Identité d'organisation dans un HSM, journal de transparence (L3) | oui | non | non | oui |
| Support, SLA, hébergement dédié | non | standard | prioritaire | dédié |

La colonne Communauté est "oui" partout parce que le code est public ; le fondateur peut vouloir réserver certaines fonctions du serveur sous une autre licence (question 8).

## 14. Modèle de menace détaillé : attaques et réponses

| # | Attaque | Réponse | Reste |
| --- | --- | --- | --- |
| A1 | Serveur hostile rend `k_srv` à un voleur d'appareil | Il faut encore `k_loc` (SE, présence) | Code de l'appareil seul (6.9) ; `require_hardware_key` |
| A2 | IdP compromis ouvre une session pour un membre | Pas de `k_loc` : rien ne se déchiffre ; un appareil ne s'ajoute que par SAS ou récupération | Hameçonnage du SAS (A3) |
| A3 | Hameçonnage : l'attaquant envoie un QR d'appairage au membre | Scanner interne seulement, code SAS, proximité Bluetooth, avertissement (spec d'architecture 4.9) | Membre qui ignore tout |
| A4 | Serveur ajoute un faux membre ou un faux appareil à la liste | Liste signée par un rôle épinglé, chaînée | Aucun |
| A5 | Serveur rejoue une ancienne politique plus souple | `seq` monotone, `PolicyRollback` | Retard d'une politique plus stricte (11.5) |
| A6 | Serveur substitue l'identité d'organisation à l'adhésion | MDM, DNS, ou TOFU signalé et vérifiable | TOFU non vérifié |
| A7 | Admin malveillant s'ajoute à tous les coffres | Ajout = signature d'un gestionnaire du coffre, ligne d'audit visible des gestionnaires | Admin qui est déjà gestionnaire |
| A8 | Admin malveillant lance une récupération | Seuil `k`, délai, prévenance, opposition, rotation, audit | `k` officiers complices (12.4) |
| A9 | Membre parti garde ses appareils | Rotation des coffres, coupure serveur, effacement par client honnête | Ce qu'il a déjà vu ; client modifié garde son cache |
| A10 | Membre parti + serveur hostile | Rotation signée par un gestionnaire : rien d'écrit après ne s'ouvre (B4) | Anciennes données |
| A11 | Agent de provisionnement compromis | Peut retirer ou inviter, ni lire ni ajouter à un coffre | Déni de service ciblé |
| A12 | Serveur supprime des segments d'audit | Reçus signés, points de contrôle croisés, trous datés | Appareil détruit avant envoi |
| A13 | Client modifié n'écrit pas d'audit | Journal d'accès du serveur, rapprochement (10.6) | Actions hors ligne |
| A14 | Console web piégée par le serveur | Aucune action signée ou déchiffrante dans le web (8.2) | Mensonge sur l'état SCIM ou SSO affiché |
| A15 | Serveur redirige l'OIDC vers un faux IdP | Émetteur épinglé dans la politique signée, vérifié par l'app | SAML (6.8) |
| A16 | Rotation de compte forgée par un appareil retiré du membre | [ROT] inchangé (clés d'appareil, confirmation) | Voir [ROT] 11 |
| A17 | Officier rend une part fausse | Vérification contre `recovery_kem_pub`, recherche de la part fautive | Déni de service de la récupération |
| A18 | Serveur forge un `DELETE` SCIM | L'agent l'applique (déni de service), vérification IdP directe en option | Voir 9.5 |
| A19 | Un propriétaire seul change les propriétaires | Quorum `ceil(n/2)` + identité (5.4) | Organisation à un seul propriétaire |
| A20 | Rejeu d'un `UnlockRequest` | `nonce_srv` à usage unique, `oidc_session_hash` | Aucun |

## 15. Modèle formel : ajouts

Mêmes outils et même lancement (`make formal`, `formal/run.sh`, résultats dans `docs/security/formal/results.md`) que les modèles existants et que `rotation*.pv` de [ROT].

| Fichier | Modélise | Requêtes attendues |
| --- | --- | --- |
| `sso_unlock.pv` (+ `sso_core.pvl`) | ARK, `k_loc` privé à l'appareil, `k_srv` connu du serveur (attaquant), IdP compromis (canal public), enveloppe, keyset | secret de l'ARK et d'un item contre serveur + IdP : vrai ; `Unlocked(dev) ==> DeviceEnrolled(dev)` : vrai ; atteignabilité du déverrouillage honnête |
| `sso_escrow.pv` (contrôle négatif) | même chose avec `k_loc` remplacé par une clé du serveur de clés | secret de l'ARK : faux, par construction (montre que A casse B1) |
| `sso_enroll.pv` | appairage SAS de [ROT] portant l'ARK, IdP compromis | un appareil de l'attaquant n'obtient l'ARK que si l'utilisateur confirme un SAS qu'il n'a pas vu : `AttackerDeviceGetsArk ==> UserConfirmed` |
| `org_roster.pv` | liste signée, rôles, serveur hostile | `MemberAccepted(m) ==> SignedBy(role_holder)` ; un `Provisioner` ne fait accepter aucun ajout à un coffre |
| `org_vault_removal.pv` | coffre partagé de [PART], retrait et rotation, membre parti = attaquant | item écrit après rotation secret pour le parti : vrai ; contrôle négatif sans rotation : faux |
| `recovery.pv` | Shamir modélisé comme `k` parts, délai et opposition comme événements | avec `k-1` parts, ARK secrète : vrai ; `Recovered ==> k Approved && not Opposed` ; contrôle négatif `k = 1` : vrai seulement avec un officier |
| `policy.pv` | politique signée et chaînée | `PolicyApplied(p) ==> PolicySigned(p)` ; pas d'application d'un `seq` inférieur |

Hors ProVerif, en tests de propriétés : chaînes d'audit (troncature, insertion, réordonnancement, trous, points de contrôle croisés), résolution des politiques (la plus stricte gagne, jamais d'assouplissement sans signature), convergence des listes d'organisation (union monotone comme 2b), machine d'état SCIM.

## 16. Jalons

Chaque jalon a son plan ; les tests listés sont les critères d'acceptation.

| Jalon | Contenu | Dépend de | Tests clés |
| --- | --- | --- | --- |
| **E0** Serveur socle | `onepass-server` : axum, Postgres, S3, image Docker, clé du serveur, relais de [RELAIS] hébergé, boîte aux lettres de [ROT] | [RELAIS], [ROT] | suite "stockage malveillant" rejouée contre le serveur (ETH 2026), fuzzing des entrées, déploiement auto-hébergé de bout en bout en CI (docker compose) |
| **E1** Organisation | identité, lignée, liste signée, rôles, comptes gérés, épinglage (MDM, DNS, TOFU), console native v0 (membres, rôles) | [PART], E0 | rejeu et bifurcation de liste refusés, rôle usurpé refusé, quorum des propriétaires, `org_roster.pv` |
| **E2** Coffres d'organisation et départ | coffres d'organisation sur [PART], retrait, rotation suivie, délai et lecture seule, effacement du parti | [PART], E1 | `org_vault_removal.pv`, parti + serveur hostile n'ouvre rien d'écrit après, coffre sans gestionnaire |
| **E3** Politiques | enregistrement signé, résolution, application client et serveur, mode restreint, voyage imposé | E1 | `policy.pv`, propriété "jamais d'assouplissement", politique expirée, `max_devices` contourné par le serveur |
| **E4** Audit | chaînes par appareil, segments scellés, reçus, points de contrôle, console de vérification, export SIEM, journal serveur | E1 | troncature, insertion, rejeu, trous détectés ; écriture fermée pour les secrets ; vie privée du coffre privé |
| **E5** SSO OIDC | ARK, `k_loc`, `k_srv`, enveloppes, déverrouillage, enrôlement par SAS, hors ligne, `require_hardware_key` | E1, [ROT] | `sso_unlock.pv`, `sso_escrow.pv`, `sso_enroll.pv` ; tests d'IdP (Okta, Entra ID, Google, Keycloak en CI) ; `UnlockRequest` rejoué ; émetteur non épinglé refusé |
| **E6** SAML et SCIM | ACS SAML, SCIM 2.0, agent de provisionnement, file manuelle | E5, E2 | validateurs SCIM d'Okta et Entra ID ; `DELETE` forgé ; agent compromis ne lit rien ; XML piégé (XXE, signature enveloppée détournée) |
| **E7** Récupération | clé à seuil, enveloppes, demande, délai, opposition, recombinaison sur l'appareil, rotation | E5, [ROT] | `recovery.pv` ; part fausse détectée ; opposition annule ; rotation après récupération |
| **E8** Console web et paliers | console web (SSO, SCIM, facturation, état), champ `plan`, activation par palier sur l'instance hébergée | E6 | aucune route web ne signe ni ne déchiffre (test d'architecture) ; une instance auto-hébergée sans clé de licence a tout |
| **E9** Audit externe | audit tiers du serveur, du SSO et de la récupération, avant toute vente | tout | rapport publié |

Ordre recommandé : E0, E1, E2, E3, E4, E5, E6, E7, E8, E9. E3 et E4 peuvent avancer en parallèle de E2.

## 17. Points de contact avec les autres specs

- [ROT] : `GenesisBody.org` (format 2) ; `Grant::SsoV1` (ARK au lieu de la Secret Key) ; quarantaine sans délai quand la liste d'organisation retire le membre (E12) ; accusé de tête étendu au `seq` de politique (11.5) ; enveloppe de récupération réécrite à chaque rotation (12.2) ; paramètres `OPP3` avec `unlock: Sso`.
- [PART] : liste de membres de coffre avec `org_id` ; règle "seuls les membres `Active`" ; droit de retrait d'un `Admin` sans clé ; proposition d'ajout depuis un groupe SCIM ; rotation suivie par la console ; `rotation_deadline_hours` et lecture seule.
- [RELAIS] : le serveur héberge le relais ; stockage de `k_loc` hors Apple ; mode navigateur sans cache hors ligne ; console native Windows et Linux.
- Codes de `RecordKind` : [ROT] prend 10 à 13 ; [PART] et [RELAIS] en prendront ; cette spec propose 20 à 29 (`OrgLineage`, `OrgRoster`, `OrgPolicy`, `AuditSegment`, `RecoveryEnvelope`, `RecoveryRequest`, `RecoveryApproval`, `RecoveryOpposition`, `ArkEnvelope`, `JoinRequest`) à confirmer quand les trois specs seront fusionnées.

## 18. Labels nouveaux

| Label | Sorte | Clé | Sur |
| --- | --- | --- | --- |
| `onepass/org-fpr/v1` | préfixe de hash | | empreinte d'organisation |
| `onepass/org-genesis/v1`, `onepass/org-change/v1` | domaine de signature | identité d'organisation et appareils des propriétaires | corps de lignée |
| `onepass/org-roster/v1` | domaine de signature | appareil d'un rôle | `RosterBody` |
| `onepass/org-policy/v1` | domaine de signature | appareil d'un rôle | `PolicyBody` |
| `onepass/scim-id/v1` | préfixe de hash | | `scim_id_hash` |
| `onepass/ark-auk/v1` | info HKDF | | clé du keyset depuis l'ARK |
| `onepass/sso-unlock/v1` | info HKDF | | `K_dev` |
| `onepass/sso-unlock-req/v1` | domaine de signature | appareil | `UnlockRequest` |
| `onepass/audit-entry/v1` | préfixe de hash | | chaîne d'audit |
| `onepass/audit-segment/v1` | domaine de signature | appareil | `AuditSegment` |
| `onepass/audit-detail/v1` | label `wrap_key_labeled` | KEM d'audit | détail scellé |
| `onepass/recovery-share/v1` | label `wrap_key_labeled` | KEM de compte d'un officier | part de Shamir |
| `onepass/recovery-ark/v1` | label `wrap_key_labeled` | KEM de récupération | ARK du membre |
| `onepass/recovery-req/v1`, `onepass/recovery-approve/v1`, `onepass/recovery-oppose/v1` | domaines de signature | appareils | demande, approbation, opposition |

## 19. Rulings

Format : décision, raison, coût si c'est faux.

- **E1** Compte géré distinct du compte personnel, jamais mélangés : l'organisation ne doit rien voir ni récupérer du personnel. Coût : deux comptes dans l'app.
- **E2** Identité d'organisation épinglée par MDM, DNS, ou TOFU signalé ; jamais suivie si le serveur la change : le serveur ne doit pas pouvoir substituer l'organisation. Coût : friction d'adhésion sans MDM.
- **E3** Un administrateur n'est pas membre de tous les coffres : séparer administrer et lire. Coût : surprise pour qui vient d'un autre produit.
- **E4** SSO par appareils de confiance et part serveur liée à l'IdP (B) : seule approche où ni l'IdP ni le serveur ne déchiffrent. Coût : compte perdu sans appareil ni récupération.
- **E5** Pas d'"approbation administrateur" légère : c'est une récupération, traitée comme telle. Coût : un membre sans appareil attend le délai.
- **E6** L'app vérifie aussi l'émetteur OIDC épinglé : le serveur ne choisit pas l'IdP. Coût : un réglage de plus dans la politique.
- **E7** Propriétaires en 2SKD obligatoire, jamais couverts par la récupération : la racine de l'organisation ne dépend ni de l'IdP ni d'autres admins. Coût : deux méthodes de déverrouillage à supporter.
- **E8** Séquestre jamais hébergé par nous : nous ne voulons pas pouvoir tout ouvrir. Coût : option réservée aux clients qui l'opèrent.
- **E9** Serveur minimal (S1), comptes personnels sur CloudKit, comptes gérés sur le serveur. Coût : deux stockages à maintenir.
- **E10** Console hybride, crypto seulement en natif : une page servie par le serveur ne doit jamais tenir une clé. Coût : admins Windows et Linux attendent [RELAIS].
- **E11** SCIM par agent de provisionnement au rôle restreint, repli manuel. Coût : un composant de plus à déployer.
- **E12** Effacement du parti au prochain lancement, sans le délai de 7 jours de [ROT] : la décision vient d'un rôle de l'organisation sur un compte géré. Coût : un admin malveillant efface les données d'organisation d'un membre (elles restent sur le serveur et chez les autres membres).
- **E13** Audit par chaînes d'appareil signées et scellées, reçus et témoins croisés (L2). Coût : stockage et vérification côté console.
- **E14** Pas d'événements d'item dans le coffre privé d'un compte géré par défaut. Coût : moins de visibilité pour la conformité.
- **E15** Politiques signées appliquées par le client, doublées par le serveur (P2). Coût : un client modifié les ignore.
- **E16** Politique expirée : jamais assouplie, mode restreint après 7 jours de grâce. Coût : gêne si le serveur tombe longtemps.
- **E17** Afficher ce qui est cryptographique et ce qui ne l'est pas. Coût : argument commercial moins flatteur.
- **E18** Récupération à seuil, désactivée par défaut, `k` au moins 2, délai 48 h. Coût : lenteur dans une vraie urgence.
- **E19** Aucune sécurité ne dépend du palier. Coût : moins de leviers de prix.
- **E20** Quorum de propriétaires `ceil(n/2)` en plus de l'identité pour la lignée d'organisation. Coût : une organisation à un seul propriétaire n'a pas cette protection.
- **E21** `k_srv` tiré par l'appareil, jamais par le serveur : le serveur ne peut pas choisir une part connue de l'IdP. Coût : aucun.
- **E22** Le serveur ne garde jamais de nom de coffre ou d'item en clair, même pour la console web. Coût : la console web n'affiche que des identifiants opaques et des emails.
- **E23** Shamir recombiné sur l'appareil du membre, jamais chez un officier. Coût : le nouvel appareil doit être en ligne pour recevoir les parts.
- **E24** Rotation de compte immédiate après toute récupération. Coût : un passage de [ROT] de plus.
- **E25** Lecture seule d'un coffre dont la rotation dépasse `rotation_deadline_hours`. Coût : blocage si aucun gestionnaire n'est disponible.
- **E26** Le journal d'accès du serveur complète l'audit, jamais ne le remplace. Coût : double source à rapprocher.
- **E27** Un seul IdP par organisation en v1. Coût : fusions et filiales attendent l'Entreprise.
- **E28** SAML jugé par le serveur seul, OIDC recommandé. Coût : moindre garantie avec SAML (A15).
- **E29** Attestation d'app non requise en v1. Coût : clients modifiés possibles.
- **E30** Rien de cette spec n'affaiblit un compte personnel : les comptes personnels ne voient aucun changement de format. Coût : aucun.

## 20. Sources

- [1P-SSO] 1Password Support, "About Unlock with SSO security" : https://support.1password.com/sso-security/
- [1P-OIDC] 1Password blog, "Unlock with SSO, OIDC" : https://1password.com/blog/unlock-with-sso-oidc
- [1P-WP] 1Password Security Design white paper (section Unlock with SSO, Recovery Group) : https://1passwordstatic.com/files/security/1password-white-paper.pdf
- [BW-TDE] Bitwarden Help, "About Trusted Devices" : https://bitwarden.com/help/about-trusted-devices/
- [BW-TDE2] Bitwarden Help, "Set up SSO with trusted devices" : https://bitwarden.com/help/setup-sso-with-trusted-devices/
- [BW-KC] Bitwarden Help, "About Key Connector" : https://bitwarden.com/help/about-key-connector/
- [KEEPER] Keeper SSO Connect Cloud, "Device Approvals" et "Security and User Flow" : https://docs.keeper.io/sso-connect-cloud/device-approvals , https://docs.keeper.io/sso-connect-cloud/security-and-user-flow
- [DASH] Dashlane, "Confidential SSO powered by AWS Nitro Enclaves" (Help Net Security, 2023-04-21) : https://www.helpnetsecurity.com/2023/04/21/dashlane-confidential-sso/ ; Dashlane blog : https://www.dashlane.com/blog/confidential-computing-zero-knowledge
- [SCIM] RFC 7643 (schéma) et RFC 7644 (protocole) : https://www.rfc-editor.org/rfc/rfc7643 , https://www.rfc-editor.org/rfc/rfc7644
- [OIDC] OpenID Connect Core 1.0, RFC 7636 (PKCE).
- [ETH] Étude ETH Zurich / USI 2026 sur les gestionnaires cloud face à un serveur malveillant, déjà référence du modèle de menace (`docs/security/README.md` 1).

Les affirmations sur les autres produits viennent de leur propre documentation, non vérifiées de façon indépendante.

## 21. Questions ouvertes pour le fondateur

1. **Approche SSO.** Appareils de confiance avec part serveur liée à l'IdP (B), serveur de clés (A), ou enclave (C) ? Mon choix : **B**, seule où ni l'IdP ni le serveur ne déchiffrent.
2. **Option séquestre (6.10).** La proposer en Entreprise, opérée par le client seulement, ou ne jamais la proposer ? Mon choix : **ne pas la proposer en v1**, la garder écrite pour un client qui l'exige par contrat.
3. **Récupération par l'organisation.** Aucune (K1), groupe à la 1Password (K2), ou clé à seuil avec délai (K3) ? Mon choix : **K3, désactivée par défaut, 2 sur 3, 48 h**.
4. **Coffre privé d'un compte géré.** Couvert par la récupération quand elle est active, ou exclu (le membre le perdrait avec ses appareils) ? Mon choix : **couvert, et l'app l'affiche en en-tête du coffre**.
5. **Administrateurs et contenu.** Un admin n'est membre d'aucun coffre par défaut (E3), ou membre de tous comme ailleurs ? Mon choix : **aucun par défaut**.
6. **Agent SCIM et vérification IdP directe.** L'agent vérifie-t-il un retrait auprès de l'API de l'IdP avant de signer (plus sûr, plus d'intégrations) ? Mon choix : **optionnel, activé quand un jeton de lecture est fourni, Okta et Entra ID d'abord**.
7. **Attestation d'app (P3).** L'exiger en option pour refuser les clients modifiés ? Mon choix : **pas en v1**, à revoir avec les premiers clients réglementés.
8. **Licence du serveur et paliers.** Tout en AGPL avec paliers seulement sur l'instance hébergée, ou fonctions Business (SSO, SCIM) sous licence commerciale séparée ? Mon choix : **tout en AGPL**, la valeur vendue est l'hébergement, le support et l'audit.
9. **Comptes de service pour la CI et les machines** (hors portée ici). Les mettre dans le jalon E5 ou dans une spec suivante ? Mon choix : **spec suivante**, après E5, sur le modèle de l'agent de provisionnement.
10. **Propriétaires en 2SKD obligatoire (E7).** Le garder, quitte à gêner une organisation 100 % SSO ? Mon choix : **le garder**.
11. **Effacement du membre parti (E12).** Immédiat au prochain lancement, ou délai de 7 jours comme [ROT] ? Mon choix : **immédiat**, les données restent sur le serveur et chez les autres membres.
12. **Hébergement.** Région de notre instance hébergée (UE, US, les deux) et ordre de lancement ? Mon choix : **UE et US dès E8**, données d'une organisation dans une seule région choisie à la création.
