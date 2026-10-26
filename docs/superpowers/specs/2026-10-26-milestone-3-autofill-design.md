# Jalon 3 : AutoFill système, passkeys et codes à usage unique

Statut : spec validée par la session elle-même (consigne du fondateur : aucune action de sa part, chaque décision tranchée et consignée en section 13). Périmètre : section 13, point 3 de la spec d'architecture (`2026-10-25-onepass-architecture-design.md`), sections 6.1 et 6.4 de cette même spec, points ouverts du jalon 2 (`2026-10-25-milestone-2-apps-design.md`, rulings R1 à R22 et E1 à E21, en particulier E20) et section 10 de `docs/security/README.md`.

## 1. Ce que l'utilisateur obtient

Sur iPhone et iPad (iOS et iPadOS 26.0 minimum, certaines fonctions en 26.2), et sur Mac (macOS 26.0) :

1. **OnePass fournisseur de remplissage automatique.** Une fois activé (Réglages de OnePass > Remplissage automatique > "Activer", qui ouvre la demande système), OnePass apparaît dans la barre QuickType au-dessus du clavier, dans Safari et dans les apps : identifiant suggéré pour le site, touche "Mots de passe" (icône clé) pour choisir un autre compte.
2. **Mots de passe.** Toucher une suggestion demande Face ID (ou le mot de passe maître), puis remplit identifiant et mot de passe. Le choix manuel ouvre la liste OnePass : comptes du site en tête, recherche dans tous les Logins.
3. **Codes à usage unique.** Sur un champ "code de vérification", OnePass propose le code TOTP du Login du site (iOS 18+ et macOS 15+, donc toujours vrai ici). OnePass peut aussi être choisi comme app de codes de vérification.
4. **Passkeys.** Un site ou une app qui crée une passkey propose "Enregistrer dans OnePass" ; la passkey est rangée dans un Login (existant ou nouveau), synchronisée comme tout item par le core et CloudKit. À la connexion, la feuille système propose la passkey OnePass ; Face ID suffit.
5. **Enregistrer un mot de passe tapé** (iOS et iPadOS 26.2+). Quand l'utilisateur tape un nouveau compte dans une app ou Safari, iOS demande à OnePass de l'enregistrer : feuille OnePass avec titre, vault, et "Mettre à jour" si le compte existe déjà avec un autre mot de passe.
6. **Mot de passe fort proposé** (iOS et iPadOS 26.2+) : dans un formulaire d'inscription, la suggestion de mot de passe vient du générateur de OnePass et respecte les règles du site.
7. **Insertion de texte** (iOS et iPadOS 18+ : menu "Remplissage automatique" du champ) : n'importe quel champ d'un item (numéro de carte, IBAN, adresse, numéro de membre) inséré dans n'importe quel champ.
8. **Fin de la feuille "Enregistrer le mot de passe ?"** après l'enregistrement d'un Login dans OnePass (limite E20 du jalon 2) : quand OnePass est le fournisseur, la demande d'enregistrement arrive à OnePass, qui reconnaît qu'elle vient de lui-même et la referme sans rien demander.

Ce que l'icône dans le champ devient (consigne "expérience icône dans le champ") : iOS et macOS ne laissent aucun fournisseur dessiner dans les champs des autres apps. L'expérience système est la barre QuickType (suggestion du compte avec le nom de OnePass), la touche clé et la feuille passkey. L'icône dans le champ des pages web arrive avec l'extension Safari du jalon 4 (ruling A12).

## 2. Vue d'ensemble

```
            ┌────────────────────────── App Group group.me.somalabs.onepass ──────────────────────────┐
            │  Library/Application Support/OnePass/vault.sqlite (SyncStore, blobs chiffrés)            │
            │  UserDefaults partagés (VaultSettings)                                                   │
            └───────────────▲───────────────────────────────────────────────▲──────────────────────────┘
                            │                                               │
  OnePass.app ──────────────┤                                               ├──────────── OnePassAutoFill.appex
  (VaultSession, sync,      │   Keychain groupe <préfixe>me.somalabs.onepass.shared    │  (ASCredentialProviderViewController,
   IdentityStoreSync)       │   Secret Key, AUK enveloppée par la Secure Enclave       │   session éphémère, déverrouillée
            │               └───────────────────────────────────────────────────────── │   par requête, verrouillée à la fin)
            │                                                                              │
            ├── ASCredentialIdentityStore (identifiants, domaines, ids de passkey ; aucun secret)
            └── notification Darwin me.somalabs.onepass.store-changed ◄──── écrit après chaque écriture de l'extension
```

- L'extension est un second processus avec sa propre session : elle ouvre la même base SQLite (le core ouvre une connexion WAL avec 5 s d'attente sur verrou), lit la Secret Key dans le Keychain partagé, déverrouille par Face ID (AUK) ou par le mot de passe maître, sert la requête, puis verrouille (drop du Repository : clés effacées).
- L'extension n'envoie jamais rien à CloudKit : elle écrit dans `pending` comme l'app. L'app pousse ces écritures au prochain tour de sync (réveil par la notification Darwin si elle tourne, sinon au lancement suivant).
- Seul le Rust manipule les clés (règle de frontière du jalon 2) : la clé privée d'une passkey est générée, stockée, et utilisée pour signer dans le Rust. Swift reçoit un `attestationObject`, des `authenticatorData` et une signature, jamais la clé.

## 3. Ajouts au core (additifs)

### 3.1 Module `webauthn` (onepass-core)

Nouveau fichier `core/onepass-core/src/webauthn.rs`, une ligne `pub mod webauthn;` dans `lib.rs`. Aucune nouvelle dépendance : ECDSA P-256 et SHA-256 par `aws-lc-rs`, CBOR écrit à la main (quelques structures fixes).

- `new_credential(rp_id, user_name, user_handle, now) -> Result<PasskeyCredential>` : paire ECDSA P-256 neuve (`EcdsaKeyPair::generate_pkcs8`, clé privée en PKCS#8 DER, le format qu'utilise déjà l'import CXF), identifiant de credential de 16 octets aléatoires. Refuse `rp_id` vide ou de plus de 253 octets, `user_handle` de plus de 64 octets (limite WebAuthn), `user_name` de plus de 1024 octets (`InvalidFormat`).
- `registration(cred, client_data_hash) -> Result<Registration>` : `authenticatorData` = SHA-256(rp_id) ‖ flags ‖ compteur ‖ données de credential attestées (AAGUID OnePass, longueur et identifiant du credential, clé publique COSE ES256 `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` en CBOR canonique) ; `attestationObject` = CBOR `{"fmt": "none", "attStmt": {}, "authData": …}` (clés dans l'ordre canonique CTAP2 : `fmt`, `attStmt`, `authData`).
- `assertion(cred, client_data_hash) -> Result<Assertion>` : `authenticatorData` = SHA-256(rp_id) ‖ flags ‖ compteur ; signature ECDSA P-256 SHA-256 en DER (`ECDSA_P256_SHA256_ASN1_SIGNING`) de `authenticatorData ‖ client_data_hash`.
- Flags : UP (présence), UV (vérification : toute requête passe par un déverrouillage frais, Face ID ou mot de passe), BE et BS (credential sauvegardé et synchronisé), AT pour l'enregistrement seulement. Compteur toujours 0 (ruling A6). `client_data_hash` doit faire 32 octets.
- AAGUID OnePass : constante de 16 octets tirée une fois (ruling A7).
- Une clé privée qui ne se relit pas en PKCS#8 P-256 donne `InvalidFormat("passkey key")` (passkey importée d'un autre algorithme).

### 3.2 État de l'appareil partagé entre deux processus

L'app et l'extension tiennent chacune un `Repository` avec son `DeviceState` en mémoire (épingle du compte, dernier manifeste vu par vault). Pour qu'un processus n'écrase pas le `last_seen` plus récent de l'autre, `Repository<SyncStore>::persist_device_state` fusionne avant d'écrire : il relit l'état stocké et garde, par vault, l'entrée de plus grand `seq` (égalité : celle de la mémoire), garde l'épingle de la mémoire (elle ne change jamais après la création), écrit le résultat dans la même transaction et l'adopte en mémoire. Changement de comportement interne, signature inchangée (ruling A4). Les écritures d'items sont déjà sûres entre processus : `commit_manifest` est conditionnel sur la version stockée (`Conflict`, retenté une fois par la session FFI) et SQLite sérialise les transactions.

### 3.3 FFI (onepass-ffi)

Ajouts seulement, nouveau fichier `core/onepass-ffi/src/autofill.rs` :

- `Session::autofill_identities() -> Vec<FfiAutofillIdentity>` : pour chaque Login vivant (ni corbeille, ni archive, ni `hide_from_autofill`) : une identité mot de passe par URL (hôte de l'URL, identifiant, id d'enregistrement `"<vault hex>:<item hex>"`, favori), une identité code à usage unique par URL si le champ `totp` est rempli, une identité passkey par passkey (`rp_id`, nom d'utilisateur, id du credential, user handle). Les vaults masqués sur l'appareil (mode partagé) sont exclus par Swift, qui passe la liste des vaults à exclure.
- `Session::autofill_candidates(service: String, include_all: bool) -> Vec<FfiAutofillCandidate>` : les Logins qui correspondent à un domaine ou une URL donnés par le système, classés (même hôte d'abord, puis même domaine enregistrable) selon la règle de correspondance de chaque URL (`MatchRule`), avec identifiant, présence d'un mot de passe, d'un TOTP, de passkeys ; `include_all` ajoute tous les autres Logins à la suite (choix manuel). Aucune valeur secrète.
- `Session::create_passkey(request: FfiPasskeyCreation) -> FfiPasskeyRegistration` : crée la passkey (3.1) et l'enregistre, soit dans le champ répétable `passkeys` d'un Login existant (avec `LoginMethod::Passkey` ajouté s'il manque), soit dans un nouveau Login (titre = `rp_id`, URL `https://<rp_id>`, identifiant = nom d'utilisateur, méthode passkey) du vault demandé. Rend `credential_id`, `attestation_object`, l'id de l'item. Refuse si une passkey de la liste `excluded_credential_ids` existe déjà pour ce `rp_id` (`OnePassError::PasskeyExcluded`, nouveau cas ajouté en fin d'enum).
- `Session::passkey_assertion(vault_id, item_id, credential_id, client_data_hash) -> FfiPasskeyAssertion` : relit l'item, trouve la passkey, signe (3.1) et rend `user_handle`, `authenticator_data`, `signature`, `credential_id`. La clé privée ne quitte pas le Rust.
- Fonction libre `password_from_rules(rules: Option<String>, fallback: FfiPasswordRecipe) -> Result<String>` : applique le langage `passwordrules` d'Apple (`minlength`, `maxlength`, `required`, `allowed`, `max-consecutive`, classes `lower`, `upper`, `digit`, `special`, `ascii-printable`, `unicode`, ensembles `[...]`) au générateur du core ; règles illisibles ou contradictoires : la recette de repli (aléatoire, 20 caractères) (ruling A10).
- La correspondance de domaines utilise la Public Suffix List par la crate `psl` 2 (la même que l'extension navigateur du jalon 4) et `url` 2, dépendances de `onepass-ffi` seulement. Hôtes comparés en ASCII minuscule (punycode) ; une adresse IP ne correspond qu'à elle-même ; `http` jamais proposé pour un domaine public (correspondance d'un site HTTPS seulement, sauf hôte local).

`FfiPasskey` reste sans user handle : la `user_handle` ne traverse que dans `FfiAutofillIdentity` et `FfiPasskeyAssertion`, là où l'API Apple l'exige (ruling A8).

## 4. VaultKit

Nouveau dossier `VaultKit/Sources/VaultKit/AutoFill/` :

- `SharedContainer` : URL du conteneur App Group (`group.me.somalabs.onepass` sur iOS, `<préfixe d'équipe>me.somalabs.onepass` sur macOS, lus dans la clé Info.plist `OnePassAppGroup`), chemin de la base (`Library/Application Support/OnePass/vault.sqlite`, dossier en `completeUntilFirstUserAuthentication` sur iOS), suite `UserDefaults` partagée. Sans conteneur (build Mac non signé), repli sur les emplacements du jalon 2 et `isShared == false`.
- `SharedContainerMigration` : au lancement de l'app, avant toute ouverture de la base, si la base partagée n'existe pas et que l'ancienne existe, déplace `vault.sqlite`, `-wal` et `-shm` (dans cet ordre inverse : `-shm`, `-wal`, puis la base, pour qu'un arrêt au milieu laisse l'ancienne base complète), puis copie une fois les clés `onepass.*` de `UserDefaults.standard` vers la suite partagée (ruling A3). Idempotent.
- `AutoFillIdentityBuilder` : transforme `FfiAutofillIdentity` en `ASPasswordCredentialIdentity`, `ASPasskeyCredentialIdentity`, `ASOneTimeCodeCredentialIdentity` (service de type domaine pour un hôte, rang 1 pour un favori).
- `IdentityStoreSync` (acteur) : `refresh(session)` remplace tout le contenu de `ASCredentialIdentityStore` (si le magasin est activé et le réglage "Suggestions" actif), anti-rebond 1 s ; `clear()` vide le magasin (réglage coupé, compte réinitialisé). Protocole `IdentityStoreClient` pour les tests (`InMemoryIdentityStore`).
- `StoreChangeNotifier` : poste et observe la notification Darwin `me.somalabs.onepass.store-changed` (aucune donnée transportée).
- `AutoFillUnlocker` : déverrouillage dans l'extension, mêmes règles que l'app (biométrie si enrôlée et autorisée par `BiometricPolicy`, sinon mot de passe maître, compteur d'échecs partagé), session rendue au plus pour la durée d'une requête.
- `AutoFillSettings` (dans `VaultSettings`) : `quickTypeSuggestions` (vrai par défaut), `autofillTipDismissed`.

`VaultEnvironment.live()` utilise `SharedContainer` (base, réglages) ; `VaultSession` appelle `IdentityStoreSync` après déverrouillage, après chaque écriture locale et après chaque changement distant appliqué, et observe `StoreChangeNotifier` pour recharger les résumés et signaler la sync.

## 5. Extension `OnePassAutoFill`

Cible `app-extension` iOS et macOS (point d'extension `com.apple.authentication-services-credential-provider-ui`), sources `apple/AutoFill/`, dépendances VaultKit et DesignKit, interface SwiftUI hébergée par `ASCredentialProviderViewController`. Capacités Info.plist : `ProvidesPasswords`, `ProvidesPasskeys`, `ProvidesOneTimeCodes`, `ProvidesTextToInsert` (iOS), `ShowsConfigurationUI`, `SupportsSavePasswordCredentials`, `SupportsGeneratePasswordCredentials` (iOS 26.2+, ignorées avant). Droits : App Group, groupe Keychain partagé, `com.apple.developer.authentication-services.autofill-credential-provider`.

Flux (le modèle `AutoFillModel` les porte, l'interface ne fait qu'afficher) :

| Point d'entrée système | Comportement |
| --- | --- |
| `prepareCredentialList(for:)` et variante passkey | écran de déverrouillage, puis liste : passkeys du `rp_id` si la requête en demande, comptes du site, recherche dans tous les Logins ; choix = remplissage |
| `provideCredentialWithoutUserInteraction(for:)` (mot de passe, passkey, code) | l'extension n'est jamais déverrouillée hors requête : annule avec `userInteractionRequired`, le système rappelle avec interface |
| `prepareInterfaceToProvideCredential(for:)` | déverrouillage (Face ID d'emblée si possible), puis remplit directement l'enregistrement demandé (`recordIdentifier`) ; enregistrement disparu : retour à la liste |
| `prepareOneTimeCodeCredentialList(for:)` | déverrouillage, Logins avec TOTP du site, code courant |
| `prepareInterfaceForPasskeyRegistration(_:)` | déverrouillage, feuille "Enregistrer une passkey pour <rp>" : "Ajouter à <Login>" (Logins du domaine dont l'identifiant est égal ou vide), sinon "Nouvel élément" dans le vault choisi ; ES256 absent des algorithmes acceptés : échec |
| `performPasskeyRegistrationWithoutUserInteractionIfPossible` | refusé (pas de création silencieuse, ruling A9) |
| `prepareInterfaceForSavePasswordRequest` (26.2+) | demande venant de OnePass lui-même (service de type app dont l'identifiant est celui de l'app, ou identique à un Login existant : même hôte, même identifiant, même mot de passe) : fin immédiate sans rien écrire ; sinon déverrouillage et feuille Enregistrer ou Mettre à jour |
| `performSavePasswordRequestWithoutUserInteractionIfPossible` (26.2+) | demande de OnePass lui-même : fin immédiate ; mot de passe généré rempli (`generatedPasswordFilled`) : fin sans écrire (l'événement suivant porte la même valeur) ; sinon `userInteractionRequired` |
| `performGeneratePasswordsRequestWithoutUserInteraction` (26.2+) | `password_from_rules` (règles du champ, du champ de confirmation, des correctifs du système), un seul mot de passe `strong` ; aucune donnée du coffre lue |
| `prepareInterfaceForUserChoosingTextToInsert` (iOS 18+) | déverrouillage, liste de tous les items (sauf Crypto Wallet), puis champs de l'item ; le champ choisi est inséré |
| `prepareInterfaceForExtensionConfiguration` | écran "OnePass est prêt" et rappel qu'il faut ouvrir l'app pour se connecter si aucun compte n'existe |

Règles communes :

- Après tout succès, échec ou annulation, la session est verrouillée et oubliée (`lock()`), et l'extension poste `store-changed` si elle a écrit.
- Aucun compte ou base illisible : écran "Ouvre OnePass pour configurer ton coffre" et annulation.
- Les items `reprompt` sont remplis sans seconde question : le déverrouillage de la requête est déjà une vérification fraîche.
- Jamais de Crypto Wallet (spec 5.4) ; jamais d'item d'un vault masqué sur cet appareil.
- Correspondance de domaine stricte (3.3) : la liste "Pour ce site" ne montre que les correspondances ; le reste est sous "Autres éléments" après une recherche ou un geste explicite.
- Le presse-papiers n'est pas utilisé.

## 6. App

- Lancement : `SharedContainerMigration` puis environnement partagé.
- Réglages > **Remplissage automatique** (nouvelle page) : état (actif ou non, lu par `ASCredentialIdentityStore.shared.state()`), bouton "Activer OnePass" (`ASSettingsHelper.requestToTurnOnCredentialProviderExtension`, repli `openCredentialProviderAppSettings`), bouton "Codes de vérification" (`openVerificationCodeAppSettings`), interrupteur "Suggestions au-dessus du clavier" (identités dans le magasin du système), texte qui dit ce que voit le système (domaines et identifiants, jamais de mot de passe).
- Accueil iPhone et barre latérale iPad et Mac : carte "Remplis tes mots de passe avec OnePass" tant que le fournisseur n'est pas actif, refermable une fois (`autofillTipDismissed`).
- Détail d'un Login : les passkeys listées montrent le site et la date de création ; la suppression d'une passkey passe par l'éditeur (champ répétable existant), qui demande confirmation.
- `IdentityStoreSync` branché sur la session (section 4) ; magasin vidé quand le réglage est coupé et quand le compte est réinitialisé.

## 7. Correction de "Enregistrer le mot de passe ?"

Cause (jalon 2, E20) : l'heuristique d'iOS voit un champ sécurisé disparaître après l'enregistrement d'un Login et propose d'enregistrer la valeur dans le fournisseur actif. Correction :

- OnePass actif comme fournisseur (iOS 26.2+) : la demande arrive à l'extension avec un service de type app égal à l'identifiant de OnePass, ou une valeur identique à un Login déjà stocké ; l'extension la referme sans interface et sans écriture.
- OnePass n'est pas le fournisseur, ou iOS 26.0 et 26.1 : la feuille peut encore apparaître (vers le fournisseur actif) ; la carte d'activation de la section 6 pousse l'utilisateur à faire de OnePass le fournisseur. Le test UI garde sa fermeture défensive pour ce cas.

## 8. Sécurité

- **Ce que voit le système** : `ASCredentialIdentityStore` reçoit hôtes, identifiants, noms d'utilisateur et ids de passkey, user handles, ids d'enregistrement opaques. Jamais un mot de passe, un code ou une clé. Le réglage "Suggestions au-dessus du clavier" le coupe. Ces métadonnées sont lisibles par le système hors du chiffrement de OnePass (ruling A5).
- **Extension** : processus distinct, session par requête, verrouillage à la fin. Le compteur d'échecs du mot de passe est partagé avec l'app (réglages partagés). La biométrie suit `BiometricPolicy` (14 jours, redémarrage, `.biometryCurrentSet`). `NSFaceIDUsageDescription` dans l'Info.plist de l'extension.
- **Mémoire** : Argon2id du mot de passe maître demande 256 Mio ; l'extension peut dépasser la limite mémoire d'une extension sur un appareil réel. Face ID n'a pas ce coût (AUK) et est proposé d'abord (ruling A2).
- **Base partagée** : même contenu chiffré qu'au jalon 2, dans le conteneur App Group. Deux processus écrivent ; l'intégrité reste celle du core (manifestes signés, écriture conditionnelle, état de l'appareil fusionné en 3.2).
- **Passkeys** : clé privée P-256 générée par `aws-lc-rs` dans le Rust, stockée chiffrée dans l'item comme toute valeur, jamais transmise à Swift. Une passkey supprimée côté OnePass reste connue du site (pas de signal `reportUnknownPublicKeyCredential` au jalon 3).
- **Hameçonnage** : le `rp_id` des passkeys est vérifié par le système (domaine de la page ou associated domains de l'app). Pour les mots de passe, OnePass ne pré-sélectionne que les correspondances PSL ; un choix hors correspondance demande un geste explicite ("Autres éléments").
- `docs/security/README.md` gagne une section 11 "Jalon 3 : AutoFill et passkeys".

## 9. Tests

- **Rust** (`core/onepass-core/src/webauthn.rs`, tests unitaires) : CBOR de la clé COSE et de l'objet d'attestation octet par octet, flags, compteur, longueur des données ; signature vérifiée par `aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1` sur `authData ‖ hash` ; clé importée non P-256 refusée ; tailles limites.
- **Rust FFI** (`core/onepass-ffi/tests/autofill.rs`) : identités produites et exclues (corbeille, archive, `hide_from_autofill`, Crypto Wallet), candidats classés (même hôte, domaine PSL, `co.uk`, IP, sosie `examp1e.com`, `http`), création de passkey dans un Login existant et nouveau, refus `excluded`, assertion vérifiable, `password_from_rules` (longueurs, classes requises, règles illisibles).
- **Rust core** : deux `Repository` sur la même base SQLite (deux connexions) qui écrivent tour à tour : aucun `last_seen` ne recule, aucun rejeu non détecté.
- **Swift** (`make -C apple test`) : migration du conteneur (déplacement, idempotence, arrêt simulé), `AutoFillIdentityBuilder`, `IdentityStoreSync` contre `InMemoryIdentityStore` (remplacement, anti-rebond, réglage coupé, vaults masqués), `AutoFillModel` (chaque ligne du tableau de la section 5 contre une vraie session à KDF rapide), `StoreChangeNotifier`.
- **UI** (`make -C apple uitest-autofill`, Simulateur `OnePass M3 iPhone`) : création de compte et d'un Login dans OnePass, activation du fournisseur depuis Réglages de OnePass (alerte système acceptée), app hôte de test `AutoFillHost` (champs identifiant et mot de passe), touche "Mots de passe" de la barre QuickType, choix de OnePass, déverrouillage par le mot de passe maître dans l'extension, choix du Login : les deux champs de l'app hôte sont remplis. Puis enregistrement d'un Login dans OnePass : aucune feuille "Enregistrer le mot de passe ?" n'apparaît.
- **Builds** : `make -C apple build-ios` et `build-mac` compilent l'app et l'extension.

## 10. Ce qui demande un build signé ou un vrai appareil

- Mac : l'extension est construite et embarquée, mais un build Mac signé ad hoc ne peut pas porter les droits App Group et fournisseur AutoFill (restreints, profil obligatoire). AutoFill sur Mac se vérifie en build signé.
- Face ID dans l'extension (Simulateur sans Secure Enclave), et la limite mémoire de l'extension avec Argon2id (ruling A2).
- Passkeys de bout en bout avec un vrai site (le Simulateur n'a pas d'associated domains signés ; la crypto est vérifiée par les tests Rust).
- Synchronisation CloudKit d'une passkey créée dans l'extension (R8 du jalon 2 : build `Release-CloudKit`).
- Flux hybride (QR code d'un autre appareil) : fourni par le système, à vérifier sur appareil.

## 11. Hors périmètre du jalon 3

- Import et export par FIDO Credential Exchange (`ASCredentialImportManager`, `ASCredentialExportManager`) : avec l'import et l'export du jalon 5 (ruling A11).
- Quick Access et barre de menus du Mac (spec 6.2) : jalon ultérieur (ruling A13).
- Vision Pro (jalon 6), extension Safari et icône dans le champ du web (jalon 4).
- Signal des passkeys inconnues ou renommées au système (`reportUnknownPublicKeyCredential`, `reportAllAcceptedPublicKeyCredentials`).
- Extensions WebAuthn PRF et largeBlob.

## 12. Fichiers partagés touchés (travail parallèle du jalon 6)

Ajouts seulement, sans reformatage : `apple/project.yml` (deux cibles, une clé Info.plist et un fichier de droits iOS pour l'app, schéma), `apple/App/**` (appel de migration au lancement, page de réglages, carte d'activation, branchement de `IdentityStoreSync`), `apple/Makefile` (cible `uitest-autofill`, Simulateur `OnePass M3 iPhone`), core (`lib.rs` une ligne, `rebase.rs` fusion de l'état d'appareil, `onepass-ffi` nouveau fichier et entrées en fin d'enum et de liste).

## 13. Décisions

- Ruling: brainstorming classé architectural, chaque validation tranchée par la session (consigne "décider tout, consigner") - le fondateur ne doit rien faire - reprendre une décision coûte une passe de spec et de plan sur la partie touchée.
- Ruling A1: base et réglages déplacés dans un conteneur App Group partagé, Secret Key et enrôlement biométrique dans le groupe Keychain déjà prévu au jalon 2 - l'extension doit ouvrir le coffre sans l'app ; un essai jetable sur Simulateur (signature ad hoc) a confirmé conteneur, groupe Keychain (préfixe injecté par Xcode) et enregistrement de l'extension auprès de `pluginkit` - si un build signé refusait le groupe, l'extension ne verrait pas le coffre ; le repli garde l'app fonctionnelle.
- Ruling A2: l'extension propose Face ID d'abord et garde le mot de passe maître (Argon2id 256 Mio) en second - Face ID (AUK) ne coûte presque pas de mémoire, et sans mot de passe un appareil sans biométrie n'aurait aucun remplissage - sur un appareil réel, la saisie du mot de passe dans l'extension peut être tuée par la limite mémoire ; à mesurer sur appareil, plan B : enveloppe de l'AUK par une clé Secure Enclave `.userPresence` (code de l'appareil).
- Ruling A3: migration par déplacement de fichiers au lancement, avant toute ouverture, base partagée prioritaire si elle existe - aucune version publique du jalon 2, une migration simple suffit - un appareil de développement qui aurait deux bases garde la partagée et ignore l'ancienne.
- Ruling A4: `persist_device_state` fusionne avec l'état stocké (plus grand `seq` par vault) - deux processus tiennent chacun un état en mémoire, l'écriture aveugle ferait reculer `last_seen` et affaiblirait la détection de rejeu - une fusion à chaque écriture coûte une lecture SQLite.
- Ruling A5: identités publiées dans `ASCredentialIdentityStore` par défaut, réglage pour les couper - sans elles, pas de suggestion QuickType, ce qui est le coeur de l'AutoFill - le système voit domaines et identifiants hors du chiffrement de OnePass (spec 6.1 l'accepte).
- Ruling A6: compteur de signature toujours 0, flags BE et BS - passkeys synchronisées, comme celles d'Apple ; un compteur ne peut pas rester monotone entre appareils - un site qui exige un compteur croissant refuserait la passkey (aucun site courant ne le fait pour BS=1).
- Ruling A7: AAGUID propre à OnePass, attestation `none` - pas d'attestation d'appareil possible pour une clé logicielle synchronisée - l'AAGUID n'est pas enregistré dans le FIDO MDS ; les sites l'affichent comme "authentificateur inconnu" jusqu'à l'enregistrement.
- Ruling A8: la user handle traverse vers Swift seulement pour les identités du système et l'assertion - l'API Apple l'exige, ce n'est pas un secret (le site la reçoit à chaque connexion) - elle est visible du magasin d'identités du système.
- Ruling A9: aucune création de passkey sans interface (mise à niveau automatique refusée) - l'extension n'est jamais déverrouillée hors requête - les mises à niveau silencieuses proposées par certains sites échouent ; l'utilisateur crée la passkey à la main.
- Ruling A10: règles de mot de passe d'Apple appliquées dans le Rust (`password_from_rules`), repli sur 20 caractères aléatoires - le générateur est déjà dans le core, testé - un site aux règles exotiques peut recevoir un mot de passe qu'il refuse ; l'utilisateur en génère un autre.
- Ruling A11: FIDO Credential Exchange (import et export système) hors du jalon 3 - c'est de l'import et de l'export, le core a déjà le lecteur CXF du jalon 5 - un utilisateur ne peut pas encore migrer ses passkeys depuis Mots de passe d'Apple par le flux système.
- Ruling A12: pas d'icône dans les champs des apps tierces ; l'expérience système (QuickType, touche clé, feuille passkey) en tient lieu - iOS et macOS ne l'autorisent à aucun fournisseur, et un clavier personnalisé est exclu par la spec 6.1 - l'icône dans le champ reste réservée aux pages web via l'extension Safari du jalon 4.
- Ruling A13: Quick Access et barre de menus du Mac (spec 6.2) hors du jalon 3 - le point 3 des jalons vise l'AutoFill système - sur Mac hors navigateur, seule l'AutoFill système (champs reconnus par macOS) est disponible.
- Ruling A14: identités limitées aux Logins (mots de passe, codes, passkeys) ; l'insertion de texte couvre les autres types - un Server ou un Email n'a pas de domaine de connexion fiable - un compte Email ne remonte pas en suggestion QuickType.
- Ruling A15: l'extension relie statiquement sa propre copie du core Rust - une seule façon de construire l'XCFramework, aucun framework dynamique à signer - la taille de l'app augmente de la taille du core (quelques Mo après LTO).
- Ruling A16: test UI de l'AutoFill sur un Simulateur dédié `OnePass M3 iPhone` et une app hôte de test `AutoFillHost` (cible iOS non livrée) - aucune autre app du Simulateur n'a de champ de connexion stable, et Safari demanderait un serveur - l'app hôte ne prouve pas la correspondance de domaine (couverte par les tests Rust).

## 14. Rulings d'exécution

Décisions prises pendant l'implémentation, au même format.
