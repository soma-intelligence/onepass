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
8. **Fin de la feuille "Enregistrer le mot de passe ?"** après l'enregistrement d'un Login dans OnePass (limite E20 du jalon 2) : quand OnePass est le fournisseur, la demande d'enregistrement arrive à OnePass, qui reconnaît qu'elle vient de lui-même (service de type app égal à OnePass) et la referme sans rien demander ; une valeur identique à un Login déjà stocké se referme juste après le déverrouillage, sans feuille.

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
- Fonction libre `password_from_rules(rules: Vec<String>, fallback: FfiPasswordRecipe) -> Result<String>` (règles du champ, de la confirmation et des correctifs du système, cumulées) : applique le langage `passwordrules` d'Apple (`minlength`, `maxlength`, `required`, `allowed`, `max-consecutive`, classes `lower`, `upper`, `digit`, `special`, `ascii-printable`, `unicode`, ensembles `[...]`) au générateur du core ; règles illisibles ou contradictoires : la recette de repli (aléatoire, 20 caractères) (ruling A10).
- La correspondance de domaines utilise la Public Suffix List par la crate `psl` 2 (la même que l'extension navigateur du jalon 4) et `url` 2, dépendances de `onepass-ffi` seulement. Hôtes comparés en ASCII minuscule (punycode) ; une adresse IP ne correspond qu'à elle-même ; `http` jamais proposé pour un domaine public (correspondance d'un site HTTPS seulement, sauf hôte local).

`FfiPasskey` reste sans user handle : la `user_handle` ne traverse que dans `FfiAutofillIdentity` et `FfiPasskeyAssertion`, là où l'API Apple l'exige (ruling A8).

## 4. VaultKit

Nouveau dossier `VaultKit/Sources/VaultKit/AutoFill/` :

- `SharedContainer` : URL du conteneur App Group (`group.me.somalabs.onepass` sur iOS, `<préfixe d'équipe>me.somalabs.onepass` sur macOS, lus dans la clé Info.plist `OnePassAppGroup`), chemin de la base (`Library/Application Support/OnePass/vault.sqlite`, dossier en `completeUntilFirstUserAuthentication` sur iOS), suite `UserDefaults` partagée. Sans conteneur (build Mac non signé), repli sur les emplacements du jalon 2 et `isShared == false`.
- `SharedContainerMigration` : au lancement de l'app, avant toute ouverture de la base, si la base partagée n'existe pas et que l'ancienne existe, déplace `vault.sqlite`, `-wal` et `-shm` (dans cet ordre inverse : `-shm`, `-wal`, puis la base, pour qu'un arrêt au milieu laisse l'ancienne base complète), puis copie une fois les clés `onepass.*` de `UserDefaults.standard` vers la suite partagée (ruling A3). Idempotent.
- `AutoFillIdentityBuilder` : transforme `FfiAutofillIdentity` en `ASPasswordCredentialIdentity`, `ASPasskeyCredentialIdentity`, `ASOneTimeCodeCredentialIdentity` (service de type domaine pour un hôte, rang 1 pour un favori).
- `IdentityStoreSync` (acteur) : `refresh(session)` remplace tout le contenu de `ASCredentialIdentityStore` (si le magasin est activé et le réglage "Suggestions" actif), anti-rebond 1 s ; `clear()` vide le magasin (réglage coupé, compte réinitialisé). Protocole `IdentityStoreClient` pour les tests (`InMemoryIdentityStore`).
- `StoreChangeNotifier` : poste et observe la notification Darwin `me.somalabs.onepass.store-changed` (aucune donnée transportée).
- Pas de `AutoFillUnlocker` séparé (ruling X1) : l'extension réutilise `VaultSession`, qui porte déjà le déverrouillage (biométrie si enrôlée et autorisée par `BiometricPolicy`, sinon mot de passe maître, compteur d'échecs partagé, intégrité). La session est ouverte par requête, sans sync (`NoSync`), et verrouillée à la fin de la requête ; `AutoFillModel` en pilote le cycle.
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
| `performPasskeyRegistrationWithoutUserInteractionIfPossible` | `failed` (pas de création silencieuse, rulings A9 et X21) |
| `prepareInterfaceForSavePasswordRequest` (26.2+) | demande venant de OnePass lui-même (service de type app dont l'identifiant est celui de l'app) ou mot de passe généré rempli : fin immédiate sans interface ni écriture ; valeur identique à un Login existant (même hôte, même identifiant à la casse près, même mot de passe) : fin juste après le déverrouillage, sans feuille ni écriture ; sinon déverrouillage et feuille Enregistrer ou Mettre à jour |
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

- OnePass actif comme fournisseur (iOS 26.2+) : la demande arrive à l'extension avec un service de type app égal à l'identifiant de OnePass ; l'extension la referme sans interface et sans écriture. Une valeur identique à un Login déjà stocké (autre service) se referme juste après le déverrouillage, sans feuille ni écriture.
- OnePass n'est pas le fournisseur, ou iOS 26.0 et 26.1 : la feuille peut encore apparaître (vers le fournisseur actif) ; la carte d'activation de la section 6 pousse l'utilisateur à faire de OnePass le fournisseur. Le test UI garde sa fermeture défensive pour ce cas.

## 8. Sécurité

- **Ce que voit le système** : `ASCredentialIdentityStore` reçoit hôtes, identifiants, noms d'utilisateur et ids de passkey, user handles, ids d'enregistrement opaques. Jamais un mot de passe, un code ou une clé. Le réglage "Suggestions au-dessus du clavier" le coupe. Ces métadonnées sont lisibles par le système hors du chiffrement de OnePass (ruling A5).
- **Extension** : processus distinct, session par requête, verrouillage à la fin. Le compteur d'échecs du mot de passe est partagé avec l'app (réglages partagés). La biométrie suit `BiometricPolicy` (14 jours, redémarrage, `.biometryCurrentSet`). `NSFaceIDUsageDescription` dans l'Info.plist de l'extension.
- **Mémoire** : Argon2id du mot de passe maître demande 256 Mio ; l'extension peut dépasser la limite mémoire d'une extension sur un appareil réel. Face ID n'a pas ce coût (AUK) et est proposé d'abord (ruling A2).
- **Base partagée** : même contenu chiffré qu'au jalon 2, dans le conteneur App Group. Deux processus écrivent ; l'intégrité reste celle du core (manifestes signés, écriture conditionnelle, état de l'appareil fusionné en 3.2).
- **Passkeys** : clé privée P-256 générée par `aws-lc-rs` dans le Rust, stockée chiffrée dans l'item comme toute valeur, jamais transmise à Swift. Une passkey supprimée côté OnePass reste connue du site (pas de signal `reportUnknownPublicKeyCredential` au jalon 3).
- **Hameçonnage** : le `rp_id` des passkeys est vérifié par le système (domaine de la page ou associated domains de l'app). Pour les mots de passe, OnePass ne pré-sélectionne que les correspondances PSL ; un choix hors correspondance demande un geste explicite ("Autres éléments").
- `docs/security/README.md` gagne une section "Jalon 3 : AutoFill et passkeys" (section 14 après la fusion avec les jalons 4, 6 et 7).

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

- Ruling X1: l'extension réutilise `VaultSession` au lieu d'un `AutoFillUnlocker` séparé (la section 4 est amendée) - mêmes règles de déverrouillage, mêmes compteurs d'échecs et même traitement des erreurs d'intégrité, sans code dupliqué - si `VaultSession` tire dans l'extension un comportement réservé à l'app (minuterie de verrouillage, sync), l'extension doit le neutraliser (`NoSync`, verrouillage à la fin de la requête).
- Ruling X2: seule l'app rebase ; l'extension ouvre une session neuve par requête, ne rebase jamais et se verrouille à la fin - aucun processus longue durée ne garde en mémoire un `seq` abandonné par un rebase (le rebase persiste avec `force`, qui impose sa propre entrée) - une future surface qui garderait une session longue et rebaserait ailleurs pourrait réécrire un `seq` mort et bloquer un vault jusqu'au prochain verrouillage.
- Ruling X3: les Logins `hide_from_autofill` sont exclus aussi de `autofill_candidates`, `include_all` compris - "caché de l'AutoFill" doit vouloir dire jamais proposé par l'extension - l'utilisateur ne peut pas choisir à la main un tel item dans l'extension (il l'ouvre dans l'app).
- Ruling X4: avec `include_all`, les Logins `http` ou à règle de correspondance `Never` peuvent apparaître en "Autres éléments" - choix manuel explicite (section 5) - un utilisateur peut remplir volontairement un mot de passe dans un formulaire `http`.
- Ruling X5: les ports sont ignorés dans la correspondance d'hôte - la spec parle d'hôtes - un Login pour `example.com:8443` est proposé sur `example.com`.
- Ruling X6: la création d'une passkey avec un nom d'utilisateur vide dans un nouveau Login est refusée - l'identifiant d'un Login est requis et les sites WebAuthn envoient toujours `user.name` - un site qui enverrait un nom vide ne peut pas enregistrer de passkey dans OnePass.
- Ruling X7: la longueur d'un mot de passe généré par `password_from_rules` est plafonnée à 64 dans tous les cas, et un `minlength` supérieur à 64 donne le repli - les règles viennent d'une page web, donc d'une entrée hostile, et la mémoire de l'extension est bornée - un site qui exige plus de 64 caractères reçoit le repli de 20 caractères et peut le refuser.
- Ruling X8: `required` seul restreint l'ensemble autorisé aux classes requises, et `special` inclut l'espace - c'est la grammaire `passwordrules` d'Apple - un site qui refuse l'espace intérieur peut rejeter le mot de passe généré.
- Ruling X9: un seul `Info.plist` pour l'extension sur les deux plateformes, `ProvidesTextToInsert` présent aussi sur macOS où le système l'ignore - un fichier de moins à maintenir - aucun (macOS n'a pas d'API d'insertion de texte).
- Ruling X10: les mises à jour des README sont regroupées dans la tâche 12 - une seule passe de documentation - aucun.
- Ruling X11: une notification `store-changed` signale aussi le coordinateur de sync quand l'app est verrouillée (les lignes `pending` partent sans déverrouillage) - l'extension écrit le plus souvent pendant que l'app est verrouillée - une tentative d'envoi de plus par notification.
- Ruling X12: `VaultSession` annule sa tâche d'observation de la notification dans `deinit` - l'extension crée une session par requête dans un processus qui peut vivre longtemps - aucun.
- Ruling X13: une requête passkey directe sans l'identifiant de credential de l'identité est refusée (`credentialNotFound`) au lieu de signer avec la première passkey du Login - ne jamais signer pour le mauvais compte - le contrôleur doit toujours passer l'identifiant de credential.
- Ruling X14: une écriture refusée (cible absente de l'écran, vault masqué) laisse l'écran inchangé, sans message - l'interface n'offre que des cibles valides - un bug d'interface ressemblerait à un bouton mort plutôt qu'à une mauvaise écriture.
- Ruling X15: une liste `supportedAlgorithms` vide vaut acceptation d'ES256 - c'est le défaut de WebAuthn - aucun pour les parties de confiance conformes.
- Ruling X16: l'extension n'ouvre ni ne crée jamais le magasin quand le fichier de base partagé manque, et la migration met de côté (sans jamais la supprimer) une base partagée sans compte quand une ancienne base existe - un magasin vide créé le premier ferait perdre le vrai coffre - un fichier de plus reste à côté du magasin après un tel lancement.
- Ruling X17: une migration qui échoue remet en place les fichiers annexes déjà déplacés avant de retomber sur l'ancien conteneur - ouvrir une base sans son WAL perd des écritures - aucun (un double échec, silencieux, reste possible).
- Ruling X18: l'état du fournisseur affiché "Désactivé" dans le Simulateur est une limite du Simulateur (service d'état de `ASCredentialIdentityStore` injoignable, "No such process") - l'interrupteur des réglages du système prouve l'activation - l'affichage "Activé" n'est vérifié que sur un appareil.
- Ruling X19: sur iOS 27, les lignes de la page Réglages n'ouvraient pas leur page (geste tactile d'activité sur `SettingsView`) ; remplacé par `onChange(of: path)` - la navigation fonctionne - un toucher dans une page de réglages ne repousse plus le verrouillage automatique.
- Ruling X20: la clé de dédoublonnage des identités du système contient l'identifiant de credential (type, service, nom d'utilisateur, identifiant d'enregistrement, identifiant de credential) - sans lui, deux passkeys d'un même Login pour le même site et le même nom seraient fusionnées et l'une disparaîtrait de la feuille passkey - aucun.
- Ruling X21: l'enregistrement conditionnel d'une passkey sans interface (`performWithoutUserInteractionIfPossible(passkeyRegistration:)`) répond `.failed` au lieu de `userInteractionRequired` - ruling A9 : jamais de passkey créée automatiquement - les mises à niveau automatiques des sites n'obtiennent jamais de passkey OnePass.
- Ruling X22: un Login vivant et non caché qui porte une passkey dont le `rp_id` est l'hôte demandé (même normalisation, casse ignorée) est un candidat `ExactHost` même sans URL correspondante - le système a déjà vérifié le `rp_id` - aucun.
- Ruling X23: un double échec de la migration (le retour en arrière échoue aussi) lève `SharedContainerMigrationError.rollbackFailed` et l'app n'ouvre aucune base pour ce lancement (écran "Données refusées", "Réessayer" n'ouvre rien) - ni l'ancienne base sans son WAL ni la base partagée absente (accueil de création de compte) ne sont sûres - il faut relancer OnePass, la migration suivante ramène les fichiers annexes égarés et reprend.

Points laissés ouverts (mineurs différés) :

- `cbor_head` tronque en silence les longueurs de 65536 et plus : plafonner l'identifiant de credential à 1023 octets (maximum WebAuthn) ou refuser.
- Pas de test de signature négatif ni de contrôle du hash du `rp_id` dans le test d'assertion ; l'effacement du PKCS#8 en mémoire n'est pas confirmé dans la documentation.
- Une session verrouillée avec un identifiant mal formé rend `InvalidInput` au lieu de `Locked`.
- La cible `uitest-autofill` du `Makefile` code en dur le chemin `Debug-iphonesimulator`.
- Migration : `resolve()` sonde à chaque appel (mis en cache par lancement dans `AppModel`, pas dans l'extension) ; un sidecar de destination périmé n'est pas testé ; `isShared` vrai avec une suite nulle est permis.
- L'extension recharge sa session après sa propre notification (sans conséquence).
- Un `viewDidDisappear` tardif d'un contrôleur réutilisé peut abandonner la requête suivante ; `abandon()` ne signale pas une écriture encore en cours.
- La carte d'activation est absente d'un Accueil vide ; double republication lors d'un rafraîchissement concurrent de l'état (anti-rebond, sans conséquence).
- Risque `0xdead10cc` (base WAL dans le conteneur partagé, connexions longues de l'app) : à vérifier sur appareil, mitigation prévue (tâche d'arrière-plan autour des écritures et de la sync, ou point de contrôle et fermeture au passage en arrière-plan), non implémentée.
- Pas de test d'entrelacement d'une écriture de l'extension au milieu d'un `rebase()` (pas de point d'accroche entre `rebase_vault` et la fin) : la persistance finale non forcée est couverte par les tests de rebase existants.
