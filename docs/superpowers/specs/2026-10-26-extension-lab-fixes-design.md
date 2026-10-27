# Extension : corrections issues du laboratoire d'autofill

Date : 2026-10-26. Branche : `feat/extension-lab-fixes` (depuis `main` 12f5c97). Statut : approuvée en autonomie (rulings en section 6).

## 1. But et critère de fin

Corriger dans l'extension (et, pour les passkeys, dans le pont et l'hôte natif) toutes les causes racines du rapport `docs/lab/2026-10-26-autofill-lab-run.md`, jusqu'à :

- au moins **95 %** de réussite hors attendus sur deux passages complets de 200 sites (graine de référence `lab-2026-10-26` et graine neuve `lab-2026-10-26-b`) ;
- **0 fuite** ;
- `npm run check`, `npm run e2e` (flux et sécurité S1 à S17, plus les nouveaux tests passkeys) et les tests Rust du pont et de l'hôte verts ;
- aucune régression : chaque verdict `pass` du smoke reste `pass`.

Chaque cause racine a une graine du labo qui échoue avant et passe après (`npm run lab:repro -- --seed lab-2026-10-26 --site <n>`), citée dans son commit et dans le rapport final.

## 2. Causes racines et corrections

| # | Cause (rapport) | Sites témoins | Correction |
| --- | --- | --- | --- |
| A1 | Lexique : allemand, espagnol faibles, italien, portugais, néerlandais absents | 120, 63, 100 | Termes de/es/it/pt/nl pour chaque rôle (identifiant, courriel, mot de passe, nouveau, confirmation, code, carte, identité, adresse) et chaque bouton (connexion, suivant, payer, enregistrer, inscription) dans `content/detect/lexicon.ts` ; tests unitaires par langue. |
| A2 | Code "Security code" lu comme CVC | 3 | Un libellé ambigu (code de sécurité, security code, Sicherheitscode...) ne compte comme CVC que si le formulaire a d'autres champs de carte ; sinon il compte comme OTP. |
| A3 | Étape "identifiant seul" sans `autocomplete` non reconnue | 123, 179 | Un formulaire avec un seul champ texte ou courriel visible, sans mot de passe, et un bouton de type "suivant"/"connexion" (lexique A1), sur une page de connexion, est une étape d'identifiant ; noms usuels (`loginfmt`, `identifier`, `login`, `user`) reconnus. |
| A4 | OTP découpé en cases | 81, 126 | Groupe de 4 à 8 champs voisins `maxlength=1` (numériques ou texte) traité comme un OTP en parties, rempli dans l'ordre. |
| B1 | Champs différés non repris | 16, 187, 97 | Toute analyse dont la signature change peut proposer l'overlay (et plus seulement la première du document), et l'échéance "page inconnue" de la chaîne (4 s) repart quand une analyse change. |
| B2 | Re-rendu SPA : champs détachés pendant le remplissage | 141, 2, 10 | Au remplissage, un `ref` détaché est résolu à nouveau dans l'analyse courante (même formulaire, même rôle) ; après remplissage, si un champ rempli a été remplacé et que le nouveau est vide, un second remplissage unique a lieu ; la chaîne n'interprète pas un re-rendu de la même étape comme `repeat` tant qu'aucune soumission n'a eu lieu. |
| C1 | Connexion dans une iframe de **même origine** jamais proposée | 84, 128, 104 | Les analyses des cadres dont l'origine est exactement celle du cadre principal comptent pour l'overlay et la chaîne ; le remplissage vise ce `frameId`. Un cadre d'un autre site reste exclu (R-10). |
| D1 | Shadow DOM ouvert | 22 xfail | L'analyse parcourt les racines fantômes ouvertes (bornes : 3000 éléments et profondeur 8 par analyse) ; l'observateur observe aussi ces racines. |
| D2 | Shadow DOM fermé | 22 xfail | Sur Chromium, `chrome.dom.openOrClosedShadowRoot(el)` (API d'extension, script de contenu) donne accès aux racines fermées de la page ; mêmes bornes. Ailleurs, limite documentée. |
| E1 | Pages SSO seules : pas d'overlay | 5, 18 et 21 autres | L'overlay est proposé aussi quand la page a un bouton fournisseur reconnu et qu'un item de l'origine a une méthode de connexion pour ce fournisseur ; la chaîne commence alors par le clic sur ce bouton (étape `provider_click` déjà présente). |
| F1 | Passkeys absentes de l'extension | 22 xfail | Section 3. |

## 3. Passkeys

### 3.1 Pont et hôte (Rust)

Trois opérations nouvelles dans `onepass-bridge` (`api.rs`, `service.rs`), servies par l'hôte natif de développement :

- `passkey_list {ctx, origin, rp_id}` : résumés des passkeys des Login vivants dont `rp_id` correspond (item, `credential_id` base64url, `user_name`, titre), sans secret.
- `passkey_get {ctx, origin, rp_id, item_id, credential_id, challenge}` : l'hôte vérifie l'origine (HTTPS), vérifie que `rp_id` est l'hôte de l'origine ou un suffixe de domaine enregistrable de cet hôte qui n'est pas un suffixe public (Public Suffix List), construit lui-même `clientDataJSON` `{"type":"webauthn.get","challenge":...,"origin":<origin>,"crossOrigin":false}`, signe avec `onepass_core::webauthn::assertion` et rend `credential_id`, `client_data_json`, `authenticator_data`, `signature`, `user_handle` (base64url). Journal d'audit, limite de débit, règle `reprompt` comme les autres secrets.
- `passkey_create {ctx, origin, rp_id, user_name, user_handle, challenge, exclude}` : mêmes vérifications, `onepass_core::webauthn::new_credential`, enregistrement dans le Login de l'origine qui a ce nom d'utilisateur ou dans un nouveau Login, rend `credential_id`, `client_data_json` (type `webauthn.create`), `attestation_object`, `authenticator_data`. Refus `excluded` si un identifiant exclu existe déjà.

Contextes permis : `passkey` (nouvelle fenêtre de choix de l'extension) et `chain`. L'origine vient toujours de l'extension, qui la tient du navigateur (`sender`), jamais de la page. La clé privée ne quitte jamais l'hôte. La fixture de l'hôte accepte un champ `passkeys` par Login (build debug seulement, comme le reste de la fixture).

### 3.2 Extension

- **Cale de page** : un script de contenu `world: "MAIN"` à `document_start`, dans tous les cadres, remplace `navigator.credentials.get` et `create` pour les seules requêtes `publicKey`. Il transmet `challenge`, `rpId`, `allowCredentials`, `user`, `excludeCredentials`, `timeout` au script de contenu isolé par un `MessageChannel` établi au démarrage, et renvoie un objet de la forme `PublicKeyCredential` (tampons `ArrayBuffer`, `getClientExtensionResults`, `authenticatorAttachment: "platform"`). Sans passkey OnePass pour ce site, ou si l'utilisateur choisit "Autre appareil", il appelle l'API d'origine. Un refus donne `NotAllowedError`.
- **Script de contenu isolé** : valide la forme (tailles, types), envoie `passkey_request` au service worker.
- **Service worker** : origine prise de `sender` ; cadre principal ou cadre de même origine seulement (sinon : API d'origine) ; liste les passkeys ; si une chaîne "Connexion en un clic" lancée par l'utilisateur tourne dans cet onglet pour un item qui a une passkey de ce `rp_id`, il signe sans autre geste (le clic sur l'overlay est le consentement) ; sinon il ouvre la fenêtre de choix `passkey.html` (page de l'extension, même modèle que la proposition d'enregistrement : jeton lié à l'onglet, au cadre et au document, garde de clic de 300 ms, clic de confiance requis) et signe après le choix.
- **Interface** : `passkey.html` suit le système visuel de l'extension (menu, proposition d'enregistrement) ; conception avec le skill `design-taste-frontend`.

### 3.3 Sécurité

Nouveaux tests e2e : `S18_passkey_needs_user_click` (une page qui appelle `credentials.get` n'obtient rien avant un clic de confiance dans la fenêtre de choix), `S19_passkey_rp_id_of_other_site_refused` (refus par l'hôte), `S20_passkey_in_cross_site_frame_falls_back` (rien de signé), `S21_passkey_client_data_origin_from_browser` (l'origine de `clientDataJSON` est celle du navigateur, pas celle annoncée par la page). Tests Rust : validation de `rp_id` (suffixe public refusé, autre domaine refusé, sous-domaine accepté), `clientDataJSON` construit par l'hôte, résumés sans secret, `passkey_get` hors contexte permis refusé. Section 12 de `docs/security/README.md` mise à jour.

## 4. Laboratoire

- `capabilities.ts` : passkeys et shadow DOM ne sont plus des échecs attendus (Chromium) ; l'iframe d'un autre site reste "rien rempli".
- Générateur : passkeys des sites dans la fixture (clé PKCS#8 construite depuis `d`, `x`, `y`) ; langues de/es/it/pt/nl dans la part de 0,2 (lexique de base complété pour it, pt, nl).
- Pilote passkey seule : l'utilisateur clique le bouton passkey du site, puis choisit le compte dans la fenêtre OnePass (clic de confiance).
- `smoke-expected.json` régénéré : seuls des verdicts meilleurs sont admis.

## 5. Ordre

A (lexique, OTP, identifiant), B (dynamique), C (iframes), D (shadow), E (SSO), F (passkeys : Rust, puis extension, puis labo), G (labo et passages complets). Chaque lot finit par sa graine témoin et un smoke vert.

## 6. Rulings

Ruling: cible mesurée sur deux graines (`lab-2026-10-26` et `lab-2026-10-26-b`), chacune au moins 95 % - une seule graine inviterait à corriger pour ce monde-là - coût si faux : un passage de 18 min de plus.
Ruling: l'hôte construit `clientDataJSON` à partir de l'origine que lui donne l'extension (tenue du navigateur) - l'origine de la page n'est jamais crue, comme pour les autres opérations du pont - coût si faux : aucun, c'est le modèle de tout le pont.
Ruling: passkeys refusées aux cadres d'un autre site (API d'origine appelée) - même règle que R-10 pour les mots de passe - coût si faux : un site qui fait sa connexion par passkey dans une iframe tierce passe par le navigateur.
Ruling: pendant une chaîne lancée par un clic de l'utilisateur sur l'overlay, la passkey de l'item choisi est signée sans second geste - le clic sur "Se connecter" est le consentement pour cet item et ce site, comme pour le mot de passe et le TOTP - coût si faux : une page qui appelle `credentials.get` pendant la chaîne obtient une assertion pour son propre site, ce qui est l'objet même de la connexion.
Ruling: shadow DOM fermé via `chrome.dom.openOrClosedShadowRoot` sur Chromium seulement - seule API qui y donne accès sans toucher la page - coût si faux : Firefox et Safari gardent la limite, documentée.
Ruling: iframes de même **origine** seulement (pas même site) pour l'overlay et la chaîne - un sous-domaine du même site peut être un autre service ; R-10 reste intact - coût si faux : une connexion dans une iframe d'un sous-domaine reste au menu.
Ruling: l'overlay sur page SSO seule ne s'affiche que si un item de l'origine a une méthode de connexion pour un fournisseur présent sur la page - sinon il proposerait de se connecter sans rien pouvoir faire - coût si faux : aucun.
Ruling: les langues it, pt, nl entrent dans le lexique de l'extension et dans le générateur - la consigne demande les langues courantes de plus ; le corpus n'en a pas, le lexique de base les apporte - coût si faux : taux par langue sur des libellés écrits à la main.
Ruling: la cale `MAIN` n'expose qu'une fonction déjà disponible à la page (demander une assertion pour sa propre origine, après un geste de l'utilisateur dans l'interface de l'extension) - une page hostile qui l'appelle n'obtient rien de plus qu'avec `navigator.credentials` - coût si faux : aucun, S18 à S21 l'épinglent.
