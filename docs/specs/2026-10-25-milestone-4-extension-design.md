# OnePass jalon 4 : extension navigateur (partie indépendante des apps)

Date : 2026-10-25
Statut : approuvée (auto-approbation, voir "Processus")
Spec parente : `2026-10-25-onepass-architecture-design.md`, sections 3, 6.3, 5.5 et 13 (item 4).

## 0. Processus

Le fondateur a demandé que tous les jalons avancent en parallèle sans action de sa part. Chaque décision qu'un humain aurait prise pendant le brainstorming est donc prise ici et notée sous la forme :

`Ruling : <quoi> - <pourquoi> - <coût si c'est faux>`

La liste complète est reprise en section 14.

## 1. Objectif et périmètre

Construire tout ce qui, dans le jalon 4, ne dépend pas des apps du jalon 2 :

1. **Le protocole extension ↔ app native** : framing native messaging, appairage, clés de session, protection contre le rejeu, liste fermée de ce que l'extension peut demander et de ce qu'elle ne reçoit jamais. Implémenté en Rust dans une nouvelle crate `core/onepass-bridge`, avec un client TypeScript dans l'extension.
2. **L'extension WebExtension** (TypeScript, Manifest V3) : Safari d'abord dans la conception, Chromium et Firefox compatibles. Détection des formulaires (connexion, inscription, changement de mot de passe, code à usage unique, carte, identité, adresse), icône dans le champ, menu de suggestions en ligne, proposition d'enregistrement, overlay "Connexion en un clic" qui enchaîne toute la chaîne d'authentification, y compris "Continuer avec Google / Apple / Microsoft" avec choix parmi plusieurs comptes.
3. **Un hôte natif de développement** (`core/onepass-native-host`) qui parle le vrai protocole et sert les vraies données du `core` (dépôt de développement de la CLI, ou jeu de données fictif), pour faire tourner l'extension de bout en bout sans les apps.

Hors périmètre de ce document (voir rulings) : intégration dans l'app Mac et dans l'extension Safari empaquetée (jalon 2), passkeys (jalon 3), mode autonome Windows et Linux (CloudKit JS), apprentissage des étapes inconnues.

## 2. Ce que le fondateur a fixé (rappel)

- Sur Mac, aucune crypto de coffre dans l'extension : elle passe par l'app. Les clés restent dans l'app.
- Appairage initial, puis session chiffrée hybride ML-KEM + X25519. L'app vérifie l'identifiant de l'extension.
- Correspondance stricte par domaine (Public Suffix List), jamais de remplissage dans une iframe d'un autre site, rien en HTTP, remplissage seulement après un geste de l'utilisateur.
- Menu et overlay rendus dans une iframe de l'origine de l'extension.
- Chaîne d'authentification pilotée par le service worker, jamais par la page. Garde-fous : démarrage par un clic, domaine vérifié à chaque étape, arrêt sur étape inconnue, CAPTCHA, validation push ou SMS, délai maximal de 60 s, bouton "Arrêter".
- Interface conforme aux maquettes approuvées (canvas Claude Design : planches Extension, Inline, Save). Marque propre, données fictives uniquement.

## 3. Modèle de menace propre à l'extension

Acteurs hostiles, du plus probable au moins probable :

1. **La page web.** Elle contrôle tout son DOM, peut créer des champs invisibles, superposer des éléments (clickjacking), envoyer des événements synthétiques, des `postMessage`, naviguer à tout moment, s'afficher sous un domaine sosie, embarquer des iframes d'autres sites.
2. **Le processus de rendu compromis.** Dans Chromium, le script de contenu tourne dans le processus de la page. Un exploit du moteur de rendu contrôle donc le script de contenu. Conséquence : le service worker traite chaque message d'un script de contenu comme non fiable, et ne croit que l'origine fournie par le navigateur (`sender`), jamais une origine écrite dans le message.
3. **Une autre extension ou un processus local** qui tente de parler à l'hôte natif. Le manifeste de l'hôte limite les extensions autorisées, mais un processus local peut lancer le binaire lui-même. L'hôte ne sert donc qu'un pair qui détient une clé d'appairage.
4. **Un intermédiaire sur le canal** entre l'extension et l'app (binaire d'hôte remplacé). Couvert par la comparaison de code à l'appairage et par l'authentification mutuelle de chaque session.

Hors périmètre, comme dans la spec parente : appareil compromis au niveau système. Un logiciel malveillant qui lit le profil du navigateur de l'utilisateur obtient la clé d'appairage stockée par l'extension. Il peut alors demander des secrets **pour des origines précises**, comme l'extension elle-même. Limite documentée, pas résolue en v1 (voir R-17).

## 4. Architecture

```
 page web (hostile)
   │ DOM seulement
 script de contenu (non fiable)          iframes extension : menu, overlay, enregistrement (fiables)
   │ runtime messages                        │ runtime messages + jeton
   └──────────────► service worker ◄─────────┘        popup (fiable)
                      │  politique d'origine, état des chaînes, session chiffrée
                      │  native messaging (JSON, longueur sur 4 octets)
                    hôte natif ── onepass-bridge (session, politique) ── onepass-core (coffre)
```

- **`core/onepass-bridge`** (bibliothèque Rust) : framing, KEM hybride, appairage, session, messages, politique de réponse, trait `VaultAccess` qui abstrait le coffre. L'app Mac du jalon 2 l'embarquera (UniFFI) ; l'hôte de développement l'embarque directement.
- **`core/onepass-native-host`** (binaire Rust) : boucle stdio, configuration, stockage des appairages, implémentation de `VaultAccess` sur `onepass_core::repo::Repository`.
- **`extension/`** (TypeScript) : service worker, script de contenu, pages d'extension (popup, menu, overlay, enregistrement), client du protocole.

Ruling R-01 : nouvelle crate `onepass-bridge` et nouveau binaire `onepass-native-host`, ajoutés aux membres du workspace, sans toucher aux API existantes de `onepass-core` - d'autres sessions modifient `core/` en parallèle et la règle de frontière de la spec parente reste vraie (seul le code Rust touche le coffre) - coût si faux : un conflit trivial sur la liste `members` du `Cargo.toml` racine au moment de la fusion.

Ruling R-02 : la bibliothèque du protocole est indépendante du transport ; l'hôte de développement n'est qu'un adaptateur stdio - dans le produit, le binaire lancé par Chrome ou Firefox sera un relais minimal vers l'app Mac (XPC), et Safari passe par `SafariWebExtensionHandler`, sans stdio - coût si faux : une couche d'adaptation de plus au jalon 2.

## 5. Transport : framing native messaging

- Chrome et Firefox : chaque message est un entier non signé de 32 bits dans l'ordre natif (petit-boutiste sur toutes les cibles Apple et x86), suivi d'autant d'octets de JSON UTF-8.
- Plafond OnePass : 1 MiB dans les deux sens (le navigateur accepte 1 MiB de l'hôte, 64 MiB vers l'hôte). Une longueur plus grande ferme la connexion sans lire le corps.
- Une fin de flux en plein message est une erreur ; une fin de flux entre deux messages est un arrêt propre.
- Le JSON extérieur ne porte que l'enveloppe du protocole (section 6). Tout contenu applicatif est chiffré.
- Arguments de lancement : Chrome passe l'origine de l'appelant (`chrome-extension://<id>/`), Firefox le chemin du manifeste et l'identifiant de l'extension. L'hôte compare l'identifiant à sa liste autorisée et refuse sinon. Contrôle informatif seulement (un processus local peut mentir sur ses arguments) : la vraie garde est l'appairage.

Ruling R-03 : même enveloppe JSON chiffrée pour Safari (dictionnaire passé à `sendNativeMessage`) et pour stdio - un seul protocole à auditer - coût si faux : aucun, Safari accepte un dictionnaire JSON.

## 6. Protocole cryptographique

### 6.1 Primitives

- KEM hybride : ML-KEM-1024 (FIPS 203) + X25519, combinés par HKDF-SHA256 (section 6.2).
- Hachage, MAC, dérivation : SHA-256, HMAC-SHA256, HKDF-SHA256.
- Chiffrement du canal : AES-256-GCM, une clé par sens, nonce de 96 bits = compteur du message sur 64 bits précédé de 4 octets nuls.
- Rust : `aws-lc-rs` (déjà dans le workspace). TypeScript : WebCrypto pour HKDF, HMAC, SHA-256 et AES-GCM ; `@noble/post-quantum` pour ML-KEM-1024 et `@noble/curves` pour X25519, versions exactes épinglées.

Ruling R-04 : AES-256-GCM avec nonces compteurs pour le canal, et non AES-256-GCM-SIV comme pour les blobs du coffre - GCM est natif dans WebCrypto sur tous les navigateurs, les clés sont éphémères et à sens unique, et le compteur strict exclut toute réutilisation de nonce - coût si faux : changer d'AEAD suppose une version 2 du protocole, négociée par le champ `v`.

Ruling R-05 : ML-KEM et X25519 en JavaScript via les bibliothèques `noble` (pur JS, sans dépendance) plutôt qu'un `core` compilé en WASM - `aws-lc-rs` ne cible pas WASM simplement, et le mode Mac ne fait aucune crypto de coffre dans l'extension - coût si faux : remplacer deux fonctions du client par un module WASM ; les vecteurs de test croisés détectent toute divergence.

### 6.2 KEM hybride du pont

Encapsulation vers une clé publique `pk = (ek_mlkem [1568 octets], pk_x [32 octets])` :

1. `(ct_m, ss_m) = ML-KEM-1024.Encaps(ek_mlkem)`.
2. Paire X25519 éphémère `(e, E)`, `ss_x = X25519(e, pk_x)`.
3. `ct = ct_m || E` (1600 octets).
4. `ss = HKDF-SHA256(salt = "onepass/bridge/kem/v1", ikm = ss_m || ss_x, info = SHA-256(ct || pk_x))`, 32 octets.

Décapsulation : symétrique, un `ct` de longueur incorrecte est refusé. Libellé propre au pont, distinct de `onepass/kem/v1` du `core`, conformément à l'avertissement du code de `crypto::kem` sur les familles de contexte.

### 6.3 Encodage

Champs binaires en base64 standard sans espaces. Chaque message porte `"v": 1` ; toute autre version est refusée par `{"t":"error","code":"version"}`. Le transcript d'un échange est la concaténation, préfixée par la longueur sur 4 octets grand-boutistes, de chaque champ dans l'ordre défini ci-dessous (jamais le JSON lui-même, dont la sérialisation n'est pas canonique).

### 6.4 Appairage (une fois par navigateur)

But : établir une clé d'appairage `PK` de 32 octets partagée par l'extension et l'app, approuvée par l'utilisateur sur les deux écrans.

Rôles : E = extension, H = hôte (l'app).

1. E → H `pair_hello` : `{commit, ext_name, browser}` où E a tiré une paire KEM hybride éphémère `(dk_E, pk_E)` et un nonce `n_E` de 32 octets, et `commit = SHA-256("onepass/bridge/commit/v1" || pk_E || n_E)`.
2. H → E `pair_offer` : `{pairing_id (16 octets), pk_H, n_H}` (paire KEM hybride éphémère de H, nonce de 32 octets).
3. E → H `pair_reveal` : `{pk_E, n_E, ct_E}` où `ct_E = Encaps(pk_H)` donne `ss`. H vérifie `commit`, décapsule `ss`.
4. Les deux calculent `T = H(transcript : ext_name, browser, commit, pairing_id, pk_H, n_H, pk_E, n_E, ct_E)` et
   - `SAS` = 6 chiffres = `(premiers 4 octets de HKDF(ss, T, "onepass/bridge/sas/v1") en entier grand-boutiste) mod 1 000 000`, affiché sous la forme `123 456` ;
   - `PK = HKDF(ss, T, "onepass/bridge/pairing-key/v1")`.
5. L'app affiche : nom et navigateur de l'extension, le code, "Approuver" (avec Touch ID dans l'app réelle). L'extension affiche le même code et "Les codes sont identiques".
6. Quand l'utilisateur approuve dans l'app, H envoie `pair_done` : `{mac_H = HMAC(K_c, "host" || T)}` avec `K_c = HKDF(ss, T, "onepass/bridge/pair-confirm/v1")`. E vérifie `mac_H`, attend la confirmation de l'utilisateur, puis envoie `pair_confirm` : `{mac_E = HMAC(K_c, "ext" || T)}`. H n'enregistre l'appairage qu'à réception d'un `mac_E` valide.
7. Refus, délai de 120 s dépassé ou MAC invalide : les deux côtés effacent l'état, aucun appairage n'est enregistré.

Pourquoi un engagement (`commit`) : sans lui, un intermédiaire pourrait choisir ses valeurs après avoir vu celles de l'autre côté et chercher deux échanges qui donnent le même code. Avec lui, chaque code vu par l'utilisateur est uniforme pour l'attaquant : une chance sur un million par tentative, et chaque tentative demande une action de l'utilisateur.

Ruling R-06 : comparaison d'un code à 6 chiffres sur les deux écrans (avec engagement), au lieu d'un code affiché dans l'app et tapé dans l'extension - un code tapé de faible entropie, utilisé comme clé de MAC, se retrouve par force brute hors ligne par un intermédiaire ; l'éviter demande un PAKE (CPace), non post-quantique et plus complexe ; la comparaison donne la même borne de 10^-6 sans attaque hors ligne, comme l'appairage par QR de la spec parente (4.9, étape 5) - coût si faux : un clic de plus pour l'utilisateur ; passer à un PAKE hybride est une version 2 de l'appairage.

Stockage :

- App (hôte de dev : fichier `pairings.json` en `0600` dans son dossier de données ; app réelle : trousseau) : `pairing_id`, `PK`, nom, navigateur, identifiant d'extension, date de création, dernier usage.
- Extension : `chrome.storage.local` : `pairing_id`, `PK`, date. Rien d'autre de durable n'est secret.
- Révocation : depuis l'app (supprime l'entrée) ou depuis l'extension ("Oublier cet appairage"). Une session avec un `pairing_id` inconnu reçoit `{"t":"error","code":"unknown_pairing"}` et l'extension propose un nouvel appairage.

### 6.5 Ouverture de session (à chaque connexion)

Le service worker MV3 s'arrête après quelques dizaines de secondes d'inactivité, et chaque `connectNative` lance un nouveau processus d'hôte : une session est donc courte et se rouvre souvent. Elle doit être rapide, mutuellement authentifiée, post-quantique et à confidentialité persistante.

1. E → H `hello` : `{pairing_id, pk_e (KEM hybride éphémère), n_e}`.
2. H : appairage connu, sinon `unknown_pairing`. `(ct, ss_e) = Encaps(pk_e)`, nonce `n_h`, `session_id` de 16 octets. `T = H(transcript : pairing_id, pk_e, n_e, ct, n_h, session_id)`. Clés : `HKDF(salt = T, ikm = ss_e || PK)` étendue avec les libellés `"onepass/bridge/session/e2h/v1"`, `"…/h2e/v1"`, `"…/confirm/v1"`. H → E `welcome` : `{ct, n_h, session_id, mac_h = HMAC(K_confirm, "host" || T)}`.
3. E décapsule, dérive les mêmes clés, vérifie `mac_h` (en temps constant), répond `finish` : `{mac_e = HMAC(K_confirm, "ext" || T)}`. H vérifie avant d'accepter le premier message chiffré.

Propriétés : seul un détenteur de `PK` dérive les clés (authentification mutuelle) ; `ss_e` éphémère donne la confidentialité persistante ; ML-KEM protège contre un enregistrement aujourd'hui déchiffré plus tard par un ordinateur quantique, X25519 contre une faiblesse de ML-KEM.

### 6.6 Messages chiffrés et rejeu

- Trame : `{"v":1,"t":"msg","c":<compteur>,"d":"<base64>"}`.
- Données associées : `session_id || sens (1 octet : 0 = E→H, 1 = H→E) || compteur (8 octets grand-boutistes)`.
- Chaque sens a son compteur, qui commence à 0 et augmente de 1. Le récepteur exige exactement le compteur attendu. Un compteur rejoué, sauté ou une trame qui ne s'ouvre pas ferme la session (le transport est ordonné, aucun trou n'est légitime).
- Un compteur qui atteindrait 2^32 ferme aussi la session (marge très large).
- Pas de rejeu entre sessions : chaque session a des clés neuves. Un `hello` rejoué donne un autre `n_h`, donc d'autres clés, et l'attaquant sans `PK` ne peut pas répondre `finish`.
- Session inactive 10 minutes : l'hôte la ferme.

### 6.7 Contenu applicatif

Clair d'une trame : JSON `{"id": <entier>, "op": "...", ...}` pour une requête, `{"id": <même>, "ok": {...}}` ou `{"id": <même>, "err": {"code": "...", "msg": "..."}}` pour une réponse. Un `id` déjà vu dans la session est refusé.

## 7. Ce que l'extension peut demander, ce qu'elle ne reçoit jamais

### 7.1 Principe

L'extension ne reçoit que ce qu'il faut pour l'action en cours, pour une origine précise, après un geste de l'utilisateur. Toute décision de correspondance est **refaite par l'hôte** : l'extension ne fait que transmettre l'origine que le navigateur lui a donnée.

### 7.2 Opérations

Le champ `ctx` de chaque requête dit d'où vient l'action : `popup`, `menu`, `overlay`, `save_prompt`, `chain`. L'hôte s'en sert pour la journalisation et pour les règles marquées ci-dessous.

| Opération | Entrée | Sortie | Règle |
| --- | --- | --- | --- |
| `status` | aucune | `locked`, nom du compte, nombre de vaults | toujours permise |
| `unlock` | aucune | `locked` | l'app demande Touch ID ; l'hôte de dev répond selon sa configuration |
| `list_for_origin` | `origin` | résumés de logins | aucun secret ; voir 7.3 |
| `search` | `query` | résumés (logins, cartes, identités) | `ctx = popup` seulement |
| `list_fillable` | `origin`, `kind` (`card`, `identity`) | résumés | `origin` en HTTPS |
| `fill_login` | `item_id`, `origin`, `fields` (`username`, `password`, `totp`) | valeurs demandées, code TOTP du moment | l'item doit correspondre à `origin` (7.3) |
| `fill_card` | `item_id`, `origin` | titulaire, numéro, expiration, CVV | `origin` en HTTPS |
| `fill_identity` | `item_id`, `origin` | nom, email, téléphone, adresse, date de naissance, société | `origin` en HTTPS |
| `totp` | `item_id`, `origin` | code et secondes restantes | correspondance ou `ctx = popup` |
| `reveal` | `item_id`, `field` | valeur d'un champ mot de passe ou masqué | `ctx = popup` seulement, champ autorisé à l'autofill |
| `check_credentials` | `origin`, `username`, `password` | `new`, `same` ou `update` avec l'item | pour la proposition d'enregistrement |
| `save_login` | `origin`, `title`, `username`, `password`, `vault_id`, `rule`, `tags` | `item_id` | création d'un Login avec l'URL de l'origine |
| `update_password` | `item_id`, `origin`, `password` | rien | l'item doit correspondre ; ancien mot de passe vers l'historique |
| `generate` | `recipe` (aléatoire, mémorisable, PIN, longueur, symboles) | mot de passe, entropie | générateur du `core` |
| `vaults` | aucune | id, nom, couleur | métadonnées |
| `provider_accounts` | `provider`, `origin` | résumés des comptes du fournisseur, et lequel est lié à `origin` | aucun secret |
| `fill_provider` | `account_item_id`, `provider`, `provider_origin`, `site_origin`, `fields` | identifiant, mot de passe, TOTP du compte fournisseur | `provider_origin` doit être un domaine officiel du fournisseur (8.4), le compte doit être un Login de ce fournisseur |
| `link_provider` | `site_origin`, `provider`, `account_item_id` | `item_id` du site | ajoute une méthode `Provider` au Login du site (ou le crée) |

Un résumé contient : `item_id`, `vault_id`, nom du vault, titre, sous-titre (identifiant, 4 derniers chiffres ou nom), type, lettre et couleur d'icône, présence d'un mot de passe, présence d'un TOTP, méthodes de connexion (fournisseur et email du compte lié), qualité de correspondance (`exact_host` ou `domain`).

### 7.3 Correspondance d'origine (hôte)

- Origine de la page : schéma `https` obligatoire. Un `http:` est refusé, sans exception (les tests de bout en bout tournent en HTTPS local).
- Domaine enregistrable (eTLD+1) calculé avec la Public Suffix List (crate `psl` côté Rust, `tldts` côté TypeScript ; vecteurs communs pour détecter une divergence).
- Règle `Domain` : même domaine enregistrable. `ExactHost` : même hôte. `ExactUrl` : même origine et même chemin (requête et fragment ignorés). `Never` : jamais.
- Port : s'il est explicite dans l'URL de l'item, il doit être égal.
- Comparaison sur la forme ASCII (punycode) : un sosie IDN ne correspond jamais à l'original.
- Items exclus : archivés, à la corbeille, `hide_from_autofill`, type Crypto Wallet (jamais d'autofill), champs dont `autofill = false`.
- Items avec `reprompt` : l'app redemande Touch ID ; l'hôte de dev refuse avec `reprompt_required` sauf configuration contraire.

### 7.4 Jamais transmis à l'extension

Mot de passe maître, Secret Key, clés de compte, de vault ou d'item, secret TOTP (seul le code du moment sort), clés privées de passkeys et de clés SSH, phrases de récupération, notes, pièces jointes, historique des mots de passe, items qui ne correspondent pas à l'origine demandée, liste complète du coffre avec secrets.

### 7.5 Limites côté hôte

- 60 requêtes de secrets (`fill_*`, `totp`, `reveal`) par minute et par session ; au-delà, `rate_limited`.
- Chaque réponse contenant un secret est journalisée localement par l'hôte (opération, item, origine, contexte, horodatage), sans la valeur.

## 8. L'extension

### 8.1 Structure et build

```
extension/
  package.json, tsconfig.json, build.mjs (esbuild), vitest.config.ts, playwright.config.ts
  manifests/ base.json + chromium.json, firefox.json, safari.json (fusionnés au build)
  src/bridge/     client du protocole (crypto, framing logique, session, appairage)
  src/background/ service worker : session, politique, chaînes, fournisseurs, enregistrement
  src/content/    détection, icône, ancrage des iframes, remplissage, observation des soumissions
  src/ui/         popup, menu, overlay, save : pages d'extension en TypeScript sans framework
  src/shared/     types des messages internes, domaines, PSL, liste des fournisseurs
  test/           tests unitaires (vitest, jsdom)
  e2e/            serveur HTTPS de test, pages, tests Playwright
```

- Build `esbuild`, une sortie par navigateur dans `extension/dist/<browser>/`.
- Chromium et Safari : `background.service_worker`. Firefox : `background.scripts` (Firefox MV3 n'a pas de service worker d'extension) avec le même code.
- Permissions : `storage`, `nativeMessaging`, `webNavigation`, `scripting`, `activeTab`, `host_permissions: ["https://*/*"]`. Pas de `<all_urls>` en HTTP.
- `web_accessible_resources` : seulement `menu.html`, `overlay.html`, `save.html` et leurs scripts, avec `use_dynamic_url` sur Chromium (empêche une page de détecter l'extension par une URL fixe).
- CSP des pages d'extension : `script-src 'self'; object-src 'none'`.

Ruling R-07 : TypeScript sans framework d'interface, build `esbuild` - quatre petites surfaces, moins de dépendances à auditer dans un gestionnaire de mots de passe, chargement instantané des iframes en page - coût si faux : réécrire les vues en composants si l'interface grossit.

Ruling R-08 : Safari est la cible de conception (APIs `browser.*` via un petit adaptateur, aucun appel propre à Chrome sans repli), mais seuls Chromium (Playwright) et le build Firefox sont exercés dans ce jalon ; l'empaquetage Safari (projet Xcode, `SafariWebExtensionHandler`) arrive avec l'app Mac au jalon 2 - Playwright ne charge d'extensions que dans Chromium, et l'extension Safari doit vivre dans une app - coût si faux : écarts de comportement Safari découverts au jalon 2.

### 8.2 Détection des champs et des formulaires

Classement de chaque champ visible :

1. Attribut `autocomplete` normalisé (`username`, `current-password`, `new-password`, `one-time-code`, `cc-*`, `given-name`, `family-name`, `email`, `tel`, `street-address`, `address-line1`, `postal-code`, `address-level2`, `country`, `bday`, `organization`) : décision directe.
2. Sinon, score pondéré sur : `type`, `name`, `id`, `placeholder`, `aria-label`, texte du `<label>` et texte voisin, `inputmode`, `maxlength`, `pattern`, en anglais et en français (`identifiant`, `mot de passe`, `code`, `numéro de carte`, `date d'expiration`, `cryptogramme`, `code postal`, etc.).
3. Champs OTP découpés : 4 à 8 champs consécutifs de `maxlength = 1` regroupés en un champ logique.

Classement du formulaire (ou du groupe de champs hors `<form>`, regroupés par ancêtre commun) :

- `login` : un mot de passe actuel, avec ou sans identifiant ; ou un identifiant seul avec un bouton "Suivant" (première étape d'une connexion en plusieurs pages).
- `signup` : un ou deux champs nouveau mot de passe et un identifiant ou email, sans mot de passe actuel.
- `change_password` : mot de passe actuel et nouveau (et confirmation).
- `otp` : un champ code à usage unique.
- `card`, `identity`, `address` : au moins deux champs de la famille.

Champs ignorés : invisibles (`display:none`, `visibility:hidden`, opacité < 0,1, taille < 4 px, hors de la fenêtre de plus de 2000 px, `aria-hidden`), désactivés, en lecture seule, de type `hidden`.

Un `MutationObserver` (avec temporisation de 150 ms) relance l'analyse pour les pages qui construisent leurs formulaires après le chargement.

Ruling R-09 : heuristiques à poids réglés à la main, et non un classifieur entraîné - aucun jeu de données réel ne doit être collecté ni copié, et les poids restent lisibles et testables - coût si faux : moins bonne détection sur les formulaires mal balisés ; le module expose une seule fonction de score, remplaçable par un modèle plus tard.

### 8.3 Icône dans le champ et menu en ligne

- Icône : petit élément positionné sur le bord droit du champ, dans une racine fantôme fermée attachée à un hôte placé dans `document.documentElement`, suivi du champ par `ResizeObserver` et défilement. Clic (événement `isTrusted` uniquement) ou focus + flèche bas : ouvre le menu.
- Menu : iframe `menu.html` (origine de l'extension) dans la même racine fantôme, sous le champ. Contenu selon la maquette Inline : en-tête "ONEPASS · <domaine>", comptes du site (lettre, titre, identifiant, indication comme "Utilisé récemment"), puis "Générer un mot de passe" (champ nouveau mot de passe) et "Enregistrer un nouveau login". Sur un formulaire carte ou identité : cartes ou identités du coffre.
- Le script de contenu ne reçoit jamais la liste : il demande au service worker l'ouverture d'un menu pour (onglet, cadre, champ). Le service worker crée un jeton aléatoire de 128 bits lié à (onglet, `frameId`, origine du cadre donnée par `sender`, type de formulaire) et renvoie l'URL `menu.html#<jeton>`. Le menu présente son jeton au service worker pour obtenir ses résumés et pour déclencher un remplissage.
- Anti-clickjacking : le menu ignore les clics pendant 300 ms après son affichage et après tout changement de position ; il se ferme si l'iframe sort de la fenêtre ; sur Chromium, il exige que l'`IntersectionObserver` v2 (`trackVisibility`) déclare l'iframe visible.
- Le menu ne traite aucun `postMessage` de la page.

### 8.4 Remplissage

Chemin unique pour tout remplissage (menu, popup, overlay, chaîne) :

1. Le geste vient d'une page d'extension (menu, popup, overlay) ou d'une étape de chaîne lancée par un tel geste.
2. Le service worker relit l'URL actuelle du cadre cible (`webNavigation.getFrame`) et vérifie : HTTPS ; même origine que celle liée au jeton (sinon : la page a navigué, refus) ; cadre principal, ou cadre du même domaine enregistrable que le cadre principal.
3. Il demande les valeurs à l'hôte (`fill_login`, `fill_card`, `fill_identity`), qui refait la correspondance.
4. Il envoie les valeurs au script de contenu du cadre (`tabs.sendMessage` avec `frameId`), qui les écrit dans les champs classés : setter natif de `value`, puis événements `input` et `change`, comme une saisie. Les valeurs ne sont gardées nulle part ensuite.

Ruling R-10 : aucune exception à la règle "pas de remplissage dans une iframe d'un autre site", même pour les iframes de paiement (Stripe, Adyen) - la règle est simple à vérifier et une liste d'exceptions est une surface d'attaque - coût si faux : les cartes ne se remplissent pas dans les formulaires de paiement en iframe ; une liste d'exceptions signée pourra suivre.

### 8.5 Proposition d'enregistrement

- Le script de contenu observe la soumission : événement `submit`, clic sur un bouton de soumission, touche Entrée dans un champ, ou disparition d'un formulaire de connexion après un clic (applications d'une seule page).
- Il envoie au service worker l'identifiant et le mot de passe saisis. Le service worker les garde en mémoire (jamais dans un stockage), avec l'origine donnée par `sender`, au plus 2 minutes.
- Après la navigation ou 1,5 s sans navigation, il appelle `check_credentials`. `same` : rien. `new` ou `update` : il ouvre `save.html#<jeton>` dans le cadre principal de l'onglet, selon la maquette Save : "Enregistrer le login ?", "Ne jamais proposer pour <domaine>", "Pas maintenant", "Mettre à jour (1)", "Nouvel élément", "Modifier" (titre, identifiant, mot de passe avec "Générer", site web, règle de correspondance, tags, coffre).
- "Ne jamais proposer" : liste de domaines dans `chrome.storage.local` (pas un secret).
- Les formulaires d'inscription et de changement de mot de passe passent par le même chemin (`update` pour un changement).

### 8.6 Overlay "Connexion en un clic" et chaîne d'authentification

L'overlay est l'iframe `overlay.html#<jeton>` en haut à droite du cadre principal, affichée sur une page de connexion reconnue du site d'un item (maquette Inline : "Se connecter à <site>", comptes, "Se connecter", texte "Un clic enchaîne toutes les étapes. Arrêt automatique si le domaine change ou sur un CAPTCHA.", puis la liste des étapes et "Arrêter" / "Recommencer").

Machine à états dans le service worker, une chaîne par onglet :

- État : onglet, item, domaine du site, domaines autorisés (site, plus domaines officiels du fournisseur si la méthode est un fournisseur), étapes faites, échéance (début + 60 s), état (`running`, `done`, `stopped`, `handoff`), raison. Persisté dans `chrome.storage.session` (mémoire seulement) pour survivre au réveil du service worker. Aucun secret dedans.
- À chaque analyse de page envoyée par le script de contenu du cadre principal de l'onglet, le service worker vérifie le domaine (donné par `sender`), puis choisit l'action :
  - champ identifiant seul : remplir, soumettre ;
  - identifiant et mot de passe : remplir les deux, soumettre ;
  - mot de passe seul : remplir, soumettre ;
  - champ code : si l'item a un TOTP, demander le code, remplir, soumettre ; sinon `handoff` (code SMS, email ou application tierce) ;
  - case "Se souvenir de cet appareil" : laissée telle quelle (voir R-12) ;
  - bouton "Continuer avec <fournisseur>" et méthode fournisseur : cliquer ;
  - page de choix de compte du fournisseur : cliquer l'entrée dont l'email est celui du compte lié ;
  - retour sur le site sans formulaire de connexion : `done`.
- Arrêt (`handoff`, message dans l'overlay, l'utilisateur reprend la main) : domaine hors liste, CAPTCHA détecté (iframes ou éléments reCAPTCHA, hCaptcha, Turnstile, texte "je ne suis pas un robot"), validation push ("approuvez sur votre téléphone"), code sans TOTP, page inconnue (aucun champ reconnu 4 s après la fin du chargement), échéance de 60 s, bouton "Arrêter", même étape répétée deux fois (mot de passe refusé).
- Soumission : clic sur le bouton de soumission du formulaire classé, sinon `requestSubmit()`, sinon Entrée. Désactivable par item (préférence locale, voir R-12) ; désactivée, la chaîne remplit puis attend que l'utilisateur soumette.
- Plusieurs comptes pour le site : l'overlay les liste tous (y compris "Se connecter avec Google (perso@…)"), l'utilisateur choisit.
- Démarrage seulement par un clic dans l'overlay, le menu ou la popup.

Ruling R-11 : la chaîne ne fait aucune action sur une page dont le domaine sort de la liste, même pour une redirection intermédiaire attendue (SSO d'entreprise, domaine de CDN d'authentification) - arrêter est sûr, deviner ne l'est pas - coût si faux : `handoff` plus fréquent sur les SSO à domaines multiples ; une liste de domaines associés par item pourra suivre.

Ruling R-12 : "se souvenir de cet appareil" n'est pas touché et la soumission automatique est une préférence par item gardée dans `chrome.storage.local` (activée par défaut) - le modèle d'item du `core` n'a pas encore ces réglages et ce jalon ne modifie pas `onepass-core` - coût si faux : réglages à migrer dans l'item quand le modèle les aura (jalon 2 ou 5).

Ruling R-13 : pas d'apprentissage des étapes inconnues dans ce jalon ; une étape inconnue rend la main - la spec demande un stockage chiffré des sélecteurs appris, qui doit vivre dans le coffre (app, jalon 2) et pas en clair dans le profil du navigateur - coût si faux : sur les sites exotiques l'utilisateur termine à la main, ce qui est déjà le comportement de repli.

### 8.7 Connexion via un fournisseur

- Domaines officiels (hôtes exacts, pas de domaine enregistrable) :
  - Google : `accounts.google.com`
  - Apple : `appleid.apple.com`, `idmsa.apple.com`
  - Microsoft : `login.microsoftonline.com`, `login.live.com`, `account.live.com`
  - GitHub : `github.com`
  - Facebook : `www.facebook.com`, `m.facebook.com`
  - X : `x.com`, `twitter.com`, `api.x.com`
  - LinkedIn : `www.linkedin.com`
  - Discord : `discord.com`
  - Slack : `slack.com`
- Détection : clic sur un bouton "Continuer avec / Se connecter avec / Sign in with / Continue with <fournisseur>" (texte, `aria-label`, lien vers un domaine officiel), puis navigation principale vers un domaine officiel (`webNavigation.onBeforeNavigate`). Le service worker retient (onglet, site d'origine, fournisseur) 5 minutes, en mémoire de session.
- Sur la page de choix de compte du fournisseur : le menu et l'overlay mettent en avant le compte lié au site ("Utilisé pour <site>"), via `provider_accounts`. Le clic de l'utilisateur sur un compte est noté.
- Au retour sur le site d'origine, si aucun lien n'existait : proposition "Enregistrer le lien <site> ↔ <fournisseur> (<email>)" dans la même iframe que l'enregistrement, puis `link_provider`.
- Sur le formulaire de connexion d'un site lié : le menu propose "Se connecter avec <fournisseur> (<email>)", qui lance la chaîne.
- Un domaine qui ressemble à un domaine officiel (`accounts.google.com.evil.test`, `accounts-google.com`) n'est jamais traité comme le fournisseur : comparaison exacte des hôtes.

### 8.8 Popup

Selon la maquette Extension : recherche "Rechercher dans OnePass", "Suggestions pour <domaine>", ligne "Domaine vérifié : <domaine>. Le remplissage ne marche que sur ce site exact.", détail d'un item (identifiant, mot de passe masqué avec révélation, TOTP avec compte à rebours, site web), bouton "Remplir", générateur ("Intelligent", "Aléatoire", "Mémorisable", "Code PIN", longueur, "Historique du générateur"), toasts "Rempli sur <domaine>". États supplémentaires : non appairé (bouton "Appairer avec OnePass", puis code à comparer), verrouillé ("Déverrouiller dans OnePass"), hôte absent ("App OnePass introuvable").

Historique du générateur : `chrome.storage.session` (mémoire), 20 entrées, effacé au verrouillage. Le mot de passe généré et rempli dans un champ "nouveau mot de passe" alimente la proposition d'enregistrement.

### 8.9 Style

Jetons de la maquette : police système (`-apple-system`, `SF Pro Text`), accent `#5856D6`, clair (`--pop #FFFFFF`, `--text #1D1D1F`, `--text2 #5F5F67`, `--field #F2F2F5`) et sombre (`--pop #232325`, `--text #F2F2F4`, `--text2 #A6A6AE`, `--field #333336`), suivant `prefers-color-scheme`. Coins 12 px pour les cartes, 8 px pour les lignes, ombre douce, cibles de 44 px minimum dans la popup, focus visible, navigation au clavier dans le menu (flèches, Entrée, Échap). Aucun élément de marque d'un tiers ; les fournisseurs sont nommés en texte seulement.

## 9. Hôte natif de développement

- Binaire `onepass-native-host`, lancé par le navigateur via un manifeste d'hôte (`me.somalabs.onepass.dev.json`) qui pointe vers un script d'enveloppe (Chrome ne passe pas d'arguments personnalisés).
- Configuration (`--config <fichier>` ou variable `ONEPASS_NATIVE_HOST_CONFIG`) en JSON : dossier de données, identifiants d'extension autorisés, source du coffre, mode d'approbation, déverrouillage.
- Sources du coffre :
  - `dev` : le dossier de la CLI de développement (`~/.onepass-dev`), déverrouillé au démarrage avec le mot de passe de `ONEPASS_PASSWORD` si `ONEPASS_DEV_ALLOW_ENV_PASSWORD=1`, comme la CLI ;
  - `fixture` : un fichier JSON d'items fictifs, chargé dans un vrai `Repository` sur un `MemoryStore` avec des paramètres Argon2 rapides (build debug uniquement, comme `dev-fast-kdf`). Les tests de bout en bout l'utilisent : ils exercent le vrai chiffrement, les vrais manifestes et le vrai modèle.
- Approbation d'appairage : `auto` (tests, build debug uniquement : un build release le refuse, car approuver sans comparer les codes laisse n'importe quel processus local s'appairer ; l'hôte écrit quand même le code dans son journal pour que le test le compare à celui de l'extension) ou `file` (l'hôte écrit `pending-pairing.json` avec le code, et attend que `onepass-native-host approve <code>` crée le fichier d'approbation).
- Bannière `DEV MODE` dans le journal (`stderr` est ignoré par Chrome, l'hôte écrit aussi dans `<data-dir>/native-host.log`, sans aucun secret).
- Script `extension/scripts/install-dev-host.mjs` : écrit le manifeste d'hôte pour Chrome, Chromium et Firefox de l'utilisateur, ou dans un dossier de profil donné (tests).

Ruling R-14 : l'hôte de développement charge le coffre en entier en mémoire au démarrage et sert les items depuis là - c'est un outil de développement et le jeu de test est petit ; l'app réelle interrogera son propre cache - coût si faux : aucun en production.

## 10. Erreurs

Codes d'erreur applicatifs, stables, sans secret dans le message : `version`, `unknown_pairing`, `bad_mac`, `bad_frame`, `locked`, `not_found`, `origin_mismatch`, `insecure_origin`, `cross_site_frame`, `not_allowed` (opération interdite dans ce `ctx`), `reprompt_required`, `rate_limited`, `invalid`, `internal`. L'extension affiche une phrase française pour chacun et n'affiche jamais un message brut de l'hôte.

## 11. Tests

### 11.1 Rust (`onepass-bridge`, `onepass-native-host`)

- Framing : aller-retour, longueur maximale, longueur trop grande, flux tronqué, flux vide.
- KEM hybride : aller-retour, `ct` modifié (un octet), longueurs fausses.
- Appairage : chemin nominal (les deux rôles en Rust), engagement faux, code identique des deux côtés, MAC faux, délai dépassé, refus, `pair_confirm` absent (rien d'enregistré).
- Session : chemin nominal, `PK` faux, `mac_h` ou `mac_e` faux, compteur rejoué, sauté, trame modifiée, `id` de requête rejoué, version inconnue, inactivité.
- Politique : correspondance (Domain, ExactHost, ExactUrl, Never, port, IDN, sous-domaine sosie, `http`), exclusions (archivé, corbeille, caché, wallet, champ non autofill), sortie des résumés sans secret (test qui sérialise chaque résumé et cherche les valeurs secrètes du jeu de données), `fill_login` sur origine non correspondante, `reveal` hors popup, limite de débit, domaines officiels des fournisseurs.
- Vecteurs croisés : le test Rust écrit `core/onepass-bridge/tests/vectors/*.json` (KEM avec aléa fixé, transcript, SAS, clés de session, trames) ; un test vérifie qu'ils sont à jour ; les tests TypeScript les relisent.
- Hôte : test d'intégration qui lance le binaire, fait l'appairage et une session en Rust par stdin/stdout, et demande un remplissage sur le jeu fictif.

### 11.2 TypeScript (vitest)

- Client du protocole contre les vecteurs Rust, puis contre le vrai binaire de l'hôte lancé par Node (appairage, session, requêtes).
- Détection : une page HTML de test par type de formulaire et par piège (invisible, désactivé, OTP découpé, champs hors `<form>`, français et anglais).
- Politique d'origine du service worker : même site, HTTPS, jetons de menu, navigation pendant la requête.
- Machine à états de la chaîne : chaque transition et chaque condition d'arrêt, avec horloge simulée.

### 11.3 Bout en bout (Playwright, Chromium)

Serveur HTTPS local (certificat auto-signé généré au lancement), Chromium lancé avec l'extension, `--host-resolver-rules` qui envoie tous les domaines de test vers le serveur local, et l'hôte natif en mode `fixture`. Aucune requête ne sort de la machine.

Pages de test (marques fictives, aucun élément graphique de tiers) :

- `https://atlas-cloud.test/login` (une page), `/multistep` (identifiant, puis mot de passe, puis TOTP), `/signup`, `/change-password`, `/checkout` (carte), `/profile` (identité et adresse), `/captcha`, `/push`.
- `https://accounts.google.com/…` : page de choix de compte fictive et neutre ("Choisir un compte"), puis identifiant, mot de passe, retour vers `https://atlas-cloud.test/oauth/callback`.
- Pièges : `https://atlas-cloud.test.evil.test/login`, `https://atlass-cloud.test/login`, `https://accounts.google.com.evil.test/…`, `http://atlas-cloud.test/login`, page de `https://evil.test` qui embarque `https://atlas-cloud.test/login` en iframe, page avec formulaire invisible, page qui envoie des clics synthétiques sur l'icône et des `postMessage` au menu.

Parcours vérifiés : appairage (code identique des deux côtés), remplissage par le menu, enregistrement d'un nouveau login puis remplissage, mise à jour au changement de mot de passe, génération dans l'inscription, chaîne en une page, chaîne en plusieurs étapes avec TOTP, chaîne via Google avec choix du bon compte parmi deux, arrêt sur CAPTCHA, arrêt sur changement de domaine, carte, identité.

### 11.4 Liste des tests de sécurité

| # | Attaque | Attendu |
| --- | --- | --- |
| S1 | Script de la page qui lit le DOM du menu ou de l'overlay | impossible (iframe d'une autre origine dans une racine fantôme fermée) ; le test vérifie que la page ne trouve aucune valeur |
| S2 | Page qui envoie un clic synthétique sur l'icône | ignoré (`isTrusted` faux) |
| S3 | Page qui envoie des `postMessage` au menu | ignorés, aucun remplissage |
| S4 | Domaine sosie (`atlass-cloud.test`, `atlas-cloud.test.evil.test`) | aucune suggestion, aucun remplissage |
| S5 | Page `http:` | aucune icône, aucun remplissage, refus `insecure_origin` côté hôte |
| S6 | Formulaire de connexion dans une iframe d'un autre site | aucun remplissage dans l'iframe |
| S7 | Formulaire invisible à côté du vrai | le champ invisible reste vide |
| S8 | Remplissage au chargement | aucun : pas de valeur sans geste |
| S9 | Navigation du cadre entre la demande et le remplissage | refus, aucune valeur envoyée |
| S10 | Chaîne redirigée vers un autre domaine | arrêt, aucune valeur sur le nouveau domaine |
| S11 | Faux domaine de fournisseur (`accounts.google.com.evil.test`) | jamais traité comme Google |
| S12 | CAPTCHA pendant la chaîne | arrêt, main rendue |
| S13 | Client sans appairage, `PK` faux, trame rejouée ou modifiée | session refusée ou fermée (tests Rust et TypeScript) |
| S14 | Script de contenu compromis qui demande un item d'un autre site | refus par le service worker (origine de `sender`) et par l'hôte (`origin_mismatch`) |
| S15 | `reveal` ou `search` depuis un script de contenu | refus `not_allowed` |
| S16 | Résumés envoyés au menu | aucun secret dedans |
| S17 | URL fixe d'une ressource de l'extension | non accessible sur Chromium (`use_dynamic_url`) |

## 12. Livrables

- `core/onepass-bridge`, `core/onepass-native-host`, ajoutés au workspace, `make check` vert.
- `extension/` : build des trois navigateurs, tests unitaires, tests de bout en bout, `README.md` en français (build, appairage avec l'hôte de dev, tests).
- Section "Extension" ajoutée à `docs/security/README.md` : protocole, menace, liste de ce qui ne sort jamais.
- CI : job `extension` (lint, types, tests unitaires, build) et tests de bout en bout dans le workflow existant ou un nouveau, sans modifier les jobs du `core`.

## 13. Hors périmètre, reporté

Ruling R-15 : le mode autonome Windows et Linux (core en WASM, CloudKit JS, WebAuthn PRF) est reporté - il n'est pas bon marché : `aws-lc-rs` ne compile pas simplement en WASM, CloudKit JS demande une connexion Apple ID et un conteneur CloudKit qui viennent du jalon 2, et la spec parente classe déjà ce mode en dernier dans le jalon 4 - coût si faux : les utilisateurs Windows et Linux attendent une version suivante.

Ruling R-16 : passkeys (interception WebAuthn, passkey proposée en premier) reportées au jalon 3 - les clés privées de passkeys et leur création passent par le fournisseur système et le `core`, qui n'a pas encore ces opérations - coût si faux : l'overlay ne propose pas encore la passkey en premier.

Ruling R-17 : la vérification de la signature de code du processus appelant (navigateur) et le relais XPC vers l'app sont au jalon 2 - ils demandent l'app Mac signée - coût si faux : aucun en développement ; l'appairage protège déjà contre un processus local qui n'a pas la clé.

## 14. Liste des rulings

| # | Décision | Pourquoi | Coût si faux |
| --- | --- | --- | --- |
| R-01 | Nouvelles crates `onepass-bridge` et `onepass-native-host`, API de `onepass-core` intactes | sessions parallèles sur `core/`, règle de frontière | conflit trivial sur `members` |
| R-02 | Protocole indépendant du transport, hôte de dev = adaptateur stdio | l'app réelle relaie par XPC, Safari n'a pas de stdio | une couche d'adaptation au jalon 2 |
| R-03 | Même enveloppe JSON pour Safari et stdio | un seul protocole à auditer | aucun |
| R-04 | AES-256-GCM à compteur pour le canal | natif dans WebCrypto, clés éphémères, compteurs stricts | version 2 du protocole |
| R-05 | ML-KEM et X25519 en JS via `noble`, pas de WASM | `aws-lc-rs` hors WASM, pas de crypto de coffre dans l'extension | remplacer deux fonctions |
| R-06 | Comparaison de code à 6 chiffres avec engagement, pas de code tapé | un code tapé demande un PAKE non post-quantique | un clic de plus |
| R-07 | TypeScript sans framework, `esbuild` | moins de dépendances, iframes rapides | réécriture des vues si elles grossissent |
| R-08 | Safari cible de conception, Chromium et Firefox exercés, empaquetage Safari au jalon 2 | Playwright ne charge d'extensions que dans Chromium | écarts Safari découverts au jalon 2 |
| R-09 | Heuristiques pondérées à la main | aucune donnée réelle à collecter | détection moins bonne sur formulaires mal balisés |
| R-10 | Aucune exception aux iframes d'autres sites, même paiement | règle simple, pas de liste à attaquer | cartes non remplies dans Stripe et consorts |
| R-11 | Chaîne arrêtée hors domaines autorisés, sans exception | arrêter est sûr | `handoff` plus fréquent sur les SSO |
| R-12 | "Se souvenir" non touché, soumission auto en préférence locale par item | le modèle d'item n'a pas ces réglages | migration vers l'item plus tard |
| R-13 | Pas d'apprentissage des étapes | le stockage chiffré doit vivre dans le coffre | fin manuelle sur les sites exotiques |
| R-14 | Hôte de dev charge le coffre en mémoire | outil de dev, petit jeu | aucun en production |
| R-15 | Mode autonome Windows et Linux reporté | WASM, CloudKit JS et Apple ID dépendent du jalon 2 | Windows et Linux attendent |
| R-16 | Passkeys reportées au jalon 3 | opérations passkey absentes du `core` | passkey pas proposée en premier |
| R-17 | Signature de l'appelant et relais XPC au jalon 2 | demandent l'app Mac signée | aucun en dev |
| R-18 | Tests de bout en bout en HTTPS local avec résolution DNS forcée, pas d'exception HTTP en mode dev | les garde-fous de production sont testés tels quels, y compris les domaines des fournisseurs | certificat et options Chromium à maintenir dans le harnais |
| R-19 | PSL : crate `psl` en Rust, `tldts` en TypeScript, vecteurs communs | deux implémentations éprouvées, pas de liste maison | divergence sur un cas limite non couvert par les vecteurs |
| R-20 | Jeux de données de test entièrement fictifs (Alex Martin, `atlas-cloud.test`, `alex@atlas.dev`) | règle du fondateur, aucune donnée réelle | aucun |
