# Laboratoire d'autofill OnePass : conception

Date : 2026-10-26. Branche de travail. Statut : approuvée (décisions prises en autonomie à la demande de l'utilisateur, chacune consignée en section 11).

## 1. But

Mettre l'extension OnePass (jalon 4) à l'épreuve sur des sites réalistes générés au hasard, sans action humaine, et mesurer ce qui marche, ce qui casse et ce qui fuit.

Demande de l'utilisateur, reformulée : un environnement qui (1) relève sur des sites publics les manières dont on se connecte et remplit des formulaires (logins, cartes, adresses, identités), (2) en tire des environnements de test aléatoires, (3) y exécute des connexions "en un clic" complètes, TOTP et passkeys compris.

Critères de réussite :

- un rapport de passage complet (taux de réussite par motif, graines des échecs) est commité sous `docs/lab/` ;
- tout échec se rejoue à l'identique à partir de sa graine (`npm run lab:repro -- --seed <graine> --site <n>`) ;
- un sous-ensemble rapide et déterministe tourne dans `npm run check` ;
- aucune donnée personnelle réelle, aucun cookie, aucune soumission vers un site réel ;
- ce que l'extension ne sait pas faire (passkeys notamment) apparaît comme échec attendu, listé en suite à donner.

Hors périmètre : implémenter des fonctions dans l'extension (seuls des crochets minimes pour le laboratoire sont permis), tester l'AutoFill système d'iOS et macOS (une interface `Driver` est prévue pour le brancher plus tard, section 7.4).

## 2. Vue d'ensemble

Tout vit dans `extension/lab/` et réutilise l'outillage du jalon 4 : Playwright 1.59.1, Chromium de Playwright, l'hôte natif de développement réel (`core/onepass-native-host`, source `fixture`), le certificat auto-signé et la résolution de tous les noms vers 127.0.0.1.

```
corpus (scraping, une fois)      générateur (graine)           exécution (Playwright)
sites.json ──> extract ──> samples/*.json ──> distill ──> patterns.json
                                                              │
                              graine ──> world.json (sites, coffre fictif, scénarios)
                                                              │
                         serveur du labo (RP, IdP, pièges, registre des POST)
                                                              │
                         Chromium + extension réelle + hôte natif réel
                                                              │
                                   results.json ──> rapport Markdown
```

Arborescence :

```
extension/lab/
  README.md                 mode d'emploi (français)
  corpus/
    sites.json              liste de pages publiques à relever (catégorie, URL)
    robots.ts               lecture de robots.txt
    sanitize.ts             nettoyage d'un relevé
    extract.ts              CLI : relevé de la structure des formulaires
    distill.ts              CLI : samples -> patterns.json
    samples/<hôte>.json     relevés épinglés (commités)
    patterns.json           motifs distillés (commités)
  gen/
    rng.ts                  PRNG à graine
    model.ts                types : World, Site, Flow, Trait, Scenario, Expectation
    data.ts                 données synthétiques (noms, adresses, cartes de test)
    capabilities.ts         ce que l'extension ne sait pas faire (échecs attendus)
    generate.ts             graine -> World
    render.ts               Site + page -> HTML
  server/
    server.ts               serveur HTTPS/HTTP local du labo
    rp.ts                   partie de confiance : mot de passe, TOTP, WebAuthn
    webauthn.ts             vérification d'assertion ES256
    idp.ts                  fournisseurs d'identité fictifs (Google, Apple, Microsoft)
    ledger.ts               registre des POST et détection de fuites
  run/
    playwright.config.ts    configuration complète et smoke
    global-setup.ts         génère le monde, certificat, hôte, cache du coffre
    lab.spec.ts             un test Playwright par lot de sites
    drive.ts                pilotes de scénarios (un clic, menu, sosie, passkey)
    oracle.ts               verdict d'un scénario
  report.ts                 results.json -> Markdown
  cli.ts                    lab, lab:smoke, lab:repro
extension/test/lab/*.test.ts  tests unitaires (vitest), dans npm run check
```

## 3. Corpus de motifs (scraping)

### 3.1 Ce qui est relevé

Pour chaque page de `sites.json` (environ 60 pages publiques : connexion, inscription, paiement de démonstration, adresse, profil, en plusieurs langues), un Chromium sans extension charge la page et extrait uniquement la structure :

- formulaires et champs : balise, `type`, `name`, `id`, `autocomplete`, `inputmode`, `maxlength`, `pattern` (présence seulement), `required`, libellé associé (`<label>`, `aria-label`, `placeholder`, texte voisin), visibilité calculée (visible, `display:none`, hors écran, opacité nulle, taille nulle) ;
- boutons : texte, `type`, et si le texte nomme un fournisseur ("Continuer avec Google") ;
- iframes : origine de `src` seulement, même site ou non ;
- racines fantômes ouvertes contenant des champs (nombre et rôle des champs) ;
- indices OTP (`autocomplete="one-time-code"`, cases à un chiffre) et WebAuthn (`autocomplete` contenant `webauthn`, appel à `navigator.credentials.get` ou `create` observé par un script d'init passif qui ne fait qu'enregistrer l'appel) ;
- étape visible : identifiant seul, mot de passe seul, les deux, code.

### 3.2 Garde-fous

- Jamais de connexion, jamais de clic ni de soumission, jamais de CAPTCHA touché. Une seule navigation `GET` par page, aucune interaction.
- `robots.txt` respecté (groupe `*` et notre agent `OnePassLabCorpus`, règle `Allow`/`Disallow` la plus longue) ; une page interdite est notée `skipped: robots` et rien n'est chargé.
- Débit : une page à la fois, au moins 5 s entre deux requêtes de pages, une seule page par hôte et par passage, délai maximal de 30 s par page.
- Contexte Playwright neuf par page, jamais sauvegardé ; aucun cookie ni stockage n'est lu ni écrit sur disque.
- Nettoyage (`sanitize.ts`) avant écriture : valeurs (`value`) jamais lues, chaînes coupées à 60 caractères, toute chaîne contenant une adresse électronique, une suite de 4 chiffres ou plus, ou un jeton de plus de 24 caractères alphanumériques est remplacée par `"<redacted>"`. Attributs `name`/`id` : jetons d'au plus 40 caractères, sinon `"<long>"`.
- Chaque relevé porte `source_url`, `captured_at` (ISO 8601), `status` (`ok`, `skipped: robots`, `error: <motif>`), la version de l'extracteur.

### 3.3 Distillation

`distill.ts` lit tous les relevés `ok` et produit `patterns.json`, trié et stable (même entrée, même sortie, octet pour octet) :

- par rôle de champ (`username`, `email`, `password`, `new_password`, `otp`, `cc_*`, `given_name`, `family_name`, `address_*`, `postal_code`, `city`, `country`, `tel`, `birth_date`) : libellés et textes indicatifs par langue, jetons de `name`/`id`, part des champs qui portent un `autocomplete` correct ;
- textes de boutons par action (connexion, suivant, payer, enregistrer) et par langue ;
- fréquences de structure : identifiant d'abord, boutons fournisseurs (lesquels), iframes, racines fantômes, OTP en cases, indices WebAuthn.

Le rôle d'un champ relevé est déduit par une table de règles simple (autocomplete d'abord, puis type, puis mots du libellé). La langue est celle de `<html lang>`, à défaut `und`.

Le générateur ne lit que `patterns.json`, jamais les relevés bruts.

## 4. Générateur de mondes

### 4.1 Graine et PRNG

`rng.ts` : `sfc32` alimenté par un hachage `cyrb128` de la graine (chaîne). Sous-générateurs dérivés par nom (`rng.fork("site:12")`), de sorte qu'ajouter un trait à un site ne décale pas les autres. Aucune autre source d'aléa dans le générateur (`Math.random`, horloge) : un test unitaire vérifie que deux générations de la même graine donnent un `world.json` identique, et épingle le condensé SHA-256 de la graine `lab-smoke-1`.

### 4.2 Monde

`generate(seed, { sites: N, patterns })` rend un `World` :

- `sites[]` : `index`, `seed` (graine du site), `host` (`<mot>-<mot>-<n>.test`), `brand`, `lang` (pondérée par le corpus, avec fr et en majoritaires), `mixLang` (libellés d'une autre langue), un `flow` principal et des `traits` ;
- `fixture` : le fichier de coffre fictif au format de `core/onepass-native-host/fixtures` (comptes, cartes, identités, comptes fournisseurs, liens `login_methods`) ;
- `idp` : pour chaque fournisseur fictif (Google, Apple, Microsoft), 2 à 3 comptes ;
- `scenarios[]` : un ou plusieurs par site, chacun avec son `expect`.

### 4.3 Flux (`flow`)

| Flux | Pages | Ce que le scénario attend |
| --- | --- | --- |
| `login_single` | identifiant et mot de passe sur une page | connexion en un clic réussie |
| `login_username_first` | identifiant, puis mot de passe (deux pages) | idem |
| `login_email_then_password` | courriel, puis mot de passe sur la même page révélé en JS | idem |
| `login_totp` | une des trois précédentes, puis code TOTP (champ unique ou 6 cases) | idem, code accepté par la RP |
| `login_passkey` | mot de passe puis passkey, ou passkey seule ("Se connecter avec une clé d'accès") | assertion WebAuthn vérifiée par la RP |
| `sso` | bouton "Continuer avec Google/Apple/Microsoft", sélecteur de compte de l'IdP fictif (2 ou 3 comptes), retour | bon compte choisi, rappel accepté |
| `signup` | inscription avec mot de passe nouveau et confirmation | mot de passe généré dans les deux champs, compte créé |
| `checkout_card` | titulaire, numéro, expiration (un champ ou deux listes), CVC | valeurs correctes dans les bons champs, envoi accepté |
| `address` | adresse de livraison | idem |
| `identity` | profil (prénom, nom, courriel, téléphone, date de naissance, société) | idem |

### 4.4 Traits (variations synthétiques)

Chaque site tire 0 à 3 traits, pondérés, compatibles avec son flux :

- structure : `iframe_same_origin`, `iframe_cross_site` (le formulaire vit dans un cadre d'un autre domaine enregistrable), `shadow_open`, `shadow_closed`, `spa_rerender` (le formulaire est remplacé par un nœud neuf après le premier `input`), `delayed_fields` (champs insérés 0,5 à 6 s après le chargement), `no_autocomplete` (aucun attribut `autocomplete`), `obfuscated_names` (`name`/`id` aléatoires), `split_otp` ;
- pièges : `honeypot` (champ "courriel" ou "mot de passe" invisible : `display:none`, hors écran, opacité nulle, 1 px, `aria-hidden`), `decoy_form` (second formulaire de connexion invisible), `lookalike` (une copie du site sous un domaine sosie : suffixe `<hôte>.evil.test`, faute de frappe, tiret, homoglyphe IDN en punycode) ;
- langue : `mixed_language` (libellés tirés d'une seconde langue du corpus).

### 4.5 Attentes (`expect`)

`capabilities.ts` décrit ce que l'extension ne sait pas faire, avec la référence documentaire :

| Capacité absente | Source | Effet |
| --- | --- | --- |
| passkeys | R-16 (spec du jalon 4) | `login_passkey` : `xfail` |
| champs dans les racines fantômes de la page | `extension/src/content/index.ts` (limite documentée) | `shadow_open`, `shadow_closed` : `xfail` |
| remplissage dans un cadre d'un autre site | R-10 | `iframe_cross_site` : attente "rien rempli" (réussite si rien n'est rempli) |
| apprentissage d'étapes inconnues | R-13 | aucune (les étapes générées sont toutes reconnaissables) |

Toute autre combinaison attend `pass`. Le rapport sépare réussite, échec, échec attendu (`xfail`), réussite inattendue (`xpass`, signe qu'une capacité est arrivée) et fuite.

## 5. Serveur du laboratoire

Un seul port local, HTTPS et HTTP (même technique que `extension/e2e/server.ts`), routé par l'en-tête `Host`, état en mémoire, remis à zéro par scénario.

### 5.1 Partie de confiance (`rp.ts`)

- Mot de passe : comparaison exacte avec le compte fictif du site.
- TOTP : RFC 6238, SHA-1, 30 s, 6 chiffres, fenêtre de plus ou moins une période.
- WebAuthn : défi aléatoire de 32 octets par session, `rpId` = hôte du site, vérification d'une assertion ES256 (`clientDataJSON` : type `webauthn.get`, défi, origine `https://<hôte>` ; `authenticatorData` : condensé du `rpId`, drapeau de présence ; signature sur `authenticatorData || SHA-256(clientDataJSON)` avec la clé publique enregistrée, compteur croissant). Implémentation avec `node:crypto` seulement.
- Champs pièges : tout envoi dont un champ piège n'est pas vide est refusé et noté.

### 5.2 Fournisseurs fictifs (`idp.ts`)

Servis sous leurs vrais noms d'hôte (`accounts.google.com`, `appleid.apple.com`, `login.microsoftonline.com`), qui résolvent tous vers 127.0.0.1 dans le navigateur de test, avec une présentation neutre (aucun logo ni charte des vrais fournisseurs). Sélecteur de compte avec 2 ou 3 comptes, puis identifiant et mot de passe (Microsoft : courriel puis mot de passe sur deux pages), puis redirection vers le site avec un code à usage unique que la RP échange.

### 5.3 Registre et oracle de fuite (`ledger.ts`)

Chaque POST reçu est noté (hôte, chemin, nom de champ, valeur). Un secret fictif (mot de passe, code TOTP, numéro de carte, CVC) est une **fuite** s'il arrive à un hôte autre que son propriétaire (sosie, autre site, piège), ou dans un champ piège. Le registre de chaque scénario va dans `results.json` sans les valeurs (seulement noms de champs, hôtes et verdicts).

## 6. Hôtes et réseau

Tous les noms générés finissent en `.test` ou sont les trois hôtes fournisseurs. Le navigateur résout tout vers le serveur local (`--host-resolver-rules`), `context.route` coupe toute requête vers un hôte qui n'est pas dans la liste du monde, et chaque réponse doit venir de 127.0.0.1 (mêmes trois filets que `extension/e2e/fixtures.ts`). Le certificat de chaque passage couvre tous les hôtes du monde (crochet minimal : `generateCert(dir, hosts)`).

## 7. Exécution

### 7.1 Préparation (`global-setup.ts`)

Construit `dist/chromium` et l'hôte natif comme l'e2e, génère le monde (graine, nombre de sites), écrit `world.json` et le coffre fictif, prépare l'hôte avec ce coffre (crochet minimal : `stageHost(dir, fixture)`), construit le cache chiffré une fois, génère le certificat.

### 7.2 Lots

Les sites sont découpés en lots de 10. Chaque lot : un profil Chromium neuf, l'extension réelle, un appairage (une fois), puis les scénarios du lot l'un après l'autre, chacun dans un onglet neuf. Les workers Playwright exécutent des lots en parallèle (4 par défaut).

### 7.3 Pilotes de scénario (`drive.ts`)

- `one_click` : ouvre la page de connexion, attend l'overlay "Connexion en un clic", clique "Se connecter" sur le bon compte (titre de l'item, ou "<site> via <fournisseur>"), attend la fin de chaîne (`done` ou `handoff` avec sa raison, 60 s au plus).
- `menu_fill` : focalise le premier champ visible du formulaire, flèche bas (événement de confiance), choisit l'item dans le menu, puis clique le bouton d'envoi comme un utilisateur.
- `lookalike` : ouvre la copie sosie ; vérifie qu'aucun overlay ni menu ne propose l'item du vrai site, puis envoie le formulaire tel qu'il est.
- `passkey_control` : contrôle du laboratoire lui-même, sans l'extension. Authentificateur virtuel de Chromium (CDP `WebAuthn.addVirtualAuthenticator` puis `addCredential` avec la clé du site) : la RP doit accepter l'assertion. Prouve que l'échec `login_passkey` vient de l'extension et pas du banc.

### 7.4 Interface `Driver`

Les pilotes passent par une interface `Driver` (`openOneClick`, `menuFill`, `pickAccount`). L'implémentation `extension` est la seule de cette version ; une implémentation `system_autofill` (macOS, iOS) est une suite à donner.

### 7.5 Oracle et relance

`oracle.ts` donne un verdict par scénario à partir du registre, de l'état de la chaîne et du DOM : `pass`, `fail` (avec cause : `no_overlay`, `no_menu_item`, `wrong_fill`, `handoff:<raison>`, `rp_refused`, `timeout`), `leak` (toujours bloquant), `xfail`, `xpass`. Un scénario en échec est rejoué une fois dans un profil neuf ; s'il réussit, il est noté `flaky`. Les erreurs du banc (hôte qui ne démarre pas, `rate_limited`) sont classées `lab_error`, hors taux.

## 8. Rapport

`results.json` (une ligne par scénario : graine du monde, index du site, graine du site, flux, traits, verdict, cause, durée, commande de rejeu) et `report.ts` qui produit le Markdown :

- résumé : nombre de sites et de scénarios, taux de réussite global (hors `xfail` et `lab_error`), fuites ;
- taux par flux, par trait, par langue ;
- liste des échecs avec graine et commande de rejeu ;
- échecs attendus et capacités manquantes, en suites à donner.

Le premier passage complet (graine `lab-2026-10-26`, 200 sites) est commité dans `docs/lab/2026-10-26-autofill-lab-run.md`.

## 9. Commandes

| Commande | Effet |
| --- | --- |
| `npm run check` | inclut les tests unitaires du labo (`test/lab/`) : PRNG, déterminisme du générateur, rendu, robots, nettoyage, TOTP, WebAuthn, oracle, rapport |
| `npm run lab:smoke` | navigateur, graine fixe `lab-smoke-18`, 12 sites couvrant chaque flux et les pièges structurels, 4 à 6 minutes |
| `npm run lab -- --seed <s> --sites <n>` | passage aléatoire complet, rapport dans `lab/out/` |
| `npm run lab:repro -- --seed <s> --site <i>` | rejoue un site d'un monde |
| `npm run lab:corpus` | relevé du corpus (réseau réel, lent, rarement) puis distillation |

## 10. Tests du laboratoire

Tests unitaires (vitest, sans navigateur, dans `npm run check`) : `rng` (graine, fork), générateur (déterminisme, condensé épinglé, contraintes : hôtes uniques, flux compatibles avec les traits, coffre valide pour l'hôte), `render` (chaque flux et trait donne le DOM attendu sous jsdom), `robots`, `sanitize` (aucune adresse, aucun nombre long ne survit), `rp` (TOTP de la RFC 6238 annexe B, WebAuthn avec une clé générée et une assertion construite, rejet d'une mauvaise origine, d'un mauvais défi, d'une signature altérée), `ledger` (fuite vers un sosie, champ piège), `oracle`, `report`.

## 11. Rulings

Ruling: le laboratoire vit dans `extension/lab/` et partage `package.json`, Playwright et le harnais e2e - même version de Playwright, même hôte natif, même certificat, pas de second `node_modules` - coût si faux : déplacer un dossier et ses imports.
Ruling: crochets minimes dans le harnais e2e (`generateCert(dir, hosts)`, `stageHost(dir, fixture)`), aucun changement dans `extension/src` - la consigne interdit d'implémenter des fonctions dans l'extension - coût si faux : aucun, paramètres optionnels.
Ruling: corpus commité sous forme d'extracteur, de relevés épinglés nettoyés et de `patterns.json` distillé ; le générateur ne lit que `patterns.json` - interface stable et petite, relevés auditables - coût si faux : un détail utile perdu à la distillation, à rajouter dans `patterns.json`.
Ruling: relevé passif (un `GET`, aucune interaction), donc seule la première étape d'un formulaire en plusieurs étapes est relevée ; les étapes suivantes viennent du catalogue synthétique - aller plus loin demanderait de soumettre des formulaires réels, interdit - coût si faux : motifs d'étapes tardives moins fidèles.
Ruling: `robots.txt` respecté pour le groupe `*` et `OnePassLabCorpus`, une page interdite est sautée et notée - consigne explicite - coût si faux : corpus plus petit (les pages de connexion sont souvent interdites).
Ruling: tous les hôtes générés en `.test`, plus les trois noms réels des fournisseurs servis en local - `.test` est réservé (RFC 6761) et ne sort jamais ; les vrais noms des fournisseurs sont nécessaires car l'extension reconnaît les fournisseurs par hôte exact - coût si faux : aucun, trois filets réseau empêchent toute sortie.
Ruling: un coffre fictif généré par monde, chargé par l'hôte natif réel en mode `fixture` - teste la vraie politique de correspondance d'origine de l'hôte - coût si faux : environ 10 s de préparation par passage.
Ruling: lots de 10 sites par profil Chromium, un appairage par lot - amortit l'appairage et reste sous la limite de 60 requêtes par minute et par session de l'hôte - coût si faux : un état partagé entre sites d'un lot masque ou crée un échec (atténué : hôtes uniques, onglet neuf par scénario, relance en profil neuf).
Ruling: les passkeys sont un échec attendu (R-16), avec un contrôle par l'authentificateur virtuel de Chromium qui prouve que la RP du labo vérifie correctement - l'extension n'a pas de passkeys, la consigne demande un échec attendu et une suite - coût si faux : aucun, le passage `xpass` signalera l'arrivée de la capacité.
Ruling: les racines fantômes de la page sont un échec attendu - limite documentée dans `extension/src/content/index.ts` - coût si faux : un `xpass` le signale.
Ruling: une iframe d'un autre site attend "rien rempli" et compte comme réussite si rien n'est rempli - R-10 en fait une règle de sécurité, pas un manque - coût si faux : aucun.
Ruling: toute fuite (secret vers un autre hôte ou dans un champ piège) est un verdict à part, jamais compté comme simple échec, et rend le passage rouge - c'est la propriété de sécurité qui compte le plus - coût si faux : aucun.
Ruling: un échec est rejoué une fois en profil neuf ; une réussite au second essai est `flaky`, comptée à part - la chaîne dépend de délais réels (4 s, 60 s) - coût si faux : un vrai défaut intermittent apparaît en `flaky` plutôt qu'en `fail`, mais reste listé.
Ruling: `npm run check` reçoit seulement les tests unitaires du labo ; le smoke navigateur est `npm run lab:smoke` - `check` ne demande aujourd'hui ni `cargo` ni Chromium, les y ajouter casserait cet usage - coût si faux : le smoke navigateur doit être lancé à part.
Ruling: PRNG `sfc32` + `cyrb128`, sous-générateurs par nom - rapide, sans dépendance, reproductible entre machines - coût si faux : changer d'algorithme change toutes les graines (version du générateur notée dans `world.json`).
Ruling: le rapport ne contient aucune valeur secrète, même fictive (noms de champs, hôtes, verdicts seulement) - règle d'hygiène du dépôt public - coût si faux : un débogage demande de rejouer la graine.
