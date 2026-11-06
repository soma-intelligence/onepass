# Banc de rejeu de sites réels : conception

Date : 2026-11-06. Statut : conception écrite et tranchée sans question (consigne de l'utilisateur « Oui, enchaîne », règles de `.superpowers/sdd/2026-11-06-replay-bench/common.md`). Le code attend la fin du chantier « forms coverage » ; cette spec et son plan sont les seuls livrables du jour. S'appuie sur `2026-10-26-autofill-lab-design.md` (laboratoire), `2026-10-27-autofill-dataset-model-design.md` (dataset), `2026-11-02-real-site-bench-and-retrain-design.md` (banc Rust à sonde), `2026-11-02-one-click-signup-design.md` (inscription en un clic) et `2026-11-06-forms-coverage-design.md` (formulaires d'identité, de voyage, de société et de permis), sans changer leurs règles de sécurité.

## 1. But

Un banc sans IA dans la boucle. L'utilisateur colle une adresse, une liste d'adresses, ou demande le top Tranco ; le banc enregistre les vraies pages une fois (réseau réel, prudent), puis les rejoue hors ligne sur le Mac autant de fois qu'il faut, avec la vraie extension OnePass chargée et le vrai hôte natif, et écrit un rapport. Sur chaque page rejouée, il mesure :

- la connexion en un clic avec un identifiant stocké (fictif) ;
- la clé d'accès (observée seulement, section 6.5) ;
- l'inscription avec un mot de passe généré, jamais affiché, champ de confirmation rempli, règles du site respectées ;
- le remplissage d'identité, de passeport, de société, de permis et de fidélité ;
- les champs qui doivent rester vides (recherche, lettre d'information, pièges).

Les pages rejouées nourrissent aussi le jeu de données du classifieur (`lab:dataset`). Le banc relève enfin les manques du générateur de mot de passe (profil lisible, lecture des consignes écrites en 7 langues, règles de longueur) et la spec fixe leurs corrections (section 10).

Ce banc complète le banc Rust `core/onepass-bench` (2026-11-02), il ne le remplace pas (décision R1) : le banc Rust injecte une sonde dans des pages élaguées commitées et sert de garde de régression en CI ; le banc de rejeu fait tourner l'extension complète sur des pages entières, scripts compris, gardées sur le Mac seulement.

## 2. Ce qui existe déjà

- `lab/corpus/crawl-top.ts` : relevé du top 1000 (Tranco, `corpus/tranco.json`), page d'accueil, plan du site, pages de formulaire choisies par `discover.ts`, au plus 6 pages par site (`SiteBudget`), un `GET` par page, `robots.txt` (`robots-net.ts`, groupes `*` et `OnePassLabCorpus`), au moins 5 s entre deux requêtes d'un hôte (`HostPacer`), WebSockets fermés, fenêtres surgissantes fermées, téléchargements annulés (`guardContext`). Il ne garde que la structure (`Sample`), pas la page.
- `lab/run/` : Chromium avec l'extension non empaquetée et l'hôte natif, filets réseau (`guard` : tout hôte hors du monde est bloqué et montré au registre de fuites ; `--host-resolver-rules=MAP * 127.0.0.1`), pilotes `Driver` (overlay, menu du champ, `smart_fill`, passkey), oracle (`oracle.ts` : fuite, `wrong_item`, `auto_submit_outside_login`, `other_person_filled`, puis but atteint).
- `lab/server/` : serveur HTTPS local, partie utilisatrice fictive (`rp.ts`), registre de fuites (`ledger.ts`, secrets indexés par hôte propriétaire, types `password`, `totp`, `card`, `csc`, `document`).
- `lab/dataset/` : lignes `DatasetRow` (traits du champ, rôle vrai, découpage par origine), jeu `real_test` étiqueté à la main (`real-test-hosts.json`).
- `src/dev/recorder.ts` et `corpus/import-recorded.ts` : enregistreur de parcours de l'utilisateur (structure seulement), relevés dans `corpus/private/` (ignoré par git).
- Générateur : `src/background/generate.ts` lit le profil du popup (`strong`, `readable`, `custom` avec longueur et symboles) et le contexte de la page (`src/content/password-context.ts` : `passwordrules`, plus grand `minlength`, plus petit `maxlength`, `pattern` testé dans l'onglet, consignes écrites par `aria-describedby` et les trois éléments suivants), puis l'hôte Rust (`core/onepass-core/src/site_password/`) résout les sources par confiance (`passwordrules` > attributs > règles connues > consignes) et génère.

## 3. Parcours de l'utilisateur

Une commande par mode, lancées depuis `extension/` :

| Commande | Effet |
| --- | --- |
| `npm run lab:site -- <url> [--refresh] [--workers n]` | enregistre la page si elle ne l'est pas (ou si `--refresh`, ou si l'enregistrement a plus de 30 jours, signalé), puis la rejoue et ouvre le rapport. But : moins de 2 minutes de bout en bout. |
| `npm run lab:sites -- <fichier> [--refresh] [--workers n]` | même chose pour une liste : une adresse par ligne, lignes vides et `#` ignorés. Les listes de l'utilisateur vivent où il veut ; `lab/replay/lists/` en garde quelques-unes commitées (adresses seulement). |
| `npm run lab:top -- --limit <n> [--from <rang>] [--record-only \| --replay-only]` | les `n` premiers hôtes du Tranco commité : découverte des pages de formulaire (`discover.ts`), enregistrement reprenable (marqueur `done` par hôte), puis rejeu de tout ce qui est enregistré. |
| `npm run lab:record-flow -- <url> [--owner-submit]` | ouvre un Chromium visible sans l'extension ; l'utilisateur fait lui-même le parcours (recherche de vol, second écran de connexion) et marque chaque étape (section 5.4). |
| `npm run lab:replay-report -- [--run <id>] [--baseline <id>]` | refait le rapport HTML et JSON d'un passage (le dernier par défaut) et sa tendance face au passage de référence (le précédent par défaut). |
| `npm run lab:replay-forget -- <hôte>` | efface tout ce qui est enregistré pour un hôte (pages, parcours, résultats). |

Chaque commande de rejeu finit par une ligne de résumé (sites, scénarios jugés, taux, fuites, durée, pages par heure) et le chemin du rapport HTML. Code de sortie 1 si le passage est rouge (une fuite attribuée à OnePass, un `wrong_item`, un envoi automatique hors connexion), comme le laboratoire.

## 4. Enregistrement

### 4.1 Format

Décision R2 : un enregistrement est une archive HAR de Playwright (`recordHar`, `content: "attach"`, fichier `.har.zip`), une par page, plus un `meta.json`. Le HAR est le format que `routeFromHAR` sait rejouer, il se lit avec n'importe quel outil, et la page est rejouée avec ses scripts, ce que les copies élaguées du banc Rust ne permettent pas.

Disposition, sous `extension/lab/recordings/` (ignoré par git) :

```
lab/recordings/<hôte>/
  site.json                 hôte, domaine enregistrable, rang Tranco, verdict robots, date, état (ok, skipped: robots, abandoned, blocked_captcha, error: ...)
  <page>/page.har.zip       requêtes et réponses de la page
  <page>/meta.json          adresse (origine et chemin), date d'enregistrement, version de Chromium, tailles, nombre de réponses écartées, empreinte sha256 du HAR, catégorie devinée
lab/corpus/private/replay/<hôte>/<parcours>/   parcours enregistrés à la main (section 5.4), même format plus steps.json
```

`<page>` est un condensé court de l'adresse (origine et chemin, sans requête ni fragment), stable d'un enregistrement à l'autre : réenregistrer remplace, et la tendance sait comparer la même page.

### 4.2 Garde-fous du relevé

Ceux de `crawl-top.ts`, repris tels quels (même code, `guardContext`, `HostPacer`, `SiteBudget`, `robots-net.ts`) :

- seul `GET` sort du navigateur ; toute autre méthode, `sendBeacon` compris, est refusée avant de partir ;
- `robots.txt` respecté pour `*` et `OnePassLabCorpus` ; une page interdite est sautée et notée ;
- au moins 5 s entre deux requêtes de page d'un même hôte, au plus 4 hôtes en parallèle ;
- aucun clic, aucune frappe, aucun envoi ; les fenêtres surgissantes sont fermées, les téléchargements annulés, les WebSockets fermés ;
- une page qui montre un CAPTCHA ou un mur anti-robot (cadre reCAPTCHA, hCaptcha, Turnstile, page de défi connue, statut 403 ou 429 avec ces marques) est notée `blocked_captcha`, jamais contournée, et son enregistrement est gardé tel quel (il dit ce que voit un visiteur).

Après le chargement, l'enregistreur attend le calme du réseau (au plus 10 s), puis 2 s, puis ferme le contexte pour clore le HAR.

### 4.3 Tailles

Décision R3 :

- images, médias et polices sont refusés pendant le relevé (`resourceType` `image`, `media`, `font`) : ils pèsent lourd et ne changent ni la détection ni le remplissage ; au rejeu, une image est une PNG transparente de 1 pixel, une police ou un média une réponse vide ;
- une réponse de plus de 2 Mo est écartée du HAR (comptée dans `meta.json`) ;
- une page de plus de 25 Mo, ou un site de plus de 100 Mo, s'arrête là (état `abandoned: size`) ;
- au plus 6 pages par site (budget existant) ;
- au-delà de 20 Go dans `lab/recordings/`, chaque commande avertit et propose `lab:replay-forget`.

Ordre de grandeur attendu : 1 à 5 Mo par page compressée, donc 5 à 15 Go pour le top 1000.

### 4.4 Masquage

Décision R4, appliquée en écrivant le HAR (`har.ts`) :

- en-têtes retirés : `cookie`, `set-cookie`, `authorization`, `proxy-authorization`, et tout en-tête dont le nom contient `token`, `csrf`, `xsrf`, `session` ou `auth` ;
- valeurs de paramètres de requête dont le nom ressemble à un jeton (`token`, `session`, `sid`, `state`, `nonce`, `code`, `auth`, `key`, `sig`, `csrf`, `ticket`, insensible à la casse, en sous-chaîne) remplacées par `REDACTED`, dans l'adresse de l'entrée ; l'appariement du rejeu ignore ces valeurs (section 5.2) ;
- corps de requête jamais gardés (le relevé n'en envoie aucun ; les parcours enregistrés à la main en ont, section 5.4) ;
- stockage local du navigateur jamais copié (profil neuf par page, détruit après).

Les corps de réponse HTML ne sont pas réécrits : un jeton CSRF caché dans une page servie à un visiteur anonyme ne dit rien de personne, et réécrire le HTML casserait les scripts. Les parcours enregistrés à la main ajoutent le masquage des valeurs tapées (section 5.4).

### 4.5 Ce qui est commité, ce qui ne l'est pas

Décision R5 : rien d'un site réel n'entre dans le dépôt (il a un miroir public).

| Commité | Ignoré par git |
| --- | --- |
| code `lab/replay/**`, tests | `lab/recordings/**` (HAR, méta) |
| listes d'adresses `lab/replay/lists/*.txt` | `lab/corpus/private/replay/**` (parcours de l'utilisateur) |
| vérités écrites à la main `lab/replay/truth/<hôte>.json` (sélecteurs, rôles, règles de mot de passe, hôtes d'envoi admis ; aucun texte de la page) | `lab/out/replay/**` (résultats, rapports) |
| HAR fictifs des tests, construits depuis les pages `.test` du laboratoire (`test/lab/replay/fixtures/`) | captures d'écran éventuelles |

`.gitignore` gagne `extension/lab/recordings/` (et `extension/lab/out/` y est déjà, comme `extension/lab/corpus/private/`).

## 5. Rejeu hors ligne

### 5.1 Navigateur

Le Chromium du laboratoire (`lab/run/browser.ts`) : contexte persistant avec l'extension construite, hôte natif réel avec un coffre fictif propre au passage, `--host-resolver-rules=MAP * 127.0.0.1:<port du serveur du labo>` (filet de dernier recours : une requête qui échapperait au routage arrive au serveur local, qui répond 421 et la note comme violation), `serviceWorkers: "block"`, WebSockets fermés, sonde réseau existante (`canary`) qui échoue le passage si une réponse vient d'une adresse non locale. Aucun réseau externe pendant le rejeu, vérifié à chaque passage.

### 5.2 Routage

Décision R6, trois couches (Playwright essaie la dernière route posée d'abord) :

1. **Envois** (posée en dernier, donc essayée en premier) : toute requête autre que `GET` et `HEAD` (formulaire, `fetch`, `XMLHttpRequest`, `sendBeacon`) va à la partie utilisatrice fictive locale : ses champs (corps formulaire, JSON, multipart, et les paramètres de l'adresse) passent au registre de fuites (`ledger.record(hôte, chemin, champs)`) et deviennent un événement `submit`. La réponse est celle du parcours enregistré quand il y en a une pour la même méthode et la même adresse (section 5.4), sinon une réponse neutre : `200` avec `{}` pour une requête de script, une page HTML « envoi reçu par le banc » pour une navigation. Rien ne part jamais vers le vrai site. Les `GET` passent à la couche suivante.
2. **Exact** : `routeFromHAR(har, { notFound: "fallback" })` sur l'archive de la page ; méthode et adresse identiques.
3. **Approché** (posée en premier) : même méthode, même origine et même chemin, mêmes noms de paramètres, valeurs des paramètres de jeton et des paramètres changeants (horodatages, `_`, `cb`, `v`, `rnd`) ignorées ; à défaut même origine et même chemin. Sans correspondance : une image ou une police reçoit son substitut (section 4.3), toute autre ressource un `404` vide, et la requête est comptée `unmatched` (par type et par hôte).

Une page dont le document principal ne s'apparie pas est `replay_miss` (pas de scénario). Une page dont un script du même domaine enregistrable n'est pas apparié est rejouée mais marquée `degraded` dans le rapport : ses échecs sont listés à part, et la tendance ne les compte pas comme régressions.

### 5.3 Déterminisme

Décision R7 :

- horloge de la page posée à la date d'enregistrement par `page.clock.install({ time })`, puis elle avance normalement (les délais des pages restent réels) ;
- `Math.random`, `crypto.getRandomValues` et `crypto.randomUUID` du monde principal de la page tirés d'un `sfc32` semé par `cyrb128(empreinte du HAR + scénario)` (script d'initialisation ; le monde isolé des content scripts et le service worker de l'extension gardent le vrai hasard, nécessaire au générateur et à WebAuthn) ;
- chaque scénario part d'une page neuve sur la même archive, dans un profil de navigateur réutilisé par travailleur mais vidé (stockage du site effacé entre scénarios), et ne partage pas sa mémoire de site avec un autre ensemble de pilotes (règle du laboratoire) ;
- un échec est rejoué une fois dans un profil neuf ; réussi alors, il est `flaky`, compté réussi et listé.

La porte de stabilité (section 12) rejoue deux fois le même jeu et exige les mêmes verdicts.

### 5.4 Parcours enregistrés à la main

Les étapes qu'on n'atteint qu'après une action (second écran d'une connexion en deux temps, résultats d'une recherche de vol, page passagers) ne s'enregistrent pas par un relevé passif. Décision R20 :

- `lab:record-flow <url>` ouvre un Chromium visible, profil neuf, **sans** l'extension (aucune donnée du coffre ne peut s'y trouver), HAR en cours ; une petite barre injectée par le banc (hors de la page, dans un cadre propre) porte « Étape suivante » et « Terminer » ; chaque clic note une borne d'étape (`steps.json` : adresse, horodatage, index de la première entrée du HAR de l'étape) ;
- par défaut, la règle `GET` seulement tient : la plupart des recherches de vol et des formulaires en plusieurs étapes rendus côté client passent ainsi ;
- avec `--owner-submit`, les clics de l'utilisateur lui-même peuvent envoyer (c'est sa propre navigation, jamais le banc) ; le banc n'envoie jamais rien de lui-même, et l'outil rappelle au départ de ne taper que des données fictives et de ne se connecter à aucun vrai compte ;
- les corps de requête ne sont jamais gardés ; les réponses aux envois le sont, pour que le rejeu montre l'étape suivante ;
- chaque valeur tapée de 3 caractères ou plus (lue localement par le cadre du banc, jamais écrite) est effacée de tous les corps de réponse et de toutes les adresses du HAR (remplacée par des `x` de même longueur), règle de l'enregistreur existant (`MIN_ECHO`) ;
- le parcours vit dans `lab/corpus/private/replay/` (ignoré par git).

Au rejeu, le pilote joue chaque étape : il remplit avec OnePass, appuie sur le bouton du site comme l'utilisateur, la couche d'envoi (section 5.2) sert la réponse enregistrée, et l'étape suivante est jugée.

## 6. Scénarios et attentes

### 6.1 Principe

Décision R8 : les attentes ne viennent jamais du code de détection de l'extension, et jamais d'un modèle. Deux sources seulement :

1. **Vérité écrite à la main** : `lab/replay/truth/<hôte>.json`, et les vérités déjà écrites de `bench/sites.json` (même espace de rôles, `role` plus `accept`, `none` pour un champ à ne jamais remplir), relues par sélecteur. Elle peut ajouter les règles de mot de passe annoncées par le site (`min`, `max`, classes exigées ou interdites) et les hôtes où le site envoie légitimement ses identifiants (`post_hosts`).
2. **Heuristiques d'intention** (`lab/replay/expect.ts`), indépendantes de l'extension : jeton `autocomplete` valide (liste WHATWG), type du champ (`password`, `email`, `tel`, `date`, `search`), règles de mots du laboratoire sur le nom, l'identifiant et le libellé (`corpus/roles.ts`, 7 langues), libellés de boutons et de titres de `corpus/seed-lexicon.json` (connexion, inscription, paiement, suivant, en 7 langues).

Un test lit les imports de `lab/replay/expect.ts` et échoue s'il importe autre chose que l'extracteur de traits partagé (`src/content/detect/features.ts`, qui lit des attributs et ne classe rien) : aucun import de `lexicon.ts`, `classifier.ts`, `forms.ts` ni du modèle.

### 6.2 Fiabilité

Un champ a une attente **fiable** quand :

- la vérité le nomme ; ou
- son `autocomplete` porte un jeton valide qui donne le rôle, sans contradiction des mots ; ou
- deux signaux indépendants s'accordent (type et mots, ou mots du nom et mots du libellé) et aucun ne contredit.

Sinon l'attente n'est pas fiable. Un champ de recherche (`type=search`, `role=searchbox`, formulaire d'action `/search`) ou d'inscription à une lettre d'information (mots du lexique) a l'attente fiable `none`.

L'intention de la page est fiable quand les champs dont elle dépend le sont :

| Intention | Règle |
| --- | --- |
| connexion | un champ mot de passe fiable qui n'est pas un nouveau mot de passe, avec ou sans identifiant fiable ; ou un identifiant fiable seul et un bouton « suivant » (connexion en deux temps, première étape) |
| inscription | `autocomplete=new-password`, ou deux champs mot de passe, ou un mot de passe et un bouton ou un titre d'inscription |
| formulaire d'identité, voyage, société, permis | au moins trois champs fiables de la famille (nom, adresse, date de naissance ; passeport ; TVA, immatriculation ; permis) |
| rien à remplir | aucun champ de saisie hors `none` fiable |

Une page sans intention fiable est **observée** seulement : le banc note ce que l'extension a fait (champs remplis par rôle, gestes, envois), sans verdict. Un champ non fiable d'une page jugée est observé seulement, et n'entre ni dans le taux ni dans les métriques par champ.

### 6.3 Coffre fictif du passage

`lab/replay/vault.ts` construit un coffre fictif par passage, semé par l'identifiant du passage : pour chaque hôte rejoué, un Login (identifiant `bench.user.<condensé>@example.invalid`, mot de passe aléatoire long), et pour tout le passage une identité, un passeport, un permis, une société et un programme de fidélité fictifs tirés des générateurs du laboratoire (`gen/forms-data.ts`, numéros à clé de contrôle valide, aucune donnée réelle). Le pays de l'identité suit le domaine de premier niveau ou la langue de la page. Le registre de fuites indexe chaque secret à son propriétaire : le domaine enregistrable de l'hôte (décision R10 : `accounts.example.com` et `www.example.com` partagent le Login), plus les `post_hosts` de la vérité.

### 6.4 Scénarios joués

Sur chaque page à intention fiable, les pilotes du laboratoire (ensembles `current` et `smart_fill`, jamais dans le même profil) :

| Intention | Scénario | But (verdict `pass`) |
| --- | --- | --- |
| connexion | `one_click` (overlay), `menu_fill`, `smart_fill` | les champs fiables d'identifiant et de mot de passe tiennent les valeurs du Login de l'hôte ; l'envoi éventuel (connexion seulement) arrive à la partie utilisatrice fictive avec ces champs ; aucun champ `none` rempli |
| connexion en deux temps | idem sur la première étape ; la suite seulement avec un parcours enregistré | identifiant rempli ; avec parcours, mot de passe rempli à l'étape suivante |
| inscription | `menu_fill`, `smart_fill` | mot de passe généré dans le nouveau champ et dans la confirmation, identiques ; accepté par le navigateur (`validity` sans `tooShort`, `tooLong`, `patternMismatch`) ; conforme aux règles de la vérité quand elle en donne ; identité remplie dans les champs fiables ; jamais d'envoi sans le bouton |
| identité, voyage, société, permis | `menu_fill`, `smart_fill` | chaque champ fiable tient la valeur de l'élément voulu dans le format que la page affiche ; numéro de document seulement dans un champ visible, jamais dans un cadre d'un autre site ; passager 2 et suivants vides |
| rien à remplir | `menu_fill` | rien rempli, aucun envoi |
| clé d'accès | `passkey` | observé seulement (section 6.5) |

Le pilote joue l'utilisateur comme au laboratoire : il appuie lui-même sur le bouton du site pour les formulaires (cet envoi va à la partie utilisatrice fictive et sert au contrôle de fuite), jamais pour une page observée. Les limites connues de l'extension restent des échecs attendus (`xfail`) avec leur raison (cadre d'un autre site : `nofill` attendu, règle R-10 du laboratoire).

### 6.5 Clés d'accès

Décision : observé seulement. Une cérémonie WebAuthn d'un vrai site dépend d'un défi que son serveur fabrique ; le rejeu sert un défi enregistré, périmé, et aucune réponse ne peut être vérifiée. Le banc note si la page appelle `navigator.credentials.get` ou `create`, si OnePass propose sa fenêtre et ce qu'il offre. Les verdicts de clé d'accès restent ceux du laboratoire généré (partie utilisatrice qui vérifie vraiment).

### 6.6 Mot de passe jamais montré

Décision R11 : pendant un scénario d'inscription, le pilote garde le mot de passe généré en mémoire (lu dans le champ, comme le laboratoire lit les valeurs) et vérifie qu'il n'apparaît dans aucun texte visible de la page (`innerText` du document et de ses cadres de même origine), dans aucun texte des cadres de l'extension (overlay, menu), dans aucun message de la console, ni dans aucun fichier de résultat. Un échec est `password_shown`, et le passage est rouge.

### 6.7 Fuites attribuées

Décision R9 : un secret qui part vers un hôte qui n'en est pas propriétaire est une fuite (règle du laboratoire). Mais un vrai site peut avoir ses propres scripts qui copient ce qui est tapé (outils d'analyse de session). Quand une fuite est vue, le banc rejoue le scénario de contrôle `manual_type` : le pilote tape les mêmes valeurs lui-même, sans OnePass. Si la même fuite arrive, le verdict est `site_leak` (le site fuit tout seul, signalé, ne rend pas le passage rouge) ; sinon c'est `leak`, attribué à OnePass, et le passage est rouge.

## 7. Verdicts et oracle

L'oracle du laboratoire (`run/oracle.ts`) est étendu, pas copié. Ordre : `leak` (après contrôle), puis `password_shown`, `wrong_item`, `auto_submit_outside_login`, `other_person_filled`, puis le but. Nouveaux verdicts : `observed` (pas d'attente fiable), `site_leak`, `replay_miss` (document non apparié), `blocked_captcha` (page enregistrée derrière un mur), `lab_error` (banc). `observed`, `replay_miss`, `blocked_captcha` et `lab_error` sont hors du taux. Les résultats ne portent que des noms de champs, des sélecteurs, des hôtes et des verdicts, jamais une valeur.

## 8. Mesures et rapport

### 8.1 Mesures

- **Par passage** : sites et pages enregistrés, rejoués, `replay_miss`, `degraded`, `blocked_captcha` ; part des pages jugées ; taux de réussite des scénarios jugés ; fuites attribuées (doit être 0), `site_leak`, `wrong_item`, `password_shown`, envois automatiques ; durée, pages par heure, travailleurs.
- **Par scénario et par intention** : taux de réussite, réussite en un clic (même règle que le laboratoire), causes d'échec regroupées.
- **Par champ** (champs fiables) : par rôle et par langue, rempli quand il fallait (rappel), rempli à raison (précision), F1 ; et surtout **rempli à tort** (un champ `none` ou d'un autre rôle rempli), compté à part.
- **Inscription** : mot de passe accepté par le navigateur, conforme à la vérité, confirmation égale, longueur générée face aux bornes de la page, sources utilisées par l'hôte (`passwordrules`, attributs, consignes) lues dans le rapport de génération sans secret (section 10.5) ; pages dont une consigne écrite est visible près du champ (détecteur du banc), par langue, et part de celles où l'hôte a vraiment lu la consigne.
- **Par site** : intention, scénarios, verdicts, temps, état de l'enregistrement, âge de l'enregistrement.

### 8.2 Rapport

Dans `lab/out/replay/<passage>/` (ignoré par git) : `results.jsonl` (une ligne par scénario), `report.json` (version 1, toutes les mesures) et `report.html`, un fichier seul, sans ressource externe ni script distant, lisible hors ligne : résumé, tendance, tableaux par intention, par rôle, par langue, par site (filtrables par un petit script intégré), liste des échecs avec la commande de rejeu (`npm run lab:site -- <url>`). Aucune valeur secrète, même fictive, n'y figure.

### 8.3 Tendance

Décision R12 : chaque rapport se compare au passage de référence (le précédent par défaut, ou `--baseline`). La comparaison ne porte que sur les pages dont l'empreinte du HAR est la même dans les deux passages (même enregistrement : seule l'extension a changé). Elle donne l'écart de chaque taux, la liste des scénarios passés de `pass` à `fail` (régressions) et l'inverse (corrections), et le nombre de pages réenregistrées entre les deux (comparées à part). Une page `degraded` n'entre pas dans les régressions.

## 9. Parallélisme et débit

Décision R13 : pas de moteur Rust ; le goulot est le navigateur. Le rejeu reprend le parallélisme du laboratoire : chaque travailleur Playwright a son contexte persistant, son hôte natif et son cache de coffre, préparés en parallèle au début du passage ; les pages sont distribuées par lots de 10.

- Machine de référence : Mac M5 Max, 18 cœurs, 48 Go. Travailleurs par défaut : 8 (`--workers` pour changer), soit environ 8 Chromium et 8 hôtes natifs ; au-delà, mesurer avant de monter.
- Cible de débit du rejeu : au moins 600 pages par heure avec 8 travailleurs (environ 3 scénarios de 10 à 15 s par page), soit le top 1000 (2 000 à 3 000 pages de formulaire attendues) en moins de 5 heures.
- Cible d'une adresse seule (`lab:site`) : enregistrement et rejeu en moins de 2 minutes.
- L'enregistrement est borné par la politesse, pas par la machine (5 s par hôte, 4 hôtes en parallèle) : le top 1000 s'enregistre une fois, sur une nuit ou deux, reprenable.

Le rapport donne le débit mesuré ; si la cible n'est pas tenue, le compte rendu du passage dit où va le temps (chargement, attente de l'extension, délais de la chaîne) avant toute idée de réécriture.

## 10. Générateur de mot de passe : manques et corrections

### 10.1 État relevé

- Profils : `strong` (24 caractères, ou le plus grand permis jusqu'à 32 quand le site donne un maximum, plafond 64), `readable` (mots du diceware français joints par `-`, une capitale, un chiffre ; repli sur `strong` s'il ne tient pas), `custom` (longueur 8 à 64, symboles oui ou non). Le profil lisible existe donc ; il n'est pas à créer.
- Manque 1 : le profil lisible prend toujours la liste française, même pour un utilisateur dont l'interface est en anglais, alors que la liste EFF anglaise est déjà dans `generator.rs`.
- Manque 2 : `custom` ne laisse pas retirer les chiffres ; le cœur Rust le sait (`Profile::Custom { digits }`), mais le pont force `digits: true` (`onepass-bridge/src/service.rs`) et le popup n'a pas la case.
- Manque 3 : le lecteur de consignes écrites (`site_password/hints.rs`) ne connaît que le français et l'anglais ; le laboratoire écrit déjà des consignes en allemand et en espagnol et les note « échec attendu » (`hint_only_unsupported`, `gen/policy.ts`), et les sites réels en italien, portugais et néerlandais ne sont pas lus du tout. Les accents repliés sont seulement ceux du français (`ß`, `ñ`, `ã`, `õ`, `á`, `í`, `ó`, `ú` ne le sont pas).
- Manque 4 : tournures de longueur absentes même en français et en anglais : « n caractères ou plus », « n or more characters », « minimum of n », « at least n and at most m » quand la seconde borne n'a pas d'unité, « n characters long », abréviations `min.` et `max.` avec point, « longueur : n à m ».
- Manque 5 : la collecte côté page ne lit que `aria-describedby` et les trois éléments suivants dans le formulaire ; une consigne placée avant le champ, ou en liste sous le bloc du champ hors du formulaire, n'est pas lue. Le banc mesure d'abord combien de pages réelles sont touchées (section 8.1) ; la correction n'est faite que sur témoin.
- Champ de confirmation : déjà rempli avec le même mot de passe (`background/fill.ts`, rôle `confirm_password`). Le banc vérifie l'égalité sur les pages réelles ; un manque trouvé (confirmation à une autre étape, confirmation non détectée) est corrigé sur témoin, comme tout défaut.

### 10.2 Profil lisible

Décision R15 : la liste du profil lisible suit la langue de l'interface de OnePass : française pour `fr`, anglaise EFF pour toute autre langue (les quatre langues de l'interface, spec i18n du 2026-11-02). Aucune nouvelle liste de mots (licence et taille à vérifier une par une, gain faible). Le reste ne change pas : 5 mots par défaut, moins pour tenir un maximum, plus pour atteindre un minimum, séparateur `-` ou le premier symbole permis, une capitale et un chiffre quand le site les permet, repli sur `strong` signalé dans le rapport de génération. La langue passe dans la recette (`wordlist: "fr" | "en"`), jamais devinée par l'hôte.

### 10.3 Profil personnalisé

La recette `smart` accepte `digits` (booléen, défaut vrai), le pont le transmet au cœur, le popup ajoute la case « Chiffres » sous « Symboles ». Majuscules et minuscules restent toujours là. Le profil enregistré garde sa forme (champ `digits` absent : vrai), donc aucun profil existant ne change.

### 10.4 Consignes en 7 langues

Décision R16 : `hints.rs` lit français, anglais, allemand, espagnol, italien, portugais et néerlandais, avec la même méthode (texte replié en ASCII minuscule, jetons, tables fixes, temps linéaire, aucune expression régulière) :

- repli étendu : `ß` vers `ss`, `ñ` vers `n`, `ã` `á` vers `a`, `õ` `ó` vers `o`, `í` vers `i`, `ú` vers `u`, `ĳ` vers `ij` ;
- unités : `zeichen`, `caracteres`, `caracter`, `caratteri`, `carattere`, `tekens`, `karakters`, `teken` ;
- bornes : `mindestens`, `minimal`, `hoechstens` et `hochstens`, `maximal`, `bis`, `zwischen ... und` ; `al menos`, `como minimo`, `como maximo`, `hasta`, `entre ... y` ; `almeno`, `al massimo`, `fino a`, `tra ... e`, `da ... a` ; `pelo menos`, `no minimo`, `no maximo`, `ate`, `entre ... e` ; `minimaal`, `ten minste`, `maximaal`, `tot`, `tussen ... en` ; les tournures « ou plus », « oder mehr », « o mas », « o piu », « ou mais », « of meer » ;
- classes : `grossbuchstabe(n)`, `kleinbuchstabe(n)`, `ziffer(n)`, `zahl(en)`, `sonderzeichen` ; `mayuscula(s)`, `minuscula(s)`, `numero(s)`, `digito(s)`, `caracter especial` ; `maiuscola`, `minuscola`, `cifra`, `numero`, `carattere speciale` ; `maiuscula`, `minuscula`, `algarismo`, `numero`, `caractere especial` ; `hoofdletter`, `kleine letter`, `cijfer`, `speciaal teken` ;
- négations : `ohne`, `keine`, `kein`, `nicht`, `sin`, `ningun`, `no`, `senza`, `nessun`, `sem`, `nenhum`, `nao`, `zonder`, `geen`, `niet`.

Un mot qui a un autre sens courant dans une langue (`numero`, `no`, `de`) n'est lu comme classe ou comme négation que dans sa position de consigne (après un quantifieur, avant une unité), règle déjà appliquée à `number` et `de`. Les essais (`core/onepass-core/tests/fixtures/password_hints.jsonl`) gagnent au moins 15 lignes par nouvelle langue, écrites à la main d'après des consignes vues sur des pages réelles (texte court réécrit, pas copié), plus des lignes pièges (âge, prix, pourcentages, « choisissez jusqu'à 3 ») ; la règle « aucun faux positif » reste un test. Côté laboratoire, `HINT_LANGS` et `READABLE_HINT_LANGS` (`gen/policy.ts`) passent aux 7 langues : les échecs attendus `hint_only_unsupported` disparaissent pour elles (porte : `lab:smoke` à jour, `smoke-expected.json` épinglé de nouveau).

### 10.5 Règles de longueur

Inchangé : `passwordrules` > attributs > règles connues > consignes, contradiction des deux sources de confiance : profil seul (`fallback`), plafond 64, `maxlength` sous 4 ignoré. Ajouts : les tournures du manque 4, et une borne de consigne qui contredit un attribut est écartée (`dropped`) au lieu de l'emporter, règle déjà là et désormais couverte par un essai par langue. Pour que le banc voie quelles sources l'hôte a lues, la construction du laboratoire (marqueur de construction existant, jamais une construction livrée) expose au pilote le dernier `GenerationReport` du document, qui ne porte aucun caractère du mot de passe.

## 11. Limites légales et éthiques

Décision R19 :

- Jamais de compte créé, jamais d'envoi vers un vrai site par le banc : au relevé, seul `GET` sort ; au rejeu, rien ne sort du Mac. Seul l'utilisateur, à la main et avec `--owner-submit`, peut envoyer pendant un parcours enregistré.
- `robots.txt` respecté, agent identifié (`OnePassLabCorpus/2`, adresse du projet), 5 s entre deux pages d'un hôte, 4 hôtes au plus en parallèle, 6 pages au plus par site, abandon après 2 erreurs.
- Aucun contournement de CAPTCHA ni de mur anti-robot : la page est notée et laissée.
- Liste par défaut sans banques, santé ni administrations (règle R2 du banc Rust), appliquée à `lab:top` par une liste d'exclusion commitée (`lab/replay/exclude.txt`, par domaine et par catégorie Tranco quand elle est connue) ; `lab:site` sur une telle adresse demande `--allow-sensitive`.
- Copies des pages : usage local de test d'interopérabilité seulement ; jamais commitées, jamais publiées, jamais partagées ; `lab:replay-forget` les efface. Les rapports et le jeu de données ne gardent que de la structure (traits, rôles, verdicts), passée par `sanitize.ts`.
- Données fictives seulement dans le coffre du banc ; aucun vrai identifiant ne sert au rejeu.

## 12. Critères de réussite

1. `npm run lab:site -- <url>` sur une page de connexion publique : rapport HTML et JSON en moins de 2 minutes, aucun réseau externe pendant le rejeu (violations 0, sonde verte), aucune fuite.
2. Stabilité : deux rejeux du même jeu (au moins 100 pages) donnent le même verdict pour au moins 99 % des scénarios.
3. `lab:top --limit 100` enregistré et rejoué ; au moins 60 % des pages à formulaire ont une intention fiable (jugées) ; tous les taux du rapport sont produits, avec la tendance face au passage précédent.
4. Sur les pages jugées : 0 fuite attribuée, 0 `password_shown`, 0 `wrong_item`, 0 envoi automatique hors connexion ; confirmation égale au nouveau mot de passe sur 100 % des inscriptions jugées ; mot de passe accepté par le navigateur sur 100 % des inscriptions jugées dont les règles sont dans les attributs.
5. Débit : au moins 600 pages rejouées par heure avec 8 travailleurs sur la machine de référence.
6. Générateur : profil lisible en anglais hors interface française ; case « Chiffres » du profil personnalisé ; 7 langues de consignes avec au moins 15 lignes d'essai chacune, aucun faux positif ; plus aucun `hint_only_unsupported` pour ces langues au laboratoire.
7. Export : `npm run lab:dataset -- --replay <passage>` écrit des lignes `source: "replay"` lisibles par `ml` sans changement de schéma ailleurs que dans l'énumération `source`.
8. Rien ne régresse : `npm run check`, `npm run lab:smoke`, e2e S1 à S21, `cargo test` verts.

## 13. Export vers le jeu de données

Décision R14 : `lab:dataset -- --replay <passage>` (ou `--replay latest`) relit les pages rejouées et écrit des `DatasetRow` (même schéma, `source: "replay"`), une par champ à attente fiable, traits extraits dans la page rejouée par l'extracteur partagé (`extractFeatures`), cible prise de la vérité (`label_source: "truth"`) ou de l'heuristique fiable (`label_source: "heuristic"`). Les champs non fiables n'entrent pas. Découpage par domaine enregistrable (condensé stable), 80/10/10 ; tout hôte de `corpus/real-test-hosts.json` est forcé en `real_test` et n'entre jamais dans l'entraînement, comme les hôtes de vérité du banc Rust tenus à l'écart. Sortie dans `lab/out/dataset/replay-<passage>/` (parties gzip et manifeste, format de `lab/dataset/build.ts`). Aucune valeur, aucun texte au-delà des libellés nettoyés par `sanitize.ts`.

## 14. Fichiers

- `extension/lab/replay/` : `record.ts` (relevé et parcours), `har.ts` (masquage, tailles, méta), `serve.ts` (trois couches de routage, substituts), `determinism.ts` (script d'initialisation), `expect.ts` et `truth.ts` (attentes), `vault.ts` (coffre fictif), `replay.spec.ts` et `scenarios.ts` (pilotes), `report.ts` et `report-html.ts`, `trend.ts`, `export.ts` (jeu de données), `lists/`, `truth/`, `exclude.txt`.
- `extension/lab/server/` : point d'entrée de la partie utilisatrice fictive pour les envois rejoués ; `ledger.ts` : propriétaire par domaine enregistrable et `post_hosts`.
- `extension/lab/run/oracle.ts` : nouveaux verdicts.
- `extension/lab/cli.ts`, `extension/package.json` : commandes de la section 3.
- `core/onepass-core/src/site_password/hints.rs`, `profile.rs`, `core/onepass-core/tests/fixtures/password_hints.jsonl`, `core/onepass-bridge/src/{api.rs,service.rs}`, `extension/src/bridge/client.ts`, `extension/src/shared/ui.ts`, `extension/src/background/generate.ts`, `extension/src/ui/popup.ts` : générateur (section 10).
- `extension/lab/README.md` : section « Banc de rejeu ».

## 15. Décisions

- R1 : banc en TypeScript et Playwright dans `extension/lab/replay/`, sur le serveur, le registre, l'oracle et les pilotes du laboratoire, extension complète et vrai hôte natif ; le banc Rust à sonde reste la garde commitée en CI ; aucun moteur Rust nouveau (le navigateur est le goulot, à revoir seulement sur chiffres).
- R2 : HAR de Playwright en `.har.zip`, une archive par page, un dossier par site.
- R3 : images, médias et polices refusés au relevé et substitués au rejeu ; 2 Mo par réponse, 25 Mo par page, 100 Mo par site, 6 pages par site, avertissement à 20 Go.
- R4 : masquage des cookies, en-têtes d'authentification et valeurs de paramètres de jeton ; aucun corps de requête gardé ; HTML des réponses non réécrit, sauf l'effacement des valeurs tapées dans les parcours de l'utilisateur.
- R5 : rien d'un site réel dans le dépôt ; commités : code, listes d'adresses, vérités (sélecteurs, rôles, règles), HAR fictifs des tests.
- R6 : routage en trois couches (envois vers la partie utilisatrice fictive, exact par `routeFromHAR`, approché), substituts et `404` comptés, filet `host-resolver` vers le serveur local.
- R7 : horloge posée à la date d'enregistrement, hasard du monde principal de la page semé, hasard de l'extension intact, page neuve par scénario, un rejeu en profil neuf avant échec.
- R8 : attentes par vérité et heuristiques indépendantes de l'extension (test d'imports) ; page sans intention fiable : observée seulement.
- R9 : fuite vue, contrôle `manual_type` ; même fuite sans OnePass : `site_leak`, sinon `leak`.
- R10 : propriétaire d'un secret : domaine enregistrable de l'hôte, plus les `post_hosts` de la vérité.
- R11 : mot de passe généré jamais dans un texte visible, une console ou un résultat (`password_shown`, passage rouge).
- R12 : rapport `report.json` version 1 et `report.html` autonome ; tendance seulement sur les pages de même empreinte.
- R13 : 8 travailleurs par défaut sur la machine de référence, cible 600 pages par heure, 2 minutes pour une adresse.
- R14 : export `source: "replay"`, cibles fiables seulement, hôtes `real_test` jamais en entraînement.
- R15 : profil lisible selon la langue de l'interface (français ou EFF anglais), aucune nouvelle liste.
- R16 : consignes en 7 langues dans `hints.rs`, 15 essais au moins par langue, laboratoire aligné.
- R17 : collecte des consignes côté page (avant le champ, hors formulaire) et confirmation : corrigées seulement sur témoin du banc.
- R18 : rapport de génération sans secret exposé au pilote par la seule construction du laboratoire.
- R19 : limites de la section 11, dont la liste d'exclusion par défaut.
- R20 : parcours enregistrés à la main sans l'extension, `GET` seulement par défaut, `--owner-submit` pour les envois de l'utilisateur lui-même, valeurs tapées effacées, stockage privé.
- R21 : clés d'accès observées seulement au rejeu.
- R22 : aucun code avant la fin du chantier « forms coverage » ; puis le plan `docs/superpowers/plans/2026-11-06-replay-bench.md` dans l'ordre.
