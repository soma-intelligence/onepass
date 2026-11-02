# Banc de sites réels et réentraînement du classifieur de champs : conception

Date : 2026-11-02. Statut : conception écrite et tranchée par l'agent `autofill-ml` (course parallèle du 2026-11-02, consigne de l'utilisateur : aucune question, chaque décision notée). Programme d'autofill, chantiers 2 et 4. S'appuie sur `2026-10-26-autofill-lab-design.md` (laboratoire), `2026-10-27-autofill-dataset-model-design.md` (dataset et modèles) et `2026-10-28-smart-fill-design.md` (moteur `fill_plan`), sans en changer les règles de sécurité.

## 1. But

- **Chantier 2** : mesurer la détection des champs et le remplissage de OnePass sur de vraies pages publiques de connexion et d'inscription, avec un banc écrit en Rust qui pilote un vrai Chromium par le protocole DevTools (CDP), une liste de sites reproductible, un rapport JSON et un mode hors ligne (pages enregistrées) utilisable en CI.
- **Chantier 4** : réentraîner le classifieur de champs sur les données du laboratoire et du banc, le comparer au classifieur livré sur des sites tenus à l'écart, et ne le livrer que s'il gagne sur les métriques fixées ici (section 6), chiffres notés dans `docs/lab/`.

## 2. Contraintes fermes (respect des sites)

- Un seul `GET` de document par site et par passage, au moins 5 s entre deux sites, un site à la fois.
- `robots.txt` respecté pour les groupes `*` et `OnePassBench` ; un site interdit est sauté (`skipped_robots`), jamais forcé.
- User agent identifiable : le Chromium garde son user agent (les sites servent sinon une autre page), le banc s'annonce par l'en-tête `X-OnePass-Bench: 1 (+https://github.com/soma-intelligence/onepass)` sur la requête de document et lit `robots.txt` sous `OnePassBench/1`.
- Aucune création de compte, aucun envoi : toute requête autre que `GET` ou `HEAD` est refusée par l'interception réseau de CDP (`Fetch.failRequest`) avant de partir, `HTMLFormElement.prototype.submit` et `requestSubmit` sont neutralisés et l'événement `submit` est annulé en phase de capture. Le banc ne clique jamais.
- Valeurs fictives seulement : `bench.user`, `bench.user@example.invalid`, un mot de passe fictif fixe. Aucune n'est un vrai secret ; aucune ne sort de la page (pas d'envoi).
- Le rapport ne contient aucune valeur, seulement des rôles, des sélecteurs et des verdicts.

## 3. Ce qui tourne dans la page

Décision R1 : le banc n'installe pas l'extension complète (elle exige l'hôte natif, un coffre et l'appairage, que le laboratoire couvre déjà sur ses sites `.test`). Il injecte une **sonde** construite par esbuild depuis le code même du content script : `analyzeDocument` (détection et classement des champs), `buildPageContext` (perception du planificateur), `extractFeatures` (traits du classifieur) et `createFiller` (le remplisseur de l'extension). Le planificateur est le vrai `onepass_core::fill_plan::plan`, appelé en Rust par le banc. Coût si c'est faux : le banc ne voit pas les défauts propres au service worker et à la messagerie, que le laboratoire mesure.

Flux par site :

1. Chromium headless (`--headless=new`), profil neuf par passage, interception `Fetch` sur toutes les requêtes.
2. Navigation vers l'URL ; attente du chargement plus 2 s de calme (au plus 15 s).
3. La sonde rend : le `PageContext`, pour chaque champ de la vérité (section 4) son rôle détecté (ou absent si le champ n'appartient à aucun formulaire détecté) et ses traits (`FieldFeatures`).
4. Le banc appelle `plan(ctx, pool)` avec un coffre fictif d'un seul Login exact pour l'hôte (connexion) ; pour une inscription le plan propose le mot de passe généré.
5. La sonde remplit chaque groupe du plan avec les valeurs fictives par le remplisseur de l'extension, puis relit les champs de la vérité (rempli ou non, valeur attendue ou non, en booléens).
6. Rien n'est envoyé ; la page est fermée.

## 4. Liste de sites et vérité

`bench/sites.json`, commité, version 1 :

```json
{ "version": 1, "sites": [
  { "id": "github-login", "url": "https://github.com/login", "kind": "login", "lang": "en",
    "fields": [ { "selector": "#login_field", "role": "username", "accept": ["email"] },
                { "selector": "#password", "role": "password" } ] } ] }
```

- `kind` : `login` ou `signup`. `role` et `accept` sont dans l'espace d'étiquettes des modèles (`ml/onepass_ml/labels.py`, plus `none` pour un champ à ne jamais remplir : recherche, lettre d'information, piège).
- La vérité est écrite à la main en lisant les attributs, libellés et textes de la page (commande `--survey`), jamais recopiée de ce que détecte l'extension.
- Un sélecteur absent de la page vivante rend le site `truth_stale`, compté à part, jamais comme une erreur de détection.
- Choix des sites (R2) : 40 à 60 pages publiques de grands services, en anglais d'abord puis français, allemand, espagnol, japonais, mêlant connexion en une étape, identifiant d'abord et inscriptions ; sites bancaires, de santé et gouvernementaux exclus (risque de blocage et de verrouillage, aucun gain de mesure).

## 5. Modes, sorties et CI

- `onepass-bench live --sites bench/sites.json --out <dir> [--only <id>] [--record]` : vrais sites. `--record` enregistre une copie élaguée de la page (section 5.1) dans `bench/recordings/<id>.html`.
- `onepass-bench offline --sites bench/sites.json --out <dir> [--check bench/expected-offline.json]` : chaque document est servi depuis `bench/recordings/` par `Fetch.fulfillRequest`, toute autre requête est refusée ; aucun réseau. `--check` compare les verdicts aux verdicts épinglés et sort en 1 sur toute régression (un succès épinglé devenu échec).
- `onepass-bench survey --url <u>` : liste les champs d'une page (sélecteur, attributs, libellé) pour écrire la vérité.
- Sorties dans `<dir>` : `report.json` et `rows.jsonl` (une ligne `DatasetRow` par champ de la vérité, `source: "rendered"`, plus `heuristic`, le rôle donné par l'extension dans la page).
- Chromium : `--chrome <chemin>`, sinon `CHROME`, sinon le Chromium de Playwright du cache local. Sonde : `extension/dist-bench/probe.js` (`npm run bench:probe`).

### 5.1 Enregistrements

Décision R3 : un enregistrement n'est pas une copie de la page. La sonde élague le DOM rendu : scripts, styles, images, médias, cadres et commentaires retirés, éléments non rendus retirés (sauf `input[type=hidden]`), attributs limités à une liste blanche utile à la détection, textes de plus de 80 caractères retirés, chiffres en série et adresses masqués par la même règle que `sanitize.ts`. Il reste la structure des formulaires, leurs libellés, titres et boutons : de quoi rejouer la détection, sans contenu éditorial des sites dans un dépôt public. Coût si c'est faux : une détection hors ligne un peu différente du vivant ; le rapport hors ligne reste une garde de régression, la mesure de référence est le passage vivant.

### 5.2 Rapport

```json
{ "version": 1, "mode": "live", "date": "...", "chrome": "...", "probe_sha256": "...",
  "summary": { "sites": 0, "scored": 0, "skipped": 0, "fields": 0, "fields_correct": 0,
               "detection_accuracy": 0.0, "merged_macro_f1": 0.0, "fill_pass": 0, "fill_rate": 0.0 },
  "sites": [ { "id": "...", "status": "ok|skipped_robots|load_error|truth_stale|probe_error",
               "fields": [ { "selector": "...", "truth": "username", "detected": "username", "correct": true,
                             "filled": true, "expected_value": true } ],
               "plan": { "intent": "login", "action": "fill", "groups": 1 },
               "fill_pass": true } ] }
```

Détection : un champ est juste si le rôle détecté (rôles de l'extension ramenés aux étiquettes, `current_password`, `new_password` et `confirm_password` vers la famille mot de passe, règle R23 du laboratoire) est dans `role` plus `accept`. Remplissage d'un site : juste si le plan a au moins un groupe, si chaque champ de vérité à remplir pour le `kind` (identifiant et mot de passe pour une connexion, mot de passe pour une inscription) tient la valeur fictive attendue et si aucun champ `none` n'a reçu de valeur.

## 6. Réentraînement (chantier 4)

### 6.1 Données

- Laboratoire : `npm run lab:dataset` sur une graine nouvelle, découpage par origine existant (80/10/10).
- Banc : les lignes `rows.jsonl` du passage vivant. Découpage **par site** (condensé `cyrb128` de l'identifiant du site et de la graine `bench-2026-11-02`, moitié en `bench_train`, moitié en `bench_holdout`). Aucune ligne d'un site tenu à l'écart n'entre dans l'entraînement.
- Entraînement : `train` du laboratoire plus `bench_train` répété `w` fois (défaut 20) pour peser sur le réel.

### 6.2 Modèle

Décision R4 : seul le modèle A (arbres boostés, `train_gbm`) est réentraîné. Le modèle B demande le modèle de base Hugging Face et des heures de MPS pour un gain non démontré ; il reste possible avec les mêmes données. Coût si c'est faux : un meilleur candidat non mesuré.

### 6.3 Métriques convenues et règle de livraison

Le classifieur livré aujourd'hui est l'heuristique (`ONEPASS_CLASSIFIER=heuristic`, défaut de `build.mjs`) : c'est « le modèle actuel ». Son rôle sur chaque ligne du banc est celui que l'extension donne dans la vraie page (colonne `heuristic`), pas l'approximation de `heuristic-role.ts`.

Le nouveau modèle est livré (défaut de construction changé et modèle commité) seulement si, sur `bench_holdout` :

- G1 : F1 macro fusionnée (mot de passe et nouveau mot de passe fusionnés) supérieure d'au moins 0,02 à celle de l'heuristique ;
- G2 : exactitude sur les champs d'identifiant et de mot de passe au moins égale à celle de l'heuristique ;
- G3 : aucun champ `none` de la vérité auquel le modèle donne un rôle d'identifiant ou de mot de passe alors que l'heuristique ne le faisait pas ;
- G4 : modèle de moins de 2 Mo, inférence médiane de moins de 5 ms par formulaire ;
- G5 : passage de laboratoire avec le modèle sans fuite et à un taux au moins égal à l'heuristique sur la même graine.

G1 à G4 sont calculés par `ml` (`onepass_ml.bench_compare`) ; G5 n'est lancé que si G1 à G4 passent. Sinon, rien ne change dans l'extension et le rapport `docs/lab/2026-11-02-classifier-retrain.md` donne les chiffres avant et après et la porte qui a manqué.

## 7. Tests

- Rust (`cargo test -p onepass-bench`) : lecteur de `robots.txt` (groupes, `Allow` plus long gagne, jokers), validation de la liste de sites, notation de détection et de remplissage, rapport sans valeur, pool fictif et plan sur un contexte fixe, cadrage des messages CDP. Test d'intégration hors ligne lancé seulement si un Chromium est trouvé.
- TypeScript (vitest) : la sonde sur jsdom (analyse, vérité, élagage, neutralisation de l'envoi).
- Python (`uv run pytest`) : découpage du banc par site, chargement des lignes, métriques et règle de livraison sur des cas fixes.

## 8. Décisions

- R1 : sonde du content script plus `fill_plan` en Rust, pas l'extension complète (section 3).
- R2 : liste de sites sans banque, santé ni administration (section 4).
- R3 : enregistrements élagués, pas des copies de pages (section 5.1).
- R4 : modèle A seul réentraîné (section 6.2).
- R5 : client CDP synchrone maison sur `tungstenite` (déjà dans `Cargo.lock`, déjà audité par `cargo vet`), sans `chromiumoxide` ni `tokio` : aucune dépendance nouvelle.
- R6 : user agent de Chromium inchangé, annonce par en-tête et par le nom de groupe `robots.txt` (section 2).
