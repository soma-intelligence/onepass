# Dataset d'autofill et modèle de classification des champs : conception

Date : 2026-10-27. Statut : design approuvé en conversation, spec à relire par l'utilisateur.
Prolonge `2026-10-26-autofill-lab-design.md` (le laboratoire) sans en changer le contrat.

## 1. But

Donner à l'extension (puis à l'AutoFill de l'app Apple) le meilleur modèle possible pour reconnaître les champs de saisie, appris sur un très grand nombre de formulaires réalistes.

Demande de l'utilisateur, reformulée : relever les formulaires des 1000 sites les plus visités au monde, avec leurs différentes étapes, les injecter dans le générateur du laboratoire, faire tourner le simulateur avec beaucoup d'utilisateurs sur beaucoup de sites et de configurations, et en tirer un dataset d'entraînement.

Critères de réussite :

- le modèle retenu dépasse les heuristiques actuelles (`classifyField`, 63,8 % au passage `lab-2026-10-26`) sur le laboratoire **et** sur le jeu de test réel (section 7.3) ;
- zéro fuite au laboratoire, comme aujourd'hui ;
- inférence de moins de 5 ms par formulaire dans le content script, sur le Mac de développement ;
- tout le dataset se régénère à l'identique depuis une graine et une version du générateur ;
- tout tourne sur le Mac de l'utilisateur (décision D3), sans service distant.

Hors périmètre : apprentissage en ligne, télémétrie des utilisateurs, modèle côté serveur, AutoFill système d'iOS et macOS dans le laboratoire (l'intégration du modèle dans l'app Apple est une suite, section 10).

## 2. Contrainte ferme : aucune interaction avec un vrai site

Passer à l'étape 2 d'un vrai formulaire exige de saisir des données et de cliquer "Suivant" chez un tiers, ce qui crée souvent un compte ou soumet un formulaire en production. Le relevé ne le fait jamais. Les étapes 2 et suivantes viennent de trois sources (décision D1) :

1. **Relevé passif rendu** du top 1000 : le DOM après exécution du JavaScript, tous les formulaires visibles sans interaction, et les URL d'étapes publiques quand elles existent (par exemple une page de mot de passe oublié ou d'inscription en deux URL).
2. **Common Crawl** : formulaires déjà archivés, aucune requête vers les sites.
3. **Parcours de l'utilisateur** : un enregistreur, en build de développement seulement, capture la structure des formulaires que l'utilisateur remplit lui-même, à chaque étape, sans jamais capturer une valeur.

Les étapes absentes des trois sources sont synthétisées par le générateur à partir des séquences observées (section 4.2).

## 3. Corpus

### 3.1 Top 1000 (relevé passif rendu)

- Liste : Tranco (liste de recherche stable, téléchargée une fois et épinglée par son identifiant de liste dans `lab/corpus/tranco.json`).
- Découverte des pages de formulaires, sans clic : liens de l'accueil dont le texte ou l'URL correspond au lexique (connexion, inscription, compte, paiement, adresse, dans les langues de `seed-lexicon.json`), `sitemap.xml`, puis une courte liste de chemins usuels (`/login`, `/signin`, `/register`, `/signup`, `/account`, `/checkout`). Au plus 6 pages par site.
- Relevé : Chromium headless de Playwright, sans extension, sans cookie conservé, un `GET` par page, attente du réseau calme (au plus 10 s), puis extraction de la structure par le même code que `extract.ts` (extracteur version 2, section 3.4).
- Garde-fous repris du corpus actuel : `robots.txt` respecté (groupes `*` et `OnePassLabCorpus`), au moins 5 s entre deux pages d'un même site, `sanitize.ts` avant toute écriture. Ajouts : user agent identifiable avec une URL de contact, pas plus de 4 sites en parallèle, abandon d'un site après 2 erreurs, aucune requête `POST`, aucune saisie, aucun clic.
- Durée attendue : environ 1000 sites x 6 pages x 5 s, soit une nuit à une journée. Le relevé reprend là où il s'est arrêté (un fichier par hôte, déjà présent = sauté).

### 3.2 Common Crawl

- Source : index Common Crawl d'une seule capture récente (épinglée), filtré sur les hôtes du top 1000 puis élargi à un échantillon de domaines hors top 1000 pour la diversité (objectif : 50 000 pages avec au moins un formulaire).
- Lecture des enregistrements WARC par plage d'octets depuis le stockage public de Common Crawl, jamais depuis les sites.
- Pas de rendu JavaScript : seuls les formulaires présents dans le HTML servi sont gardés. Chaque relevé porte `source: "commoncrawl"` pour pouvoir le pondérer ou l'exclure.
- Même extracteur (en mode DOM statique, via un parseur HTML) et même `sanitize.ts`.

### 3.3 Parcours de l'utilisateur

- Enregistreur dans l'extension, compilé seulement quand `ONEPASS_LAB_RECORDER=1` à la construction ; absent de tout build publié.
- Quand l'utilisateur soumet un formulaire, l'enregistreur écrit la structure de chaque étape (champs, libellés, boutons, ordre des étapes, rôle effectivement rempli par l'utilisateur ou par OnePass) dans le stockage local de l'extension. Aucune valeur saisie, aucune URL complète : l'hôte seul.
- Export manuel en JSON depuis la page d'options de développement, puis `sanitize.ts`.
- Ces relevés ne sont **jamais commités** (ils révèlent les sites qu'utilise l'utilisateur) : ils vivent dans `lab/corpus/private/`, ignoré par git. Ils servent d'abord au jeu de test réel (section 7.3).

### 3.4 Extracteur version 2

`Sample` gagne :

- `source: "rendered" | "commoncrawl" | "recorded"` ;
- `steps?: SampleForm[][]` : séquence d'étapes quand elle est connue (enregistreur, ou URL d'étapes publiques) ;
- par champ : texte voisin nettoyé (au plus 40 caractères avant et après), `placeholder`, `aria-label`, indice de position dans le formulaire, profondeur DOM, nombre de champs frères, présence d'un `pattern`, `inputmode`, `maxlength` ;
- `framework?: string` : détection passive (React, Vue, Angular, autre) par marqueurs du DOM.

Les relevés existants (extracteur 1) restent lisibles : les champs nouveaux sont optionnels.

### 3.5 Ce qui est commité

Les relevés rendus du top 1000 sont commités sous `lab/corpus/samples/` comme aujourd'hui, après nettoyage. Les relevés Common Crawl ne sont pas commités (volume) : seul le manifeste (identifiant de capture, liste des enregistrements) l'est, pour rejouer l'extraction. `patterns.json` passe en version 2 et reste commité.

## 4. Générateur

### 4.1 `patterns.json` version 2

En plus de la version 1 : séquences d'étapes observées et leur fréquence (par exemple `email > password > otp`, `email > code`, `name > address > card`), distribution des libellés par rôle et par langue sur 15 à 20 langues, distribution des frameworks, taux de chaque trait mesuré sur le corpus réel.

### 4.2 Formulaires multi-étapes

Nouveau flux `multi_step` : le générateur tire une séquence dans `patterns.json` puis rend chaque étape comme une page ou un rerendu SPA, selon le framework tiré. Les étapes manquantes des relevés sont complétées par le catalogue synthétique existant (`render-forms.ts`), pondéré par les séquences observées.

### 4.3 Nouveaux axes

- Langues : celles du corpus, pondérées par leur part.
- Rendu : HTML statique, React, Vue, Angular simulés (rerendus, champs contrôlés, attributs générés).
- Design systems : 6 à 8 gabarits de balisage (libellé flottant, libellé dans le `placeholder`, libellé dans un `div` voisin, grille, champs en ligne).
- Traits durs déjà mesurés : SPA, champs différés, iframe de même origine, TOTP libellé comme un CVC, identifiant seul sans `autocomplete`.

`GENERATOR_VERSION` passe à 2 : toutes les graines changent, ce qui est attendu.

## 5. Population simulée

Un profil d'utilisateur tiré par graine : taille du coffre (0 à 500 éléments), doublons et comptes multiples sur un même site, langue et pays (formats d'adresse et de téléphone), navigateur (Chromium seulement au laboratoire, le champ existe pour plus tard), comportement (remplissage partiel, correction manuelle d'un champ, abandon à une étape).

Les profils servent au laboratoire d'évaluation (section 7). Le dataset de champs n'en dépend pas : l'étiquette d'un champ ne change pas avec l'utilisateur.

## 6. Dataset

### 6.1 Production rapide, sans extension

Le laboratoire complet tourne à environ 11 sites par minute (délais réels de la chaîne). Le dataset est donc produit à part :

1. le générateur produit N formulaires (objectif initial 2 millions de champs) ;
2. un pool de pages Chromium headless (sans extension, sans hôte natif, autant de pages que de cœurs) charge chaque formulaire servi par le serveur du laboratoire ;
3. un script injecté extrait, pour chaque champ, les traits de la section 6.2 depuis le DOM réellement rendu (après rerendus et délais), avec l'étiquette vraie connue du générateur.

Objectif de débit : au moins 50 formulaires par seconde sur le Mac. Commande : `npm run lab:dataset -- --seed <s> --forms <n> [--workers <k>]`.

### 6.2 Contenu d'une ligne

Une ligne par champ : identifiants (graine, site, étape, index du champ), source (`synthetic`, `rendered`, `commoncrawl`, `recorded`), langue, framework, traits du site, attributs bruts (`type`, `name`, `id`, `autocomplete`, `inputmode`, `maxlength`, `pattern`), textes (libellé, `placeholder`, `aria-label`, texte voisin), contexte (rôles et libellés des champs voisins, texte des boutons, titre de la page, étape dans la séquence), géométrie (visible, taille, position), et l'étiquette : un `Role` ou `none` (champ à ne jamais remplir : piège, recherche, newsletter).

Aucune valeur de secret, même fictive, n'entre dans le dataset.

### 6.3 Format, découpage, stockage

- Parquet, un fichier par lot, sous `extension/lab/out/dataset/<graine>-g<version>/` (ignoré par git), avec un `manifest.json` (graine, version, comptes par rôle, langue, source).
- Découpage train / validation / test **par site d'origine** (et par motif réel d'origine pour les sites synthétiques dérivés d'un relevé), jamais par champ, pour éviter qu'un même site se retrouve des deux côtés.
- Les relevés réels (rendus et enregistrés) n'entrent que dans le jeu de test réel (section 7.3), sauf décision contraire après mesure.

## 7. Modèles et évaluation

### 7.1 Deux modèles comparés (décision D2)

- **A, arbres boostés** : LightGBM sur des traits dérivés (jetons des attributs et libellés hachés, indicateurs du lexique existant, contexte des voisins, géométrie). Export ONNX. Cible : moins de 2 Mo.
- **B, petit encodeur** : encodeur multilingue distillé (taille de l'ordre de MiniLM) qui lit une sérialisation texte du champ et de son contexte, tête de classification sur les rôles. Entraîné sur le Mac (PyTorch, backend MPS), quantifié int8, export ONNX. Cible : moins de 30 Mo.

Code d'entraînement en Python sous `ml/` à la racine du dépôt (environnement `uv`, versions épinglées). Les deux exports portent la version du dataset et la graine.

### 7.2 Intégration dans l'extension

- Interface `FieldClassifier` dans `extension/src/content/detect/` ; trois implémentations : heuristiques actuelles (`classifyField`), A, B. Le choix se fait à la construction (`ONEPASS_CLASSIFIER=heuristic|gbm|encoder`).
- Exécution par `onnxruntime-web` (WASM), modèle chargé une fois par onglet, inférence par formulaire en lot.
- **Les règles de sécurité restent en code et passent avant le modèle** : iframe d'un autre site (R-10), champs pièges invisibles, sosies de domaine, origine du secret. Le modèle propose un rôle ; il ne peut jamais autoriser un remplissage qu'une règle refuse.
- Si le modèle échoue à se charger, l'extension retombe sur les heuristiques.

### 7.3 Évaluation

- **Hors ligne** : exactitude et F1 par rôle sur le test synthétique et sur le jeu de test réel (relevés rendus du top 1000 étiquetés à la main pour un échantillon de 200 pages, plus les parcours enregistrés). Matrice de confusion, avec attention particulière à `otp` contre `cc_csc` et `password` contre `new_password`.
- **Laboratoire** : `npm run lab` sur une même graine avec chacun des trois classifieurs ; comparaison des taux par flux, trait et langue, et des fuites.
- **Performance** : temps d'inférence par formulaire mesuré dans le content script.
- Décision : le modèle retenu est celui qui remplit les critères de la section 1 avec le meilleur taux au laboratoire ; à égalité, le plus petit.

## 8. Arborescence ajoutée

```
extension/lab/
  corpus/
    tranco.json            liste épinglée
    discover.ts            pages de formulaires d'un site, sans clic
    commoncrawl.ts         manifeste et extraction WARC
    private/               relevés de l'enregistreur (ignoré par git)
  gen/
    population.ts          profils d'utilisateurs
    steps.ts               séquences multi-étapes
  dataset/
    build.ts               pool de pages, extraction, Parquet
    features.ts            script d'extraction injecté
    split.ts               découpage par site d'origine
extension/src/content/detect/
  classifier.ts            interface FieldClassifier et choix à la construction
  model/                   chargeur ONNX
extension/src/dev/recorder.ts   enregistreur (build de développement seulement)
ml/
  pyproject.toml
  train_gbm.py
  train_encoder.py
  export.py
  eval.py
```

## 9. Tests

- Unitaires (vitest, dans `npm run check`) : découverte de pages sur des fixtures HTML, `sanitize.ts` sur les nouveaux champs, séquences d'étapes déterministes par graine, découpage sans site commun entre train et test, extraction de traits sur des formulaires fixes, `FieldClassifier` qui ne lève jamais un refus de sécurité.
- Le smoke du laboratoire (`lab:smoke`) tourne avec les trois classifieurs.
- Python : tests sur un mini-dataset commité (quelques centaines de lignes synthétiques) pour l'entraînement, l'export et le rechargement ONNX.

## 10. Suites

- Brancher le modèle retenu dans l'extension AutoFill de l'app Apple (Core ML ou ONNX Runtime).
- Pilote `Driver` pour l'AutoFill système au laboratoire.
- Réentraîner à chaque nouvelle version du générateur ou du corpus.

## 11. Décisions

- **D1** : étapes 2 et suivantes = relevé passif rendu + Common Crawl + parcours de l'utilisateur, jamais d'interaction automatique avec un vrai site (choix de l'utilisateur, 2026-10-27).
- **D2** : deux modèles, arbres boostés et petit encodeur, comparés au laboratoire (choix de l'utilisateur).
- **D3** : tout tourne sur le Mac, sans Azure (choix de l'utilisateur).
- **D4** : dataset produit sans l'extension, laboratoire complet réservé à l'évaluation (design approuvé).
- **D5** : règles de sécurité en code, avant le modèle (design approuvé).
- **D6** : relevés de l'enregistreur jamais commités (dépôt public).
