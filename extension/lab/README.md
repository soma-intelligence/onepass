# Laboratoire d'autofill

## But

Mesurer ce que l'extension remplit, et ce qu'elle ne doit jamais remplir, sur un grand nombre de sites générés au hasard mais reproductibles. Une graine donne un monde : des sites fictifs (formulaires de connexion, inscription, paiement, adresse, identité, SSO, TOTP, passkeys) avec des traits qui compliquent la détection (iframes, shadow DOM, champs retardés, noms obfusqués, champs pièges, sosies de domaine). Le laboratoire pilote Chromium avec l'extension chargée et l'hôte natif réel, et note un verdict par scénario. Il ne modifie rien dans `extension/src`.

## Architecture

- `corpus/` : extracteur passif de motifs de formulaires réels, relevés nettoyés et `patterns.json` distillé (version 2 : libellés, suites d'étapes, frameworks, poids des traits). Les libellés passent un filtre : ponctuation seule, plus de 40 caractères, captcha, recherche, lettre d'information, discussion, mots d'inscription sur un identifiant, consignes de mot de passe ; pour les pages relevées en masse, le libellé doit aussi s'accorder avec le rôle du champ. La distillation lit les 59 relevés choisis à la main (`samples/`), le top 1000 (`samples/top1000/`), les pages Common Crawl copiées (déjà nettoyées) dans `samples/commoncrawl/` (jamais `lab/out/`, pour que `patterns.json` se reconstruise depuis un dépôt propre), et les parcours enregistrés de `private/` seulement avec `--with-private` (le `patterns.json` commité n'en dépend jamais). Le générateur ne lit que `patterns.json`.
- `gen/` : générateur de mondes (PRNG `sfc32` + `cyrb128`, déterminisme par graine), rendu HTML des sites et capacités attendues (`capabilities.ts`). Depuis la version 2 du générateur : formulaires en plusieurs étapes (`multi_step`, une page par étape, `steps.ts`), mises en page (`layouts.ts`) et frameworks simulés en HTML et script simples, sans dépendance (`frameworks.ts`).
- `gen/population.ts` : population simulée. Un profil d'utilisateur fixe la taille du coffre (0 à 500), les doublons, les comptes multiples par site, le pays (formats d'adresse, de téléphone et de code postal : US, FR, DE, ES, GB, JP) et le comportement après le remplissage. Le profil `p0` est l'utilisateur historique (coffre du monde seul) ; les autres viennent d'un flux aléatoire séparé, donc demander plus de profils ne change ni le monde, ni les profils précédents.
- `server/` : serveur HTTPS local qui sert tous les hôtes `.test`, les trois fournisseurs d'identité (Google, Apple, Microsoft) sous leurs vrais noms d'hôte résolus en local, la partie utilisatrice (mots de passe, TOTP, WebAuthn) et le registre de fuites.
- `run/` : configuration Playwright, préparation unique (compilation, hôte natif, coffre fictif, certificats), pilotes de scénarios et oracle.
- `report.ts` et `cli.ts` : rapport Markdown et ligne de commande.

Les résultats d'un passage sont dans `lab/out/<graine>/` (ignoré par git) : `world.json`, `fixture.json` (coffre fictif), `results.jsonl` (une ligne par scénario) et `report.md`.

## Population simulée

Avec `--profiles <p>`, chaque scénario est joué pour chaque profil (`p0` à `p<p-1>`) :

- **Coffre** : `vaultSize` est un plancher. Le coffre garde toujours les éléments du monde (les scénarios en ont besoin) et des éléments de remplissage fictifs montent jusqu'à `vaultSize` (hôtes `*-archive.test`, jamais ceux du monde). `0` donne un coffre vide : l'extension n'a rien à proposer, les scénarios attendent `nofill`, sauf le générateur de mot de passe d'une inscription, qui n'a besoin d'aucun élément.
- **Doublons** : des identifiants de site répétés à l'identique. **Comptes multiples** : un second compte (autre identifiant, autre mot de passe, titre « <site> (2) ») pour chaque site à mot de passe.
- **Pays** : les éléments d'identité reprennent les formats du pays (code postal japonais `NNN-NNNN`, téléphone international). La langue du profil suit le pays.
- **Comportement** (pilote `menu_fill` seulement) : `partial` vide un champ rempli avant d'envoyer, `corrects_field` retape un champ, `abandons_step` s'arrête après la première étape d'un formulaire en plusieurs étapes. L'oracle juge alors ce que l'extension a rempli (instantané pris avant l'action de l'utilisateur), pas la réponse du site à l'envoi corrigé ; sous `abandons_step`, seule la première étape compte.

Chaque profil a son propre hôte natif et son cache de coffre, préparés en parallèle à l'installation du passage. Sans `--profiles`, le monde, le coffre et `smoke-expected.json` sont ceux du profil historique.

## Garde-fous du corpus

Le relevé du corpus (`npm run lab:corpus`) touche le réseau réel. Il est passif et prudent :

- un seul `GET` par page, aucun clic, aucune soumission de formulaire, aucune interaction ; seule la première étape d'un formulaire en plusieurs étapes est donc relevée ;
- `robots.txt` est respecté pour les groupes `*` et `OnePassLabCorpus` ; une page interdite est sautée et notée ;
- débit limité : au moins 5 secondes entre deux requêtes de page ;
- nettoyage avant écriture (`sanitize.ts`) : aucune adresse, aucun nombre long, aucun contenu personnel ne survit dans les relevés commités.

Le passage du laboratoire lui-même n'utilise aucun réseau externe : tous les hôtes générés sont en `.test` (RFC 6761) et des filets réseau empêchent toute sortie.

## Commandes

À lancer depuis `extension/`.

| Commande | Effet |
| --- | --- |
| `npm run check` | typage, tests unitaires (dont `test/lab/`), compilation. Sans navigateur. |
| `npm run lab:smoke` | navigateur, graine fixe `lab-smoke-17`, 12 sites couvrant chaque flux (dont `multi_step`) et les pièges structurels (cadre inter-sites, shadow DOM fermé, rerendu SPA, OTP découpé, sosie), avec plusieurs mises en page et frameworks simulés ; compare au résultat épinglé `smoke-expected.json` |
| `npm run lab -- --seed <s> --sites <n> [--workers 4] [--report <md>]` | passage complet ; rapport dans `lab/out/<s>/report.md`, copié dans `<md>` si demandé. Code de sortie 1 s'il y a une fuite. |
| `npm run lab -- --seed <s> --sites <n> --profiles <p>` | même passage joué par `p` utilisateurs simulés (défaut 1, le profil historique). Chaque profil a son coffre et son navigateur : le temps de passage est multiplié par `p`. Le rapport ajoute le tableau « Par profil ». |
| `npm run lab:repro -- --seed <s> --site <i> [--sites <n>]` | rejoue un seul site du monde ; résultats dans `lab/out/<s>-repro-<i>/` |
| `npm run lab:corpus` | relevé du corpus (réseau réel, lent, rarement) puis distillation |
| `npm run lab:label` | outil d'étiquetage à la main du jeu de test réel : formulaire sur `127.0.0.1` (port libre affiché), 200 pages tirées par graine, sites entiers en nombre minimal, catégories rares d'abord (`corpus/real-test-hosts.json` : graine, hôtes, nombre de pages), étiquettes dans `corpus/labels/<hôte>.<n>.json` (celles des flux enregistrés dans `corpus/private/labels/`, non commitées) |
| `npm run lab:real` | compte les champs étiquetés du jeu réel (`real_test: 0 labels` tant qu'aucune étiquette n'existe) ; `-- --pick` retire les hôtes (200 pages au moins). La distillation écarte ces hôtes (tous les sites des relevés) pour que `patterns.json` ne contienne jamais leurs libellés |
| `node --experimental-strip-types lab/corpus/distill.ts [--with-private]` | distillation seule, sans réseau : réécrit `patterns.json` |
| `node --experimental-strip-types lab/cli.ts report --out <dossier> [--md <fichier>]` | refait le rapport d'un dossier de résultats existant |
| `npm run lab -- --seed <s> --sites <n> --classifier heuristic\|gbm\|encoder [--model-dir <dossier>]` | même passage avec ce classifieur de champs (construction `ONEPASS_CLASSIFIER`, modèle pris dans `--model-dir`, obligatoire sauf pour `heuristic`) ; résultats dans `lab/out/<s>-<classifieur>/`, extension construite dans son propre dossier `dist-lab/<s>-<classifieur>/chromium` (jamais `dist/chromium`, et vérifiée avant le passage : CSP du manifeste et empreinte sha256 du modèle), avec `classifier.json` (marqueur de construction, taille du modèle, F1 hors ligne lus dans `<modèle>-eval.json`, temps de classement médian par formulaire mesuré dans le service worker) |
| `node --experimental-strip-types lab/cli.ts compare --out <dossier1> <dossier2> <dossier3> --md <fichier> [--real-rows <lignes.jsonl>]` | comparaison des trois classifieurs sur la même graine : tableaux par flux, trait, langue (et profil), fuites, métriques hors ligne, puis verdict de la règle de la spec (7.3). `--real-rows` donne les lignes `real_test` sur lesquelles l'heuristique est notée ; sans lignes étiquetées le verdict reste « heuristic », provisoire. Les passages doivent avoir même graine, mêmes sites, mêmes profils, classifieurs distincts ; le critère real_test fusionne `password` et `new_password` (R23) et exige les mêmes lignes des deux côtés (empreinte) |

Le passage complet demande Chromium (Playwright), `cargo` pour l'hôte natif et une dizaine de secondes de préparation.

## Lire le rapport

- **Résumé** : nombre de sites et de scénarios, taux de réussite global, fuites. Le taux est (réussis + instables) sur le total sans les échecs attendus, les réussites inattendues et les erreurs du labo.
- **Taux par flux, trait, langue, pilote** : un site à plusieurs traits compte une fois sous chacun de ses traits.
- **Échecs** : chaque ligne donne le site, le flux, le pilote, les traits, la cause et la commande de rejeu.
- **Réussites inattendues** (`xpass`) : une capacité attendue manquante est arrivée ; retirer l'attente d'échec dans `gen/capabilities.ts`.
- **Ce que l'extension ne fait pas encore** : échecs attendus (`xfail`) regroupés par cause, puis causes d'échec récurrentes.
- **Fuites** : tout secret envoyé à un hôte qui n'est pas son propriétaire, ou écrit dans un champ piège. Une fuite a son propre verdict, n'est jamais comptée comme un simple échec et rend le passage rouge.
- **Instables** : échec rejoué une fois en profil neuf puis réussi (`flaky`). Compté comme réussi, mais listé.
- `lab_error` : erreur du banc (préfixe `lab:`, limite de débit de l'hôte natif), exclue du taux.

Le rapport ne contient aucune valeur secrète, même fictive : seulement des noms de champs, des hôtes et des verdicts.

## Rejouer une graine

Chaque ligne d'échec porte sa commande, par exemple `npm run lab:repro -- --seed lab-2026-10-26 --site 42`. Le monde doit être identique à l'original : même graine et même nombre de sites. La commande relit le nombre de sites dans `lab/out/<graine>/world.json` s'il existe ; sinon elle suppose 200 sites, et il faut passer `--sites <n>` si le passage d'origine en avait un autre nombre. Le générateur est versionné dans `world.json` : changer d'algorithme change toutes les graines.

## Limites

- **Passkeys** (R-16) : reportées au jalon 3. Les scénarios `login_passkey` en `one_click` sont des échecs attendus ; un contrôle par l'authentificateur virtuel de Chromium prouve que la partie utilisatrice du labo vérifie correctement.
- **Shadow DOM** : les racines fantômes de la page sont un échec attendu (limite documentée dans `extension/src/content/index.ts`).
- **Iframes d'autres sites** (R-10) : aucune exception, même pour un paiement. Le scénario attend "rien rempli" et réussit si rien n'est rempli ; ce n'est pas un manque.
- **AutoFill système** (trousseau d'iOS ou de macOS) : non couvert. Le labo pilote l'extension seulement ; un autre pilote (`Driver`) pourra brancher l'AutoFill système plus tard.
- Corpus : seule la première étape des formulaires en plusieurs étapes est relevée ; une page qui ne demande que l'identifiant (ou que le mot de passe, ou qu'un code) laisse deviner la suite, et le générateur complète l'étape manquante. Seuls les parcours enregistrés donnent des suites complètes.
- Les délais de la chaîne (4 s, 60 s) sont réels : un passage de 200 sites dure longtemps, d'où les lots de 10 sites par profil et le parallélisme (`--workers`).
