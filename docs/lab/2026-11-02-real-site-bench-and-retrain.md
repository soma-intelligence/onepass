# Banc de sites réels et réentraînement du classifieur : passage du 2026-11-02

Spec : `docs/superpowers/specs/2026-11-02-real-site-bench-and-retrain-design.md`. Plan : `docs/superpowers/plans/2026-11-02-real-site-bench-and-retrain.md`.

## 1. Banc de sites réels (chantier 2)

Chromium for Testing 147.0.7727.15 headless, sonde du content script (classifieur livré : heuristique), planificateur `onepass_core::fill_plan`. Un `GET` de `robots.txt` et un `GET` de page par site, 5 s entre deux sites, aucun envoi. Rapport : `bench/runs/2026-11-02-live-report.json`, lignes : `bench/runs/2026-11-02-live-rows.jsonl`.

Liste : 60 pages candidates relevées (`survey`). 16 refusées par `robots.txt` (Reddit, LinkedIn, X, Facebook, Instagram, Wikipédia, Hacker News, Pinterest, Medium, Twitch, Netflix, PyPI) ; 10 sans aucun champ en headless (GitLab connexion, Discord connexion, npm, Etsy, Idealista, note, GitHub et Stack Overflow en inscription) ; d'autres sans formulaire de connexion visible (web.de, GMX, SoundCloud, Airbnb, Yahoo Japan, WordPress et Duolingo en inscription) ou en double d'une autre page (Trello, Dropbox et Vimeo en inscription). 23 pages retenues (19 connexions, 4 inscriptions ; anglais, français, allemand, japonais).

| Mesure | Vivant | Hors ligne (enregistrements) |
| --- | --- | --- |
| Sites notés | 23 / 23 | 23 / 23 |
| Champs justes | 42 / 44 (95,5 %) | 41 / 44 (93,2 %) |
| F1 macro fusionnée (familles) | 0,845 | 0,838 |
| Sites à détection entière juste | 21 / 23 | 20 / 23 |
| Remplissage juste | 18 / 23 (78,3 %) | 17 / 23 |

Échecs du vivant, par cause :

| Site | Cause |
| --- | --- |
| wordpress-login | identifiant `usernameOrEmail` non détecté (rôle `unknown`), plan `ignore` |
| zoom-login | identifiant `#email` (`name=account`, `autocomplete=off`, libellé en `aria-label` seul) non détecté, plan `ignore` |
| microsoft-login | identifiant seul (première étape) détecté, mais le plan lit l'intention `signup` : menu, pas de remplissage |
| spiegel-login | même cause que Microsoft (première étape d'identifiant lue `signup`) |
| qiita-signup | mot de passe lu `current_password` (aucun indice `new-password`), plan `login` sans élément : menu |

Hors ligne, `vimeo-login` échoue en plus (l'enregistrement élagué perd le contexte qui fait reconnaître l'identifiant) : épinglé en échec dans `bench/expected-offline.json`.

Garde réseau : sur les 23 pages, le banc a refusé des centaines de requêtes `POST` et `OPTIONS` (mesure d'audience, traces d'erreurs, et `POST https://www.tumblr.com/api/v2/password/strength` pendant le remplissage de l'inscription Tumblr : sans la garde, le mot de passe fictif serait parti). Aucune requête autre que `GET` ou `HEAD` n'est sortie. Liste par site dans `refused.json` de chaque passage (non commité).

## 2. Réentraînement (chantier 4)

Données : dataset du laboratoire `am-retrain-2026-11-02` (générateur 3, 400 000 formulaires, 1 016 049 champs ; train 812 983, val 101 250, test 101 816), plus les 43 lignes du banc. Découpage du banc par origine : `bench_train` 24 lignes, `bench_holdout` 19 lignes sur 8 origines (docker, qiita, slack, vimeo, duolingo, figma, tumblr, zoom). Modèle A (LightGBM, 7 feuilles, 150 tours, export ONNX), poids des lignes du banc 20.

| Modèle | F1 macro fusionnée holdout | Exactitude identifiants et mots de passe holdout | G3 | Taille | Inférence (natif, par formulaire) | F1 macro test synthétique |
| --- | --- | --- | --- | --- | --- | --- |
| Heuristique livrée (avant) | 0,931 | 0,941 | | | | |
| A, laboratoire seul | 0,847 | 0,941 | 1 violation (champ de recherche Tumblr lu `username`) | 1 541 120 o | 0,047 ms | 0,99989 |
| A, laboratoire + banc (après) | 0,953 | 0,941 | 0 | 1 537 679 o | 0,047 ms | 0,99981 |

Lecture : le modèle entraîné sur le seul laboratoire est moins bon que l'heuristique sur le réel (F1 0,847) et remplirait un champ de recherche. Les 24 lignes réelles corrigent les deux défauts (recherche Tumblr, `new_password` Tumblr). Le gain sur l'heuristique tient à un seul champ (`zoom-login`, identifiant que l'heuristique ne détecte pas) sur 19 : +0,022, juste au-dessus de la marge G1 de 0,02.

G5 : laboratoire, graine `g5-2026-11-02`, 200 sites, 4 workers, même graine pour les deux classifieurs.

| Classifieur | Scénarios | Taux | Échecs | Fuites | Un clic courant |
| --- | --- | --- | --- | --- | --- |
| Heuristique livrée | 207 (+22 contrôles) | 94,0 % | 12 | 0 | 92 / 183 |
| A, laboratoire + banc | 207 (+22 contrôles) | 80,0 % | 40 | 0 | 66 / 183 |

Échecs du modèle par cause : 29 `no_overlay` (un clic : surtout `sso` et `login_passkey` en langues mêlées, mais aussi `login_single` et `login_username_first` sans variante), 6 `no_menu`, 2 `chain_ended:done`, 1 `handoff:repeat`, 1 `rp_refused:unknown_user`, 1 `wrong_fill`. Heuristique : 5 `no_menu`, 3 `timeout`, 2 `chain_ended:done`, 2 `rp_refused:unknown_user`. Inférence dans la page : médiane 0,3 ms par formulaire (52 formulaires classés). Les deux passages ont tourné sur une machine très chargée (charge 170 à 450) ; les `timeout` de l'heuristique en viennent, l'écart de 28 échecs `no_overlay` non.

## 3. Décision

**Le modèle n'est pas livré.** G1 à G4 passent sur `bench_holdout`, G5 échoue : 80,0 % contre 94,0 % sur la même graine, sans fuite mais avec 28 échecs de plus, presque tous des surcouches un clic absentes sur des connexions que l'heuristique traite. Le défaut de construction reste `ONEPASS_CLASSIFIER=heuristic` ; aucun modèle n'est commité dans l'extension, la CSP des pages de l'extension ne change pas.

Lecture :

- Le gain G1 tient à un seul champ réel sur 19 (+0,022 pour une marge de 0,02) : trop mince pour compenser une perte nette dans le laboratoire.
- Le F1 du test synthétique (0,9998) ne prédit ni le réel (0,953) ni le comportement de bout en bout : le modèle classe juste champ par champ, mais la chaîne un clic de l'extension s'appuie sur des signaux de l'heuristique (ou sur son moment d'exécution) que le chemin modèle ne reproduit pas. À instruire avant tout nouveau réentraînement : comparer, sur les sites `no_overlay`, les rôles et le moment de la décision des deux chemins.
- Pistes chiffrables ensuite : plus de pages réelles (23 aujourd'hui, la moitié des candidats refusés par `robots.txt` ou vides en headless), poids du banc plus fort, modèle B.

Chiffres avant et après, en une ligne : réel holdout F1 fusionnée 0,931 (heuristique) contre 0,953 (modèle), laboratoire 94,0 % contre 80,0 %. Livré : l'heuristique, inchangée.

## 4. Correctifs de l'heuristique (après le banc)

Les quatre défauts de la section 1 sont corrigés dans l'heuristique livrée, sans cas par site ; chacun est épinglé par un test sur sa page enregistrée (`extension/test/bench/recordings.test.ts`) et, pour l'intention, par un test de `fill_plan` (commits `ecd7124a`, `e968f491`, `935a63d1`).

| Défaut | Règle générale |
| --- | --- |
| wordpress-login (et vimeo-login) | un « Continuer » désactivé marque encore l'étape d'identifiant ; il n'est jamais le bouton que OnePass presse |
| zoom-login | un « Next » placé après un `<form>` sans bouton propre est son envoi, si aucun champ d'un autre groupe n'est entre eux |
| microsoft-login, spiegel-login | le genre `login` du détecteur l'emporte sur un lien de création ; « Anmelden oder Konto erstellen » est un bouton de connexion |
| qiita-signup | un mot de passe seul, sous un envoi qui crée un compte, dans un formulaire qui demande deux champs d'identité, est un nouveau mot de passe |

| Mesure | Avant | Après |
| --- | --- | --- |
| Banc hors ligne, champs justes | 41 / 44 | 44 / 44 |
| Banc hors ligne, F1 macro fusionnée | 0,838 | 0,889 |
| Banc hors ligne, remplissage juste | 17 / 23 | 23 / 23 |
| Laboratoire `g5-2026-11-02`, 200 sites, 3 workers, même `main` | 90,5 % (19 échecs) | 95,5 % (9 échecs) |
| Un clic courant | 83 / 183 | 92 / 183 |
| Fuites | 0 | 0 |

Le laboratoire « avant » est le même `main` avec les trois commits retirés de l'arbre de travail, passé le même jour ; la charge de la machine différait entre les deux passages (plus forte pour « avant »), mais les sites 63 et 72 rejoués seuls tranchent : une première version de la règle Qiita les cassait (libellé bruité « create imagelog in »), corrigée par `935a63d1` avant la mesure finale. `vimeo-login` passe désormais hors ligne ; son verdict épinglé est mis à jour. Le banc vivant n'a pas été relancé (une passe par site et par jour).
