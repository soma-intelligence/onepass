# Laboratoire d'autofill : inscriptions avec règles de mot de passe

- Plan : générateur de mots de passe qui suit les règles du site, tâche 12 (axe « règles d'inscription » du laboratoire)
- Date : 2026-11-01
- Graine : `lab-2026-11-01`, 200 sites, 4 processus, pilotes actuels. Commande : `npm --prefix extension run lab -- --seed lab-2026-11-01 --sites 200 --workers 4`
- Code : `35d449a7` plus les changements de la tâche 12 (arbre non commité pendant le passage). Générateur du labo : toujours v3 (le résumé du monde change pour les inscriptions, voir plus bas).
- Rapport brut : `extension/lab/out/lab-2026-11-01/report.md` (ignoré par git). Tableau par catégorie : `node --experimental-strip-types lab/policy-stats.ts --out lab/out/lab-2026-11-01`

## Ce que le labo fait maintenant

Environ 60 % des sites d'inscription tirent une règle de mot de passe (`Site.passwordPolicy`, flux propre à la graine, rien d'autre du site ne bouge). Une règle porte : longueur mini et maxi, classes exigées (majuscule, chiffre, symbole), « sans symbole », et parfois un `pattern` simple (`[A-Za-z0-9]+` ou `\S+`, un seul quantificateur, aucun groupe). Elle est affichée par une ou deux sources parmi `attributes` (`minlength`, `maxlength`, `pattern` sur les deux champs de mot de passe), `passwordrules` et `hints` (une phrase sous le premier champ, dans la langue du site : fr, en, de, es). Chaque partie de la règle est écrite par au moins une des sources du site, donc toute règle tirée est satisfaisable par un lecteur de ces sources. Les langues it, pt et nl n'ont pas de phrase : leurs sites n'utilisent jamais `hints`.

Le serveur de la partie utilisatrice refuse avec la raison `policy` un mot de passe qui casse la règle, après le contrôle `looksGenerated`, qui reste. Sous une règle, `looksGenerated` ajuste deux points : la longueur minimale tombe au maximum de la règle quand il est sous 12, et une règle « sans symbole » compte trois classes (minuscule, majuscule, chiffre).

Les phrases en fr et en ont été relues par le lecteur Rust de `core/onepass-core` (`parse_hints`), hors dépôt, sur les 35 phrases d'un monde de 1 500 sites : longueurs, classes exigées et « sans symbole » toutes reconnues ; les 29 chaînes `passwordrules` aussi (`parse_passwordrules`).

## Verdict

**Zéro refus `policy`** sur les inscriptions du passage 2, toutes catégories confondues. Le critère est atteint, sur un échantillon petit (20 inscriptions dans la graine, 11 jouées avec une règle).

| Catégorie | Sites d'inscription (monde) | Scénarios joués | Réussis | Refus `policy` | Refus `weak_password` | Autres échecs |
| --- | --- | --- | --- | --- | --- | --- |
| attributes | 7 | 6 | 6 | 0 | 0 | 0 |
| passwordrules | 6 | 5 | 4 + 1 instable | 0 | 0 | 0 |
| hints_readable (fr, en) | 3 | 2 | 1 | 0 | 0 | 1 (site 6, voir plus bas) |
| hint_only_unsupported (de, es) | 0 | 0 | 0 | 0 | 0 | 0 |
| sans règle | 4 | 3 | 3 | 0 | 0 | 0 |

Les inscriptions à cadre inter-sites (sites 15, 35, 118, 153) sont attendues vides (R-10) et ne comptent pas dans les scénarios joués ; deux portaient une règle.

La graine ne contient aucun site « indice seul en langue non lue » : la catégorie `hint_only_unsupported` vaut 0 ici. Sur un monde de 1 500 sites (graine `policy-props`), les 128 inscriptions se répartissent en : sans règle 53, passwordrules 29, hints_readable 28, attributes 14, hint_only_unsupported 4. Ces dernières sont attendues en échec quand l'indice est la seule source ; elles sont comptées à part et ne comptent pas dans la cible de zéro refus. Leur taux n'est donc pas mesuré par ce passage.

## Les deux passages

| Passage | Code | Durée | Scénarios | Réussis | Échecs | Instables | Fuites | Refus `policy` | Refus `weak_password` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | règle `required: X` seule dans `passwordrules` | 37 min | 208 | n/a | 7 | n/a | 0 | 0 | 3 |
| 2 | règle écrite avec `allowed` | 37 min | 208 | 188 | 8 | 5 | 0 | 0 | 0 |

Le passage 1 a trouvé un défaut du labo, pas de l'extension : `passwordrules: required: digit` sans `allowed` limite le mot de passe aux classes nommées (lecture d'Apple, reprise par l'extension : « required » compte aussi comme « allowed »). L'extension a donc fabriqué un mot de passe fait de chiffres, que `looksGenerated` a refusé (`weak_password`, sites 93, 182, 196). Le labo écrit maintenant `allowed: upper, lower, digit, special` avec les classes exigées (ou `allowed: upper, lower, digit` pour « sans symbole »), comme les vraies pages qui veulent des symboles en plus. Au passage 2 il n'y a plus de refus `weak_password`.

## Échecs et instables hors règle de mot de passe

Le taux global du passage 2 est de 96,0 % (hors attendus). Les échecs ne viennent pas des règles :

- Site 6 (inscription, fr, mise en page `card`, règle `attributes` + `hints`) : `no_menu`, aux deux passages. Le champ « Nouveau mot de passe » est nommé `password-confirm`. Reproduit avec `POLICY_RATE = 0` (sans aucune règle) : même échec, donc antérieur à ce changement.
- Site 196 (règle `attributes` + `passwordrules`) : instable (délai du menu), réussi au rejeu.
- Les autres échecs (sites 50, 61, 104, 147, 161, 173, 177, 178, 183, 189, 195) sont des flux de connexion, SSO ou formulaires, sans lien avec les inscriptions.
- Sites 58 et 59 (checkout_card avec `iframe_same_origin`, `spa_rerender`, `no_autocomplete`, puis identity) : le lot 5 reste bloqué sur le site 58 jusqu'au délai du lot (35 min), aux deux passages et en rejeu seul (`lab:repro --site 58`, 5 min sans fin). Ces deux sites n'ont donc pas de verdict, et le lot est compté en échec par Playwright (`20 passed`, 1 failed). Le site 58 n'est pas une inscription : ni le rendu ni le serveur n'ont changé pour lui. Non élucidé ici ; à traiter à part.

## Portes

- `npm --prefix extension test` : 1 651 passés, 9 ignorés, 0 échec. `npm --prefix extension run typecheck` : vert.
- Nouveaux tests : `test/lab/policy.test.ts` (déterminisme, taux entre 50 et 70 %, satisfaisabilité, patterns sûrs, rendu des trois sources, verdicts du serveur, tableau par catégorie) ; `looksGenerated` sous règle dans `test/lab/rp.test.ts` ; l'empreinte du monde `g2` de `generate.test.ts` est recalée (seules les inscriptions changent).
