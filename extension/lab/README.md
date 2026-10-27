# Laboratoire d'autofill

## But

Mesurer ce que l'extension remplit, et ce qu'elle ne doit jamais remplir, sur un grand nombre de sites générés au hasard mais reproductibles. Une graine donne un monde : des sites fictifs (formulaires de connexion, inscription, paiement, adresse, identité, SSO, TOTP, passkeys) avec des traits qui compliquent la détection (iframes, shadow DOM, champs retardés, noms obfusqués, champs pièges, sosies de domaine). Le laboratoire pilote Chromium avec l'extension chargée et l'hôte natif réel, et note un verdict par scénario. Il ne modifie rien dans `extension/src`.

## Architecture

- `corpus/` : extracteur passif de motifs de formulaires réels, relevés nettoyés et `patterns.json` distillé. Le générateur ne lit que `patterns.json`.
- `gen/` : générateur de mondes (PRNG `sfc32` + `cyrb128`, déterminisme par graine), rendu HTML des sites et capacités attendues (`capabilities.ts`).
- `server/` : serveur HTTPS local qui sert tous les hôtes `.test`, les trois fournisseurs d'identité (Google, Apple, Microsoft) sous leurs vrais noms d'hôte résolus en local, la partie utilisatrice (mots de passe, TOTP, WebAuthn) et le registre de fuites.
- `run/` : configuration Playwright, préparation unique (compilation, hôte natif, coffre fictif, certificats), pilotes de scénarios et oracle.
- `report.ts` et `cli.ts` : rapport Markdown et ligne de commande.

Les résultats d'un passage sont dans `lab/out/<graine>/` (ignoré par git) : `world.json`, `fixture.json` (coffre fictif), `results.jsonl` (une ligne par scénario) et `report.md`.

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
| `npm run lab:smoke` | navigateur, graine fixe `lab-smoke-18`, 12 sites couvrant chaque flux et les pièges structurels (cadre inter-sites, shadow DOM fermé, rerendu SPA, OTP découpé, sosie) ; compare au résultat épinglé `smoke-expected.json` |
| `npm run lab -- --seed <s> --sites <n> [--workers 4] [--report <md>]` | passage complet ; rapport dans `lab/out/<s>/report.md`, copié dans `<md>` si demandé. Code de sortie 1 s'il y a une fuite. |
| `npm run lab:repro -- --seed <s> --site <i> [--sites <n>]` | rejoue un seul site du monde ; résultats dans `lab/out/<s>-repro-<i>/` |
| `npm run lab:corpus` | relevé du corpus (réseau réel, lent, rarement) puis distillation |
| `node --experimental-strip-types lab/cli.ts report --out <dossier> [--md <fichier>]` | refait le rapport d'un dossier de résultats existant |

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
- Corpus : seule la première étape des formulaires en plusieurs étapes est relevée ; les étapes suivantes viennent du catalogue synthétique.
- Les délais de la chaîne (4 s, 60 s) sont réels : un passage de 200 sites dure longtemps, d'où les lots de 10 sites par profil et le parallélisme (`--workers`).
