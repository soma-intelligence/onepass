# Modèle formel de OnePass

Modèles ProVerif 2.05 des constructions cryptographiques de OnePass. La documentation complète (modèle d'attaquant, hypothèses, abstractions, ce qui est prouvé et ce qui ne l'est pas) est dans [`docs/security/formal/README.md`](../docs/security/formal/README.md), les derniers résultats dans [`docs/security/formal/results.md`](../docs/security/formal/results.md).

- `proverif/common.pvl` : bibliothèque commune (types, AEAD avec engagement, HKDF, signatures, KEM hybride, Argon2).
- `proverif/*.pv` : un modèle par construction ; `sanity.pv` teste la bibliothèque et le harnais.
- `proverif/account_core.pvl` : processus du compte (création, déverrouillage, coffres, items), partagés par `account.pv` et ses deux variantes à KEM cassé. Un modèle charge une bibliothèque supplémentaire de `proverif/` après `common.pvl` par une ligne exacte `(* formal-lib: nom.pvl *)`.
- `expected.txt` : résultat attendu de chaque requête (`fichier.pv | requête telle qu'imprimée | true|false`).
- `run.sh` : lance les modèles (300 s maximum par fichier), compare à `expected.txt`, écrit `docs/security/formal/results.md`.

Lancer : `make formal` à la racine (ou `formal/run.sh fichier.pv` pour un seul modèle). `PROVERIF` choisit le binaire (par défaut `proverif` dans le `PATH`, puis `~/.local/bin/proverif`), `FORMAL_TIMEOUT` le délai en secondes entières. Les journaux de ProVerif et `formal/out/results.md` (avec les temps) sont dans `formal/out/` (ignoré par git) ; seul un lancement complet réécrit `docs/security/formal/results.md`, sans les temps.
