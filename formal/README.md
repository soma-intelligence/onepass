# Modèle formel de OnePass

Modèles ProVerif 2.05 des constructions cryptographiques de OnePass. La documentation complète (modèle d'attaquant, hypothèses, abstractions, ce qui est prouvé et ce qui ne l'est pas) est dans [`docs/security/formal/README.md`](../docs/security/formal/README.md), les derniers résultats dans [`docs/security/formal/results.md`](../docs/security/formal/results.md).

- `proverif/common.pvl` : bibliothèque commune (types, AEAD avec engagement, HKDF, signatures, KEM hybride, Argon2).
- `proverif/*.pv` : un modèle par construction ; `sanity.pv` teste la bibliothèque et le harnais.
- `proverif/account_core.pvl` : processus du compte (création, déverrouillage, coffres, items), partagés par `account.pv` et ses deux variantes à KEM cassé. Un modèle charge une bibliothèque supplémentaire de `proverif/` après `common.pvl` par une ligne exacte `(* formal-lib: nom.pvl *)`.
- `proverif/rotation_core.pvl` : déclarations et processus de la rotation des clés ancrée dans les clés d'appareil (spec `2026-10-28-key-rotation-v2-design.md`), partagés par `rotation.pv` et ses deux témoins négatifs `rotation_autofollow.pv` (suivi sans confirmation de l'utilisateur) et `rotation_account_anchor.pv` (rotation authentifiée par une clé du compte d'avant), dont les attaques sont le résultat attendu. Modèle de conception, écrit avant le code.
- `proverif/sharing_core.pvl` : déclarations et processus du partage de coffres entre comptes (spec `2026-10-30-sharing-families-design.md`, section 17) : comptes Alice (propriétaire, Gérer), Bob (Modifier), Carol (Modifier, retirée) et Dave (Lire, malveillant), carnet de contacts vérifiés par canal authentifié, liste des membres signée, enveloppes avec `key_commit`, manifestes partagés, retrait à la génération g+1.
- `proverif/sharing.pv` : secret de ce qui est écrit après le retrait et de la clé de chaque génération, niveau Lien en lecture seule (décision 1), sanité du déroulé.
- `proverif/sharing_auth.pv` : même déroulé (processus recopié de `sharing.pv`), droit d'écrire face à un lecteur et à un retiré qui signent.
- `proverif/sharing_auth_keys.pv` : même déroulé, liste des membres signée par un gestionnaire et enveloppes engagées par `key_commit`.
- `proverif/sharing_member_rotation.pv` : rotation de l'identité d'un membre (section 12, décision 6), adoption seulement après le code (Lire) ou le QR en personne (Modifier, Gérer) ; charge `rotation_core.pvl` puis `sharing_core.pvl`.
- `proverif/sharing_server_directory.pv` : témoin négatif, clés des membres prises au serveur ; le coffre tombe (attaque attendue).
- `proverif/sharing_no_rekey.pv` : témoin négatif, retrait sans nouvelle génération ; Carol lit ce qui est écrit après (attaque attendue).
- `proverif/sharing_no_role_check.pv` : témoin négatif, lecteurs qui ne vérifient pas le rôle du signataire ; un manifeste signé par le lecteur Dave est accepté (attaque attendue).
- `proverif/sharing_member_autofollow.pv` : témoin négatif, adoption d'une rotation de membre sans geste ; Bob enveloppe la clé pour l'identité de l'attaquant (attaque attendue).
- `expected.txt` : résultat attendu de chaque requête (`fichier.pv | requête telle qu'imprimée | true|false`).
- `run.sh` : lance les modèles (300 s maximum par fichier), compare à `expected.txt`, écrit `docs/security/formal/results.md`.

Lancer : `make formal` à la racine (ou `formal/run.sh fichier.pv` pour un seul modèle). `PROVERIF` choisit le binaire (par défaut `proverif` dans le `PATH`, puis `~/.local/bin/proverif`), `FORMAL_TIMEOUT` le délai en secondes entières. Les journaux de ProVerif et `formal/out/results.md` (avec les temps) sont dans `formal/out/` (ignoré par git) ; seul un lancement complet réécrit `docs/security/formal/results.md`, sans les temps.
