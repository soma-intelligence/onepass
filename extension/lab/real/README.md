# Banc sur sites réels (`lab/real/`)

## But

Jouer l'extension comme un utilisateur réel, sur les vrais sites du top 1000 (Tranco, `lab/corpus/tranco.json`), avec une machine « déjà polluée » : un autre gestionnaire de mots de passe installé, certains sites déjà connectés, d'autres non. Le banc relève les erreurs de comportement de la carte de connexion (overlay), du menu de champ et des icônes, pour les corriger dans `extension/src`.

Règles produit vérifiées (l'oracle, `oracle.ts`) :

- **R1 carte utile seulement** : la carte de connexion n'apparaît que sur une page où l'utilisateur doit se connecter et où le coffre a un compte du site. Jamais sur une page connectée (menu de compte, « Se déconnecter », avatar), jamais sur une page sans formulaire de connexion (accueil, article, recherche, panier), jamais pour un champ de recherche ou de lettre d'information.
- **R2 tout reste cliquable** : à tout moment, les contrôles de la page (liens, boutons, champs) restent cliquables. Aucun cadre OnePass invisible ou transparent ne couvre la page ; la carte ne couvre que sa propre surface ; le × ferme tout de suite.
- **R3 pas de redondance** : jamais deux interfaces OnePass à la fois pour le même besoin (carte et menu de champ ouverts ensemble, deux cartes, deux icônes dans un champ, icône dans un champ qui n'en a pas besoin).
- **R4 pas de conflit avec un autre gestionnaire** : avec Bitwarden (réel) ou un gestionnaire simulé (1Password, LastPass, Dashlane), les icônes ne se superposent pas, deux menus ne s'ouvrent pas l'un sur l'autre, OnePass ne vole pas le focus et ne remplit pas par-dessus une valeur que l'autre vient de poser.
- **R5 aucune fuite, aucun envoi** : aucune requête autre que `GET`/`HEAD` ne part vers un site réel (filet `guard.ts`) ; aucun identifiant n'est jamais envoyé, même fictif.

## Trois sortes de cibles

| Sorte | Où | État de connexion |
| --- | --- | --- |
| `live` | la vraie URL du site, en lecture seule | non connecté |
| `profile` | la vraie URL, dans le profil Chrome de test où le testeur s'est connecté à la main | connecté (vrais cookies) |
| `replica` | copie locale de la vraie page (HTML capturé par `GET`), servie sous le vrai nom d'hôte résolu en local | connecté ou non, selon la variante |

Le profil connecté se prépare une fois avec `npm run lab:real-site:profile` : il ouvre Chrome for Testing sur un dossier de profil persistant (`lab/out/real-profile/`, ignoré par git) ; le testeur s'y connecte lui-même aux sites de son choix. Le banc ne tape jamais un vrai mot de passe et ne lit jamais les cookies hors du navigateur.

## Machine polluée

- **Bitwarden réel** : extension Chrome officielle, prise dans la release GitHub de `bitwarden/clients` (`managers/fetch-bitwarden.ts`, dossier `lab/out/managers/bitwarden/`), chargée non connectée (son icône et son menu de champ apparaissent quand même).
- **Gestionnaires simulés** (`managers/fake/`) : une extension MV3 qui imite le DOM et le comportement de 1Password (`com-1password-button`, menu en shadow DOM), LastPass (`data-lastpass-icon-root`, `data-lastpass-root`) et Dashlane (`data-dashlane-rid`, icône à droite du champ), choisi par site.
- Profil au passé chargé : historique, onglets ouverts, autres extensions courantes simulées (bloqueur, traduction) selon ce qui est faisable sans téléchargement supplémentaire.

## Coffre fictif

Un élément de connexion fictif par site du top 1000 (identifiant `lab-<n>@example.test`, mot de passe généré, jamais réel), plus des doublons et deux comptes sur une partie des sites. Coffre servi par l'hôte natif de développement, comme `lab/run/`.

## Parcours d'un utilisateur (`visit.ts`)

Pour chaque site : accueil, attente, défilement ; recherche du lien de connexion et visite de la page de connexion ; focus des champs, Échap, clics sur des contrôles de la page pendant que la carte est là ; fermeture par ×, rechargement (la carte ne doit pas revenir après ×) ; ouverture du menu de champ ; navigation vers une autre page du site. Jamais d'envoi de formulaire, jamais de clic sur un bouton qui envoie.

## Garde-fous réseau

- `GET` et `HEAD` seulement vers les sites réels ; tout `POST`, `PUT`, `PATCH`, `DELETE`, toute soumission de formulaire et tout `navigator.sendBeacon` sont coupés avant de partir (route Playwright et blocage de l'événement `submit`).
- `robots.txt` respecté (réutilise `lab/corpus/robots.ts`), au moins 5 s entre deux pages d'un même hôte, agent `OnePassLabReal`.
- Rien de personnel n'est écrit dans les résultats : noms de champs, hôtes, verdicts, captures d'écran de la zone de la carte.

## Sorties

`lab/out/real-<date>/` : `results.jsonl` (une ligne par site et par étape), `report.md` (violations par règle, puis par site, avec la capture), `shots/`.
