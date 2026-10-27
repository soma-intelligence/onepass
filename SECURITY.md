# Politique de sécurité

OnePass est un gestionnaire de mots de passe. Une faille y a des conséquences directes pour les gens qui s'en servent : nous préférons les apprendre par un signalement privé plutôt que par une publication.

## Périmètre

Dans le périmètre :

- le noyau Rust (`core/`) : cryptographie, format du coffre, synchronisation, restauration, import ;
- les applications Apple (`apple/`) : iOS, macOS, Watch, extensions et widgets ;
- l'extension de navigateur (`extension/`) et l'hôte natif (`core/onepass-native-host`, `core/onepass-bridge`) ;
- la ligne de commande (`core/onepass-cli`) et les interfaces locales (`core/onepass-ffi`, `core/onepass-mcp`, `core/onepass-ssh-agent`) ;
- la chaîne de fabrication : workflows GitHub Actions, dépendances, signatures.

Le modèle de menace et les garanties visées sont décrits dans `docs/security/README.md`.

## Signaler une vulnérabilité

Ne créez pas de ticket public pour une faille.

- Par courriel : `TODO-CONTACT` (adresse à renseigner avant la publication du dépôt). Chiffrez le message si vous le pouvez ; la clé publique sera publiée avec l'adresse.
- Par le signalement privé de GitHub (Security > Report a vulnerability), dès que le dépôt sera public.

Merci d'inclure :

- la version ou le commit concerné, la plateforme et la version du système ;
- une description de la faille et de son impact (quelles données, quel attaquant, quelles conditions) ;
- les étapes pour la reproduire, de préférence avec un jeu de données synthétique, jamais un vrai coffre ;
- une preuve de concept si vous en avez une, et vos pistes de correction éventuelles ;
- si vous souhaitez être crédité, le nom à utiliser.

## Délais

- Accusé de réception sous 72 heures.
- Première évaluation (faille confirmée ou non, gravité estimée) sous 7 jours.
- Correctif publié, ou plan de correction daté communiqué, sous 90 jours.

Si une faille est déjà exploitée, nous publions un correctif ou une mesure d'atténuation dès que possible, sans attendre la fin du délai.

## Divulgation coordonnée

Nous demandons de ne rien publier avant qu'un correctif soit disponible ou que les 90 jours soient écoulés, selon ce qui arrive en premier. Si le délai ne peut pas être tenu, nous le disons et nous convenons d'une date avec vous. Les personnes qui signalent sont créditées dans l'avis de sécurité, sauf demande contraire.

## Cadre protecteur pour la recherche de bonne foi

Nous n'engagerons aucune action en justice et ne demanderons aucune poursuite contre une personne qui recherche et signale une faille de bonne foi, dans le respect de ces règles :

- tester uniquement vos propres comptes, appareils et données, ou des données synthétiques ;
- ne pas accéder aux données d'autres personnes, ne pas les modifier ni les détruire ;
- ne pas dégrader un service partagé (pas de déni de service, pas de tests de charge sur CloudKit ou sur une infrastructure tierce) ;
- ne pas utiliser d'ingénierie sociale ni d'attaque physique contre des personnes ;
- nous laisser le délai raisonnable ci-dessus avant toute publication.

## Hors périmètre

- Les attaques qui exigent un appareil déjà compromis au niveau du système (racine, noyau, débogage de l'application par le propriétaire), ou un accès physique à un appareil déverrouillé.
- Un mot de passe maître faible ou réutilisé choisi par la personne.
- Les failles de la plateforme (iOS, macOS, navigateur, CloudKit) sans lien avec notre code ; signalez-les à l'éditeur concerné.
- Les rapports d'outils automatiques sans preuve d'impact, les en-têtes ou configurations sans conséquence démontrée.
- L'hameçonnage et l'ingénierie sociale.
- Les limites déjà documentées dans `docs/security/README.md` et dans les spécifications sous `docs/superpowers/specs/`.

## Versions prises en charge

OnePass n'a pas encore de version 1.0. Seule la branche `main` reçoit des correctifs de sécurité. Après la 1.0, cette section listera les versions maintenues.

## Chaîne d'approvisionnement

Les dépendances sont contrôlées par `cargo deny`, `cargo vet` et `npm audit` ; les actions GitHub sont épinglées par SHA de commit. Voir `docs/security/reproducible-builds.md`.
