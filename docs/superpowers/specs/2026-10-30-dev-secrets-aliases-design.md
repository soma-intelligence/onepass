# OnePass : secrets pour développeurs et alias d'email

Date : 2026-10-30
Statut : brouillon pour la revue du fondateur (rulings proposés, questions ouvertes en fin de document). Rien n'est implémenté.
Branche : `docs/dev-secrets-aliases`, depuis la `main` privée (`88468668`).
Portée : deux extras du produit. (A) gestion des secrets pour développeurs : `onepass run`, environnements, comptes de service pour la CI, intégration GitHub Actions, signature Git, audit. (B) alias d'email (« masquer mon adresse ») : service propre ou intégration de fournisseurs, création depuis l'autofill, stockage, réponse depuis un alias.

Specs lues et non refaites ici : architecture (`2026-10-25-onepass-architecture-design.md`, sections 4, 5, 9, 14), jalon 7 (`2026-10-25-milestone-7-mcp-ssh-design.md`), durcissement (`2026-10-26-mcp-ssh-hardening-design.md`), Secret Key de la CLI (`2026-10-28-cli-secret-key-design.md`), rotation v2 (`2026-10-28-key-rotation-v2-design.md`, branche `docs/key-rotation-v2`), prêt pour les agents (`2026-10-28-agent-ready-design.md`, branche `docs/agent-ready-spec`), et `docs/security/README.md`. Trois sessions parallèles écrivent en ce moment les specs partage et familles (`docs/sharing-families`), entreprise (`docs/enterprise`) et clients multiplateformes (`docs/cross-platform-clients`) ; les points de contact sont signalés (section 13).

## 1. Inventaire : ce qui existe, ce qui manque

### 1.1 Ce que OnePass couvre déjà (code sur `main`)

| Fonction | Où | État |
| --- | --- | --- |
| Références `onepass://<vault>/<item>/[<section>/]<champ>` | `onepass-core/src/reference.rs` (`parse_ref`, `Repository::resolve`) | livré : noms ou ids, refus des ambiguïtés, TOTP par `totp`, clé SSH en PEM |
| Lire un secret par référence | `onepass read <ref>` | livré |
| Lancer une commande avec des secrets injectés | outil MCP `run_with_secrets` (`onepass-mcp`), relais `onepass-mcp-relay` dans l'app Mac | livré, **réservé aux agents MCP** : appairage du client, portées, approbation, masquage (valeur, base64, hex), journal |
| Remplir un modèle | outil MCP `fill_template` (`{{ onepass://... }}`, fichier `0600`) | livré, MCP seulement |
| Agent SSH | `onepass-ssh-agent`, `onepass ssh-agent`, app Mac (`onepass-ffi/src/developer`) | livré : Ed25519, ECDSA, RSA SHA-2, `session-bind`, clés liées aux hôtes, transfert refusé, approbation par (clé, identité de code, destination) |
| Signature de commits Git par SSH | `sshsig.rs`, champ `git_signing` du modèle SSH Key, exception `git` du durcissement | livré côté agent : `ssh-keygen -Y sign` passe ; testé avec un `allowed_signers` (`onepass-cli/tests/ssh.rs`) |
| Identité des clients, appairage, autorisations courtes, limites de débit | `onepass-peer`, `onepass-guard` (`clients.rs`, `grants.rs`, `limits.rs`, `control.rs`) | livré |
| Journal d'audit chaîné et signé | `onepass-guard/src/audit.rs` | livré pour les surfaces `Mcp` et `Ssh` |
| Item API Credential | modèle 5.4 : clé, secret, environnement, nom de variable d'environnement, expiration | livré |
| Item Email avec alias répétables, adresse relais de Sign in with Apple | modèle 5.4 et 5.5 | livré (champ texte, aucune création) |
| Approbation sur iPhone, déverrouillage à distance pour agents | spec agent-ready | en revue, branche `feat/agent-ready` |

### 1.2 Ce qui manque, face à 1Password

| 1Password | OnePass aujourd'hui | Écart |
| --- | --- | --- |
| `op run` : lance une commande, résout les `op://` de l'environnement et d'un `--env-file`, masque la sortie | prévu en 9.1 de l'architecture, absent de la CLI (`main.rs` n'a ni `run` ni `inject`) ; le moteur existe dans `onepass-mcp` | **manque** la commande humaine |
| `op inject` : fichier modèle | `fill_template` côté MCP seulement | **manque** la commande humaine |
| Références `op://`, y compris dans un `.env` versionné | `onepass://` existe | manque la lecture d'un `.env` à références |
| Environments (bêta publique depuis le 2025-10-29) : jeux de variables, fichier `.env` monté par un tube nommé, invite d'autorisation à la lecture, Mac et Linux [1][2] | rien | **manque** |
| Service accounts : jeton non interactif, vaults choisis, limites de débit (Business : 10 000 lectures et 1 000 écritures par heure et par jeton) [4] | « plus tard, avec le serveur » (architecture 9.1 et 14) | **manque**, et OnePass n'a pas de serveur |
| `load-secrets-action` GitHub : jeton de service account, Connect ou Workload Identity (OIDC, bêta privée), sortie de pas ou variables [3] | rien | **manque** |
| Connect server : API REST auto-hébergée, cache, sans limite de débit [4] | rien | hors v1 (lié au futur serveur) |
| Signature Git : bouton « Configure Commit Signing » qui écrit `gpg.format ssh`, `user.signingkey`, `gpg.ssh.program = op-ssh-sign`, et un fichier `allowed_signers` [5] | la signature passe par l'agent, mais aucune aide à la configuration, et `ssh-keygen` ne lit pas `IdentityAgent` | **manque** l'outillage |
| Shell plugins (`gh`, `aws`...) | rien | hors périmètre de cette spec (suite possible) |
| Masked Email Fastmail, créé depuis le remplissage [9] | rien | partie (B) |

### 1.3 Bitwarden Secrets Manager, Doppler, Infisical

- **Bitwarden Secrets Manager** : produit séparé du gestionnaire. Comptes machine avec des jetons d'accès affichés une seule fois, droits par projet, CLI `bws`, action `bitwarden/sm-action` qui associe des ids de secrets à des noms de variables, `base_url` pour l'auto-hébergement [6]. Le générateur du gestionnaire crée aussi des alias chez addy.io, Fastmail, SimpleLogin, Firefox Relay, DuckDuckGo et Forward Email avec la clé d'API de l'utilisateur [11].
- **Doppler** : jetons de service par configuration ; identités de service account par OIDC (`doppler oidc login` échange le jeton de la CI contre un jeton court, plans Team et Enterprise) [7] ; `doppler run --fallback` garde une copie chiffrée locale (documentation tierce, non vérifiée sur la doc officielle).
- **Infisical** : identités machine, authentification OIDC depuis GitHub Actions (`id-token: write`, sujet du jeton vérifié), rotation automatique et secrets dynamiques à bail [8].

Leçon commune : la CI moderne évite le jeton statique (OIDC, jeton court), et le serveur de ces produits voit les secrets en clair (Doppler, Infisical en mode géré) ou tient les clés (Bitwarden SM chiffre de bout en bout côté client, mais le jeton d'accès suffit). OnePass n'a pas de serveur en v1 et refuse que le stockage soit de confiance : la solution doit tenir sans serveur, puis gagner l'OIDC quand le serveur auto-hébergé existera.

## 2. Principes communs aux deux parties

1. Seul `core` voit des secrets en clair (architecture, section 3). Le noyau ne fait aucun accès réseau : les appels HTTP (fournisseurs d'alias, téléchargements) sont faits par l'appelant (CLI, app, extension), le noyau construit les requêtes et lit les réponses, comme pour HIBP (sécurité, section 7).
2. Aucun changement de format existant. Les nouveautés sont des modèles d'item (architecture 5.2 : « un nouveau type = un nouveau modèle, sans migration »), des variantes ajoutées en fin d'énumération, des types de blob en ajout seul.
3. Chaque accès à un secret hors de l'app (CLI, CI, fournisseur d'alias) laisse une entrée dans le journal chaîné de `onepass-guard`.
4. Le comportement réel d'une protection est écrit tel quel : ce que le masquage, l'expiration d'un paquet ou un fournisseur ne garantissent pas est dit.

# Partie A : secrets pour développeurs

## 3. `onepass run`, `onepass inject` et références dans un `.env`

### 3.1 Approches

1. **Commandes CLI qui réutilisent le moteur MCP (retenue).** Le lanceur (`runner.rs`), le masquage (`mask.rs`) et les modèles (`template.rs`) de `onepass-mcp` passent dans une crate `onepass-exec`, dont dépendent `onepass-mcp` et `onepass-cli`. Une seule implémentation du masquage, déjà testée contre l'exfiltration en base64 et hexadécimal.
2. Réécrire dans la CLI. Deux masquages à maintenir, rejeté.
3. Passer par le serveur MCP en local (la CLI parle JSON-RPC à elle-même). Couplage absurde, rejeté.

Ruling: extraction de `runner`, `mask` et `template` dans `onepass-exec` - le code existe, est fuzzé et testé contre les abus, et le dupliquer créerait deux comportements de masquage - coût si faux : un déplacement de modules, sans changement de comportement.

### 3.2 Comportement

- `onepass run [--env-file <f>]... [--environment <ref>] [--no-masking] -- <cmd> [args]` :
  - lit chaque `--env-file` (syntaxe dotenv : `NOM=valeur`, commentaires `#`, guillemets simples ou doubles, pas d'interpolation `$VAR` ni de commande) ; une valeur qui commence par `onepass://` est une référence, les autres passent telles quelles ;
  - parcourt aussi l'environnement hérité : toute variable dont la valeur commence par `onepass://` est résolue (comportement de `op run`, utile en CI et dans les `Makefile`) ;
  - `--environment` charge un item Environment (3.4) ;
  - résout tout avant de lancer : une seule référence introuvable, ambiguë ou hors portée fait échouer la commande sans rien lancer (code 4) ;
  - lance `argv` directement, sans shell implicite, environnement hérité moins `ONEPASS_*` plus les variables résolues ;
  - stdout et stderr sont masqués par défaut (`<concealed:NOM>`), comme `run_with_secrets` ; `--no-masking` le coupe et le dit sur stderr ; une sortie vers un terminal (TTY) n'est masquée que ligne à ligne, ce qui casse les programmes interactifs : `--no-masking` est alors suggéré par le message.
  - Code de sortie : celui du programme. Signaux relayés (`SIGINT`, `SIGTERM`, `SIGHUP`).
- `onepass inject -i <modèle> -o <sortie> [--force]` : même syntaxe que `fill_template` (`{{ onepass://... }}`), sortie `0600`, refus d'écraser sans `--force`, refus d'écrire dans le dossier de données ; `-o -` écrit sur stdout seulement si stdout n'est pas un terminal.
- Pas de nouvelle syntaxe de référence. Les paramètres de requête à la `?ssh-format=` ne sont pas ajoutés : une clé SSH sort déjà en PEM OpenSSH.

Ruling: masquage actif par défaut dans `onepass run` - même défaut que `op run`, et une sortie de CI est un journal public ou semi-public - coût si faux : un drapeau à passer pour un programme interactif.

Ruling: aucune interpolation dans le `.env` - l'interpolation ferait d'un fichier versionné un petit langage, avec ses pièges (valeur qui contient `$`) ; le fichier ne porte que des noms et des références - coût si faux : écrire la valeur composée dans l'item.

### 3.3 Qui approuve

- **CLI autonome (Linux, ou Mac sans app)** : le déverrouillage actuel de la CLI (mot de passe sur `/dev/tty`, Secret Key dans le magasin du système). Le titulaire est l'appelant : pas d'invite par référence. Chaque `run` et `inject` écrit une entrée d'audit (section 7).
- **CLI sur un Mac avec l'app** : la CLI devient un client du socket de l'app, comme le relais MCP. Nouvelle surface `Cli` dans `onepass-guard` : identité du processus appelant par `onepass-peer` (premier ancêtre non lanceur), appairage, autorisations courtes (5 min par défaut) et Touch ID, exactement les règles du durcissement. Un agent IA qui a un shell et tape `onepass run` passe donc par les mêmes gardes que s'il appelait `run_with_secrets` : pas de contournement du MCP par la CLI.
- La grant d'un `run` couvre le chemin canonique du programme et l'empreinte SHA-256 de ses arguments-fichiers (règle du jalon 7 dans les apps, sécurité 11.1) ; un interpréteur (`sh`, `node`, `npm`, `make`) n'est jamais mémorisé.

Ruling: surface `Cli` soumise à l'appairage et aux grants quand l'app sert - sinon un agent appairé avec `metadata` seulement lirait tout par `onepass read` dans son shell - coût si faux : une invite Touch ID de plus par terminal toutes les 5 minutes, réglable jusqu'à 60.

### 3.4 Environnements

1Password Environments regroupe des variables par projet et par étape, et monte un `.env` virtuel [1][2]. Approches :

1. **Modèle d'item Environment (retenu).** Champs : projet*, étape* (menu : dev, staging, prod, autre), variables (section répétable : nom*, valeur masquée, ou lien vers un champ d'un autre item), notes. `onepass run --environment "onepass://Projet X/api prod"` injecte toutes ses variables. Un lien vers un champ (type « lien vers un autre item » existant) évite de recopier un secret déjà rangé dans un item API Credential : la rotation de la clé met à jour tous les environnements qui la citent.
2. Un vault par environnement. Lourd (un vault = une clé, un manifeste), et un environnement n'est pas une frontière de partage.
3. Seulement des `.env` à références versionnés. Gardé comme usage de base (3.2), mais sans vue d'ensemble dans l'app.

Ruling: modèle Environment, `.env` à références toujours accepté - un modèle s'ajoute sans migration, et l'app peut montrer « quels environnements utilisent cette clé » - coût si faux : un modèle de plus parmi 27.

`.env` monté par tube nommé (comme 1Password) : écarté de la v1. Une fois l'autorisation donnée, tout processus du même utilisateur lit le fichier jusqu'au verrouillage [2] ; c'est l'inverse de la règle « approbation par client » du durcissement. Question ouverte 2.

## 4. Comptes de service pour la CI

### 4.1 Contraintes

- La CI n'a ni mot de passe maître, ni Secret Key, ni appareil de confiance, ni accès à la base CloudKit privée du titulaire.
- OnePass n'a pas de serveur en v1. Le stockage (CloudKit, futur serveur) reste hostile.
- Rotation v2 : la confiance repose sur les clés d'appareil épinglées et sur l'utilisateur ; un appareil retiré garde tous les secrets du compte qu'il a connus (« le passé n'est pas protégé »). Un compte de service ne doit pas devenir un appareil : il ne doit ni signer de rotation, ni présenter d'appareil, ni suivre une rotation.
- 2SKD : rien de ce que tient la CI ne doit approcher l'AUK, le keyset ou la Secret Key.

### 4.2 Approches

1. **Paquet scellé pour un compte de service, sans serveur (retenu en phase 1).** Un appareil déverrouillé crée un compte de service (paire hybride ML-KEM-1024 + X25519 propre), puis scelle un paquet ne contenant que les variables choisies, chiffré vers ce compte et signé par le compte OnePass. Le paquet chiffré vit dans le dépôt ; le jeton du compte de service (la clé privée) vit dans les secrets de la CI. Proche de SOPS ou age, avec la cryptographie et le format d'archive existants.
2. **Compte de service membre de vaults, lecture par le serveur** (modèle Bitwarden SM, 1Password service accounts). Exige le serveur auto-hébergé, la liste signée des membres de vault (spec partage) et un protocole de lecture. Reporté.
3. **Clé partagée en deux, libérée par OIDC (retenu en phase 2, avec le serveur).** La clé du compte de service est dérivée de deux parts : une dans les secrets de la CI, une gardée par le serveur, libérée seulement contre un jeton OIDC de GitHub dont les revendications (`repository`, `ref`, `environment`, `job_workflow_ref`) correspondent à la règle du compte [10]. Le serveur ne peut rien déchiffrer seul ; un jeton de CI volé ne sert à rien hors d'un workflow autorisé.
4. **Relais à la Connect** chez l'utilisateur. Un service à exploiter pour chaque client, et un cache de secrets en clair sur sa machine. Rejeté pour la v1.
5. **Recopier les valeurs dans les secrets GitHub** (`gh secret set` depuis OnePass). Simple, mais GitHub tient alors les valeurs, sans trace côté OnePass, et sans rotation groupée. Gardé comme commande de confort hors du modèle de sécurité (question ouverte 5).

Ruling: paquet scellé en phase 1, OIDC à deux parts en phase 2 avec le serveur - la phase 1 marche sans serveur et sans tiers, la phase 2 retire le jeton statique comme Doppler et Infisical [7][8] sans donner les secrets au serveur - coût si faux : un format de paquet à faire évoluer (versionné dès le départ).

### 4.3 Le compte de service

Nouveau modèle d'item **Service Account**, rangé dans un vault au choix (synchronisé, chiffré, vu par tous les appareils du compte) :

- nom*, description, clé publique hybride (KEM ML-KEM-1024 + X25519, signature non nécessaire en phase 1), empreinte, date de création, appareil créateur (id), statut (actif, révoqué), date de révocation ;
- portée : la liste des références que ses paquets ont le droit de contenir (vide = aucune) ; un `seal` qui demande une référence hors portée est refusé ;
- liaison déclarée (texte, affichée et signée dans le paquet) : `github:<propriétaire>/<dépôt>` et éventuellement environnement GitHub ; en phase 1 c'est une information, en phase 2 c'est la règle OIDC ;
- paquets émis (section répétable : id du paquet, date, expiration, empreinte du chiffré, noms des variables).

**Jeton** : `OPSA1-` puis base32 de `version || id du compte de service (16) || graine (32)` avec le caractère de contrôle Luhn mod 32 de la Secret Key (sécurité 3.1). La graine donne la paire par `HKDF-SHA256(graine, info = "onepass/sa/kem/v1")` puis génération déterministe ML-KEM-1024 (FIPS 203, `d || z` de 64 octets) et X25519. Si `aws-lc-rs` n'expose pas la génération ML-KEM depuis une graine, le jeton porte la clé secrète sérialisée (3 200 octets, environ 5 Kio en base32, sous la limite de 48 Kio des secrets GitHub) ; point à trancher au plan. Le jeton est affiché une seule fois, jamais stocké par OnePass (ni dans l'item, ni dans le trousseau).

Création : `onepass ci account create <nom> --vault <v> --scope <ref>... [--bind github:o/r]` ou l'écran Réglages > Développeur > Comptes de service. Présence fraîche (Touch ID, sinon mot de passe maître), comme le retrait d'un appareil.

Ruling: compte de service = item, pas appareil ni membre de vault - il n'entre jamais dans le roster de la rotation v2, ne reçoit jamais de `KeyDelivery`, ne peut ni signer ni suivre une rotation, et ne lit que ce qu'on scelle pour lui - coût si faux : quand le partage arrivera, un compte de service membre d'un vault (approche 2) sera un second type, pas une migration.

Ruling: jeton jamais conservé par OnePass - qui vole le coffre ne doit pas obtenir les jetons de CI ; la CI est le seul endroit où il vit - coût si faux : un jeton perdu se remplace par un nouveau compte et un nouveau scellement.

### 4.4 Le paquet

Le paquet réutilise le conteneur d'archive du jalon 5 (sécurité, section 6) avec deux ajouts en fin d'énumération : type d'archive `CiBundle`, type de destinataire `ServiceAccount` (enveloppe KEM hybride vers la clé publique du compte de service, contexte `"onepass/ci-bundle/v1" || archive_id`, préfixé de sa longueur comme l'exige la section 3.3 de la sécurité pour toute nouvelle famille de contextes).

- En-tête (clair) : `archive_id`, type, date, un seul destinataire.
- Charge scellée : id du compte de service, liaison déclarée, `issued_at`, `not_after` (90 jours par défaut, 1 an au plus), numéro de série croissant par compte de service, et les paires `NOM -> valeur`. Aucune référence, aucun titre d'item, aucun id de vault : le dépôt ne doit rien apprendre du coffre.
- Signature : obligatoire, par la clé de signature hybride du compte OnePass (ML-DSA-87 + Ed25519, domaine `"onepass/ci-bundle/v1"`), sur le hash de l'en-tête et de la charge scellée, comme une archive de compte.
- Fichier : `.onepass/ci/<nom>.opci` dans le dépôt. Taille arrondie par paliers (padding du blob).

Vérification par la CI (`onepass-ci`, 4.6), dans cet ordre : format, signature contre la clé publique **épinglée dans le workflow** (`issuer`, empreinte de la clé de signature du compte, information publique), ouverture de l'enveloppe avec le jeton, déchiffrement, id du compte de service égal à celui du jeton, `not_after` dans le futur, série au moins égale à `min-serial` si le workflow le donne.

Ruling: paquet chiffré versionné dans le dépôt plutôt que stocké chez GitHub - le dépôt garde l'historique des scellements, une revue de code voit qu'un paquet a changé, et GitHub ne voit jamais les valeurs - coût si faux : chaque rotation d'un secret demande un commit (`reseal`).

Ruling: aucune référence ni métadonnée du coffre dans le paquet - un dépôt public ou un collaborateur ne doit pas apprendre la structure du coffre - coût si faux : `reseal` relit la portée dans l'item Service Account, pas dans le paquet.

Limite écrite : `not_after` et `min-serial` ne lient que l'outil honnête. Qui tient le jeton déchiffre tout paquet qui lui a été scellé, y compris d'anciens paquets de l'historique Git. La seule vraie révocation est la rotation des valeurs (4.5).

### 4.5 Rotation et révocation

- **Rotation d'un secret** : l'app repère qu'un item cité dans la portée d'un compte de service a changé depuis le dernier paquet (version d'item) et l'affiche (« Paquet CI périmé : Projet X / deploy »). `onepass ci reseal <compte> [--all]` rescelle avec une série plus haute ; l'utilisateur commite.
- **Révocation d'un compte de service = rotation** : marquer l'item révoqué (présence fraîche), puis la liste de toutes les valeurs que ce compte a pu lire (union des paquets émis) part dans Watchtower comme « Secrets exposés à un compte de service révoqué », avec un lien vers chaque item à faire tourner. Tant que ces valeurs n'ont pas changé chez leur fournisseur (AWS, Stripe...), la révocation n'a rien protégé : l'écran le dit.
- **Rotation des clés du compte OnePass (rotation v2)** : les paquets sont scellés vers la clé du compte de service, pas vers les clés du compte : ils restent lisibles. Leur signature, faite par l'ancienne identité, ne vérifie plus contre une épingle mise à jour. Après une rotation, l'app propose `reseal --all` et affiche la nouvelle empreinte `issuer` à mettre dans les workflows. La CI ne suit pas la lignée de rotation : elle ne peut pas faire l'étape utilisateur que la rotation v2 exige (G2), donc l'épingle se change par un commit, que l'humain relit.
- **Retrait d'un appareil** : l'appareil retiré connaissait les valeurs de ses vaults, donc celles des paquets. Watchtower ajoute les valeurs des portées de comptes de service aux « secrets connus d'un appareil retiré » (même logique que la rotation v2, section 11 : le passé n'est pas protégé).

Ruling: épingle `issuer` changée par un commit après une rotation de compte, sans suivi automatique de lignée par la CI - la rotation v2 exige que l'utilisateur confirme chaque nouvelle identité ; dans la CI, le commit relu est cette confirmation - coût si faux : un commit par dépôt après chaque rotation du compte, rare.

### 4.6 GitHub Actions et CI générique

- **Binaire `onepass-ci`** : Rust, statique (musl), Linux x86_64 et arm64, macOS arm64, sans état, sans réseau, sans dépendance sur `onepass-cli`. Commandes : `onepass-ci run --bundle <f> --issuer <empreinte> -- <cmd>` (masquage `onepass-exec`), `onepass-ci export --format github-env|dotenv|json`. Le jeton vient de la variable `ONEPASS_SERVICE_TOKEN`, effacée de l'environnement transmis à la commande. Construit par la chaîne de publication existante (`docs/security/release-pipeline.md`, builds reproductibles), signé, avec sommes de contrôle publiées.
- **Action `soma-intelligence/onepass-ci-action`** (composite, pas JavaScript) : télécharge une version épinglée de `onepass-ci`, vérifie sa somme SHA-256 inscrite dans l'action (pas téléchargée à côté), ouvre le paquet, émet `::add-mask::` pour chaque valeur puis expose les variables en sorties de pas (défaut) ou dans `GITHUB_ENV` (`export-env: true`), comme `load-secrets-action` [3]. Entrées : `bundle`, `issuer`, `min-serial`, `export-env`.
- **Usage recommandé dans la doc** : sorties de pas plutôt que `GITHUB_ENV` (une variable d'environnement est lue par toutes les étapes suivantes, y compris des actions tierces) ; jamais sur `pull_request_target` avec du code de fork ; secret `ONEPASS_SERVICE_TOKEN` attaché à un environnement GitHub protégé pour la prod.
- **CI générique** (GitLab, Buildkite, Woodpecker, cron) : `onepass-ci run`, même contrat. Pas d'intégration dédiée en v1.

Ruling: action composite qui épingle la somme du binaire dans son propre code - une action JavaScript embarque un `node_modules` à auditer ; une somme lue à côté du binaire téléchargé ne prouve rien - coût si faux : une mise à jour de l'action par version de `onepass-ci`.

### 4.7 Phase 2 : OIDC à deux parts (avec le serveur auto-hébergé)

Esquisse, détaillée dans la spec du serveur :

- La graine du compte de service devient `HKDF(part_ci || part_serveur, "onepass/sa/seed/v2")`. `part_ci` est dans les secrets de la CI, `part_serveur` est gardée par le serveur, chiffrée au repos, associée à une règle OIDC (émetteur `https://token.actions.githubusercontent.com`, `repository`, `ref`, `environment`, `job_workflow_ref`) [10].
- Le job demande un jeton OIDC (`permissions: id-token: write`), le présente au serveur, qui vérifie la signature et les revendications puis rend `part_serveur` ; le serveur journalise chaque libération (dépôt, exécution, commit) : c'est l'audit des accès CI que la phase 1 ne peut pas avoir.
- Le serveur seul ne déchiffre rien (il lui manque `part_ci`) ; un `part_ci` exfiltré ne sert à rien hors d'un workflow qui satisfait la règle ; révoquer = effacer `part_serveur`, effet immédiat pour les prochains jobs. Le passé reste non protégé (anciens jobs).

## 5. Git

### 5.1 Signature des commits

Existant : l'agent signe `SSHSIG` pour l'espace `git` avec une clé `git_signing`. Manque : la configuration, et le fait que `ssh-keygen` lit `SSH_AUTH_SOCK`, pas l'option `IdentityAgent` de `~/.ssh/config` que OnePass recommande.

- **`onepass-ssh-sign`** : petit exécutable (livré avec la CLI et dans `OnePass.app/Contents/Helpers/`) qui fixe `SSH_AUTH_SOCK` sur le socket de l'agent OnePass puis exécute `/usr/bin/ssh-keygen` (chemin absolu) avec les arguments reçus. Équivalent de `op-ssh-sign` [5]. Aucune clé, aucune logique de signature.
- **`onepass git signing setup <item> [--global | --repo] [--apply]`** : affiche les commandes `git config` (`gpg.format ssh`, `user.signingkey "key::<clé publique>"`, `gpg.ssh.program <chemin de onepass-ssh-sign>`, `commit.gpgsign true`, `tag.gpgsign true`). Sans `--apply`, rien n'est écrit. Avec `--apply`, seulement la configuration du dépôt courant (`.git/config`) ; `--global` n'écrit jamais, il affiche. Vérifie que l'item a `git_signing = oui`, sinon propose de le cocher.
- **`allowed_signers`** : `onepass git signing allowed-signers --out <f>` écrit `<email> namespaces="git" <clé publique>` pour chaque clé `git_signing` (email tiré du Login GitHub ou GitLab lié, sinon demandé) et affiche la ligne `gpg.ssh.allowedSignersFile`.
- App Mac : Réglages > Développeur > « Configurer la signature Git » fait la même chose (aperçu, puis écriture dans un dépôt choisi).

Ruling: jamais d'écriture dans la configuration Git globale, aperçu par défaut - même règle que `ssh-key config` (jamais `~/.ssh/config`) : l'utilisateur garde la main sur ses fichiers - coût si faux : une commande copiée à la main.

### 5.2 Authentification HTTPS

`onepass git credential` : assistant d'identification Git (`credential.helper`), protocole `get` seulement. Pour `host=github.com`, il cherche un item API Credential ou Login dont l'URL correspond (règle de correspondance de domaine du noyau, PSL), renvoie `username` et `password` (le jeton). Surface `Cli`, donc appairage et grant sous l'app. `store` et `erase` sont ignorés (OnePass n'enregistre rien en silence). Milestone D2.

## 6. Ce que les agents gagnent

Rien de nouveau côté MCP : `run_with_secrets` accepte en plus `environment: <ref>` (un item Environment) et `env_file: <chemin>` (lu par le relais, références résolues par l'app). Mêmes portées (`use`), mêmes approbations.

## 7. Audit des accès aux secrets

- Le journal de `onepass-guard` gagne la surface `Cli` (actions `read`, `run`, `inject`, `git_credential`) et la surface `Ci` (actions locales `sa_create`, `seal`, `reseal`, `sa_revoke`), avec les champs du durcissement (`client_id`, décision, ids de vault et d'item, jamais de valeur ni de titre). Les anciennes lignes restent vérifiables (champs optionnels).
- CLI autonome : le journal est dans le dossier de données de la CLI, mêmes garanties et mêmes limites (sécurité 11.1).
- `onepass audit --surface cli|ci|mcp|ssh` filtre.
- **Ce que la phase 1 ne sait pas** : quand la CI déchiffre un paquet. Il n'existe aucun point de passage. L'audit côté OnePass s'arrête au scellement ; les journaux d'exécution de GitHub sont la seule trace. La phase 2 (serveur) journalise chaque libération de part.
- Watchtower : « secrets jamais scellés depuis 90 jours », « paquet expiré », « compte de service sans paquet ».

## 8. Modèle de menace (partie A)

Actifs : valeurs des secrets, jeton du compte de service, clé de signature du compte (qui authentifie les paquets).

| Attaquant | Capacités | Défenses | Résidu |
| --- | --- | --- | --- |
| A1. Dépendance malveillante dans un job de CI | Lit l'environnement et les fichiers du job | Sorties de pas plutôt que `GITHUB_ENV`, portée minimale par compte de service, un compte par dépôt et par environnement | Elle lit ce que le job reçoit. Aucun outil ne l'empêche. Rotation après incident. |
| A2. Fuite du jeton (journal, fork, poste d'un mainteneur) | Déchiffre tous les paquets scellés pour ce compte, historique Git compris | Masquage, jeton jamais chez OnePass, révocation = rotation des valeurs (4.5), phase 2 OIDC | En phase 1, une fuite du jeton = fuite des valeurs du périmètre jusqu'à leur rotation. |
| A3. Collaborateur ou dépôt hostile | Modifie ou remplace le paquet, rejoue un ancien paquet | Signature du compte épinglée par `issuer`, série et `not_after` | Rejouer un ancien paquet ne donne que d'anciennes valeurs, qui doivent avoir tourné. Un `issuer` changé dans le workflow se voit en revue. |
| A4. Stockage hostile (CloudKit) | Réécrit l'item Service Account | Item scellé et manifeste signé (noyau) | Aucun nouveau. |
| A5. Agent IA avec un shell local | Tape `onepass run` ou `onepass read` | Surface `Cli` appairée et approuvée sous l'app (3.3) | CLI autonome : l'agent qui a le mot de passe sur le terminal a tout, comme aujourd'hui. |
| A6. Appareil retiré (T1 de la rotation v2) | Connaît les valeurs, l'ancienne identité, peut signer un paquet à l'ancienne identité | Épingle `issuer` mise à jour après la rotation, Watchtower liste les secrets à faire tourner | Avant la mise à jour de l'épingle, il peut faire accepter un paquet forgé à la CI. D'où : `reseal --all` et changement d'épingle proposés dans le même écran que la rotation. |
| A7. Processus local du même uid pendant `onepass run` | Lit `/proc/<pid>/environ` (Linux) ou la mémoire | Hors périmètre (même uid) | Documenté. |

Hors périmètre : un runner de CI compromis au niveau système ; GitHub lui-même.

# Partie B : alias d'email

## 9. Service propre ou fournisseurs

### 9.1 Ce qu'un service propre demande

Un service de transfert, c'est :

- **Réception** : MX sur un ou plusieurs domaines, SMTP entrant, anti-spam en entrée (sinon OnePass transfère du spam et sa réputation tombe).
- **Transfert** : réécriture de l'expéditeur (SRS) pour que SPF passe, signature DKIM du domaine d'alias, ARC pour garder le résultat d'authentification d'origine, DMARC strict, rDNS des IP. Les plaintes de délivrabilité des auto-hébergeurs de SimpleLogin viennent presque toujours de DKIM ou du rDNS [12] ; le port 25 sortant n'est pas ouvert chez tous les hébergeurs [12].
- **Réponse** : alias inverses par correspondant, réécriture des en-têtes, suppression des en-têtes qui trahissent la vraie adresse (`Received`, `X-Originating-IP`), gestion des rebonds (VERP).
- **Abus** : un service d'alias gratuit attire le spam sortant et les inscriptions en masse ; il faut un guichet abuse, des limites par compte, des listes de blocage, et répondre aux réquisitions.
- **Coût** : quelques serveurs et IP dédiées à réputation chauffée (estimation : 50 à 300 USD par mois au départ, hors temps humain), plus l'astreinte délivrabilité et abus, qui est le vrai coût pour une équipe d'une personne.
- **Vie privée** : le service doit connaître la correspondance alias vers vraie adresse en clair (il doit transférer) et voit chaque message en clair, sauf chiffrement PGP au transfert. OnePass deviendrait l'opérateur qui voit le courrier de ses utilisateurs, à l'opposé de son modèle « le stockage ne voit rien ».

### 9.2 Fournisseurs existants

| Fournisseur | API | Code et auto-hébergement | Réponse depuis l'alias | PGP | Remarques |
| --- | --- | --- | --- | --- | --- |
| SimpleLogin (Proton) | REST, clé d'API, alias aléatoire (`mode=uuid` ou `word`) ou personnalisé (suffixe signé), contacts = alias inverses [13] | AGPL-3.0, auto-hébergeable [12] | alias inverse par contact (offre payante pour certains usages) [13] | oui, par boîte | Domaine personnalisé possible |
| addy.io (ex-AnonAddy) | REST, clé d'API, création, désactivation, suppression, opérations en masse [15] | AGPL-3.0, auto-hébergeable [14] | réponse par l'adresse de transfert ; envoi depuis un alias | oui : clé OpenPGP par destinataire, sujet protégé, réponses chiffrées puis déchiffrées par le serveur avant envoi [14] | Gratuit : 10 alias sur domaine partagé, alias standard illimités, bande passante bornée (chiffres de tiers, à vérifier) [15] |
| Fastmail Masked Email | JMAP, capacité propre, `MaskedEmail/get` et `MaskedEmail/set`, `forDomain`, seule une adresse qui n'a jamais reçu de courrier peut être détruite [9] | non | native : la boîte Fastmail envoie depuis l'adresse masquée | non (Fastmail est la boîte) | Aucun tiers de plus que la boîte mail ; 1Password l'utilise, requêtes directes du client vers `api.fastmail.com` [9] |
| iCloud Hide My Email | **aucune API publique** ; l'ouverture aux apps tierces annoncée pour Ventura a disparu ; seuls des outils non officiels utilisent des points d'accès privés avec cookies de session [16] | non | via Mail iCloud | non | Impossible à créer depuis OnePass |
| DuckDuckGo, Firefox Relay | API existantes, utilisées par le générateur de Bitwarden [11] | non (Relay : code ouvert, non auto-hébergeable simplement) | limitée | non | Seconde vague |

### 9.3 Approches

1. Service propre. Voir 9.1 : coût humain, réputation, vie privée inverse du modèle. Rejeté pour la v1.
2. **Intégrer les fournisseurs avec la clé d'API de l'utilisateur (retenu).** OnePass ne voit jamais le courrier, n'a aucun serveur à tenir, et l'utilisateur choisit son tiers (y compris son propre SimpleLogin ou addy.io auto-hébergé, par une URL de base).
3. Service propre bâti sur SimpleLogin auto-hébergé, plus tard, si une offre payante le justifie. Gardé ouvert (question ouverte 9), sans engagement.

Ruling: intégration de fournisseurs, aucun service de transfert OnePass en v1 - tout service de transfert voit le courrier en clair et la correspondance des alias ; OnePass n'a ni l'équipe abus ni la réputation d'IP, et ce serait le premier serveur de confiance du produit - coût si faux : un adaptateur de plus le jour où OnePass aurait son propre domaine d'alias.

Ordre des adaptateurs : SimpleLogin et addy.io d'abord (code ouvert, auto-hébergeables, URL de base réglable), Fastmail ensuite, DuckDuckGo et Firefox Relay plus tard. iCloud Hide My Email : saisie manuelle seulement (9.6).

## 10. Conception des alias

### 10.1 Noyau : adaptateurs sans réseau

Module `onepass-core::alias` (ou crate `onepass-alias` si le noyau doit rester petit) :

- `trait AliasProvider` : `build_create(&self, req: &CreateAlias) -> HttpRequest`, `parse_create(&self, resp: &HttpResponse) -> Result<RemoteAlias>`, idem pour `disable`, `delete`, `list`, `create_reverse` (si le fournisseur sait faire). `HttpRequest` = méthode, URL, en-têtes, corps ; aucune E/S.
- Implémentations : `SimpleLogin { base_url }`, `Addy { base_url }`, `FastmailJmap` (session JMAP puis `MaskedEmail/set`).
- Réponses traitées comme hostiles : taille plafonnée (1 Mio), JSON strict, adresse renvoyée validée (syntaxe RFC 5321, longueur, domaine dans la liste attendue du fournisseur ou du domaine personnalisé), cible de fuzzing par adaptateur.
- La CLI exécute par `/usr/bin/curl` (chemin absolu, comme HIBP) ; l'app par `URLSession` éphémère sans cookies ; l'extension ne fait jamais l'appel elle-même (10.3).

### 10.2 Stockage

- **Clé d'API du fournisseur** : un item API Credential existant, avec un champ menu nouveau « fournisseur d'alias » (SimpleLogin, addy.io, Fastmail) et l'URL de base. Synchronisé et chiffré comme tout item, donc disponible sur tous les appareils. Un réglage de compte (dans le meta du vault Personnel, lié au manifeste) désigne l'item par défaut.
- **Alias** : sur le Login créé ou mis à jour, le champ email reçoit l'adresse, et une section `Alias` (champs ajoutés au modèle Login, en fin) porte : fournisseur, id distant, adresse, boîte de destination (libellé), créé le, état (actif, désactivé, supprimé chez le fournisseur), alias inverses (répétable : correspondant, adresse inverse). Un alias créé sans Login (bouton du générateur) devient un item Email avec la même section.
- Vue « Alias » dans la barre latérale : groupée par fournisseur, avec « alias jamais utilisés » (créés mais sans Login enregistré, 10.3).

Ruling: la clé d'API du fournisseur est un item synchronisé, pas un réglage par appareil - l'utilisateur crée des alias depuis l'iPhone comme depuis le Mac, et l'item profite du chiffrement, du manifeste et de Watchtower (expiration) - coût si faux : qui lit le coffre déverrouillé obtient la clé d'API (section 11, B3).

### 10.3 Création depuis le remplissage

**Extension navigateur (Mac, par l'app)** :

1. Sur un champ email d'un formulaire d'inscription (détection existante des formulaires « nouveau mot de passe », champ `autocomplete="email"` ou classifieur), le menu en ligne (iframe de l'origine de l'extension) propose « Créer un alias » à côté des adresses connues.
2. Geste de l'utilisateur obligatoire (règle 6.3 : jamais au chargement). L'extension envoie à l'app par le pont existant : origine de la page (vérifiée par l'extension, jamais lue dans la page) et id du champ. Aucune clé d'API dans l'extension.
3. L'app construit la requête (adaptateur), l'exécute, valide la réponse, renvoie l'adresse ; l'extension remplit le champ.
4. Un Login en attente est créé en mémoire de l'app avec la section Alias ; il est enregistré à la soumission du formulaire avec le mot de passe (flux existant « enregistrer à la soumission »). Si la page est abandonnée, l'alias est rangé en « alias jamais utilisés », avec « Supprimer chez le fournisseur » (pour Fastmail, possible tant qu'il n'a rien reçu [9]).
5. Limite : 10 créations par heure et par appareil, pour qu'une page piégée qui multiplie les champs ne vide pas le quota du fournisseur.

**Mode autonome Windows et Linux** : l'extension tient `core` en WASM et le coffre déverrouillé ; elle fait l'appel HTTP elle-même, la clé d'API restant en mémoire le temps de la requête. Même geste, même limite. À trancher avec la spec multiplateforme.

**iOS et iPadOS** :

- Insertion de texte AutoFill (iOS 18+, déjà utilisée pour « n'importe quel champ ») : une entrée « Nouvel alias » dans la liste proposée par l'extension. L'extension appelle le fournisseur (réseau autorisé dans l'extension, mémoire très en dessous de 120 Mo), insère l'adresse, et crée l'item Email avec la section Alias. Le domaine de l'app ou du site n'est connu que si le système le donne (`serviceIdentifiers`).
- Éditeur de Login dans l'app : bouton « Générer un alias » à côté du champ email.
- App Intent « Créer un alias » (Raccourcis), qui renvoie l'adresse sans biométrie : une adresse d'alias n'est pas un secret.
- Après un redémarrage, si l'extension n'a pas le keyset, elle ouvre l'app (règle 4.1 existante).

Ruling: aucun appel au fournisseur depuis l'extension sur Mac, toujours par l'app - la clé d'API ne doit pas exister dans le processus du navigateur, qui exécute du contenu web hostile - coût si faux : un aller-retour par le pont natif, quelques dizaines de millisecondes.

### 10.4 Ce qui est envoyé au fournisseur

Par défaut : seulement ce que l'API exige (clé, mode aléatoire). Pas de note, pas de `forDomain`, pas de préfixe lisible (`github.xyz@...`). Option « Aider à trier chez le fournisseur » : envoie le domaine du site en note (`forDomain` pour Fastmail, `note` pour SimpleLogin, `description` pour addy.io). Les alias sont générés en mode aléatoire (`uuid` chez SimpleLogin), jamais à partir du nom du site.

Ruling: aucune métadonnée de site envoyée par défaut - le fournisseur apprendra l'expéditeur au premier courrier, mais pas la liste des sites où l'utilisateur s'est inscrit sans y recevoir de courrier, ni l'heure exacte où il visitait le formulaire associé à un domaine - coût si faux : un tri un peu moins pratique dans le tableau de bord du fournisseur.

### 10.5 Répondre depuis un alias

OnePass n'est pas un client mail. Il aide à obtenir la bonne adresse d'envoi :

- **SimpleLogin** : « Écrire depuis cet alias » demande l'adresse du correspondant, crée le contact par l'API (alias inverse), range l'adresse inverse dans la section Alias, puis la copie (presse-papiers 90 s) ou ouvre un `mailto:` vers elle. Le courrier envoyé à l'alias inverse depuis la boîte vérifiée part depuis l'alias [13].
- **addy.io** : même bouton, adresse d'envoi au format du fournisseur (calculée par l'adaptateur selon la documentation addy.io) ; la réponse à un courrier transféré fonctionne déjà par l'adresse de réponse réécrite [14].
- **Fastmail** : rien à faire : dans Fastmail, l'utilisateur choisit l'adresse masquée comme expéditeur. OnePass l'explique dans la fiche.
- **iCloud** : Mail iCloud gère l'envoi depuis Hide My Email ; OnePass l'explique.

### 10.6 iCloud Hide My Email

Pas d'API publique [16] : pas de création. L'app propose « Ajouter un alias iCloud existant » (saisie ou collage, fournisseur `iCloud`, sans id distant) pour que la vue Alias et Watchtower soient complètes. L'adresse relais de Sign in with Apple, déjà enregistrée (5.5), apparaît dans la même vue. Les outils qui appellent les points d'accès privés d'iCloud avec des cookies de session sont exclus : ils demanderaient de manipuler la session Apple de l'utilisateur.

### 10.7 Watchtower et cycle de vie

- « Alias chez un fournisseur sans clé d'API valide » (clé révoquée ou expirée) : création impossible, alias existants toujours valides chez le fournisseur.
- « Alias jamais utilisés » (10.3) et « alias désactivés encore liés à un Login actif » (le site ne peut plus écrire, par exemple pour une réinitialisation de mot de passe).
- **Dépendance au fournisseur** : un compte dont l'email de récupération est un alias dépend du fournisseur. Watchtower compte, par fournisseur, les Logins dont l'adresse est un alias de ce fournisseur, et recommande un domaine personnalisé (SimpleLogin et addy.io le permettent) pour les comptes importants : si le fournisseur ferme, le domaine se rebranche ailleurs.
- `onepass alias list|create|disable|delete|sync` (CLI) ; `sync` relit la liste distante et signale les écarts (alias supprimé chez le fournisseur, alias inconnu de OnePass) sans rien supprimer de lui-même.

## 11. Modèle de menace (partie B)

Actifs : la vraie adresse, la liste des sites de l'utilisateur, la clé d'API du fournisseur, la capacité à recevoir les courriers de réinitialisation.

| Attaquant | Capacités | Défenses | Résidu |
| --- | --- | --- | --- |
| B1. Le fournisseur | Voit la vraie adresse, tous les alias, leurs dates, chaque courrier transféré, l'IP des appels d'API | Choix du fournisseur par l'utilisateur, auto-hébergement possible, rien envoyé par défaut (10.4), PGP chez SimpleLogin et addy.io | Il voit le courrier. C'est le contrat d'un service de transfert ; Fastmail est la boîte elle-même. |
| B2. Fournisseur fermé ou compte suspendu | Les alias cessent de recevoir | Watchtower « dépendance », domaine personnalisé recommandé, export de la liste | Récupération de compte bloquée si l'alias était l'email de récupération. Dit dans l'app. |
| B3. Vol de la clé d'API | Créer, désactiver, supprimer des alias, lister les sites ; selon le fournisseur, ajouter une boîte de destination (vérifiée par courrier chez SimpleLogin et addy.io) | Clé dans un item chiffré, jamais dans l'extension sur Mac, jamais dans les journaux, Watchtower rappelle de la faire tourner, portée minimale si le fournisseur en propose | Qui a le coffre déverrouillé a la clé. Désactiver tous les alias est un déni de service grave (plus de courriers de réinitialisation). |
| B4. Page web hostile | Déclenche le menu sur de faux champs, tente des créations en boucle | Geste obligatoire, iframe de l'extension, 10 créations par heure | Une création par geste trompé, rangée en « jamais utilisés ». |
| B5. Réponse hostile du fournisseur (ou réseau) | Renvoie une adresse piégée (séquences de contrôle, domaine inattendu, taille énorme) | Validation stricte, domaine attendu, plafond, fuzzing | Aucun. |
| B6. Stockage hostile | Réécrit l'item | Noyau (manifeste signé) | Aucun nouveau. |

Ce que OnePass apprend : rien. Aucun serveur OnePass n'est sur le chemin.

# Commun

## 12. Jalons

Chaque jalon a son plan TDD.

| Jalon | Contenu | Dépend de |
| --- | --- | --- |
| D1 | `onepass-exec` (extraction), `onepass run`, `onepass inject`, `.env` à références, surface `Cli` dans le journal ; CLI autonome | `main` |
| D2 | Surface `Cli` servie par l'app Mac (appairage, grants, Touch ID), `onepass git credential` | jalon 7 dans les apps |
| D3 | `onepass-ssh-sign`, `onepass git signing setup`, `allowed-signers`, écran de l'app | `main` |
| D4 | Modèle Environment, `run --environment`, `run_with_secrets` avec `environment` et `env_file` | D1 |
| D5 | Comptes de service phase 1 : modèle Service Account, jeton, paquet `CiBundle`, `onepass ci account|seal|reseal|revoke`, Watchtower, binaire `onepass-ci` | D1, conteneur d'archive |
| D6 | Action GitHub, publication reproductible de `onepass-ci`, documentation CI | D5, chaîne de publication |
| D7 | Phase 2 OIDC à deux parts | serveur auto-hébergé (hors v1) |
| E1 | `onepass-core::alias`, adaptateurs SimpleLogin et addy.io, CLI `onepass alias`, item API Credential « fournisseur d'alias » | `main` |
| E2 | App Mac et extension : « Créer un alias », section Alias, vue Alias, Watchtower | E1, jalon 4 |
| E3 | iOS : insertion de texte AutoFill, éditeur, App Intent | E2, jalon 3 |
| E4 | Fastmail JMAP, réponses (alias inverses), saisie iCloud | E1 |

Ordre proposé : D1, D3, E1, D5, D6, E2, D2, D4, E3, E4. D1 et D3 ferment les écarts les plus visibles face à `op` pour un coût faible ; E1 est indépendant.

## 13. Interactions avec les autres specs

- **Rotation v2** : comptes de service hors roster ; après une rotation, l'écran de fin propose `reseal --all` et montre la nouvelle empreinte `issuer` ; Watchtower ajoute les portées des comptes de service aux secrets connus d'un appareil retiré.
- **Partage et familles** (en cours) : un compte de service membre d'un vault partagé (approche 4.2-2) relève de cette spec-là. Le modèle Service Account de la phase 1 est indépendant des membres de vault.
- **Entreprise** (en cours) : la phase 2 OIDC, les comptes de service gérés par une organisation et l'audit centralisé en dépendent.
- **Clients multiplateformes** (en cours) : création d'alias en mode autonome Windows et Linux (10.3), `onepass-ci` sous Windows.
- **Prêt pour les agents** : un `run` de la CLI sous l'app peut être approuvé depuis l'iPhone par le même chemin, sans changement de protocole.

## 14. Tests

**Partie A**

- `onepass-exec` : les tests existants du masquage et du lanceur suivent l'extraction sans changement (même comportement octet pour octet).
- `.env` : guillemets, commentaires, lignes vides, `export NOM=`, valeur avec `=`, refus de `$VAR` interpolé (gardé littéral), fichier de 1 Mio au plus, propriété « aucune panique » (fuzzing).
- `onepass run` : référence introuvable ou ambiguë = rien n'est lancé (sonde : fichier témoin non créé) ; masquage en clair, base64, hex ; `ONEPASS_*` absentes de l'enfant ; code de sortie relayé ; signaux relayés ; `--no-masking` annoncé sur stderr.
- `onepass inject` : refus d'écraser, sortie `0600`, refus dans le dossier de données, `-o -` refusé vers un terminal.
- Surface `Cli` sous l'app : client non appairé refusé, grant expirée, agent appairé `metadata` seulement qui tente `onepass read` (refusé, approbateur jamais appelé).
- Paquet : aller-retour ; signature d'un autre compte refusée ; `issuer` faux refusé ; un octet modifié de l'en-tête, de l'enveloppe ou de la charge refusé ; jeton d'un autre compte de service refusé ; `not_after` passé refusé ; série sous `min-serial` refusée ; référence hors portée refusée au scellement ; aucune référence, aucun titre ni id de vault dans le fichier (recherche d'octets) ; vecteur hexadécimal figé du format.
- Jeton : caractère de contrôle (substitution, transposition), refus d'un mauvais préfixe ou d'une mauvaise version, jeton absent de l'item, du journal et de la sortie JSON.
- Rotation v2 : après une rotation de compte, l'ancien paquet vérifie avec l'ancienne épingle et échoue avec la nouvelle ; `reseal --all` produit des paquets qui vérifient avec la nouvelle ; un paquet signé par l'identité d'un appareil retiré est refusé dès que l'épingle a changé.
- Révocation : la liste Watchtower contient exactement l'union des valeurs des paquets émis.
- `onepass-ci` : test de bout en bout dans un conteneur Linux sans réseau ; l'action GitHub testée dans le dépôt (workflow avec paquet de test et jeton de test, valeurs synthétiques), y compris une somme de binaire fausse (échec).
- Git : `onepass git signing setup --apply` sur un dépôt temporaire, `git commit -S` réussit par l'agent et `git log --show-signature` vérifie avec le `allowed_signers` généré ; `--global` n'écrit rien (configuration globale isolée par `GIT_CONFIG_GLOBAL`) ; clé sans `git_signing` refusée par l'agent (existant).
- Assistant Git : `get` pour un hôte connu, hôte sosie refusé (PSL), `store` et `erase` sans effet.
- Audit : chaque commande ci-dessus écrit une entrée, la chaîne vérifie, aucune valeur dans le journal.

**Partie B**

- Adaptateurs : requêtes construites comparées à des fixtures (méthode, URL, en-têtes, corps) ; réponses réelles enregistrées et anonymisées ; réponses hostiles (JSON tronqué, 2 Mio, adresse avec CR LF ou ESC, domaine inattendu, champs en trop) refusées ; cible de fuzzing par adaptateur.
- Rien d'envoyé par défaut : aucune requête de création ne contient le domaine du site sans l'option (assertion sur le corps).
- Extension : Playwright sur une page piégée (dix champs email cachés, déclenchement sans geste, iframe d'un autre site) : aucune création sans geste, aucune dans une iframe d'une autre origine, plafond horaire ; la clé d'API n'apparaît jamais dans les messages du pont (inspection des trames).
- Flux complet contre un faux fournisseur local : création, remplissage, enregistrement à la soumission, abandon (alias en « jamais utilisés »), suppression.
- iOS : test UI de l'insertion de texte avec un faux fournisseur ; extension sans keyset ouvre l'app.
- Réponses : création d'un contact SimpleLogin (faux serveur), adresse inverse rangée, presse-papiers effacé.
- `alias sync` : alias supprimé à distance signalé, rien supprimé localement.
- Manuel, `#[ignore]` : un aller-retour réel par fournisseur avec un compte de test, lancé à la main.

## 15. Hors périmètre

- Service de transfert d'email OnePass.
- Connect server, API REST, secrets dynamiques à bail, rotation automatique chez les fournisseurs de secrets (AWS, Stripe).
- Shell plugins (`gh`, `aws`, `stripe`) : suite naturelle de la surface `Cli`, spec à part.
- `.env` monté par tube nommé (question ouverte 2).
- Kubernetes, Terraform, Vercel : `onepass-ci run` couvre le cas générique.

## 16. Récapitulatif des rulings

1. Extraction de `runner`, `mask`, `template` dans `onepass-exec`.
2. Masquage actif par défaut dans `onepass run`.
3. Aucune interpolation dans le `.env`.
4. Surface `Cli` soumise à l'appairage et aux grants quand l'app sert.
5. Modèle Environment, `.env` à références toujours accepté.
6. Paquet scellé en phase 1, OIDC à deux parts en phase 2.
7. Compte de service = item, jamais appareil ni membre de vault.
8. Jeton jamais conservé par OnePass.
9. Paquet chiffré versionné dans le dépôt.
10. Aucune référence ni métadonnée du coffre dans le paquet.
11. Épingle `issuer` changée par un commit après une rotation de compte.
12. Action composite qui épingle la somme du binaire.
13. Jamais d'écriture dans la configuration Git globale.
14. Intégration de fournisseurs d'alias, aucun service de transfert OnePass en v1.
15. Clé d'API du fournisseur dans un item synchronisé.
16. Aucun appel au fournisseur depuis l'extension sur Mac.
17. Aucune métadonnée de site envoyée par défaut.

## 17. Sources

1. 1Password, « 1Password Environments: .env files, public beta », https://1password.com/blog/1password-environments-env-files-public-beta
2. 1Password Developer, « Local .env file », https://developer.1password.com/docs/environments/local-env-file
3. 1Password, `load-secrets-action`, https://github.com/1Password/load-secrets-action ; « GitHub Actions », https://www.1password.dev/ci-cd/github-actions
4. 1Password Developer, « Secrets Automation » et « Service account rate limits », https://developer.1password.com/docs/secrets-automation , https://developer.1password.com/docs/service-accounts/rate-limits
5. 1Password Developer, « Sign Git commits with SSH », https://developer.1password.com/docs/ssh/git-commit-signing
6. Bitwarden, « GitHub Actions integration » (Secrets Manager), https://bitwarden.com/help/github-actions-integration/
7. Doppler, « Service Account Identities (OIDC) », https://docs.doppler.com/docs/service-account-identities
8. Infisical, « GitHub Actions secrets », https://infisical.com/blog/github-actions-secrets.md
9. Fastmail, « Masked Email API », https://www.fastmail.com/for-developers/masked-email/ ; 1Password, « How and why we built Masked Email with JMAP », https://1password.com/blog/making-masked-email-with-jmap ; requête directe vers Fastmail, https://dev.to/dvcrn/creating-fastmail-masked-emails-anywhere-and-everywhere-1b30
10. GitHub, « About security hardening with OpenID Connect », https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
11. Bitwarden, « How to use the Bitwarden forwarded email alias generator », https://bitwarden.com/blog/how-to-use-the-bitwarden-forwarded-email-alias-generator/
12. SimpleLogin, dépôt et guide d'auto-hébergement, https://github.com/simple-login/app ; retours d'auto-hébergeurs sur DKIM et rDNS, https://lemmy.linuxuserspace.show/post/49561
13. SimpleLogin, documentation de l'API, https://github.com/simple-login/app/blob/master/docs/api.md
14. addy.io, https://addy.io/ et dépôt https://github.com/anonaddy/anonaddy
15. Synthèses tierces de l'API et des limites d'addy.io (non officielles, à vérifier sur la documentation du compte) : https://jentic.com/apis/addy.io/addy.md , https://freetier.co/directory/products/addyio
16. Absence d'API Hide My Email pour les tiers : https://mobilesyrup.com/2022/08/12/apple-hide-my-email-third-party-support-cancelled-or-delayed/ , https://1password.community/discussion/144190/iclouds-hide-my-email-integration

Vérifié le 2026-10-30 par recherche web. Les points marqués « à vérifier » (fallback de Doppler, limites d'addy.io) viennent de sources tierces.

## 18. Questions ouvertes pour le fondateur

1. **Environnements : modèle d'item ou un vault par environnement ?** Je prendrais le modèle d'item Environment, avec les `.env` à références toujours acceptés.
2. **`.env` monté par tube nommé comme 1Password ?** Je prendrais non en v1 : une fois autorisé, tout processus du même utilisateur le lit. À revoir si les retours le demandent, avec une approbation par client.
3. **CI phase 1 : paquet scellé dans le dépôt, ou attendre le serveur ?** Je prendrais le paquet scellé maintenant : il marche sans serveur et sans tiers.
4. **Où vit le paquet : dans le dépôt ou comme secret GitHub ?** Je prendrais le dépôt (chiffré, relu en revue), le jeton seul dans les secrets GitHub.
5. **Ajouter une commande de confort `onepass ci push-github` qui recopie les valeurs dans les secrets GitHub (`gh secret set`) ?** Je prendrais non : GitHub tiendrait les valeurs sans trace côté OnePass, et cela concurrence le paquet.
6. **Qui peut créer un compte de service ?** Je prendrais tout appareil dans l'état `Current` de la rotation v2, avec présence fraîche (Touch ID, sinon mot de passe maître), jamais l'extension ni la CLI sous agent.
7. **Durée de vie par défaut d'un paquet ?** Je prendrais 90 jours, 1 an au plus, avec rappel Watchtower à 14 jours de l'échéance.
8. **Fournisseurs d'alias en premier ?** Je prendrais SimpleLogin et addy.io (code ouvert, auto-hébergeables), Fastmail juste après.
9. **Service d'alias OnePass un jour ?** Je prendrais non pour la v1, et réexaminer seulement avec une offre payante et quelqu'un pour l'abus et la délivrabilité, sur la base de SimpleLogin auto-hébergé.
10. **Envoyer le domaine du site au fournisseur comme note ?** Je prendrais désactivé par défaut, option « Aider à trier chez le fournisseur ».
11. **iCloud Hide My Email : saisie manuelle seulement ?** Je prendrais oui ; jamais de points d'accès privés d'iCloud.
12. **Configuration Git : écrire dans le dépôt avec `--apply`, jamais en global ?** Je prendrais oui, aperçu par défaut.
13. **`onepass run` sous l'app Mac : appairage et Touch ID comme le MCP ?** Je prendrais oui, sinon un agent contourne ses portées MCP par le shell.
14. **Clé d'API du fournisseur d'alias : item synchronisé ou réglage local par appareil ?** Je prendrais l'item synchronisé, pour créer des alias depuis l'iPhone.
15. **Ordre des jalons ?** Je prendrais D1, D3, E1, D5, D6, E2, D2, D4, E3, E4.

## Décisions du fondateur (2026-10-30)

Réponses du fondateur marquées **(fondateur)**. Les autres sont une première passe de Claude, à confirmer, marquées **(première passe)**. Une décision ici prime sur le texte de la spec ; les sections touchées sont à réécrire au prochain passage.

Toutes les décisions de cette spec sont une première passe ; le fondateur n'a pas encore répondu. Elles reprennent les recommandations de la spec.

1. **Environnements : nouveau type d'item, `.env` à références toujours acceptés (première passe).**
2. **Pas de `.env` par tube nommé en v1 (première passe).**
3. **CI : paquet scellé maintenant, sans serveur (première passe).**
4. **Paquet dans le dépôt, jeton seul dans les secrets GitHub (première passe).**
5. **Pas de `onepass ci push-github` (première passe).**
6. **Création d'un compte de service : appareil `Current` avec présence fraîche, jamais l'extension ni la CLI sous agent (première passe).** Un PC peut le faire (cohérent avec la décision 8 de la spec multi-plateforme).
7. **Paquet : 90 jours par défaut, 1 an au plus, rappel Watchtower à 14 jours (première passe).**
8. **Alias : SimpleLogin et addy.io, puis Fastmail (première passe).**
9. **Pas de service d'alias OnePass en v1 (première passe).**
10. **Domaine du site non envoyé au fournisseur par défaut (première passe).**
11. **iCloud Hide My Email : saisie manuelle seulement (première passe).**
12. **Configuration Git écrite dans le dépôt avec `--apply`, aperçu par défaut, jamais en global (première passe).**
13. **`onepass run` sous l'app Mac : appairage et Touch ID comme le MCP (première passe).**
14. **Clé d'API du fournisseur d'alias : item synchronisé (première passe).**
15. **Ordre : D1, D3, E1, D5, D6, E2, D2, D4, E3, E4 (première passe).**
