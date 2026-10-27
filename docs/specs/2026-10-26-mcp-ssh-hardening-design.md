# Durcissement du serveur MCP et de l'agent SSH

Date : 2026-10-26
Statut : approuvée (auto-approbation, session autonome)
Portée : durcir `onepass mcp` et `onepass ssh-agent` (jalon 7, spec `2026-10-25-milestone-7-mcp-ssh-design.md`) sans les désactiver. Brief : `.superpowers/briefs/mcp-ssh-hardening.md`.

## 1. Compréhension

Ce que le brief demande : un modèle de menace écrit (4 attaquants), une défense contre l'usurpation de client (identité du pair, signature de code, appairage), des approbations par client et par coffre, courtes, révocables, limitées en débit, regroupées, fortes (Touch ID) pour toute révélation, aucun secret dans le contexte du modèle sauf politique explicite, un journal d'audit lisible et chaîné, un agent SSH à confirmation réglable, clés liées aux hôtes, transfert refusé, signatures journalisées, et des tests d'abus (secrets hors portée, injection dans un titre, client non signé, rejeu d'une autorisation expirée).

Ce qui existe déjà au jalon 7 et reste : scopes par vault (`metadata`, `use`, `write`, `totp`, `reveal`), politique signée, ordre fixe des contrôles, quarantaine d'intégrité, approbation sur terminal avec code de confirmation, journal chaîné et signé obligatoire avant les actions sur secret, uid du pair vérifié, transfert d'agent refusé par défaut, `session-bind` vérifié, marque-pages `hosts` indicatifs.

Hypothèses : l'app Mac (jalon 2) n'héberge pas encore ces serveurs ; ils tournent dans la CLI. Touch ID est appelé depuis la CLI via LocalAuthentication. Les autres sessions durcissent le reste du cœur : les changements du cœur restent additifs (ici : aucun).

## 2. Modèle de menace

Actif protégé : les valeurs secrètes des items, les clés privées SSH, et la capacité de les utiliser. Hors périmètre (inchangé) : un attaquant root ou qui lit la mémoire du processus déverrouillé.

| Attaquant | Capacités | Ce qu'il veut | Défenses |
| --- | --- | --- | --- |
| A1. Injection de prompt (contenu d'un item, d'une page, d'un outil) | Écrit du texte que le modèle lira : titre, URL, tag, sortie d'une commande | Pousser le modèle à demander un secret, à l'exfiltrer, à approuver en masse | Données du coffre balisées `untrusted_vault_data` ; aucune valeur rendue sans scope `reveal` ; approbation humaine qui affiche la demande exacte ; masquage des sorties ; limites de débit ; refus groupés après des refus répétés |
| A2. Agent IA malveillant ou piloté | Appelle tous les outils MCP avec des arguments arbitraires, a souvent un shell sous le même uid | Obtenir des secrets hors de sa portée, contourner l'approbation, user l'utilisateur | Scopes par client et par vault ; approbation forte (Touch ID) pour `reveal` et `totp` ; autorisations courtes et révocables, liées au client ; limites de débit ; blocage temporaire après refus ; journal que l'agent ne peut pas réécrire sans être détecté |
| A3. Processus local qui se fait passer pour un client | Même uid ; se connecte au socket SSH ou lance `onepass mcp` lui-même | Signer avec une clé ou lire des secrets en se présentant comme un client approuvé | Identité du pair par le noyau (uid, pid, jeton d'audit) ; identité de code signée (équipe et identifiant) vérifiée par le système ; seul un client appairé est servi ; un binaire non signé est épinglé par son empreinte |
| A4. Fatigue d'approbation | Déclenche des dizaines d'invites pour obtenir un « oui » réflexe | Une approbation obtenue par lassitude | Regroupement : une seule invite par requête, toutes cibles incluses ; autorisations de courte durée explicites ; plafond d'invites par minute ; blocage du client après 3 refus ; Touch ID pour toute révélation ; code de confirmation à recopier |

Ruling: modèle de menace limité aux 4 attaquants du brief, l'attaquant root restant hors périmètre - il lit la mémoire du processus quoi qu'on fasse - coût si faux : aucun, c'est la limite déjà documentée.

## 3. Identité des clients

### 3.1 Nouvelle crate `onepass-peer`

Une crate dédiée regroupe ce que le noyau sait du processus en face :

- `PeerCred { uid, pid, audit_token }` pour un `UnixStream` (macOS : `getpeereid`, `LOCAL_PEERPID`, `LOCAL_PEERTOKEN` ; Linux : `SO_PEERCRED`) et pour le processus parent (`getppid`).
- `exe_path(pid)`.
- `CodeIdentity` : ce que le système dit du code exécuté.
  - `Platform { identifier }` : binaire Apple (exigence `anchor apple`).
  - `Team { team_id, identifier }` : signé par un développeur (exigence `anchor apple generic` valide, équipe lue dans les informations de signature).
  - `AdHoc { path, cdhash }` (macOS) : signé ad hoc (tout binaire compilé localement sur Apple Silicon) ou dont la signature de développeur ne tient pas, épinglé par le hachage du répertoire de code (cdhash) que le noyau a enregistré pour l'image en cours d'exécution (`csops` par pid, `csops_audittoken` par jeton d'audit), jamais par une relecture du fichier.
  - `Unsigned { path, sha256 }` (Linux seulement) : épinglé par l'empreinte SHA-256 de l'image en cours d'exécution, lue par `/proc/<pid>/exe`, qui reste liée à cette image même si le chemin est remplacé.
  - Un code macOS sans aucune signature (possible seulement sur Intel) est refusé (`Unreadable("unsigned code")`), de même qu'une image que le noyau ne tient plus pour valide.
  - `AdHoc` porte aussi `hardened` (runtime renforcé, drapeau `CS_RUNTIME`), hors de l'identifiant de client. Un processus ad hoc marqué `CS_DEBUGGED` est refusé (`Unreadable("debugged or injectable code")`).
- `identify(pid | audit_token) -> ClientIdentity { code: CodeIdentity, exe, pid, chain }`. Sur macOS, `SecCodeCopyGuestWithAttributes` (par jeton d'audit pour un socket, sinon par pid), le cdhash du noyau, puis `SecCodeCheckValidity` contre des exigences qui nomment ce cdhash (`anchor apple and cdhash H"..."`, puis `anchor apple generic and ...`) : une identité de plateforme ou d'équipe ne vaut que pour l'image exacte en cours d'exécution. `SecCodeCopySigningInformation` donne l'équipe et l'identifiant, revérifiés par une exigence qui les nomme exactement. Tout code qui ne satisfait aucune des deux exigences est `AdHoc`. Avec un jeton d'audit, le chemin de l'exécutable ne vient que de l'objet de code, jamais d'une lecture par pid. Sur Linux, toujours `Unsigned`.
- `identity_of_file(path)` pour l'appairage explicite (`--exe`) : sur macOS le cdhash du code statique (égal à celui du noyau pour un binaire non modifié), après validation complète des pages ; plateforme et équipe comme pour un processus. Sur Linux, l'empreinte SHA-256 du fichier.
- Identifiant stable d'un client : `platform:<identifier>`, `team:<team_id>:<identifier>`, `adhoc:<cdhash>` (macOS), `unsigned:<sha256>` (Linux).

Limite : appairer un outil ad hoc, c'est faire confiance à cet outil et à toute bibliothèque qu'il charge. Sans runtime renforcé, `DYLD_INSERT_LIBRARIES` injecte du code sans changer son cdhash ni sa validité. Seul un outil signé avec le runtime renforcé (par exemple `codesign -s - -o runtime`) écarte cette injection ; l'appairage avertit pour un outil ad hoc qui ne l'est pas.

Le module `peer.rs` de `onepass-ssh-agent` est remplacé par cette crate.

Ruling: identité de code par les exigences de signature du système (Security.framework) plutôt que par le chemin - un chemin se remplace, une signature d'équipe non - coût si faux : un client signé mais compromis reste accepté (hors périmètre, attaquant root ou chaîne de signature compromise).

Ruling: binaire ad hoc épinglé sur macOS par le cdhash que le noyau tient pour l'image en cours d'exécution, jamais par le fichier - un attaquant du même uid peut renommer un autre fichier sur le chemin après `exec`, et une relecture du fichier lui prêterait l'identité du remplaçant ; le cdhash change à chaque recompilation - coût si faux : il faut réappairer un outil local après chaque mise à jour.

Ruling: `Unsigned` réservé à Linux, épinglé par l'empreinte SHA-256 de `/proc/<pid>/exe` ; un code macOS sans aucune signature est refusé - Linux n'a pas de signature de code, et `/proc/<pid>/exe` reste lié à l'image exécutée ; sur macOS seul Intel exécute du code non signé, sans cdhash à épingler - coût si faux : un outil non signé sur un Mac Intel ne peut pas être appairé (le signer ad hoc suffit).

Ruling: jeton d'audit (`LOCAL_PEERTOKEN`) plutôt que pid pour le socket SSH - un pid peut être réutilisé entre `accept` et la vérification - coût si faux : aucun sur macOS ; Linux garde le pid.

### 3.2 Client MCP

Le client MCP est le processus qui lance `onepass mcp` (stdio). Son identité est celle du premier ancêtre qui n'est pas un lanceur : les shells et `env` du système (`com.apple.sh`, `com.apple.bash`, `com.apple.zsh`, `com.apple.dash`, `com.apple.env`) sont traversés, au plus 8 niveaux. La chaîne complète est journalisée. Sur Linux, où rien n'est signé, les lanceurs sont reconnus par le chemin de leur exécutable (`/bin` et `/usr/bin` : `sh`, `bash`, `dash`, `zsh`, `env`). Le pid 1 et `systemd` ne sont jamais un client (`Unreadable("no client process")`). Après l'identification de chaque ancêtre, le parent de son enfant est relu : s'il a changé (ancêtre terminé, pid réutilisé), l'identification échoue. Le nom déclaré par le client dans `initialize` n'est qu'une étiquette affichée.

Ruling: identité MCP = premier ancêtre non lanceur - un hôte MCP lance souvent le serveur par un shell ; appairer `sh` reviendrait à appairer tout le monde - coût si faux : un hôte qui passe par un interpréteur générique (`node`, `python`) appaire cet interpréteur ; documenté.

### 3.3 Appairage

Registre signé `<data-dir>/clients.json` (`SignedConfig`, domaine `clients`), par surface (`mcp`, `ssh`) :

```
{ "account_id", "generation", "clients": [ { "id", "surface", "label", "code": {...}, "paired_at",
  "mcp_scopes": { "<vault id>": ["metadata", "use", ...] },   // MCP seulement
  "ssh_keys": ["<empreinte>", ...] | null } ] }              // SSH seulement, null = toutes
```

- Un client inconnu n'est jamais servi : MCP répond à chaque appel d'outil `Refused("client not paired: run onepass clients pair ...")` et écrit une entrée d'audit ; SSH répond `FAILURE`, aucune clé listée.
- Appairage interactif à la première connexion, seulement pour un client `Platform` ou `Team`, par une approbation forte (section 4.4) qui affiche l'identité vérifiée. Scopes MCP par défaut à l'appairage : `metadata` et `use` sur chaque vault MCP ; clés SSH : toutes.
- Un client `AdHoc` (macOS) ou `Unsigned` (Linux) ne s'appaire que par la commande explicite `onepass clients pair --surface <s> --exe <chemin>` (mot de passe maître, empreinte affichée).
- `onepass clients list | pair | unpair <id> | scopes <id> --vault <v> --scopes <liste> | keys <id> --key <empreinte>...`.
- Les serveurs relisent et vérifient le registre à chaque requête : un désappairage prend effet tout de suite.
- L'écriture du registre se fait sous verrou exclusif (`clients.json.lock`, attente bornée à 2 s) ; la nouvelle génération dépasse à la fois celle du disque, celle du registre en mémoire et la plus haute vue : deux écrivains ne produisent jamais deux registres de même génération.
- Après un désappairage (et tout changement du registre), la commande pousse le désappairage (client, date) et la nouvelle génération à chaque serveur en marche par le canal de contrôle signé (section 4.6) et affiche les serveurs atteints et ceux qui n'ont pas répondu.

Ruling: aucun client servi sans appairage - c'est la seule défense contre A3 qui tienne pour le même uid - coût si faux : une étape de plus au premier usage.

Ruling: appairage interactif réservé aux clients signés, non signés par commande explicite - une invite « appairer ce binaire ad hoc ? » ne donne aucune information vérifiable à l'utilisateur - coût si faux : un outil local demande une commande de plus.

Ruling: registre signé avec un compteur `generation`, le plus haut vu étant gardé en mémoire par chaque serveur et relevé par le canal de contrôle à chaque changement, qui porte aussi les désappairages - un registre plus ancien rejoué, ou blanchi à une génération plus haute, ne ramène pas un client désappairé pendant que le serveur tourne - coût si faux : au redémarrage, un ancien registre authentique peut être rejoué (documenté, comme la politique MCP).

## 4. Approbations

### 4.1 Portées par client et par coffre

Scopes effectifs MCP = politique du vault (`mcp-policy.json`) ∩ scopes du client appairé ∩ restriction de lancement (`--vault`, `--scopes`). Un vault hors des scopes du client lui est invisible, comme un vault non MCP.

Ruling: les scopes du client s'ajoutent à la politique existante par intersection - la politique reste le plafond global, le client ne fait que restreindre - coût si faux : aucun.

### 4.2 Autorisations courtes et révocables

Les « accords de session » en mémoire du jalon 7 deviennent des autorisations persistées dans un fichier signé `<data-dir>/grants.json` (`generation`, liste d'autorisations) :

```
{ "id", "client_id", "surface", "action", "key", "vault_id", "expires_at", "created_at" }
```

- Durée par défaut 5 minutes, au plus 60 minutes, choisie à l'invite (`s` = 5 min ; `s15`, `s60`).
- Liée au client appairé (identifiant de code) : un autre processus ne la réutilise pas.
- Vérifiée à chaque usage : signature du fichier, `expires_at` dans le futur (horloge murale et horloge monotone du serveur), client identique, requête identique (`key`).
- `onepass grants list` et `onepass grants revoke <id> | --all | --client <id>` ; la révocation réécrit le fichier signé avec une génération plus haute, puis pousse les autorisations révoquées et la nouvelle génération à chaque serveur en marche par le canal de contrôle (section 4.6), qui les garde en mémoire jusqu'à leur expiration ; la commande affiche les serveurs atteints et ceux qui n'ont pas répondu.
- Lecture et écriture sous verrou (`grants.json.lock`, partagé en lecture, exclusif en écriture, attente bornée à 2 s : au-delà, aucune autorisation n'est accordée et l'écriture échoue).
- Une autorisation émise par le serveur est périmée dès que son échéance monotone est passée, même si l'horloge murale recule ; une autorisation émise par un autre processus ne dépend que de l'horloge murale (et de `created_at` passé).
- Une autorisation expirée ou révoquée est refusée et l'utilisateur est de nouveau sollicité ; le refus est journalisé (`grant_expired`, `grant_revoked`).
- `reveal`, `totp` et les clés SSH `confirm_each_use` ne donnent jamais d'autorisation.

Ruling: autorisations dans un fichier signé relu à chaque requête plutôt qu'en mémoire - la révocation depuis un autre terminal doit agir sur un serveur en marche - coût si faux : une lecture et une vérification de signature par requête.

Ruling: durée par défaut 5 min, plafond 60 min - assez pour une tâche, trop court pour une session d'agent oubliée - coût si faux : plus d'invites.

### 4.3 Limites de débit et fatigue

Par client et par surface, en mémoire du serveur :

- au plus 6 invites par minute ; au-delà, refus immédiat sans invite (`rate_limited`) ;
- au plus 30 requêtes à secret par minute (MCP) ou 60 signatures par minute (SSH) ;
- après 3 refus de l'utilisateur d'affilée, le client est bloqué 10 minutes : refus sans invite (`client_cooling_down`), annoncé une fois sur le terminal ;
- regroupement : une requête = une invite pour toutes ses cibles (déjà le cas pour `run_with_secrets`) ; une requête identique à une invite en attente attend son résultat au lieu d'en ouvrir une autre.

Ruling: seuils 6 invites/min, 3 refus puis 10 min de pause - un humain ne répond pas sérieusement à plus d'une invite toutes les 10 s, et 3 refus signalent un agent qui insiste - coût si faux : un usage légitime intense est freiné, réglable par variables de configuration documentées.

### 4.4 Approbation forte

Trait `StrongAuth` dans `onepass-guard` : `fn verify(&self, reason: &str) -> StrongOutcome`.

- macOS : LocalAuthentication, politique « propriétaire de l'appareil » (Touch ID, Apple Watch, ou mot de passe de session macOS en repli), raison affichée par le système avec le client et la cible.
- Ailleurs ou si LocalAuthentication est indisponible (session SSH, pas d'interface) : le mot de passe maître retapé sur `/dev/tty`, vérifié contre le compte.
- Développement : `ONEPASS_DEV_STRONG_AUTH=allow|deny`, builds de debug seulement.

Exigée pour : `reveal_secret`, `totp_code`, l'appairage interactif, et (option `--strong`) chaque signature SSH. Elle s'ajoute à l'invite avec code de confirmation : l'invite dit quoi, l'approbation forte prouve qui.

Ruling: Touch ID via LocalAuthentication depuis la CLI (crates `objc2-local-authentication`) avec repli sur le mot de passe maître - c'est l'approbation forte demandée et la seule disponible sans app - coût si faux : une dépendance Objective-C de plus, limitée à macOS.

### 4.5 Secrets hors du contexte du modèle

Inchangé et confirmé : seules `reveal_secret` (scope `reveal`, absent par défaut, Touch ID) et `totp_code` (scope `totp`, Touch ID) rendent une valeur. Le chemin par défaut est `run_with_secrets` (injection dans l'environnement de la commande, sortie masquée).

### 4.6 Canal de contrôle signé

Un fichier authentique plus ancien peut être restauré, puis blanchi : un processus neuf le relit et le réécrit à une génération plus haute, l'autorisation révoquée toujours vivante. La génération seule ne suffit donc pas : la commande qui révoque ou désappaire envoie la révocation elle-même à chaque serveur en marche, qui la garde en mémoire.

- Chaque serveur écoute sur `<data-dir>/run/<pid>.sock`, jamais à la place d'un socket vivant (un socket mort est remplacé). La protection est le répertoire : créé `0700`, ou réglé à `0700` par son descripteur ouvert sans suivre de lien symbolique ; le mode du socket lui-même est laissé au umask, sans `chmod` par chemin qui pourrait suivre un chemin échangé. Un chemin plus long que `sun_path` (104 octets sur macOS) donne l'erreur « data directory path too long for a control socket ».
- Notification : une ligne JSON signée par la clé locale du compte sous le domaine `control-notify`, sur le JSON canonique de tous ses champs sauf `sig` : `{ "account_id", "kind": "grants", "generation", "nonce", "revoked": [{ "id", "expires_at" }], "selectors": [...] }` ou `{ "account_id", "kind": "clients", "generation", "nonce", "unpaired": [{ "client_id", "at" }] }`. Le compte doit être celui du serveur. Le serveur relève sa génération plancher et garde en mémoire ce qu'on lui pousse, quel que soit le fichier qu'il lit ensuite :
  - les sélecteurs de la révocation, `{ "id" }`, `{ "client_id", "created_at_or_before": T }` ou `{ "all_created_at_or_before": T }` (T = heure murale de la commande), gardés jusqu'à maintenant + 60 min (la plus longue vie d'une autorisation) ; `check` refuse toute autorisation qu'un sélecteur couvre, `created_at` venant de l'autorisation signée. Le fichier lu par la commande ne fait pas foi : il a pu être restauré pour cacher une autorisation, d'où des sélecteurs plutôt qu'une liste d'identifiants. `revoke <id>` pousse `{ "id" }` même si l'identifiant est absent du fichier lu. Les identifiants trouvés sont aussi poussés (`revoked`), gardés jusqu'à leur expiration ;
  - chaque désappairage `{ "client_id", "at" }`, poussé même si le client est absent du registre lu, avec `at` = le plus tard de l'heure de la commande et du `paired_at` le plus récent retiré ; un enregistrement de ce client n'est plus accepté que si son `paired_at` est postérieur à `at` (un nouvel appairage). Il répond ensuite `{ "nonce", "pid", "generation", "sig" }` signé sous le domaine `control-ack`. Un message invalide ferme la connexion sans réponse. Au plus 8 connexions de contrôle à la fois (les suivantes sont fermées aussitôt), chacune en 2 s au total.
- La commande contacte en même temps tous les sockets du répertoire nommés `<pid>.sock` (1 à 10 chiffres) dont le processus existe (`kill(pid, 0)` réussit ou échoue avec `EPERM`), 256 au plus (au-delà erreur) ; les autres noms sont ignorés. Un délai global (3 s par défaut) borne l'appel : envoi et lecture complète de la réponse utilisent ce qui en reste ; une connexion bloquante ne peut pas être bornée ainsi et son fil peut survivre à l'appel, ce qui convient à une commande ponctuelle ; un serveur ne compte comme atteint que si sa réponse est signée, porte le même nonce, la même génération et le pid du nom de son socket. Elle ne supprime aucun socket (chaque serveur supprime le sien en s'arrêtant) et affiche les pid atteints et les sockets qui n'ont pas répondu correctement.
- Échec fermé : toutes les secondes, un fil de surveillance du serveur se connecte à son propre chemin de socket et envoie un nonce frais signé (domaine `control-ping`) ; le serveur se considère vivant seulement si sa boucle d'acceptation a reçu ce nonce depuis moins de 2 s. Il le vérifie à chaque requête ; sinon (socket supprimé ou remplacé) il ne peut plus être prévenu et il s'arrête. Un premier ping réussi est exigé au démarrage.
- Limites connues :
  - un attaquant qui renomme le socket et relaie depuis le chemin d'origine peut laisser passer les pings et retenir les notifications ; la commande voit alors ce serveur en échec (pas de réponse signée), ce qu'elle affiche ;
  - un serveur démarré après une révocation n'a rien en mémoire et fait confiance aux fichiers qu'il lit : un attaquant du même uid peut restaurer un fichier d'avant la révocation (ou le désappairage) avant le démarrage d'un nouveau serveur. Résidu accepté, de même nature que le rejeu après redémarrage (section 9).

Ruling: révocations et désappairages poussés aux serveurs par un canal de contrôle signé qui porte la révocation elle-même sous forme de sélecteurs (identifiant, client et date, tout et date) et les désappairages demandés, gardés en mémoire par le serveur - seul le serveur en marche sait ce qu'on lui a dit, un fichier restauré ou blanchi peut porter n'importe quelle génération, et le fichier lu par la commande peut lui-même avoir été restauré pour cacher une autorisation ou un client - coût si faux : un socket par serveur, une connexion par serveur à chaque révocation, un peu de mémoire jusqu'à l'expiration des autorisations révoquées.

Ruling: un serveur démarré après une révocation ne connaît pas les révocations passées - résidu accepté, documenté avec les limites - coût si faux : une autorisation révoquée (au plus 60 min de vie) peut revivre si un attaquant restaure le fichier avant le démarrage d'un nouveau serveur.

Ruling: serveurs en échec fermé par un ping signé vers leur propre socket chaque seconde - un serveur que la commande ne peut plus joindre ne doit plus servir - coût si faux : un serveur s'arrête si son socket est supprimé ou si ses connexions de contrôle sont saturées plus de 2 s.

## 5. Journal d'audit

Le journal du jalon 7 (`audit.log`, chaîné SHA-256, tête signée, en ajout seul sous verrou) gagne :

- `client_id` (identifiant de code) et `client_label` dans chaque entrée (champs optionnels : les anciennes lignes restent vérifiables) ;
- les nouveaux résultats `not_paired`, `rate_limited`, `client_cooling_down`, `grant_expired`, `grant_revoked`, `strong_auth_failed`, `host_not_bound` ;
- `onepass audit [--verify] [--client <id>] [--since <durée>]` : lecture humaine (date locale, client, action, vault et item par leur nom, décision, résultat), vérification de la chaîne toujours faite avant l'affichage.

Ruling: une commande `onepass audit` de premier niveau, `onepass mcp audit` gardée comme alias - le journal couvre MCP et SSH - coût si faux : aucun.

## 6. Agent SSH

- Confirmation réglable : `onepass ssh-agent --confirm session|always` (défaut `session`) ; `confirm_each_use` de l'item force `always` pour sa clé ; `--strong` exige l'approbation forte à chaque signature.
- Clés liées aux hôtes : une clé dont le champ `hosts` n'est pas vide ne signe que pour une connexion liée (`session-bind`) dont la clé d'hôte correspond, dans `known_hosts`, à un de ses hôtes. Sans liaison, ou destination non correspondante : refus (`host_not_bound`), sauf signature `SSHSIG` d'espace de noms `git` pour une clé dont `git_signing` vaut oui. Une clé sans `hosts` reste utilisable partout, avec approbation.
- Transfert : refusé sauf `--allow-forwarded` (inchangé), et jamais d'autorisation pour une connexion transférée.
- Liste des clés par client : un client appairé avec `ssh_keys` ne voit et n'utilise que ces clés.
- Chaque signature, acceptée ou refusée, est journalisée avec client, clé, destination liée et espace de noms.

Ruling: marque-pages `hosts` désormais bloquants - le brief demande des clés liées à des hôtes, et `session-bind` donne une destination vérifiée - coût si faux : une clé avec `hosts` ne marche plus avec un client trop ancien pour `session-bind` (OpenSSH < 8.9) ; il faut vider `hosts`.

Ruling: exception `git` pour les signatures de commits - `ssh-keygen -Y sign` ne lie aucune session ; `git_signing` existe déjà dans le modèle - coût si faux : une clé `git_signing` peut signer n'importe quel contenu de l'espace `git`.

## 7. Tests d'abus

- Agent qui demande des secrets hors de sa portée : scope absent du client, vault hors des scopes du client, vault non MCP ; l'approbateur n'est jamais appelé.
- Injection de prompt dans un titre : le titre revient balisé, nettoyé à l'affichage, et n'ouvre aucune autorisation.
- Client non signé : un binaire de test ad hoc se connecte au socket SSH et lance `onepass mcp` : refusé tant qu'il n'est pas appairé ; appairé par `clients pair --exe`, il est servi ; le binaire modifié (recompilé ou re-signé ; sur Linux, un octet de plus suffit) est refusé, de même que le binaire en cours d'exécution dont le chemin est remplacé par un autre fichier.
- Rejeu d'une autorisation expirée : autorisation créée, horloge avancée (horloge injectable), requête refusée et invite de nouveau ; fichier `grants.json` restauré après révocation : refusé (génération plus basse) ; autorisation copiée vers un autre client : refusée.
- Fatigue : 7 invites en une minute (la 7e refusée sans invite) ; 3 refus puis blocage ; requêtes identiques simultanées regroupées.
- SSH : clé avec `hosts` sans liaison refusée ; liaison vers un autre hôte refusée ; signature `git` acceptée seulement avec `git_signing`.

## 8. Red team

Avant la revue finale, une équipe rouge (modèle le plus puissant) attaque MCP et SSH avec les 4 attaquants de la section 2, écrit ses attaques en tests, et tout ce qu'elle casse est corrigé.

## 9. Hors périmètre

- Héberger les serveurs dans l'app Mac (jalon 2b ou suivant).
- Sandbox des commandes lancées par `run_with_secrets`.
- Détection du retour en arrière des registres signés après un redémarrage (même limite que la politique MCP).

## 10. Récapitulatif des rulings

1. Modèle de menace limité aux 4 attaquants.
2. Identité de code par les exigences de signature du système.
3. Binaire ad hoc épinglé par le cdhash du noyau (macOS) ; `Unsigned` par SHA-256 de l'image sur Linux seulement ; code macOS non signé refusé.
4. Jeton d'audit pour le socket SSH.
5. Identité MCP = premier ancêtre non lanceur.
6. Aucun client servi sans appairage.
7. Appairage interactif réservé aux clients signés.
8. Registre signé avec génération.
9. Scopes client par intersection.
10. Autorisations dans un fichier signé relu à chaque requête.
11. Durées 5 min par défaut, 60 min au plus.
12. Seuils de débit et de fatigue.
13. Touch ID via LocalAuthentication, repli mot de passe maître.
14. Commande `onepass audit` de premier niveau.
15. Marque-pages `hosts` bloquants.
16. Exception `git` pour les signatures de commits.
17. Canal de contrôle signé qui pousse les révocations (sélecteurs) et désappairages eux-mêmes, gardés en mémoire par les serveurs.
18. Serveurs en échec fermé par un ping signé vers leur propre socket.
19. Serveur démarré après une révocation sans mémoire de celle-ci : résidu accepté.
