# Jalon 7 dans les apps : agent SSH, serveur MCP et Travel Mode

Date : 2026-10-27
Statut : approuvée (auto-approbation, règle permanente du propriétaire)
Portée : amener le jalon 7 (`2026-10-25-milestone-7-mcp-ssh-design.md`, durci par `2026-10-26-mcp-ssh-hardening-design.md`) de « fait dans la CLI » à « fait dans les apps Apple ». Branche `feat/m7-app`, partie de `feat/onepass-redesign`.

## 1. Ce qui est demandé

- Mac : l'app sert elle-même l'agent SSH et le serveur MCP sur les coffres de l'app (plus de dossier `~/.onepass-dev`), avec approbation native et Touch ID, journal d'audit lisible, réglages.
- Mac : générer ou importer une clé SSH dans un item, voir les clés exposées, copier la configuration (`IdentityAgent`, `SSH_AUTH_SOCK`, bloc `mcpServers`).
- Mac : clients MCP appairés, portées par coffre, autorisations en cours révocables, politique signée.
- Mac et iOS : Travel Mode (marquer un coffre « sûr en voyage », entrer et sortir, coffres retirés de l'appareil puis rendus vérifiés). Le drapeau `travel_safe` est dans le meta du coffre, donc synchronisé.
- Garanties du durcissement conservées : aucun secret ne sort sans approbation, journal chaîné et signé, client identifié par sa signature de code, autorisations courtes et révocables, limites de débit.

Ruling: « drapeau synchronisé » lu comme le drapeau `travel_safe` des coffres (meta synchronisé par CloudKit) ; l'état actif du Travel Mode reste propre à chaque appareil, comme dans le noyau - un état de voyage partagé exigerait un nouveau type d'enregistrement synchronisé, donc un changement de format du noyau - coût si faux : un réglage par appareil au lieu d'un seul, à reprendre avec un enregistrement signé de compte.

## 2. Approches

1. **Serveurs dans l'app, en Rust par FFI (retenue).** L'app déverrouillée tient la `Session` ; `onepass-ffi` gagne un module qui fait tourner `onepass-ssh-agent` et `onepass-mcp` sur cette session, avec l'approbateur et l'authentification forte fournis par Swift (interfaces de rappel UniFFI). Le code durci reste celui des crates du jalon 7.
2. Piloter la CLI depuis l'app. Deux magasins (SQLite de la CLI, `SyncStore` de l'app), deux mots de passe, rien pour iOS.
3. Réécrire les serveurs en Swift. Double code de sécurité à maintenir.

Ruling: approche 1 - une seule implémentation des protocoles et des gardes, testée en Rust - coût si faux : une surface FFI de plus.

## 3. Agent SSH dans l'app (Mac)

- Socket : `<conteneur>/.onepass/ssh.sock` (l'app est en bac à sable ; `NSHomeDirectory()` est le dossier `Data` du conteneur, comme le fait Secretive). Dossier `0700`, socket `0600`, chemin refusé au-delà de 100 octets (`sun_path`). Le réglage affiche le chemin, la ligne `IdentityAgent` et la ligne `export SSH_AUTH_SOCK=...`, copiables.
- Source des clés : la session déverrouillée (items SSH Key avec « utiliser dans l'agent »), relue à chaque demande. Verrouiller l'app arrête l'agent (aucune clé servie verrouillé) ; il redémarre au déverrouillage s'il est activé.
- Approbation : panneau natif qui affiche clé, empreinte, programme demandeur (pid, chemin), destination liée, transfert, espace de noms `SSHSIG`. Choix : refuser, une fois, 5, 15 ou 60 minutes (sauf `confirm_each_use`). Réglage « Touch ID à chaque signature » (défaut : oui) : l'approbation exige alors Touch ID (ou le mot de passe de session) en plus du clic.
- `known_hosts` : l'app ne lit pas `~/.ssh` sans permission ; l'utilisateur peut choisir le fichier une fois (signet à portée de sécurité). Sans lui, une destination liée s'affiche par son empreinte.
- Transfert : refusé par défaut, réglage « Autoriser les connexions transférées ».
- Journal : `<conteneur>/.onepass/audit.log` signé par la clé du compte (`sign_local`), partagé avec MCP.
- Générer (`ed25519`, `ecdsa-p256/384/521`, `rsa-3072/4096`) ou importer (OpenSSH chiffré ou non, PEM) une clé dans un item SSH Key d'un coffre choisi, avec hôtes, agent, confirmation à chaque usage ; copier la clé publique.

Ruling: approbation dans un panneau natif plus Touch ID au lieu du code de confirmation du terminal - le code protégeait contre une frappe injectée dans un terminal partagé, un panneau d'app reçoit des clics que l'agent ne peut pas forger, et Touch ID prouve la présence - coût si faux : un clic forgé par un outil d'accessibilité autorisé ; Touch ID reste exigé par défaut.

Ruling: agent arrêté au verrouillage - aucune clé ne doit être utilisable quand l'app est verrouillée - coût si faux : `ssh` échoue tant que l'app est verrouillée, ce qui est voulu.

## 4. Serveur MCP dans l'app (Mac)

### 4.1 Relais

Un client MCP lance un programme et lui parle sur stdio. L'app embarque un relais, `OnePass.app/Contents/Helpers/onepass-mcp` (crate Rust `onepass-mcp-relay`), à déclarer dans le client :

```
{ "mcpServers": { "onepass": { "command": "<app>/Contents/Helpers/onepass-mcp",
  "args": ["--socket", "<conteneur>/.onepass/mcp.sock"] } } }
```

- Le relais identifie son client exactement comme `onepass mcp` (premier ancêtre non lanceur, `onepass-peer::identify_mcp_parent`) et l'annonce dans un message `hello`.
- Il se connecte au socket MCP de l'app et relaie les lignes JSON-RPC sans les interpréter.
- Il exécute pour l'app ce qu'elle ne peut pas faire dans son bac à sable : la commande de `run_with_secrets` (même `runner` que la CLI) et la lecture et l'écriture de fichiers de `fill_template`, dans l'environnement réel de l'utilisateur. L'app lui envoie la commande et les valeurs, il rend la sortie brute ; le masquage, la politique, l'approbation et le journal restent dans l'app.
- L'app ne sert que ce relais : l'identité de code du pair (jeton d'audit) doit être celle du fichier `Contents/Helpers/onepass-mcp` de son propre paquet (même équipe et identifiant si signé, même cdhash si ad hoc). Tout autre pair est fermé sans réponse et journalisé (`not_paired`). Le relais signé utilise le runtime renforcé : on ne peut pas y injecter de code.

Ruling: relais embarqué, signé par l'équipe, qui exécute pour l'app - une app en bac à sable ne peut lancer les commandes de l'utilisateur que dans son conteneur, ce qui rendrait `run_with_secrets` inutile ; le relais est notre code et ne renvoie au client que ce que l'app a masqué - coût si faux : les valeurs à injecter traversent le socket local (dossier `0700` du conteneur) vers un processus que l'app a vérifié.

Ruling: identité du client annoncée par le relais, crue parce que le relais est vérifié - c'est lui qui voit la chaîne de processus du client ; l'app ne voit que le relais - coût si faux : aucun tant que le relais n'est pas compromis (même hypothèse que la CLI pour son propre binaire).

### 4.2 Protocole du socket

Lignes JSON (1 MiB au plus, comme `MAX_LINE`), dans les deux sens :

- relais vers app : `{"t":"hello","v":1,"client":{...}|null,"error":...}` en premier ; puis `{"t":"mcp","line":"..."}`, `{"t":"exec_result","id":n,...}`, `{"t":"file_result","id":n,...}` ;
- app vers relais : `{"t":"mcp","line":"..."}`, `{"t":"exec","id":n,"argv":[],"env":[[k,v]],"files":[[k,v]],"cwd":...,"timeout_secs":n}`, `{"t":"read_template","id":n,"path":...,"forbidden":...}`, `{"t":"write_output","id":n,"path":...,"content":...,"overwrite":b,"forbidden":...}`.

`onepass-mcp` gagne un trait `Workspace` (exécuter, lire un modèle, vérifier et écrire une sortie) ; `LocalWorkspace` garde le comportement de la CLI, l'app fournit un `Workspace` qui passe par le relais.

### 4.3 Clients, portées, autorisations

- Mêmes fichiers signés que la CLI, dans `<conteneur>/.onepass/` : `clients.json`, `grants.json`, `mcp-policy.json`, `audit.log`.
- Client signé inconnu : l'app demande l'appairage (panneau + Touch ID) ; accepté, il reçoit `metadata` et `use` sur chaque coffre MCP. Client ad hoc ou non signé : refusé, et l'app propose « Appairer un programme… » qui demande le fichier (empreinte affichée) puis Touch ID, comme `onepass clients pair --exe`.
- Réglages : clients appairés, portées par coffre (`metadata`, `use`, `write`, `totp`, `reveal`), désappairer ; autorisations en cours, révoquer une ou toutes ; politique signée par coffre et `allow_generate`.
- Révocation et désappairage agissent sur les objets partagés en mémoire du serveur (même processus) : pas besoin du canal de contrôle de la CLI.
- `reveal_secret` et `totp_code` exigent l'authentification forte (Touch ID par LocalAuthentication, rappel Swift).

Ruling: pas de canal de contrôle dans l'app - le serveur et la commande qui révoque sont le même processus ; la révocation modifie directement le magasin d'autorisations et le registre gardés en mémoire - coût si faux : aucun.

### 4.4 Coffres exposés

Le drapeau `mcp_access` du coffre devient réglable dans l'éditeur de coffre, mais l'app n'expose un coffre que s'il figure dans la politique signée (`mcp-policy.json`) : sans fichier, l'app écrit une politique vide (rien d'exposé), elle n'applique jamais la politique par défaut de la CLI. Activer l'accès MCP d'un coffre écrit les deux (meta et politique signée), après Touch ID.

Ruling: politique signée obligatoire dans l'app - le meta d'un coffre n'est pas lié au manifeste, un stockage hostile pourrait rejouer `mcp_access = true` ; la politique est signée localement par la clé du compte et ne voyage pas - coût si faux : un coffre exposé par la CLI n'est pas exposé par l'app sans passer par ses réglages.

## 5. Travel Mode dans l'app (Mac et iOS)

Le noyau (`repo/travel.rs`) est générique sur `RecordStore`. Sur le `SyncStore` de l'app, une suppression crée une suppression en attente qui partirait vers CloudKit : effacer la seule copie distante. Ajouts au noyau, additifs :

- `RecordStore::evict(kind, id)` : retire la copie locale seulement ; par défaut `delete` (CLI inchangée). `SyncStore` le surcharge : la ligne quitte toutes les couches (`base`, `pending`, `staging`, `ancestor`, `kept`) sans rien mettre en attente. `enter_travel` et le retour arrière de `restore` utilisent `evict`.
- `SyncStore::set_travel_hidden(ids)` / `travel_hidden()` (meta locale) : tant que la liste n'est pas vide, `stage_remote` ignore les enregistrements de ces coffres (clé, meta, manifeste, items par préfixe) ; la synchro ne les ramène pas pendant le voyage.
- Vue amont : la couche `base` (dernier état confirmé par le serveur), lue comme un `RecordStore` en lecture seule.

FFI (`Session`) :

- `travel_status()` : actif ou non, date d'entrée, coffres cachés (noms, après déverrouillage).
- `travel_plan()` : coffres qui partent et coffres qui restent, affichés avant confirmation.
- `enter_travel()` : refusé si un enregistrement d'un coffre à cacher attend encore d'être envoyé ; sinon `enter_travel(base)`, état scellé (`seal_travel_state`) rangé dans la meta locale du magasin, liste des coffres cachés posée, base compactée.
- `begin_travel_exit()` puis, après un rechargement complet depuis le serveur, `finish_travel_exit()` : `exit_travel(base, état)` ; succès : meta effacée ; échec (amont qui rejoue un état ancien, item retiré) : les copies sont de nouveau retirées, la liste remise, l'état reste valable, l'erreur est affichée.
- Toute ouverture de session (`Session::new`) qui trouve l'état scellé appelle `resume_travel` : l'app, l'extension AutoFill et les widgets voient les mêmes coffres.

Swift : `VaultSession` lance d'abord une synchro (envoi des attentes), montre le plan, demande Touch ID ou le mot de passe, puis entre ; la sortie lance `refetchFromScratch` puis `finish_travel_exit`. Réglages > Travel Mode sur Mac et iOS, interrupteur « Sûr en voyage » dans l'éditeur de coffre.

Ruling: `evict` comme méthode par défaut du trait plutôt qu'un second chemin de Travel Mode - le noyau garde une seule logique vérifiée, et la CLI ne change pas - coût si faux : une méthode de trait de plus à implémenter pour un futur magasin.

Ruling: amont = couche `base` après une synchro réussie - c'est l'état que le serveur a confirmé, et l'entrée exige qu'aucune écriture locale de ces coffres n'attende - coût si faux : si le serveur a perdu un enregistrement depuis la dernière synchro, la sortie le signale comme un amont incomplet (refus, rien n'est perdu localement tant que l'état scellé reste).

Ruling: la liste des coffres cachés est en clair dans la meta locale - la synchro doit filtrer verrouillée, et la liste signée des coffres (synchronisée) nomme déjà tous les identifiants ; les noms restent chiffrés - coût si faux : un examen du fichier révèle combien de coffres sont cachés, comme `travel.bin` de la CLI.

## 6. Interface

Style de la refonte (`EditorCard`, `PageHeader`, `PageTile`, `CodeBox`, textes en français tutoyé, `String(localized:)`).

- Mac, Réglages : nouvel onglet « Développeur » (agent SSH, serveur MCP, clients, autorisations, journal) ; onglet « Travel Mode ».
- iOS : Réglages > Travel Mode.
- Page Développeur : les cartes ouvrent les réglages au lieu des guides de la CLI ; le guide CLI reste.
- Éditeur de coffre : interrupteurs « Sûr en voyage » et « Accès MCP » (Mac).

## 7. Tests

- Noyau : `evict` sur `SyncStore` ne met rien en attente ; aller-retour du Travel Mode sur `SyncStore` sans aucune suppression en attente ; `stage_remote` ignore les coffres cachés ; amont qui rejoue un manifeste ancien refusé à la sortie, copies retirées.
- `onepass-mcp` : `Workspace` scripté reçoit la commande et les valeurs, le masquage s'applique à la sortie rendue.
- Relais : codec des messages, `hello`, exécution d'une commande, refus d'écrire dans le dossier interdit.
- FFI : agent SSH sur un socket temporaire (liste, signature approuvée, refus), serveur MCP avec un faux relais (pair vérifié par une identité injectée en test), appairage, portées, révocation, journal vérifié ; Travel Mode aller-retour, état repris par une nouvelle session.
- VaultKit : `TravelMode` et les hôtes développeur au-dessus du cœur de test.

## 8. Hors périmètre

- Agent SSH et MCP sur iOS (pas de socket local partagé avec un terminal).
- Appairage par client et liste de clés par client pour l'agent SSH (la CLI ne le fait pas encore non plus).
- État de voyage partagé entre appareils (voir le premier ruling).

## 9. Récapitulatif des rulings

1. Drapeau synchronisé = `travel_safe` ; état de voyage par appareil.
2. Serveurs dans l'app par FFI.
3. Panneau natif plus Touch ID au lieu du code de terminal.
4. Agent arrêté au verrouillage.
5. Relais embarqué qui exécute pour l'app.
6. Identité du client annoncée par le relais vérifié.
7. Pas de canal de contrôle dans l'app.
8. Politique signée obligatoire dans l'app.
9. `evict` par défaut du trait.
10. Amont = `base` après synchro.
11. Liste des coffres cachés en clair dans la meta locale.
