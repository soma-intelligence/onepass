# OnePass prêt pour les agents : approbation sur iPhone, déverrouillage à distance, installation en une commande

Date : 2026-10-28
Statut : en revue (design validé section par section avec le fondateur le 2026-10-28)
Portée : au-dessus du jalon 7 dans les apps (`2026-10-27-m7-app-design.md`), rendre le serveur MCP de l'app Mac utilisable par tout agent IA du Mac, y compris quand le titulaire n'est pas devant l'écran. Branche `docs/agent-ready-spec`, implémentation sur une branche partie de `feat/onepass-redesign`.

## 1. Compréhension

Ce que le fondateur veut : un agent IA qui tourne sur le Mac (Claude Code, Claude desktop, Codex, Cursor) utilise les secrets de OnePass sans terminal, sans jamais voir une valeur qu'il n'a pas le droit de voir, et le titulaire approuve chaque demande là où il se trouve : sur le Mac, sur la montre ou sur l'iPhone, même loin du Mac.

Décisions prises pendant le design :

- Approbations : panneau du Mac (Touch ID ou montre) **et** iPhone, en parallèle, la première réponse valide gagne.
- Coffre verrouillé : l'iPhone peut le déverrouiller à distance, pour les agents seulement, pendant une fenêtre bornée.
- Transport Mac vers iPhone : base privée CloudKit et notification visible, sans serveur à nous.

Ce qui existe déjà et reste (jalon 7, durcissement, jalon 7 dans les apps) :

- Serveur MCP dans l'app Mac par FFI, relais embarqué `OnePass.app/Contents/Helpers/onepass-mcp` (crate `onepass-mcp-relay`) sur `<conteneur>/.onepass/mcp.sock`, qui exécute `run_with_secrets` et `fill_template` hors du bac à sable.
- Identité du client (premier ancêtre non lanceur, `onepass-peer`), appairage par Touch ID, portées par coffre, autorisations courtes et révocables, limites de débit, blocage après refus, journal chaîné et signé, politique signée obligatoire.
- Rappel Swift `FfiDeveloperUi` (`approve`, `pair_request`, `verify_presence`), servi par `PromptBridge` dans `VaultKit/Developer/DeveloperHosts.swift`.
- Réglages > Développeur : copier le bloc `mcpServers`.
- Déverrouillage biométrique : `Account::unlock_exporting_auk` et `unlock_with_auk` (AUK gardée dans le trousseau derrière la biométrie).

Ce qui manque, et que cette spec ajoute :

1. Une approbation hors du Mac (iPhone, et la montre par la notification relayée).
2. Un service aux agents quand l'app est verrouillée (ruling 4 du jalon 7 dans les apps : « agent arrêté au verrouillage »), sans clé hors d'un appareil.
3. Une installation en une commande dans les clients MCP courants.
4. Une documentation destinée aux agents qui les pousse vers `run_with_secrets` et les références `onepass://`.

Critère de réussite : depuis Claude Code sur un Mac verrouillé, le titulaire étant loin, une demande `run_with_secrets` déclenche une notification sur l'iPhone ; un Face ID déverrouille le coffre pour les agents et approuve la demande ; la commande tourne avec le secret injecté et masqué ; le journal signé nomme l'iPhone comme approbateur. Tous les tests Rust et Swift passent, le modèle ProVerif étendu prouve le secret de l'AUK face à un CloudKit hostile.

## 2. Approches

1. **CloudKit privé et notification visible (retenue).** Le Mac écrit une demande scellée et signée dans la base privée ; un `CKQuerySubscription` déclenche une notification sur l'iPhone ; l'iPhone répond par un enregistrement signé.
2. Relais hébergé et APNs. Plus rapide, utilisable hors Apple plus tard, mais un serveur à exploiter, une clé APNs à garder, et un tiers qui sait quand le coffre sert.
3. Réseau local seulement (Bonjour, comme l'appairage). Aucun nuage, mais inutile loin du Mac, qui est le cas demandé.

Ruling: CloudKit privé et notification visible - aucun serveur, la synchro CloudKit existe déjà, le stockage reste traité comme hostile (il ne voit que du chiffré signé) - coût si faux : changer le transport des enregistrements, le protocole au-dessus ne bouge pas.

Ruling: notification visible à niveau « sensible au temps », pas de notification silencieuse - iOS limite les notifications silencieuses et peut les retarder de plusieurs minutes - coût si faux : aucun, une notification visible arrive au moins aussi vite.

## 3. Architecture

```
agent (Claude Code, Claude desktop, Codex, Cursor)
  stdio MCP -> OnePass.app/Contents/Helpers/onepass-mcp (relais existant)
  -> mcp.sock -> OnePass.app : gardes (clients, portées, limites, journal) + coffre
       -> approbation : panneau Mac (Touch ID / montre)  ||  iPhone par CloudKit
          première réponse valide gagne, l'autre est retirée
       -> coffre verrouillé : déverrouillage à distance par l'iPhone, agents seulement, fenêtre bornée
```

Unités nouvelles :

- `onepass-core::approvers` : registre signé des clés d'approbation par appareil (section 4).
- `onepass-core::remote` : protocole des demandes et réponses à distance, scellement, signature, vérification (section 5). Aucune E/S.
- `onepass-core::remote_unlock` : enrôlement, enveloppe `C`, ouverture, révocation (section 6).
- `onepass-ffi::remote` : exposition à Swift de ces trois modules sur la `Session`.
- `VaultKit/Remote/` : transport CloudKit (`RemoteChannel`), coordinateur d'approbation côté Mac (`RemoteApprover`), écran et coordinateur côté iPhone (`AgentRequestsView`, `RemoteResponder`).
- `PromptBridge` devient une course entre le panneau du Mac et `RemoteApprover`.
- `onepass-mcp-relay` gagne la sous-commande `install` (section 8).

Règle de frontière inchangée : seul le Rust manipule les clés et vérifie les signatures ; Swift transporte des octets opaques et affiche.

## 4. Clés d'approbation par appareil

La liste des appareils (`devices.rs`, `DeviceEntry`) ne porte aucune clé publique. Un nouvel enregistrement signé, additif, les ajoute :

```
approvers = SignedConfig(domaine "approvers", signé par la clé du compte) {
  generation: u64,
  entries: [ { device_id, sign_pub: HybridSignPublic (ML-DSA-87 + Ed25519),
               kem_pub: HybridKemPublic (ML-KEM-1024 + X25519),
               role: Mac | Phone, added_at } ]
}
```

- Chaque appareil génère ses deux paires de clés à l'activation de la fonction, garde les privées dans son trousseau (ce seul appareil, sans synchro iCloud), signe l'entrée avec la clé du compte (le coffre est ouvert à ce moment) et l'enregistrement part par la synchro CloudKit habituelle.
- Une entrée ne vaut que si son `device_id` figure dans la liste des appareils et n'y est pas révoqué. Révoquer un appareil invalide donc ses clés d'approbation sans autre écriture.
- Chaque appareil garde en mémoire la plus haute `generation` vue (comme le registre des clients) : un registre plus ancien rejoué est refusé.

Ruling: registre séparé plutôt que des champs dans `DeviceEntry` - aucun changement du format de la liste des appareils, les anciens clients l'ignorent - coût si faux : une lecture de plus à chaque vérification, mise en cache par session.

Ruling: clé privée du téléphone hors synchro iCloud - une clé synchronisée laisserait n'importe quel appareil du compte Apple répondre à la place du téléphone - coût si faux : un nouveau téléphone doit s'enrôler à nouveau.

## 5. Approbation à distance

### 5.1 Messages

Demande (Mac vers un téléphone), une par téléphone enrôlé :

```
RemoteRequest { v: 1, request_id: [u8; 16], from: device_id (Mac), to: device_id (téléphone),
  created_at, expires_at (created_at + 60 s), registry_generation (clients),
  approvers_generation, kind: Approve | Unlock | ApproveAndUnlock | Pair,
  body: scellé pour kem_pub du téléphone {
    client: identité vérifiée affichable, action, lignes de détail non secrètes,
    cibles (coffre, item, champ en noms), remember_allowed, strong_required,
    confirm_code (2 lettres, celles montrées à l'agent),
    unlock_eph_pub (si Unlock) } }
  signature hybride du Mac sur tout ce qui précède
```

Réponse (téléphone vers Mac) :

```
RemoteResponse { v: 1, request_id, from: téléphone, to: Mac, created_at,
  decision: Denied | Once | Grant5m,
  unlock: Option<scellé pour unlock_eph_pub { K_r }>,
  signature hybride du téléphone }
```

- Scellement : `kem::wrap_key_labeled` avec les étiquettes `onepass/remote/request/v1` et `onepass/remote/unlock/v1`, contexte = `request_id || from || to`, comme la charge de la montre (`companion.rs`).
- Le Mac n'accepte qu'une réponse par `request_id`, signée par un téléphone du registre, adressée à lui, avant `expires_at` (horloge du Mac), pour une demande qu'il a lui-même émise et qui attend encore. Toute autre réponse est refusée et journalisée.
- Le téléphone refuse une demande expirée, non signée par un Mac du registre, ou déjà vue (liste des `request_id` des 24 dernières heures).

### 5.2 Transport CloudKit

- Zone `AgentRequests` de la base privée, type d'enregistrement `RemoteMessage` : `to` (identifiant d'appareil en clair, pour l'abonnement), `blob` (octets du message), `expires_at`.
- Chaque appareil s'abonne aux enregistrements dont `to` est son identifiant. Côté iPhone : notification visible, `interruptionLevel = .timeSensitive`, texte générique (« Demande d'un agent sur <nom du Mac> »), sans nom de coffre, d'item ni de commande, car Apple voit ce texte. Côté Mac : abonnement plus lecture toutes les 2 s tant qu'une demande attend.
- L'émetteur efface ses enregistrements à la réponse ou à l'expiration ; chaque appareil efface au lancement ceux qui ont expiré.

Ruling: identifiant d'appareil en clair dans l'enregistrement - l'abonnement CloudKit ne filtre que sur des champs lisibles, et la liste des appareils nomme déjà ces identifiants - coût si faux : CloudKit sait quel appareil reçoit une demande et quand (risque résiduel, section 9).

### 5.3 Course côté Mac

`PromptBridge.approve` :

1. Calcule le code de confirmation et le renvoie à l'agent dans une notification MCP de progression (« Approuve sur ton Mac ou ton iPhone, code `kq` »).
2. Ouvre le panneau du Mac et, si au moins un téléphone est enrôlé et CloudKit joignable, émet une `RemoteRequest` par téléphone.
3. La première réponse valide gagne : clic plus Touch ID sur le Mac, ou `RemoteResponse` vérifiée. Le panneau se ferme, les demandes restantes sont effacées, un refus ailleurs n'annule pas une approbation déjà retenue.
4. Délai de 60 s, puis refus, comme aujourd'hui.
5. L'entrée du journal gagne le champ `approved_on` : `mac` ou `phone:<device_id>`.

`strong_required` (`reveal_secret`, `totp_code`, appairage) : sur le Mac, Touch ID ou le mot de passe de session ; sur l'iPhone, Face ID (`.biometryCurrentSet`). Un geste sur la montre seule ne vaut jamais approbation forte ni déverrouillage à distance.

Ruling: la montre approuve seulement par le panneau du Mac (déverrouillage par la montre de LocalAuthentication) et voit les notifications de l'iPhone sans pouvoir y répondre - une action de notification sur la montre ne peut pas exiger une biométrie, et l'approbation à distance doit prouver la présence - coût si faux : un tap de plus (ouvrir l'iPhone) quand le titulaire n'a que sa montre.

Sans iCloud, sans téléphone enrôlé ou CloudKit injoignable : panneau du Mac seul, et le panneau le dit (« iPhone indisponible : approuve ici »).

## 6. Déverrouillage à distance

### 6.1 Enrôlement

Désactivé par défaut. Réglages > Développeur > « Déverrouiller depuis mon iPhone » sur le Mac, avec le coffre ouvert :

1. Touch ID sur le Mac.
2. Le Mac tire `K_r` (32 octets aléatoires, `aws_lc_rs::rand`), calcule `C = seal(K_r, BlobKind::RemoteUnlock, aad = mac_device_id || phone_device_id, AUK)` et garde `C` dans son trousseau (ce seul appareil).
3. Le Mac envoie `K_r` scellé pour `kem_pub` du téléphone dans une `RemoteRequest` de type `Pair`. Le téléphone affiche le nom du Mac et le code, demande Face ID, puis range `K_r` dans son trousseau (`.biometryCurrentSet`, ce seul appareil, sans synchro).
4. Le Mac efface `K_r` de sa mémoire (`Zeroizing`). À partir de là, ni le Mac seul (il n'a que `C`), ni le téléphone seul (il n'a que `K_r`), ni CloudKit (il ne voit que des scellés) ne peut ouvrir le coffre.

Un `C` par couple (Mac, téléphone). Changer le mot de passe maître ou faire tourner l'AUK efface tous les `C` et demande de réenrôler.

### 6.2 Ouverture

1. Une demande d'agent arrive, app verrouillée, déverrouillage à distance enrôlé : le relais garde la connexion, l'app émet une `RemoteRequest` `ApproveAndUnlock` avec une clé éphémère hybride `unlock_eph_pub` neuve et le détail de la demande.
2. L'iPhone affiche « <nom du Mac> est verrouillé. Déverrouiller pour les agents et autoriser cette demande ? », le détail, le code et la durée de la fenêtre. Face ID débloque `K_r`, qui part scellé pour `unlock_eph_pub`.
3. Le Mac ouvre le scellé avec sa clé éphémère, ouvre `C`, appelle `unlock_with_auk`, efface `K_r`, l'AUK et la clé éphémère, puis sert la demande. Un seul Face ID couvre le déverrouillage et cette demande ; les suivantes de la fenêtre sont approuvées comme d'habitude.
4. Sans réponse en 60 s : refus, message à l'agent « OnePass est verrouillé sur ce Mac. Approuve sur ton iPhone ou déverrouille l'app. ».

### 6.3 Mode agents seulement

Une session ouverte à distance est marquée `AgentOnly` dans la `Session` FFI :

- seuls les serveurs MCP et SSH la servent ; l'interface de l'app, l'extension, l'AutoFill et les widgets la voient verrouillée et exigent Touch ID ou le mot de passe ;
- fenêtre de 1 h par défaut, réglable de 15 min à 8 h, sans prolongation par l'usage ;
- fin anticipée : « Verrouiller maintenant » sur l'iPhone (message signé `Lock`), verrouillage manuel du Mac, mise en veille, fermeture de session macOS ;
- à la fin, la session est fermée et les clés effacées comme à un verrouillage normal.

Ruling: mode agents seulement plutôt qu'un déverrouillage complet - un Mac laissé sans surveillance ne doit pas montrer le coffre à qui s'assoit devant - coût si faux : le titulaire revenu devant le Mac déverrouille une seconde fois.

Ruling: ce mode remplace, pour les sessions ouvertes à distance seulement, le ruling 4 du jalon 7 dans les apps (« agent arrêté au verrouillage ») - un verrouillage normal arrête toujours les agents - coût si faux : aucun pour qui n'enrôle pas.

### 6.4 Révocation

- iPhone, Réglages > Agents > <Mac> > « Oublier le déverrouillage à distance » : efface `K_r`, envoie `ForgetUnlock` signé ; le Mac efface `C`.
- Mac, même réglage : efface `C`, envoie `ForgetUnlock` au téléphone.
- Appareil révoqué dans la liste des appareils : l'autre côté efface sa moitié au prochain chargement de la liste.
- Une moitié seule ne sert à rien : un message de révocation perdu ne rouvre rien.

## 7. Interface

Style de la refonte (`EditorCard`, `PageHeader`, `CodeBox`, textes en français tutoyé et en anglais, `String(localized:)`).

- Mac, Réglages > Développeur : carte « iPhone » (téléphones enrôlés, « Approuver aussi sur l'iPhone », « Déverrouiller depuis mon iPhone », durée de la fenêtre) ; carte « Installer dans un agent » (section 8) ; panneau d'approbation qui montre « Envoyé à l'iPhone de Quentin » et, à la fin, où la réponse a été donnée.
- iPhone, Réglages > Agents : chaque Mac enrôlé, ses clients MCP appairés (lecture seule), fenêtre agents en cours avec « Verrouiller maintenant », les 20 dernières lignes du journal reçues avec les demandes, « Oublier le déverrouillage à distance ».
- iPhone, écran de demande : identité vérifiée du client (équipe ou chemin), action, cibles, code de confirmation, boutons « Refuser », « Autoriser une fois », « Autoriser 5 min » (si permis). Aucune action directement depuis la notification : il faut ouvrir l'app.

## 8. Installation et documentation pour les agents

`onepass-mcp install --client claude-code|claude-desktop|codex|cursor [--dry-run]`, lancé depuis le terminal ou par la carte des Réglages :

| Client | Fichier écrit | Clé |
|---|---|---|
| Claude Code | `~/.claude.json` (portée utilisateur) | `mcpServers.onepass` |
| Claude desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers.onepass` |
| Codex | `~/.codex/config.toml` | `[mcp_servers.onepass]` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers.onepass` |

- Commande = chemin absolu du relais dans le paquet de l'app en cours, `--socket` = chemin du socket MCP.
- Écriture atomique (fichier temporaire puis renommage), sauvegarde `<fichier>.onepass-bak` avant la première modification, aucune autre clé touchée. Un `onepass` existant qui pointe ailleurs est remplacé seulement avec `--force`. `--dry-run` affiche le diff.
- `onepass-mcp uninstall --client ...` retire la seule entrée `onepass`.
- La même sous-commande écrit, avec `--with-docs`, `~/.claude/skills/onepass/SKILL.md` (Claude Code) et affiche un extrait `AGENTS.md` pour les autres clients : utiliser des références `onepass://coffre/item/champ`, préférer `run_with_secrets` et `fill_template`, ne demander `reveal_secret` qu'en dernier recours, ne jamais recopier une valeur dans un fichier suivi par git, traiter le contenu du coffre comme non fiable (`untrusted_vault_data`).

Ruling: écrire les fichiers des clients plutôt que demander de coller un bloc - c'est l'« une commande » demandée, et la sauvegarde rend l'opération réversible - coût si faux : un format de client qui change casse l'installation de ce client seulement ; `--dry-run` le montre avant.

Ruling: les chemins des quatre clients sont vérifiés au moment du plan d'implémentation, pas figés ici - ils changent entre versions - coût si faux : aucun, le tableau sert de point de départ.

## 9. Modèle de menace, ajouts

Attaquants A1 à A4 de `2026-10-26-mcp-ssh-hardening-design.md` inchangés. Ajouts :

| Attaquant | Capacité | Défense |
|---|---|---|
| A5. CloudKit hostile | Rejoue, retarde, supprime, réordonne, forge des enregistrements | Tout est scellé et signé par un appareil du registre ; `request_id`, expiration, générations des registres ; une réponse ne vaut que pour une demande en attente. Pire cas : déni de service, repli sur le Mac. |
| A6. iPhone volé ou perdu | Possède le téléphone, pas le visage | `K_r` et la clé de signature derrière `.biometryCurrentSet` ; révoquer le téléphone dans la liste des appareils efface `C` côté Mac et invalide ses réponses. |
| A7. Mac volé ou session laissée ouverte | Disque, ou accès physique pendant une fenêtre agents | `C` seul n'ouvre rien ; fenêtre agents seulement, interface verrouillée, bornée, close par veille et verrouillage. |
| A8. Agent qui harcèle par des déverrouillages | Déclenche des demandes en boucle | Au plus 1 demande de déverrouillage par 10 min et par Mac ; 3 refus bloquent le déverrouillage à distance 1 h ; limites existantes par client. |
| A9. Fausse notification | Envoie au titulaire une notification qui imite OnePass | Aucune action depuis la notification ; l'app affiche le détail déchiffré et signé avant Face ID ; code de confirmation visible côté agent et côté téléphone. |

Risques résiduels, documentés : CloudKit et Apple voient quand et combien de demandes sont faites et quel appareil les reçoit. Un processus malveillant du même utilisateur, signé par une équipe appairée, pendant une fenêtre agents, reste le cas « système compromis » hors périmètre de la spec d'architecture.

## 10. Tests

- Rust, `approvers` : signature par la clé du compte, appareil révoqué ignoré, génération plus ancienne refusée.
- Rust, `remote` : aller-retour scellé et signé ; refus d'une réponse expirée, rejouée, d'un autre appareil, d'un appareil révoqué, adressée à un autre Mac, pour une demande inconnue ; demande dont la génération des clients a reculé.
- Rust, `remote_unlock` : enrôlement puis ouverture donnent la même AUK que le mot de passe ; `C` seul et `K_r` seul n'ouvrent rien ; révocation ; changement de mot de passe qui efface les `C`.
- FFI : session `AgentOnly` refuse les appels d'interface et sert MCP ; fin de fenêtre ; `PromptBridge` avec un approbateur à distance scripté (première réponse gagne, l'autre retirée, refus tardif ignoré).
- Swift : `RemoteChannel` sur un faux CloudKit en mémoire ; `RemoteResponder` (Face ID simulé) ; écran de demande sur le simulateur.
- Relais : `install` et `uninstall` dans un `HOME` temporaire pour les quatre clients, sauvegarde, `--dry-run`, `--force`, fichier existant avec d'autres serveurs intact.
- Bout en bout : relais signé, vrai client MCP, app sur un coffre de test, réponse à distance injectée par le faux CloudKit.
- Modèle formel : extension du modèle ProVerif (`formal/`) avec l'enrôlement et l'ouverture à distance ; secret de l'AUK et authenticité des réponses face à un CloudKit qui contrôle le réseau.
- Seulement sur du vrai matériel : délai de livraison des notifications, Face ID, notification relayée sur la montre, veille du Mac qui ferme la fenêtre.

## 11. Hors périmètre

- Agents sur une autre machine ou dans le nuage, transport HTTP du MCP.
- Approbation sur l'iPad et le Vision Pro (même code que l'iPhone, activés plus tard).
- Relais hébergé, APNs direct, appareils hors Apple.
- Serveurs MCP et SSH sur iOS.

## 12. Récapitulatif des rulings

1. CloudKit privé et notification visible.
2. Notification sensible au temps, pas silencieuse.
3. Registre des clés d'approbation séparé de la liste des appareils.
4. Clés privées du téléphone hors synchro iCloud.
5. Identifiant d'appareil destinataire en clair dans l'enregistrement CloudKit.
6. La montre approuve par le panneau du Mac, pas par la notification.
7. Mode agents seulement après un déverrouillage à distance.
8. Ce mode remplace le ruling 4 du jalon 7 dans les apps pour les sessions ouvertes à distance seulement.
9. Installation par écriture des fichiers des clients, avec sauvegarde.
10. Chemins des clients vérifiés au plan d'implémentation.
