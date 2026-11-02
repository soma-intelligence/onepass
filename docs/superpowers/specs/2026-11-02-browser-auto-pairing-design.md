# Association automatique des extensions de navigateur

Date : 2026-11-02
Statut : approuvée (demande du fondateur : "Appairage automatique entre l'extension du navigateur et l'app. Je veux pas que l'utilisateur ait à se faire chier à connecter les deux.")
Portée : complète `2026-10-27-release-bridge-design.md` (pont de production) et la section 6.4 de la spec d'architecture (appairage à code comparé). Le protocole d'appairage (engagement, KEM hybride, MAC de confirmation) ne change pas ; seule l'étape humaine saute quand le système d'exploitation prouve qui parle.

## 1. Ce que l'utilisateur obtient

1. Il installe OnePass sur le Mac, l'ouvre une fois, installe l'extension (Safari, Chrome, Edge, Brave ou Firefox).
2. Il ouvre l'extension : elle affiche "Connexion à OnePass…" puis la liste (ou "OnePass est verrouillé"), avec un toast "Connectée à OnePass". Aucun code, aucune feuille dans l'app, aucun Touch ID pour l'association.
3. L'extension tente aussi l'association en arrière-plan à l'installation et au démarrage du navigateur, si bien que la première ouverture est déjà connectée.
4. Réglages > Appareils > Extensions de navigateur liste chaque extension associée, avec "Associée automatiquement" et le navigateur vérifié par signature. "Oublier" la révoque et bloque son retour automatique ; une association manuelle (code + Touch ID) ou "Autoriser de nouveau" lève le blocage.
5. Un navigateur que l'app ne peut pas vérifier (Chromium non signé, navigateur hors liste, signature illisible) garde le parcours actuel : bouton "Associer à OnePass", code à comparer, Touch ID. Jamais d'association silencieuse.

## 2. Carte du parcours actuel (avant ce changement)

- Safari : JS de l'extension -> `browser.runtime.sendNativeMessage` -> appex `me.somalabs.onepass.safari` (`SafariWebExtensionHandler`, `AppSocket`) -> `bridge.sock` du conteneur de groupe -> `BridgeServer` (Rust, `onepass-ffi/src/bridge.rs`). L'app vérifie la signature de l'appex par le jeton d'audit (`onepass-relay::server::admit`, même équipe, identifiant `<app>.safari`).
- Chrome, Edge, Brave, Firefox : JS -> `connectNative("me.somalabs.onepass")` -> le navigateur lance `OnePass.app/Contents/Helpers/onepass-relay` (manifeste natif, `allowed_origins` / `allowed_extensions`) avec l'origine en argument -> trame d'ouverture `{"onepass_relay":1,"extension":"<id>"}` -> même socket. L'app vérifie la signature du relais (`<app>.relay`), puis compare l'identifiant à `OnePassBrowserExtensions` (Info.plist) ; hors liste : `not_allowed`.
- Appairage (`onepass-bridge::host::Conn::pairing`) : `pair_hello` (engagement), `pair_offer`, `pair_reveal`, `pair_sas`, l'app montre la feuille (`BrowserBridge.show`, "pairing request shown"), l'utilisateur compare et approuve avec Touch ID (`approve`, "pairing approved" ou "pairing refused: no user presence"), `pair_done`, l'utilisateur confirme dans l'extension ("Les codes sont identiques"), `pair_confirm`, `pair_ok`. Clé d'appairage au trousseau (`BridgePairingStore`, `WhenUnlockedThisDeviceOnly`) côté app, IndexedDB côté extension.
- Manifestes natifs : posés à la main (`extension/scripts/install-app-host.mjs`). L'identifiant de l'extension dans la trame d'ouverture est déclaratif : tout processus local peut lancer `onepass-relay` avec un faux identifiant (sécurité 12.x, "Ce que la signature ne prouve pas"). C'est pourquoi le code comparé était la garde.

## 3. Ce que le système prouve, et ce qu'on en fait

- Safari : Safari ne route les messages natifs d'une extension que vers l'appex de l'app qui la contient, et l'app vérifie la signature de cet appex (même équipe, identifiant exact). Une connexion Safari admise est donc notre extension, dans notre bundle signé. Association automatique.
- Famille Chromium et Firefox : la signature du relais prouve que c'est notre binaire, pas qui l'a lancé. On ajoute la preuve manquante : le relais (signé, runtime renforcé, non injectable) identifie son processus parent par sa signature de code (`onepass-peer::identify_pid`, exigence `anchor apple generic`, équipe et identifiant exacts, épinglée au cdhash du noyau), puis relit `getppid()` : s'il a changé, le parent est mort et son pid peut être réutilisé, le relais ne se porte garant de rien. Il transmet l'identité vérifiée dans la trame d'ouverture (`"launcher":"team:<équipe>:<identifiant>"`). L'app n'associe automatiquement que si (a) cette identité est dans la table des navigateurs connus, (b) l'identifiant d'extension est dans `OnePassBrowserExtensions`, (c) la forme de l'identifiant correspond à la famille (32 lettres a-p pour Chromium, autre forme pour Firefox), (d) l'extension n'est pas bloquée par une révocation.
- Un navigateur signé ne lance un hôte natif que pour les extensions listées dans le manifeste ; l'identifiant qu'il passe en argument est donc celui d'une extension installée dans ce navigateur.

## 4. Protocole

- `pair_hello` gagne un champ facultatif `"auto": true` : "associe-moi sans code si tu peux te porter garant, sinon refuse". Absent ou faux : parcours manuel inchangé. Le champ n'entre pas dans la transcription : il ne fait que demander, c'est l'hôte qui décide à partir de faits du système, jamais de l'extension.
- Nouvelle enveloppe hôte vers extension `pair_auto` (sans champ), à la place de `pair_sas`, quand l'hôte se porte garant. Suite identique : `pair_done` (MAC hôte), l'extension vérifie le MAC et confirme d'elle-même, `pair_confirm`, `pair_ok`. La clé d'appairage sort toujours de l'échange ML-KEM-768 + X25519 avec preuve de clé des deux côtés ; aucun secret statique partagé.
- `auto: true` et l'hôte ne peut pas se porter garant (ou l'extension est bloquée) : erreur `not_allowed` juste après `pair_hello`, sans feuille ni activation de l'app. L'extension affiche alors le bouton d'association manuelle.
- Un ancien hôte ignore `auto` et répond `pair_sas` : l'extension en mode automatique abandonne (ferme) et propose le bouton manuel.

## 5. Manifestes natifs posés par l'app

Au lancement de l'app et à chaque retour au premier plan, `NativeMessagingManifests` (VaultKit, macOS) écrit `me.somalabs.onepass.json` pour chaque navigateur installé (détecté par `NSWorkspace` d'après l'identifiant de bundle) dont le dossier de support existe : `path` = `Contents/Helpers/onepass-relay` du bundle en cours, `allowed_origins` = les identifiants Chromium de `OnePassBrowserExtensions`, `allowed_extensions` = les identifiants Firefox. Un fichier identique n'est pas réécrit ; sans relais (build non signé) rien n'est écrit. L'app sandboxée reçoit, pour la seule build signée, une exception `home-relative-path` en lecture-écriture limitée aux dossiers `NativeMessagingHosts` de ces navigateurs (jamais le profil entier : pas d'accès aux cookies).

## 6. Révocation

"Oublier" retire la clé (comme avant) et ajoute l'identifiant d'extension à une liste de blocage (trousseau, même élément de service). Une demande automatique d'une extension bloquée reçoit `not_allowed`. Une association manuelle approuvée par Touch ID pour cet identifiant, ou le bouton "Autoriser de nouveau" des Réglages, lève le blocage.

## 7. Rulings

- Ruling A1 : preuve Chromium et Firefox = signature du processus parent du relais vérifiée par le relais lui-même, puis `getppid()` relu - l'argument du navigateur seul est falsifiable par tout processus local, et l'app ne voit pas le parent de façon fiable à travers le socket - coût si faux : le navigateur lance l'hôte depuis un autre processus que son processus principal, l'utilisateur voit le code (repli manuel, jamais silencieux).
- Ruling A2 : table des navigateurs = Google `EQHXZ8M8AV` (Chrome, Beta, Dev, Canary), Microsoft `UBF8T346G9` (Edge, Beta, Dev, Canary), Brave `KL8N8XSYF4` (Brave, Beta, Nightly), Mozilla `43AQ936H96` (Firefox, Developer Edition, Nightly) ; Vivaldi, Arc, Opera et Chromium non signés restent manuels tant que leur équipe n'a pas été lue avec `codesign -dv` sur une machine - aucune équipe inventée - coût si faux : ces navigateurs montrent le code.
- Ruling A3 : les identifiants hors `OnePassBrowserExtensions` restent refusés (`not_allowed`), comme aujourd'hui, plutôt que de tomber dans le parcours manuel - plus strict que la consigne, aucun comportement relâché - coût si faux : un développeur ajoute son identifiant non empaqueté au réglage de build.
- Ruling A4 : l'identifiant Chrome Web Store n'est pas connu (extension pas encore publiée) ; il n'est pas inventé et pas forcé par une clé `key` dans le manifeste - publier fixe l'identifiant - coût si faux : jusqu'à son ajout dans `ONEPASS_BROWSER_EXTENSIONS`, Chrome n'a ni manifeste posé ni association automatique.
- Ruling A5 : l'association automatique ne demande pas le coffre déverrouillé - elle n'échange que des clés, toute lecture passe par une session qui exige le coffre ouvert et les règles de présence par remplissage (`reprompt`) - coût si faux : une association peut se faire pendant que le coffre est verrouillé, révocable dans les Réglages.
- Ruling A6 : `auto` hors transcription - un attaquant qui retire `auto` n'obtient que le parcours avec code, un attaquant qui l'ajoute n'obtient rien que l'hôte n'aurait accordé à une demande signée - coût si faux : aucun sur les clés, qui restent liées à toute la transcription.
- Ruling A7 : la révocation bloque par identifiant d'extension (tous navigateurs de cet identifiant) - plus simple qu'une clé par navigateur et sans retour automatique surprise - coût si faux : révoquer Chrome bloque aussi le retour automatique de Brave avec le même identifiant, que l'utilisateur réautorise d'un clic.
- Ruling A8 : manifestes rafraîchis au lancement et au retour au premier plan, uniquement pour les navigateurs dont le dossier de support existe - l'app ne crée pas de dossier de profil pour un navigateur jamais lancé - coût si faux : un navigateur lancé pour la première fois après l'app attend le prochain passage de l'app au premier plan.
- Ruling A9 : aucune notification système à l'association automatique ; la ligne des Réglages ("Associée automatiquement", navigateur vérifié) et le journal `bridge` suffisent - pas de nouvelle autorisation de notifications à demander - coût si faux : une association indésirable n'est vue qu'en ouvrant les Réglages.

## 8. Risques résiduels (sécurité, à reporter dans `docs/security/README.md`)

- Un processus du même utilisateur qui charge dans un navigateur signé une extension portant notre identifiant (Chrome "non empaqueté" avec notre clé publique, module Firefox temporaire avec notre identifiant) obtient une association sans code. Il lui faut l'interface du navigateur (mode développeur, `about:debugging`) ; il n'obtient rien tant que le coffre est verrouillé, et chaque élément `reprompt` demande Touch ID. Révocable, et la révocation tient.
- Un processus du même utilisateur qui réécrit un manifeste natif peut se faire passer pour l'app auprès de l'extension. Il n'a pas le coffre : il ne voit que ce que l'utilisateur enregistre depuis l'extension. L'app réécrit le manifeste à chaque passage au premier plan.
- Un navigateur mis à jour sur place pendant qu'il tourne peut échouer à la vérification de signature jusqu'à son redémarrage : repli manuel.

## 9. Tests

- Rust `onepass-relay` : table des navigateurs, forme des identifiants, garant (Safari, relais vérifié, parent inconnu, identifiant hors liste, famille croisée, bloqué), trame d'ouverture avec `launcher` (stricte, refusée pour Safari).
- Rust `onepass-bridge` : `pair_auto` de bout en bout sans approbateur, `auto` sans garant -> `not_allowed` sans `begin`, `auto` absent avec garant -> parcours manuel.
- Rust `onepass-ffi` : association automatique sur le serveur réel (pas de `pairing_requested`, `pairing_stored` avec le navigateur vérifié), blocage, levée du blocage.
- Swift : `NativeMessagingManifests` (contenu, familles, idempotence, dossier absent, sans relais), `BridgePairingStore` (champ vérifié, blocage, lecture des anciens éléments).
- Extension : `client.pair` en mode `auto` (`pair_auto` confirme seul, `pair_sas` abandonne, `not_allowed`), `Session` qui s'associe seule quand il n'y a pas d'enregistrement, popup ("Connexion à OnePass…", toast "Connectée").
- Sur appareil (fondateur) : installer l'app et l'extension Chrome de zéro, ouvrir l'extension, constater la connexion sans clic.
