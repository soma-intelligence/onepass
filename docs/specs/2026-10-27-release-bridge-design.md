# Pont de production : extensions Safari, Chrome et Firefox vers l'app Mac

Date : 2026-10-27. Branche : `feat/onepass-redesign`. Statut : approuvée (auto-approbation, accord du fondateur "Construire le pont").
Specs parentes : `2026-10-25-milestone-4-extension-design.md` (R-02, R-03, R-08, R-17), `docs/security/README.md` section 12.

## 1. Rulings

Ruling P-01 : le rendez-vous est un socket Unix `bridge.sock` à la racine du conteneur App Group `<équipe>.me.somalabs.onepass`, servi par l'app Mac elle-même - une app lancée par LaunchServices ne peut pas annoncer de service Mach (NSXPCListener(machServiceName:) exige un job launchd), un service XPC embarqué est privé à chaque client et ne joint pas l'app qui tient le coffre ouvert, et un login item (SMAppService) ajoute un processus, une entrée dans les éléments d'arrière-plan que l'utilisateur doit accepter, puis un second saut vers l'app ; le sandbox autorise bind et connect dans le conteneur du groupe pour ses membres (vérifié le 2026-10-27 avec deux exécutables sandboxés signés de l'équipe) - coût si faux : changer le transport du relais seulement, le protocole au-dessus ne bouge pas.

Ruling P-02 : chaque côté vérifie l'autre par la signature de code, via le jeton d'audit du noyau (`LOCAL_PEERTOKEN`) et `onepass-peer` (cdhash du noyau, exigence `anchor apple generic`, équipe et identifiant exacts) ; l'app n'accepte que `me.somalabs.onepass.safari` et `me.somalabs.onepass.relay` signés par sa propre équipe, les clients n'acceptent que `me.somalabs.onepass` de leur équipe - le conteneur de groupe n'est pas une frontière contre un processus non sandboxé du même utilisateur ; la signature l'est - coût si faux : aucun en production, un build signé ad hoc ne sert ni ne joint le pont (il garde l'hôte de développement).

Amendement P-02 (mesuré le 2026-10-27, exécutables signés de l'équipe) : l'app, même sandboxée, lit toujours la signature d'un client qui se connecte. Mais un processus sandboxé situé dans un bundle d'app reçoit EPERM (`kPOSIXErrorBase + EPERM`) quand il cherche la signature du processus qui écoute ; hors bundle, ou sans sandbox, la recherche réussit. L'extension Safari, forcément sandboxée, vérifie donc l'app quand le système le permet, refuse un pair identifié comme autre chose, et sinon s'en remet au conteneur de groupe et au protocole (une session demande la clé d'appairage, un appairage demande le code comparé avec la feuille Touch ID de l'app). Le relais reste tenu de vérifier l'app (voir P-09).

Ruling P-09 bis : le relais n'est pas sandboxé (runtime renforcé, App Group seul) - sandboxé, il ne pourrait pas vérifier l'app (amendement P-02) et un faux serveur pourrait recevoir les mots de passe d'une proposition d'enregistrement après un faux appairage ; Developer ID l'autorise - coût si faux : une distribution Mac App Store exige un relais sandboxé, qui perdrait cette vérification (choix à refaire avant une soumission).

Ruling P-03 : l'appairage, la session et l'enveloppe chiffrée ne changent pas ; la boucle de connexion de l'hôte (`Conn`) passe de `onepass-native-host` à `onepass-bridge::host`, générique sur le stockage des appairages, l'approbation et le journal - une seule implémentation du protocole côté hôte, celle déjà testée - coût si faux : un déplacement de code, couvert par les tests existants déplacés avec lui.

Ruling P-04 : le serveur tourne dans le processus de l'app, en Rust (`onepass-ffi`, objet `BridgeServer`), sur la `Session` déverrouillée de l'app ; verrouiller l'app verrouille le pont (même `Session`) - le pont doit servir "le coffre que l'utilisateur a ouvert", et seul le Rust touche aux clés - coût si faux : aucun.

Ruling P-05 : approbation de l'appairage dans l'app : feuille avec le nom de l'extension, le navigateur et le code à 6 chiffres, "Approuver" demande Touch ID (ou la montre), et le coffre doit être déverrouillé - un appairage donne un accès durable au coffre, c'est une décision du titulaire - coût si faux : sans biométrie enrôlée, l'appairage est refusé ; enrôler Touch ID d'abord.

Ruling P-06 : clés d'appairage dans le trousseau (élément générique `me.somalabs.onepass.bridge`, `WhenUnlockedThisDeviceOnly`, jamais synchronisé), un élément par appairage ; elles transitent par Swift comme la Secret Key - spec 6.4 ("app réelle : trousseau") - coût si faux : Swift voit 32 octets de clé de canal, pas une clé de coffre.

Ruling P-07 : items `reprompt` : l'app demande Touch ID à chaque fois ; sans biométrie, `reprompt_required` - même règle que l'app - coût si faux : aucun.

Ruling P-08 : `unlock` demandé par l'extension met l'app au premier plan et répond `locked` ; le déverrouillage se fait dans l'app - jamais de mot de passe maître hors de l'app - coût si faux : un clic de plus.

Ruling P-09 : Chrome et Firefox lancent `OnePass.app/Contents/Helpers/onepass-relay`, un relais minimal (App Group seulement, voir P-09 bis) qui recopie les trames de 1 MiB au plus dans les deux sens sans les lire ; il transmet l'identifiant d'extension que le navigateur lui donne dans une trame d'ouverture, contrôle informatif comme dans l'hôte de dev - le vrai garde reste l'appairage - coût si faux : aucun.

Ruling P-10 : identifiants d'extension Chrome et Firefox autorisés : la liste `OnePassBrowserExtensions` de l'Info.plist de l'app (réglage `ONEPASS_BROWSER_EXTENSIONS`), Firefox `onepass@somalabs.me` par défaut, l'identifiant Chrome à ajouter (non publié aujourd'hui) - pas d'identifiant inventé - coût si faux : un build pour ajouter un identifiant.

Ruling P-11 : le manifeste de messagerie native (`me.somalabs.onepass`) est installé par `extension/scripts/install-app-host.mjs`, pas par l'app - une app sandboxée n'écrit pas dans le dossier de Chrome sans exception temporaire d'entitlement, à décider avant l'App Store - coût si faux : une étape manuelle jusqu'à un bouton dans l'app.

Ruling P-12 : l'extension parle à l'hôte `me.somalabs.onepass` ; `node build.mjs --dev-host` (et les builds de test e2e et du labo) garde `me.somalabs.onepass.dev` - pas de repli silencieux d'un hôte à l'autre - coût si faux : reconstruire avec le bon drapeau.

Ruling P-13 : Debug inchangé : l'appex embarque l'hôte de développement et le préfère ; sans lui, elle tente le socket de l'app - coût si faux : aucun.

Ruling P-14 : au plus 8 connexions simultanées côté app, une par thread à pile de 16 Mio (SLH-DSA), trames et délais de `onepass-bridge::host` - coût si faux : une neuvième connexion est fermée, l'extension réessaie.

## 2. Chemin des données

```
Safari : page -> extension (safari.ts) -> sendNativeMessage -> OnePassSafari.appex (RelayHub)
            -> socket bridge.sock (signature vérifiée des deux côtés) -> OnePass.app (BridgeServer)
Chrome : page -> extension (native.ts) -> connectNative("me.somalabs.onepass") -> onepass-relay
            -> socket bridge.sock (idem) -> OnePass.app (BridgeServer)
OnePass.app : onepass-bridge::host::Conn (appairage, session, Service) -> Session du coffre ouvert
```

Trame d'ouverture (client vers app, première trame, même framing) : `{"onepass_relay":1}` pour Safari, `{"onepass_relay":1,"caller":"<argument du navigateur>"}` pour le relais. Ensuite les enveloppes passent octet pour octet.

## 3. Messages à l'utilisateur

- App fermée ou non installée : le socket manque ou refuse, le relais ou l'appex ferme, l'extension montre "App OnePass introuvable / Installe ou ouvre l'app OnePass sur cet ordinateur" (texte existant, exact).
- App verrouillée : `status` répond `locked`, "OnePass est verrouillé", le bouton met l'app au premier plan.
- App : feuille d'appairage et liste "Navigateurs" (oublier un appairage) dans Réglages, en français et en anglais.

## 4. Tests

Rust : `onepass-bridge` (boucle déplacée), `onepass-relay` (trame d'ouverture, politique de pair, recopie bornée, serveur et client sur un socket temporaire), `onepass-ffi` (serveur sur une session de test, appairage approuvé et refusé, verrou). Swift : `SafariRelay` (lanceur socket). Extension : vitest et tsc. Bout en bout : relais et serveur de test signés par l'équipe et sandboxés, client TypeScript réel.
