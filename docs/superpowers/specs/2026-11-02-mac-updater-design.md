# Mises à jour de l'app Mac depuis GitHub : conception

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, rulings en section 9).

Demande du fondateur : « un système pour mettre à jour l'application depuis GitHub, qui vérifie si une mise à jour est disponible ».

## 1. But et périmètre

L'app Mac distribuée hors App Store (Developer ID, notarisée, `OnePass-<v>-mac.zip` sur les Releases de `soma-intelligence/onepass`) vérifie au lancement puis toutes les 24 heures si une version plus récente est publiée, propose de l'installer, et ne remplace jamais l'app par un binaire non vérifié.

Hors périmètre :

- iPhone, iPad, Apple Watch, Vision Pro : App Store et TestFlight, aucune mise à jour par l'app. Rien n'est affiché (la section n'existe que sur le Mac).
- Extensions Chrome et Firefox : mises à jour par leurs magasins. L'extension Safari fait partie de l'app Mac et suit sa mise à jour.
- CLI `onepass` : binaire de développement, pas de mise à jour automatique.

## 2. Choix : Sparkle 2

Sparkle 2.10.1 (paquet Swift, binaire vérifié par sa somme de contrôle SwiftPM) plutôt qu'un installateur écrit à la main. Sparkle apporte, testé par des milliers d'apps :

- signature EdDSA (Ed25519) de l'archive, vérifiée **avant** extraction (`SUVerifyUpdateBeforeExtraction`) ;
- signature EdDSA du flux lui-même (`SURequireSignedFeed`) : un flux modifié est refusé ;
- contrôle de la signature Apple de la nouvelle app : Developer ID, et même Team ID que l'app installée (ABCDE12345) ;
- installation par son service XPC, compatible avec le bac à sable (`SUEnableInstallerLauncherService` et deux exceptions `mach-lookup`) ;
- refus de toute version qui n'est pas strictement plus récente.

OnePass ajoute un garde à lui : le délégué refuse toute version dont le numéro (`sparkle:version`) n'est pas strictement supérieur au `CFBundleVersion` installé, comparé en nombres (`UpdateVersionPolicy`), même si Sparkle l'avait accepté. Le ticket de notarisation est vérifié dans la chaîne de publication avant la signature EdDSA : la clé ne signe qu'une archive notarisée et agrafée.

## 3. Le flux (appcast)

- Adresse fixe : `https://github.com/soma-intelligence/onepass/releases/latest/download/appcast.xml`. GitHub la redirige vers le fichier `appcast.xml` de la release marquée *Latest*. Le flux devient visible au moment où une personne publie le brouillon, jamais avant.
- Une préversion (tag avec suffixe, `v0.3.0-rc.1`) n'est jamais *Latest* : elle n'est proposée à personne.
- Un seul élément par flux : la release elle-même. Pas de mises à jour delta (ruling U6).
- L'élément porte `sparkle:version` (= `CFBundleVersion` de l'app livrée), `sparkle:shortVersionString`, `sparkle:minimumSystemVersion` (= `LSMinimumSystemVersion`), `sparkle:hardwareRequirements` `arm64`, une description en texte brut (pas de HTML, pas de vue web), l'URL de la page de release, l'URL du zip, sa taille et sa signature `sparkle:edSignature`. Le flux se termine par le bloc `sparkle-signatures` (signature Ed25519 du contenu et sa longueur).

## 4. Numéros de version

- `CFBundleShortVersionString` = `MARKETING_VERSION` (inchangé).
- L'app Mac Developer ID reçoit `CFBundleVersion` = le cœur numérique du tag (`v0.3.0` donne `0.3.0`, `v0.3.0-rc.1` donne aussi `0.3.0`), passé à `xcodebuild` par le workflow. Les autres builds gardent `CURRENT_PROJECT_VERSION`.
- Le script d'appcast lit `CFBundleVersion` et `CFBundleShortVersionString` dans le zip et refuse s'ils ne correspondent pas à la version publiée.

## 5. L'app

Paquet local `apple/UpdateKit` (macOS seulement, dépend de Sparkle), lié à la cible `OnePass` pour la destination macOS uniquement :

- `UpdateConfiguration.status(info:)` lit l'Info.plist : clé publique vide = mises à jour désactivées (build de développement, aucun menu) ; clé qui n'est pas 32 octets en base64, flux non HTTPS, flux non signé exigé, vérification avant extraction coupée, profilage système allumé = configuration invalide, désactivée et journalisée.
- `UpdateVersionPolicy.isUpgrade(from:to:)` : versions pointées purement numériques, strictement supérieures, sinon refus.
- `AppUpdater` (`@MainActor`, `@Observable`) enveloppe `SPUStandardUpdaterController` : démarrage, vérification en arrière-plan au lancement si les vérifications automatiques sont actives, intervalle de 24 h, `checkForUpdates()`, `canCheckForUpdates`, réglage `automaticallyChecksForUpdates` (stocké par Sparkle dans les préférences de l'app).

Interface (Mac seulement) :

- Menu OnePass, après « À propos » : « Rechercher les mises à jour… ».
- Réglages, À propos, section « Mises à jour » : interrupteur « Rechercher automatiquement les mises à jour » (actif par défaut), bouton « Rechercher maintenant », une phrase sur ce que la requête envoie.
- Les fenêtres de Sparkle (mise à jour trouvée, téléchargement, installation) sont les siennes, traduites par Sparkle en français, anglais, espagnol et italien.
- Installation : toujours après l'accord de l'utilisateur (`SUAllowsAutomaticUpdates` à `NO`, pas d'installation silencieuse).

Info.plist (toutes plateformes, valeurs vides hors Mac utile) : `SUFeedURL` = `$(ONEPASS_UPDATE_FEED_URL)`, `SUPublicEDKey` = `$(ONEPASS_SPARKLE_PUBLIC_KEY)`, `SURequireSignedFeed`, `SUVerifyUpdateBeforeExtraction`, `SUEnableAutomaticChecks`, `SUScheduledCheckInterval` 86400, `SUAllowsAutomaticUpdates` `NO`, `SUEnableSystemProfiling` `NO`, `SUEnableInstallerLauncherService`.

Contrôle de build : la phase `Check update key` (`apple/scripts/check-update-key.sh`) fait échouer tout build macOS signé « Developer ID Application » dont la clé publique n'est pas 32 octets en base64 ou dont le flux n'est pas en HTTPS. Les builds de développement et ad hoc passent sans clé.

## 6. Publication

- `scripts/appcast.py` (bibliothèque standard Python, Ed25519 par OpenSSL 3 ou plus récent, jamais LibreSSL) : lit la graine privée (32 octets en base64, le format de `generate_keys` de Sparkle) dans `SPARKLE_ED_PRIVATE_KEY` ou, sur un Mac, dans le trousseau (élément `https://sparkle-project.org`, compte `ed25519`), vérifie que l'app du zip fait confiance à la clé publique correspondante et porte les bons numéros, signe le zip puis le flux, revérifie les deux signatures, écrit `appcast.xml`. La graine n'est écrite que dans un fichier 0600 d'un dossier temporaire 0700, effacé à la fin.
- `release.yml` : la clé publique vient de la variable d'environnement `SPARKLE_ED_PUBLIC_KEY`, la graine du secret `SPARKLE_ED_PRIVATE_KEY`, toutes deux dans l'environnement `release`. Le job `mac` passe la clé publique et `CFBundleVersion` à `xcodebuild` ; un nouveau job `appcast` (ubuntu, environnement `release`) lance les tests du script puis produit `appcast.xml`, qui rejoint `SHA256SUMS`, l'attestation et le brouillon.
- Une préversion n'est plus marquée par `0.` mais seulement par un suffixe : une 0.x publiée devient *Latest* et donc proposée.
- La clé n'est jamais générée par le dépôt ni par un agent : le fondateur la crée une fois (`docs/security/release-pipeline.md`).

## 7. Vie privée

La vérification est une requête HTTPS GET vers `github.com`, redirigée vers le stockage des releases de GitHub. Elle porte l'en-tête User-Agent habituel (nom et version de l'app, version de Sparkle), aucun identifiant de compte, d'appareil ou d'installation, aucun profil système, aucun cookie posé par OnePass. Le téléchargement de la mise à jour, quand l'utilisateur l'accepte, est un GET du même genre. Couper l'interrupteur arrête toute requête automatique.

## 8. Tests

- Python (`scripts/test_appcast.py`) : vecteur RFC 8032, signature puis vérification, archive ou flux modifié refusé, flux complet relu comme Sparkle le relit, refus d'une clé qui ne correspond pas, de numéros faux, d'un flux HTTP, d'une graine de mauvaise taille, et le script `check-update-key.sh` sur ses cas.
- Swift (`UpdateKitTests`) : `UpdateConfiguration` (désactivé, valide, chaque refus), `UpdateVersionPolicy` (plus récent, égal, plus ancien, non numérique).
- Build Mac ad hoc compilé ; vérification de bout en bout (vraie release, vraie clé) à faire par le fondateur à la première version.

## 9. Rulings

- U1 Sparkle 2.10.1 plutôt qu'un installateur maison : signatures EdDSA, Team ID et XPC du bac à sable déjà éprouvés. Coût si faux : une dépendance binaire de plus à suivre (avis de sécurité Sparkle).
- U2 Flux à `releases/latest/download/appcast.xml` plutôt que GitHub Pages : rien à configurer, publié au clic sur Publish. Coût si faux : une release *Latest* sans `appcast.xml` coupe les mises à jour jusqu'à la suivante.
- U3 Préversion = tag avec suffixe seulement (plus `0.*`). Coût si faux : les 0.x publiées s'affichent *Latest* au lieu de *Pre-release* ; cocher *Pre-release* à la main les retire des mises à jour.
- U4 Clé publique par variable d'environnement GitHub, passée en ligne de commande à `xcodebuild` (pas de xcconfig, où `//` couperait une base64). Coût si faux : une variable modifiée par un admin change la clé de confiance, comme un secret.
- U5 Installation toujours confirmée par l'utilisateur. Coût si faux : un correctif de sécurité arrive plus lentement.
- U6 Pas de delta. Coût si faux : téléchargement complet (quelques dizaines de Mo).
- U7 Vérifications automatiques actives par défaut, sans la question de Sparkle au deuxième lancement. Coût si faux : une requête quotidienne que l'utilisateur n'a pas demandée explicitement (documentée, coupable).
- U8 Notarisation vérifiée par la chaîne de publication avant signature, pas par l'app. Coût si faux : une clé EdDSA volée plus un certificat Developer ID volé suffiraient ; l'un sans l'autre ne suffit pas.
- U9 Clés Sparkle présentes aussi dans l'Info.plist iOS (Info.plist partagé), sans effet. Coût si faux : aucun connu.
- U10 Graine Ed25519 de 32 octets seulement (format actuel de `generate_keys`) ; l'ancien format de 96 octets est refusé. Coût si faux : une ancienne clé doit être régénérée.
