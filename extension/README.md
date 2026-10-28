# Extension OnePass

Extension WebExtension (Manifest V3, TypeScript, sans framework, bundle `esbuild`) pour Chromium, Firefox et Safari. Elle parle à l'app (ici, l'hôte natif de développement `onepass-native-host`) par le protocole du pont décrit dans la spec du jalon 4 (`docs/specs/2026-10-25-milestone-4-extension-design.md`) et dans la section "Extension navigateur" de [`docs/security/README.md`](../docs/security/README.md).

Aucune crypto de coffre dans l'extension : elle ne reçoit que ce qu'il faut pour l'action en cours, pour une origine précise, après un geste de l'utilisateur.

## Prérequis

- Node 22 (`npm ci` depuis `extension/`, `package-lock.json` commité, versions exactes).
- Rust via `rustup` (toolchain fixée par `core/rust-toolchain.toml`) pour construire l'hôte natif.
- Pour les tests de bout en bout : `openssl` (certificat auto-signé de test) et Chromium de Playwright (`npx playwright install chromium`).

## Construire

```sh
cd extension
npm ci
npm run build              # dist/chromium, dist/firefox, dist/safari
npm run build:chromium     # un seul navigateur
node build.mjs firefox     # idem pour Firefox ou Safari
node build.mjs --dev       # ajoute des source maps en ligne (absentes par défaut)
node build.mjs --dev-host  # Chrome et Firefox parlent à l'hôte de développement
```

Chrome et Firefox parlent par défaut à l'hôte `me.somalabs.onepass`, le relais de l'app Mac (section "App Mac"). `--dev-host` construit pour l'hôte de développement `me.somalabs.onepass.dev` ; les tests de bout en bout et le labo le passent. Un build ne parle qu'à un seul hôte, sans repli.

## Identifiant de l'extension

Le manifeste Chromium n'a pas de champ `key` : l'identifiant est calculé par Chrome à partir du chemin du dossier chargé (`dist/chromium`). Il change donc d'une machine à l'autre ; le manifeste de l'hôte natif doit lister l'identifiant effectivement obtenu. Firefox utilise `onepass@somalabs.me`.

## Charger l'extension non empaquetée

Construire d'abord (`npm run build`).

**Chrome et Chromium.** Ouvrir `chrome://extensions`, activer le mode développeur, "Charger l'extension non empaquetée", choisir `extension/dist/chromium`. Noter l'identifiant affiché : il sert au manifeste de l'hôte (voir plus bas).

**Firefox.** Ouvrir `about:debugging#/runtime/this-firefox`, "Charger un module complémentaire temporaire", choisir `extension/dist/firefox/manifest.json`. Le module est retiré à la fermeture de Firefox. Son identifiant est fixe : `onepass@somalabs.me`.

Firefox MV3 n'accorde pas les permissions d'hôte à l'installation : elles sont optionnelles. Sans elles, le script de contenu ne s'injecte nulle part et aucune icône n'apparaît. Les accorder dans `about:addons` > OnePass > Permissions : activer l'accès aux données de `https://*/*` (tous les sites en HTTPS). Le manifeste ne demande que `https://*/*`, jamais HTTP.

**Safari (Mac).** L'extension est empaquetée dans l'app Mac : cible `OnePassSafari` (`apple/SafariExtension/`, identifiant `me.somalabs.onepass.safari`), intégrée à `OnePass.app/Contents/PlugIns`, dont les ressources sont `dist/safari` (une phase de build les copie ; construire l'extension avant l'app). Safari n'a pas d'hôte de messagerie native : `src/background/safari.ts` envoie chaque trame par `browser.runtime.sendNativeMessage` au `SafariWebExtensionHandler` de l'extension d'app, qui la relaie octet pour octet (même enveloppe, même appairage, même session que Chrome, R-03). `native.ts` choisit ce transport quand les pages de l'extension sont servies depuis `safari-web-extension:`.

Dans un build signé par l'équipe (Release-CloudKit, Release-Signed), l'extension d'app joint l'app par son socket `bridge.sock` dans le conteneur App Group (section "App Mac"). Le build Debug embarque en plus l'hôte de développement (`Contents/MacOS/onepass-native-host`, signé avec le bac à sable hérité) et le préfère, en le lançant une fois par connexion, comme Chrome. Sans l'un ni l'autre (Release signé ad hoc), l'extension affiche "App OnePass introuvable". L'extension d'app est dans le bac à sable : l'hôte lit `~/.onepass-dev/native-host.json` où `~` est `~/Library/Containers/me.somalabs.onepass.safari/Data`, avec `"allowed_extensions": ["me.somalabs.onepass.safari"]`. Le fichier de fixture et le `data_dir` doivent être dans ce conteneur (le bac à sable ne lit pas le dépôt). Approbation `file` : `onepass-native-host approve <code> --config ~/Library/Containers/me.somalabs.onepass.safari/Data/.onepass-dev/native-host.json`.

Essayer : `cd extension && npm run build`, puis `make -C apple project` si besoin et un build Debug de `OnePass` pour macOS, lancer l'app une fois (Safari découvre l'extension), activer Safari > Réglages > Avancés > "Afficher les fonctionnalités pour les développeurs web", puis Développement > "Autoriser les extensions non signées" (build signé ad hoc), et cocher OnePass dans Safari > Réglages > Extensions. Safari sur iPhone et iPad attend le pont dans l'app (pas de processus fils sur iOS).

## App Mac (production)

Spec : `docs/specs/2026-10-27-release-bridge-design.md`. L'app OnePass sert le pont depuis le coffre déverrouillé, sur `bridge.sock` dans son conteneur App Group ; elle vérifie la signature de chaque client (extension Safari, relais) et chaque client vérifie la sienne. Chrome et Firefox lancent `OnePass.app/Contents/Helpers/onepass-relay` (builds signés par l'équipe seulement) :

```sh
node scripts/install-app-host.mjs --app /Applications/OnePass.app --browser chrome --extension-id <identifiant>
node scripts/install-app-host.mjs --app /Applications/OnePass.app --browser firefox
```

L'app ne sert que les identifiants de son réglage `ONEPASS_BROWSER_EXTENSIONS` (`apple/project.yml`, Firefox par défaut) : y ajouter l'identifiant Chrome, puis reconstruire. App fermée : "App OnePass introuvable" ; app verrouillée : "OnePass est verrouillé", le bouton met l'app au premier plan. L'appairage s'approuve dans l'app avec Touch ID ; Réglages > Remplissage automatique > Navigateurs liste et oublie les appairages.

Test de bout en bout optionnel (relais signé, sonde signée à la place de l'app) : `test/bridge/app-relay.test.ts`, mode d'emploi en tête du fichier et dans `core/onepass-ffi/examples/bridge_probe.rs`.

## Hôte natif de développement

`node scripts/install-dev-host.mjs --browser chrome|chromium|firefox|all [--profile <dossier>] [--extension-id <id>] [--host <binaire>] [--config <fichier>]` écrit le manifeste `me.somalabs.onepass.dev.json` et un script d'enveloppe `onepass-native-host.sh` (à côté de la configuration, `~/.onepass-dev/native-host.json` par défaut) qui lance `core/target/debug/onepass-native-host --config <fichier>`. Sans `--profile`, les manifestes vont dans les dossiers utilisateur de Chrome, Chromium et Firefox ; avec `--profile <dossier>`, dans `<dossier>/NativeMessagingHosts/` (famille Chromium seulement). Pour Chrome et Chromium, l'identifiant vient de `--extension-id`, sinon de `allowed_extensions` dans la configuration.

### Configuration de l'hôte

Le fichier JSON est lu par `onepass-native-host` (`--config <fichier>`, sinon `ONEPASS_NATIVE_HOST_CONFIG`, sinon `~/.onepass-dev/native-host.json`). Champs inconnus refusés.

| Champ | Sens |
| --- | --- |
| `data_dir` | dossier de données de l'hôte (`~` accepté) |
| `allowed_extensions` | identifiants d'extension autorisés : identifiant Chrome nu (sans `chrome-extension://`) et `onepass@somalabs.me` pour Firefox |
| `source` | `{"kind":"fixture","path":...}` ou `{"kind":"dev"}` (voir ci-dessous) |
| `approval` | `auto` ou `file` |
| `unlocked` | coffre déverrouillé au démarrage, `true` par défaut |
| `reprompt` | `deny` (défaut) ou `allow` : réponse aux items qui demandent une nouvelle authentification |

Source `fixture` : items fictifs d'un fichier JSON (par exemple `core/onepass-native-host/fixtures/e2e.json`, Alex Martin et `atlas-cloud.test`), chargés dans un vrai coffre chiffré en mémoire. Build debug uniquement : un binaire release la refuse.

```json
{
  "data_dir": "~/.onepass-dev/native-host",
  "allowed_extensions": ["<identifiant Chrome>", "onepass@somalabs.me"],
  "source": { "kind": "fixture", "path": "/chemin/vers/onepass/core/onepass-native-host/fixtures/e2e.json" },
  "approval": "file"
}
```

Source `dev` : le dossier de la CLI de développement (`path` optionnel, défaut `data_dir`).

```json
{
  "data_dir": "~/.onepass-dev",
  "allowed_extensions": ["<identifiant Chrome>", "onepass@somalabs.me"],
  "source": { "kind": "dev" },
  "approval": "file"
}
```

Le coffre `dev` se déverrouille comme la CLI : `ONEPASS_PASSWORD` avec `ONEPASS_DEV_ALLOW_ENV_PASSWORD=1`.

### Installer l'hôte

```sh
cd core && cargo build -p onepass-native-host      # core/target/debug/onepass-native-host
cd ../extension
node scripts/install-dev-host.mjs --browser chrome --extension-id <identifiant> --config <fichier>
node scripts/install-dev-host.mjs --browser firefox --config <fichier>
```

Sans `--profile`, les manifestes vont dans les dossiers utilisateur du navigateur. Même contrainte pour l'installateur : si le dépôt est sous `~/Desktop`, `~/Documents` ou `~/Downloads`, le navigateur ne pourra pas lancer `core/target/debug/onepass-native-host`; passer une copie du binaire située ailleurs avec `--host <binaire>`. Pour essayer sans toucher à un profil réel : `--browser chromium --profile <dossier-temporaire>` écrit `<dossier>/NativeMessagingHosts/me.somalabs.onepass.dev.json` (famille Chromium seulement ; `--profile` avec Firefox est refusé).

## Appairage

1. Cliquer l'icône de l'extension : "Appairer avec OnePass". L'extension affiche un code à 6 chiffres (`123 456`).
2. Côté hôte :
   - `approval: "auto"` : approbation immédiate (tests), le code est écrit dans `<data_dir>/native-host.log` ;
   - `approval: "file"` : l'hôte écrit `<data_dir>/pending-pairing.json` (code, nom, navigateur). Comparer le code avec celui de l'extension, puis le valider avec `core/target/debug/onepass-native-host approve 123456 --config <fichier>` (écrit `<data_dir>/pairing-approved`).
3. Si les deux codes sont identiques, cliquer "Les codes sont identiques" dans l'extension. Si les codes diffèrent, refuser : quelqu'un s'est glissé sur le canal.

Le délai est de 120 s. L'appairage est enregistré des deux côtés seulement après les deux confirmations (spec 6.4). "Oublier cet appairage" dans l'extension, ou la suppression de l'entrée de `pairings.json` côté hôte, le révoque.

## Tests de bout en bout

`npm run e2e` (Playwright, `e2e/playwright.config.ts`) :

- construit `dist/chromium` et `dist/chromium-e2e` (`node build.mjs chromium --e2e` : même extension, plus une poignée vers le routeur et la session du service worker, utilisée seulement par `e2e/security.spec.ts` ; le build normal ne la contient pas), puis l'hôte natif (`cargo build -p onepass-native-host`) ;
- génère un certificat auto-signé avec `openssl` (requis) pour les hôtes de test, que Chromium accepte par `--ignore-certificate-errors-spki-list` (empreinte de sa clé seulement) ;
- démarre un serveur local (`e2e/server.ts`) qui sert HTTPS et HTTP sur un seul port ; `--host-resolver-rules="MAP * 127.0.0.1:<port>, EXCLUDE localhost"` y envoie tous les noms (`atlas-cloud.test`, `accounts.google.com`, `evil.test`…), et `context.route` coupe toute autre requête. Aucune requête ne sort de la machine ; aucun site tiers réel n'est contacté ;
- lance Chromium sans interface (`channel: "chromium"`, nouveau mode headless, qui charge les extensions) avec un profil neuf par test, et l'hôte natif réel en mode `fixture` (`core/onepass-native-host/fixtures/e2e.json`, approbation `auto`).

Découverte de l'hôte natif : Chromium lit le manifeste dans `<user-data-dir>/NativeMessagingHosts/` du profil lancé par Playwright ; rien n'est écrit dans les dossiers de l'utilisateur. Le manifeste est lu au moment de `connectNative` : le harnais lit l'identifiant de l'extension dans l'URL du service worker, puis écrit le manifeste et la configuration de l'hôte avant le premier appairage, sans relancer le navigateur.

Le coffre chiffré de la fixture est construit une fois par lancement (environ 10 s en debug) puis copié pour chaque test. Premier lancement : `npx playwright install chromium`.

## Lancer les tests

```sh
cd extension
npm run check    # typecheck, vitest, build des trois navigateurs
npm run e2e      # Playwright, Chromium, hôte natif réel
cd ../core
cargo test -p onepass-bridge -p onepass-native-host
cargo test -p onepass-bridge --features vectors --test vectors   # vecteurs croisés Rust/TypeScript à jour
```

`npm run e2e` demande `cargo` (il construit l'hôte avec `cargo build --locked -p onepass-native-host` au démarrage), `openssl`, et Chromium de Playwright : `npx playwright install chromium` une fois. Le harnais lance l'hôte depuis une copie temporaire, car macOS interdit à Chromium sans interface de lancer un binaire situé sous `~/Desktop`, `~/Documents` ou `~/Downloads`. Rien n'est écrit dans les profils de l'utilisateur et aucune requête ne sort de la machine.

## Harnais visuel

`npm run build:chromium && node scripts/ui-shots.mjs <dossier-de-sortie> [--only nom,nom]` rend les pages de l'extension (popup, menu, overlay, proposition d'enregistrement) hors extension, avec des réponses fictives, en clair et en sombre, et enregistre une capture par état. Outil de développement, rien n'est embarqué dans l'extension.

## Langue et apparence

L'interface suit la langue du navigateur (`chrome.i18n.getUILanguage()`) : français (tutoiement) si elle commence par `fr`, anglais sinon, français sans runtime (tests unitaires). Les textes sont écrits en paires `tr("…", "…")` (`src/shared/i18n.ts`) ; la description du manifeste vient de `_locales/fr` et `_locales/en` (`default_locale: fr`). Les tests de bout en bout et le laboratoire lancent Chromium avec `--lang=fr-FR`.

Apparence alignée sur l'app Mac : sombre d'abord avec un mode clair, surfaces translucides (flou, filets de 1 px, coins de 12 à 14 px), accent indigo `#5856D6`, cartes de lignes avec étiquettes en minuscules teintées d'accent, icônes de catégorie illustrées (`src/ui/art.ts`, dessins originaux), toasts avec coche verte ou triangle rouge. L'app n'envoie pas d'icône de site par le pont : pas de favicon, et aucun service d'icônes tiers.

Captures sur la vraie extension et le vrai hôte (hors suite) : `ONEPASS_E2E_SHOTS=<dossier> npx playwright test -c e2e/playwright.config.ts shots`. Le harnais visuel accepte `--lang en`.

## Laboratoire d'autofill

`lab/` contient un laboratoire qui génère des sites fictifs à partir d'une graine et mesure ce que l'extension remplit, et ce qu'elle ne doit jamais remplir (fuites vers un autre hôte ou un champ piège). Commandes (`npm run lab:smoke`, `npm run lab`, `npm run lab:repro`, `npm run lab:corpus`), garde-fous du corpus et limites : voir [`lab/README.md`](lab/README.md).

## Limites et reports

Rulings de la spec (section 14) qui bornent cette version :

- R-08 : Chromium et Firefox sont exercés, les tests de bout en bout ne tournent que sur Chromium (Playwright ne charge d'extensions que là). Safari est empaqueté pour le Mac (voir plus haut) ; son relais a des tests unitaires (`swift test --package-path apple/SafariExtension/SafariRelay`) mais pas de test de bout en bout.
- R-10 : aucune exception aux iframes d'autres sites, même pour un paiement (Stripe et consorts). Les cartes dans ces iframes ne sont pas remplies.
- R-11 : la chaîne "Connexion en un clic" s'arrête (`handoff`) dès que le domaine sort de la liste autorisée, sans exception, même pour un SSO d'entreprise à domaines multiples.
- R-12 : "Se souvenir de cet appareil" n'est jamais touché. La soumission automatique est une préférence locale par item (`chrome.storage.local`, activée par défaut) ; il n'y a pas encore d'interface pour la changer (pas d'UI `autoSubmit`).
- R-13 : pas d'apprentissage des étapes inconnues ; une étape inconnue rend la main.
- R-15 : mode autonome Windows et Linux (core en WASM, CloudKit JS, WebAuthn PRF) reporté.
- R-16 : passkeys reportées au jalon 3.
- R-17 : vérification de la signature de code du navigateur appelant et relais XPC vers l'app au jalon 2. Un logiciel qui lit le profil du navigateur obtient la clé d'appairage et peut demander des secrets pour des origines précises (voir la section "Extension navigateur" de `docs/security/README.md`).

Origines : HTTPS seulement, aucune exception de développement (R-18).

## Hygiène mémoire

- L'historique du générateur (20 entrées) vit dans un tableau en mémoire du service worker. Il n'est écrit dans aucun stockage (`storage.session` compris), il est vidé au verrouillage et quand l'appairage est oublié, et un redémarrage du worker le repart vide. L'ancienne clé `genHistory` de `storage.session` est supprimée au démarrage.
- Le mot de passe de la proposition d'enregistrement est effacé dès l'enregistrement, le refus ou la fermeture, et au plus tard après 2 minutes.
- Les `Uint8Array` de clés et de secrets (appairage, KEM, session, canal natif) sont effacés par `wipe` dans des blocs `finally`, y compris sur les chemins d'erreur.
- Limite assumée : les chaînes JavaScript sont immuables et ne peuvent pas être effacées. Un mot de passe affiché, copié, rempli ou décodé depuis un message reste en mémoire jusqu'au ramasse-miettes, hors de notre contrôle.

## Avertissements de développement

- L'hôte de développement affiche `DEV MODE` dans son journal et n'est pas fait pour de vrais secrets. N'y mettre aucun vrai identifiant, mot de passe, carte ou coffre personnel.
- Son dossier de données (`data_dir`) contient : `pairings.json` (clé d'appairage en clair, 0600), `native-host.log` et `audit.log` (opérations sans valeurs), `fixture-cache.bin` (coffre de la fixture, clés de test comprises) et, en mode `file`, `pending-pairing.json` / `pairing-approved`.
- Le cache de la fixture persiste tout login enregistré via l'extension (proposition d'enregistrement, "Enregistrer un nouveau login"), d'une session à l'autre. Supprimer `fixture-cache.bin` pour repartir de zéro.
- Ne jamais utiliser de vrais secrets avec la fixture ni avec la source `dev` hors de la machine de développement.
