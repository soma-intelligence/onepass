# Extension OnePass

Extension WebExtension (Manifest V3, TypeScript) pour Chromium, Firefox et Safari.

## Commandes

- `npm run build` : un dossier par navigateur dans `dist/<browser>/` (`npm run build:chromium` pour un seul). Ajouter `--dev` (`node build.mjs --dev`) pour des source maps en ligne ; elles sont absentes par défaut.
- `npm run typecheck`, `npm test`, `npm run e2e`, `npm run check` (typecheck, tests, build).

## Identifiant de l'extension

Le manifeste Chromium n'a pas de champ `key` : l'identifiant est calculé par Chrome à partir du chemin du dossier chargé (`dist/chromium`). Il change donc d'une machine à l'autre ; le manifeste de l'hôte natif doit lister l'identifiant effectivement obtenu. Firefox utilise `onepass@somalabs.me`.

## Hôte natif de développement

`node scripts/install-dev-host.mjs --browser chrome|chromium|firefox|all [--profile <dossier>] [--extension-id <id>] [--host <binaire>] [--config <fichier>]` écrit le manifeste `me.somalabs.onepass.dev.json` et un script d'enveloppe `onepass-native-host.sh` (à côté de la configuration, `~/.onepass-dev/native-host.json` par défaut) qui lance `core/target/debug/onepass-native-host --config <fichier>`. Sans `--profile`, les manifestes vont dans les dossiers utilisateur de Chrome, Chromium et Firefox ; avec `--profile <dossier>`, dans `<dossier>/NativeMessagingHosts/` (famille Chromium seulement). Pour Chrome et Chromium, l'identifiant vient de `--extension-id`, sinon de `allowed_extensions` dans la configuration.

## Tests de bout en bout

`npm run e2e` (Playwright, `e2e/playwright.config.ts`) :

- construit `dist/chromium` et `dist/chromium-e2e` (`node build.mjs chromium --e2e` : même extension, plus une poignée vers le routeur et la session du service worker, utilisée seulement par `e2e/security.spec.ts` ; le build normal ne la contient pas), puis l'hôte natif (`cargo build -p onepass-native-host`) ;
- génère un certificat auto-signé avec `openssl` (requis) pour les hôtes de test, que Chromium accepte par `--ignore-certificate-errors-spki-list` (empreinte de sa clé seulement) ;
- démarre un serveur local (`e2e/server.ts`) qui sert HTTPS et HTTP sur un seul port ; `--host-resolver-rules="MAP * 127.0.0.1:<port>, EXCLUDE localhost"` y envoie tous les noms (`atlas-cloud.test`, `accounts.google.com`, `evil.test`…), et `context.route` coupe toute autre requête. Aucune requête ne sort de la machine ; aucun site tiers réel n'est contacté ;
- lance Chromium sans interface (`channel: "chromium"`, nouveau mode headless, qui charge les extensions) avec un profil neuf par test, et l'hôte natif réel en mode `fixture` (`core/onepass-native-host/fixtures/e2e.json`, approbation `auto`).

Découverte de l'hôte natif : Chromium lit le manifeste dans `<user-data-dir>/NativeMessagingHosts/` du profil lancé par Playwright ; rien n'est écrit dans les dossiers de l'utilisateur. Le manifeste est lu au moment de `connectNative` : le harnais lit l'identifiant de l'extension dans l'URL du service worker, puis écrit le manifeste et la configuration de l'hôte avant le premier appairage, sans relancer le navigateur.

Le coffre chiffré de la fixture est construit une fois par lancement (environ 10 s en debug) puis copié pour chaque test. Premier lancement : `npx playwright install chromium`.
