# Extension OnePass

Extension WebExtension (Manifest V3, TypeScript) pour Chromium, Firefox et Safari.

## Commandes

- `npm run build` : un dossier par navigateur dans `dist/<browser>/` (`npm run build:chromium` pour un seul). Ajouter `--dev` (`node build.mjs --dev`) pour des source maps en ligne ; elles sont absentes par défaut.
- `npm run typecheck`, `npm test`, `npm run e2e`, `npm run check` (typecheck, tests, build).

## Identifiant de l'extension

Le manifeste Chromium n'a pas de champ `key` : l'identifiant est calculé par Chrome à partir du chemin du dossier chargé (`dist/chromium`). Il change donc d'une machine à l'autre ; le manifeste de l'hôte natif doit lister l'identifiant effectivement obtenu. Firefox utilise `onepass@somalabs.me`.
