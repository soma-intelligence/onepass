# Pack d'icônes de sites

Les icônes de marques que l'app affiche pour les éléments viennent d'un pack construit à partir de jeux ouverts, mis à jour chaque semaine, et téléchargé en entier : jamais une requête par site. Demander l'icône d'un site à un service tiers (favicons de Google, DuckDuckGo, logo.dev, Clearbit) lui apprendrait quels sites la personne utilise ; OnePass ne le fait pas.

## Sources et licences

| Source | Licence | Ce qui est pris | Correspondance avec un domaine |
| --- | --- | --- | --- |
| [Simple Icons](https://github.com/simple-icons/simple-icons) | CC0-1.0 | marques d'une couleur (SVG), dessinées dans la couleur de la marque (`hex`) ; noir et blanc restent une marque d'une couleur que l'app dessine dans la couleur du texte | nom identique à une entrée de 2FA Directory, sinon hôte de `source` quand son nom est celui de la marque |
| [gilbarbara/logos](https://github.com/gilbarbara/logos) | CC0-1.0 | la variante carrée `-icon.svg` en couleurs, sinon le logo principal s'il est carré | champ `url` |
| [2FA Directory](https://github.com/2factorauth/twofactorauth) | MIT | `img/` en SVG, carrés seulement (un mot-marque large devient illisible dans une tuile) | `domain` et `additional-domains` |

Écartés : les icônes de Simple Icons qui portent une autre licence que CC0, MIT, Apache-2.0, BSD, ISC ou Unlicense (CC-BY-SA, NC, ND, GPL, licences maison) ; aegis-icons (licences mêlées icône par icône, dont GPL et CC-BY) ; dashboard-icons (applications auto-hébergées, peu de sites grand public). Une licence copyleft ou à attribution par icône ne convient ni à l'AGPL distribuée sur l'App Store ni à la licence commerciale.

Les logos restent des marques de leurs propriétaires. Ils servent ici à reconnaître un compte, comme une favicon ; leur présence ne signifie aucune affiliation. Une marque qui demande le retrait de son icône l'obtient en amont (Simple Icons, 2FA Directory) ou par une exclusion dans `scripts/icon_pack.py`. Mentions : [`NOTICE`](../NOTICE).

## Construction

`scripts/icon_pack.py build` lit les trois dépôts (données non fiables : chaque archive est dépaquetée dans son propre dossier vide, rien n'y est exécuté, Python tourne avec `-I`), garde pour chaque domaine la meilleure icône (logos `-icon` en couleurs, puis 2FA Directory en couleurs, puis Simple Icons, puis les autres carrées), refuse tout SVG qui lirait autre chose que lui-même (DOCTYPE, entité, script, image, `href` externe, `url()` externe, `@import`, texte), le dessine avec [resvg](https://github.com/linebender/resvg) en carré de 256 px (dossier de ressources vide, polices système ignorées) et l'encode en WebP sans perte (`cwebp -lossless`). Une icône presque vide est écartée et le domaine passe à la suivante.

Format 1 du pack (`onepass-icons-<version>.bin`, entiers big-endian) : `OPIP`, octet de format, longueur de l'index (u32), index JSON (`version`, `size`, `icons` en `[offset, longueur, drapeaux]`, `domains` en domaine vers numéro d'icône), puis les icônes. Drapeau 1 : marque d'une couleur. Le manifeste `icon-pack-manifest.json` donne la version, la taille et le SHA-256 du pack et les commits amont ; `icon-pack-manifest.json.sig` est la signature Ed25519 (base64) de ses octets exacts.

Tests : `python3 -I scripts/test_icon_pack.py` (rendu de bout en bout si `resvg` et `cwebp` sont là, signature si OpenSSL 3 est là) et la suite `IconPack` de VaultKit.

## Publication et mise à jour

`.github/workflows/icon-pack.yml`, chaque lundi dans le dépôt public (ou à la main) : tests, commits amont du jour, construction, signature avec `ICON_PACK_ED_PRIVATE_KEY`, vérification avec la variable `ICON_PACK_ED_PUBLIC_KEY`, attestation de provenance, puis envoi sur la release `icon-pack`. Cette release est une préversion jamais marquée *Latest* : la mise à jour de l'app Mac lit `releases/latest/download/appcast.xml` et ne doit jamais tomber sur elle.

Dans l'app, `IconPackStore` (VaultKit) prend le plus récent du pack livré dans l'app (de confiance comme le reste de l'app) et du dernier pack téléchargé. Au plus une fois par semaine, il lit le manifeste et sa signature, vérifie la signature avec la clé publique compilée dans l'app (`IconPackStore.publicKey`), puis, si la version est plus grande, télécharge le pack, contrôle taille et SHA-256, le lit en entier et le met en place par un renommage atomique. Une version égale ou plus ancienne est refusée (pas de retour en arrière), une signature fausse ou un pack qui ne correspond pas aussi ; le pack en place reste. Sans clé publique, aucune mise à jour : le pack livré reste seul.

### Clé de signature (une fois, par le fondateur)

Une clé à part, jamais la clé Sparkle : une fuite de l'une ne doit rien donner sur l'autre.

1. `openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64` donne la graine (32 octets, base64). La ranger dans le gestionnaire de mots de passe de l'équipe.
2. `ICON_PACK_ED_PRIVATE_KEY=<graine> python3 -I scripts/icon_pack.py public-key` donne la clé publique.
3. Dépôt public, Settings, Environments, New environment `icon-pack` (relecteur obligatoire conseillé, références limitées à `main`) : secret `ICON_PACK_ED_PRIVATE_KEY`, variable `ICON_PACK_ED_PUBLIC_KEY`.
4. Écrire la clé publique dans `IconPackStore.publicKey` (`apple/VaultKit/Sources/VaultKit/Support/IconPack.swift`) et livrer une version de l'app.

## Ordre de recherche d'une icône (proposé, en attente d'accord)

1. Icône choisie par la personne pour l'élément, s'il y en a une.
2. Pack : l'hôte de l'élément, puis ses noms parents jusqu'au domaine enregistrable.
3. Icône du site lui-même (`SiteIconLoader`), seulement si sa source fait au moins 64 px : en dessous, plutôt qu'une image floue étirée, une tuile monogramme propre.
4. Illustration de la catégorie.
