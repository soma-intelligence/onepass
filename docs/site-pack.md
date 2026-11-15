# Pack des sites

Ce que l'app sait d'un site (propose-t-il la double authentification, les passkeys, et où sont ses réglages de sécurité) vient d'un pack construit à partir de jeux ouverts, mis à jour chaque semaine, et téléchargé en entier : jamais une requête par site. Interroger un service tiers site par site (`api.2fa.directory`, `passkeys-api.2fa.directory`) lui apprendrait quels sites la personne utilise ; OnePass ne le fait pas. Rien du coffre ne quitte l'appareil : la seule requête est le téléchargement du pack depuis la release GitHub de OnePass, au plus une fois tous les 7 jours.

## Sources et licences

| Source | Licence | Ce qui est pris |
| --- | --- | --- |
| [2FA Directory](https://github.com/2factorauth/twofactorauth) (`entries/*/*.json`) | MIT | `domain`, `additional-domains`, `tfa` (les méthodes), `documentation` |
| [2factorauth/passkeys](https://github.com/2factorauth/passkeys) (`entries/*/*.json`) | CC-BY-4.0 | `domain`, `additional-domains`, `passwordless` et `mfa`, `documentation` |
| `data/site-setup/<domaine>.json` (écrit à la main) | celle du dépôt (AGPL) | domaines liés, page de réglages et recette de mise en place, vérifiées par le fondateur |

Jamais embarqués : bitwarden/passkeys-index, passkeys.directory, les icônes de 2fa.directory. Mentions : [`NOTICE`](../NOTICE) et la ligne « Sources des données » de l'app. Le point CC-BY-4.0 dans une app de l'App Store reste une question juridique ouverte pour le fondateur ; ce pack ne la tranche pas.

## Format

`onepass-sites-<version>.json`, JSON compact, clés triées, 16 Mio et 100 000 sites au plus :

```json
{
  "format": 1,
  "version": 2026112001,
  "sites": {
    "github.com": {
      "twofa": ["custom-software", "sms", "totp", "u2f"],
      "passkey": "signin",
      "help": "https://docs.github.com/...",
      "additional_domains": [],
      "setup_totp": {
        "url": "https://github.com/settings/security",
        "verified": { "date": "2026-11-20", "browser": "chromium" },
        "steps": []
      }
    }
  }
}
```

- `twofa` : la liste `tfa` de 2FA Directory, triée, valeurs telles que l'amont les écrit.
- `passkey` : `"signin"` quand l'entrée passkeys a `passwordless: "allowed"`, sinon `"mfa"` quand elle a `mfa: "allowed"`, sinon absent.
- `help` : l'URL `documentation` de 2FA Directory (https, 2048 octets au plus), sinon celle de l'entrée passkeys, sinon absent.
- `additional_domains` : l'union des `additional-domains` des deux jeux et de la carte à la main.
- `setup_totp`, `setup_passkey` : seulement depuis `data/site-setup/<domaine>.json`. `steps` peut être vide (l'adresse de la page de réglages seule). `browser` vaut `chromium`, `firefox` ou `safari`.

Le manifeste `site-pack-manifest.json` donne la version, la date, le fichier du pack avec sa taille et son SHA-256, le nombre de sites et les commits amont (avec le SHA-256 de chaque archive). `site-pack-manifest.json.sig` est la signature Ed25519 (base64, puis une fin de ligne) de ses octets exacts.

## Règles des recettes

Appliquées à la construction, puis de nouveau au chargement dans l'app :

- vocabulaire fermé : `goto`, `click`, `wait_for`, `reauth`, `expect_qr`, `expect_passkey_prompt`, `done` ; toute autre étape ou clé est refusée ;
- `goto` : https seulement, sur le domaine du site ou l'un de ses domaines liés ; pas de saisie de texte, pas de script ;
- 12 étapes au plus, `timeout_s` de 1 à 60 ;
- un `click` dont le nom contient `delete`, `disable`, `remove`, `pay` (ou leurs formes françaises, espagnoles et italiennes) est refusé, comme un dernier clic « Verify » ou « Activate » ;
- une recette `setup_totp` finit par `expect_qr`, une recette `setup_passkey` par `expect_passkey_prompt`, et aucune ne contient l'`expect_*` de l'autre ;
- un bloc sans `verified` (`date`, `browser`) n'entre pas dans le pack et est listé dans `report.json`.

Le détail est dans [`data/site-setup/README.md`](../data/site-setup/README.md). Aucune recette ne s'exécute dans cette vague : le bandeau ne propose pas encore « Activer » ; `has_recipe` traverse le pont pour la suite.

## Construction

`scripts/site_pack.py build --twofa DIR --passkeys DIR --setup data/site-setup --sources FILE --version N --out DIR` lit les deux dépôts (données non fiables : chaque archive est dépaquetée dans son propre dossier vide, rien n'y est exécuté, Python tourne avec `-I`) et la carte à la main, puis écrit le pack, le manifeste et `report.json`. Une recette qui casse une règle fait échouer la construction et nomme le fichier. Autres commandes : `sign --manifest PATH` (clé dans `SITE_PACK_ED_PRIVATE_KEY`), `verify --manifest PATH --pack PATH --public-key B64`, `public-key`.

Tests : `python3 -I scripts/test_site_pack.py` (signature si OpenSSL 3 est là) et les suites de `core` et de VaultKit.

## Publication et mise à jour

`.github/workflows/site-pack.yml`, chaque lundi à 06:30 UTC dans le dépôt public (ou à la main, `publish: false` pour ne garder que les fichiers en artefacts) : tests, commits amont du jour (archive épinglée par commit et SHA-256), construction, signature avec `SITE_PACK_ED_PRIVATE_KEY`, vérification avec la variable `SITE_PACK_ED_PUBLIC_KEY`, attestation de provenance, puis envoi sur la release `site-pack` : le pack, puis la signature, puis le manifeste (`--clobber`). Les deux packs les plus récents restent. Cette release est une préversion jamais marquée *Latest* : la mise à jour de l'app Mac lit `releases/latest/download/appcast.xml` et ne doit jamais tomber sur elle.

Dans l'app, `SitePackStore` (VaultKit, `apple/VaultKit/Sources/VaultKit/Support/SitePack.swift`) prend le plus récent du pack livré et du dernier pack téléchargé. Au plus une fois par semaine, il lit le manifeste et sa signature depuis `https://github.com/soma-intelligence/onepass/releases/download/site-pack/`, vérifie la signature avec la clé publique compilée dans l'app (`SitePackStore.publicKey`), puis, si la version est plus grande, télécharge le pack, contrôle taille et SHA-256, vérifie chaque recette et le met en place par un renommage atomique. Une version égale ou plus ancienne, une signature fausse ou un pack qui ne correspond pas sont refusés ; le pack en place reste. La copie téléchargée est revérifiée à chaque chargement. Sans clé publique, aucune mise à jour : le pack livré reste seul. La copie livrée est de confiance comme le reste de l'app.

### Clé de signature (une fois, par le fondateur)

Une clé à part, jamais la clé Sparkle ni celle du pack d'icônes : une fuite de l'une ne doit rien donner sur les autres.

1. `openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64` donne la graine (32 octets, base64). La ranger dans le gestionnaire de mots de passe de l'équipe.
2. `SITE_PACK_ED_PRIVATE_KEY=<graine> python3 -I scripts/site_pack.py public-key` donne la clé publique.
3. Dépôt public, Settings, Environments, New environment `site-pack` (relecteur obligatoire conseillé, références limitées à `main`) : secret `SITE_PACK_ED_PRIVATE_KEY`, variable `SITE_PACK_ED_PUBLIC_KEY`.
4. Écrire la clé publique dans `SitePackStore.publicKey` et livrer une version de l'app.

## Pack livré dans l'app

`apple/SitePack/onepass-sites.json` est le pack de base, copié dans l'app à une version de l'app, jamais chaque semaine : les packs hebdomadaires arrivent par la mise à jour signée ci-dessus. Pour le remplacer : construire, vérifier le SHA-256 contre le manifeste, copier le fichier.

## Liste du fondateur pour `data/site-setup`

Les cartes de `data/site-setup` sont la seule entrée écrite à la main du pack. Pour chaque site :

1. Vérifier le domaine, ses domaines liés et la page de réglages de sécurité (URL https exacte).
2. Dérouler la recette soi-même, sur son propre compte connecté, dans le navigateur noté, jusqu'au QR code (TOTP) ou à l'invite de passkey, sans jamais valider ni activer.
3. Seulement alors, écrire `verified` (`date` du jour, `browser` : `chromium`, `firefox` ou `safari`). Personne d'autre, aucun script ne le pose.
4. Lancer `python3 -I scripts/site_pack.py build ...` en local : la construction nomme le fichier et la règle en cas d'erreur, et `report.json` liste ce qui reste hors du pack.
5. Revoir la recette à chaque changement visible du site : un bloc périmé se retire (ou perd `verified`).
