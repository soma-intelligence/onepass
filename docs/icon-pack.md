# Pack d'icônes de sites

Les icônes de marques que l'app affiche pour les éléments viennent d'un pack construit à partir de jeux ouverts, mis à jour chaque semaine, et téléchargé en entier : jamais une requête par site. Demander l'icône d'un site à un service tiers (favicons de Google, DuckDuckGo, logo.dev, Clearbit) lui apprendrait quels sites la personne utilise ; OnePass ne le fait pas.

## Sources et licences

| Source | Licence | Ce qui est pris | Correspondance avec un domaine |
| --- | --- | --- | --- |
| [Simple Icons](https://github.com/simple-icons/simple-icons) | CC0-1.0 | marques d'une couleur (SVG), dessinées dans la couleur de la marque (`hex`) ; noir et blanc restent une marque d'une couleur que l'app dessine dans la couleur du texte | nom identique à une entrée de 2FA Directory, sinon hôte de `source` quand son nom est celui de la marque |
| [gilbarbara/logos](https://github.com/gilbarbara/logos) | CC0-1.0 | la variante carrée `-icon.svg` en couleurs, sinon le logo principal s'il est carré | champ `url` |
| [2FA Directory](https://github.com/2factorauth/twofactorauth) | MIT | `img/` en SVG, carrés seulement (un mot-marque large devient illisible dans une tuile) | `domain` et `additional-domains` |
| [Wikimedia Commons](https://commons.wikimedia.org) (liste choisie à la main) | domaine public (logo fait de texte, [PD-textlogo](https://commons.wikimedia.org/wiki/Template:PD-textlogo)), marque de son propriétaire | le mot-marque vectoriel d'une marque dont le nom est le logo (Aēsop), fichier épinglé par son SHA-1 | `scripts/icon-pack-curated.json` |
| [Wikidata](https://www.wikidata.org) et [Wikimedia Commons](https://commons.wikimedia.org) (`--wikidata`, voir plus bas) | domaine public ou CC0 seulement (`LicenseShortName` de Commons), marque de son propriétaire | le logo actuel (P154) d'un élément Wikidata qui a un site officiel (P856), SVG ou image d'au moins 180 px, jamais un mot-marque plus large que 2,6 | l'hôte du site officiel, sans `www.` |
| Icône propre de la marque (liste choisie à la main) | marque de son propriétaire, montrée comme un navigateur montre une favicon | l'icône de son app iOS (App Store, 256 px, vendeur vérifié), sinon l'icône de son site (apple-touch-icon, manifeste, favicon.ico ou la copie qu'en garde Google), 180 px au moins | `scripts/icon-pack-curated.json` |

| Domaines populaires (`--domains`, voir plus bas) | marque de son propriétaire, montrée comme un navigateur montre une favicon | l'icône du site lui-même (apple-touch-icon, manifeste, favicon.ico), 128 px au moins | le domaine tel qu'il est listé |

Écartés : les icônes de Simple Icons qui portent une autre licence que CC0, MIT, Apache-2.0, BSD, ISC ou Unlicense (CC-BY-SA, NC, ND, GPL, licences maison) ; aegis-icons (licences mêlées icône par icône, dont GPL et CC-BY) ; dashboard-icons (applications auto-hébergées, peu de sites grand public). Une licence copyleft ou à attribution par icône ne convient ni à l'AGPL distribuée sur l'App Store ni à la licence commerciale.

Les logos restent des marques de leurs propriétaires. Ils servent ici à reconnaître un compte, comme une favicon ; leur présence ne signifie aucune affiliation. Une marque qui demande le retrait de son icône l'obtient en amont (Simple Icons, 2FA Directory) ou par une exclusion dans `scripts/icon_pack.py`. Mentions : [`NOTICE`](../NOTICE).

## Liste choisie à la main

`scripts/icon-pack-curated.json` passe avant toute correspondance automatique. Chaque marque y a ses domaines (alias et pays compris) et sa source : une icône précise d'un des trois jeux (`simple-icons:<slug>`, `logos:<fichier>`, `2fa:<fichier>`), ou `site`, l'icône de la marque elle-même, prise **à la construction du pack** (`icon_pack.py sites`), jamais par l'app. `commons:<fichier>` prend un logo SVG de Wikimedia Commons, lui aussi à la construction (`sites`), seulement si son SHA-1 est celui de `sha1` : un nouvel envoi du fichier est refusé jusqu'à ce que quelqu'un le regarde et déplace l'épingle. `tile` pose la marque sur un carré de sa couleur (le fantôme de Snapchat sur jaune). `mono` en fait une marque d'une couleur, dessinée dans la couleur du texte. `wordmark` garde un mot-marque entier (jusqu'à 4,5 fois plus large que haut) là où une marque de la liste plus large que 2,6 est refusée. `view` recadre le logo sur la marque (`x y largeur hauteur`), sans ce qui l'accompagne (le ® d'Aēsop, du bruit à la taille des listes). `note` dit comment un nom flou a été lu. Les jeux ouverts d'abord ; l'icône de la marque seulement quand aucun ne l'a en couleurs ou la dessine mal. Sans icône de 180 px au moins, la marque n'entre pas dans le pack et l'app dessine sa tuile monogramme.

La même liste nomme les plateformes qui hébergent d'autres marques (`tenants` : Zendesk, Okta, Substack, SharePoint...) : leur icône ne passe pas à leurs sous-domaines (`acme.zendesk.com` est le centre d'aide d'Acme, pas Zendesk).

L'index du pack porte aussi `names` : le nom de chaque marque (lettres et chiffres, sans accents) vers son icône, pour un élément sans adresse dont le titre est le nom de la marque. Un nom que deux icônes réclament n'y entre pas, sauf si la liste choisie ou un domaine au nom de la marque tranche.

## Domaines populaires

`--domains FILE` (sur `sites` et sur `build`, répétable) ajoute au pack l'icône des sites d'une liste de domaines populaires, pour que l'app n'ait presque jamais à demander une icône à un site. Un fichier est un texte simple (un domaine par ligne, `#` pour un commentaire) ; une ligne avec une virgule (un CSV classé) est refusée. Chaque entrée devient son domaine enregistrable, une seule fois, dans l'ordre de la liste. `scripts/icon-pack-domains-fr.txt` est une liste faite à la main de services français (banques, assurances, énergie, opérateurs, administrations, transports, commerces, santé).

Tout se passe **à la construction**, jamais dans l'app :

1. `icon_pack.py sites --domains LISTE --out DIR` va chercher l'icône de chaque domaine (même chercheur que les marques de la liste choisie : page, apple-touch-icon, manifeste, favicon.ico, copie de Google), 128 px au moins, dans `DIR/domains/` et `DIR/domains.json` (URL, SHA-256, taille, hôtes finaux).
2. `icon_pack.py build ... --sites DIR --domains LISTE` les dessine en carrés de **128 px** avec le drapeau **2** (bit 2) dans l'entrée de l'index ; les icônes choisies à la main et celles des jeux ouverts restent à 256 px (drapeau 1 pour une marque d'une couleur). Un domaine de la liste choisie à la main est ignoré (la liste choisie gagne). Une source de moins de 128 px est écartée, et les contrôles habituels s'appliquent (SVG sûr, icône presque vide).

Le domaine est pris tel qu'il est listé : l'icône est rangée sous ce domaine même quand le site redirige ailleurs, jamais sous la cible de la redirection.

Le manifeste nomme les listes utilisées (`sources["domain-list"]`) ; le rapport `report.json` ajoute `domains_fetched`, `domains_kept` et `domains_blocked`.

### Liste d'exclusion

`scripts/icon-pack-blocklist.txt` (`--blocklist`, par défaut ce fichier) : une ligne est un domaine (`www.` ignoré ; lui et tous ses sous-domaines, donc `m.mauvais.fr` est bloqué par `mauvais.fr`) ou `*.suffixe` (le suffixe et tout hôte en dessous, donc `*.xxx` couvre une extension entière), `#` pour un commentaire. Un domaine listé qui y figure n'est même pas contacté par `sites` ; un domaine dont la page finit, après redirections, sur un hôte de la liste est écarté, et `build` refait les deux contrôles (une liste d'exclusion peut grandir entre `sites` et `build`). Le fichier livré est un point de départ (extensions et sites adultes ou de jeux d'argent, DNS dynamique gratuit souvent détourné) que le fondateur complète avant toute vraie construction.

## Icônes de plateformes

Beaucoup de sites ne montrent pas l'icône de leur marque mais celle du logiciel qui les héberge : le portail des membres d'une salle de sport sert la favicon de son logiciel de club, une boutique celle de son créateur de site, une page de connexion celle de son fournisseur d'identité (Salesforce, Okta, Shopify, Wix...). Cette icône n'est jamais montrée comme le logo de la marque.

À la construction :

1. `icon_pack.py sites` va aussi chercher l'icône de chaque plateforme de `scripts/icon-pack-platforms.txt` (`--platforms`, par défaut ce fichier, chaîne vide pour aucune ; même chercheur que les marques, 32 px au moins) dans `DIR/platforms/` et `DIR/platforms.json`. La liste est faite à la main, rangée par groupes en commentaires `#` : logiciels de clubs et de salles (Daxko, Club Automation, Mindbody...), créateurs de sites, fournisseurs d'identité, Salesforce, centres d'aide, commerce en ligne, forums et communautés, portails scolaires.
2. `icon_pack.py build --sites DIR` dessine avec resvg chaque icône de site récupérée (marques `site` de la liste choisie, domaines populaires) et chaque icône de plateforme dans un carré de 128 px, puis en calcule le dHash (64 bits, le même calcul que `IconHash` dans VaultKit, vecteurs communs dans `scripts/testdata/dhash-vectors.json`). Le hachage porte toujours sur le PNG dessiné, jamais sur le fichier téléchargé.
3. Sont des rejets : le hash de chaque icône de plateforme, et tout hash qu'au moins 3 marques différentes servent (hashes à 6 bits d'écart au plus ; une marque compte une seule fois sur tous ses domaines, `marque.com` et `marque.fr` donnent la même marque `marque`).
4. Une icône de site proche d'un rejet (6 bits au plus) quitte le pack : le domaine passe à son icône suivante ou n'en a pas. Seul le domaine de la plateforme elle-même garde la sienne, et il entre dans `tenants` : ses sous-domaines (le portail d'un club sur `club.clubautomation.com`) n'en héritent pas. `report.json` donne `rejects` (leur nombre) et `platform_icons_dropped` (les domaines touchés).

L'index porte les rejets dans `rejects` : liste triée, sans doublon, de hashes en 16 chiffres hexadécimaux minuscules. Dans l'app, `SiteIconLoader` calcule le dHash du PNG normalisé qu'il s'apprête à garder (au plus 256 px de côté, jamais le fichier téléchargé) et le refuse s'il est à 6 bits ou moins d'un rejet : il essaie le candidat suivant, et si tous sont refusés le site n'a pas d'icône (échec retenu comme les autres). Une icône de site déjà en cache qui correspond à un rejet arrivé avec un pack plus récent n'est pas montrée non plus : `ItemIconResolver` la vérifie à la lecture, une fois par hôte et par icône, la retire du cache et redemande aussitôt le site, qui passe à son candidat suivant. Un hash peu informatif (moins de 8 ou plus de 56 bits à 1, comme la tuile unie qui donne 0) n'est jamais un rejet et n'est jamais refusé, des deux côtés.

Voulu : le sous-domaine d'un client sur une plateforme (`acme.clubautomation.com`) est refusé quand il sert l'icône de la plateforme. Accepté : le domaine d'une plateforme absent du pack peut perdre sa propre icône dans l'app, car seule la construction l'exempte.

## Wikidata et Wikimedia Commons

`icon_pack.py wikidata --out DIR` interroge Wikidata **à la construction**, jamais dans l'app : le service SPARQL (`query.wikidata.org`) donne les éléments qui ont un logo (P154) et un site officiel (P856), par pages (`--page-size`, 2000 par défaut, `ORDER BY` puis `LIMIT`/`OFFSET`, au plus `--max-pages` pages) pour qu'aucune requête n'expire. Chaque appel passe par le même chercheur HTTPS que les sites, avec l'agent `OnePass icon pack builder (https://github.com/soma-intelligence/onepass)` (le nom de l'outil et son dépôt public, rien sur la personne qui lance la construction), et recommence après un 429, un 5xx, une erreur de connexion ou un délai dépassé (`Retry-After` quand le serveur le donne, sinon 2, 4, 8... secondes, 5 essais). Une réponse coupée (JSON illisible) ou trop grosse est redemandée une fois, puis notée dans `page_errors` sans arrêter la construction ; une page pleine compte ses éléments distincts, et la pagination s'arrête sur une page incomplète ou qui n'apporte aucun élément nouveau. `--dry-run` affiche le service, l'agent et la requête de la première page sans rien envoyer.

1. Le logo actuel de chaque élément : les déclarations dépréciées et celles qui ont une date de fin (P582) sont écartées, le rang préféré passe d'abord, puis la date de début (P580) la plus récente ; l'ordre des noms de fichiers tranche le reste.
2. Le domaine : l'hôte de chaque site officiel non déprécié, en minuscules, sans `www.`. Sont écartés les réseaux sociaux, magasins d'apps, pages de liens, hébergeurs de code et de fichiers (une page de la marque sur le service d'un autre, pas son site), les plateformes de `scripts/icon-pack-platforms.txt` et la liste d'exclusion, sous-domaines compris. Quand plusieurs éléments donnent le même domaine, celui qui a le plus de liens vers les Wikipédias (`wikibase:sitelinks`) le garde ; les autres sont notés comme conflits.
3. Commons (`imageinfo`, 50 fichiers par requête) donne l'URL, le SHA-1, la taille, le type et la licence (`extmetadata.LicenseShortName`). Gardés : `Public domain`, `PD`, `PD-*` (PD-textlogo, PD-ineligible, PD-shape..., sans espace ni seconde licence) et `CC0`, sans tenir compte de la casse. Tout le reste (CC BY, CC BY-SA, GFDL...) est écarté et compté : pas d'attribution par icône.
4. Le fichier original est téléchargé depuis `upload.wikimedia.org` seulement, plafonné comme les autres sources (512 Kio pour un SVG, 2 Mio pour une image), et gardé seulement si ses octets ont le SHA-1 que Commons annonce. Un SVG passe les contrôles habituels (SVG sûr), une image doit être un PNG, JPEG ou WebP d'au moins 180 px, et un logo plus large que 2,6 fois sa hauteur est un mot-marque écarté. Le fichier est rangé sous `DIR/files/<sha1>.<ext>`, jamais sous son titre Commons.

`DIR/wikidata.json` garde la date de la requête (`queried`), les pages perdues (`page_errors`), chaque domaine retenu (élément, libellé, fichier, SHA-1, SHA-256, licence, URL), le compte par licence (`kept`, `dropped`), les écarts par raison et les conflits.

`build --wikidata DIR` relit ce dossier comme une entrée non fiable : chemin de la forme `files/<sha1>.<ext>`, SHA-256 identique, SVG sûr ou en-tête d'image, forme pas plus large que 2,6. Un domaine de la liste choisie à la main garde son icône (la liste choisie gagne, `use: none` compris), et un sous-domaine d'un domaine choisi est écarté (`subdomain-of-curated`) : l'app trouve l'icône d'un sous-domaine par son parent, il cacherait l'icône choisie. Un sous-domaine dont le parent n'a qu'une icône des jeux ouverts garde son logo Wikidata (une filiale comme `aws.amazon.com` a le sien) et est listé dans `report.json` (`subdomain-override`) ; la liste d'exclusion et les plateformes sont revérifiées. Ordre : liste choisie, puis Wikidata, puis gilbarbara/logos, 2FA Directory, Simple Icons, puis les icônes de sites. Le libellé de l'élément entre dans `names` (sauf nom réclamé par deux icônes, règle habituelle). Un logo Wikidata n'est pas une icône de site : les rejets de plateformes ne l'écartent jamais. Le manifeste note la date de la requête (`wikidata_queried`, et `sources.wikidata` : licence, service, et pour chaque icône du pack l'élément, le fichier, son SHA-1 et sa licence) ; `report.json` ajoute `wikidata` : comptes par licence (gardés, écartés, dans le pack), écarts par raison, conflits.

La première vraie construction avec Wikidata (requêtes et téléchargements) attend l'accord du fondateur ; les tests n'utilisent que des réponses au format exact des deux services, écrites à la main dans `scripts/testdata/wikidata/` (le chercheur réseau est remplacé).

## Construction

`scripts/icon_pack.py build` lit les trois dépôts (données non fiables : chaque archive est dépaquetée dans son propre dossier vide, rien n'y est exécuté, Python tourne avec `-I`), garde pour chaque domaine la meilleure icône (logos `-icon` en couleurs, puis 2FA Directory en couleurs, puis Simple Icons, puis les autres carrées), refuse tout SVG qui lirait autre chose que lui-même (DOCTYPE, entité, script, image, `href` externe, `url()` externe, `@import`, texte), le dessine avec [resvg](https://github.com/linebender/resvg) en carré de 256 px (dossier de ressources vide, polices système ignorées) et l'encode en WebP sans perte (`cwebp -lossless`). Une icône presque vide est écartée et le domaine passe à la suivante.

Format 1 du pack (`onepass-icons-<version>.bin`, entiers big-endian) : `OPIP`, octet de format, longueur de l'index (u32), index JSON (`version`, `size`, `icons` en `[offset, longueur, drapeaux]`, `domains` en domaine vers numéro d'icône, et en option `names`, `tenants` et `rejects`, qu'un lecteur plus ancien ignore ; un pack sans `rejects` n'en a aucun), puis les icônes. Drapeau 1 : marque d'une couleur. Drapeau 2 : icône de 128 px issue d'une liste de domaines (les autres font `size` px). Le manifeste `icon-pack-manifest.json` donne la version, la taille et le SHA-256 du pack et les commits amont ; `icon-pack-manifest.json.sig` est la signature Ed25519 (base64) de ses octets exacts.

Tests : `python3 -I scripts/test_icon_pack.py` (rendu de bout en bout si `resvg` et `cwebp` sont là, signature si OpenSSL 3 est là) et la suite `IconPack` de VaultKit.

## Publication et mise à jour

`.github/workflows/icon-pack.yml`, chaque lundi dans le dépôt public (ou à la main) : tests, commits amont du jour, icônes des sites (`sites --domains scripts/icon-pack-domains-fr.txt`), logos Wikidata (`wikidata`), construction (`build --sites --domains --wikidata --blocklist`), signature avec `ICON_PACK_ED_PRIVATE_KEY`, vérification avec la variable `ICON_PACK_ED_PUBLIC_KEY`, attestation de provenance, puis envoi sur la release `icon-pack`. Cette release est une préversion jamais marquée *Latest* : la mise à jour de l'app Mac lit `releases/latest/download/appcast.xml` et ne doit jamais tomber sur elle.

Dans l'app, `IconPackStore` (VaultKit) prend le plus récent du pack livré dans l'app (de confiance comme le reste de l'app) et du dernier pack téléchargé. Au plus une fois par semaine, il lit le manifeste et sa signature, vérifie la signature avec la clé publique compilée dans l'app (`IconPackStore.publicKey`), puis, si la version est plus grande, télécharge le pack, contrôle taille et SHA-256, le lit en entier et le met en place par un renommage atomique. Une version égale ou plus ancienne est refusée (pas de retour en arrière), une signature fausse ou un pack qui ne correspond pas aussi ; le pack en place reste. Sans clé publique, aucune mise à jour : le pack livré reste seul.

### Clé de signature (une fois, par le fondateur)

Une clé à part, jamais la clé Sparkle : une fuite de l'une ne doit rien donner sur l'autre.

1. `openssl genpkey -algorithm ed25519 -outform DER | tail -c 32 | base64` donne la graine (32 octets, base64). La ranger dans le gestionnaire de mots de passe de l'équipe.
2. `ICON_PACK_ED_PRIVATE_KEY=<graine> python3 -I scripts/icon_pack.py public-key` donne la clé publique.
3. Dépôt public, Settings, Environments, New environment `icon-pack` (relecteur obligatoire conseillé, références limitées à `main`) : secret `ICON_PACK_ED_PRIVATE_KEY`, variable `ICON_PACK_ED_PUBLIC_KEY`.
4. Écrire la clé publique dans `IconPackStore.publicKey` (`apple/VaultKit/Sources/VaultKit/Support/IconPack.swift`) et livrer une version de l'app.

## Pack livré dans l'app

`apple/IconPack/onepass-icons.bin` est le pack de base, construit par `scripts/icon_pack.py sites` puis `build --sites` (version 2026110304, après la revue du fondateur sur ses appareils, puis 2026110401 : la même avec le mot-marque Aēsop entier à la place de la favicon « Aē », seule l'icône d'Aesop changée ; son manifeste `apple/IconPack/icon-pack-manifest.json` donne le SHA-256 et les commits amont). Il est copié une seule fois dans l'app (iOS, Mac, visionOS ; la cible `OnePass` de `apple/project.yml`). L'extension AutoFill ne l'embarque pas : elle le lit dans l'app qui la contient, ou dans la copie que l'app pose au lancement dans le dossier partagé du groupe d'apps (`SharedContainer.iconPackFolder`, où arrivent aussi les packs téléchargés). La montre et l'hôte de l'extension Safari n'affichent pas d'icônes d'éléments : pas de pack.

Le binaire (environ 11 Mo) n'est remplacé qu'à une version de l'app, jamais chaque semaine : les packs hebdomadaires arrivent par la mise à jour signée ci-dessus. Pour le remplacer : construire, vérifier le SHA-256 contre le manifeste, copier les deux fichiers.

## Ordre de recherche d'une icône

`ItemIconResolver` (VaultKit), utilisé par l'app et par l'extension AutoFill :

1. Icône choisie par la personne pour l'élément (menu de l'icône dans l'éditeur, « Choisir une icône… »). Le cœur la garde (`custom_icon`, PNG ou WebP de 64 Ko au plus) et la vérifie à chaque lecture (taille, type, jamais une pièce jointe de l'élément, en-tête du fichier déchiffré) ; le pont l'expose (`customIconId`, `customIconData`). L'app la déchiffre en mémoire seulement (`CustomIconStore`), oubliée au verrouillage, au changement de compte et en arrière-plan ; une vue la relit à chaque image, sans en garder de copie. `ItemIcon` refuse une image qui déclare plus de 1024 px de côté. Celle qui ne se charge pas (pas encore synchronisée) laisse place au reste de cet ordre.
2. Pack : l'hôte de l'élément, puis ses noms parents jusqu'au domaine enregistrable (jamais le parent d'une plateforme `tenants`). Un hôte couvert par le pack n'est jamais demandé au site, même en préchargement.
3. Pack, par le titre de l'élément quand c'est le nom d'une marque (« Reddit ») ou une adresse (« reddit.com ») : un élément sans adresse trouve aussi sa marque.
4. Marque mère par le nom du site : la page d'accueil déjà lue pour l'icône du site donne son nom (`og:site_name`, `application-name`, le `name` du manifeste s'il a été lu, puis le `<title>` jusqu'au premier séparateur). Ce nom, sans un « my » initial ni au plus deux mots génériques finaux (connect, portal, member...), est cherché dans les `names` du pack : « Bay Club Connect » donne Bay Club. Aucune requête en plus.
5. Icône du site lui-même (`SiteIconLoader`), seulement si sa source fait au moins 32 px sur son grand côté (stockée entre 64 et 127 px, une source de 32 à 63 px est dessinée nue à sa taille, jamais étirée) : en dessous, plutôt qu'une image floue, la tuile monogramme. Jamais l'icône d'une plateforme d'hébergement (`rejects`, voir plus haut).
6. Marque mère par un domaine lié, seulement si le site n'a pas d'icône montrable (aucune, refusée comme plateforme, ou trop petite) : les domaines vers lesquels la page pointe (liens, `canonical`, `og:url`), au plus 5, hors réseaux sociaux, magasins d'apps, CDN, mesure d'audience, paiement et captcha, et seulement le domaine canonique ou un domaine dont le nom commence comme celui du site (4 caractères). Les numéros trouvés sont mis en cache par hôte avec la version du pack, et recherchés à nouveau quand le pack change.
7. Sinon `ItemIcon` dessine la tuile monogramme (un identifiant qui a un titre) ou l'illustration de la catégorie.

## Rendu dans les listes

Chaque icône occupe le même carré, pour que les lignes s'alignent :

- une icône d'app (artwork plein bord, ou carré arrondi sur fond transparent) remplit la tuile ;
- toute autre marque est recadrée sur son encre puis mise à une même taille optique (la racine carrée de l'aire de sa boîte fait 58 % de la tuile, son grand côté au plus 74 %), et dessinée sans tuile, agrandie d'un facteur 0,96/0,74 : son grand côté atteint au plus 96 % du carré. Une marque d'une couleur prend la couleur du texte ;
- une marque en couleurs garde une tuile grise discrète seulement quand elle disparaîtrait sans : surtout noire en mode sombre (tuile claire), presque blanche en mode clair (tuile sombre).

Le réglage « Icônes des sites » coupé : ni pack ni icône de site, aucune requête.

L'extension de navigateur garde la favicon de la page : servir le pack par l'hôte natif demanderait un nouveau message dans le protocole du pont (`core/onepass-bridge`, vecteurs de test compris) alors que le pack vit côté Swift.
