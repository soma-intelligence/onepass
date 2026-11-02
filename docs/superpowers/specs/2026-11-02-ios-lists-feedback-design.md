# iPhone et iPad : listes, recherche, À proximité, icônes, Watchtower (retours du 2026-11-02)

Date : 2026-11-02. Branche : `main` (agent ios-lists). Statut : approuvée en autonomie (rulings en section 9). Source : `.superpowers/briefs/2026-11-02-ios-feedback.md`, points 1, 2, 3, 6, 7, 9, 11, 18, 19.

## 1. Fondu sous les en-têtes (points 3, 6, 19)

- Un seul modificateur partagé, `headerFade(color:header:)` (DesignKit, `HeaderFade.swift`), remplace la copie privée `TopBlurFade` de `PhoneTabsView` qui ne couvrait que la racine de chaque onglet.
- Appliqué une fois par pile iPhone : la racine et chaque écran poussé (`navigationDestination` : liste filtrée, liste Watchtower comme « Ancien mot de passe », détail). Sur iPad : colonne liste, colonne détail (détail et éditeur), page pleine (Watchtower, Développeur). Feuille « + » : l'en-tête (titre, recherche) devient une `safeAreaBar` au-dessus des tuiles, le voile couvre l'en-tête puis s'efface sur 44 pt.
- Même rendu que l'Accueil : effet de bord de défilement doux du système, plus un voile de la couleur du fond, presque opaque en haut, qui s'efface sous la barre. Nouveau : le voile n'apparaît qu'une fois le contenu passé sous l'en-tête (rampe de 18 pt), un écran au repos n'est jamais voilé.

## 2. Barre du haut sans compteur (point 2)

Le compteur « 521 éléments » quitte la barre de `CategoryListView`. Le compteur du Mac et de l'iPad (en-tête de liste) ne change pas.

## 3. Balayage : Archiver d'abord (point 1)

Balayage de droite à gauche sur une ligne active : Archiver (premier bouton, balayage complet), puis Corbeille. Un élément archivé propose Désarchiver à la place d'Archiver. `AppModel.archive(_:)` et `unarchive(_:)` appellent `VaultSession.archive/unarchive` et montrent un toast comme la corbeille.

## 4. Recherche (point 7)

- Champ : invite courte « Rechercher dans tes éléments ».
- Avant toute frappe : recherches récentes de la session (mémoire seule, vidées au verrouillage, bouton Vider), éléments ouverts récemment (5), puis « Parcourir » : les catégories présentes en tuiles deux par ligne avec leur nombre ; une tuile ouvre la catégorie.
- En frappant : résultats à chaque touche, meilleurs d'abord (`ItemSearch.ranked` : titre qui commence par la requête, puis un mot du titre, puis le titre qui la contient, puis un autre champ), puces de portée (catégories parmi les résultats, avec leur nombre), en-tête « N résultats ».
- Rien trouvé : la requête, quoi essayer, et « Chercher partout » quand une catégorie restreint la recherche. Coffre vide : l'état vide des listes.
- Une recherche est retenue quand on ouvre un de ses résultats (`VaultSession.noteSearch`, `RecentSearches` : 8 au plus, sans doublon de casse ni d'accent).

## 5. À proximité plus rapide (point 9)

Mesures et causes :
1. Index : la première recherche déchiffrait tous les éléments actifs un par un (`session.item` puis conversion FFI complète) pour trouver leurs lieux. Le cœur déchiffre déjà tout pour les résumés : le résumé porte maintenant `has_places` (`FfiItemSummary`, défaut `false` côté uniffi), et l'index ne lit que les éléments qui ont un lieu.
2. Position : `requestLocation()` attend la meilleure précision possible (souvent plusieurs secondes). `LocationAccess` réutilise une position de moins de 5 min et précise à 500 m, sinon démarre les mises à jour et rend la première position précise à 1 km (6 s au plus, la meilleure vue sinon), puis les arrête.
3. Durées dans le journal (`nearby: fix …, index …`), jamais une position.

## 6. Icônes de site (point 11)

Source (`SiteIconLoader`, mêmes règles de confidentialité : HTTPS, noms et adresses publics, plafonds, pas de cookie, aucun service tiers) :
- Une source de 180 px termine la recherche (128 avant), 8 images au plus (6 avant), et chaque sorte de candidat (manifeste, liens de la page...) a 3 échecs au plus : un manifeste périmé (tesla.com, 8 entrées en 404) n'épuise plus la recherche avant le favicon de la page.
- Après le domaine et `www.`, les hôtes d'application du même domaine (`app.`, `account.`, `my.`) : withings.com refuse tout client sauf un navigateur, app.withings.com sert son icône 144 px.
- Fraîcheur : une icône de plus de 30 jours s'affiche puis se recharge en arrière-plan ; la nouvelle la remplace si elle existe. Version de cache v4 : tout est rechargé une fois.

Tuile (`ItemIcon`, `SiteIconTreatment`) :
- Illustration bord à bord (icône d'app) : remplit la tuile.
- Marque sur un carré blanc ou noir uni : le carré est effacé depuis les bords (les zones enfermées gardent leur couleur), sauf si le fond fait moins d'un tiers ou plus de 97 % de l'image.
- Marque sur fond transparent : marque d'une couleur dessinée dans la couleur du texte sur une tuile grise neutre ; marque en couleurs sur blanc (clair) ou presque noir (sombre), inversé quand la marque serait illisible (marine en sombre, pâle en clair).

## 7. Barre de progression Watchtower (point 18)

`ScanProgressBar` (DesignKit) : nom de l'étape, chiffres à droite en chiffres tabulaires, piste fine arrondie remplie de l'accent ; sans chiffres, un segment parcourt la piste (respiration sur place avec Réduire les animations). iPhone : une carte sous le paragraphe pendant l'analyse. Mac et iPad : la même barre à la place de la ligne d'état.

## 8. Tests

- VaultKit : `NearbyCostTests` (500 éléments, 12 avec lieu : 12 lus), tests du chargeur d'icônes (manifeste mort, hôte d'application, rafraîchissement), classement et recherches récentes.
- DesignKit : `SiteIconTreatmentTests`.
- Rust : `summaries_say_which_items_hold_a_place`.

## 9. Rulings

- R1 : recherches récentes en mémoire seule, vidées au verrouillage, jamais écrites : une recherche nomme les sites qu'on a. Coût si faux : rien de gardé entre deux déverrouillages.
- R2 : « un balayage plus long donne la corbeille » n'existe pas sur iOS (le balayage complet lance le premier bouton) : Archiver au balayage complet, Corbeille en second bouton, comme le brief l'autorise.
- R3 : pas de rendu SVG sur iOS (aucune API système, un moteur maison serait une surface d'attaque) ni de service d'icônes tiers (fuite des sites du coffre).
- R4 : `has_places` dans le résumé plutôt que les coordonnées elles-mêmes : un booléen ne dit rien du lieu.
- R5 : les Réglages (agent ios-shell) prennent le même fondu dans `settingsPage()` ; la couleur par défaut du voile est le jeton `Theme.page`, il suit donc le thème clair ou sombre.
- R6 : la tuile d'une marque se choisit sur la part de pixels presque blancs ou presque noirs, pas sur la luminance moyenne : un G en couleurs sur un disque blanc garde une tuile blanche en clair.
