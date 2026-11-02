# Travel Mode : détection du voyage et protection par élément

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, rulings en section 9). Retours du fondateur, points 14 et 15 (`.superpowers/briefs/2026-11-02-ios-feedback.md`).
S'appuie sur le jalon 7 (`2026-10-25-milestone-7-mcp-ssh-design.md`, section 5 ; `2026-10-27-m7-app-design.md`, section 5) sans en affaiblir les garanties : un coffre qui part quitte vraiment l'appareil, revient seulement par la vérification normale du noyau (manifeste signé, `last_seen`), et rien n'est jamais effacé côté serveur.

## 1. But

1. **Détection.** Quand la localisation est déjà permise (pour « À proximité »), OnePass apprend, sur l'appareil seulement, les régions où l'utilisateur vit d'habitude. S'il se trouve loin de toutes, OnePass propose une seule fois le Travel Mode : une carte dans l'app « Tu voyages ? Oui / Non / Plus tard », et une notification discrète quand l'app est en arrière-plan et que le système peut la réveiller. Oui ouvre la confirmation habituelle ; Non apprend l'endroit ; Plus tard se tait jusqu'au prochain voyage.
2. **Protection par élément.** En plus des coffres entiers, un élément peut être :
   - **Caché en voyage** : il quitte l'appareil comme un coffre qui part (ses enregistrements sont retirés du stockage local, pas filtrés dans l'interface) et revient vérifié à la sortie ;
   - **Protection renforcée** : en voyage, l'afficher demande le mot de passe maître **et** la biométrie, et il n'est proposé nulle part hors de l'app (AutoFill, extension, Apple Watch).

## 2. Modèle de menace

Acteurs : un agent à une frontière qui fouille l'appareil (déverrouillé ou non) ; une personne qui contraint l'utilisateur à déverrouiller l'app ; un examen forensique du conteneur de l'app ; un serveur iCloud hostile (déjà dans le modèle du jalon 7).

| Menace | Ce qui protège | Limite assumée |
|---|---|---|
| Fouille de l'app déverrouillée | Les coffres qui partent et les éléments cachés ne sont plus sur l'appareil : rien à montrer, même sous contrainte. | L'utilisateur peut être contraint de sortir du Travel Mode s'il a du réseau : la sortie demande le mot de passe maître et Face ID, et ramène tout. Le Travel Mode protège contre la fouille de l'appareil, pas contre une contrainte qui dure jusqu'à la sortie. |
| Déverrouillage forcé, puis lecture d'un élément sensible resté | Protection renforcée : mot de passe maître et biométrie, et aucune autre surface ne le livre. | C'est une barrière d'interface sur une donnée présente : quelqu'un qui obtient le mot de passe maître et le visage de l'utilisateur la lit. Pour un secret critique, « Caché en voyage » est la bonne réponse ; la carte d'options le dit. |
| Examen forensique du conteneur | Enregistrements retirés de toutes les couches du magasin (`evict`), base compactée (`VACUUM`), état de voyage scellé au compte (KEM hybride, AES-256-GCM-SIV, signé). | Le manifeste signé, en clair dans la base, liste toujours les identifiants et les versions des éléments cachés : on peut compter les éléments absents, pas les lire ni les nommer. La meta locale `travel_hidden_items` porte les mêmes identifiants. Les lieux appris (section 5) révèlent des régions d'environ 150 km, chiffrées par une clé du trousseau liée à l'appareil. |
| Serveur qui rejoue un ancien état à la sortie | Les coffres : `last_seen` mis de côté et scellé (jalon 7). Les éléments cachés : leur coffre reste sur l'appareil, son manifeste reste épinglé par `last_seen` ; la sortie vérifie chaque élément ramené contre l'entrée du manifeste local (version et hash). | Inchangée. |
| Serveur qui retire un élément caché pendant le voyage | Le manifeste local le liste toujours : la sortie le réclame et refuse sans lui (`ManifestMissingItem`) ; l'état reste valable. | Un autre appareil de l'utilisateur peut le supprimer pour de vrai (nouveau manifeste signé) : c'est une écriture légitime, acceptée. |
| Appareil qui écrit dans le coffre pendant le voyage | Les entrées des éléments cachés restent dans chaque nouveau manifeste (le noyau ne réécrit que l'entrée qu'il change) ; écrire, supprimer ou déplacer un élément caché est refusé. | Une rotation de clé est refusée pendant le voyage (elle réécrirait tous les éléments). |
| Suggestion de voyage | Les lieux ne quittent jamais l'appareil (ni iCloud, ni géocodeur Apple) ; rien n'est demandé au système en plus de la permission existante. | Sans permission « Toujours », la détection n'a lieu qu'à l'ouverture de l'app (pas de notification en arrière-plan). |

Hors champ : une saisie de l'appareil avec extraction du trousseau et du mot de passe ; un agent qui exige l'accès au compte iCloud ou à un autre appareil non voyageur.

## 3. Drapeaux par élément (noyau)

Les deux drapeaux sont des étiquettes réservées, comme `onepass:pending` et `onepass:profile` : `onepass:travel-hidden` et `onepass:travel-guard`. Aucun format d'élément ne change, les drapeaux sont chiffrés avec l'élément et synchronisés, et un ancien client les garde intacts.

- `Item::travel_hidden()` et `Item::travel_guarded()` les lisent ; `Item::set_travel_hidden(bool)` et `set_travel_guarded(bool)` les posent sans doublon.
- Le profil du compte n'est jamais caché.
- Côté FFI, `FfiItem` et `FfiItemSummary` gagnent `travel_hidden` et `travel_guard` (défaut `false`) ; les étiquettes réservées sont retirées de `tags` à la conversion et remises depuis les booléens au retour : l'interface ne les montre jamais comme étiquettes.

## 4. Éléments cachés : sortir de l'appareil pour de vrai

### 4.1 Entrer

`Repository::enter_travel(upstream)` fait comme avant pour les coffres sans `travel_safe`, puis, pour chaque coffre `travel_safe`, chaque élément du manifeste vérifié marqué `travel_hidden` :

- l'amont doit tenir son enregistrement d'élément octet pour octet, et chaque fragment de ses pièces jointes ; sinon l'entrée est refusée avant toute suppression (`upstream does not hold the vault`), comme pour un coffre ;
- tous les enregistrements locaux de l'élément partent (l'actuel, les restes ignorés, les fragments), dans le même `evict_all` que les coffres : tout ou rien ;
- `TravelState` (schéma 2) gagne `parked_items : vault id -> ensemble d'item ids` ; le manifeste du coffre, lui, ne change pas et reste épinglé dans `last_seen`.

Un élément caché d'un coffre qui part part avec son coffre (rien de plus à faire).

### 4.2 Pendant le voyage

Le dépôt garde en mémoire `travel_parked_items` (repris par `resume_travel`) :

- `load` et la copie locale (`copy_from`) acceptent qu'une entrée d'élément mis de côté n'ait pas d'enregistrement ; s'il y en a un, il est vérifié normalement. `Loaded.manifest` garde toutes les entrées : chaque écriture du coffre (`save_item`, `delete_item`, `move_item`, meta) les recopie, donc un élément caché n'est jamais supprimé par un manifeste écrit pendant le voyage.
- Écrire, supprimer ou déplacer un élément mis de côté est refusé (`NotFound`, rien n'est écrit).
- `rotate` est refusée (`travel mode active`) dès qu'un coffre ou un élément est mis de côté.
- La synchro (`SyncStore::set_travel_hidden_items`) ignore les enregistrements de ces éléments (par item id, lu dans le corps de l'enregistrement) et les fragments de leurs pièces jointes (par id de fragment) : un autre appareil peut modifier l'élément, la nouvelle version ne descend pas.

### 4.3 Sortir

`exit_travel(upstream, state)` fait comme avant pour les coffres, puis pour chaque coffre listé encore présent qui a des éléments mis de côté : copie depuis l'amont les enregistrements de ces éléments que le manifeste local vérifié liste (même item id, même version, même hash) et les fragments de leurs pièces jointes, retire les éléments de `travel_parked_items`, puis recharge le coffre par `items()`. Un élément absent ou différent : refus, copies retirées, ensemble remis, `TravelState` toujours valable. Un élément que le manifeste ne liste plus (supprimé par un autre appareil) est simplement oublié.

Sur l'app, la sortie reste en deux temps : `begin_travel_exit` vide aussi `travel_hidden_items`, la synchro recharge depuis zéro, `finish_travel_exit` vérifie ; en cas d'échec, les enregistrements des éléments reviennent hors de l'appareil et le filtre est remis.

### 4.4 État scellé

`TravelState` schéma 2 = `{ parked, entered_at, parked_items }`, scellé exactement comme le schéma 1 (le schéma est dans l'AAD). `open_travel_state` lit les deux : un état écrit avant cette version s'ouvre avec `parked_items` vide. Taille fixe inchangée (64 Ko).

### 4.5 Entrée possible

Entrer est permis dès qu'un coffre part, qu'un élément est caché ou qu'un élément est en protection renforcée. Le noyau tient `travelling` (vrai après `enter_travel` ou `resume_travel`, faux après une sortie réussie).

## 5. Protection renforcée

Pendant le voyage (`Repository::travelling()`), un élément `travel_guarded` :

- n'est proposé ni par AutoFill (candidats, insertion de texte), ni par l'extension (pont), ni sur l'Apple Watch ;
- dans l'app, s'affiche verrouillé : la biométrie puis le mot de passe maître sont demandés, les deux, à chaque ouverture (pas de mémoire de session) ; sans biométrie disponible, le mot de passe seul.

Hors voyage, rien ne change.

## 6. Détection du voyage (app)

### 6.1 Données

- Cellule = géohash de précision 3 (environ 156 km sur 156 km à l'équateur). Calcul local, aucun géocodeur.
- Lieu habituel = une cellule vue sur au moins 3 jours distincts dans les 60 derniers jours, ou apprise par « Non ». On garde au plus 64 cellules, 60 jours par cellule.
- Loin de chez soi = la cellule courante et ses 8 voisines ne sont pas habituelles. Avant 3 jours d'observation au total, on ne propose rien (apprentissage).
- Stockage : un fichier local (Application Support, exclu de la sauvegarde, protection `complete`), chiffré AES-GCM (CryptoKit) par une clé du trousseau `WhenUnlockedThisDeviceOnly`. Jamais synchronisé. « Oublier les lieux appris » efface fichier et clé.

### 6.2 Quand

- Réglage « Proposer le Travel Mode » (désactivé par défaut), avec une ligne d'explication : « Quand tu sembles en voyage, OnePass te le propose. Tes lieux restent sur cet appareil. »
- À chaque passage au premier plan, coffre déverrouillé, au plus une fois toutes les 3 heures : une position réduite (`kCLLocationAccuracyReduced`, une requête), seulement si la permission est déjà donnée. Jamais de demande de permission depuis la détection.
- Si la permission est « Toujours » : surveillance des changements significatifs (pas de GPS continu) ; un changement qui sort des lieux habituels poste une notification locale `passive` (respecte Concentration et la réduction des interruptions du système), une seule par voyage.

### 6.3 Réponses

- **Oui** : la confirmation habituelle du Travel Mode (plan, Face ID, synchro, entrée).
- **Non** : la cellule courante devient habituelle.
- **Plus tard** : silence jusqu'au retour dans un lieu habituel (fin du voyage).
- Travel Mode déjà actif : aucune proposition. De retour dans un lieu habituel avec le Travel Mode actif : une carte « De retour ? Désactiver le Travel Mode », sans notification.

## 7. Interface

- iPhone et Mac, éditeur d'élément, carte d'options : « Caché en voyage » et « Protection renforcée en voyage », avec une aide d'une ligne.
- Réglages > Travel Mode : l'interrupteur de suggestion, « Oublier les lieux appris », le nombre d'éléments cachés et renforcés ; la confirmation d'entrée nomme les coffres et le nombre d'éléments qui partent.
- Liste et détail : un petit badge avion sur un élément caché ou renforcé (hors voyage, pour savoir ce qui partira).
- La carte de suggestion s'affiche en haut de l'accueil (iPhone) et de la liste (Mac).

## 8. Tests

- Noyau (`tests/travel_items.rs`) : aller-retour d'un élément caché (enregistrements absents du magasin local, items() sans lui, retour intact) ; amont sans l'élément refuse l'entrée sans rien effacer ; écriture d'un autre élément du coffre pendant le voyage garde l'entrée cachée ; écrire, supprimer, déplacer l'élément caché refusé ; sortie avec un enregistrement amont différent refusée et état restauré ; élément supprimé par un autre appareil oublié ; état schéma 1 toujours lisible ; pièces jointes suivies ; rotation refusée ; la synchro ignore les versions de l'élément pendant le voyage.
- FFI : drapeaux par booléens sans étiquettes visibles ; statut et plan d'entrée comptent les éléments ; AutoFill ne propose pas un élément renforcé en voyage.
- VaultKit : géohash (vecteurs connus), voisins, apprentissage, décision (apprentissage, chez soi, voyage, Plus tard, Non), fichier chiffré (aller-retour, clé absente, effacement).
- Simulateur : `simctl location` à Paris (habituel) puis Tokyo : carte affichée ; captures dans `OnePass-test-videos/2026-11-02-feedback/travel/`.

## 9. Rulings

1. Drapeaux en étiquettes réservées plutôt qu'en champs d'élément - aucun changement de format, synchronisés et chiffrés, gardés par les anciens clients - coût si faux : un ancien client montre l'étiquette `onepass:travel-hidden`.
2. Éléments cachés : on retire les enregistrements et on garde les entrées du manifeste, plutôt que de déplacer l'élément dans un coffre caché - un déplacement change le coffre (partage, droits) et réécrit deux manifestes ; garder les entrées laisse le manifeste épinglé et détecte tout retrait - coût si faux : on peut compter les éléments cachés dans la base.
3. Protection renforcée = barrière d'interface plus retrait de toutes les autres surfaces, sans second chiffrement - un chiffrement sous le mot de passe demanderait un nouveau format d'élément et ne résiste pas à la contrainte non plus - coût si faux : un élément renforcé reste lisible par qui a le mot de passe et le visage ; l'interface oriente vers « Caché en voyage ».
4. Détection par distance (géohash 3 et voisins) plutôt que pays ou aéroport - pays et aéroport demandent un géocodeur (réseau) ou une base embarquée lourde ; « loin de tous les lieux habituels » couvre l'aéroport à l'étranger - coût si faux : un voyage à moins d'environ 150 km d'un lieu habituel n'est pas détecté, et une frontière proche du domicile non plus.
5. Permission existante seulement (« Lorsque l'app est active ») ; arrière-plan et notification seulement si « Toujours » est déjà donnée - demander « Toujours » pour une suggestion serait disproportionné - coût si faux : sans « Toujours », la proposition arrive à l'ouverture de l'app, pas à l'atterrissage.
6. Lieux dans un fichier local chiffré, pas dans un coffre - un coffre se synchronise (même chiffré, ils quitteraient l'appareil) - coût si faux : chaque appareil apprend ses lieux seul.
7. Un élément marqué caché après l'entrée ne part qu'à la prochaine entrée - le changer pendant le voyage voudrait dire entrer à nouveau - coût si faux : l'utilisateur doit sortir puis rentrer pour cacher un nouvel élément.
8. Rotation de clé refusée pendant le voyage (déjà vrai pour les coffres) - elle réécrirait les éléments absents - coût si faux : la rotation attend le retour.
9. Pas de nouveau `RecordKind` - tout tient dans l'état scellé et la meta locale.
