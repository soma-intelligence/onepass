# Travel Mode : voyages programmés, calendrier et aéroport

Date : 2026-11-14. Statut : design approuvé par le fondateur en conversation (approches A, B et C retenues, « Toujours » demandé à l'activation de l'aéroport, section 2 approuvée). Spec à relire avant le plan.
S'appuie sur `2026-11-02-travel-detection-and-items-design.md` (détection par lieux, section 6) et sur le jalon 7 (Travel Mode du noyau). Le noyau ne change pas : tout se passe dans VaultKit et l'app.

## 1. But

Le Travel Mode protège à la frontière seulement s'il est actif **avant** elle, avec du réseau (l'entrée pousse la synchro puis retire les coffres). La détection actuelle se déclenche loin des lieux habituels, donc après l'atterrissage : trop tard pour la frontière d'arrivée. Cette spec ajoute des déclencheurs qui arrivent avant le départ, et une activation automatique optionnelle :

1. **Voyages programmés (A).** L'utilisateur saisit un voyage (départ, retour). OnePass rappelle par notification locale, puis propose ou active le Travel Mode au premier déverrouillage dans la fenêtre du voyage.
2. **Fuseau horaire (A).** Un fuseau horaire inhabituel s'ajoute aux signaux de la détection existante, sans permission.
3. **Calendrier (B).** Sur demande, OnePass lit en local les 30 prochains jours du calendrier, repère les vols et propose de créer le voyage.
4. **Aéroport (C).** Sur demande, avec la permission « Toujours », OnePass surveille les grands aéroports proches et notifie à l'arrivée au terminal.

Hors champ : sortie automatique (section 7), activation pendant que le coffre est verrouillé (les clés ne sont pas en mémoire), Apple Watch et visionOS (rien de nouveau), type d'élément « vol ».

## 2. Modèle de menace (ajouts)

| Menace | Ce qui protège | Limite assumée |
|---|---|---|
| Fuite des voyages, du calendrier ou des positions | Voyages et état dans le fichier local chiffré existant (`TravelPlacesStore`, clé `WhenUnlockedThisDeviceOnly`, exclu de la sauvegarde, jamais synchronisé). Du calendrier on garde seulement l'identifiant de l'événement retenu ou écarté, ni titre, ni lieu, ni participants. Aucun géocodeur, aucune requête réseau. | Un examen forensique avec le trousseau de l'appareil lit les dates de voyage. |
| Signal falsifié (fausse position, faux fuseau, faux événement) | Un signal ne peut que **proposer** ou **activer** le Travel Mode, ce qui retire des données. Il ne peut jamais en ramener : la sortie reste manuelle. | Un faux signal peut activer le Travel Mode d'un voyage `autoEnter` : gêne, pas fuite. |
| Activation sans réseau | L'entrée exige la synchro (le noyau refuse sinon) : rien n'est retiré, la carte dit de réessayer avant la frontière. | L'utilisateur sans réseau à l'aéroport passe sans Travel Mode. |
| Permission « Toujours » | Demandée seulement quand l'utilisateur active « Proposer à l'aéroport ». Utilisée pour la surveillance de zones et les changements significatifs, jamais pour un GPS continu. | Le système peut réveiller l'app près des aéroports. |

## 3. Modèle (VaultKit)

### 3.1 Voyage

```swift
public struct TravelTrip: Codable, Equatable, Sendable, Identifiable {
    public var id: UUID
    public var start: Date          // départ (date et heure)
    public var end: Date            // retour
    public var source: Source       // .manual, .calendar, .airport
    public var autoEnter: Bool      // false par défaut
    public var calendarEventID: String?  // source .calendar seulement
    public var autoTried: Bool      // la tentative automatique a eu lieu
}
```

Règles : `end > start` ; au plus 16 voyages ; un voyage dont `end` est passé depuis plus de 7 jours est retiré au prochain enregistrement.

### 3.2 Ajouts à `TravelPlaces`

- `trips: [TravelTrip]`.
- `usualOffsets: [String: [Int]]` : clé `"<TimeZone.identifier>|<décalage UTC en secondes>"` vers les jours où elle a été vue (même fenêtre de 60 jours que les cellules). Un décalage est habituel après 3 jours distincts, ou si un décalage habituel porte le même identifiant de fuseau (l'heure d'été chez soi ne déclenche rien).
- `seenEventIDs: Set<String>` : événements de calendrier déjà proposés (acceptés ou refusés), au plus 256, les plus anciens partent d'abord.
- `lastCalendarScan: Double?`, `lastAirportNotice: Int?` (jour).
- `airportsEnabled`, `calendarEnabled` restent dans `UserDefaults` comme `onepass.travel.suggest` (préférences, pas des données de lieu).

**Compatibilité du fichier.** Le `Codable` synthétisé de Swift ignore les valeurs par défaut des propriétés : un fichier écrit avant cette version, sans `trips`, échouerait au décodage, et `load()` repartirait de zéro en effaçant les lieux appris. `TravelPlaces` gagne donc un `init(from:)` écrit à la main, avec `decodeIfPresent` pour chaque champ, anciens comme nouveaux. Un test décode un fichier de la version actuelle.

## 4. Règles pures : `TravelPlanner`

Nouveau type dans `VaultKit/Travel/TravelPlanner.swift`, sans horloge, sans position, sans entrées-sorties, à côté de `TravelDetector` qui reste tel quel.

Entrée `TravelSignals` : `now`, `places` (inout), `travelling`, `unlocked`, verdict de lieu (`TravelVerdict?`), décalage UTC courant, `atAirport: Bool`.

Sortie : un nouveau type `TravelPrompt` (`TravelSuggestion` reste celui de `TravelDetector`, inchangé, et le planner le traduit) :
- `.none` ;
- `.suggest(reason: Reason, notify: Bool)` avec `Reason` = `.away(cell)` (existant), `.tripStarting(tripID)`, `.flightFound(eventID, start, end)`, `.atAirport`, `.newTimeZone` ;
- `.autoEnter(tripID)` ;
- `.welcomeBack` (existant).

Ordre de décision (le premier qui s'applique gagne) :
1. Travel Mode actif : `.welcomeBack` si un voyage couvrant `now` vient de finir ou si le verdict est `.home`, et que la carte n'a pas été écartée ; sinon `.none`.
2. Un voyage couvre `now` (de `start - 3 h` à `end`) : `.autoEnter` s'il est `autoEnter` et que le coffre est déverrouillé, sinon `.suggest(.tripStarting)`.
3. `atAirport` : `.suggest(.atAirport)`.
4. Verdict `.away` : comportement actuel de `TravelDetector.check` (Plus tard, une notification par voyage).
5. Décalage UTC non habituel, avec au moins 3 jours d'observation : `.suggest(.newTimeZone)`, soumis au même « Plus tard » que `.away`.
6. Sinon `.none`.

« Non » sur `.newTimeZone` rend le décalage habituel. « Non » sur `.tripStarting` supprime le voyage. « Plus tard » se tait jusqu'au retour (règle existante). La détection d'un vol dans le calendrier (section 6) produit `.flightFound` directement, hors de cet ordre, car elle ne dépend pas de l'instant.

## 5. A : voyages programmés et fuseau horaire

- **Saisie.** Réglages > Travel Mode > Voyages > « Ajouter un voyage » : départ (date et heure), retour (date), « Activer automatiquement » (désactivé). Modifier, supprimer par glissement (iPhone) ou menu (Mac).
- **Notifications.** À l'enregistrement d'un voyage, deux `UNCalendarNotificationTrigger` : la veille à 19 h et 3 h avant le départ. Identifiants `travel.trip.<id>.eve` et `.go`. Retirées quand le voyage change, est supprimé ou que le Travel Mode est déjà actif. Niveau `active`. Seulement si les notifications sont déjà permises : la permission est demandée une fois, à l'enregistrement du premier voyage.
- **Activation automatique.** Au déverrouillage, si le planner rend `.autoEnter`, l'app appelle le même chemin que le bouton actuel (`TravelSettings.enter` déplacé dans `AppModel.enterTravel(reason:)` pour être partagé) : présence (Face ID, Touch ID ou code), `syncNow`, `enterTravel`. En cas d'échec (pas de réseau, synchro refusée), la carte `.tripStarting` s'affiche avec l'erreur. Une seule tentative automatique par voyage (`autoTried` dans le voyage) ; ensuite la carte seule.
- **Fuseau horaire.** À chaque vérification existante (premier plan, au plus toutes les 3 h), `TimeZone.current.secondsFromGMT()` est observé hors Travel Mode, comme une cellule. Ça marche aussi sans permission de localisation : la vérification se fait même si la position est refusée (le verdict de lieu vaut alors `nil`).

## 6. B : calendrier

- **Interrupteur** « Chercher mes vols dans le calendrier » (désactivé). Au premier passage à activé : `EKEventStore.requestFullAccessToEvents()`. Refus : l'interrupteur revient à désactivé avec une ligne qui renvoie aux Réglages du système.
- **Clés.** iOS et macOS : `NSCalendarsFullAccessUsageDescription`. macOS : entitlement sandbox `com.apple.security.personal-information.calendars`.
- **Quand.** Au premier plan, coffre déverrouillé, au plus une fois par jour (`lastCalendarScan`).
- **Quoi.** Les événements des 30 prochains jours, tous calendriers. Un événement est un vol si l'une des règles suivantes s'applique :
  1. Le titre contient deux codes IATA de 3 lettres majuscules connus de la liste d'aéroports (section 7) ;
  2. Le titre contient un numéro de vol (`[A-Z0-9]{2}\s?\d{1,4}`) et un mot-clé de vol des 4 langues de l'app (fr, en, es, it : `vol`, `flight`, `vuelo`, `volo`, liste dans un fichier de règles) ;
  3. L'événement a un `timeZone` dont le décalage diffère de l'actuel et un `structuredLocation`.
- **Résultat.** Le premier vol non vu donne `.flightFound` ; le retour est le prochain vol trouvé dans les 30 jours, sinon `start + 7 jours`, modifiable. La carte « Vol le 3 déc. Créer un voyage ? » : Oui ouvre l'éditeur de voyage prérempli, Non et Plus tard ajoutent l'identifiant à `seenEventIDs`. Jamais de création silencieuse.
- **Mémoire.** Ni titre, ni lieu, ni notes ne sont gardés : seulement l'identifiant et les dates du voyage créé.

## 7. C : aéroport

- **Interrupteur** « Proposer à l'aéroport » (désactivé). Au premier passage à activé : `requestAlwaysAuthorization()` (après « Lorsque l'app est active » si rien n'est encore donné). Sans « Toujours », l'interrupteur reste activé mais ne vérifie qu'au premier plan, et une ligne le dit.
- **Clé.** `NSLocationAlwaysAndWhenInUseUsageDescription` ajoutée à `project.yml` et à `Info.plist`. Elle rend aussi possible la partie arrière-plan de la détection existante, qui ne pouvait jamais s'exécuter faute de cette clé.
- **Données.** `airports.json` dans VaultKit, construit une fois depuis OurAirports (domaine public) par un script versionné (`scripts/build-airports.py`) : type `large_airport` avec vols réguliers, code IATA, latitude, longitude. Environ 600 entrées, moins de 30 Ko. Mention dans `NOTICE`.
- **Surveillance.** iOS limite une app à 20 zones. On surveille les 20 aéroports les plus proches (`CLCircularRegion`, rayon 2 km), recalculés à chaque changement significatif de position. Mac : mêmes API, sans changement significatif ; recalcul à chaque vérification au premier plan.
- **Entrée dans une zone.** Si le Travel Mode n'est pas actif et qu'aucune notification d'aéroport n'est partie ce jour-là : une notification `timeSensitive` « Tu es à l'aéroport. Active le Travel Mode avant le contrôle. » Nouvel entitlement `com.apple.developer.usernotifications.time-sensitive`. À l'ouverture, le planner rend `.atAirport`, ou `.autoEnter` si un voyage `autoEnter` couvre ce jour.
- **Au retour.** Une arrivée dans une zone d'aéroport avec le Travel Mode actif ne fait rien : la sortie reste manuelle.

## 8. Sortie

Jamais automatique, quel que soit le signal. La carte « De retour ? Désactiver le Travel Mode » s'affiche quand le voyage en cours est fini ou que le verdict de lieu est `.home`, et ouvre la sortie habituelle (réseau, vérification). Pas de notification.

## 9. Interface

- **Réglages > Travel Mode** (iPhone et Mac) : la section « Détection » existante devient trois interrupteurs (lieux et fuseau, calendrier, aéroport), chacun avec une ligne d'explication ; une section « Voyages » au-dessus.
- **Carte d'accueil** (iPhone) et de liste (Mac) : la carte existante prend un titre selon la raison (« Ton voyage commence », « Vol trouvé », « À l'aéroport », « Nouveau fuseau horaire », « Tu voyages ? »). Réponses Oui, Non, Plus tard ; pour `.flightFound`, Oui ouvre l'éditeur de voyage.
- **Textes** dans les 4 langues de l'app (catalogue existant).

## 10. Tests

- **VaultKit, `TravelPlannerTests`** : chaque branche de l'ordre de décision ; fenêtre `start - 3 h` ; `autoEnter` seulement déverrouillé ; une seule tentative auto ; « Non » et « Plus tard » par raison ; décalage habituel après 3 jours ; Travel Mode actif ne propose rien sauf `.welcomeBack` ; nettoyage des voyages finis depuis 7 jours ; limite de 16 voyages.
- **VaultKit, compatibilité** : un `TravelPlaces` encodé par la version actuelle (fixture JSON) se décode avec ses lieux intacts et `trips` vide.
- **VaultKit, `FlightMatcherTests`** : règles 1 à 3 sur des titres connus dans les 4 langues, faux positifs (« Volley », « Volontariat » sans numéro), événement sans lieu.
- **VaultKit, `AirportIndexTests`** : les 20 plus proches de Paris, de Tokyo, autour de l'antiméridien ; le fichier se charge et a des codes uniques.
- **App, UI tests (bundle QA)** : ajouter un voyage, la carte « Ton voyage commence » à l'ouverture avec une horloge de test (`-travel-now`) ; aéroport simulé (`simctl location` sur CDG) avec `-travel-airports-on` en DEBUG.
- **Notifications** : test unitaire des identifiants et des dates programmées, sans le centre système (protocole injecté).

## 11. Phases

1. **A** : modèle, `TravelPlanner`, compatibilité, voyages, notifications, activation auto, fuseau horaire.
2. **B** : calendrier.
3. **C** : aéroports, permission « Toujours », entitlement `timeSensitive`.

Chaque phase a son plan et se livre seule ; B et C dépendent de A.

## 12. Rulings

1. Sortie jamais automatique - un signal falsifié ne doit pas pouvoir ramener des données - coût si faux : un clic de plus au retour.
2. Activation auto seulement au déverrouillage - les clés ne sont pas en mémoire sinon, et l'entrée demande la présence - coût si faux : un voyage `autoEnter` sans ouverture de l'app part sans Travel Mode ; les notifications le rappellent.
3. Voyages dans le fichier local chiffré, pas dans un coffre - un coffre se synchronise - coût si faux : chaque appareil a ses voyages ; à saisir sur iPhone et Mac.
4. Calendrier en accès complet, demandé seulement à l'interrupteur - l'accès en écriture seule ne lit rien - coût si faux : une grosse permission pour un gestionnaire de mots de passe, d'où l'opt-in et la mémoire limitée aux identifiants.
5. « Toujours » demandé à l'activation de l'aéroport (décision du fondateur, remplace le ruling 5 du 2026-11-02 pour ce seul interrupteur) - une zone ne réveille pas l'app sans elle - coût si faux : une permission forte de plus.
6. 20 aéroports les plus proches, liste embarquée - limite de 20 zones d'iOS, pas de réseau - coût si faux : un petit aéroport n'est pas couvert.
7. Notification d'aéroport `timeSensitive` - elle doit passer la Concentration pour arriver avant le contrôle - coût si faux : un entitlement de plus, une notification par jour au plus.
8. Le planner est un nouveau type, `TravelDetector` reste tel quel - ses tests et son comportement sont figés - coût si faux : deux types à lire pour comprendre la décision.
