# Profil : compte et sécurité, ouvert depuis le panneau compte

Date : 2026-11-14. Statut : design approuvé par le fondateur en conversation (contenu « Compte » et « Sécurité », ouverture par la ligne compte, même design recopié par app). Spec à relire avant le plan.

## 1. But

Aujourd'hui, la ligne « nom + Appareil personnel » en haut du panneau compte (`AccountPanel.currentAccount`, `apple/App/Browse/Phone/AccountMenu.swift`) est un simple en-tête : un tap ne fait rien. La page Profil (`apple/App/Browse/Phone/ProfileView.swift`, Accueil > Profil) montre seulement l'avatar, le nom, l'identité principale et la carte principale, et n'existe que sur iOS.

Cette spec :

1. rend la ligne compte cliquable, elle ouvre le Profil ;
2. ajoute au Profil une carte **Compte** et une carte **Sécurité**, au-dessus des cartes Identité et Carte de paiement, qui ne changent pas ;
3. porte le Profil sur Mac ;
4. recopie la même mise en page dans Prism et Soma Flight, chaque app avec ses propres données et son propre code.

Hors champ : statistiques du coffre, liste des appareils du compte, nouveau stockage côté noyau, nouveau package Swift partagé entre les repos.

## 2. Entrée

- **iPhone, iPad** : `currentAccount` devient un bouton avec un chevron à droite. Il renvoie une nouvelle action `AccountPanelAction.profile`. `AccountMenu.run` pousse `PhoneRoute.profile` sur la pile de l'onglet affiché (même chemin que la tuile Profil de l'accueil, `HomeTab`).
- **Plusieurs comptes** : la section comptes ne change pas (chaque ligne bascule de compte). Une rangée « Profil » s'ajoute en tête du groupe d'actions, avec la même action. Le Profil montre toujours le compte actif.
- **Mac** : le même panneau s'ouvre sous la ligne compte de la barre latérale. L'action `.profile` sélectionne une nouvelle entrée de barre latérale « Profil » qui affiche la page dans la colonne de détail.
- Identifiants d'accessibilité : `account.current` reste sur la ligne, `account.profile` sur la rangée dédiée.

**Coordination :** au moment de la spec, une autre session a des changements non commités dans `AccountMenu.swift` et `Sidebar.swift` (rangée « Configurer un appareil », panneau sur Mac). L'implémentation attend que ces changements soient commités, puis part de cet état.

## 3. Page Profil

Ordre de haut en bas. Le style reprend les cartes de `ProfileCard` (barre colorée en haut, tuile et titre, rangées). Chaque rangée de navigation se termine par un chevron et mène à l'écran de Réglages qui la modifie. Aucune valeur n'est modifiée sur la page même.

### 3.1 En-tête

- Avatar 72 (`AccountBadgeAvatar`), nom affiché.
- Sous le nom, en secondaire : le libellé du compte (`AccountProfile.label`) s'il diffère du nom, sinon rien.
- Pastille : « Appareil personnel » ou « Appareil partagé » (`settings.deviceMode`), avec la couleur du compte.

### 3.2 Carte Compte

| Rangée | Source | Comportement |
|---|---|---|
| Type de compte | `AccountProfile.kind` (personnel, professionnel, géré par une organisation) | Texte seul |
| ID du compte | `AccountProfile.accountID`, affiché en 4 premiers et 4 derniers caractères | Copier au tap (toast « ID copié »), absent si nil |
| Domaines pro | `AccountProfile.workDomains` | Absente si la liste est vide |
| Synchronisation | `AppModel.syncStatus` : libellé du statut, plus `lastSync` en relatif (« il y a 3 min ») quand il est connu | Ouvre Réglages > Sync |

Pas de date de création du compte : le noyau ne stocke que la date d'ajout du compte sur cet appareil (`FfiAccountEntry.createdAt`, 0 pour le compte principal), ce n'est pas la même information. Pas de rangée kit de secours : l'app n'a pas d'écran du kit après l'inscription.

### 3.3 Carte Sécurité

| Rangée | Source | Comportement |
|---|---|---|
| Watchtower | `WatchtowerModel.report` : score sur 100 dans un petit anneau, puis les deux vérifications avec le plus de problèmes (ex. « 3 réutilisés · 2 faibles ») | Ouvre Watchtower. Pendant le calcul, l'anneau est vide et le texte dit « Analyse… ». La page appelle `refreshIfNeeded` |
| Déverrouillage | Biométrie active ou non (Face ID, Touch ID, Optic ID selon l'appareil) et `settings.autoLockDelay` (« Face ID · 5 min ») | Ouvre Réglages > Sécurité |
| Appareil | `settings.deviceMode` | Ouvre la section du mode d'appareil dans Réglages > Sécurité |
| Mot de passe principal | Texte « Changer » | Ouvre `ChangePasswordSheet` |
| Passkeys | Nombre d'éléments avec au moins une passkey (`session.counts().passkeys`) | Ouvre la liste `ItemFilter.passkeys` |

Pas de compteur de codes 2FA : les résumés en mémoire n'indiquent pas la présence d'un champ TOTP, et charger chaque élément serait trop lent. Les sites qui proposent la 2FA restent dans Watchtower.

### 3.4 Identité et Carte de paiement

Pas de changement : mêmes cartes, même lecture des champs, même garde reprompt et Travel Mode.

### 3.5 États

- Coffre verrouillé : la page n'est pas atteignable (le panneau est derrière le déverrouillage). Si le coffre se verrouille pendant l'affichage, le comportement existant s'applique.
- Travel Mode actif : les rangées Compte et Sécurité restent visibles. Les comptes Watchtower et 2FA ne comptent que les coffres visibles, comme le fait déjà Watchtower.
- Compte local sans synchro : la rangée Synchronisation affiche « Désactivée » et ouvre quand même les réglages.

## 4. Confidentialité

- Rien de secret n'est affiché : ni Secret Key, ni mot de passe, ni numéro de carte complet. Le Profil ne donne aucun accès à la Secret Key.
- L'ID du compte est tronqué à l'écran. La copie met l'ID complet dans le presse-papiers en local seulement, par `Clipboard.copy(_:concealed: false)` de VaultKit, comme les autres copies de l'app.
- Les rangées portent `.privacySensitive()` comme les rangées actuelles.

## 5. Plateformes

- iOS et iPadOS : `ProfileView` enrichie.
- macOS : `ProfileView` sort du `#if os(iOS)`. Les parties propres à l'iPhone (`pushPhoneRoute`, `PhoneBackground`, `navigationBarTitleDisplayMode`) passent derrière des conditions ou des petites vues par plateforme. Les feuilles (choix de l'identité, changement de mot de passe) s'ouvrent comme les autres feuilles du Mac.
- watchOS, visionOS : rien de nouveau.

## 6. Localisation

Nouvelles clés `profile.account.*` et `profile.security.*` dans `Localizable.xcstrings`, avec le français, l'anglais, l'espagnol et l'italien, comme les clés `profile.*` existantes.

## 7. Prism et Soma Flight

Même design, code propre à chaque app, comme le portage des Réglages du 2026-11-03. Pas de dépendance entre repos.

- **Prism** (`Soma_iOS/Prism/Features/Settings/SettingsSheet.swift`) : la ligne compte ouvre déjà `SettingsRoute.account`. L'écran du compte reçoit le même en-tête et deux cartes : Compte (e-mail de `AccountSession`, prénom, statut de synchro Santé) et Sécurité (verrouillage de l'app s'il existe, consentements, suppression du compte). Le plan fait l'inventaire des données réellement disponibles et n'affiche que celles-ci.
- **Soma Flight** (`Soma_Flight/Packages/FlightKit/Sources/FlightKit/UI/Screens/SettingsView.swift`) : la ligne compte ouvre l'écran Profil existant (`ProfileStore`). Il reçoit le même en-tête et deux cartes : Compte (méthode de connexion, nom et emoji vus par les amis) et Sécurité (déconnexion, suppression du compte, confidentialité). Même règle d'inventaire.
- Ordre : OnePass d'abord, validé à l'écran par le fondateur, puis Prism et Soma Flight, chacun dans son repo, sur sa branche habituelle.

## 8. Tests

- Tests unitaires VaultKit ou App pour les fonctions pures : troncature de l'ID, texte de synchro relatif, texte de déverrouillage, comptage 2FA et passkeys sur des résumés de test.
- Test UI iPhone : tap sur `account.current` ouvre la page, les identifiants `profile.account` et `profile.security` sont présents, chaque rangée de navigation ouvre le bon écran.
- Captures iPhone, iPad et Mac, clair et sombre, à faire valider par le fondateur avant Prism et Soma Flight.
- Aucun tirage aléatoire de l'OS dans `apple/`, même dans un `#Preview` (garde `rng_guard`).

## 9. Questions tranchées au plan

1. Date de création du compte : pas de source, rangée retirée (section 3.2).
2. Compteur 2FA : retiré. Passkeys : filtre `ItemFilter.passkeys` existant (section 3.3).
3. Kit de secours : pas d'écran existant, rangée retirée (section 3.2).
