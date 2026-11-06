# Wi-Fi automatique (Android)

Date : 2026-11-04. Statut : branche `wifi-auto-android`, pas encore sur main. Apple : `2026-11-04-wifi-auto.md`.
Windows et Linux : la CLI.

## Ce que veut le fondateur

Intégré au système, presque invisible. Wi-Fi : aucun bouton, ça se fait tout seul, « je ne veux
même pas y penser ».

## Ce qui se passe

Un seul réglage, **Wi-Fi automatique**, désactivé par défaut (depuis le 2026-11-06). Rien d'autre à l'écran.

### Du coffre vers le téléphone

Chaque réseau que le modèle partagé du core retient (`onepass_core::wifi`, exposé par
`Session.wifiNetworks`) devient une suggestion de réseau Android (`WifiNetworkSuggestion`,
Android 10 et plus). Le téléphone s'y connecte seul quand il est à portée, comme à un réseau
enregistré.

- Mêmes règles que les autres plateformes, puisque c'est le même code : SSID de 1 à 32 octets,
  sécurité personnelle (WPA, WPA2, WPA3, SAE, ou vide avec un mot de passe), phrase WPA valide
  (8 à 63 caractères ASCII imprimables, ou 64 chiffres hexadécimaux), ni corbeille ni archive,
  un réseau par SSID (l'élément modifié le plus récemment gagne).
- Une clé brute de 64 chiffres hexadécimaux reste hors d'Android : les suggestions ne prennent
  qu'une phrase de 8 à 63 caractères. Le réseau est compté à part, sans faire échouer la synchro.
- Jamais proposés : réseaux ouverts, WEP, entreprise (802.1X, EAP, RADIUS), sécurité inconnue.
  Un téléphone qui rejoint seul un réseau ouvert ou d'entreprise se fait piéger par un faux point
  d'accès (evil twin).
- Resynchronisé à chaque ouverture du coffre et à chaque modification (création, modification,
  corbeille, restauration, archive, commit distant) : les nouveaux réseaux sont ajoutés, les
  disparus retirés, les modifiés mis à jour, et rien n'est touché quand rien n'a changé.
- Registre local (préférences de l'app, jamais sauvegardé : `allowBackup=false`) : par SSID, la
  sécurité et l'empreinte du core. L'empreinte ne dépend pas du mot de passe (élément, SSID,
  sécurité, masqué, date de modification) : le registre ne contient rien qui permette de tester un
  mot de passe.
- Android 11 et plus : un réseau modifié est réajouté sur place. Android 10 : retiré puis réajouté
  (Android 10 refuse un doublon). Une sécurité changée est une autre clé Android : l'ancienne
  suggestion part d'abord.
- Android 11 et plus : si Android a perdu les suggestions que le registre liste, tout est
  réinstallé.
- Android 13 et plus : un retrait laisse vivre la connexion en cours (`LINGER`) ; un coffre
  momentanément incomplet ne coupe pas un appel.
- Un réseau refusé par Android ne bloque pas les autres (ajout un par un après un refus de lot),
  et il est retenté à la modification suivante du coffre.
- Réglage coupé : toutes les suggestions de OnePass quittent Android. Rallumé : elles reviennent
  dès que le coffre est ouvert.

À la différence d'Apple (décision R4 du spec Apple : pas de retrait automatique), Android retire
les réseaux d'un élément supprimé : une suggestion appartient à OnePass, pas à l'utilisateur, et
Android l'efface de toute façon à la désinstallation. Les réseaux que l'utilisateur a enregistrés
lui-même ne sont jamais touchés.

### Du téléphone vers le coffre

Impossible. Android ne donne à aucune app les mots de passe des réseaux enregistrés (ni
`WifiManager`, ni les configurations, depuis Android 10). Pas de capture par QR code ni de
partage vers OnePass pour l'instant : l'app Android n'a pas encore d'écran de coffre où enregistrer
un élément (voir Décisions).

## La question système qui reste

| Question | Pourquoi | Combien |
|---|---|---|
| « Autoriser les réseaux suggérés par OnePass ? » (notification Android) | imposée par l'API des suggestions | une fois pour l'app, la première fois qu'un réseau suggéré est à portée |

Aucune API ne la déclenche ni ne la supprime. OnePass la prépare une fois : la première synchro qui
donne des réseaux à Android avant l'accord affiche un message court (« Android te demandera une
seule fois... »), et la ligne d'état du réglage le répète tant que l'accord manque. Sur Android 12
et plus, OnePass lit l'état de l'accord ; refusé, la ligne d'état ouvre les réglages de l'app.

## Code

- `android/wifi` (module sans dépendance au core, tests JVM) : `WifiSync.kt` (plan, synchro,
  registre), `AndroidSuggestionPort.kt` (WifiManager), `WifiAutomation.kt` (point d'entrée de
  l'app, réglage, fil Wi-Fi, registre en préférences).
- `android/app/.../wifi/VaultWifi.kt` : du coffre (`Session.wifiNetworks`) vers le module.
- `core/onepass-ffi/src/wifi.rs` : `Session.wifi_networks(excluded_vault_ids)` sur le modèle
  partagé.
- Réglage : `MainActivity` (l'app n'a pas encore d'autres écrans).
- Debug seulement : `WifiDemoActivity` (`adb shell am start -n me.somalabs.onepass/.WifiDemoActivity
  -e step seed|edit|clear`), un coffre jetable de routeurs de test synchronisé par le vrai chemin.
- Tests : `android/wifi/src/test/.../WifiAutoSyncTest.kt` (faux WifiManager derrière
  `SuggestionPort`), `android/vaultkit-android/src/test/.../WifiNetworksTest.kt` (sélection par
  les bindings Kotlin).

## Branchement

L'app Android n'a pas encore d'écran de coffre ni de déverrouillage. Le point d'entrée est prêt :
l'écran qui ouvre le coffre appelle `VaultWifi.opened(automation, session)`, chaque modification
appelle `VaultWifi.changed`, le verrouillage `VaultWifi.locked`. Aucun autre geste : pas de bouton.
En attendant, seul `WifiDemoActivity` (debug) passe par ce chemin.

## Décisions

- A1 : suggestions de réseau, pas `ACTION_WIFI_ADD_NETWORKS`. Les suggestions sont silencieuses
  après un accord unique ; l'autre API ouvre une fenêtre à chaque lot. Coût si faux : un utilisateur
  qui refuse la notification n'a plus de Wi-Fi automatique avant de l'autoriser dans les réglages.
- A2 : la sélection vient du core (`Session.wifiNetworks`), pas d'une copie en Kotlin. Coût si
  faux : aucun, Android suit les autres plateformes.
- A3 : retrait automatique des réseaux d'un élément supprimé (voir plus haut). Coût si faux : un
  réseau disparaît d'Android pendant une synchro partielle, revient à la suivante ; Android 13+
  garde la connexion en cours.
- A4 : réseau invité du routeur (`guest_ssid`) non proposé, comme sur les autres plateformes.
  Coût si faux : l'utilisateur rejoint lui-même son réseau invité.
- A5 : pas de capture QR ni de partage vers OnePass : il faudrait un écran de coffre ouvert pour
  enregistrer l'élément, l'app Android n'en a pas encore. À faire avec les écrans du coffre.
