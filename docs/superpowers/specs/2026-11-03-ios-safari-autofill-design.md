# Remplissage dans Safari sur iPhone et iPad

Date : 2026-11-03
Statut : approuvée (demande du fondateur, d'après son enregistrement de 1Password dans Safari iOS : "this is exactly the flow and design I want: a modal to unlock the vault to do the autofill, the whole integration in the keyboard, the full flow, the option to select an account, on mobile").
Portée : lève R-17 côté iOS ("the iOS one needs the bridge in the app"). Complète `2026-10-27-release-bridge-design.md` (pont), `2026-11-02-browser-auto-pairing-design.md` (association sans code), `2026-11-02-passkeys-on-iphone-design.md` (fournisseur de passkeys) et `2026-11-03` autofill-ranking (classement appris).

## 1. Ce que l'utilisateur obtient

1. Champ d'identifiant focalisé dans Safari : une petite icône OnePass dans le champ, une bulle "Déverrouiller OnePass" au-dessus quand le coffre est verrouillé ("OnePass" quand il est ouvert). La barre QuickType du clavier propose le compte du site (mot de passe ou passkey) publié par OnePass, comme pour 1Password.
2. Toucher l'icône, coffre verrouillé : une feuille pleine hauteur monte (fond sombre, "Annuler" en haut à droite, icône de l'app, avatar et nom du compte, champ "Mot de passe maître" avec le glyphe Face ID). Face ID part une fois tout seul ; réussi, la feuille descend et le remplissage continue (menu des comptes, ou remplissage direct quand le plan est sûr). Raté ou annulé : bouton "Déverrouiller avec Face ID" et champ mot de passe, jamais de nouvel essai automatique dans la même présentation.
3. Coffre ouvert : le menu en ligne (design B du Mac, liste groupée, bouton Remplir par ligne) s'ouvre sous le champ, en cibles tactiles de 44 pt. Choisir un compte remplit ; un formulaire à étapes (identifiant, puis mot de passe, puis code TOTP) se termine depuis la page comme sur le Mac (carte "Connexion en cours").
4. Menu système "Choisir un mot de passe enregistré" : chaque élément OnePass a un titre lisible (l'identifiant, ou le titre de l'élément quand l'identifiant est vide, ou "Se connecte avec Apple/Google" pour un élément sans mot de passe qui passe par un fournisseur). Le bouton "OnePass" ouvre le fournisseur AutoFill (liste de comptes, déverrouillage natif).
5. Passkeys : la barre QuickType propose "passkey pour ce site" ; l'assertion et l'enregistrement passent par le fournisseur (API iOS 17+, déjà en place, `prepareCredentialList(for:requestParameters:)`, `prepareInterface(forPasskeyRegistration:)`).

## 2. Architecture

```
Safari iOS : page -> script de contenu (icône, menu, feuille) -> fond de l'extension
  -> browser.runtime.sendNativeMessage -> OnePassSafari.appex (iOS)
     SafariWebExtensionHandler (NSExtensionRequestHandling)
       RelayHub (SafariRelay, partagé avec le Mac)
         InProcessHostLauncher -> paire de sockets -> BridgeServer.connect_in_process (Rust)
           onepass-bridge::host::Conn (appairage, session, service : le même code qu'au Mac)
             Session du coffre ouverte DANS l'appex (VaultSession, VaultKit)
       VaultGate : vault_state, unlock_biometric, unlock_password (hors pont, voir 4)
Clavier : ASCredentialIdentityStore <- IdentityStoreSync (app et appex) <- Session::autofill_identities
          OnePassAutoFill.appex (fournisseur) : liste, QuickType, passkeys
```

- Le code web de l'extension est celui du Mac (`extension/dist/safari`, copié par `copy-web-extension.sh`) ; le comportement tactile se décide à l'exécution (`matchMedia("(pointer: coarse)")`), sans build séparé.
- Le pont garde son contrat : enveloppes chiffrées, appairage ML-KEM + X25519, session, opérations. Sur iOS il n'y a pas d'app qui écoute : l'appex sert le pont lui-même, en Rust, sur une paire de sockets créée par `BridgeServer::connect_in_process`. L'admission par signature du Mac n'a pas lieu d'être : Safari ne route les messages natifs d'une extension que vers l'appex du bundle qui la contient. La connexion est admise comme Safari et associée sans code (sauf révocation), comme sur le Mac.
- Le coffre : l'appex ouvre sa propre `VaultSession` sur la base partagée (App Group) avec les clés du trousseau partagé (`me.somalabs.onepass.shared`), comme le fournisseur AutoFill. La session vit dans le processus de l'appex : quand iOS tue l'appex (page de fond déchargée), le coffre est de nouveau verrouillé. Verrouillage automatique après le délai réglé dans l'app (`autoLock`), au plus 15 minutes sans requête.
- `SafariRelay` devient multiplateforme : le lanceur de processus et le socket de l'app restent macOS ; `InProcessHostLauncher` (un descripteur de socket fourni par une fermeture) sert iOS et les tests.

## 3. Droits (entitlements) et cibles

- Nouvelle cible `OnePassSafariMobile` (app-extension, iOS, `com.apple.Safari.web-extension`, identifiant `$(ONEPASS_BUNDLE_ID_PREFIX).safari`), embarquée dans l'app iOS. Droits : App Group `$(ONEPASS_APP_GROUP)`, `keychain-access-groups` `$(AppIdentifierPrefix)$(ONEPASS_KEYCHAIN_GROUP)`. Pas de droit AutoFill (c'est le fournisseur qui l'a).
- Info.plist : `NSFaceIDUsageDescription`, `OnePassKeychainGroup`, `OnePassAppGroup`, `AppIdentifierPrefix`, `OnePassMailboxURL` (lus par VaultKit), `SFSafariWebExtensionConverterVersion` non requis.
- Le fournisseur `OnePassAutoFill` est inchangé côté droits (`autofill-credential-provider`, `ProvidesPasskeys`).

## 4. Modèle de sécurité du gestionnaire natif

- Appelant : seul Safari parle à l'appex, et seulement pour l'extension de ce bundle (garantie système). Pas d'autre point d'entrée : l'appex n'écoute aucun socket, la paire de sockets est privée au processus.
- Pont : inchangé. Une session demande la clé d'appairage (trousseau partagé, `WhenUnlockedThisDeviceOnly`, élément `me.somalabs.onepass.bridge`), les éléments `reprompt` demandent Face ID à chaque fois (`confirm_reprompt`), le mode Voyage cache ce qui doit l'être (`AppVault` du Rust).
- Déverrouillage : trois messages natifs hors pont, au même format strict que le relais (`onepass: 1`, clés connues seulement) :
  - `vault_state` -> `{locked, account, biometry: "faceID"|"touchID"|"none", password_reason}` ;
  - `unlock_biometric` -> la politique biométrique de VaultKit, inchangée : mot de passe après un redémarrage, tous les 14 jours, après un changement de biométrie (`BiometricUnlock`, `VaultError.passwordRequired`) ;
  - `unlock_password` -> le mot de passe maître tapé dans la feuille. Il ne passe que par la page de l'extension (origine de l'extension, iframe que la page web ne lit pas), le message natif de Safari, puis `SecretBytes` effacé après usage. Le compteur d'échecs et le blocage de l'app s'appliquent (`checkLockout`).
- Une seule tentative Face ID automatique par présentation de la feuille ; après un échec, le bouton explicite. Le code de l'écran de verrouillage du 2026-11-03 au matin (a8344232, reverté par 3e4b39c2) n'est pas réutilisé.
- Rien ne sort du Rust sauf ce que le pont sert déjà (valeurs d'un élément choisi, pour une origine précise).

## 5. Clavier et menu système

- `autofill_identities` classe avec l'historique appris (`fill_plan::learned::affinity`, contexte `system_autofill`) en plus du dernier utilisé et des favoris : `rank = base + bonus appris`, borné.
- Identifiant vide : l'identité porte le titre de l'élément (texte affiché seulement ; le remplissage rend l'identifiant réel, vide).
- Élément sans mot de passe ni identifiant qui se connecte par un fournisseur : identité mot de passe avec `sign_in_with` (nouveau champ), affichée "Se connecte avec <fournisseur>". Choisie, elle remplit l'adresse relais du fournisseur s'il y en a une, jamais un faux mot de passe.
- Synchronisation du magasin : l'app (déjà), le fournisseur (déjà), et l'appex Safari après chaque écriture du pont (`vault_changed` -> `publishAutofillIdentitiesNow`).

## 6. Ce qui demande le fondateur

1. developer.apple.com : identifiant d'app `me.somalabs.onepass.safari` pour iOS (le même que le Mac s'il existe déjà, plate-forme iOS cochée), capacités App Groups (`group.me.somalabs.onepass`) et Keychain Sharing ; régénérer les profils de développement (Xcode automatique le fait).
2. Sur l'iPhone : Réglages > Apps > Safari > Extensions > OnePass : activer, "Tous les sites web" : Autoriser. Réglages > Général > Remplissage automatique et mots de passe : OnePass activé (déjà fait).
3. Installation sur l'appareil (pas faite par l'agent).

## 7. Tests

- Rust : `connect_in_process` associe sans code, sert le coffre, voit le verrou ; révocation respectée ; identités : classement appris, titre de repli, fournisseur.
- Swift : `SafariRelay` (lanceur en processus, nouveaux messages stricts), VaultKit (passerelle de déverrouillage : une seule tentative automatique, politique, mot de passe effacé), constructeur d'identités.
- Extension : vitest (mode tactile, bulle, feuille de déverrouillage, transport des nouveaux messages).
- Bout en bout : Simulateur "OnePass-safari", page locale HTTPS à trois étapes (identifiant, mot de passe, TOTP), coffre verrouillé, feuille, choix du compte, QuickType. Vidéo dans `~/Desktop/OnePass-test-videos/2026-11-03-ios-safari-autofill/`.

## 8. Rulings

- I1 : l'appex sert le pont en processus (Rust `connect_in_process`) - il n'y a pas d'app qui écoute sur iOS et le contrat reste le même - coût si faux : un transport à changer, pas le protocole.
- I2 : association sans code pour l'extension Safari iOS - Safari ne route que l'extension du bundle - coût si faux : aucun ; une révocation la bloque comme sur le Mac.
- I3 : la session du coffre vit dans l'appex et meurt avec lui - pas de clé de coffre persistée hors Secure Enclave - coût si faux : Face ID plus souvent.
- I4 : déverrouillage par messages natifs hors pont - le pont n'a pas d'opération de déverrouillage et l'appelant est déjà authentifié par Safari - coût si faux : une opération de pont à ajouter.
- I5 : champ mot de passe maître dans la feuille de l'extension (exception à P-08 sur iOS) - le fondateur veut le parcours de 1Password et il n'y a pas d'app au premier plan - coût si faux : retirer le champ, garder Face ID et le fournisseur.
- I6 : la feuille est une iframe d'extension dans la page (pas la fenêtre surgissante de la barre) - testable, toujours disponible au toucher de l'icône - coût si faux : passer par `action.openPopup`.
- I7 : un seul build web, le tactile décidé à l'exécution - un code à maintenir - coût si faux : un drapeau de build.
- I8 : titre de l'élément comme texte d'identité quand l'identifiant est vide - le menu système doit être lisible - coût si faux : une ligne vide.
