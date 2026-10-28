# Jalon 2b dans les apps : appairage, appareils, retrait, mode public

Date : 2026-10-27
Statut : approuvée (auto-approbation, règle permanente du propriétaire)
Portée : sections 5 à 8 de `2026-10-26-milestone-2b-pairing-design.md` (spec normative, désignée ci-dessous "spec 2b"), côté FFI, VaultKit et app (iPhone, iPad, Mac). Le core (`onepass-core` : `chain`, `lists`, `devices`, `vaultlist`, `pairing/`) est fusionné et ne change pas, sauf ajout additif si un test le révèle.

## 1. Ce qui manque

- La FFI n'expose ni l'appairage, ni la liste des appareils, ni le retrait, ni la suppression de coffre, ni le changement de mot de passe.
- VaultKit n'a ni transport, ni coordinateurs, ni session publique.
- L'app affiche "J'ai déjà OnePass sur un autre appareil" grisé (`soon: true`) et n'a pas de page Appareils.

Le jalon est fini quand la ligne M2b du README peut dire "Done" : appairage par QR, liste signée des appareils, retrait, mode public, dans les apps Mac et iOS.

## 2. FFI (`core/onepass-ffi/src/pairing.rs`, `devices.rs`)

Exactement la tâche 5 du plan 2b, avec ces précisions :

- Types : `FfiDevice{id, name, kind, mode, added_at, added_by, revoked_at, is_this_device}`, `FfiDeviceKind{Phone, Tablet, Mac, Vision, Other}`, `FfiDeviceMode{Personal, Shared, Public}`, `FfiPeerDevice{id, name, kind}`, `FfiPairingMessage`, `FfiAuditAction{Opened, Copied{label}}`, `FfiItemRef{vault_id, item_id}`.
- `Session` : `change_password`, `devices`, `this_device_id`, `register_this_device`, `revoke_device`, `rename_device`, `is_this_device_revoked`, `delete_vault`, `params_epoch`. Fonctions libres `store_params_epoch(db_path)` et `pinned_params_epoch(db_path)`.
- Objets `PairingNewcomer` et `PairingApprover` (UniFFI `Object`, état interne sous `Mutex`). Le core tient tout l'état cryptographique ; Swift ne voit que des octets opaques, le texte du QR, le code à 6 chiffres et, pour une session publique, les éléments déchiffrés (comme toute la FFI).
- `PairingApprover::seal_full_grant(session, secret_key, mode)` : ajoute l'appareil à la liste signée (`add_device`, `added_by` = cet appareil), persiste, puis construit l'instantané depuis le magasin (`snapshot_from_store`, plafond 50 Mio) et scelle l'autorisation. Refusé sans la confirmation du pair et sans `user_confirmed` (déjà dans le core).
- `PairingNewcomer::import_snapshot(db_path)` : magasin vide exigé (`AccountState::Empty`), import par `stage_remote` puis `commit_remote` (vérifications du magasin hostile), enregistrement du `device_id` attribué dans `chain`. En cas d'échec, le magasin est remis à vide et la Secret Key n'est pas rendue à Swift (elle n'est lue qu'après un import réussi : `take_secret_key()`).

## 3. VaultKit

Tâche 6 du plan 2b. Précisions :

- `PairingTransport` (protocole), `InMemoryPairingTransport`, `LocalNetworkPairingTransport` (Network.framework, `_onepass-pair._tcp`, nom de service = `session_id` en hexadécimal, `includePeerToPeer = true`, trames préfixées par 4 octets big-endian, 64 Mio au plus).
- Le `session_id` en hexadécimal est rendu par `PairingNewcomer.serviceName()` et, côté approbateur, lu dans le QR par `PairingApprover` avant la connexion (`pairing_service_name(qr_text)` en fonction libre : parse le QR, ne fait confiance à rien d'autre).
- `PairingNewcomerFlow`, `PairingApproverFlow`, `PublicSession`, extensions `VaultSession+Devices`.
- `VaultSession` : après chaque déverrouillage et chaque sync, `is_this_device_revoked` ; vrai : effacement (base, Secret Key, enrôlement biométrique, comme `resetForRecovery`) puis état `.failed(.deviceRevoked)`. Après déverrouillage, `register_this_device` si l'appareil n'a pas d'id (nom = nom de l'appareil, type = plateforme, mode = mode d'appareil courant).

## 4. App

### 4.1 Nouvel appareil

Accueil : "J'ai déjà OnePass sur un autre appareil" devient actif. Étapes : choix du mode (personnel, partagé, public) ; QR renouvelé toutes les 30 s avec le texte "Sur ton iPhone : Réglages > Appareils > Ajouter un appareil" ; comparaison du code à 6 chiffres ("Les codes sont identiques" / "Ils sont différents") ; attente ; puis mot de passe maître (personnel, partagé) ou session publique.

### 4.2 Session publique (nouvel appareil)

Racine dédiée, rien sur le disque : bandeau "Session invitée · se termine dans 14 min" avec compte à rebours visible, liste des éléments en lecture seule, détail en lecture seule, copie avec effacement du presse-papiers après 30 s, bouton "Terminer". Fin à l'expiration, sur `End`, à la perte de connexion, après 5 min sans activité, et quand l'app quitte ou passe en arrière-plan.

### 4.3 Approbateur

Réglages > Appareils (iPhone, iPad, Mac) : liste signée (nom, type, mode, date d'ajout, "Cet appareil", "Retiré le …"), "Ajouter un appareil", "Retirer cet appareil".

"Ajouter un appareil" : avertissement "Ne scanne jamais un QR code qu'on t'a envoyé", scanner, puis le type, le nom et le mode demandés par le pair, le code à 6 chiffres, "Les codes sont identiques", Face ID (sinon mot de passe maître), envoi. En mode public : choix des éléments, durée (15 min par défaut, 60 au plus), puis écran de suivi (compte à rebours, journal, "Terminer la session").

Retrait : confirmation, présence (Face ID ou mot de passe maître), puis conseil "Change ton mot de passe maître si cet appareil a été perdu ou volé." L'appareil courant ne peut pas se retirer lui-même depuis cette liste.

Réglages > Sécurité : "Changer le mot de passe maître". Réglages > Coffres : "Supprimer le coffre" (vide, pas le dernier).

### 4.4 Style

Langage visuel de la refonte en cours (`feat/onepass-redesign`) : mêmes composants DesignKit, cartes, titres et formulations à "tu" que les pages Réglages existantes. Aucun nouveau composant de base si un existant convient.

## 5. Sécurité

Toutes les propriétés de la spec 2b restent (5.3, 5.4, 11). En particulier : le QR ne s'ouvre qu'avec le scanner de OnePass ; jamais de collage du texte du QR en build de production ; rien ne part avant les deux confirmations et la présence ; la session publique n'écrit rien.

## 6. Tests

- Rust (`core/onepass-ffi/tests/m2b.rs`) : les six tests de la tâche 5 du plan 2b, plus `import_refuses_non_empty_store` et `secret_key_withheld_after_failed_import`.
- Swift : les huit tests de la tâche 6 du plan 2b.
- Bout en bout : Mac (nouvel appareil, QR affiché) et Simulateur iOS `OnePass M2b iPhone` (approbateur, texte du QR injecté en Debug), sur le transport réseau local de la machine.
- Seulement sur du vrai matériel : caméra, AWDL entre deux appareils, autorisation "Réseau local" sur un iPhone, retrait propagé par CloudKit entre deux appareils signés.

## 7. Décisions

Les rulings d'exécution sont dans `(internal notes, not published)`.
