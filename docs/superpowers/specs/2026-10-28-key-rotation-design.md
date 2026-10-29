# Rotation des clés du compte (constat F1)

Date : 2026-10-28
Statut : approuvée (auto-approbation, rulings en section 11)
Branche : `fix/key-rotation`, depuis la `main` privée `889284d`.
Portée : constat F1 (gravité moyenne) de l'audit du 2026-10-28. Le retrait d'un appareil marque seulement l'appareil dans la liste signée (`core/onepass-core/src/devices.rs`, `revoke_device`) et lui demande de s'effacer ; le changement de mot de passe rescelle le même keyset sous une nouvelle AUK (`repo.rs`, `change_password`, ruling B1 du jalon 2b). Rien ne fait tourner les clés de coffre, le keyset ni la Secret Key (limites 11 et 12 de la spec 2b). Un appareil perdu qui garde sa Secret Key, ou quelqu'un qui a eu un jour le mot de passe et la Secret Key, continue de déchiffrer tout ce que le serveur détient ou détiendra.

## 1. Ce que l'utilisateur obtient

1. **Retirer un appareil coupe vraiment l'accès.** Le retrait demande le mot de passe maître (c'est déjà le cas dans l'app) et fait tourner toutes les clés du compte dans la même écriture : nouvelle Secret Key, nouveau keyset, nouvelles clés de coffre, tous les éléments rechiffrés. Un nouvel Emergency Kit est affiché ; l'ancien ne sert plus à rien.
2. **Changer le mot de passe peut aussi faire tourner les clés** (option proposée, désactivée par défaut) : utile si le mot de passe et la Secret Key ont pu fuir ensemble.
3. **"Faire tourner les clés"** seul, dans Réglages > Sécurité.
4. Les autres appareils de confiance reçoivent la nouvelle Secret Key en étant réappairés (QR et code court, protocole du jalon 2b) ou en la saisissant depuis le nouvel Emergency Kit. Ils gardent leur état épinglé (plancher Argon2id, époques, listes vues).

## 2. Ce que la rotation garantit

Adversaire : un appareil retiré qui garde sa base, sa Secret Key et son keyset (ou un attaquant qui a extrait tout cela, ou qui connaissait mot de passe et Secret Key), allié à un stockage hostile (qui sert, rejoue ou retient n'importe quel enregistrement, et accepte ses écritures).

- **Confidentialité après rotation** : rien de ce qui est écrit après la rotation ne s'ouvre avec les anciennes clés. Les clés de coffre sont neuves et enveloppées pour la nouvelle clé KEM ; chaque élément est rescellé sous une clé d'élément neuve, elle-même scellée par la nouvelle clé de coffre.
- **Plus d'ancien chiffré chez un serveur honnête** : les anciens enregistrements d'élément sont supprimés dans la même écriture. Un serveur hostile qui les garde ne donne à l'ancien appareil que ce qu'il pouvait déjà lire avant (pas de secret avant la rotation, voir 10).
- **Plus de signature acceptée avec les anciennes clés** : manifestes, listes et époque de restauration sont signés de nouveau par la nouvelle clé de signature ; tout ce que signe encore l'ancienne clé (un manifeste, une liste qui réinscrit l'appareil retiré, une liste qui marque des coffres supprimés) est refusé (`Signature`).
- **Pas de retour à l'ancien keyset** : un appareil qui a vu la rotation refuse les anciens paramètres (`ParamsRollback` par l'époque épinglée, `ParamsUnsigned` par l'identité épinglée là où l'époque n'est pas conservée).
- **L'ancienne identité ne peut plus rien signer d'accepté** : l'appareil épingle la nouvelle clé d'identité ; des paramètres signés par l'ancienne sont refusés.

## 3. Ce qui tourne

| Élément | Tourne ? | Pourquoi |
| --- | --- | --- |
| Secret Key | oui | L'AUK = f(mot de passe, Secret Key) : sans nouvelle Secret Key, l'ancien appareil qui connaît le mot de passe ouvrirait le nouveau keyset. |
| Clé KEM du compte | oui | Les clés de coffre sont enveloppées pour elle. |
| Clé de signature hybride | oui | Elle authentifie manifestes, listes et époques : l'ancienne permettrait de forger un manifeste, une liste ou une suppression de coffre. |
| Clé d'identité SLH-DSA | oui | Elle signe les paramètres du compte : gardée, elle permettrait à l'ancien appareil de publier des paramètres (clés KEM et de signature à lui) qu'un appareil encore à l'ancienne Secret Key accepterait. |
| Paramètres Argon2id | sel neuf, coûts = max(actuels, plancher) | Comme un changement de mot de passe. |
| Mot de passe | optionnel | Le mot de passe actuel, ou un nouveau. |
| Clés de coffre | oui, et tous les éléments rechiffrés | Voir ruling K3. |
| `account_id`, ids de coffre et d'élément | non | Les ids ne sont pas secrets ; les garder évite toute migration des listes et du `last_seen`. |

## 4. Construction

### 4.1 Paramètres et keyset

Format v2 inchangé (`OPP2`, keyset `OPK2`) : les paramètres v2 portent déjà `identity_pub`, `signing_pub`, `kem_pub` et l'époque, signés par l'identité. La rotation écrit des paramètres d'époque + 1 avec les trois nouvelles clés publiques, signés par la **nouvelle** identité, et un keyset v2 scellé sous `AUK(mot de passe, nouvelle Secret Key, nouveaux paramètres Argon2id)`. Aucun nouveau format, aucune lecture à ajouter (ruling K2).

`Account::rotate(self, new_secret_key, password)` produit le compte neuf, sa nouvelle AUK et les deux enregistrements, puis prouve que la paire s'ouvre avant toute écriture (comme `rekey`).

### 4.2 Coffres et éléments

Pour chaque coffre vivant (`vaults()`, avec toutes les vérifications habituelles, chargement strict `load`) :

1. nouvelle clé de coffre aléatoire, enveloppée pour la nouvelle clé KEM (contexte `"vault:" || vault_id`, inchangé), métadonnées rescellées ;
2. chaque élément listé (vivant, archivé, à la corbeille) ouvert puis rescellé à la version + 1 sous une clé d'élément neuve, nouvel id de blob ;
3. manifeste suivant (`prev_hash` = hash du manifeste chargé), signé par la nouvelle clé de signature, `seq = max(seq + 1, époque × 2^32)` (voir 4.4) ;
4. suppression des anciens enregistrements d'élément listés et des restes ignorés.

### 4.3 Listes signées

La liste des appareils et la liste des coffres sont resignées par la nouvelle clé, au `seq` suivant (chaînage inchangé, les appareils qui les ont vues les acceptent). Lors d'un retrait, l'entrée de l'appareil passe à `revoked_at` dans cette même liste.

### 4.4 Époque de restauration

La rotation émet une époque de restauration (`max(époque retenue, époque stockée) + 1`), raison `EpochReason::KeyRotation` (variante ajoutée en fin), signée par la nouvelle clé, dont les têtes sont les nouveaux manifestes. Elle remplace l'ancienne (signée par l'ancienne clé, donc illisible après). Les autres appareils remplacent leur `last_seen` par ces têtes ; le plancher de `seq` (époque × 2^32) garantit qu'aucun manifeste d'avant ne passe pour un suivant.

### 4.5 Écriture unique

Tout part en une écriture (`RecordStore::put_all_if_version_and_delete`, une transaction en SQLite et dans `SyncStore`) : keyset, paramètres, clés, métadonnées et manifestes de chaque coffre, nouveaux éléments, deux listes, époque, puis les suppressions. Chaque écriture est conditionnelle à la version lue : une écriture concurrente donne `Conflict` et rien n'est écrit. Ensuite, en mémoire : nouveau compte, épingle sur la nouvelle identité (plancher relevé), époque des paramètres, listes vues, époque de restauration, `last_seen` = têtes, marque d'époque dans le magasin.

### 4.6 API du cœur

- `Repository::rotate_keys(current, secret_key, new_secret_key, new_password: Option<&str>) -> Result<Auk>` : rotation seule, ou avec un nouveau mot de passe.
- `Repository::revoke_device_rotating(id, password, secret_key, new_secret_key) -> Result<Auk>` : retrait plus rotation, une écriture. Refusé pour l'appareil courant (`Validation("device")`), un id inconnu est `NotFound`.
- `Repository::unlock_after_rotation(store, password, new_secret_key, device) -> Result<(Repository, Auk)>` : déverrouillage d'un appareil de confiance après une rotation faite ailleurs (voir 5). Il refuse une nouvelle identité présentée avec une Secret Key que l'appareil a déjà utilisée sous une autre identité (K15).
- `Repository::keys_rotated(store, device) -> Result<bool>` : sans déverrouiller, les paramètres stockés sont signés par une autre identité que celle épinglée, pour le même compte, à une époque supérieure à l'époque épinglée (l'app demande alors la nouvelle Secret Key).
- `revoke_device` (marque seule) reste pour la compatibilité et les tests ; les apps passent à `revoke_device_rotating`.

La nouvelle Secret Key vient de l'appelant (`SecretKey::generate`) et doit différer de l'actuelle (`Validation("secret key")`, K11) : il la range comme "en attente" avant l'appel et la promeut après `Ok`. Toute erreur de `rotate_keys` survient avant l'écriture ; une fois l'écriture validée, l'appel réussit, même si la tenue de compte qui suit échoue (K12). L'appelant ne jette la clé en attente que sur `WrongPassword`, `Conflict`, `Validation`, `Locked` ou `InvalidInput` ; sur toute autre erreur il garde les deux clés et essaie l'une puis l'autre au déverrouillage suivant. Une coupure entre la validation de l'écriture et la promotion laisse aussi les deux clés à l'appareil (ruling K6).

## 5. Les autres appareils de confiance

Après la rotation, un appareil resté sur l'ancienne Secret Key ne peut plus déverrouiller : l'identité stockée n'est plus celle qu'il a épinglée (`ParamsUnsigned`), son AUK biométrique n'ouvre plus le keyset. `keys_rotated` le lui dit sans déverrouiller ; l'app affiche "Les clés de ton compte ont changé sur un autre appareil. Saisis la nouvelle Secret Key ou réappaire cet appareil."

- **Saisie de la nouvelle Secret Key** : `unlock_after_rotation`, seulement sur un magasin qui retient les clés utilisées (`SyncStore`, K20). Il accepte une nouvelle identité seulement si les paramètres sont valablement signés par elle, pour le même `account_id`, si cette identité n'est pas une identité que l'appareil a quittée (`ParamsRollback`, K18), si l'appareil a une trace d'une clé pour l'identité qu'il épingle (sinon refus, `Validation`, K18 : fermeture sûre), si la Secret Key fournie n'est pas une clé qu'il a utilisée sous une autre identité (`Validation`, K15, K18), et si le keyset s'ouvre sous le mot de passe et la Secret Key saisis. L'époque épinglée sous l'identité quittée ne compte pas (K17) : elle est remplacée par celle des nouveaux paramètres, et l'époque de restauration acceptée sous elle est remise à zéro. L'épingle passe à la nouvelle identité, l'ancienne est retirée ; le plancher Argon2id, les listes vues et l'identifiant d'appareil restent.
- **Réappairage** : le protocole du jalon 2b transporte déjà la Secret Key et un instantané du magasin, sous un canal confirmé par code court ; rien à changer.

Pourquoi pas de livraison automatique (ruling K4) : un appareil qui ne connaît que les anciens secrets ne peut pas distinguer la rotation honnête d'une fausse rotation fabriquée par l'appareil retiré, qui connaît exactement les mêmes secrets. Seul un canal que l'appareil retiré ne contrôle pas (le code court de l'appairage, ou l'utilisateur qui tape la nouvelle clé) authentifie la nouvelle Secret Key. Pour la même raison, le déverrouillage normal (`unlock`, `unlock_with_auk`) ne suit jamais un changement d'identité : seul `unlock_after_rotation`, appelé avec une clé que l'utilisateur vient de fournir, le fait.

## 6. Ce que peut faire un stockage hostile

| Attaque | Résultat |
| --- | --- |
| Servir les anciens paramètres et l'ancien keyset à un appareil qui a vu la rotation | `ParamsRollback` (époque épinglée, `SyncStore`) ; `ParamsUnsigned` sur un magasin sans état épinglé (identité épinglée) |
| Même chose pendant `unlock_after_rotation` | `ParamsRollback` (époque inférieure) |
| Servir une ancienne enveloppe de clé de coffre | `Commitment` (ne s'ouvre pas avec la nouvelle clé KEM) |
| Servir un ancien manifeste, une ancienne liste ou l'ancienne époque | `Signature` |
| Manifeste, liste ou époque forgés par l'appareil retiré (ancienne clé de signature) | `Signature` |
| Paramètres forgés par l'appareil retiré (ancienne identité, époque plus haute) | `ParamsUnsigned` (identité épinglée) |
| Rotation coupée par le serveur (une partie des enregistrements seulement) | le magasin local reste cohérent (une transaction) ; un autre appareil qui récupère une rotation incomplète voit une erreur d'intégrité jusqu'à la fin de l'envoi (limite 10) |
| L'appareil retiré tente `unlock_after_rotation` avec son ancienne Secret Key | refusé (`Validation`, c'est la clé que l'appareil détenait) ; une autre clé est `WrongPassword` |
| L'appareil retiré fabrique une fausse rotation scellée sous l'ancienne Secret Key et le serveur la sert | `keys_rotated` le signale, mais `unlock_after_rotation` refuse l'ancienne clé (`Validation`) : l'épingle ne bouge pas (K11) |
| Le serveur sert des paramètres d'une autre identité à une époque non supérieure à l'époque épinglée | `keys_rotated` reste faux (K11) |
| Le serveur, un changement de mot de passe concurrent ou l'appareil retiré sert des paramètres de l'ancienne identité, à n'importe quelle époque, pendant que la rotation part | la paire de la rotation n'est jamais jetée et passe par-dessus, à sa propre époque ; rien d'autre ne part avant elle (K10, K17) |

## 7. Sûreté en cas de coupure

- Locale : une seule transaction ; avant elle rien n'est écrit, après elle tout l'est. Pas d'état intermédiaire à réparer.
- Secret Key : voir 4.6 et K6.
- Serveur : l'envoi de `SyncStore` n'est pas atomique côté CloudKit. Tant qu'une rotation attend (époque de restauration `KeyRotation` en attente) et que ses paramètres ne sont pas sur le serveur, `pending_changes` ne rend que la paire paramètres et keyset, seule (K10). Le reste (clés de coffre, métadonnées, manifestes, éléments, suppressions, listes, époque) part au tour suivant, une fois la paire confirmée. Un appareil qui récupère entre les deux voit la nouvelle paire et l'ancien contenu : il ne peut rien ouvrir sans la nouvelle Secret Key, et avec elle les coffres échouent jusqu'au second envoi. Un appareil réappairé reçoit l'instantané cohérent de l'approbateur.
- Marqueur durable (K13) : la transaction de la rotation pose dans `meta` l'identité tournée ; « rotation en attente » ne dépend que de lui (plus de l'époque de restauration, qu'un rebase pouvait jeter). Il tombe quand le serveur détient des paramètres de cette identité et que plus rien n'attend l'envoi. Tant qu'il est posé : la paire part seule et n'est jamais jetée ; un coffre retenu dont le manifeste serveur n'est pas signé par la nouvelle clé (écriture faite avec les anciennes clés) prend la copie de l'appareil (enregistrements d'élément étrangers supprimés, manifeste reconstruit sur celui du serveur) ; l'époque `KeyRotation` n'est jamais jetée, elle est réémise au numéro suivant avec les têtes courantes (le numéro du serveur, signé par l'identité quittée, ne compte pas). La clé et les métadonnées d'un coffre retenu attendent avec son manifeste, rotation ou non.
- Paire de l'ancienne identité sur le serveur (K17) : quelle que soit son époque (changement de mot de passe concurrent, ou appareil retiré qui signe avec l'ancienne identité), elle ne bloque rien : la paire de la rotation part par-dessus, à sa propre époque, sans réémission. Des paramètres non vérifiés comptent pour rien non plus. L'appareil qui tourne lève `password_change_overtaken` quand l'ancienne identité a écrit à une époque au moins égale à la sienne (K16). Un appareil resté sur l'ancienne identité ne pousse jamais un changement de mot de passe par-dessus des paramètres d'une autre identité : il le perd (`password_change_superseded`) et suit la rotation.
- Deux rotations concurrentes (K19) : la première complète gagne. Complète : paramètres, époque `KeyRotation`, tous les manifestes et les deux listes du serveur signés par la même nouvelle identité. Une rotation qui n'est pas complète peut être écrasée ; l'appareil qui l'avait faite remet sa paire en attente (gardée dans le marqueur) et reprend. Devant une rotation complète d'une autre identité, l'appareil ne pousse plus rien, son rebase rend `RotationOvertaken`, abandonne tout son contenu en attente et le marqueur ; l'utilisateur suit le gagnant (`unlock_after_rotation` avec sa clé) et peut tourner de nouveau ensuite.
- Après l'écriture : la marque d'époque et le nettoyage des copies gardées ne peuvent plus faire échouer l'appel (K12), ni la sauvegarde de l'état de l'appareil dans le FFI. La session suivante les refait.

## 8. Déclencheurs

- Retrait d'un appareil : automatique (`revoke_device_rotating`).
- Changement de mot de passe : option (`rotate_keys` avec `new_password`), FFI `rotate_keys`, CLI `account rotate-keys --change-password`.
- Rotation seule : `rotate_keys` sans nouveau mot de passe, FFI `rotate_keys`, CLI `account rotate-keys`.

## 9. Emergency Kit

La nouvelle Secret Key invalide l'ancien kit : avec l'ancien kit et le mot de passe, le keyset ne s'ouvre plus (`WrongPassword`). L'app doit afficher le nouveau kit tout de suite après la rotation et le faire confirmer comme à la création (suite à faire côté Swift, section 12). La CLI de développement affiche la nouvelle Secret Key avant l'écriture.

## 10. Limites

- Ce qu'un appareil retiré a déjà déchiffré, ou peut encore déchiffrer à partir de copies que garde un serveur hostile, reste à lui : la rotation protège l'avenir, pas le passé.
- Changement de mot de passe concurrent : perdu au profit de la rotation (K10).
- Rotation en attente sans AUK en mémoire (impossible par les chemins actuels : chaque déverrouillage et la rotation la gardent) : le rebase répond `InvalidFormat("rotation pending: unlock with the password")`.
- La boucle de sync de l'app doit repousser tant que `pending_changes` n'est pas vide : une rotation demande deux envois.
- Écritures concurrentes : une écriture d'un autre appareil faite avec les anciennes clés et arrivée sur le serveur avant la rotation est perdue pour ce coffre (le rebase ne peut pas vérifier un manifeste signé par l'ancienne clé : alerte, sortie "garder cet appareil"). Il faut synchroniser avant de faire tourner les clés ; l'app le fera.
- Mode voyage : refusé tant que des coffres sont garés (`InvalidFormat("travel mode active")`) ; l'état de voyage est scellé pour l'ancien compte.
- Archives liées au compte faites avant la rotation : elles sont enveloppées pour l'ancienne clé KEM et ne s'ouvrent plus avec le compte tourné. Les archives à phrase de passe ne changent pas. Refaire une sauvegarde après une rotation.
- Un appareil qui a manqué la rotation garde son épingle sur l'ancienne identité jusqu'à `unlock_after_rotation` ; entre-temps, il ne peut rien prouver de la liste des coffres signée (suppressions distantes refusées, fermeture sûre).
- Coût : chaque élément est réécrit (une version de plus, un enregistrement neuf), donc la rotation pousse tout le coffre.
- Le modèle formel ProVerif ne couvre pas la rotation (voir `docs/security/formal/README.md`).

## 11. Décisions

- Ruling K1: les trois clés du keyset tournent, identité comprise, avec une nouvelle Secret Key - l'appareil retiré détient tout le keyset et la Secret Key ; garder l'identité lui laisserait le droit de publier des paramètres, garder la clé de signature celui de forger manifestes, listes et suppressions de coffre - les appareils de confiance doivent réépingler (K4).
- Ruling K2: pas de nouveau format de paramètres ni de lien signé ancienne identité vers nouvelle ; le v2 porte déjà les trois clés publiques et l'époque - un lien signé par l'ancienne identité n'authentifie rien face à l'appareil retiré, qui la détient aussi - un appareil qui a manqué la rotation ne peut pas la suivre seul, il lui faut la nouvelle Secret Key.
- Ruling K3: les clés de coffre tournent et tous les éléments sont rechiffrés (clé d'élément neuve, version + 1), pas seulement les nouveaux - les clés d'élément anciennes sont connues de l'appareil retiré, et chez un serveur honnête les anciens chiffrés disparaissent : l'attaquant qui avait le mot de passe et la Secret Key mais pas encore les données ne peut plus les obtenir - la rotation réécrit tout le coffre (coût proportionnel au nombre d'éléments).
- Ruling K4: pas de livraison automatique de la nouvelle Secret Key aux autres appareils ; réappairage (QR et code court) ou saisie du nouveau kit, puis `unlock_after_rotation` - un appareil qui ne connaît que les anciens secrets ne peut distinguer la vraie rotation d'une fausse faite par l'appareil retiré ; il n'existe pas de clé propre à chaque appareil à laquelle sceller la nouvelle clé - une étape manuelle par appareil restant.
- Ruling K5: tout dans une écriture atomique et conditionnelle, avec une époque de restauration `KeyRotation` - pas d'état intermédiaire à réparer, et les autres appareils remplacent `last_seen` d'un bloc - une rotation concurrente à une autre écriture échoue (`Conflict`) et se refait.
- Ruling K6: la nouvelle Secret Key est fournie par l'appelant, qui la range avant l'écriture - une coupure entre l'écriture et l'affichage du kit ne doit jamais rendre le compte inaccessible - l'appelant gère deux clés pendant un instant.
- Ruling K7: le retrait par l'app fait toujours tourner les clés (`revoke_device_rotating`) ; `revoke_device` reste dans le cœur et le FFI pour la compatibilité - l'app demande déjà le mot de passe au retrait - tant que Swift appelle l'ancienne fonction, le retrait reste une simple marque (suite 12).
- Ruling K8: rotation refusée en mode voyage - l'état de voyage est scellé et signé pour l'ancien compte - quitter le mode voyage d'abord.
- Ruling K9: le déverrouillage normal ne suit jamais un changement d'identité ; seul `unlock_after_rotation` le fait - l'AUK biométrique ou la Secret Key déjà rangée ne prouvent rien de neuf - une saisie de plus après une rotation.
- Ruling K10 (revue adverse, 2026-10-28): une paire de rotation en attente n'est jamais jetée par la sync ; elle part seule, avant tout le reste de la rotation, et si le serveur la dépasse, le rebase la resigne au-dessus de son époque avec les mêmes clés et la même AUK - jeter la paire en gardant le reste laissait clés de coffre, manifestes et éléments liés à des clés qu'aucun paramètre ne nomme (compte détruit, par une course honnête ou par le serveur seul) - une rotation part en deux envois et gagne contre un changement de mot de passe concurrent, qui est perdu.
- Ruling K11 (revue adverse): `rotate_keys` refuse une nouvelle Secret Key égale à l'actuelle, `unlock_after_rotation` refuse une nouvelle identité présentée avec la Secret Key que l'appareil détenait (passée par l'appelant, comparaison en temps constant), et `keys_rotated` exige une époque supérieure à l'époque épinglée - l'appareil retiré connaît le mot de passe et l'ancienne clé : une fausse rotation scellée sous eux s'ouvrait et l'appareil de confiance épinglait l'identité de l'attaquant - l'appelant doit fournir l'ancienne Secret Key ; un serveur hostile peut encore provoquer la demande de nouvelle clé avec une époque plus haute, sans rien obtenir.
- Ruling K12 (revue adverse): après l'écriture validée, rien ne fait échouer la rotation (marque d'époque, nettoyage des copies gardées, sauvegarde de l'état dans le FFI : erreurs ignorées, refaites à la session suivante) ; l'appelant ne jette la nouvelle clé que sur `WrongPassword`, `Conflict`, `Validation`, `Locked` ou `InvalidInput` - une erreur rendue après l'écriture faisait jeter la seule clé qui ouvre le compte - un état d'appareil non sauvegardé se rattrape par `unlock_after_rotation` au déverrouillage suivant.
- Ruling K13 (seconde revue): « rotation en attente » repose sur un marqueur durable posé dans la transaction de la rotation et levé seulement quand le serveur détient l'identité tournée et que rien n'attend ; tant qu'il est posé, l'époque `KeyRotation` n'est jamais jetée (réémise), et un coffre retenu sous un manifeste non signé par la nouvelle clé prend la copie de l'appareil ; la clé et les métadonnées d'un coffre retenu attendent son manifeste - l'époque, seul indicateur jusque-là, était jetée par le rebase dès qu'un coffre était retenu, et la course honnête détruisait de nouveau le compte ; la clé d'un coffre retenu partait seule, laissant un coffre illisible - une écriture concurrente faite avec les anciennes clés est perdue (elle l'était déjà).
- Ruling K14 (seconde revue): la paire en attente ne tient compte que de paramètres serveur vérifiés (signés par leur identité, pour ce compte) ; une réémission ne monte jamais à plus de 16 au-dessus de l'époque de la rotation (`IntegrityError::ParamsEpochJump`, nouvelle variante en fin d'enum) - le serveur choisissait l'époque de réémission et pouvait la porter à `u64::MAX`, bloquant à jamais changements de mot de passe et rotations - plus de 16 changements de mot de passe concurrents d'une rotation en attente donnent une alerte.
- Ruling K15 (seconde revue): l'appareil retient l'empreinte de chaque Secret Key qu'il a utilisée (déverrouillage, création, rotation) avec l'empreinte de l'identité qu'elle ouvrait (HKDF-SHA256 de la clé, sel = id du compte ; 16 au plus, dans `meta` du `SyncStore`) ; `unlock_after_rotation` refuse une nouvelle identité présentée avec une clé connue sous une autre identité, et ne prend plus de « clé précédente » - la comparaison de deux arguments dépendait de leur ordre, et le conseil K12 « essaie l'une puis l'autre » l'inversait - un magasin sans mémoire (CLI) ne vérifie rien ; un état d'appareil d'avant ce changement ne connaît aucune clé jusqu'au prochain déverrouillage par mot de passe.
- Ruling K16 (seconde revue): l'appareil qui réémet sa rotation au-dessus de paramètres d'une autre identité lève `password_change_overtaken` (`SyncStore::take_password_change_overtaken`, FFI `take_password_change_overtaken`), pour que l'app l'écrive avec le nouvel Emergency Kit - le changement de mot de passe concurrent était perdu en silence - l'autre appareil ne le sait qu'en voyant la rotation (`keys_rotated`).
- Principes de la troisième revue (2026-10-28). Les rulings K17 à K20 en découlent ; ils remplacent la réémission au-dessus de l'époque du serveur de K10 et K14 :
  - P1 : dès qu'un appareil lance ou suit une rotation qui quitte I_old, I_old est compromise (l'appareil retiré en détient les clés). Rien de signé par I_old, à aucune époque, ne bloque, ne retarde ni ne dépasse la rotation sur cet appareil, et rien ne gèle toutes les écritures sans issue.
  - P2 : un appareil n'accepte une nouvelle identité qu'avec une Secret Key qu'il n'a jamais utilisée pour ce compte, et s'il ne peut pas le prouver (aucune trace), il refuse.
  - P3 : entre deux nouvelles identités issues de rotations de confiance, la première complète gagne ; la perdante ne la dépasse pas, signale `RotationOvertaken`, abandonne son contenu en attente, et l'utilisateur suit la gagnante.
- Ruling K17 (P1): les paramètres de l'ancienne identité ne comptent pas, à aucune époque : la paire de la rotation passe par-dessus à sa propre époque, sans réémission (supprimée, avec `Account::reissue` et le plafond de K14) ; un appareil qui suit une rotation ne compare pas l'époque des nouveaux paramètres à celle qu'il avait épinglée sous l'identité quittée, et la remplace (`params_forced`), comme son époque de restauration ; `keys_rotated` ne regarde plus l'époque ; un changement de mot de passe sous une identité qui n'est plus celle du serveur n'est jamais poussé et se perd - l'appareil retiré, qui détient l'ancienne identité, pouvait signer des paramètres à une époque arbitraire et bloquer ou faire monter la rotation jusqu'à `u64::MAX` - une rotation peut porter une époque inférieure à celle de paramètres de l'ancienne identité ; un serveur peut toujours provoquer la demande de nouvelle clé avec une identité fabriquée, sans rien obtenir.
- Ruling K18 (P2): une nouvelle identité n'est suivie qu'avec une clé jamais utilisée sur l'appareil sous une autre identité ; un appareil sans trace de clé pour l'identité qu'il épingle refuse (fermeture sûre) ; `Session::note_secret_key` (FFI) enregistre la clé du Keychain après un déverrouillage biométrique ; `rotate_keys` refuse toute clé connue de l'appareil ; l'identité quittée est retirée (dans la transaction de la rotation, ou au suivi) et n'est jamais suivie de nouveau (`ParamsRollback`), ce qui remplace l'époque comme garde contre le retour en arrière - un appareil qui ne se déverrouillait que par Face ID n'avait aucune trace et suivait une fausse rotation scellée sous l'ancienne clé - l'app doit appeler `note_secret_key` ; un appareil d'avant cette mémoire doit se déverrouiller une fois avec son mot de passe, ou être réappairé.
- Ruling K19 (P3): la première rotation complète gagne ; complète = paramètres, époque `KeyRotation`, tous les manifestes et les deux listes du serveur signés par la même identité ; une rotation incomplète peut être écrasée, et son auteur remet sa paire en attente depuis le marqueur ; devant une rotation complète, l'appareil perdant ne pousse plus rien, son rebase rend `IntegrityError::RotationOvertaken` (nouvelle variante en fin d'enum, à la place de `ParamsEpochJump`), il abandonne son contenu en attente et son marqueur - deux rotations concurrentes laissaient des paramètres d'une identité et un contenu signé par l'autre, illisibles pour tous - les écritures faites sur l'appareil perdant depuis sa rotation sont perdues.
- Ruling K20 (constat 4): suivre une rotation (`unlock_after_rotation` sur un appareil épinglé) demande un magasin qui retient les clés utilisées et les identités quittées (`RecordStore::keeps_known_keys`, seul `SyncStore`) ; ailleurs, erreur explicite `InvalidFormat` - la CLI et le magasin en mémoire ne peuvent pas prouver P2 - la CLI de développement ne suit pas de rotation (elle n'a qu'un appareil).

## 12. Suites (hors de cette branche)

- Swift (VaultKit et app) : boucle de sync qui repousse tant qu'il reste des changements (la rotation part en deux envois) ; `unlock_after_rotation` sans clé précédente (l'appareil retient les clés connues) ; `take_password_change_overtaken` dans le texte du kit ; `revokeDevice` sur `revoke_device_rotating` ; option "Faire aussi tourner les clés" dans le changement de mot de passe ; "Faire tourner les clés" dans Réglages > Sécurité ; Secret Key en attente dans le Keychain avant l'appel (K6) ; nouvel Emergency Kit affiché et confirmé ; à l'ouverture, `store_keys_rotated` puis saisie de la nouvelle Secret Key et `unlock_after_rotation` ; synchronisation complète avant et après.
- Clés propres à chaque appareil (KEM hybride dans la liste des appareils) pour une livraison scellée de la nouvelle Secret Key, si le réappairage s'avère trop lourd.
- Archives : garder les anciennes clés KEM dans le keyset pour ouvrir les archives d'avant la rotation, ou rechiffrer les sauvegardes.
- Ordre d'envoi de `SyncStore` : paramètres et keyset en dernier lors d'une rotation.
- Modèle ProVerif de la rotation.
