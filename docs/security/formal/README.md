# OnePass : modèle formel du protocole

Ce document décrit les modèles ProVerif de OnePass, ce qu'ils prouvent, comment ils ont été construits à partir du code, et ce qu'ils ne prouvent pas. Spec : [`docs/superpowers/specs/2026-10-26-formal-model-design.md`](../../superpowers/specs/2026-10-26-formal-model-design.md). Modèles : [`formal/`](../../../formal/). Derniers résultats : [`results.md`](results.md) (généré par `make formal`, ne pas modifier à la main).

Le modèle est symbolique (Dolev-Yao) : les primitives sont idéales, l'attaquant contrôle le réseau et le stockage, et ProVerif cherche une trace qui viole chaque propriété pour un nombre non borné de sessions. Un résultat « vrai » est une preuve dans ce modèle, pas une borne de sécurité calculatoire (section 10).

## 1. Outil et version

- **ProVerif 2.05** (Blanchet, Cheval, Sylvestre). Ruling F-01 de la spec : preuves automatiques de secret et d'authentification pour un nombre non borné de sessions, entiers naturels et requêtes temporelles (utiles au retour en arrière des manifestes). Tamarin a été écarté (Maude et une chaîne Haskell absentes de Homebrew, lemmes d'état souvent écrits à la main).
- Bibliothèque commune `formal/proverif/common.pvl` (types, AEAD, HKDF, Argon2, signatures, KEM hybride), plus une bibliothèque par construction : `account_core.pvl` (compte, coffres, items, partagée par `account*.pv` et `emergency_kit.pv`), `bridge_core.pvl` (pont, partagée par `bridge*.pv`). Un modèle charge une bibliothèque supplémentaire par une ligne exacte `(* formal-lib: nom.pvl *)`, cherchée dans tout le fichier.
- Chaque processus cite en commentaire le fichier et la fonction Rust (et, pour le pont, TypeScript) qu'il représente.

## 2. Lancer

```sh
make formal                         # tous les modèles, comparés à formal/expected.txt
formal/run.sh formal/proverif/bridge.pv   # un seul modèle (n'écrit pas results.md)
```

`formal/run.sh` lance chaque `formal/proverif/*.pv` avec un délai de 300 s par fichier, lit chaque ligne `RESULT` de ProVerif et la compare à `formal/expected.txt` (`fichier.pv | requête telle qu'imprimée | true|false`). La commande échoue sur tout écart : résultat différent, « cannot be proved », délai dépassé, erreur de ProVerif, requête absente d'`expected.txt`, ligne attendue sans résultat, modèle nommé dans `expected.txt` qui n'a pas tourné. Variables : `PROVERIF` (binaire, par défaut `proverif` dans le `PATH`, puis `~/.local/bin/proverif`), `FORMAL_TIMEOUT` (secondes entières, 300 par défaut). Journaux de ProVerif dans `formal/out/` (ignoré par git) ; seul un lancement complet réécrit `docs/security/formal/results.md`.

Temps mesurés sur le Mac du fondateur : `emergency_kit.pv` de 35 à 120 s selon la charge, `manifest.pv` environ 40 s, `bridge.pv` environ 17 s, les autres quelques secondes. Total : 2 à 3 minutes.

### Installer ProVerif 2.05

**macOS, dans l'espace utilisateur** (sans opam, ruling F-04) :

```sh
brew install ocaml
curl -LO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05
./build -nointeract            # sans l'interface graphique (lablgtk)
mkdir -p ~/.local/bin && cp proverif ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
proverif -help | head -n 1     # Proverif 2.05. ...
```

**Linux, par opam** (chemin officiel, utilisé par le CI) :

```sh
opam install proverif.2.05 -y
opam exec -- make formal
```

### CI optionnel

`.github/workflows/formal.yml` : déclenché à la main (`workflow_dispatch`) et sur `push` / `pull_request` qui touchent `formal/**`, `Makefile` ou le workflow lui-même. `ubuntu-latest`, `ocaml/setup-ocaml@v3` (OCaml 4.14), `opam install proverif.2.05 -y`, puis `opam exec -- make formal` (le `bin` du switch opam en tête du `PATH`). En cas d'échec, `formal/out` (journaux de ProVerif) est publié comme artefact. Le CI n'est pas obligatoire pour fusionner : il ne se lance pas sur les changements du code seul.

## 3. Modèle d'attaquant et hypothèses

- **Stockage et réseau publics.** CloudKit, serveur, disque partagé et réseau sont le canal public `c` : l'attaquant lit, supprime, rejoue, réordonne et forge. Paramètres du compte, keyset scellé, enveloppes KEM, méta de coffre, manifestes signés, items, messages du pont : tout passe par `c`. Aucun canal privé, sauf ceux justifiés ci-dessous.
- **Canal native messaging public.** Tout processus local peut parler à l'hôte natif ou le lancer ; un hôte remplacé peut parler à l'extension. Les processus hôte acceptent n'importe quel nombre de `pair_hello` et de `hello`.
- **Canaux privés justifiés.** L'état local de l'appareil (Secret Key, mot de passe saisi, épingle du compte, `last_seen`) est passé en paramètre de processus ; la Secret Key lue dans le kit (QR ou saisie) et le mot de passe tapé sont des entrées privées de l'utilisateur vers l'appareil ; la comparaison du code SAS est un canal hors bande authentifié (section 4.3).
- **Primitives idéales.** AEAD avec engagement de clé, signatures EUF-CMA (les signatures hybrides ML-DSA-87 + Ed25519 comme une seule signature idéale ; `getmess` donne le message signé à l'attaquant), hachage et HKDF à sens unique, KEM IND-CCA. Chaque moitié du KEM hybride (ML-KEM-1024, X25519) est un KEM idéal indépendant.
- **Mot de passe.** Argon2id est une fonction à sens unique sur un secret de faible entropie : le mot de passe est déclaré `weaksecret` (ProVerif cherche alors une attaque par dictionnaire hors ligne, c'est-à-dire un terme qui permet de tester une supposition).
- **Hôte natif en mode `file`.** Un attaquant local ne peut ni lire ni écrire le dossier de données de l'hôte (`pending-pairing.json`, `pairing-approved`, `pairings.json`). Celui qui écrit `pairing-approved` approuve son propre appairage, celui qui lit `pairings.json` détient une clé d'appairage : les deux cas sont des enregistrements corrompus du modèle (section 4.3), hors de P10 à P15.
- **Un processus par état d'appareil.** `DeviceState` (épingle, `last_seen`) est une valeur linéaire par appareil : chaque opération lit la valeur courante et la remplace. Le code le garantit par la persistance après chaque opération réussie, lectures comprises (`onepass-ffi/src/session.rs` `Session::with`, `onepass-cli/src/session.rs` `save_after`, et l'hôte natif depuis les commits 80950ee et 9924d64, section 8). Deux processus qui écriraient le même état sans fusion sortent du modèle.
- **Hors modèle** : canaux auxiliaires, mémoire du processus, appareil compromis, Secure Enclave (l'AUK enveloppée est traitée comme l'AUK, stockée sur un appareil de confiance), comportement de l'utilisateur au-delà de la comparaison SAS et de la saisie du mot de passe.

## 4. Abstractions

Chaque abstraction est soit une sur-approximation (l'attaquant a plus de pouvoir que dans le code, donc une preuve reste valable), soit une borne justifiée sur le papier. Les écarts du sens inverse (modèle plus fort que le code) sont listés en section 8.

### 4.1 Primitives (`common.pvl`)

- **AEAD déterministe.** Le nonce aléatoire de AES-256-GCM-SIV n'est pas modélisé : `aead_seal(k, ad, m)` est un constructeur, `aead_open` ne réussit qu'avec la clé et l'AAD exactes. Le compteur qui forme le nonce du canal du pont est gardé dans l'AAD, ce qui conserve la propriété qu'il porte (P14).
- **AEAD avec engagement de clé.** Une seule clé ouvre un chiffré (`aead.rs`, engagement HMAC). P5 et P1 en dépendent : un coffre n'est accepté que si son manifeste signé s'ouvre avec la clé reçue.
- **AES-256-GCM du pont modélisé par le même AEAD avec engagement.** GCM n'engage pas la clé ; symboliquement c'est sans effet (une clé ne s'obtient que par la dérivation), mais un argument calculatoire devrait le traiter à part.
- **Échecs du KEM.** Le rejet implicite de ML-KEM (une clé pseudo-aléatoire au lieu d'une erreur) et un X25519 dont la clé éphémère ne correspond pas sont modélisés comme un échec de déchiffrement : la clé obtenue serait de toute façon inconnue de l'attaquant et sans usage, l'AEAD qui suit échoue.
- **Combineurs.** Celui du `core` (`kem.rs`, `combine` : HKDF sur `ss_m, ss_x, ct_m, eph, pk_x` avec `(libellé, contexte)`) et celui du pont (HKDF avec le sel `onepass/bridge/kem/v1`, IKM `ss_m || ss_x`, info = hachage du chiffré) sont modélisés à part. `wrap_key` (libellé et contexte concaténés sans cadre) et `wrap_key_labeled` (préfixés par leur longueur) deviennent tous deux la paire `(libellé, contexte)` : ils restent distingués par l'identifiant de blob interne de l'AAD.
- **Encodages.** En-têtes de blob, padding, postcard, JSON du pont et transcript du pont sont des constructeurs injectifs (pas d'ambiguïté d'encodage). Leur correction est couverte par les tests, les vecteurs croisés et le fuzzing.

### 4.2 Compte, coffres, items (`account_core.pvl`, `account*.pv`, `emergency_kit.pv`)

- **Coûts KDF.** Un seul jeu de paramètres signé par compte, représenté par son sel ; plancher, cliquet (`raise_floor`) et plafond non modélisés. Il n'existe aujourd'hui qu'un jeu signé par compte (pas de changement de mot de passe ni de KDF), donc pas de retour à un jeu plus faible à modéliser.
- **`seq` et `prev_hash` frais dans le modèle du compte.** Le manifeste qu'écrit un appareil (`save_item`) porte un `seq` et un `prev_hash` frais au lieu de `next_seq(seq)` et `h(m)`. Argument : chaîné au manifeste lu dans le stockage, cette étape de signature laisse l'attaquant faire croître des termes sans borne (`next_seq(next_seq(...))`) et le modèle ne termine pas (essayé, plus de 120 s). L'historique (retour en arrière, bifurcation) est la tâche de `manifest.pv` ; ici seuls l'identifiant du coffre et la clé du coffre comptent pour P1 et P5, et ni l'un ni l'autre ne dépend de `seq` ou de `prev_hash`. Les manifestes portent au plus une entrée, la racine de Merkle est repliée dans les entrées, `verify_manifest` tourne avec `last_seen = None`.
- **`new n[vid]`.** Les noms frais de la branche d'écriture ont pour seul argument explicite l'identifiant du coffre : ils dépendent de `vid` et des indices de réplication des sessions englobantes (`CreateAccount`, `Device`), pas des autres entrées lues (paramètres, keyset, enveloppe, manifeste). Sans cela, un manifeste écrit puis relu imbrique des noms dans des noms sans borne. Moins d'arguments fusionne des sessions : sur-approximation valable pour le secret et la correspondance non injective.
- **Lectures groupées.** Les enregistrements d'items arrivent dans la même entrée que leur manifeste ; `save_item` part du manifeste vérifié par la liste des coffres (le code le relit dans `load`, mêmes vérifications) ; le préfixe de 16 octets d'un enregistrement d'item et la vérification `finish_unlock` (identifiant d'enregistrement des paramètres) ne sont pas modélisés.
- **Non modélisés** : `move_item`, `update_vault_meta`, `delete_item`, `unlock_with_auk` (AUK dans le trousseau), sync et rebase, Travel Mode.
- **Restauration.** Après l'épingle, l'appareil restauré continue comme le `Device` épinglé, qui relit les enregistrements du compte dans le stockage (le code garde le compte en mémoire) : le stockage peut les rejouer, l'épingle n'admet que des paramètres signés par l'identité épinglée pour l'identifiant épinglé, donc les états atteignables sont les mêmes ou plus nombreux. Un appareil restaurant par compte, répliqué (tentatives sans limite).

### 4.3 Pont (`bridge_core.pvl`, `bridge*.pv`)

- **SAS = canal hors bande authentifié (ruling F-02).** Chaque côté « affiche » son code en l'insérant dans une table (`ext_screen`, `host_screen`) et en le publiant sur `c` (l'attaquant lit les deux écrans). L'attaquant ne peut pas insérer dans une table : c'est la moitié « non modifiable » du canal authentifié. La comparaison de l'utilisateur est une recherche dans la table avec le code du côté comme clé ; n'importe quel écran de n'importe quelle session peut correspondre (l'utilisateur regarde la mauvaise fenêtre), ce qui est plus fort pour l'attaquant qu'un écran par tentative. Le code du modèle est la sortie HKDF complète, pas sa troncature à 6 chiffres : la borne de collision de 10^-6, et avec elle le rôle de l'engagement, restent un argument papier (spec du jalon 4, 6.4).
- **Découplage des sessions (abstraction compositionnelle).** Le modèle composé (sessions sur la clé d'appairage `PK` dérivée par les processus d'appairage) ne termine pas : avec la fuite de phase 1, ni P11 ni P14 n'aboutissent en 600 s, et P14 seul sans phase non plus en 10 minutes. Les sessions tournent donc sur des enregistrements tirés par `PairingRecord` (une `PK` fraîche et secrète sous un `pairing_id` frais, insérée des deux côtés), et les processus d'appairage émettent `HostPaired` / `ExtConfirm` là où le code enregistre. **Argument de composition**, prouvé dans le même fichier : P10 (la `PK` de chaque appairage terminé est secrète) et P11 (un enregistrement côté hôte n'existe qu'avec une extension qui a confirmé le même `pairing_id`, la même transcription et la même `PK`, et réciproquement, de façon injective). Un appairage terminé donne donc exactement une clé secrète partagée par `pairing_id`, ce que tire `PairingRecord`. Écart non couvert : `PK`, le SAS et `K_c` sortent du même `(T, ss)` sous des libellés HKDF distincts, indépendants dans le modèle symbolique.
- **Enregistrements corrompus.** `! CorruptRecord` tire un `pairing_id` et une `PK` frais, les insère des deux côtés avec le drapeau `cor` et publie les deux. Les événements de session portent le drapeau ; P12 à P15 sont énoncés pour `hon`. Une requête de sanité montre que l'attaquant mène bien des sessions sur un enregistrement corrompu (la restriction à `hon` n'est pas un isolement à vide). Causes réelles d'un enregistrement corrompu : approbation `auto` (refusée en release depuis c63cdfd), approbation `file` écrite par un processus local, profil du navigateur ou `pairings.json` lus.
- **Bornes et détails.** Deux requêtes et deux réponses par session, compteurs constants `ctr0`, `ctr1`, état du canal passé de processus en processus (pas de cellule) ; `check_name`, analyse des clés, délais (120 s, 600 s), limite de 2^32, révocation, contrôle des `id` de requête et enveloppes vides `pair_sas` / `pair_ok` non modélisés (ils ne font qu'interrompre). Confidentialité persistante face à la compromission de `PK` seulement (les secrets KEM éphémères sont effacés et ne fuient jamais en phase 1).

### 4.4 Manifestes (`manifest.pv`)

- **Bornes.** Les écrivains s'arrêtent à `seq = 4` ; chaque appareil fait 3 lectures après son premier usage ou après la création du coffre (`Manifest::next` n'est borné que par `u64::MAX`). **Pourquoi 3 lectures suffisent** : les propriétés d'historique portent sur deux acceptations d'un même appareil (P7, P8) ou sur une lecture et l'état juste avant (chaînage), et deux lectures consécutives témoignent déjà de tout retour en arrière ; comme `never_seen` atteint en `Read1` n'importe quel état, la lecture `k + 1` d'une séquence plus longue est couverte par une séquence de 3 lectures qui commence plus tard. **Pourquoi `seq` jusqu'à 4** : avec 3 seulement, le seul `seq` 1 fait que tout écart se chaîne ; il faut `seq = 4` pour qu'un appareil qui a vu `seq = 2` puisse accepter un `seq = 4` construit sur une bifurcation de 2 (limite de la section 6).
- **Arbre d'écrivains.** Les écrivains honnêtes forment un arbre de signatures enraciné en `seq = 1` : chaque manifeste signé a autant d'enfants qu'on veut (réplication), deux enfants d'un même nœud sont une bifurcation, exactement ce que produisent deux appareils qui chargent le même manifeste et écrivent en même temps (`put_if_version` est vérifié par le stockage, qui est l'attaquant). Un écrivain ne construit que sur un manifeste vérifié sous la clé du compte, donc signé par un écrivain honnête : l'arbre est le même ensemble de manifestes signés, sans entrée de l'attaquant dans les écrivains (la version « appareil qui lit puis écrit » n'a donné aucun résultat en 600 s). La mise à jour de `last_seen` de l'appareil qui écrit n'est pas un événement `Accept`.
- **État de l'appareil passé de lecture en lecture**, pas une cellule privée : une cellule ProVerif n'est pas linéaire (une valeur sortie reste dérivable à jamais), et donnait de faux « cannot be proved » sur P7 et P8 (mutation M9). `set preciseActions = true` est nécessaire (chaque entrée d'une session reçoit une seule valeur). Hypothèse : un processus par état d'appareil (section 3).
- **`check_records` permissif avec un manifeste vide.** Quand le manifeste ne liste aucune entrée, n'importe quel enregistrement servi est accepté sans vérification (événement `no_item`) : l'attaquant est plus fort que dans le code.
- **Version d'item = `seq - 1`** dans toutes les branches (le manifeste de création, `seq = 1`, n'a pas d'entrée ; l'écrivain du `seq = n` écrit la version `n - 1`).
- **Clés de coffre publiques** (attaquant plus fort que le code) : l'intégrité ne repose que sur la signature du compte.
- Un manifeste liste au plus une entrée, un identifiant d'item par coffre (le tri et l'unicité de `check_shape` sont trivialement vrais) ; la racine de Merkle est un hachage idéal de la liste ; `delete_item`, `move_item`, corbeille, archive, règles d'écriture interrompue et de restes tolérés de `load`, sync et rebase non modélisés.

## 5. Propriétés P1 à P18

« vrai » : la propriété est prouvée (ProVerif imprime `is true`). Texte exact des requêtes dans [`results.md`](results.md) et `formal/expected.txt`. Toutes les valeurs obtenues égalent les valeurs attendues.

| # | Modèle | Requête (forme abrégée) | Attendu | Obtenu | Sens |
| --- | --- | --- | --- | --- | --- |
| P1 | `account.pv`, variantes ML-KEM et X25519 cassées | `not (VaultCreated(acct_main,...,k) && attacker(k))`, `not (ItemSealed(acct_main,m) && attacker(m))` | vrai | vrai | Les clés de coffre et le contenu des items, y compris ceux qu'écrit un appareil, restent secrets face au stockage, même si une des deux moitiés du KEM est cassée. |
| P2 | `account.pv` | `not (AukCreated(acct_sk_leaked,k) && attacker(k))`, idem `acct_pw_leaked`, `acct_main` | vrai | vrai | L'AUK reste secrète si l'attaquant a la Secret Key ou le mot de passe, pas les deux (avec la Secret Key seule, pour un mot de passe fort : section 6). |
| P3 | `account.pv` | `Weak secret pw_main` | vrai | vrai | Sans la Secret Key, rien de ce que voit le stockage ne permet de tester un mot de passe hors ligne. |
| P4 | `account.pv` | `ParamsAccepted(...) ==> ParamsSigned(...)` | vrai | vrai | Un appareil épinglé n'accepte que des paramètres signés par l'identité épinglée. |
| P5 | `account.pv`, variantes | `VaultAccepted(t,s,v,k) ==> VaultCreated(t,s,v,k)` | vrai | vrai | Une clé de coffre substituée par le stockage n'est jamais acceptée : le manifeste signé doit s'ouvrir avec la clé reçue. |
| P6 | `manifest.pv` | `Accept(d,v,n,mh,e) ==> Signed(v,n,p,mh,e)` | vrai | vrai | Tout manifeste accepté a été signé par un appareil du compte, pour ce coffre, avec ce `seq` et ces entrées. |
| P7 | `manifest.pv` | `Accept(d,v,n,...)@i && Accept(d,v,m,...)@j ==> i > j \|\| m ≥ n` | vrai | vrai | Pas de retour en arrière : après avoir accepté `seq = n`, l'appareil n'accepte plus de `seq` inférieur pour ce coffre. |
| P8 | `manifest.pv` | `Accept(d,v,n,h1,...) && Accept(d,v,n,h2,...) ==> h1 = h2` ; chaînage `Fetched(d,v,seen(n,h0),n + 1,mh) ==> Signed(v,n + 1,h0,mh,e)` | vrai | vrai | Pas de bifurcation : jamais deux manifestes différents acceptés au même `seq` par un appareil, et le `seq` suivant lu se chaîne au manifeste vu. |
| P9 | `manifest.pv` | `ItemAccepted(d,v,one_entry(i,ver,rh)) ==> Accept(d,v,n,mh,one_entry(i,ver,rh))` | vrai | vrai | Un item accepté figure, avec la même version et le même hash, dans un manifeste que l'appareil a accepté. |
| P10 | `bridge.pv`, variantes | `not (HostPaired(p,t,k) && attacker(k))`, idem `ExtConfirm` | vrai | vrai | La clé d'appairage `PK` reste secrète des deux côtés, même avec une moitié du KEM cassée. |
| P11 | `bridge.pv` | `inj-event(ExtConfirm(p,t,k)) ==> inj-event(HostDone(p,t,k))` et `HostPaired ==> ExtConfirm` | vrai | vrai | Après la comparaison SAS, extension et hôte s'accordent, une session pour une, sur `pairing_id`, transcription et `PK`. |
| P12 | `bridge.pv`, variantes | `not (SessionKey(hon,r,s,k) && attacker(k))`, `not (AppMsg(hon,m) && attacker(m))` | vrai | vrai | Clés de session et messages applicatifs secrets. |
| P13 | `bridge.pv`, variantes | mêmes requêtes avec `attacker_p1` | vrai | vrai | Confidentialité persistante : une session terminée reste secrète si `PK` fuit ensuite (phase 1). |
| P14 | `bridge.pv` | `inj-event(HostRecv(hon,s,d,n,m)) ==> inj-event(ExtSend(hon,s,d,n,m))` et sens inverse | vrai | vrai | Chaque message applicatif reçu a été envoyé par le pair, une fois, avec ce `session_id`, ce sens et ce compteur (pas de rejeu ni de réflexion). |
| P15 | `bridge.pv` | `HostServe(hon,p,k,s,m) ==> ExtFinish(hon,p,k,s)` | vrai | vrai | L'hôte ne sert une requête qu'à un pair qui a fini la poignée de main avec `PK`. |
| P16 | `emergency_kit.pv` | `not (VaultCreated(acct_main,...) && attacker(k))`, `not (ItemSealed(acct_main\|restore_main,m) && attacker(m))`, `VaultAccepted(restore_main,...) ==> VaultCreated(acct_main,...)`, `ItemRead(restore_main,...) ==> ItemSealed(acct_main,m) \|\| ItemSealed(restore_main,m)` | vrai | vrai | Restauration par kit sur un stockage hostile : clés et items du vrai compte secrets, seules les vraies clés de coffre sont acceptées, seuls les vrais items sont affichés. |
| P17 | `emergency_kit.pv` | `not (ItemSealed(acct_kit_lost\|restore_kit_lost,m) && attacker(m))`, `not (AukCreated(acct_kit_lost,k) && attacker(k))`, `Pinned(restore_kit_lost,a,i) ==> AccountOwned(acct_kit_lost,a,i)` | vrai | vrai | Kit perdu (Secret Key publique), mot de passe fort : items et AUK restent secrets, l'appareil n'épingle que le compte de l'utilisateur. |
| P18 | `emergency_kit.pv` | `Pinned(restore_main,a,i) ==> AccountOwned(acct_main,a,i)` | vrai | vrai | Au premier usage, l'appareil n'épingle que le compte de l'utilisateur tant qu'un des deux facteurs reste secret (2SKD : le keyset doit s'ouvrir sous l'AUK). |

Requêtes vraies complémentaires : `Weak secret pw_main` dans `emergency_kit.pv` (le sel choisi par le stockage ne donne aucun test hors ligne) et `Weak secret pw_no_keyset` (Secret Key publique sans vrai keyset dans le stockage : la dérivation sur un sel de l'attaquant n'offre aucun test hors ligne).

**Sanité.** Chaque chemin principal a une requête d'atteignabilité dont le résultat attendu et obtenu est « attaque trouvée » (`A trace has been found`) : déverrouillage de chaque compte, coffre listé, item lu, item écrit (`account*.pv`) ; bifurcation signée, lecture du suivant, d'un écart, du même `seq`, du suivant après 2, item accepté (`manifest.pv`) ; appairage des deux côtés, session ouverte, deuxième requête et deuxième réponse, fuite de `PK` en phase 1, session sur un enregistrement corrompu (`bridge*.pv`) ; épingle, coffre listé, item lu et écrit à la restauration, épingle et écriture d'un item kit perdu, AUK dérivée sans vrai keyset (`emergency_kit.pv`) ; primitives et harnais (`sanity.pv`). Aucune propriété ne passe à vide.

## 6. Requêtes à attaque attendue et limites documentées (ruling F-03)

Une requête dont le résultat attendu est « faux » n'est permise que pour la sanité et pour une limite déjà documentée. Elle montre ce que OnePass ne garantit pas.

1. **Mot de passe faible une fois la Secret Key connue** (`account.pv`, `Weak secret pw_sk_leaked` ; `emergency_kit.pv`, `Weak secret pw_kit_lost`). Avec la Secret Key, le keyset scellé est un vérificateur : l'attaquant teste chaque mot de passe hors ligne. P2 (attaquant avec la Secret Key) et P17 ne valent donc que pour un mot de passe fort ; le coût Argon2id (section 10) est la seule défense. Documenté en spec section 3 et dans `docs/security/README.md` section 1.
2. **Écart de plus d'un `seq` accepté sans chaînage** (`manifest.pv`, `Fetched(d,v,seen(2,h0),4,mh) ==> Signed(v,4,p,mh,e) && Signed(v,3,h0,p,e3)`). `verify_manifest` (`manifest.rs:227-240`) refuse un `seq` plus ancien et exige le chaînage pour `seq + 1`, mais accepte un écart plus grand sans vérifier l'ascendance : un appareil qui a vu `seq = 2` accepte un `seq = 4` construit sur une bifurcation de 2. Tous les manifestes restent signés par le compte (P6) et l'appareil ne recule jamais (P7). Documenté dans `docs/security/README.md` section 3.7.
3. **P18 avec les deux facteurs connus** (`emergency_kit.pv`, `Pinned(restore_kit_pw,a,i) ==> AccountOwned(acct_kit_pw,a,i)` et `ItemRead(restore_kit_pw,...) ==> ...`). Quand le mot de passe et la Secret Key sont connus (kit perdu avec le mot de passe écrit à la main dessus, ou Secret Key fuitée puis mot de passe trouvé hors ligne par la limite 1), un stockage hostile au premier usage fait épingler un compte de l'attaquant : l'appareil affiche son coffre et ses items, et ce que l'utilisateur enregistre part vers le compte de l'attaquant (qui pouvait de toute façon déjà lire le vrai compte). Avec un seul facteur connu, P18 et P17 sont vrais : la confiance au premier usage est protégée par 2SKD. La spec prévoyait l'attaque sans condition ; le modèle et le code (`repo.rs:282`, l'épingle n'est posée qu'après l'ouverture du keyset, et l'étape 5 de `open_keyset`, `account.rs:301-306`, interdit de mélanger le vrai keyset et de faux paramètres) l'ont corrigée.

## 7. Mutations

Chaque propriété a été vérifiée non vide en cassant à la main, sur une copie, la vérification du code qui la porte, puis en relançant le modèle (copies non commitées).

**`account.pv`**

| Mutation | Requêtes qui tombent |
| --- | --- |
| Les deux moitiés du KEM publiées | P1 (les deux requêtes) : les variantes à une moitié ne sont pas à vide |
| Secret Key et mot de passe de `acct_sk_leaked` publiés | P2 de ce compte |
| `Device` sans vérification de la signature du manifeste, ou sans ouverture du manifeste avec la clé reçue | P5, et P1 sur les items (l'appareil écrit sous la clé de l'attaquant) |
| `Device` sans vérification de l'épingle | P4 |

**`manifest.pv`**

| Mutation | Requêtes qui tombent |
| --- | --- |
| M1 `seq` plus ancien accepté | P7, P8 |
| M2 même `seq` sans égalité des hash | P8 seul |
| M3 `seq` suivant sans vérification de `prev_hash` | P8 chaînage seul |
| M4 pas de vérification de signature | P6, P7, P8 chaînage |
| M5 `check_records` sans le hash de l'enregistrement | P9 seul |
| M6 pas de vérification de l'identifiant de coffre décodé | aucune (redondant avec l'AAD et la clé de coffre, défense en profondeur) |
| M7 état non gardé entre deux lectures | P7, P8 : les requêtes dépendent de la persistance de `last_seen` |
| M9 cellule privée au lieu de l'état passé en paramètre | P7, P8, P8 chaînage « cannot be proved » (dérivation parasite, section 4.4) |

**`bridge.pv`**

| Mutation | Requêtes qui tombent |
| --- | --- |
| M1 l'hôte ne vérifie pas l'engagement | aucune (rôle probabiliste, F-02) |
| M2 l'extension ne vérifie pas le MAC de `pair_done` | P11 extension vers hôte |
| M3 l'hôte ne vérifie pas le MAC de `pair_confirm` | P11 hôte vers extension |
| M4 aucune comparaison SAS | P10 (deux côtés), P11 (deux sens) |
| M4a pas de comparaison côté hôte (= approbation `auto`) | P10 hôte, P11 hôte vers extension |
| M4b pas de comparaison côté extension | P10 extension, P11 extension vers hôte |
| M5 `PK` retirée de l'IKM de session | P12, P13, P14, P15 |
| M6 l'extension ne vérifie pas le MAC de `welcome` | P13 |
| M7 l'hôte ne vérifie pas le MAC de `finish` | P13 clés |
| M8 compteur retiré de l'AAD (rejoué sur P14 seul, 66 s) | P14 hôte vers extension faux (réponse rejouée au compteur 1), P14 extension vers hôte « cannot be proved » |
| M8b l'hôte n'avance pas son compteur de réception | P14 extension vers hôte |
| M9 une clé pour les deux sens, sens absent de l'AAD | P14 hôte vers extension faux, P14 extension vers hôte « cannot be proved » |
| M10 les deux moitiés du KEM publiées (variante ML-KEM) | P10, P13 : les variantes ne sont pas à vide |
| M11 `ss_e` retiré de l'IKM de session | P13 |
| M12 clés de session tirées de `PK` seule, sans `session_id` dans l'AAD | P13, P14 |
| M13 pas de vérification du compteur de la trame (`msg.c`) | aucune (redondant avec le compteur dans l'AAD et le nonce) |

**`emergency_kit.pv`**

| Mutation | Requêtes qui tombent |
| --- | --- |
| M1 épingle posée avant l'ouverture du keyset | P18, P17 épingle |
| M2 l'appareil publie une valeur de contrôle `h(AUK)` | `Weak secret pw_no_keyset` : la requête n'est pas à vide |
| M4 pas d'étape 5 (clés publiques du keyset contre clés signées) | P18, P17 épingle (vrai keyset sous une identité de l'attaquant) |
| M5 pas de vérification de l'auto-signature au premier usage | aucune (redondant avec l'étape 5 pour la confiance au premier usage) |
| M6 Secret Key et mot de passe de `acct_main` publiés | toutes les requêtes P16, P18, `pw_main` |

**`run.sh`** : un `expected.txt` faux (valeur inversée, ligne absente, ligne en trop, modèle absent), un délai dépassé, un « cannot be proved », une erreur de ProVerif ou une bibliothèque `formal-lib` absente font échouer `make formal` (testé à la main lors de la tâche 1).

## 8. Écarts entre le modèle et le code, décisions

### Corrigés dans le code

1. **Approbation `auto` de l'hôte natif refusée en release** (commit c63cdfd). `approval: auto` approuvait un appairage sans comparaison de code ; la mutation M4a montre que tout processus local qui lance l'hôte avec un identifiant d'extension autorisé s'appaire et obtient une `PK` valide. `core/onepass-native-host/src/main.rs`, `check_build(cfg, release)` refuse désormais `auto` (et la fixture) quand le binaire n'est pas un build debug ; tests `release_build_refuses_auto_approval`, `release_build_refuses_fixture_source`.
2. **État d'appareil de l'hôte natif enregistré après les lectures et jamais régressé** (commits 80950ee et 9924d64). Trouvé par le modèle des manifestes : l'hôte (source `dev`) n'enregistrait `device.bin` qu'après une écriture, et chargeait l'état une fois pour le réécrire de mémoire, ce qui pouvait faire reculer `last_seen` écrit par la CLI. Correctif additif dans `core/onepass-native-host/src/vault.rs` : relecture sous verrou avant chaque opération (`Refresh`), enregistrement après chaque lecture, fusion par coffre gardant le `seq` le plus haut (bifurcation au même `seq` et épingle d'un autre compte refusées). Tests `dev_reads_persist_device_state`, `dev_host_never_regresses_a_cli_advance`, `dev_rollback_after_a_host_read_is_refused`, `dev_host_refreshes_device_state_before_each_operation`, et tests unitaires de `merge_device`. Limites acceptées : `status` et `vaults` ne relisent pas (peuvent être en retard, n'écrivent jamais) ; une écriture qui échoue après sa relecture n'enregistre pas, la requête suivante le fait.

### Documentés (pas de changement du code)

3. **FFI : état non enregistré sur erreur** (info). `onepass-ffi/src/session.rs:55-59` saute `persist_device_state` si l'opération échoue, alors qu'elle a pu déjà faire avancer `last_seen` en mémoire (`move_item` valide le manifeste cible avant d'échouer sur la source). L'état en mémoire est enregistré au succès suivant ; seul un plantage entre les deux le perd (l'appareil réaccepte alors une fois son propre manifeste précédent).
4. **`reset_for_recovery` efface `last_seen`** (faible). Après « Le compte a disparu » et une restauration par kit, `reset_for_recovery` (`sync/store.rs`) vide tout l'état de l'appareil : chaque coffre repasse au premier usage (un ancien manifeste signé, ou un coffre jamais lu et masqué, est accepté une fois). Couvert par `docs/security/README.md` 10.6 et section 1, et par le départ `never_seen` de `manifest.pv`.
5. **Délai de l'offre vérifié côté TypeScript seulement** (info). `ExtPairing::offer_with` (`core/onepass-bridge/src/pairing.rs`) ne vérifie pas le délai de 120 s, contrairement aux autres étapes ; le jumeau TypeScript le vérifie (`extension/src/bridge/pairing.ts`, `this.take()`). Les délais ne sont pas modélisés.
6. **Paire KEM d'appairage de l'extension** (info). Elle ne sert jamais à décapsuler : `pk_E` n'est qu'une valeur engagée dans la transcription (la spec du jalon 4, 6.4, parle de paire KEM). Sans effet de sécurité.
7. **Identifiant du compte imprimé sur le kit jamais comparé** (info). `EmergencyKit.swift` imprime l'identifiant, la restauration (`OnboardingFlow.swift`) ne le compare pas à celui du stockage. Sans effet : l'attaquant peut réutiliser l'identifiant public du vrai compte, et 2SKD lie déjà le compte (P18).
8. **Supposition en ligne pendant une restauration** (info). Un attaquant qui connaît la Secret Key peut servir un keyset scellé sous un mot de passe supposé et observer si l'appareil continue (écrit dans le stockage) : une supposition par restauration lancée par l'utilisateur, l'échec s'affichant comme un faux « mot de passe incorrect ». Le compteur d'essais de la section 10.1 ne ralentit pas cet attaquant ; ce canal est dominé par la vérification hors ligne avec le vrai keyset (limite 1 de la section 6), strictement pire, donc aucune mesure de plus.
9. **Oracle `Signature` contre `WrongPassword` sur un appareil épinglé** (info). Même oracle : un stockage qui sert des paramètres et un keyset construits sur une supposition voit l'appareil afficher l'écran « Données refusées » (`Signature`, le keyset s'ouvre mais ne correspond pas) ou « mot de passe incorrect » (`WrongPassword`). Une supposition par déverrouillage, dominée par l'attaque hors ligne dès que la Secret Key est connue ; sans la Secret Key, rien à tester (P3).
10. **Redondances** (info, défense en profondeur). L'engagement de l'appairage n'a pas d'effet symbolique (M1, il protège la borne 10^-6) ; le MAC de `finish` et celui de `welcome` ne servent qu'à P13 (M6, M7) ; le contrôle du compteur de trame (M13), l'identifiant de coffre décodé (M6 des manifestes), la version à côté du hash de l'enregistrement (`manifest.rs:259`) et l'auto-signature au premier usage (M5 du kit) sont redondants.
11. **Détection de bifurcation par appareil** (info). P8 est par appareil : deux appareils peuvent accepter chacun une branche différente au même `seq`. Le rebase de la sync (README 10.6) vérifie le chaînage avec l'ancêtre gardé.

Aucun bug trouvé dans `core/onepass-core` ni `core/onepass-bridge`. Le modèle suit l'ordre de vérification du code (signature puis épingle des paramètres ; engagement avant décapsulation ; MAC avant canal ; signature, ouverture, décodage, racine, historique pour les manifestes). Modèle plus fort que le code : le SAS du modèle est la sortie HKDF complète (F-02) ; AES-GCM du pont modélisé avec engagement (section 4.1). Aucun autre écart dans ce sens.

## 9. Ce qui est prouvé

Dans le modèle symbolique, pour un nombre non borné de sessions (sauf les bornes de la section 4.4 pour les manifestes et de la section 4.3 pour le canal), avec un stockage et un canal native messaging entièrement hostiles : P1 à P18 tels qu'énoncés en section 5, y compris le secret des clés et des items quand une des deux moitiés du KEM hybride est cassée (variantes `*_kem_mlkem_broken.pv`, `*_kem_x25519_broken.pv`, où la moitié livrée est réellement publiée sur `c`).

## 10. Ce qui n'est pas prouvé

- **Bornes probabilistes.** Le modèle symbolique n'a pas de probabilités : la borne de collision du SAS à 6 chiffres (10^-6 par tentative, chaque tentative demandant une action de l'utilisateur) et le rôle de l'engagement qui la rend uniforme restent un argument papier (spec du jalon 4, 6.4 ; F-02). Idem pour les tailles de clés, la sécurité des KEM et des signatures, et toute réduction.
- **Solidité calculatoire.** Pas de preuve que le modèle symbolique est fidèle aux primitives réelles (pas de CryptoVerif ni d'EasyCrypt). En particulier AES-GCM n'engage pas la clé, ML-KEM rejette implicitement, X25519 n'est pas un KEM au sens strict (section 4.1).
- **Canaux auxiliaires** : temps, cache, mémoire du processus, effacement des secrets, journaux.
- **Encodages et padding** : postcard, JSON, en-têtes de blob, paliers de padding, transcript du pont sont supposés injectifs ; leur correction relève des tests, des vecteurs croisés et du fuzzing.
- **Concurrence et restes tolérés** : écritures concurrentes, `put_if_version`, écritures interrompues et restes tolérés par `load` (`docs/security/README.md` 3.7), sync et rebase, Travel Mode.
- **Politique de divulgation du jalon 4** : correspondance d'origine, `ctx`, limite de débit, `reprompt`, journal d'audit. Le modèle s'arrête au canal authentifié.
- **Coût d'Argon2id** : la résistance d'un mot de passe faible une fois la Secret Key connue dépend des paramètres (`m = 256 MiB`, `t = 4`, `p = 4`) et de l'entropie du mot de passe, hors du modèle (section 6, limite 1). Plancher, cliquet et plafond KDF non modélisés.
- **Appareil compromis, Secure Enclave, comportement de l'utilisateur** au-delà de la comparaison SAS et de la saisie du mot de passe ; profil du navigateur ou dossier de l'hôte lus (enregistrements corrompus).
- **Opérations non modélisées** : `move_item`, `update_vault_meta`, `delete_item`, corbeille, archive, `unlock_with_auk`, révocation d'un appairage, délais et expirations.
