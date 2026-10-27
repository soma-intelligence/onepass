# OnePass : modèle formel du protocole

Date : 2026-10-26
Statut : approuvée (auto-approbation, sur consigne du fondateur relayée par le contrôleur)
Références : `docs/security/README.md` (sections 1 à 3, 10, 12), spec d'architecture (sections 4.1 à 4.4, 6.3, 12), spec du jalon 4 (section 6).

## 1. Objectif

Vérifier par un outil automatique, dans le modèle symbolique (Dolev-Yao), les propriétés de sécurité que le code revendique, pour les cinq constructions suivantes :

1. la dérivation 2SKD (mot de passe maître, Argon2id, Secret Key, HKDF vers l'AUK) et le keyset scellé ;
2. l'enveloppe des clés de coffre (KEM hybride ML-KEM-1024 + X25519) et le chiffrement des items ;
3. les manifestes signés, avec détection du retour en arrière et de la bifurcation ;
4. le protocole du pont entre l'extension et l'app (jalon 4) : appairage, session, canal ;
5. la restauration par Emergency Kit sur un nouvel appareil.

Le modèle est tiré du code réel (`core/onepass-core`, `core/onepass-bridge`) et de `docs/security/README.md`. Tout écart entre le modèle et le code est tranché (section 7).

## 2. Outil

Ruling F-01 : ProVerif 2.05, construit depuis les sources dans l'espace utilisateur (OCaml via Homebrew) - ProVerif prouve secret et authentification pour un nombre non borné de sessions sans aide manuelle, gère les entiers naturels et les requêtes temporelles nécessaires au retour en arrière ; Tamarin demande Maude et une chaîne Haskell absentes de Homebrew sans dépôt tiers, et ses preuves d'état demandent souvent des lemmes écrits à la main - coût si faux : la propriété de non-retour en arrière, très liée à l'état, peut demander une abstraction (état de l'appareil passé de version en version par une cellule privée) moins fidèle que les règles multiset de Tamarin.

## 3. Modèle d'attaquant et hypothèses

- Le stockage (CloudKit, serveur, disque) et le réseau sont un canal public : l'attaquant lit, supprime, rejoue, réordonne, forge.
- Le canal native messaging et les messages entre extension et app sont publics : un processus local peut parler à l'hôte, un hôte remplacé peut parler à l'extension.
- Primitives idéales : AEAD (avec engagement de clé), signatures EUF-CMA, hachage et HKDF comme fonctions à sens unique, KEM IND-CCA.
- KEM hybride : chaque moitié (ML-KEM, X25519) est un KEM idéal. Pour la propriété « casser un seul des deux ne suffit pas », chaque modèle concerné est lancé en deux variantes où l'attaquant obtient le secret d'une des deux moitiés.
- Argon2id : fonction à sens unique sur un mot de passe de faible entropie. Le mot de passe est modélisé comme un secret « faible » (`weaksecret` de ProVerif, attaque par dictionnaire hors ligne) quand la Secret Key fuit, et comme un secret ordinaire sinon.
- Le code SAS à 6 chiffres est comparé par l'utilisateur : canal hors bande authentifié (lu par l'attaquant, non modifiable). Ruling F-02 : comparaison SAS = canal authentifié hors bande - le modèle symbolique ne sait pas exprimer une probabilité de collision de 10^-6, c'est l'abstraction usuelle pour les protocoles à comparaison de code - coût si faux : la borne probabiliste reste un argument papier (spec du jalon 4, 6.4).
- Hors modèle : canaux auxiliaires, mémoire du processus, appareil compromis, comportement de l'utilisateur au-delà de la comparaison SAS et de la saisie du mot de passe, Secure Enclave (l'AUK enveloppée est traitée comme l'AUK elle-même, stockée sur un appareil de confiance).

## 4. Modèles

Un fichier `.pv` par construction, une bibliothèque commune `formal/proverif/common.pvl` (types, primitives, KEM hybride, AEAD, signatures, HKDF). Chaque modèle contient au moins une requête de **sanité** (le protocole peut aller au bout : `query event(Fin) ` attendu faux au sens « non atteignable » = l'attaque trouvée prouve l'atteignabilité) pour qu'aucune preuve ne passe à vide.

| Fichier | Construction | Propriétés |
| --- | --- | --- |
| `account.pv` | 2SKD, paramètres signés par l'identité, épingle, keyset scellé par l'AUK, enveloppe KEM de la clé de coffre, clé d'item, contenu d'item | P1 secret des items et de la clé de coffre face au stockage ; P2 secret de l'AUK si l'attaquant a la Secret Key ou le mot de passe mais pas les deux ; P3 le mot de passe reste un secret faible tant que la Secret Key ne fuit pas ; P4 un appareil épinglé n'accepte que les paramètres signés par l'identité épinglée ; P5 clé de coffre substituée par le stockage jamais acceptée (un coffre n'est accepté que si son manifeste signé s'ouvre avec la clé reçue) |
| `account_kem_mlkem_broken.pv`, `account_kem_x25519_broken.pv` | mêmes processus, une moitié du KEM livrée à l'attaquant | P1 reste vrai |
| `manifest.pv` | manifeste signé (`seq`, `prev_hash`, racine), état de l'appareil (dernier `seq` et hash vus) | P6 authenticité : tout manifeste accepté a été signé par le compte ; P7 pas de retour en arrière : après avoir accepté `seq = n`, l'appareil n'accepte jamais `seq < n` ; P8 pas de bifurcation : jamais deux manifestes différents acceptés pour le même `seq` ; P9 un item accepté figure dans un manifeste accepté avec la même version et le même hash |
| `bridge.pv` | appairage avec engagement et SAS, ouverture de session, canal | P10 secret de la clé d'appairage `PK` ; P11 accord injectif sur `PK` et la transcription entre extension et hôte après comparaison SAS ; P12 secret des clés de session ; P13 confidentialité persistante : les clés d'une session terminée restent secrètes même si `PK` fuit ensuite (phase 1) ; P14 authenticité et non-rejeu des messages applicatifs (correspondance injective sur `(session_id, sens, compteur)`) ; P15 l'hôte ne sert aucun message applicatif à un pair sans `PK` |
| `bridge_kem_*_broken.pv` | une moitié du KEM livrée | P12 et P13 restent vrais |
| `emergency_kit.pv` | nouvel appareil sans épingle, Secret Key lue dans le kit, mot de passe saisi, paramètres lus dans un stockage hostile | P16 secret des items du vrai compte même si le stockage est hostile pendant la restauration ; P17 la Secret Key seule (kit perdu) ne révèle pas les items ; P18 (limite attendue, requête dont l'attaque est le résultat attendu) un stockage hostile au premier usage peut faire épingler un faux compte : documenté comme la confiance au premier usage connue |

Ruling F-03 : une requête dont le résultat attendu est « attaque trouvée » est permise seulement pour les limites déjà documentées (P18) et les requêtes de sanité, et le fichier des résultats attendus le dit - cela montre ce que le modèle ne garantit pas au lieu de le taire - coût si faux : aucun.

## 5. Exécution

- `formal/run.sh` lance chaque modèle avec un délai maximal (300 s par fichier), lit la sortie de ProVerif et compare chaque requête au fichier `formal/expected.txt` (`fichier | requête | true/false`). Tout écart (résultat différent, « cannot be proved », délai dépassé) fait échouer la commande.
- `make formal` à la racine du dépôt appelle `formal/run.sh`.
- Les résultats sont écrits dans `docs/security/formal/` : `results.md` généré (tableau requête, attendu, obtenu, temps) et `README.md` écrit à la main (modèle, hypothèses, abstractions, ce qui est prouvé, ce qui ne l'est pas).
- CI : `.github/workflows/formal.yml`, optionnel (déclenché à la main et sur les chemins `formal/**`), sur `ubuntu-latest`, ProVerif installé par `opam install proverif` (version 2.05 épinglée).

Ruling F-04 : CI sur Ubuntu avec opam, localement construit depuis les sources - opam est le chemin officiel et rapide sous Linux ; sous macOS l'installation par les sources évite d'initialiser opam dans le profil du fondateur - coût si faux : une différence de version, évitée par l'épinglage 2.05.

## 6. Abstractions assumées

- Les entiers (`seq`, compteurs) sont des naturels ProVerif ; l'arbre de Merkle est un hachage de la liste d'entrées (la propriété porte sur l'engagement, pas sur la forme de l'arbre).
- Le padding, les en-têtes de blob et l'encodage postcard sont abstraits par des constructeurs injectifs (pas d'ambiguïté d'encodage) : leur correction est couverte par les tests et le fuzzing, pas par le modèle.
- Les écritures concurrentes et les restes tolérés (section 3.7 du document de sécurité) ne sont pas modélisés.
- La politique de divulgation du jalon 4 (origine, `ctx`) n'est pas modélisée : le modèle s'arrête au canal authentifié.

## 7. Écarts entre le modèle et le code

Chaque écart trouvé est consigné dans `docs/security/formal/README.md` avec sa décision :

- le modèle avait tort : on corrige le modèle ;
- le code a un bug : correctif additif dans `core/` (sans changer d'API existante) avec un test qui échoue avant, puis le modèle est relancé ;
- l'écart est une limite connue : on la documente, avec une requête dont l'attaque est le résultat attendu (F-03).

## 8. Fin

Fini quand `make formal` passe (tous les résultats égaux aux attendus), les résultats et le README sont dans `docs/security/formal/`, le CI optionnel existe, la branche `feat/formal-model` est rebasée sur la `main` locale et revue.

## 9. Rulings

| # | Décision | Pourquoi | Coût si faux |
| --- | --- | --- | --- |
| F-01 | ProVerif 2.05 construit depuis les sources | automatique, sessions non bornées, Tamarin indisponible sans dépôt tiers | abstraction de l'état pour le retour en arrière |
| F-02 | comparaison SAS = canal authentifié hors bande | pas de probabilités dans le modèle symbolique | borne 10^-6 reste un argument papier |
| F-03 | requêtes à attaque attendue seulement pour limites documentées et sanité | montrer ce qui n'est pas garanti | aucun |
| F-04 | CI Ubuntu par opam, version épinglée | chemin officiel sous Linux | écart de version évité par l'épinglage |
