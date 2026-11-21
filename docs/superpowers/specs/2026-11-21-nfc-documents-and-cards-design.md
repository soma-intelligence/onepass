# Pièces d'identité lues par NFC, rendu « document » animé, cartes bancaires par NFC

Date : 2026-11-21. Statut : besoin validé par le fondateur en conversation (lecture des pièces d'identité, beau rendu animé des passeports et cartes FR et US, ajout de carte bancaire par NFC). Spec à relire avant le plan.

## 1. But

Sur l'iPhone, l'utilisateur pose sa pièce d'identité ou sa carte bancaire au dos du téléphone, et OnePass crée l'élément complet, sans saisie :

1. **Passeport et carte d'identité électroniques.** La MRZ (ou le CAN) est lue à la caméra, puis la puce est lue en NFC : identité, dates, numéro, photo officielle. La signature de l'État est vérifiée (authentification passive), et l'élément affiche « Authentifié par la puce ».
2. **Permis et State ID américains.** Pas de puce : le code-barres PDF417 du verso (norme AAMVA) est lu à la caméra.
3. **Rendu « document ».** Chaque passeport, carte d'identité ou permis s'affiche comme un bel objet : livret qui s'ouvre, carte qui se retourne, reflet qui suit l'inclinaison du téléphone. Le rendu est **évocateur, jamais une réplique** (section 4).
4. **Carte bancaire par NFC.** La carte sans contact posée au dos de l'iPhone donne le numéro et l'expiration (EMV). Le CVV reste à saisir.

Succès : avec un passeport français, un passeport américain et une CNI française au format carte, l'utilisateur crée chaque élément en moins de 30 secondes. L'élément porte la photo de la puce et le statut « Authentifié par la puce ». Il s'affiche avec son rendu animé sur l'iPhone, puis sur le Mac après synchro. Un permis californien scanné au verso donne un élément Permis rempli. Une Visa et une Mastercard sans contact donnent un élément Carte bancaire avec le bon numéro, la bonne expiration et le bon réseau. Les tests existants restent verts.

## 2. Existant (exploration 2026-11-21)

- Les types existent dans le noyau (`core/onepass-core/src/model/templates.rs`) : `IdCard` (avec `can_number`, `mrz`, `scan_front`, `scan_back`), `Passport` (avec `mrz`, `passport_type`, `scan`), `DriverLicense`, `CreditCard` (réseau calculé depuis le BIN).
- Les pièces jointes chiffrées existent (`attachment.rs`, champs `file`).
- Le remplissage automatique sait déjà utiliser les champs passeport (`fill_plan`, `PassportNumber`, `PassportExpiry`, etc.), et Travel auto les reprend.
- Le seul scanner caméra est celui de la clé secrète (`apple/App/Onboarding/SecretKeyScanner.swift`, VisionKit). Aucun code NFC, aucun entitlement NFC dans `apple/project.yml`.
- Aucun rendu « document » : les pièces d'identité s'affichent comme une fiche de champs.
- Cible iOS 26 : `NFCTagReaderSession` et `DataScannerViewController` sont disponibles.
- Il existe une app Android (`android/`). Elle n'est pas dans le périmètre, mais tout le décodage va dans le noyau Rust pour qu'elle puisse le reprendre (section 5).

## 3. Hors champ

- Badges d'immeuble, cartes de transport, Vigik, MIFARE Classic (voir la conversation du 2026-11-21 : lecture partielle, réutilisation impossible).
- Émulation de carte (HCE) : OnePass ne présente jamais un document ni une carte à un lecteur.
- Empreintes digitales et iris (DG3, DG4) : protégés par l'EAC, réservés aux États.
- Authentification active et Chip Authentication (prouvent que la puce n'est pas clonée) : phase ultérieure (section 11).
- Lecture NFC sur le Mac (pas de lecteur) et sur Android (phase ultérieure). Le Mac, la Watch et visionOS affichent les éléments et leur rendu.
- Carte Vitale, carte grise, permis français (puces à contact ou non publiques). Le permis français reste en saisie manuelle et OCR.
- Paiement, ajout à Apple Wallet.

## 4. Règle de rendu : évocateur, jamais une réplique

Une reproduction fidèle d'un document officiel peut être qualifiée de faux document (France : article 441-1 du code pénal ; États-Unis : 18 USC 1028, et 18 USC 713 pour le Great Seal). Apple rejette aussi les apps qui imitent des pièces d'État. Règles fermes, vérifiées en revue de design :

**Interdit**
- Emblèmes et sceaux : Marianne, logo RF, armoiries, Great Seal, aigle américain, drapeaux reproduits en motif officiel.
- Motifs de sécurité : guilloches, fonds anti-copie, hologrammes, encres optiquement variables, microtextes, reproduits ou imités de près.
- Mise en page officielle copiée case pour case, polices officielles des documents.
- Export ou impression du rendu (image, PDF, AirDrop). Seuls les champs se partagent, comme aujourd'hui.

**Autorisé**
- Format physique réel : carte ID-1 (85,60 × 53,98 mm), livret TD3 (125 × 88 mm).
- Teintes de couverture évocatrices : bordeaux (passeport FR), bleu marine (passeport US), bleu clair (CNI FR), dégradé neutre (permis US).
- Le nom du pays en texte, le type de document en texte (« Passeport », « Passport »), le symbole générique de puce électronique (ICAO).
- Les vraies données de l'utilisateur et la photo de sa puce.
- Un reflet générique (texture « brossée » de DesignKit), sans motif ni symbole.
- La mention fixe « Copie numérique, non officielle » (« Digital copy, not an official document » en anglais), toujours visible sur la face de données.

## 5. Architecture

Principe : **le noyau Rust décode et vérifie, l'app Swift transporte.** Core NFC ne sert qu'à échanger des APDU. Tout ce qui se teste sans appareil (MRZ, TLV, secure messaging, signatures, AAMVA, EMV) va dans le noyau, avec des vecteurs de test, et sera repris tel quel par Android.

### 5.1 Noyau : nouveau module `core/onepass-core/src/scan/`

| Sous-module | Rôle |
|---|---|
| `mrz.rs` | Parse les MRZ TD1 (carte, 3 × 30) et TD3 (passeport, 2 × 44). Chiffres de contrôle ICAO 9303 partie 3. Corrige les confusions OCR courantes (`O`/`0`, `I`/`1`, `B`/`8`) seulement quand le chiffre de contrôle le confirme. |
| `icao/session.rs` | Machine à états d'une lecture de puce. Entrée : clé d'accès (MRZ ou CAN). Sortie : la prochaine APDU à envoyer, ou le résultat. L'app boucle « envoyer, rendre la réponse » sans rien comprendre. |
| `icao/pace.rs` | PACE (ECDH Generic Mapping, AES), d'abord, car obligatoire sur la CNI française. |
| `icao/bac.rs` | BAC (3DES) en repli pour les passeports anciens. |
| `icao/sm.rs` | Secure messaging (3DES et AES, MAC, compteur). |
| `icao/dg.rs` | Décode EF.COM, DG1 (MRZ), DG2 (photo JPEG ou JPEG 2000), DG7 (signature manuscrite, si présente), DG11 et DG12 (lieu de naissance, autorité, date de délivrance), EF.SOD. |
| `icao/passive_auth.rs` | Vérifie EF.SOD : signature CMS du Document Signer, chaîne jusqu'à un CSCA de la liste maîtresse, empreinte de chaque DG lu. Crates RustCrypto (`cms`, `x509-cert`, `p256`, `p384`, `rsa`, `sha2`). |
| `aamva.rs` | Parse le texte du PDF417 AAMVA (versions 1 à 10) : nom, numéro, dates, adresse, catégories, sexe, taille, yeux, donneur. |
| `emv.rs` | Décodage BER-TLV, sélection PPSE, AID, GPO avec PDOL par défaut, lecture des enregistrements de l'AFL, extraction de `5A` (numéro), `5F24` (expiration), `5F20` (titulaire, si présent), `57` (repli). |
| `mod.rs` | `ScanResult` vers un `Item` du bon type, avec les champs remplis. |

Exposé par la FFI existante (UniFFI) : `mrz_parse`, `IcaoSession` (`new`, `next_command`, `on_response`, `result`), `aamva_parse`, `EmvSession` (même forme que `IcaoSession`), `scan_to_item`.

**Liste maîtresse CSCA.** On embarque la liste maîtresse publiée par le BSI allemand (fichier CMS public, contient les CSCA de plus de 70 pays, dont FR et US). Le noyau vérifie sa signature au chargement. Elle est mise à jour avec l'app, pas par le réseau, pour ne contacter aucun serveur pendant une lecture. Un document dont le CSCA manque obtient le statut « Signature non vérifiable », pas une erreur.

### 5.2 VaultKit et app (Swift)

- `VaultKit/Scan/NFCTransport.swift` : enveloppe `NFCTagReaderSession` (`.iso14443`), ouvre la session, envoie chaque APDU que donne le noyau, met à jour le message système (« Lecture de la puce, 40 % »), gère la perte de contact (relance automatique, une fois).
- `VaultKit/Scan/DocumentScanner.swift` : `DataScannerViewController` pour la MRZ (texte), le CAN (6 chiffres) et le PDF417 (code-barres).
- `App/Scan/` : le parcours (section 6).
- `DesignKit/Documents/` : le rendu (section 7).

### 5.3 Configuration

- `apple/project.yml` : capacité « NFC Tag Reading » (`com.apple.developer.nfc.readersession.formats` = `TAG`) pour la cible iOS seulement.
- `Info.plist` iOS :
  - `NFCReaderUsageDescription` : « OnePass lit la puce de tes documents et cartes pour les ranger dans ton coffre. Rien ne quitte ton téléphone sans chiffrement. »
  - `com.apple.developer.nfc.readersession.iso7816.select-identifiers` : `A0000002471001` (eMRTD), `325041592E5359532E4444463031` (PPSE), `A0000000031010` (Visa), `A0000000041010` (Mastercard), `A0000000042203` (Maestro), `A0000000421010` (CB), `A00000002501` (Amex).
  - `NSCameraUsageDescription` existe déjà (scanner QR).
- Les builds personnels (équipe M968YV4J8W) doivent avoir la capacité NFC sur l'App ID : à vérifier au début du plan.

## 6. Parcours

### 6.1 Entrée

Bouton « Scanner » dans la feuille « Nouvel élément » (iPhone), et action « Scanner la puce » dans le détail d'un Passeport, d'une Carte d'identité ou d'une Carte bancaire existants (complète l'élément sans écraser un champ que l'utilisateur a modifié à la main ; un conflit propose les deux valeurs).

Premier écran : « Que veux-tu ajouter ? » Passeport, Carte d'identité, Permis de conduire, Carte bancaire. Le pays se déduit ensuite de la MRZ, pas d'un menu.

### 6.2 Passeport et carte d'identité

1. **Caméra.** Cadre au format du document, consigne « Montre la page avec ta photo » (passeport) ou « Montre le verso » (CNI). Le scanner lit la MRZ en continu ; il s'arrête quand trois lectures de suite donnent la même MRZ valide (chiffres de contrôle). Bouton « Saisir le CAN » pour une CNI : il lit les 6 chiffres au recto.
2. **Aperçu.** Le rendu du document apparaît déjà, rempli avec les données de la MRZ (section 7.4). Consigne : « Pose ton téléphone sur le document. » Petite animation qui montre où (haut du dos de l'iPhone ; couverture du passeport FR et US, face de la carte).
3. **NFC.** Feuille système Core NFC. Ordre de lecture : EF.COM, EF.SOD, DG1, DG2, puis DG11, DG12, DG7 s'ils existent. Durée typique 5 à 15 s (la photo pèse 15 à 30 Ko).
4. **Vérification.** Le noyau compare DG1 à la MRZ scannée et fait l'authentification passive.
5. **Révélation.** La photo apparaît dans le rendu, les champs se remplissent, le badge de statut s'affiche (section 7.3). Bouton « Enregistrer » ; choix du coffre comme pour tout élément.

Erreurs, chaque fois avec une action :

| Cas | Message | Action |
|---|---|---|
| MRZ illisible après 20 s | « Je n'arrive pas à lire les lignes du bas. » | Saisie manuelle de la MRZ ou du CAN |
| Clé refusée par la puce | « La puce a refusé l'accès. Les lignes scannées ne correspondent pas. » | Rescanner la MRZ |
| Contact perdu | « Garde le téléphone immobile sur le document. » | Relance automatique une fois, puis bouton |
| Pas de puce (ancienne CNI FR, passeport non biométrique) | « Ce document n'a pas de puce. » | Garder les données de la MRZ et la photo du document |
| NFC indisponible | « Cet iPhone ne lit pas le NFC. » | Saisie par MRZ seulement |

### 6.3 Permis et State ID américains

Caméra sur le verso, lecture du PDF417 avec `DataScannerViewController` (symbologie `.pdf417`). Le noyau parse l'AAMVA. Statut « Lu depuis le code-barres » (non signé). Le recto est pris en photo pour `scan_front` (le portrait n'est pas dans le code-barres).

Les autres permis (FR, UE) : photo recto et verso, OCR, statut « Saisi ».

### 6.4 Carte bancaire

1. Écran « Pose ta carte au dos du téléphone ».
2. Session NFC : SELECT PPSE, choix de l'AID (priorité du PPSE ; si plusieurs, par exemple CB et Visa, on garde le réseau international pour le logo et on note les deux dans `card_type`), GPO, READ RECORD.
3. Élément Carte bancaire prérempli : `number`, `expiry`, `cardholder` si la carte le donne. Le champ CVV prend le focus : « Le CVV n'est pas dans la puce. Retourne ta carte. »
4. Rien d'autre de la carte n'est gardé : ni piste 2, ni compteur, ni cryptogramme, ni journal de transactions (section 8).

## 7. Rendu « document »

### 7.1 Familles

Nouvelle vue `DocumentFace` dans DesignKit, choisie par `(type, pays)` :

| Famille | Format | Couverture ou fond | Contenu |
|---|---|---|---|
| `passport.fr` | Livret TD3 | Bordeaux grainé, titre « Passeport » et « République française » en texte | Page de données : photo de la puce, champs, MRZ masquée |
| `passport.us` | Livret TD3 | Bleu marine grainé, « Passport » et « United States of America » en texte | Idem |
| `passport.generic` | Livret TD3 | Teinte neutre dérivée de l'accent du coffre | Idem |
| `idcard.fr` | Carte ID-1 | Bleu clair à blanc, « Carte nationale d'identité » en texte | Recto : photo, nom, prénoms, naissance. Verso : adresse, dates, MRZ masquée |
| `license.us` | Carte ID-1 | Dégradé neutre, nom de l'État en texte | Recto : photo du scan, champs. Verso : catégories, restrictions |
| `idcard.generic` | Carte ID-1 | Teinte neutre | Recto et verso |

Ajouter un pays = ajouter une entrée de table (teinte, libellés), jamais un motif.

### 7.2 Animations

- **Passeport** : fermé en vignette dans la liste. Au toucher, la couverture pivote sur son bord gauche (`rotation3DEffect`, ressort doux, environ 0,6 s) et révèle la page de données. Glisser vers la droite le referme.
- **Carte** : toucher ou glisser horizontal la retourne (recto vers verso, 0,45 s).
- **Reflet** : un dégradé léger se déplace avec l'inclinaison (`CMMotionManager`, 30 Hz, seulement quand la vue est à l'écran). Pas de lueur ni de halo (règle de goût OnePass).
- **Révélation après lecture** (section 6.2, étape 5) : la photo apparaît en fondu, les champs se remplissent ligne par ligne (40 ms d'écart), puis le badge de statut se pose. Retour haptique léger à la fin.
- **Réduire les animations** : fondus seulement, pas de rotation, reflet figé.
- Le Mac affiche les mêmes faces ; l'inclinaison suit le pointeur au survol. La Watch affiche une vignette fixe.

### 7.3 Statut de la puce

Badge sous le document et ligne dans le détail :

| Statut | Libellé | Condition |
|---|---|---|
| `chip_verified` | « Authentifié par la puce » (coche) | Authentification passive réussie, DG1 identique à la MRZ |
| `chip_unverifiable` | « Lu sur la puce, signature non vérifiable » | CSCA absent de la liste maîtresse, ou certificat expiré |
| `chip_invalid` | « Signature invalide » (alerte) | Empreinte ou signature fausse. L'élément s'enregistre quand même, avec ce statut visible |
| `barcode` | « Lu depuis le code-barres » | PDF417 AAMVA |
| `manual` | Aucun badge | Saisie ou OCR |

Le statut est figé à la date de lecture : « Authentifié par la puce le 21 nov. 2026 ». Le badge dit d'où viennent les données, il ne prétend pas que le document est valide aujourd'hui (il peut être annulé ou déclaré perdu).

### 7.4 Données sensibles à l'écran

- La MRZ, le numéro de document et le CAN sont masqués par défaut dans le rendu, révélés au toucher comme les autres secrets (Face ID si le coffre l'exige).
- Le rendu est flouté dans le sélecteur d'apps et masqué en capture d'écran et en partage d'écran (même mécanisme que les mots de passe révélés).

## 8. Modèle de menace (ajouts)

| Menace | Ce qui protège | Limite assumée |
|---|---|---|
| Fuite de la photo officielle et des données d'identité | Elles deviennent des champs et des pièces jointes chiffrées comme le reste du coffre. Aucune donnée lue ne part en clair, aucun service tiers n'est appelé (liste maîtresse embarquée, OCR et décodage sur l'appareil). | Une copie numérique d'identité dans un coffre compromis est plus riche qu'un numéro seul. |
| Rendu utilisé comme faux document | Section 4 : pas de motif officiel, mention « non officielle » fixe, pas d'export d'image. | Une capture d'écran faite par un autre appareil reste possible. |
| Lecture de la puce à l'insu du titulaire | La puce exige la MRZ ou le CAN (BAC, PACE) : il faut avoir vu le document. OnePass ne garde pas de clé de session. | Les limites propres au BAC (entropie faible de la MRZ) restent celles du document. |
| Données de paiement au-delà du nécessaire | Le noyau ne garde que `5A`, `5F24`, `5F20`. Les réponses APDU brutes ne sont jamais écrites sur disque ni dans les journaux. | Le numéro de carte est dans le coffre, comme aujourd'hui pour une saisie manuelle. |
| Faux document qui se fait passer pour vérifié | L'authentification passive vérifie la signature de l'État. Un échec reste visible (`chip_invalid`). | Sans authentification active, une puce clonée à l'identique passe. Le badge le dit en aide : « vérifie la signature, pas l'unicité de la puce ». |
| Journaux | Le transport NFC ne journalise que des étapes (« DG2 lu, 23 Ko »), jamais des octets. | Aucune. |

## 9. Modèle de données (noyau)

Ajouts aux modèles existants, rétrocompatibles (champs optionnels, anciens éléments inchangés) :

- `IdCard` et `Passport` : `portrait` (fichier, photo de la puce, JPEG ; un JPEG 2000 est converti en JPEG sur l'appareil avant chiffrement), `signature_image` (fichier, DG7, optionnel), `chip_status` (menu caché : valeurs de la section 7.3), `chip_read_on` (date), `document_code` (texte, P, PD, PS, ID ; alimente `passport_type`).
- `DriverLicense` : `portrait` (fichier, découpé du scan recto si l'utilisateur accepte), `chip_status` (`barcode` ou `manual`), `document_discriminator` (texte, champ AAMVA DCF).
- `CreditCard` : aucun nouveau champ. `card_type` reçoit la liste des réseaux lus.
- Les noms et prénoms MRZ (majuscules, `<`) sont remplacés par ceux de DG11 si présents, sinon remis en casse lisible (« DUPONT JEAN PIERRE » devient « Dupont », « Jean Pierre »).
- Choix de la famille de rendu : calculé à l'affichage depuis le type et le pays (code ICAO à trois lettres), rien n'est stocké.

## 10. Tests

- **Noyau** :
  - MRZ : exemples officiels ICAO 9303 (TD1, TD3), chiffres de contrôle, corrections OCR acceptées seulement si le contrôle passe.
  - BAC et secure messaging : vecteurs de l'annexe D de l'ICAO 9303 partie 11.
  - PACE : vecteurs de la BSI TR-03110 (Generic Mapping ECDH).
  - Authentification passive : un EF.SOD de test signé par une CSCA de test générée dans le test ; un DG modifié doit donner `chip_invalid` ; un CSCA absent `chip_unverifiable`.
  - AAMVA : échantillons des versions 8, 9 et 10 de la norme (données fictives).
  - EMV : réponses enregistrées et anonymisées (numéros de test publics des réseaux), PDOL, AFL, carte à deux AID.
  - `scan_to_item` : chaque cas remplit les bons champs, la casse des noms.
- **VaultKit** : `NFCTransport` contre un faux tag qui rejoue une session enregistrée (succès, perte de contact au milieu, refus).
- **DesignKit** : instantanés des six familles en clair et en sombre, en français et en anglais, avec et sans « Réduire les animations ».
- **Revue de design** : liste de la section 4 vérifiée sur chaque famille avant fusion.
- **Appareil** (à la main, par le fondateur) : passeport FR, passeport US, CNI FR carte, permis US, une Visa, une Mastercard, une carte CB co-badgée.

## 11. Phases

1. **P1 : passeport.** `mrz.rs`, BAC, PACE, SM, DG1 et DG2, authentification passive, liste maîtresse, parcours iPhone, familles `passport.fr`, `passport.us`, `passport.generic` avec animations.
2. **P2 : cartes d'identité et permis.** CNI FR (CAN, PACE), DG11 et DG12, `idcard.fr`, `idcard.generic`, AAMVA et `license.us`.
3. **P3 : carte bancaire.** `emv.rs`, parcours carte. Revue App Store préparée (justification des AID de paiement).
4. **P4 (plus tard)** : authentification active et Chip Authentication, lecture NFC sur Android avec le même noyau.

Chaque phase est livrable seule.

## 12. Questions ouvertes

1. **Noyau ou bibliothèque Swift ?** La spec met BAC, PACE et la vérification dans le noyau Rust (testable sans appareil, repris par Android). L'alternative rapide est d'embarquer `NFCPassportReader` (Swift, MIT, OpenSSL) dans `apple/Vendor`. Recommandation : le noyau, en se servant de `NFCPassportReader` comme référence pour les détails propres aux appareils.
2. **Photo du permis US** : découper automatiquement le portrait du scan recto (Vision, détection de visage), ou laisser le scan entier ?
3. **Garder ou non la signature manuscrite (DG7)** : elle est utile pour le rendu, mais c'est une donnée de plus à protéger. Proposition : la lire, mais l'afficher seulement si l'utilisateur l'active.
4. **Nom de la mention** : « Copie numérique, non officielle » convient-il, ou faut-il un libellé plus court sur la carte ID-1 ?
