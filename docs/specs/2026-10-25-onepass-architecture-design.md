# OnePass : spec d'architecture globale

Date : 2026-10-25
Statut : en revue
Portée : architecture d'ensemble du produit. Chaque jalon (section 13) aura sa propre spec détaillée et son plan d'implémentation.

## 1. Objectif et cadrage

OnePass est un gestionnaire de mots de passe et de secrets, public et open source, conçu d'abord pour l'écosystème Apple.

Décisions prises :

- Produit public dès le départ, code source public.
- Gratuit en v1. Le compte porte un champ `plan` pour un abonnement futur, sans facturation en v1.
- Plateformes v1 : iPhone, iPad, Mac, Apple Watch, Apple Vision Pro, extensions navigateur. Pas de web app en v1.
- Sync v1 : CloudKit (base privée de l'utilisateur). Serveur self-host plus tard, derrière la même interface de stockage.
- Groupes v1 : plusieurs vaults personnels pour ranger (Perso, Projet X, Boulot). Le partage entre personnes vient plus tard, mais la crypto le prévoit dès la v1 (une clé par vault).
- Noyau Rust partagé par toutes les surfaces.
- Crypto post-quantique au niveau le plus élevé raisonnable en 2026.
- Interface inspirée de la logique de 1Password (barre latérale, liste, détail), avec une marque, des icônes et des couleurs propres.

Nom : "OnePass" est le nom de travail retenu par le fondateur. Risque connu : proximité avec la marque déposée 1Password. Une vérification juridique de marque est obligatoire avant le lancement public (section 15).

## 2. Modèle de menace

- CloudKit, le futur serveur et le réseau sont hostiles. Ils peuvent modifier, rejouer, supprimer, réordonner ou injecter n'importe quel blob. Le client doit détecter chacun de ces cas et refuser les données.
- Référence : l'étude ETH Zurich / USI de 2026 sur les gestionnaires cloud face à un serveur malveillant (12 attaques sur Bitwarden, 7 sur LastPass, 6 sur Dashlane). Chaque classe d'attaque de cette étude devient un test (section 12).
- Les pages web sont hostiles : phishing, iframes d'autres sites, formulaires invisibles, clickjacking.
- Les agents IA connectés via MCP sont des clients peu fiables : ils ne voient pas de secret sans approbation humaine explicite.
- Hors périmètre : appareil déverrouillé et compromis au niveau système (malware root, jailbreak).

## 3. Vue d'ensemble des composants

Règle de frontière : seul `core` manipule des secrets en clair, et seulement en mémoire. Tout ce qui sort de `core` vers un stockage ou le réseau est chiffré.

1. `core` (Rust) : crypto, modèle des items et vaults, base locale SQLite chiffrée ligne par ligne, moteur de sync derrière le trait `RecordStore`, générateur, TOTP, logique Watchtower, parseurs d'import et d'export.
2. `VaultKit` (Swift Package) : bindings UniFFI vers `core`, adaptateur `RecordStore` CloudKit (via `CKSyncEngine`), stockage des clés dans le Keychain et la Secure Enclave.
3. Apps Apple (SwiftUI) : une app pour iPhone, iPad, Mac et Vision Pro, une app Apple Watch. Extensions : AutoFill Credential Provider, Safari Web Extension, widgets, Contrôles, App Intents. Native messaging host et agent SSH dans l'app Mac.
4. Extension navigateur (TypeScript, Manifest V3) : un seul code pour Safari, Chromium (Chrome, Arc, Brave, Edge, Opera, Vivaldi) et Firefox. Sur Mac, aucune crypto dans l'extension : elle passe par l'app. Hors Mac, mode autonome avec `core` en WASM et CloudKit JS.
5. CLI et MCP (Rust, sur `core`) : sur Mac, ils passent par l'app via un socket local, avec Touch ID.

Plus tard, sur le même `core` : serveur `axum` self-host (Postgres + stockage objet S3), web app (`core` en WASM).

## 4. Crypto et clés

### 4.1 Dérivation au déverrouillage (2SKD)

- `Argon2id(mot de passe maître, sel)` avec m = 256 MiB, t = 4, p = 4.
- Paramètres Argon2 et sel signés par la clé d'identité du compte. Le client refuse des paramètres non signés ou plus faibles que ceux déjà connus.
- Sortie combinée à la Secret Key via `HKDF-SHA256`, ce qui donne l'AUK (Account Unlock Key, 256 bits).
- Secret Key : 256 bits aléatoires créés sur l'appareil. Stockée dans le Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) et dans l'Emergency Kit (QR code + 52 caractères base32).
- Nouvel appareil : Secret Key transférée par QR code depuis un appareil connecté, dans un canal chiffré hybride ML-KEM-1024 + X25519.
- Option "garder la Secret Key dans le trousseau iCloud" : désactivée par défaut, avec avertissement (affaiblit la protection face à une fuite côté Apple).
- Option 3e facteur : clé matérielle ou passkey via l'extension WebAuthn PRF, intégrée à la dérivation.
- L'extension AutoFill iOS a une limite mémoire d'environ 120 MB. Si elle a besoin du mot de passe maître (après redémarrage), elle ouvre l'app principale pour la dérivation.

### 4.2 Hiérarchie de clés

- L'AUK déchiffre le keyset du compte :
  - paire de chiffrement hybride ML-KEM-1024 + X25519 ;
  - paire de signature hybride ML-DSA-87 + Ed25519 pour les signatures courantes ;
  - clé racine d'identité SLH-DSA, qui ne signe que des clés et des paramètres de compte.
- Clé de vault : 256 bits aléatoires, encapsulée par la paire de chiffrement de chaque membre. En v1 le seul membre est le propriétaire.
- Clé d'item : 256 bits aléatoires par item, enveloppée par la clé du vault. Les pièces jointes ont leur propre clé, enveloppée par la clé d'item.
- Déplacer un item d'un vault à l'autre = ré-envelopper sa clé, sans re-chiffrer son contenu.

### 4.3 Chiffrement symétrique

- AEAD : AES-256-GCM-SIV (RFC 8452), résistant à la réutilisation accidentelle d'un nonce.
- Engagement de clé (committing AEAD) sur chaque blob, contre les attaques par oracle de partition.
- Données associées : id du blob, id du vault, version de schéma, type d'objet.
- En-tête de chaque blob : version de format et identifiants d'algorithmes, pour permettre une migration future.
- Padding de la taille des blobs par paliers, pour ne pas révéler le type d'item.

### 4.4 Intégrité face à un stockage malveillant

- Chaque vault a un manifeste signé : arbre de Merkle des items avec leurs versions, numéro de séquence croissant, hash du manifeste précédent.
- Le client détecte : item supprimé, ancienne version rejouée, item injecté, items intervertis, retour en arrière du vault.
- Chaque appareil garde le dernier numéro de séquence vu par vault et refuse tout manifeste plus ancien.

### 4.5 Métadonnées

Tout est chiffré : titres, URL, types, tags, nombre de champs, dates. Les seules données en clair côté stockage sont les identifiants opaques, les tailles arrondies et les horodatages techniques de CloudKit.

### 4.6 Déverrouillage biométrique

- Clé Secure Enclave (P-256) avec contrôle d'accès `.biometryCurrentSet`. Elle enveloppe le keyset déverrouillé, stocké dans le Keychain `WhenUnlockedThisDeviceOnly`, avec un groupe d'accès partagé entre l'app et ses extensions.
- P-256 n'est pas post-quantique, mais cette clé ne quitte jamais la puce : l'attaquer suppose d'avoir l'appareil.
- Ajout d'un doigt ou d'un visage : la clé est invalidée et le mot de passe maître est redemandé.
- Mot de passe maître redemandé tous les 14 jours (réglable) et après chaque redémarrage.
- Mac : Touch ID ou Apple Watch (`deviceOwnerAuthenticationWithBiometricsOrWatch`). Vision Pro : Optic ID.

### 4.7 Implémentation

- Bibliothèque principale : `aws-lc-rs` (FIPS 140-3 : ML-KEM, ML-DSA, AES-GCM-SIV, HKDF). Compléments : `argon2`, implémentation SLH-DSA à choisir dans la spec du jalon 1.
- `libcrux` en test différentiel dans la CI : mêmes entrées, mêmes sorties exigées. Des bugs ont été trouvés en 2026 dans des parties vérifiées de libcrux, donc la vérification formelle seule ne suffit pas.
- Protocole modélisé dans Tamarin ou ProVerif : propriétés de confidentialité et d'intégrité face à un stockage malveillant.
- `zeroize` sur tous les secrets en Rust, `mlock` des pages sensibles. Aucun secret conservé dans une `String` Swift au-delà de l'affichage.
- Verrouillage automatique (délai réglable) qui efface les clés en mémoire.

### 4.8 Perte d'accès

Sans mot de passe maître et sans Secret Key, rien n'est récupérable. L'Emergency Kit est proposé à la création du compte et rappelé ensuite. Les codes de récupération viendront avec le serveur.

### 4.9 Connexion d'un nouvel appareil par QR code

Question posée en premier sur le nouvel appareil : "Cet appareil est-il à toi, partagé ou public ?". La réponse choisit le mode (4.10).

Déroulé :

1. Le nouvel appareil crée une paire de clés éphémère hybride ML-KEM-1024 + X25519. Il affiche un QR code qui contient : version du protocole, id de session, hash (32 octets) de sa clé publique éphémère, nom et type de l'appareil, expiration. Le QR expire après 2 minutes et change toutes les 30 s.
2. La clé publique complète passe par un point de rendez-vous : une zone "appairage" dans la base CloudKit privée du même compte iCloud. Sur Windows et Linux, l'extension y accède après la connexion Apple ID qu'elle demande déjà.
3. Sur un appareil déjà connecté et déverrouillé, l'utilisateur scanne le QR **avec le scanner de l'app** (jamais l'appareil photo du système), après Face ID ou Touch ID.
4. L'appareil connecté récupère la clé publique, vérifie qu'elle correspond au hash du QR, encapsule une clé de session et ouvre un canal chiffré.
5. **Code de vérification** : les deux écrans affichent le même code à 6 chiffres, dérivé de toute la transcription de l'échange. L'utilisateur confirme qu'ils sont identiques. Bloque l'attaquant qui se placerait au milieu.
6. **Preuve de proximité** : les deux appareils doivent se détecter en Bluetooth LE (et en UWB quand le matériel le permet). Bloque l'attaque principale des connexions par QR : un pirate qui envoie à distance son propre QR en demandant de le "scanner pour se connecter".
7. L'écran d'approbation affiche le type d'appareil, son nom, le mode choisi et l'avertissement "Ne scanne jamais un QR code qu'on t'a envoyé". L'approbation demande une deuxième biométrie.
8. Mode personnel ou partagé : l'appareil connecté envoie par le canal l'id du compte, la Secret Key, les paramètres Argon2 signés et une autorisation d'appareil signée par la clé d'identité du compte. Le nouvel appareil demande ensuite le mot de passe maître : il faut donc à la fois un appareil de confiance et le mot de passe.
9. Le nouvel appareil crée ses propres clés d'appareil, qui sont ajoutées à la **liste signée des appareils** du compte. Tous les autres appareils reçoivent une notification "Nouvel appareil connecté".

Sans appareil de confiance : Emergency Kit (scan du QR ou saisie de la Secret Key) puis mot de passe maître. Option "délai de sécurité" (activée par défaut) : les vaults marqués sensibles restent verrouillés 24 h après une connexion par ce chemin, avec une alerte sur tous les appareils, qui peuvent annuler la connexion.

Gestion des appareils :

- Liste dans les réglages : nom, type, mode, première connexion, dernière activité.
- Révocation d'un appareil : il est retiré de la liste signée, reçoit un ordre d'effacement, et les clés de tous les vaults qu'il connaissait sont renouvelées. Ainsi, même s'il ignore l'ordre d'effacement, il ne lit plus aucune donnée future.

### 4.10 Modes d'appareil : personnel, partagé, public

- **Personnel** : inscription complète (Secret Key stockée, Face ID, cache local chiffré, autofill complet).
- **Partagé** (ordinateur de la famille, poste au bureau) : inscription complète, mais pas de biométrie, verrouillage après 5 min d'inactivité, mot de passe maître à chaque déverrouillage, vaults visibles choisis à la connexion.
- **Public** (ordinateur d'hôtel, de bibliothèque, d'un tiers) : **session déléguée**, sans inscription.
  - Le mot de passe maître n'est **jamais tapé** sur l'appareil public, ce qui neutralise les keyloggers. La Secret Key ne quitte jamais le téléphone.
  - Sur le téléphone, l'utilisateur choisit les vaults ou les items à ouvrir, la durée (15 min par défaut, 1 h maximum) et lecture seule oui/non.
  - Le téléphone n'envoie que les clés de ces vaults ou items, enveloppées pour la clé éphémère de la session. Aucune autorisation d'appareil n'est créée.
  - Rien sur le disque : ni cache, ni clé, ni historique, ni proposition d'enregistrer un mot de passe. Presse-papiers effacé après 30 s.
  - Fin de session automatique à l'expiration, à la fermeture du navigateur ou après 5 min d'inactivité. Fin à distance depuis le téléphone à tout moment, avec un compteur de temps restant affiché sur les deux appareils.
  - Le téléphone garde un journal de la session : items ouverts, champs copiés ou remplis.
  - Limite affichée honnêtement : un ordinateur public compromis peut voir ce qui est ouvert pendant la session. D'où l'ouverture du strict nécessaire.

## 5. Vaults et items

### 5.1 Vaults

- Plusieurs vaults personnels. Un vault "Personnel" est créé au départ.
- Chaque vault : nom, icône, couleur, clé propre, option "autorisé en voyage" (section 10), option "accessible au MCP" (section 9.2).
- Un item appartient à un seul vault.
- Corbeille de 30 jours, puis suppression définitive. Archive : l'item sort des listes et de l'autofill sans être supprimé.

### 5.2 Format générique

Chaque item suit un format générique. Les types sont des modèles sur ce format : un nouveau type plus tard = un nouveau modèle, sans migration.

Types de champ : texte, masqué, mot de passe, URL, email, téléphone, date, mois/année, nombre, montant, adresse, menu, OTP, passkey, clé SSH, fichier, localisation, phrase mnémonique, code-barres, lien vers un autre item.

Chaque champ peut être masqué, copié et exclu de l'autofill.

### 5.3 Enveloppe commune (tous les types)

Les champs marqués `*` sont obligatoires, tous les autres sont facultatifs.

- Titre*, type*, vault*, sous-titre (calculé : identifiant, 4 derniers chiffres, etc.)
- Tags, favori, couleur, icône perso
- Notes (Markdown)
- URL (répétable) : libellé, adresse, règle de correspondance (domaine, sous-domaine exact, URL exacte, jamais), principale oui/non
- Applications liées (répétable) : bundle ID iOS ou macOS
- Localisations (répétable) : étiquette, adresse, coordonnées, rayon, suggérer sur place oui/non
- Pièces jointes (répétable)
- Sections de champs perso (répétable) : nom de section, puis champs typés
- Expiration générique, rappel de rotation (tous les N jours)
- Sécurité : redemander la biométrie à chaque ouverture, masquer de l'autofill, exclusions Watchtower
- Disponible sur la Watch oui/non
- Archivé oui/non
- Calculés : créé le, modifié le, appareil, dernier usage, nombre d'usages, historique des versions, historique des mots de passe

### 5.4 Les 26 modèles

Accès :

- Login : identifiant*, mot de passe, email, méthodes de connexion (section 5.5), TOTP, passkeys (répétable, lecture seule : site, nom d'utilisateur, créée le, id), PIN, téléphone pour la 2FA, codes de secours 2FA (répétable, utilisé oui/non), questions de sécurité (répétable, question et réponse masquée).
- Password : mot de passe*, contexte, règles de génération utilisées.
- Email : adresse*, mot de passe, mot de passe d'application, fournisseur, type de compte (IMAP, POP, Exchange, JMAP), alias (répétable), email et téléphone de récupération, TOTP. Entrant : serveur, port, sécurité (SSL/TLS, STARTTLS, aucune), méthode d'auth, identifiant. Sortant (SMTP) : serveur, port, sécurité, identifiant, mot de passe.
- Server : hôte ou IP*, port, protocole (SSH, RDP, VNC, HTTPS, SFTP, FTP), utilisateur, mot de passe, clé SSH (lien), empreinte d'hôte, bastion (lien), VPN requis (lien), OS, IPv4, IPv6, région, environnement (prod, staging, dev), TOTP. Admin : URL du panneau, utilisateur, mot de passe. Hébergeur : nom, URL console, compte (lien), téléphone support.
- Database : moteur* (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, MongoDB, Redis, SQLite, ClickHouse, Cassandra, Elasticsearch, autre), hôte*, port, base, schéma, utilisateur, mot de passe, SID ou nom de service, mode SSL, certificat CA, certificat client, clé client, options de connexion, tunnel SSH (lien vers Server), environnement, lecture seule oui/non, alias. Calculé : chaîne de connexion.
- Router (Wi-Fi) : SSID*, mot de passe Wi-Fi, sécurité (WPA3, WPA2, WPA, WEP, ouvert), bande (2,4 / 5 / 6 GHz), réseau masqué oui/non, SSID invité, mot de passe invité, modèle, numéro de série, adresse MAC, version du firmware, IP ou URL admin, utilisateur admin, mot de passe admin, FAI, numéro client FAI, identifiants PPPoE, IP publique, DNS. Calculé : QR code de connexion.
- API Credential : service*, clé ou token*, secret, client ID, type (clé API, bearer, basic, OAuth2 client, HMAC, JWT), environnement, URL de base, scopes, nom de l'en-tête HTTP, secret de webhook, nom de variable d'environnement, créée le, expire le, URL de la console, compte lié.
- SSH Key : clé privée* (générée ou importée), algorithme (Ed25519, ECDSA P-256 ou P-384, RSA 4096), passphrase, commentaire, certificat SSH, hôtes associés (répétable), utiliser dans l'agent oui/non, confirmer à chaque usage oui/non, signature Git oui/non. Calculés : clé publique, empreinte SHA256.

Finance :

- Credit Card : titulaire*, numéro*, expiration* (mois/année), CVV, PIN, type (crédit, débit, prépayée), carte virtuelle oui/non, date d'émission, banque émettrice, devise, plafond, adresse de facturation, téléphone support (local et international), site de la banque. Calculé : marque (par le BIN).
- Bank Account : banque*, titulaire*, type (courant, épargne, pro, joint, autre), IBAN (validé), BIC/SWIFT, numéro de compte, code banque, code guichet, clé RIB, routing number (US), sort code (UK), devise, PIN, banque en ligne (lien vers Login), conseiller (nom, téléphone, email), adresse de l'agence, ouvert le.
- Crypto Wallet : nom*, phrase de récupération* (12, 18 ou 24 mots, validée BIP39), type (logiciel, matériel, papier, exchange), blockchains (répétable), passphrase BIP39, mot de passe du wallet, PIN, clé privée, adresses publiques (répétable : réseau, adresse), xpub, chemin de dérivation, modèle et numéro de série du matériel, exchange (lien), créé le, emplacement de la sauvegarde physique. Jamais d'autofill. Copie seulement après biométrie.
- Abonnement : service*, prix, devise, fréquence (mensuel, annuel, autre), prochain renouvellement, moyen de paiement (lien vers Credit Card), début, préavis de résiliation, URL de résiliation, compte (lien), rappel N jours avant le renouvellement.

Identité :

- Identity : civilité, prénom*, deuxième prénom, nom, nom de naissance, sexe, date de naissance, lieu de naissance, nationalité, adresse (ligne 1, ligne 2, ville, code postal, région, pays), téléphones (mobile, domicile, pro), email, entreprise, poste, service, site web, pseudos (répétable : réseau, pseudo).
- Carte d'identité : pays*, numéro*, expiration*, nom, prénoms, nom d'usage, date et lieu de naissance, sexe, nationalité, taille, adresse, date d'émission, autorité, numéro CAN, lignes MRZ, scans recto et verso.
- Passport : pays émetteur*, numéro*, expiration*, type, nom, prénoms, nationalité, date et lieu de naissance, sexe, date d'émission, autorité, lieu de délivrance, lignes MRZ, scan.
- Driver License : nom complet*, numéro*, pays et région, date de naissance, adresse, catégories (répétable), date d'émission, expiration, restrictions, autorité, sexe, taille, couleur des yeux, donneur d'organes, scans recto et verso.
- Social Security Number : nom*, numéro* (validé selon le pays : SSN US, NIR France, NI UK, SIN Canada, etc.), pays, date d'émission, scan.
- Medical Record : patient*, date de naissance, groupe sanguin, taille, poids, allergies (répétable), antécédents (répétable), traitements (répétable : médicament, dose, fréquence), vaccins (répétable : nom, date, lot), médecin traitant (nom, téléphone, adresse), établissement, numéro de dossier, assurance santé (assureur, numéro d'adhérent, numéro de groupe), contact d'urgence (lien vers Identity ou texte), directives anticipées, donneur d'organes.
- Membership : organisation*, numéro de membre*, nom du membre, niveau, adhésion le, expiration, PIN, code-barres (valeur et format : QR, Code 128, PDF417, Aztec ; affichage plein écran), téléphone, site, adresse.
- Reward Program : entreprise*, numéro de membre*, nom du membre, PIN, niveau, solde de points, expiration des points, code-barres, téléphone, site, compte en ligne (lien).

Biens et contrats :

- Assurance : assureur*, numéro de contrat*, type (auto, habitation, santé, vie, voyage, responsabilité civile, autre), assurés, bien couvert (lien vers Véhicule, adresse ou texte), début, échéance, prime et fréquence, franchise, garanties, numéro d'assistance, numéro de déclaration de sinistre, conseiller, espace client (lien vers Login), attestation (fichier).
- Véhicule : immatriculation*, marque, modèle, version, année, couleur, VIN, première mise en circulation, carte grise (numéro et scan), titulaire, code de démarrage ou d'autoradio, prochain contrôle technique, prochain entretien, assurance (lien), clés (nombre, emplacement).
- Digicode / code d'accès : code*, lieu* (localisation), étiquette (portail, immeuble, alarme, casier, garage), horaires de validité, code de l'alarme, instructions, contact (gardien, syndic).

Autres :

- Secure Note : contenu Markdown* (le champ notes de l'enveloppe, affiché en grand).
- Document : fichiers* (répétable), date du document, expiration, émetteur. Calculé : texte extrait par OCR local (Vision), chiffré, utilisé pour la recherche.
- Software License : logiciel*, clé de licence*, version, fichier de licence, licencié (nom, email), entreprise, nombre de postes, plateformes, acheté le, prix, numéro de commande, revendeur (site, email support), mises à jour jusqu'au, lien de téléchargement, compte (lien).

### 5.5 Méthodes de connexion et comptes fournisseurs

- Un Login a une ou plusieurs méthodes de connexion : mot de passe, passkey, ou via un fournisseur.
- Fournisseurs reconnus : Google, Apple, Microsoft, GitHub, Facebook, X, LinkedIn, Discord, Slack, et SSO d'entreprise (Okta, Entra ID, autre domaine OIDC ou SAML).
- La méthode "via un fournisseur" pointe vers le Login du compte fournisseur précis (par exemple `perso@gmail.com` ou `pro@entreprise.com`). Plusieurs comptes d'un même fournisseur sont gérés.
- Sign in with Apple : l'adresse relais "Masquer mon adresse" est enregistrée avec le site.
- Vue "Connexions liées" dans la barre latérale : groupée par fournisseur, puis par compte, puis par site.

### 5.6 Localisation

- Un item peut avoir plusieurs lieux : étiquette, adresse ou coordonnées, rayon.
- Usage : liste "À proximité" dans l'app, widget, Watch, suggestion du bon digicode, Wi-Fi ou carte de membre sur place.
- Calcul entièrement local. Coordonnées chiffrées comme le reste. Géofences enregistrées seulement sur l'appareil.
- Fonction désactivée par défaut. Permission de localisation demandée seulement à l'activation.

### 5.7 Icônes

Ordre de recherche :

1. icône perso de l'item ;
2. pack intégré d'environ 5 000 marques courantes, livré dans l'app ;
3. favicon et `apple-touch-icon` récupérés directement sur le site, sans cookies ;
4. lettre sur fond coloré.

Aucun service tiers (pas de service de favicons d'un moteur de recherche). Cache chiffré local. Cartes et banques : icône déduite du BIN ou de l'IBAN. Cryptos : pack intégré.

## 6. Autofill

### 6.1 Système Apple (iPhone, iPad, Mac, Vision Pro)

Extension AutoFill Credential Provider :

- Mots de passe : suggestions dans la barre QuickType, dans Safari et dans les apps. `ASCredentialIdentityStore` reçoit seulement identifiants et domaines, jamais de secret.
- Passkeys : création et connexion (iOS 17+), flux hybride du système pour un autre appareil.
- Codes à usage unique : TOTP proposés dans le champ du code (iOS 18+).
- N'importe quel champ (carte, adresse, identité, IBAN, etc.) via l'insertion de texte AutoFill (iOS 18+).
- Import et export de passkeys et mots de passe via FIDO Credential Exchange (iOS 26 / macOS 26).
- Pas de clavier custom : la barre QuickType suffit, et iOS bloque les claviers tiers sur les champs mot de passe.
- À vérifier en implémentation : ce qu'iOS 26 expose aux fournisseurs tiers pour enregistrer un nouveau mot de passe tapé dans une app, et le support des fournisseurs tiers sur visionOS.
- Apple TV : l'AutoFill de l'iPhone fonctionne dans le clavier de saisie pour la TV.

### 6.2 Mac hors navigateur

- Quick Access : raccourci global (par défaut `⌥⌘Space`), recherche, copie ou saisie dans l'app au premier plan, suggestion d'après l'app active.
- Menu bar : recherche, générateur, TOTP.

### 6.3 Extension navigateur

Navigateurs : Safari (Mac, iPhone, iPad, Vision Pro), Chrome, Arc, Brave, Edge, Opera, Vivaldi, Firefox.

Modes :

- Safari : parle à l'app native.
- Chromium et Firefox sur Mac : native messaging vers l'app Mac. Appairage initial avec un code affiché dans l'app, puis session chiffrée hybride ML-KEM + X25519. L'app vérifie l'ID de l'extension et la signature de l'appelant. Les clés restent dans l'app.
- Chromium et Firefox sur Windows et Linux : mode autonome, `core` en WASM, données via CloudKit JS (connexion Apple ID). Déverrouillage par mot de passe maître, ou Windows Hello / passkey via WebAuthn PRF. Clés en mémoire seulement, effacées au verrouillage et à la fermeture du navigateur. L'utilisateur avec Advanced Data Protection doit activer "Accéder aux données iCloud sur le web".
- Sur Mac, si l'app est installée, l'extension passe toujours par l'app.

Fonctions :

- Détection des champs : attributs `autocomplete`, heuristiques, petit classifieur local pour les formulaires mal balisés.
- Icône dans le champ et menu en ligne. Le menu est rendu dans une iframe de l'origine de l'extension (anti-clickjacking, la page ne peut pas le lire).
- Anti-phishing : correspondance stricte par domaine via la Public Suffix List ; jamais de remplissage dans une iframe d'un autre site ; rien en HTTP ; remplissage seulement après un geste de l'utilisateur, jamais au chargement.
- Enregistrement à la soumission d'un formulaire, mise à jour au changement de mot de passe, générateur dans les champs "nouveau mot de passe".
- TOTP collé dans le champ du code à l'étape suivante, ou copié.
- Passkeys via l'interception de l'API WebAuthn de la page.

Connexion en un clic (overlay) :

- Sur une page de connexion reconnue, une carte en overlay (iframe de l'origine de l'extension) affiche le ou les comptes du site, avec un bouton "Se connecter".
- Un clic enchaîne toute la chaîne d'authentification : identifiant, soumission, page suivante, mot de passe, soumission, code TOTP, soumission, option "se souvenir de cet appareil" selon le réglage de l'item. Fonctionne aussi sur les formulaires en une seule page et les champs dans une modale.
- Avec un compte fournisseur : clic sur "Continuer avec Google" (ou autre), choix du bon compte sur la page du fournisseur, mot de passe, 2FA du fournisseur, puis retour sur le site.
- Avec une passkey : la connexion passkey est proposée en premier si le site la supporte.
- L'état de la chaîne vit dans le service worker de l'extension, jamais dans la page.
- Garde-fous :
  - démarrage seulement par un clic de l'utilisateur ;
  - à chaque étape, le domaine doit correspondre au site de l'item ou au domaine officiel du fournisseur lié, sinon arrêt ;
  - arrêt et main rendue à l'utilisateur sur une étape inconnue, un CAPTCHA (jamais résolu automatiquement), une validation push ou un code SMS ;
  - délai maximal de 60 s, bouton "Arrêter" visible pendant toute la chaîne ;
  - soumission automatique activable par item (activée par défaut, désactivable).
- Apprentissage : quand une étape n'est pas reconnue et que l'utilisateur la termine à la main, l'extension mémorise localement (chiffré) les sélecteurs de cette étape pour ce site.

Connexion via un fournisseur :

- Détection d'un clic sur "Continuer avec Google" (ou autre fournisseur) et de la redirection OAuth/OIDC (`accounts.google.com/o/oauth2…`, `appleid.apple.com/auth…`, `login.microsoftonline.com…`, etc.), avec le site d'origine.
- Sur la page de choix de compte du fournisseur, mise en avant du compte utilisé pour ce site ("Utilisé pour notion.so").
- Au retour sur le site connecté, proposition d'enregistrer le lien site, fournisseur, compte.
- Sur le formulaire de connexion d'un site déjà lié, le menu propose "Se connecter avec Google (perso@gmail.com)".
- Dans les apps iOS (`ASWebAuthenticationSession`), le flux n'est pas visible : lien manuel, ou suggestion quand le domaine de l'app correspond à un site déjà lié.

### 6.4 TOTP

- Ajout par caméra, scan d'un QR affiché à l'écran (Mac, ScreenCaptureKit), lien `otpauth://`, import de l'export Google Authenticator (`otpauth-migration://`).
- SHA-1, SHA-256, SHA-512, 6 à 8 chiffres, période réglable. Steam Guard en option.

### 6.5 Presse-papiers

Effacé après 90 s, `localOnly` (pas de presse-papiers universel), marqué "concealed" pour les gestionnaires de presse-papiers.

## 7. Surfaces Apple

- iPhone : onglets Accueil (favoris, récents, à proximité), Rechercher, Watchtower, Réglages.
- iPad : même app, multi-fenêtres, Stage Manager, raccourcis clavier, glisser-déposer d'un champ.
- Mac : 3 colonnes (barre latérale avec vaults, catégories, tags, connexions liées, Watchtower, archive, corbeille ; liste ; détail).
- Apple Watch : app autonome en lecture. Seuls les items marqués "Sur la Watch" y sont copiés, envoi chiffré de bout en bout depuis l'iPhone. Contenu : codes TOTP, codes-barres plein écran, mots de passe Wi-Fi, digicodes suggérés sur place, cartes et identité. Code de la Watch obligatoire, verrouillage dès qu'elle quitte le poignet. Complication et Smart Stack : ouvrent l'app, n'affichent jamais de secret.
- Vision Pro : même app que l'iPad, Optic ID, extension Safari.
- Widgets : favoris, TOTP (masqués tant que l'appareil est verrouillé), à proximité.
- Contrôles (Centre de contrôle, bouton Action) : générateur, Quick Access, scan d'un QR TOTP.
- Raccourcis / App Intents : générer un mot de passe, ouvrir un item, verrouiller. Aucun secret renvoyé à un raccourci sans biométrie.
- Handoff entre appareils.
- Spotlight : rien d'indexé par défaut, option "titres seulement".
- Confidentialité : écran flouté dans le sélecteur d'apps, champs révélés protégés contre la capture d'écran.

## 8. Watchtower

Calculs locaux dans `core`.

- Mots de passe fuités : API Pwned Passwords de HIBP en k-anonymity (5 premiers caractères du SHA-1, en-tête `Add-Padding: true`).
- Sites piratés : liste publique des fuites HIBP téléchargée en entier, comparée en local aux domaines.
- Surveillance des adresses email : demande une clé API HIBP. En v1, seulement avec la clé personnelle de l'utilisateur (option). Version hébergée plus tard avec le serveur.
- Mots de passe faibles (`zxcvbn`), réutilisés, anciens.
- 2FA disponible mais absente, passkey disponible : listes 2fa.directory et passkeys.directory, embarquées et mises à jour.
- URL en HTTP, Wi-Fi en WEP ou ouvert, clé SSH faible (RSA < 3072), doublons, codes de secours manquants, wallet sans sauvegarde physique notée.
- Échéances : cartes, passeports, permis, cartes d'identité, assurances, abonnements, licences, clés API.
- Comptes fournisseurs : liste des sites qui dépendent de chaque compte. Si ce compte fuite ou n'a ni 2FA ni passkey, alerte prioritaire avec tous les sites exposés. Détection des doublons (même site avec un compte fournisseur et un mot de passe séparé).
- Score par vault et global, notifications locales.

## 9. CLI, MCP, agent SSH

### 9.1 CLI

- Binaire Rust. Sur Mac, déverrouillage via l'app avec Touch ID. Session par terminal, expire après 10 min d'inactivité. La CLI ne stocke ni clé ni secret.
- Commandes : `item list|get|create|edit|delete`, `read "onepass://Perso/GitHub/password"`, `run -- <cmd>` (variables d'environnement depuis un `.env` à références, valeurs masquées dans la sortie), `inject` (fichier modèle), `totp`, `generate`, `import`, `export`, `watchtower`.
- Sortie texte ou `--json`, complétion zsh, bash, fish.
- Usage en CI sans Mac : plus tard, avec les comptes de service du serveur.

### 9.2 MCP

- Serveur stdio local, passe par l'app Mac.
- Par défaut, seulement des métadonnées : titre, type, vault, URL, noms des champs.
- Outils sans révélation : `run_with_secrets` (valeurs masquées dans la sortie), `fill_template`, `create_login` (génère et enregistre, ne renvoie rien de secret).
- `reveal_secret` et `totp_code` : Touch ID à chaque appel, avec nom de l'agent, item et champ affichés.
- Accès limité aux vaults marqués "accessible au MCP". Journal local de chaque accès.
- Le contenu des items est renvoyé comme donnée balisée, jamais comme instruction (protection contre l'injection de prompt cachée dans une note).

### 9.3 Agent SSH

- Socket `SSH_AUTH_SOCK` fourni par l'app Mac, branché via `IdentityAgent` dans `~/.ssh/config`.
- Signe avec les items SSH Key marqués "agent". La clé privée ne sort jamais de l'app.
- Touch ID à chaque usage, ou une fois par session et par app, avec le nom du processus demandeur.
- Signature des commits Git par clé SSH.

## 10. Générateur, import, export, sauvegarde, voyage

- Générateur : aléatoire (8 à 100 caractères, jeux de symboles, sans caractères ambigus), phrase de passe (listes EFF anglais et français), PIN. Respect des règles par site (attribut `passwordrules` et base de règles par site). CSPRNG du système.
- Import : 1Password (`.1pux`), Apple Passwords (CSV et Credential Exchange), Bitwarden (JSON), KeePass (`.kdbx`), Chrome, Firefox, LastPass, Dashlane, Proton Pass, Google Authenticator.
- Import Wi-Fi depuis Apple (aucune API publique ne lit les mots de passe Wi-Fi) :
  1. Mac : liste des réseaux connus via `CoreWLAN`, mots de passe lus dans le trousseau Système (items "AirPort network password") avec authentification admin. Couvre les réseaux synchronisés par le trousseau iCloud. Disponible dans la CLI (`import wifi --from-keychain`) et dans la version Mac distribuée en direct, pas dans la version Mac App Store (sandbox).
  2. Credential Exchange (iOS 26 / macOS 26) : import groupé si l'export Apple inclut le type Wi-Fi. À vérifier sur appareil, l'importeur gère ce type de toute façon.
  3. QR code réseau par réseau depuis l'app Mots de passe (`WIFI:S:…;T:…;P:…;;`), par caméra ou capture d'écran sur Mac.
  4. Réseau actuel absent du coffre : proposition de créer l'item avec le SSID pré-rempli (`NEHotspotNetwork`, permission de localisation).
- Export : archive chiffrée, Credential Exchange, CSV avec avertissement.
- Sauvegarde locale automatique chiffrée, hebdomadaire, dans un dossier choisi. CloudKit n'est pas une sauvegarde : une suppression s'y propage partout.
- Emergency Kit PDF : Secret Key, QR code, instructions.
- Travel Mode : seuls les vaults "autorisés en voyage" restent sur les appareils. Les autres sont effacés localement avec leurs clés, puis resynchronisés au retour.
- Langues v1 : français et anglais.

## 11. Repo, licence, distribution

- Monorepo public sur GitHub, organisation `soma-intelligence`.
  - `core/` : workspace Rust (`core`, `core-ffi`, `cli`, `mcp`, `wasm`).
  - `apple/` : projet Xcode, packages `VaultKit` et design, apps et extensions.
  - `extension/` : TypeScript, Manifest V3.
  - `formal/` : modèles Tamarin.
  - `docs/` : livre blanc sécurité, specs, plans.
- Licence : GPL-3.0 pour les clients, AGPL-3.0 pour le futur serveur, CLA pour les contributeurs (nécessaire pour publier sur l'App Store). Décision du 2026-10-26 : AGPL-3.0-or-later pour tout le dépôt, avec un CLA.
- Bundle ID racine : `me.somalabs.onepass`.
- Mac distribué en deux versions : Mac App Store et téléchargement direct notarisé (import Wi-Fi par trousseau, agent SSH sans contraintes de sandbox).
- Interface : style iOS 26 natif (Liquid Glass), package de design SwiftUI partagé, sobre et neutre. Accessibilité : Dynamic Type, VoiceOver, contraste élevé, mode sombre.

## 12. Tests

- Crypto : vecteurs officiels NIST pour ML-KEM, ML-DSA et SLH-DSA ; test différentiel `aws-lc-rs` contre `libcrux`.
- Formats et import : tests property-based (`proptest`), fuzzing (`cargo-fuzz`) sur tous les parseurs.
- Suite "stockage malveillant" : un test par classe d'attaque (paramètres KDF affaiblis, rollback, items intervertis, item supprimé, clé injectée, manifeste ancien). Chaque cas doit être détecté et refusé.
- Appairage QR : QR expiré ou rejoué, clé publique qui ne correspond pas au hash, codes de vérification différents, absence de proximité Bluetooth, session publique utilisée après expiration ou fin à distance, appareil révoqué qui tente de lire des données après rotation.
- Modèle Tamarin ou ProVerif vérifié en CI.
- Apple : Swift Testing pour `VaultKit`, tests UI des flux AutoFill.
- Extension : Playwright sur des pages piégées (iframe d'un autre site, formulaire invisible, page HTTP, domaine sosie, flux OAuth simulé).
- CI : build de toutes les cibles, `cargo-deny`, `cargo-audit`, vérification des builds reproductibles.

## 13. Jalons

Chaque jalon a sa propre spec détaillée et son plan.

1. `core` : crypto, modèle des 26 types, base locale, CLI de base. Testable sans interface.
2. `VaultKit`, sync CloudKit, apps iPhone, iPad et Mac : création de compte, déverrouillage, vaults, éditeurs.
3. AutoFill système, passkeys, TOTP.
4. Extension : Safari, puis Chromium et Firefox via l'app Mac (avec connexion via fournisseur), puis mode autonome Windows et Linux.
5. Watchtower, icônes, import et export (dont Wi-Fi), sauvegarde.
6. Apple Watch, Vision Pro, widgets, Contrôles, Raccourcis.
7. MCP, agent SSH, Travel Mode.
8. Audit externe, vérification de marque, lancement public.

## 14. Hors v1 (prévu plus tard)

Serveur self-host, partage entre personnes et organisations, web app, surveillance hébergée des emails, comptes de service pour la CI, codes de récupération, pass Apple Wallet, abonnement payant.

## 15. Risques et points ouverts

- Marque : "OnePass" est proche de 1Password. Vérification juridique obligatoire avant le lancement public, nom de remplacement à prévoir.
- Implémentation SLH-DSA en Rust : choix et maturité à valider dans la spec du jalon 1.
- APIs iOS 26 à confirmer sur appareil : enregistrement d'un nouveau mot de passe depuis une app tierce, fournisseurs tiers sur visionOS, type Wi-Fi dans l'export Credential Exchange d'Apple.
- CloudKit JS pour l'extension autonome : fiabilité et limites à mesurer au jalon 4.
- Audit externe de `core` obligatoire avant le lancement.
