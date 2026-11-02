# Soldes crypto en lecture seule : conception

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, rulings en section 9). Décision du fondateur : afficher le solde des portefeuilles crypto rangés dans OnePass, façon application bancaire, sans jamais signer, envoyer, échanger ni détenir de clé pour une transaction.

## 1. But

Un portefeuille crypto de OnePass garde aujourd'hui sa phrase de récupération et sa clé privée. Il gagne un suivi du solde : adresses publiques par réseau, xpub/ypub/zpub pour Bitcoin, montants et valeur dans la devise de l'utilisateur, courbe sur 24 h, 1 semaine, 1 mois, 1 an. Un écran « Crypto » (accueil et catégorie Portefeuilles crypto) montre le total, les avoirs, le détail par crypto et une remise à l'app de portefeuille de l'utilisateur pour tout ce qui bouge de l'argent.

Hors champ, pour toujours : signer, envoyer, échanger, acheter, vendre, staker, se connecter à une dapp, garder une clé hors du coffre.

## 2. Modèle

- **Champs existants.** Le modèle `cryptoWallet` a déjà `public_addresses` (répétable, une entrée « réseau, adresse ») et `xpub`. Aucun champ nouveau, aucun `RecordKind`.
- **Entrée.** `Bitcoin, bc1q…`, `Ethereum: 0x…` ou l'adresse seule ; un réseau nommé doit correspondre à l'adresse. Le core (`onepass-core/src/wallet_watch`) valide et met en forme canonique :
  - Bitcoin : base58check (P2PKH, P2SH), bech32 (segwit v0, BIP173) et bech32m (taproot et versions suivantes, BIP350), sommes de contrôle vérifiées, mainnet seulement.
  - Ethereum : 20 octets hexadécimaux ; une casse mixte doit respecter EIP-55 (Keccak-256), la forme canonique est la casse EIP-55.
  - Solana : base58 de 32 octets exactement.
- **xpub.** `xpub` (BIP44, P2PKH), `ypub` (BIP49, P2SH-P2WPKH), `zpub` (BIP84, P2WPKH). Dérivation publique BIP32 (CKDpub, secp256k1 via `k256`) locale ; une clé étendue privée (`xprv`…) est refusée. Le balayage s'arrête après 20 adresses vides consécutives (limite d'écart BIP44) sur les branches de réception et de change, plafonné à 1 000 par branche.
- **Dérivation depuis la phrase.** Jamais automatique. Seul le bouton « Dériver les adresses publiques de cette phrase », après confirmation, la lance : le core lit la phrase dans l'élément, en mémoire, calcule la graine BIP39 (PBKDF2-HMAC-SHA512, 2 048 tours, NFKD, avec la passphrase BIP39 de l'élément s'il y en a une), en tire la zpub BIP84 `m/84'/0'/0'`, l'adresse Ethereum `m/44'/60'/0'/0/0` et l'adresse Solana SLIP-0010 `m/44'/501'/0'/0'`, efface tous les tampons secrets (`Zeroizing`) et ne rend que ces données publiques. La phrase ne traverse jamais la frontière FFI pour cette opération. Swift ajoute les trois valeurs aux champs de l'élément et l'enregistre.

## 3. Fournisseurs de solde

- **Désactivé par défaut**, par compte, dans Réglages > Crypto. Tant que c'est désactivé, aucune requête ne part.
- **Choix par réseau** : Bitcoin = API Esplora (mempool.space, Blockstream ou le serveur de l'utilisateur) ; Ethereum = JSON-RPC (PublicNode, LlamaRPC ou le nœud de l'utilisateur, une clé d'API pouvant faire partie du chemin, ce qui couvre les services de type Etherscan/Infura) ; Solana = JSON-RPC (Solana Foundation, PublicNode ou le nœud de l'utilisateur). Une URL personnelle doit être en HTTPS, ou en HTTP vers un hôte du réseau local (`localhost`, `*.local`, IPv4 privée), sans identifiants, requête ni fragment.
- **Cours** : API compatible CoinGecko (CoinGecko ou serveur de l'utilisateur), ou aucune (montants seuls). Seuls les identifiants des cryptos et la devise lui sont envoyés.
- **Quand** : à l'ouverture de l'écran Crypto (sauf si la dernière actualisation a moins de 60 s, même devise, mêmes portefeuilles), au tirer-pour-actualiser, au bouton Actualiser. Jamais en arrière-plan, jamais depuis l'accueil, Watchtower ou le détail d'un élément (ils lisent le cache).
- **Comment** : un lot JSON-RPC par réseau (solde natif, `balanceOf` des jetons connus, comptes de jetons SPL), une requête Esplora par adresse. `URLSession` éphémère (ni cache, ni cookies, ni identifiants), en-têtes génériques (`User-Agent: OnePass`), réponse plafonnée à 4 Mo. Rien d'autre que les adresses ne part vers le fournisseur de solde.
- **Avis** : une ligne, sur l'écran et dans Réglages : « Le service choisi voit tes adresses publiques et ton adresse IP. »
- **Cache chiffré** : réglages et dernier relevé dans `<base>.cryptowatch`, AES-GCM, clé de 256 bits dans le trousseau (`cryptowatch.key.<compte>`), données associées liées au compte. Hors ligne, l'écran affiche les valeurs « au » moment du relevé. Une adresse dont la requête échoue garde son dernier montant connu. Au verrouillage, tout ce qui est en mémoire est oublié.

## 4. Actifs suivis

Natifs BTC, ETH, SOL ; jetons ERC-20 USDT, USDC, DAI, WBTC, LINK, UNI ; jetons SPL USDC et USDT. Chaque jeton est une requête que le fournisseur voit : la liste reste courte et fixe (ruling CW2).

## 5. Écran Crypto

Mise en page inspirée d'une application bancaire (référence de mise en page seulement, aucune marque ni action d'argent reprise) :

- Total centré en grand (centimes plus petits), variation absolue et en pourcentage avec un triangle, courbe pleine largeur (Swift Charts, `catmullRom`, sélection au doigt) sur un fond indigo discret, clair et sombre.
- Quatre boutons ronds en verre : **Recevoir** (adresse et code QR, URI `bitcoin:`/`ethereum:`/`solana:`), **Ouvrir dans…** (app par défaut du réseau, Ledger Live, MetaMask, Phantom, Coinbase Wallet, Trust, Exodus, Rainbow, Solflare, BlueWallet, ou le schéma d'URL de l'app de l'utilisateur), **Actualiser**, **Plus** (réglages, personnaliser). Ni « Envoyer », ni « Échanger », ni « Acheter ».
- Cartes en verre à grand rayon, réordonnables et masquables : portefeuilles (total, variation, chevron de repli, lignes crypto « montant SYMBOLE · cours », valeur, variation colorée), tuiles de cours des principales cryptos (sparkline, ligne pointillée à l'ouverture), plus fortes variations (en hausse / en baisse, parmi les avoirs), toutes les cryptos (marché, « Tout afficher »).
- Détail d'une crypto : valeur, cours, courbe, montant par portefeuille et par adresse, copie et QR de chaque adresse, prochaine adresse de réception d'une xpub, Ouvrir dans….
- Icônes de cryptos dessinées dans l'app (ruling CW4), jamais chargées depuis un serveur.
- Pied de page : heure du relevé, avis de confidentialité, « Lecture seule. OnePass n'envoie, n'échange ni ne signe jamais rien. »

Accès : carte Crypto de l'accueil iPhone (total en cache), lien en tête de la liste Portefeuilles crypto, ligne Crypto de la barre latérale (iPad, Mac), Réglages > Crypto, carte « Suivi du solde » du détail d'un portefeuille.

## 6. Watchtower

Nouvelle alerte : un portefeuille dont le solde suivi est non nul et dont la phrase de récupération est rangée sans protection Travel Mode propre à l'élément (étiquettes réservées `onepass:travel-hidden` ou `onepass:travel-guard` de la fonction Travel Mode par élément). La carte propose de masquer ou de protéger ces éléments pour les voyages et ouvre leur liste ; le détail de chaque élément porte les réglages Travel Mode. La vérification est dans le core (`wallet_watch::phrase_unprotected`) et lit les étiquettes par leur texte : elle fonctionne avant comme après l'arrivée de la fonction Travel Mode sur `main`. Watchtower lit le cache : elle ne déclenche aucune requête.

## 7. Confidentialité

- Les adresses publiques et l'IP de l'appareil sont visibles du fournisseur choisi : c'est dit en une ligne, et le nœud de l'utilisateur est proposé pour l'éviter. Aucune autre donnée (nom de l'élément, compte OnePass, langue, identifiant d'appareil) ne part.
- Le cours et le marché ne reçoivent que des identifiants publics de cryptos et la devise.
- Aucune requête en arrière-plan, aucune télémétrie, aucune requête tant que l'option est désactivée.
- Le cache est chiffré et lié au compte ; il est oublié de la mémoire au verrouillage.
- La dérivation ne garde rien de secret : seules des données publiques sont écrites dans l'élément.

## 8. Lecture réglementaire et App Store

Lecture de l'équipe, pas un avis juridique.

- **Pas de garde.** OnePass ne détient aucun actif pour l'utilisateur, ne contrôle aucune clé pour une transaction et ne peut rien déplacer : la fonction n'est ni un service de conservation, ni un prestataire de services sur crypto-actifs (MiCA, UE), ni un transmetteur d'argent (US). La phrase et la clé restent des secrets rangés dans le coffre, comme aujourd'hui.
- **Pas de transfert, pas d'échange.** Aucune signature, aucun envoi, aucun échange, aucun achat ni vente dans l'app. « Ouvrir dans… » remet une adresse publique à une app tierce choisie par l'utilisateur ; tout mouvement d'argent se fait là-bas.
- **Pas de conseil.** Cours et marché sont affichés à titre d'information, sans recommandation, sans alerte d'achat ni classement d'opportunités.
- **App Store, règle 3.1.5 (cryptomonnaies).** Pas de minage, pas d'échange ni de transaction (3.1.5(iii)), pas d'offre de jetons ni de récompense en crypto (3.1.5(iv), (v)). Le stockage de portefeuille (3.1.5(i)) existait déjà et relève d'un développeur inscrit comme organisation. Suivre des soldes publics en lecture seule ne fait entrer l'app dans aucune catégorie supplémentaire.

## 9. Rulings

Format : `Ruling: <quoi> - <pourquoi> - <coût si faux>`.

- CW1. Ruling: mainnet seulement (testnet, signet, Sepolia, devnet refusés) - un gestionnaire de mots de passe suit de vrais avoirs, et refuser les préfixes de test évite de mélanger des soldes sans valeur - ajouter les préfixes de test au validateur et un réglage, une journée.
- CW2. Ruling: liste fixe des jetons les plus détenus, détection automatique sur chaque adresse, pas de champ « actifs » - chaque jeton est une requête que le fournisseur voit et une liste ouverte demanderait de saisir des contrats - un jeton absent n'est pas compté ; l'ajouter au catalogue est une ligne.
- CW3. Ruling: cache dans un fichier AES-GCM à clé dans le trousseau plutôt que dans un blob scellé par le core - un nouveau type de blob du core aurait touché un format partagé par les autres agents de la course - le cache ne se synchronise pas entre appareils ; chaque appareil relève lui-même, ce qui est voulu.
- CW4. Ruling: icônes de cryptos dessinées en SwiftUI (marque simple et couleur), pas de jeu d'icônes téléchargé - aucune licence à vérifier, rien de chargé d'un serveur - moins fidèles que les logos officiels ; un jeu sous licence compatible pourra les remplacer.
- CW5. Ruling: les URL personnelles (qui peuvent porter une clé d'API) sont gardées dans le fichier chiffré, jamais dans `UserDefaults` - une clé d'API est un secret - aucun.
- CW6. Ruling: les API de type Etherscan avec clé passent par une URL JSON-RPC personnelle, pas d'adaptateur dédié - les fournisseurs à clé (Infura, Alchemy, QuickNode, Etherscan) exposent tous un point JSON-RPC - un service sans JSON-RPC n'est pas utilisable.
- CW7. Ruling: pas de carte Transactions/Activité - l'historique demande d'autres appels par adresse et expose plus au fournisseur, pour peu de valeur dans un coffre - à ajouter plus tard derrière le même interrupteur.
- CW8. Ruling: seules les étiquettes Travel Mode de l'élément comptent comme protection - un coffre entier marqué pour le voyage n'était pas lisible par le core dans cette course - une phrase dans un coffre protégé en entier peut déclencher l'alerte à tort ; l'utilisateur la lève en protégeant l'élément.
- CW9. Ruling: plus fortes variations calculées sur les avoirs, liste du marché tirée de CoinGecko - montrer les avoirs d'abord, le marché à titre d'information - aucun.
- CW10. Ruling: l'historique du portefeuille = montants actuels × cours passés - l'historique des montants demanderait les transactions (CW7) - la courbe ignore les mouvements passés ; c'est dit par la forme (courbe de valeur, pas de relevé).
- CW11. Ruling: le fichier `.cryptowatch` d'un compte retiré reste sur le disque - il est chiffré et sa clé est dans le trousseau du compte ; l'effacer demandait de toucher au retrait de compte d'un autre agent - un petit fichier orphelin ; « Désactiver et effacer » en retire le relevé avant le retrait.
- CW12. Ruling: actualisation automatique à l'ouverture seulement si le dernier relevé a plus de 60 s, ou si la devise, les portefeuilles ou la courbe de la période ont changé - aller et venir entre écrans ne doit pas répéter les requêtes - une valeur peut avoir jusqu'à une minute ; tirer pour actualiser force la requête.
- CW13. Ruling: les entrées `common.*` utilisées (Annuler, Copier, Copié, OK, Terminé, Enregistrer, Partager) sont ajoutées au catalogue de l'app depuis le glossaire - elles n'y étaient pas encore - un conflit de fusion si un autre agent les ajoute en même temps ; résolu en gardant une seule copie, identique.
