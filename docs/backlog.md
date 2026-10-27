# Idées en attente

Idées validées par le fondateur mais pas encore planifiées. Chacune passera par sa propre spec et son plan avant tout code.

## Transfert sans fil vers un appareil hors écosystème Apple

Noté le 2026-10-26. Pas commencé.

**Besoin.** Ouvrir OnePass sur un appareil qui n'est pas Apple (PC Windows, Linux, Android) et y faire arriver ses données en sans fil, directement depuis un appareil Apple déjà connecté. iCloud n'est pas disponible sur ces appareils.

**Principe envisagé.**
- L'appareil Apple déjà déverrouillé sert de source. Le nouvel appareil affiche un QR code (ou l'inverse), comme l'appairage QR prévu au jalon 2b (spec d'architecture, section 4.9).
- Le QR porte une clé publique éphémère et un code court à confirmer des deux côtés, pour qu'un tiers ne puisse pas s'intercaler.
- Échange de clés hybride post-quantique (ML-KEM-1024 + X25519, comme le reste du core). Les données voyagent déjà chiffrées : les blobs et manifestes signés du coffre, jamais du clair. Le canal ajoute une seconde couche de chiffrement.
- Transport local sans serveur : réseau local (Wi-Fi), avec Bluetooth ou Wi-Fi Direct en option. Un relais chiffré de bout en bout seulement si les deux appareils ne se voient pas.
- Le nouvel appareil demande toujours le mot de passe maître. La Secret Key peut voyager dans le canal chiffré, après confirmation explicite sur l'appareil source.
- Les questions « appareil personnel, partagé ou public » (spec, section 4.10) s'appliquent : un appareil public reçoit une session déléguée, pas le coffre complet.

**Dépendances.** Il faut un client OnePass sur l'appareil cible : extension en mode autonome (jalon 4), ou future app Windows, Linux ou Android. Le mieux est de le traiter avec le jalon 2b (appairage et appareils), qui pose le même protocole d'appairage.

**Questions ouvertes.** Transfert unique ou sync continue entre l'appareil Apple et l'appareil hors Apple ? Quel stockage local sur l'appareil cible ? Comment révoquer l'appareil (liste signée des appareils, jalon 2b) ?

## Extension : connexion dans une iframe de même origine, limites restantes

Noté le 2026-10-26 (Task 3, C1). Pas commencé.

- **Boutons fournisseur et sélecteur de compte dans un cadre enfant.** La chaîne et l'overlay ne retiennent d'un cadre enfant de même origine que ses formulaires de connexion ou de code. Un bouton "Continuer avec Google" ou un sélecteur de compte placé dans ce cadre n'est pas cliqué : une page qui ne propose que cela dans une iframe reste au menu.
- **Commits du cadre et compteur de navigation.** Un commit du cadre où la chaîne a agi fait avancer le compteur de navigation de la chaîne, comme un commit du cadre principal. Entre ce commit et l'analyse du nouveau document du cadre, une analyse du cadre principal sans formulaire peut lancer l'attente de fin (1,5 s) plus tôt que voulu. Même course que pour une navigation du cadre principal ; la fin n'arrive jamais moins de 4 s après le chargement.
