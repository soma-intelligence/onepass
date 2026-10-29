# Appairage inversé : le Mac affiche le code

Date : 2026-10-28
Statut : approuvée (demande du propriétaire : "execute ça")
Portée : complète la section 5 de `2026-10-26-milestone-2b-pairing-design.md` (protocole) et le ruling B13 (le Mac ne fait que se faire ajouter).

## 1. Ce que l'utilisateur obtient

1. Sur le Mac : Fichier > Configurer un appareil… (ou Réglages > Appareils) ouvre une fenêtre avec un grand QR code et, dessous, un code à 8 caractères (`K7QM-4XPR`). Les deux changent toutes les 30 s.
2. Sur le nouvel appareil : "J'ai déjà OnePass sur un autre appareil", le type d'appareil, puis "Scanner un QR code" (caméra, iPhone et iPad) ou "Saisir un code".
3. Les deux écrans affichent le même code à 6 chiffres. L'utilisateur confirme des deux côtés, le Mac demande Touch ID (sinon le mot de passe maître), envoie l'accès. Le nouvel appareil demande le mot de passe maître.
4. L'ancien sens (le nouvel appareil affiche `OPPAIR1:`, un iPhone ou un iPad le scanne) marche toujours.

## 2. Protocole

Seul le sens de la découverte change. Le nouvel appareil garde la paire de clés éphémère (c'est lui qui décapsule) ; l'hôte n'a pas de clé : il a un code.

- Code : 5 octets aléatoires. QR : `OPPAIR2:` + base32 (8 caractères). Saisie : les mêmes 8 caractères, `XXXX-XXXX`, casse, espaces et trait d'union ignorés, `0` lu `O` et `1` lu `I`.
- Service local : `_onepass-pair._tcp` (le même type), nommé `hex(SHA-256("onepass/pairing/rv/svc/v2" || code)[0..16])`. L'hôte publie un service par code vivant ; le nouvel appareil dérive le nom du code et se connecte à celui-là seul.
- `JoinHello` : `"OPH2" || postcard(Hello) || proof`, `Hello` étant celui de la version 1 avec un `session_id` tiré par le nouvel appareil, `proof = HMAC-SHA256(HKDF(code, "onepass/pairing/rv/proof/v2"), "OPH2" || postcard(Hello))`.
- L'hôte (`Host`) essaie chaque code vivant sans s'arrêter au premier succès, refuse un code expiré, enveloppe la clé de session avec l'étiquette `onepass/pairing/v2` et la transcription `SHA-256("OPPAIR2:<code>" || JoinHello)`, puis la suite est celle de la version 1 (code à 6 chiffres, canal, autorisation).
- Un Hello accepté épuise tous les codes. Cinq Hello refusés ferment l'hôte.

## 3. Rulings

- Ruling C1 : les 40 bits du code ne suffisent pas à un échange de clés authentifié, la preuve (HMAC) ne sert qu'à n'accepter que des Hello venus de qui connaît le code, et le code à 6 chiffres reste la défense contre l'homme du milieu - comme pour le Bluetooth - une chance sur un million par tentative.
- Ruling C2 : le nom du service dérive du code (hash) plutôt qu'un nom aléatoire - le nouvel appareil trouve l'hôte sans parcourir le réseau et un voisin qui tente un code n'use pas les essais d'un hôte qui n'est pas le sien - le hash est lisible sur le réseau (sécurité 15.8).
- Ruling C3 : plusieurs codes vivants (5) plutôt qu'un seul renouvelé - le code qu'on tape ne change pas pendant la frappe, il reste valable 120 s - un service Bonjour par code.
- Ruling C4 : le Mac ne prête pas d'éléments en session invitée - le sélecteur d'éléments n'existe que sur iPhone et iPad - une demande publique devant un Mac est refusée avec "Utilise ton iPhone ou ton iPad".
- Ruling C5 : un nouvel appareil en mode public n'a que l'ancien sens - personne n'affiche de code pour lui - le choix de la méthode disparaît.
