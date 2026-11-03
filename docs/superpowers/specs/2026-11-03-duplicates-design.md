# Doublons : détection, fusion, revue

Date : 2026-11-03. Statut : approuvée en autonomie (course parallèle, rulings dans `.superpowers/sdd/2026-11-03-duplicates/progress.md`).
Demande du fondateur : une notification sur l'accueil, sous la barre de recherche et au-dessus de « Tous les éléments » et « Favoris », pour gérer les doublons ; fusionner, archiver ou supprimer deux éléments qui se ressemblent beaucoup.

## 1. Détection (noyau, `onepass-core/src/duplicates.rs`)

Un groupe naît seulement de signaux forts, entre deux éléments vivants du même compte :

| Signal | Condition |
|---|---|
| `SameLogin` | même type, un domaine enregistrable commun (eTLD+1 par la Public Suffix List, crate `psl`, sur les sites, les liens d'app et un champ `host`), même identifiant normalisé (`username`, sinon `email`, sinon `address`, en minuscules) |
| `SameTotp` | même secret TOTP, comparé décodé (URI `otpauth://` ou base32), par un hash |
| `SameCardNumber` / `SameDocumentNumber` | même numéro de carte (chiffres) ou de pièce (carte d'identité, passeport, permis, sécurité sociale), même type |
| `SameTitleAndUsername` | même type, même titre et même identifiant, aucun site ni lien d'app des deux côtés |

Jamais un doublon : même mot de passe sur le même domaine avec d'autres identifiants (réutilisation, déjà dans Watchtower), un élément archivé, à la corbeille, en attente (`onepass:pending`) ou le profil, deux copies du même identifiant d'élément (un déplacement interrompu). Les groupes sont la fermeture transitive des paires. Plusieurs coffres d'un même compte : oui, chaque copie dit son coffre. Plusieurs comptes de l'appareil : jamais (une session = un compte). Les coffres masqués par l'app sont exclus.

Un groupe sans aucune copie modifiable (toutes dans des coffres partagés en lecture seule) n'est pas montré. La copie principale suggérée est toujours modifiable : celle qui a passkey ou TOTP, puis la plus récemment modifiée, puis la plus remplie.

« Pas des doublons » : chaque copie modifiable reçoit l'étiquette cachée `onepass:distinct:<id hex de l'autre>`, chiffrée et synchronisée avec l'élément, écrite sans changer `updated_at`. Une paire est écartée si l'un des deux côtés la porte. Une nouvelle copie crée de nouvelles paires : le groupe revient. Le FFI retire ces étiquettes de `tags` et les remet à l'enregistrement. Watchtower (`Duplicate`) respecte aussi ce choix.

## 2. Fusion (noyau, `duplicates::merge` et `repo::duplicates`)

- Principale : modifiable obligatoirement (`Validation("primary", "read only")`).
- Sites, liens d'app, lieux, méthodes de connexion, étiquettes visibles : union. Favori, re-demande, surveillance : gardés si une copie les a.
- Notes : celles des autres ajoutées sous une ligne `--- <titre> ---`.
- Champs : un champ vide de la principale prend la valeur ; un champ répétable (passkeys, codes de secours) reçoit les valeurs en plus ; un champ personnalisé absent est ajouté ; une valeur en conflit devient un champ supplémentaire « <libellé> (<titre de l'autre>) » dans une section `merged`, jamais rempli automatiquement. TOTP et passkeys sont donc toujours gardés.
- Mot de passe : celui de la principale ; les autres mots de passe et leur historique passent dans l'historique de la principale.
- Pièces jointes : copiées (relues, rescellées pour le coffre de la principale) ; les copies archivées gardent les leurs, intactes.
- Les autres sont archivées (pas supprimées) avec la note « Fusionné dans <titre> » fournie par l'app dans sa langue : désarchiver annule la fusion pour elles.
- Une copie en lecture seule n'est ni fusionnée ni archivée ; la principale la marque « pas un doublon ».
- Ordre d'écriture : pièces jointes, puis principale, puis archivage. Une coupure laisse au pire le groupe visible, rien n'est perdu ; refusionner n'ajoute rien.
- Autres actions : « Archiver les autres » et « Supprimer » (corbeille existante, restaurable), refusées pour une copie en lecture seule avant toute écriture.

## 3. Apps

- iOS et iPadOS, accueil : bannière compacte « N doublons possibles » avec chevron, sous la recherche et au-dessus des tuiles « Tous les éléments » et « Favoris » ; cachée à zéro ou quand l'utilisateur l'a fermée, jusqu'à l'apparition d'un nouveau groupe.
- Écran de revue : une carte par groupe, chaque copie (icône, titre, identifiant, coffre, date de modification, ce qui diffère), actions Fusionner (aperçu du résultat, choix de la principale), Archiver les autres, Supprimer, Pas des doublons.
- Chaînes sous clés sémantiques `duplicates.*`, en fr, en, es, it.
