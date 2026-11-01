# Pièces jointes : conception

Date : 2026-10-31. Demande du propriétaire : pouvoir garder un PDF (ou tout fichier) avec n'importe quel élément, par exemple les documents liés à un compte.

## Ce que voit l'utilisateur

- La fiche de tout élément montre une section « Pièces jointes » : nom, taille, et une ligne « Ajouter un fichier… » (20 Mo au plus par fichier, 32 fichiers au plus par élément).
- Un clic ouvre l'aperçu dans l'app (PDF avec PDFKit, image). Le lecteur est minimaliste : pages sur un fond gris clair avec une ombre légère, un bouton rond en Liquid Glass pour fermer, une capsule en Liquid Glass en bas (nom du fichier, page, exporter). Il reste en apparence claire, comme une feuille, quel que soit le thème de l'app. Le menu de la ligne propose Aperçu, Exporter… (panneau d'enregistrement du système) et Supprimer… (avec confirmation).
- Les fichiers suivent l'élément : modification, corbeille, archive, déplacement vers un autre coffre. Supprimer l'élément définitivement efface ses fichiers.
- Un fichier pas encore arrivé par la synchro donne « Ce fichier n'est pas encore arrivé sur cet appareil ».

## Format

- Chaque pièce jointe a sa propre clé aléatoire de 256 bits.
- Le fichier est découpé en tranches de 512 Kio (`attachment::CHUNK`). Chaque tranche est un enregistrement de type `RecordKind::Attachment` (code 25), donc aucun enregistrement ne dépasse la limite de synchro de 900 Kio.
- Données d'une tranche : `vault_id (16 octets) || postcard(AttachmentChunk { attachment_id, index, count, wrapped_key, blob })`. Elle a le même préfixe qu'un enregistrement d'item, donc la synchro la rattache à son coffre : attente, Mode Voyage, coffre supprimé, rotation.
- Identifiant d'une tranche : l'identifiant de la pièce jointe pour la tranche 0. Pour les autres, les 16 premiers octets de `SHA-256("onepass/attachment-chunk/v1" || id || index BE)`.
- Le contenu d'une tranche est scellé sous la clé de la pièce jointe : type `Attachment`, contexte `(id de la tranche, sans vault)`.
- La clé de la pièce jointe est scellée sous la clé du vault : type `Attachment`, contexte `(id de la pièce jointe, id du vault)`. Elle est recopiée dans chaque tranche, donc chaque tranche s'ouvre seule.
- L'élément liste ses pièces jointes dans `Item.attachments` (`AttachmentRef { id, name, size, mime }`, déjà dans le format figé). Une version ancienne de l'app conserve donc la liste quand elle modifie l'élément.
- L'élément est couvert par le manifeste signé. La taille qu'il garde fixe le nombre de tranches et la longueur de chacune. Une tranche manquante, coupée, en trop, échangée ou d'une autre pièce jointe est refusée.

## Décisions

- **D1. Clé sous la clé du vault, pas sous la clé d'item** (écart à la spec d'architecture 4.2). La clé d'item change à chaque enregistrement. Une clé gardée dans le clair de l'item obligerait à changer le format figé de l'item, ou à ajouter une remorque qu'une version ancienne perdrait en modifiant l'élément (fichiers perdus). Le coût : un déplacement ou une rotation réenveloppe la clé de chaque tranche, sans rechiffrer les fichiers.
- **D2. Pièce jointe immuable.** Remplacer un fichier, c'est en ajouter un nouveau puis retirer l'ancien.
- **D3. Écritures : tranches d'abord, élément ensuite.** Un échec à l'enregistrement de l'élément efface les tranches écrites. Le retrait enregistre l'élément sans la pièce jointe, puis efface les tranches. Une coupure laisse au pire des tranches orphelines, jamais une référence sans fichier.
- **D4. Déplacement.** Les tranches sont réenveloppées après les deux manifestes. Si une coupure laisse des tranches sous l'ancien coffre, la lecture les réenveloppe (`heal_attachment`).
- **D5. Rotation v2.** Chaque tranche des coffres vivants est réenveloppée sous la nouvelle clé de vault, dans la même transaction, et poussée en phase 2. Les octets ne sont pas rechiffrés : un appareil révoqué qui avait déjà la clé d'une pièce jointe peut lire les octets qu'il avait déjà, comme pour les items qu'il avait déjà lus.
- **D6. Appairage.** L'instantané d'appairage n'emporte pas les tranches (limite de 50 Mio). Le nouvel appareil les récupère par la synchro, comme tout appareil.
- **D7. Synchro Apple.** `SyncCoordinator.isValid` accepte le type 25. Les tranches partent avant les items et les manifestes qui les listent.
- **D8. Archives et exports.** Ils n'emportent pas les fichiers (comme prévu au jalon 5). Un élément restauré garde ses références : les fichiers s'ouvrent s'ils sont encore sur le compte, sinon « pas encore arrivé ».
- **D9. Aperçu sans disque.** Les octets déchiffrés restent en mémoire (PDFKit, image). Ils ne passent par un fichier que sur un export choisi par l'utilisateur.

## Limites connues

- Les tranches orphelines (coupure entre deux écritures, élément supprimé par une version ancienne de l'app) ne sont pas encore ramassées.
- La CLI de développement ne lit ni n'écrit les pièces jointes.
- Le modèle formel ProVerif ne couvre pas encore le type `Attachment`.
- Le champ « Fichiers » du type Document reste en lecture seule. Les fichiers d'un Document passent par la section « Pièces jointes ».
