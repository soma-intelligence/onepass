# OnePass jalon 5 (côté apps) : Watchtower, import, export, sauvegardes signées

Date : 2026-10-27
Statut : validée (auto-validation, règle permanente de Quentin)
Portée : apps Apple (Mac, iPhone, iPad, Vision Pro) et surface UniFFI. Le core et la CLI du jalon 5 sont faits (spec `2026-10-25-milestone-5-watchtower-import-design.md`).
Branche : `feat/m5-app-ui`, coupée de `feat/onepass-redesign` (c35cb67).

## 1. Audit de départ

Ce que l'app avait déjà :

- Watchtower : page Mac et onglet iPhone (cadran), score, force des mots de passe, huit cartes, réglage « Vérifier les fuites » (désactivé : aucune requête réseau), plages HIBP en k-anonymity avec `Add-Padding`, catalogues 2fa.directory en cache une semaine.
- Import : feuille `ImportSheet`, tous les formats de `import_formats()` atteignables (sources nommées et détection automatique), aperçu par type et avertissements, import dans un vault choisi.
- Sauvegarde chiffrée : `ExportBackupSheet`, atteignable seulement depuis les sorties de secours de « Données refusées ».

Écarts constatés (tous fermés par ce jalon) :

| # | Écart | Preuve |
| --- | --- | --- |
| G1 | Aucune restauration d'une archive `.onepass` : l'import refuse le fichier, la FFI n'expose ni `inspect` ni `open` ni `restore_plan`. | `ImportSheet.load`, `onepass-ffi/src/import.rs` |
| G2 | Signature de la sauvegarde jamais vérifiée côté app (pas d'ouverture du tout), donc pas d'erreur claire sur une archive modifiée. | idem |
| G3 | Pas d'export CSV en clair (FFI absente, aucune UI). | `onepass-ffi/src/hardening.rs` |
| G4 | La sauvegarde chiffrée n'est pas atteignable en temps normal (Réglages). | `SafeExitViews.swift` |
| G5 | Six contrôles du core sans carte : `provider_exposed`, `breached_site`, `wifi_insecure`, `ssh_weak`, `duplicate`, `wallet_no_backup`. Leurs constats sont calculés puis jetés. | `WatchtowerCard.all` |
| G6 | `breached_site` ne tourne jamais : la FFI passe `breaches: None`. | `onepass-ffi/src/watchtower.rs` |
| G7 | Aucune exclusion par item dans le détail ; la bannière passkey ne s'affiche jamais (`PasskeyOffer.offer` rend `nil`). | `ItemDetailView.swift` |
| G8 | Aucune notification Watchtower. | grep `UserNotifications` |
| G9 | Le résultat d'un import n'est qu'un toast avec un total, sans le détail par type ni les avertissements. | `ImportSheet.runImport` |

## 2. Surface FFI ajoutée (`onepass-ffi/src/archive.rs`, additive)

```rust
pub fn inspect_archive(bytes: Vec<u8>) -> Result<FfiArchiveInfo, OnePassError>;
impl Session {
    pub fn archive_info(&self, bytes: Vec<u8>) -> Result<FfiArchiveInfo, OnePassError>; // + mine
    pub fn preview_restore(&self, bytes: Vec<u8>, passphrase: Option<Vec<u8>>) -> Result<FfiRestoreSummary, OnePassError>;
    pub fn restore_archive(&self, bytes: Vec<u8>, passphrase: Option<Vec<u8>>) -> Result<FfiRestoreSummary, OnePassError>;
    pub fn export_plaintext_csv(&self, vault_ids: Vec<String>) -> Result<Vec<u8>, OnePassError>;
}
```

- `FfiArchiveInfo` : type (export ou sauvegarde), date, schéma, `newer_version`, `has_passphrase`, `signed`, `for_this_account` (vrai quand le destinataire compte est le compte ouvert).
- Choix de l'ouverture, comme `onepass backup restore` : destinataire compte égal au compte ouvert : `Unlock::Account` (la signature hybride est vérifiée, aucune saisie). Sinon phrase de passe ; sans phrase, `InvalidInput("archive passphrase")`. Archive d'un autre compte sans phrase : `InvalidInput("archive of another account")`.
- Erreurs : signature absente ou fausse : `Integrity { kind: "signature" }` ; bit modifié : `Integrity { kind: ... }` de l'AEAD ; mauvaise phrase : `WrongPassword` ; schéma futur : `InvalidInput("archive from a newer version")`.
- `preview_restore` ouvre, planifie (`restore_plan`) et compte sans rien écrire. `restore_archive` valide chaque item avant la première écriture, crée les vaults manquants, écrit, puis émet une époque de restauration (`EpochReason::Restore`). Corbeille et archivés restaurés tels quels, aucun écrasement (spec core 5.5).
- `FfiRestoreSummary` : `kind`, `created_at`, `vaults_created`, `items` (à restaurer ou restaurés), `by_type`, `skipped`, `signature_verified`, `epoch: Option<u64>`.
- `export_plaintext_csv` : `export::csv_plaintext` sur les vaults donnés (tous si vide), corbeille exclue, comme la CLI.
- `FfiWatchtowerOptions.breach_catalog: Option<Vec<u8>>` (HIBP `/api/v3/breaches`, sans clé) branché sur `BreachCatalog::from_hibp`. Ajout en fin de record.

## 3. VaultKit

- `VaultSession+Archive.swift` : `archiveInfo`, `previewRestore`, `restoreArchive`, `exportPlaintextCSV`. Phrases de passe en `SecretBytes`, octets effacés après usage.
- `PlaintextExportFile` : nom `OnePass export non chiffré <jour>.csv`, écriture en mode 0600, jamais d'écrasement, protection complète sur iOS, dossier temporaire balayé au lancement (même modèle que `EncryptedBackupFile`).
- `WatchtowerFetcher.breachCatalog(allowNetwork:)` : catalogue entier, en cache une semaine, plafond 16 Mio. Rien sur les sites du coffre ne sort.
- `WatchtowerAlerts` (logique pure, TDD) : à partir d'un rapport, l'ensemble des constats alertables (`compromised`, `breached_site`, `provider_exposed`, `expired`, `expiring`) sous forme d'empreintes SHA-256 tronquées de `check|item_id` ; compare avec l'ensemble mémorisé, rend les nouveautés par contrôle. Premier passage : mémorise sans notifier. Les ids d'items ne sont jamais stockés en clair.
- `WatchtowerExclusions` (logique pure, TDD) : contrôles excluables d'un item, ajout et retrait sans doublon.

## 4. Apps

- Réglages > Général, section « Sauvegarde et export » : « Exporter une sauvegarde chiffrée… » (feuille existante), « Restaurer une sauvegarde… », « Exporter en CSV non chiffré… ». Mac : aussi Fichier > Restaurer une sauvegarde….
- `RestoreSheet` : choix du fichier (`.onepass`), en-tête lu sans secret, phrase de passe demandée seulement si l'archive n'est pas pour ce compte, aperçu (vaults créés, items par type, items déjà présents), puis restauration et résultat. Badge « Signature vérifiée » quand l'ouverture passe par le compte. Archive modifiée : « Cette sauvegarde a été modifiée ou abîmée : sa signature ne correspond pas. Rien n'a été restauré. »
- `ImportSheet` : un fichier `.onepass` ouvre `RestoreSheet` avec les mêmes octets au lieu d'une erreur ; après import, une étape résultat (items écrits par type, avertissements, ignorés) remplace le toast.
- `PlaintextExportSheet` : avertissement appuyé (fichier lisible par toute personne ou app qui y accède, tableur pouvant exécuter des formules, passkeys et lieux absents), case « Je comprends » obligatoire, mot de passe maître redemandé, choix des vaults, enregistrement (Mac : panneau avec second avertissement pour un dossier cloud ; iOS : feuille de partage, copie temporaire supprimée à la fermeture).
- Watchtower : six cartes neuves (G5), `breached_site` alimentée par le catalogue HIBP quand « Vérifier les fuites » est actif. Réglage « Me prévenir » (notifications locales, désactivé par défaut, demande d'autorisation à l'activation). Texte de notification sans titre d'item ni hôte (écran verrouillé).
- Détail d'un item : section « Watchtower » qui liste les constats du dernier rapport pour cet item, avec « Ignorer pour cet élément », et les contrôles ignorés avec « Rétablir ». Bannière passkey alimentée par le rapport.

## 5. Hors périmètre

Sauvegarde automatique planifiée, pièces jointes, export Credential Exchange, sélection d'items à restaurer.

## 6. Rulings

1. Ruling: ouverture par le compte quand l'en-tête le désigne, sinon phrase - même règle que la CLI, et c'est le seul chemin où la signature est vérifiable (la clé publique d'un autre compte n'est pas connue) - une archive d'un autre compte restaurée par phrase n'a que l'intégrité AEAD ; l'aperçu l'indique (pas de badge).
2. Ruling: restauration toujours précédée d'un aperçu qui ouvre l'archive une première fois - l'utilisateur voit ce qui sera écrit - un second Argon2id pour les archives à phrase (quelques secondes).
3. Ruling: époque de restauration émise après écriture, échec rapporté sans annuler - comportement de la CLI - les autres appareils peuvent refuser l'état restauré jusqu'à une nouvelle émission ; message dédié.
4. Ruling: CSV en clair exige mot de passe maître et case cochée - c'est la sortie la plus dangereuse de l'app - une étape de plus.
5. Ruling: notifications désactivées par défaut, empreintes tronquées au lieu d'ids - pas de demande d'autorisation au premier lancement, aucune métadonnée en clair dans les préférences - un utilisateur qui ne les active pas n'est pas prévenu.
6. Ruling: notifications calculées quand un rapport aboutit (app ouverte), pas de tâche de fond - pas de déchiffrement hors session - une fuite n'est signalée qu'à la prochaine ouverture.
7. Ruling: catalogue HIBP des fuites téléchargé en entier - rien sur le coffre ne sort - environ 1 Mio par semaine.
8. Ruling: tout contrôle d'un constat est excluable depuis le détail, y compris `reused` et `duplicate` - le core accepte tout identifiant et l'utilisateur reste maître - un constat ignoré par erreur se rétablit depuis la même section.
