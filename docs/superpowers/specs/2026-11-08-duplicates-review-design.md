# Doublons : revue en deux niveaux

Date : 2026-11-08. Statut : approuvée par le fondateur le 2026-11-08 (design présenté en conversation).
Complète `2026-11-03-duplicates-design.md` : la détection et la fusion restent celles-là.

Demande : la page « Doublons possibles » était illisible (deux éléments bruts côte à côte, « Diffère : mot de passe, champs » sans valeur). Pour chaque groupe : une description claire de l'élément, puis exactement ce qui diffère entre les copies, en lignes de champs. Ensuite un traitement par lots en deux niveaux de confiance.

## 1. Lignes de différence (noyau, `duplicates/review.rs`)

`review(copies)` compare les copies d'un groupe, la principale suggérée en premier. Une ligne n'existe que si les copies diffèrent. Chaque ligne porte une valeur par copie (ou rien), un drapeau « secret » (mot de passe, champ masqué, TOTP, phrase de récupération) et la copie gagnante par défaut.

| Genre | Cas | Fusion |
|---|---|---|
| `Added` | une seule copie a la valeur ; un site, une étiquette, un fichier, une passkey en plus ; une note qui contient les autres | gardé, aucune question |
| `Kept` | titres différents (celui de la principale gagne) ; mots de passe différents dont un seul n'est dans aucun historique (les autres sont d'anciens mots de passe réenregistrés) | gagnant sans question |
| `Conflict` | deux valeurs différentes pour le même champ : mot de passe, identifiant, secret TOTP, numéro, autre champ ; deux notes différentes | l'utilisateur choisit |

Identifiant : casse et espaces ignorés. TOTP : comparé décodé (URI ou base32). Gagnant par défaut d'un conflit : la copie modifiée le plus récemment ; pour deux notes, « garder les deux ».

Confiance : `Sure` sans aucun conflit, `Review` sinon.

## 2. Fusion avec réponses (`merge_with`)

Une réponse (`Choice`) nomme la copie dont la valeur gagne pour un sujet (`title`, `notes`, `password` ou un identifiant de champ). Rien n'est perdu :

- mot de passe : celui de la principale passe dans l'historique ;
- autre champ : la valeur remplacée devient un champ « libellé (titre de la principale) » de la section `merged`, jamais rempli automatiquement ;
- notes : la note choisie seule ; les autres restent dans les copies archivées. `from: None` garde toutes les notes (fusion d'origine).

`merge` = `merge_with` sans réponse.

## 3. Lot sûr (`Repository::merge_sure_duplicates`)

L'app envoie les identifiants des groupes cochés. Le noyau refait l'analyse au moment d'écrire et ne fusionne que les groupes encore `Sure`, avec les réponses par défaut. Un groupe disparu ou devenu conflictuel entre-temps est laissé tel quel. La note des copies archivées vient d'un modèle de l'app où `{title}` devient le titre gardé.

## 4. Page (Mac, iPad, Vision Pro en page ; iPhone empilé)

- En-tête : nombre de groupes sans risque et à vérifier.
- « Fusion sûre » : une ligne par groupe (case cochée, icône, titre, identifiant, nombre de copies, coffres) et « Ajoute : site …, tag … » (jamais de valeur secrète). Bouton « Fusionner la sélection (N) ». Menu « … » : Pas des doublons, Archiver les autres, Supprimer les autres.
- « À vérifier » : un groupe à la fois (« 1 sur N », précédent, suivant), la question (« Les mots de passe diffèrent. Lequel est le bon ? »), le tableau des lignes qui diffèrent (une colonne par copie avec coffre et date, conflits en premier avec un choix par cellule), puis « Fusionner avec ces choix », « Ce ne sont pas des doublons », « Passer ».
- Secrets masqués, œil pour afficher 30 s, masqués au verrouillage ; jamais d'œil pour un élément qui demande une confirmation (`reprompt`).
- Chaînes `duplicates.*` en fr, en, es, it.
