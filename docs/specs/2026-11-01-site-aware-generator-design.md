# Générateur conforme aux règles du site : conception

Date : 2026-11-01. Statut : spec à relire par l'utilisateur.
Premier des quatre chantiers du « un clic partout » (générateur, banc sur vrais sites, inscription en un clic, réentraînement du classifieur). S'appuie sur `2026-10-28-smart-fill-design.md` (D2 : rien n'est envoyé hors connexion) sans en changer les règles de sécurité.

## 1. But

Demande de l'utilisateur : à l'inscription, OnePass génère un mot de passe que l'utilisateur ne voit jamais, le met dans le champ du mot de passe et dans celui de confirmation, toujours long et complexe, mais réglable (lisible, ou longueur adaptée à ce que le site demande : plus de 8, plus de 12, moins de 20).

Critères de réussite :

- le mot de passe généré respecte toutes les contraintes lisibles du champ (attributs, `passwordrules`, consignes écrites, exceptions connues du site) dans 100 % des cas satisfiables du laboratoire ;
- à contraintes égales, il est le plus long et le plus riche que le site accepte, dans la limite du profil ;
- un mot de passe généré n'est jamais perdu : il est dans le coffre avant que le formulaire parte ;
- le même calcul sert l'extension (Chrome, Safari) et l'AutoFill système (iPhone, iPad, Mac) ;
- génération en moins de 5 ms côté hôte.

## 2. Existant

- `core/onepass-core/src/generator.rs` : recettes `Random`, `Passphrase`, `Pin`, tirage sans biais. Aucune notion de site.
- `core/onepass-ffi/src/rules.rs` : lecteur du langage `passwordrules` d'Apple, utilisé seulement par l'extension AutoFill iOS (`CredentialProviderViewController.generatePasswords`), avec les règles que le système transmet (champ, confirmation, exceptions Apple).
- `core/onepass-bridge/src/service.rs` (`generator_recipe`) : l'extension demande `{ kind: "smart" }` et reçoit 20 caractères avec symboles, quel que soit le site.
- `extension/src/background/fill.ts` (`fillGenerated`) : le mot de passe va déjà dans `new_password` et `confirm_password`.
- `extension/src/background/chain/save-flow.ts` (`rememberGenerated`) : le mot de passe généré attend en mémoire, et n'est enregistré qu'à l'envoi détecté. Si l'envoi n'est pas détecté, ou si le coffre se verrouille, le mot de passe est perdu alors que le site l'a peut-être reçu.

## 3. Décisions

- **G1, un seul moteur de contraintes dans le core.** `rules.rs` passe de `onepass-ffi` à `onepass-core` (`generator/rules.rs`) et devient un module de contraintes général. L'hôte natif (extension) et l'FFI (Apple) l'appellent tous les deux.
- **G2, quatre sources, la plus stricte gagne.** Attributs HTML (`minlength`, `maxlength`, `pattern`), attribut `passwordrules`, consignes écrites près du champ, base d'exceptions par domaine. Les contraintes se combinent par intersection.
- **G3, contradiction : on lâche la source la moins sûre.** Ordre de confiance, du plus sûr au moins sûr : `passwordrules` et attributs du champ, exceptions connues, consignes écrites. Tant que l'ensemble est insatisfiable, la source la moins sûre est retirée. Sans aucune contrainte satisfiable, la recette du profil s'applique seule, avec un avertissement dans le rapport.
- **G4, `pattern` vérifié par le navigateur.** Le core ne compile pas d'expression régulière (pas de dépendance `regex`, et la syntaxe JavaScript diffère). Le content script teste le candidat avec `new RegExp("^(?:" + pattern + ")$", "v")`, comme le navigateur le fait. En cas d'échec, l'extension redemande avec une recette plus étroite (section 6.3), trois fois au plus.
- **G5, profils réglables, « Fort » par défaut.** Trois profils (section 5). Réglage par appareil : `chrome.storage.local` pour l'extension, `UserDefaults` du groupe d'app pour Apple. La synchronisation du réglage entre appareils est hors périmètre.
- **G6, jamais affiché, jamais perdu.** Le mot de passe n'apparaît dans aucune interface de page ni de menu. Il est écrit dans le coffre comme élément en attente au moment du remplissage, avant tout envoi (section 7).
- **G7, base d'exceptions embarquée.** Le fichier `quirks/password-rules.json` du projet `apple/password-manager-resources` (licence MIT) est copié dans `core/onepass-core/data/`, à un commit figé, avec un script de mise à jour. Aucun appel réseau à l'exécution.

## 4. Contrats

### 4.1 Contexte du champ

Construit par le content script pour le champ de nouveau mot de passe (et sa confirmation). Aucune valeur saisie.

```
PasswordContext {
  origin: String,               // origine du cadre, pour la base d'exceptions
  rules: Vec<String>,           // attributs passwordrules du champ et de la confirmation
  min_length: Option<u32>,      // minlength
  max_length: Option<u32>,      // maxlength (le plus petit des deux champs)
  hint_text: Option<String>,    // consignes écrites, 600 caractères au plus
  has_pattern: bool,            // le champ porte un pattern (testé côté page, G4)
}
```

`hint_text` réunit, dans cet ordre et sans doublon : le texte des éléments de `aria-describedby`, puis les éléments de texte du même formulaire situés après le champ et à moins de trois frères de distance, chacun coupé à 200 caractères.

Sur Apple, le contexte vient de `ASGeneratePasswordsRequest` : `rules` = règles du champ, de la confirmation et des exceptions du système ; les autres membres restent vides.

### 4.2 Contraintes

```
Constraints {
  min_length: u32,              // 1 par défaut
  max_length: Option<u32>,
  allowed: CharSet,             // ASCII imprimable par défaut
  required: Vec<CharSet>,       // une classe à fournir au moins une fois chacune
  forbidden: CharSet,           // retirés de allowed (consignes « sans espace », etc.)
  max_consecutive: Option<u32>,
}
```

### 4.3 Requête et réponse

Requête de l'extension, champ ajouté au `Recipe` existant de `onepass-bridge/src/api.rs` :

```
Recipe { kind, length?, symbols?, context?: PasswordContext, narrow?: u8 }
```

`narrow` (0 à 2) est le niveau de repli après un échec du `pattern` (section 6.3).

Réponse : le mot de passe, plus un rapport sans secret, utilisé par le banc de test (chantier 2) :

```
GenerationReport {
  length: u32,
  classes: [lower, upper, digit, special],   // classes présentes
  sources: [Attributes | PasswordRules | Hints | Quirks],  // sources retenues
  dropped: [source],                          // retirées pour contradiction (G3)
  fallback: bool,                             // aucune contrainte satisfiable
  entropy_bits: f64,
}
```

Côté FFI, `password_from_rules(rules, fallback)` garde sa signature et appelle le nouveau module ; une fonction `password_for_context(context, profile)` est ajoutée.

## 5. Profils

| Profil | Sans contrainte du site | Avec contraintes |
|---|---|---|
| **Fort** (défaut) | 24 caractères, minuscules, majuscules, chiffres, symboles | la plus grande longueur permise jusqu'à 32, toutes les classes permises |
| **Lisible** | 5 mots français (diceware), séparateur `-`, une majuscule et un chiffre | nombre de mots ajusté entre 3 et 8 pour tenir dans la longueur ; majuscule, chiffre ou symbole ajoutés si exigés ; séparateur pris dans les symboles permis, sinon aucun |
| **Personnalisé** | longueur et classes choisies par l'utilisateur | les choix de l'utilisateur, resserrés par les contraintes du site |

Règles communes :

- longueur plafonnée à 64 ;
- sans `maxlength` ni règle de longueur, « Fort » s'arrête à 24 : certains sites tronquent sans le dire ;
- les symboles proposés par défaut restent ceux de `generator.rs` (`-_.!?#@$%&*+=`) ; un site qui en exige d'autres les obtient par `allowed` ;
- « Lisible » qui ne tient pas dans la longueur maximale bascule sur « Fort », avec avertissement dans le rapport ;
- le PIN reste une recette à part, hors profils.

## 6. Lecture des sources

### 6.1 Attributs et `passwordrules`

Lecture actuelle de `rules.rs` conservée (propriétés inconnues ignorées, valeur mal formée qui rend la règle illisible). `minlength` et `maxlength` deviennent `min_length` et `max_length`. Un `maxlength` inférieur à 4 est ignoré (champ mal codé).

### 6.2 Consignes écrites

Lecteur déterministe en Rust, français et anglais, insensible à la casse et aux accents. Motifs reconnus :

- longueur : « 8 à 20 caractères », « entre 8 et 20 », « au moins 12 », « minimum 8 », « 20 caractères maximum », « between 8 and 64 », « at least 12 », « up to 16 », « 8+ characters » ;
- classes exigées : « une majuscule », « un chiffre », « un caractère spécial », « one uppercase », « a number », « a symbol » ;
- classes interdites : « sans espace », « sans caractères spéciaux », « lettres et chiffres uniquement », « no spaces », « alphanumeric only » ;
- symboles listés : « parmi !@#$% » ou « (!@#$%^&*) » restreint les symboles permis à cette liste.

Un nombre hors de 1 à 128 est ignoré. Le texte est lu tel quel, jamais exécuté ; au-delà de 600 caractères il est coupé.

### 6.3 `pattern` et repli

Le content script teste le candidat avant de remplir. En cas d'échec, l'extension redemande avec `narrow` :

1. `narrow = 1` : sans symboles ;
2. `narrow = 2` : minuscules et chiffres seulement, longueur gardée.

Après trois échecs, rien n'est rempli et l'utilisateur voit « Ce site refuse le mot de passe généré », avec un lien vers le générateur de l'app. Aucun candidat refusé n'est gardé.

### 6.4 Base d'exceptions

Recherche par domaine enregistrable puis par domaine parent. La règle trouvée s'ajoute à `rules`. Le fichier est lu une fois et gardé en mémoire (environ 40 Ko).

## 7. Jamais affiché, jamais perdu

1. Au remplissage d'un mot de passe généré sur une page d'inscription, l'extension écrit aussitôt un élément Login en attente dans le coffre : site, identifiant s'il est connu, mot de passe, tag `onepass:pending`. Opération hôte `save_pending`, même contrôle d'origine que `save`. Une page de réinitialisation ou de changement n'écrit rien en attente : le mot de passe est seulement retenu, et à l'envoi la proposition de mise à jour vise le Login que l'utilisateur a déjà.
2. L'envoi détecté (flux existant de `save-flow.ts`) confirme l'élément : le tag tombe, l'identifiant final est complété.
3. Sans envoi détecté, l'élément reste en attente. Le prochain remplissage du même site le propose en premier. Au bout de 30 jours sans usage, OnePass le signale dans Watchtower ; il n'est jamais supprimé sans l'utilisateur.
4. Une nouvelle génération sur le même onglet et le même site remplace le mot de passe de l'élément en attente, l'ancien part dans `password_history`.
5. Le menu et la fenêtre de l'extension n'affichent jamais la valeur. L'app la montre seulement sur demande, comme tout mot de passe.

## 8. Sécurité

- Le texte de page (`hint_text`, règles) est une donnée non fiable : tailles bornées, aucune évaluation, lecture en temps linéaire.
- Le tirage reste celui de `generator.rs` : CSPRNG, rejet sans biais de modulo.
- Le rapport ne contient aucun caractère du mot de passe.
- Les règles de D2 ne changent pas : à l'inscription, rien n'est envoyé.
- Entropie minimale : en dessous de 60 bits (site qui impose par exemple 6 chiffres), le remplissage a lieu mais le rapport et l'élément portent l'avertissement « mot de passe faible imposé par le site ».

## 9. Tests

- **Unitaires** : chaque motif de consigne (français et anglais), chaque source, chaque contradiction de G3, chaque profil.
- **Propriétés** (`proptest`, déjà dans le core) : pour 10 000 jeux de contraintes tirés au hasard, tout mot de passe produit les respecte, ou la réponse est un repli signalé ; jamais de longueur au-delà de 64.
- **Corpus de consignes** : 200 consignes réelles tirées des 3087 pages du corpus top 1000 (`extension/lab/corpus/samples/top1000`), contraintes attendues écrites à la main, taux de lecture correct visé à 95 %.
- **Laboratoire** : nouvel axe des mondes synthétiques, des sites d'inscription avec règles côté serveur (longueur, classes, `pattern`, consignes écrites). Le serveur refuse un mot de passe hors règles ; le critère est zéro refus pour les cas satisfiables.
- **Non-régression** : `password_from_rules` donne le même comportement sur les tests existants de `onepass-ffi/tests/rules.rs`.

## 10. Hors périmètre

- Synchronisation du profil entre appareils.
- Changement automatique du mot de passe d'un compte existant.
- Banc sur vrais sites (chantier 2), qui consommera le `GenerationReport`.
- Remplissage de l'identité à l'inscription et passkeys (chantier 3).
