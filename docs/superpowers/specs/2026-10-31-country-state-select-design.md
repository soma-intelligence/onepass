# Extension : listes pays et état remplies avec intelligence

Date : 2026-10-31. Branche : `feat/extension-shadow-dom` (après Task 4, cd30551c). Statut : approuvée en autonomie (rulings en section 5). Demandée par Quentin, file du contrôleur.

## 1. But

Aujourd'hui `matchOption` (`extension/src/content/filler.ts`) ne retient qu'une option dont la valeur ou le texte est égal à la valeur de l'identité : « FR » ne choisit pas « France », « Rhone » ne choisit pas « 69 - Rhône », et une liste d'états rechargée après le choix du pays reste vide. Le but : choisir la bonne option comme le ferait une personne, ou ne rien choisir quand le doute existe.

## 2. Valeurs canoniques et ce que l'extension reçoit

- Le coffre garde `address.country` et `address.region` tels que saisis. Le pont les recopie sans transformation (`policy.rs`, `fill_identity`) ; `identity_country` de `compose.rs` lit le même champ, mis en majuscules, et le traite comme un code alpha-2 (choix de l'identité selon le TLD). La valeur attendue est donc **ISO 3166-1 alpha-2** pour le pays et **ISO 3166-2** pour la région (`US-CA`, `FR-75`, `FR-IDF`, `DE-BY`, `CA-QC`).
- L'extension tolère aussi les valeurs historiques : nom du pays (langues d'`Intl.DisplayNames` : langue de la page, fr, en), alpha-3, numérique ; pour la région, le code seul (`CA`, `75`, `BY`), le nom, l'abréviation (`Calif.`, `N.Y.`, `PACA`), l'exonyme (`Bavaria`, `Bavière`).

## 3. Comportement

1. **Pays** : la valeur est résolue en alpha-2 ; chaque option l'est aussi (par sa valeur puis son texte : alpha-2, alpha-3, numérique, nom en langue de la page, fr, en, quelques alias comme `USA`, `UK`). Comparaison sans accents, sans casse, sans ponctuation ; le texte entre parenthèses est ignoré en second essai (« France (+33) »).
2. **Région** : table embarquée (`content/geo/regions.ts`) : 50 états des États-Unis, DC et territoires ; provinces et territoires du Canada ; 13 régions métropolitaines, 96 départements et 5 départements d'outre-mer de France ; 16 Länder. Une option « 75 - Paris » est lue partie par partie : toutes les parties doivent désigner la même région. Un département choisit sa région quand la liste ne propose que des régions (parent), jamais l'inverse.
3. **Ordre et attente** : les champs région passent après le pays. Si la région ne trouve pas d'option tout de suite et qu'un pays vient d'être écrit (ou choisi dans un combobox), le remplisseur observe la page (MutationObserver, 2 s au plus, essais groupés) : liste rechargée, champ apparu ou remplacé, puis il écrit la région. Le compte synchrone de `fillForm` ne compte pas cette écriture différée.
4. **Code postal** : sans région dans l'élément, la région se déduit du code postal pour une liste ou un combobox (jamais pour un champ texte) : États-Unis par plages ZIP à 3 chiffres (exceptions à 5 chiffres pour les territoires du Pacifique), France par les deux premiers chiffres (Corse : 200 à 201 donne 2A, 202 à 206 donne 2B ; outre-mer : trois chiffres 971 à 976). Le pays vient de l'élément, sinon de la liste pays du formulaire.
5. **Combobox ARIA** (React-select, Downshift, MUI) : un champ `role=combobox`, `aria-autocomplete=list|both` ou `aria-haspopup=listbox` de rôle pays ou région reçoit le nom (langue de la page) comme une frappe, puis l'option `role=option` correspondante de sa liste (`aria-controls`, `aria-owns`, `aria-activedescendant`, sinon liste voisine) reçoit `mousedown`, `mouseup`, `click` : le chemin d'événements que le remplisseur et `submit.ts` utilisent déjà. Attente bornée de la liste (2 s).
6. **Égalité** : si les meilleures options ont des valeurs différentes (« Georgia » pays et état dans la même liste, « CA » sans pays connu), rien n'est choisi. Des doublons de même valeur (pays favoris en tête de liste) ne sont pas une égalité : la première est prise.
7. **Champ texte** : une région canonique `US-CA` s'écrit `CA` (États-Unis, Canada) ou le nom (France, Allemagne) ; `autocomplete=country-name` reçoit le nom du pays. Toute autre valeur s'écrit telle quelle, comme avant.

## 4. Exception à « champ caché jamais rempli »

Une `<select>` cachée qui **sert** le combobox visible en cours de remplissage reçoit la même option. Conditions, toutes requises : le combobox visible vient d'être rempli par OnePass pour le rôle pays ou région ; la `select` n'est pas visible ; elle est dans le plus proche conteneur du combobox (4 niveaux au plus) qui ne contient aucun autre champ visible ; une de ses options correspond à la même valeur, sans égalité. Justification : ces bibliothèques (select2, Chosen, composants « natifs cachés ») soumettent la `select` et non le texte affiché ; la personne qui choisit l'option dans le widget écrit aussi cette `select` par le script du widget. La règle des champs cachés vise les pièges (un champ caché qui aspire une donnée) : ici la valeur est publique, déjà écrite à côté, jamais un secret ni un autre rôle que pays ou région.

## 5. Rulings

- R1 : la règle d'égalité vaut pour les rôles pays et région seulement ; mois, années et autres rôles gardent la première correspondance (inchangé).
- R2 : l'égalité exacte de valeur ou de texte reste le premier essai, avant la résolution par code.
- R3 : sans pays connu, une région se résout dans toutes les tables ; plusieurs régions possibles font une égalité, donc rien.
- R4 : codes militaires américains (AA, AE, AP) hors table : aucune déduction.
- R5 : fixtures du labo écrites (pages synthétiques façon Shopify, Stripe, Amazon, site français, dans `extension/lab/fixtures/country-state/`) et rejouées en jsdom dès maintenant ; le passage navigateur demande une route du serveur du labo et un scénario, hors de ce lot (fichiers d'une autre tâche).
- R6 : la page « attend » au plus 2 s après le pays ; un oracle qui lit les champs plus tôt peut voir la région vide (point ouvert pour le labo).
