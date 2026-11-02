# Inscription en un clic : conception

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, rulings en section 8). Chantier 3 de l'autofill, après le générateur selon le site (chantier 1, `2026-11-01-site-aware-generator.md`).
S'appuie sur `2026-10-28-smart-fill-design.md` (moteur `fill_plan`, intention `Signup`, sauvegarde en attente), `2026-10-31-country-state-select-design.md` (listes pays et état) et le relais de clés d'accès de l'extension (`extension/src/background/passkey.ts`), sans en changer les règles de sécurité.

## 1. But

Sur un formulaire d'inscription, un clic remplit tout depuis l'identité de l'utilisateur (nom, e-mail, téléphone, adresse avec pays et état, date de naissance), met un mot de passe généré selon les règles du site, propose une clé d'accès à la place quand le site en crée, et enregistre le nouveau Login dès l'envoi. Jamais d'envoi sans le clic de l'utilisateur sur le bouton du site, ou sur un choix explicite de OnePass qui le nomme.

Ce qui existe déjà et reste tel quel : l'intention `Signup` de `fill_plan` (identité plus mot de passe généré, jamais d'envoi), le choix de l'identité (mémoire du site, pays du domaine, sinon menu), le mot de passe du générateur selon le site, le Login en attente (`onepass:pending`) écrit avant l'envoi puis confirmé à la soumission, les listes pays et état.

Ce qui manque, et que cette conception ajoute :

1. **La clé d'accès à la place.** Rien ne propose la clé d'accès quand le formulaire en offre une.
2. **L'inscription sans mot de passe.** Un formulaire « e-mail, nom, Créer un compte » sans champ mot de passe est lu comme une connexion (règle 6) : il n'a pas le plan d'inscription.
3. **L'identifiant du Login en attente.** Le Login en attente est écrit sans identifiant ; il ne le reçoit qu'à la soumission, si la soumission en porte un.
4. **La date de naissance.** La valeur `AAAA-MM-JJ` est écrite telle quelle : un champ `JJ/MM/AAAA` ou trois listes jour, mois, année restent faux ou vides.
5. **L'AutoFill système.** L'insertion de texte ne propose ni la date de naissance ni les parties de l'adresse, et les identités sont noyées dans la liste alphabétique.

Les alias d'e-mail (`2026-10-30-dev-secrets-aliases-design.md`, partie B) n'existent pas encore dans le code (aucun module `alias`, aucun fournisseur) : l'e-mail de l'identité est utilisé, comme aujourd'hui. Le plan d'inscription garde la place (groupe identité, rôle `email`) où un alias viendra.

## 2. Clé d'accès à la place

### 2.1 Perception

Un bouton dont le libellé parle de clé d'accès (`passkey`, `clé d'accès`, `security key` exclu) et pas de connexion (« Se connecter avec une clé d'accès » reste un bouton de connexion) prend la classe `passkey`. Elle est ajoutée à `ButtonClass` (core et extension), en fin d'énumération. Les boutons `passkey` sont gardés en tête avec `pay` et `create` quand la limite de 32 boutons coupe.

### 2.2 Décision (core)

- `FillPlan` gagne `passkey: Option<PasskeyOffer { form_ref, button_ref }>`, rempli seulement pour l'intention `Signup`, avec le premier bouton `passkey` du premier formulaire planifié qui en a un, et la raison `PasskeyOffered`.
- Un bouton `passkey` ne retient pas l'envoi automatique d'une connexion : « Utiliser une clé d'accès » à côté d'un formulaire de connexion est une autre façon d'entrer, pas un compte créé. Un formulaire d'inscription sans mot de passe qui montre ce bouton est une inscription (section 3), donc jamais envoyé seul.
- L'action du plan ne change pas : `Fill` ou `ShowMenu`.

### 2.3 Action (extension)

- Un plan d'inscription avec offre de clé d'accès ouvre le menu au lieu de remplir. En tête du menu, deux choix : « Créer le compte avec un mot de passe fort » (mis en avant) et « Créer une clé d'accès à la place ». Le reste du menu ne change pas.
- Mot de passe : le plan s'exécute comme avant (identité, mot de passe généré, Login en attente), sans envoi.
- Clé d'accès : seuls les groupes identité s'exécutent (le nom et l'e-mail que le site enverra avec la création), aucun mot de passe n'est généré ni enregistré ; puis le travailleur arme la création de clé d'accès pour ce document, et le content script clique le bouton `passkey` du plan après avoir relu sa classe (un bouton relabellisé depuis le plan est refusé).
- Armement : une seule création, dans les 15 s, pour cet onglet, ce cadre principal, ce document et ce site, compte comme faite sous activation. Il ne fait qu'ouvrir la fenêtre de choix OnePass : la création demande toujours un clic de confiance dans cette fenêtre, comme aujourd'hui. Sans armement ni activation, le navigateur garde la main (inchangé).
- La clé d'accès créée est enregistrée par l'hôte (`passkey_create`), comme toute création.

## 3. Inscription sans mot de passe (core)

Nouvelle règle 4 bis de `fill_plan::intent`, après la règle 4 : sans aucun champ mot de passe ni code, un formulaire est une inscription si son détecteur dit `signup`, ou s'il a un bouton `create` ou `passkey` et des mots d'inscription ; et il porte au moins un identifiant ou un champ d'identité. Il a donc le groupe identité (e-mail aussi dans `username`) et jamais d'envoi automatique. Un formulaire de connexion qui montre un lien « Créer un compte » n'a pas de mots d'inscription dans ses propres titres et boutons de connexion : il reste une connexion, sauf si son détecteur dit `signup`.

## 4. Identifiant du Login en attente (extension)

Quand le groupe identité du plan a écrit l'e-mail dans un champ `email` ou `username` de ce formulaire, cet e-mail devient l'identifiant du Login en attente (`savePending`, `username`). L'e-mail arrive au travailleur par `fill_identity` comme aujourd'hui et n'est gardé que le temps de l'appel. La soumission garde le dernier mot : si l'utilisateur change l'adresse avant d'envoyer, `confirm_pending` reçoit l'adresse envoyée.

## 5. Date de naissance (extension, remplisseur)

`bday` reste un seul rôle (le classifieur n'est pas touché). Le remplisseur lit le champ et écrit la bonne forme de `AAAA-MM-JJ` :

1. `input[type=date]` : `AAAA-MM-JJ`.
2. Partie seule, par `autocomplete` (`bday-day`, `bday-month`, `bday-year`, lus comme le rôle `bday`), sinon par `name`, `id`, `placeholder` ou libellé (`day`, `jour`, `dd`, `jj` ; `month`, `mois`, `mm` ; `year`, `année`, `yyyy`, `aaaa`), sinon, pour une liste, par ses options (1 à 31, 12 mois, années sur quatre chiffres) : la partie (jour et mois sans zéro de tête pour une liste dont les valeurs n'en ont pas).
3. Champ texte entier : le motif lu dans `placeholder` ou `pattern` (`JJ/MM/AAAA`, `MM/DD/YYYY`, `DD.MM.YYYY`, `YYYY-MM-DD`, séparateurs `/`, `.`, `-`) ; sans motif, l'ordre de la langue de la page (`en` et `en-US` mois d'abord, sinon jour d'abord) avec `/`.
4. Liste des mois : par numéro, puis par nom (langue de la page, `fr`, `en`, abrégé ou entier), comme `matchOption`.

Une partie qu'aucune règle ne désigne n'est pas écrite (rien d'inventé dans le champ).

## 6. AutoFill système (Apple)

`ASCredentialProviderViewController` ne voit pas la page : pas de plan d'inscription. Périmètre honnête, ce qui existe déjà :

- mot de passe fort selon les règles du site (`ASGeneratePasswordsRequest`, iOS 26.2+, chantier 1) ;
- enregistrement après l'envoi (`ASSavePasswordRequest`) ;
- création de clé d'accès (`prepareInterface(forPasskeyRegistration:)`).

Ajouts :

- insertion de texte : les identités en tête de la liste « Choisis un élément » (l'insertion sert surtout aux formulaires d'inscription et d'adresse), le reste par titre comme avant ;
- la date de naissance (et tout champ date) s'insère en date numérique de la langue de l'appareil ;
- une adresse s'insère par parties : rue, complément, ville, code postal, région, pays, chacune une ligne (le pays en nom complet de la langue de l'appareil quand c'est un code ISO).

L'extension Safari sur iPhone, iPad et Mac a le plan complet, comme Chrome.

## 7. Sécurité

- Aucun envoi automatique d'inscription : l'intention `Signup` n'en a jamais (moteur, `planner.ts`, content script). Le clic sur le bouton de clé d'accès suit le choix explicite « Créer une clé d'accès à la place » de l'utilisateur, nomme le bouton qu'il clique, et relit sa classe au moment du clic.
- L'armement de clé d'accès est à usage unique, borné à 15 s, au cadre principal, au document et au site du menu ; une navigation ou un nouveau menu l'efface. Il n'ouvre qu'une fenêtre de choix, jamais une signature.
- `PageContext` reste une entrée hostile : la nouvelle classe de bouton ne change aucune borne ; la cible `plan_fill` du fuzz la couvre par la désérialisation.
- La date de naissance et les parties d'adresse sont des valeurs de l'identité déjà remplissables : aucun nouveau secret ne circule.

## 8. Rulings

- R1 : clé d'accès proposée seulement quand le formulaire montre un bouton de création de clé d'accès. Le site détient le défi WebAuthn : OnePass ne peut pas appeler `create` à sa place, il doit déclencher le parcours du site. Coût si faux : les sites qui proposent la clé d'accès seulement après l'inscription n'ont pas l'offre (ils l'ont déjà par le relais à leur appel).
- R2 : sur ces formulaires, le clic ouvre le choix au lieu de remplir : les deux chemins s'excluent (un Login en attente serait écrit pour rien). Coût si faux : un clic de plus sur ces sites seulement.
- R3 : un bouton `passkey` ne retient pas l'envoi automatique d'une connexion (beaucoup de pages de connexion montrent « Utiliser une clé d'accès ») ; « Se connecter avec une clé d'accès » n'est même pas `passkey` (mots de connexion). Les formulaires d'inscription qui le montrent sont des inscriptions (règle 4 ou 4 bis). Coût si faux : une inscription sans mot de passe ni mots d'inscription, lue comme connexion, pourrait être envoyée par la chaîne avec un Login du site.
- R4 : armement de 15 s plutôt que l'activation propagée depuis le cadre du menu : l'appel de l'hôte (Touch ID) peut dépasser les 5 s d'activation. Coût si faux : aucun, l'armement ne fait qu'ouvrir la fenêtre qui demande un clic.
- R5 : pas d'alias, l'e-mail de l'identité : aucun fournisseur d'alias n'est dans le code. Coût si faux : brancher l'alias au groupe identité quand la partie B existera.
- R6 : la date de naissance est formatée dans le remplisseur, pas par de nouveaux rôles : le classifieur et le modèle appartiennent à un autre chantier. Coût si faux : des formulaires à trois champs sans indice lisible restent sans date.
- R7 : AutoFill système, insertion de texte seulement (identités en tête, dates, parties d'adresse) : l'API ne donne pas la page. Coût si faux : aucun.

## 9. Tests

- Core : classe `passkey` lue et écrite ; offre seulement pour `Signup` ; connexion en un clic gardée à côté d'un bouton `passkey` ; règle 4 bis (inscription sans mot de passe, connexion avec lien d'inscription inchangée) ; `PlanOut` du pont porte `passkey`.
- Extension : `buttonClass` (fr, en, connexion par clé d'accès exclue) ; rang des boutons ; planner (identifiant du Login en attente, menu sur offre, garde) ; menu (deux choix, `menu_signup` mot de passe et clé d'accès) ; armement (usage unique, expiration, autre document) ; `click_passkey` relit la classe ; formats de date (type date, trois listes, motif, langue) ; e2e : inscription avec offre de clé d'accès, choix mot de passe puis choix clé d'accès jusqu'à la fenêtre OnePass, aucun envoi du formulaire hors du clic choisi.
- Apple : ordre des éléments de l'insertion de texte ; date et parties d'adresse insérables (VaultKit, `AutoFillModelTests`).
