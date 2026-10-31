# Remplissage intelligent en un clic : conception

Date : 2026-10-28. Statut : design approuvé en conversation section par section, spec à relire par l'utilisateur.
S'appuie sur `2026-10-25-milestone-4-extension-design.md` (extension, chaîne de connexion), `2026-10-26-milestone-3-autofill-design.md` (AutoFill système) et `2026-10-27-autofill-dataset-model-design.md` (classifieur de champs), sans en changer les règles de sécurité.

## 1. But

Demande de l'utilisateur : que l'extension et le reste de OnePass aient l'intelligence et la conscience du contexte nécessaires pour un remplissage en un clic.

Reformulé en quatre résultats, tous retenus :

1. **Le bon élément sans choisir.** Un clic remplit le bon Login, la bonne carte, la bonne identité, sans menu, quand OnePass est sûr.
2. **Toute la page en un clic.** Un clic remplit tout ce que la page demande, en mêlant plusieurs éléments (Login + TOTP, ou identité + adresse + carte + e-mail au paiement).
3. **Plusieurs étapes et envoi.** Sur une connexion, OnePass remplit, envoie, reconnaît l'étape suivante (mot de passe, code) et continue jusqu'à être connecté.
4. **Le même cerveau partout.** Safari et Chrome (extension) et l'AutoFill système d'iPhone, iPad et Mac décident de la même façon.

Critères de réussite :

- zéro remplissage du mauvais élément au laboratoire ;
- zéro envoi automatique hors d'une page de connexion ;
- zéro fuite, comme aujourd'hui ;
- taux de réussite en un clic par flux supérieur au parcours actuel (menu d'abord) sur la même graine du laboratoire ;
- `plan_fill` répond en moins de 20 ms côté hôte pour un coffre de 500 éléments, sur le Mac de développement.

## 2. Décisions

- **D1, où vit le raisonnement.** Règles déterministes et petit modèle, en local seulement. Aucun LLM, ni sur l'appareil ni distant. La seule partie apprise est le classifieur de champs du dataset ; le choix des éléments est un calcul à poids fixes, testé.
- **D2, jusqu'où va un clic.** Envoi automatique pour la connexion seulement, à confiance haute. Inscription, réinitialisation, paiement et adresse : tout est rempli, rien n'est envoyé, l'utilisateur appuie lui-même sur le bouton.
- **D3, architecture.** Un moteur unique `fill_plan` dans `onepass-core` (approche A). Rejetées : un moteur TypeScript dans l'extension porté plus tard en Swift (deux cerveaux qui divergent, et l'extension devrait détenir des métadonnées du coffre), un moteur Rust compilé en WASM dans l'extension (mêmes métadonnées dans le processus du navigateur).
- **D4, deux classements existants.** `list_for_origin` (`core/onepass-bridge/src/service.rs`) pour l'extension et `autofill_candidates` (`core/onepass-ffi/src/autofill.rs`) pour iOS et Mac deviennent de fines enveloppes du même classement, sans changer leur résultat actuel.

## 3. Vue d'ensemble

Trois couches :

1. **Perception, par plateforme.** Le content script regroupe les champs en formulaires, le classifieur (`FieldClassifier` : heuristiques aujourd'hui, modèle du dataset quand il sera fusionné) donne un rôle et une confiance par champ, puis la perception déduit des indices d'intention et la position dans une séquence d'étapes. Le résultat est un `PageContext`, sans aucune valeur.
2. **Décision, dans le core.** `onepass-core::fill_plan` filtre les éléments candidats par des règles dures, les note, compose un plan qui couvre toute la page et donne une confiance. Le résultat est un `FillPlan` qui ne porte que des identifiants.
3. **Action, par plateforme.** L'extension exécute le plan : remplissage direct, chaîne de connexion (`chain/machine.ts`) ou menu. Les valeurs passent toujours par les opérations `fill_*` existantes, juste à temps, après la nouvelle vérification d'origine par l'hôte.

Les règles de sécurité restent en code, avant le plan et de nouveau avant la livraison (section 9). Le moteur ne peut que restreindre ce qui est permis, jamais l'élargir.

## 4. Contrats

### 4.1 `PageContext`

Construit par le content script (extension) ou par l'extension AutoFill (contexte partiel, section 8). Aucune valeur saisie, aucun chemin d'URL.

```
PageContext {
  origin: String,                 // origine du cadre analysé
  top_origin: String,
  frame_kind: Top | SameOriginChild,
  forms: [FormContext],
  typed_username_hash: Option<[u8; 32]>,
}

FormContext {
  form_ref: String,
  intent_hints: IntentHints,      // section 5.1
  step_index: Option<u8>,         // position connue dans une séquence d'étapes
  fields: [FieldContext],
  buttons: [ButtonContext],
}

FieldContext {
  field_ref: String,
  role: FieldRole | None,
  confidence: f32,                // 0..1, donnée par le classifieur
  visible: bool,
  prefilled: Empty | Typed | Ours,
}

ButtonContext {
  button_ref: String,
  class: Submit | Next | Pay | Create | Other,
}
```

`typed_username_hash` : quand l'utilisateur a déjà tapé un identifiant, l'extension envoie un hachage avec sel de session (SHA-256 sur `sel || identifiant normalisé`), le sel étant donné par l'hôte à l'ouverture de la session. L'hôte compare avec les identifiants des candidats hachés de la même façon. L'identifiant en clair ne quitte jamais la page par ce chemin.

### 4.2 `FillPlan`

```
FillPlan {
  intent: Login | Signup | Reset | Otp | Checkout | Address | Ignore,
  groups: [PlanGroup],
  action: Fill | FillAndSubmit | OpenChain | ShowMenu | Nothing,
  confidence: High | Medium | Low,
  alternatives: [ItemId],         // au plus 5, classés
  reasons: [ReasonCode],          // laboratoire et journal de débogage, jamais affichés bruts
}

PlanGroup {
  form_ref: String,
  item_id: ItemId | Generated,
  kind: Login | Card | Identity | GeneratedPassword,
  fields: [(field_ref, FieldRole)],
}
```

### 4.3 Hôte et FFI

- Nouvelle opération du pont `plan_fill { ctx, context: PageContext }`, réponse `FillPlan`. Même audit que les autres opérations ; le journal n'enregistre que l'hôte, l'intention, l'action et la confiance.
- Nouvelle fonction FFI `autofill_plan(context)` pour l'extension AutoFill des apps.
- `list_for_origin` et `autofill_candidates` appellent le même classement interne, avec un contexte réduit qui reproduit leur ordre actuel (tests de propriété en section 10).
- Les valeurs sont toujours obtenues par `fill_login`, `fill_card`, `fill_identity`, `fill_provider`, après la nouvelle vérification d'origine. Le plan ne transporte jamais de secret.

## 5. Intention et étapes

### 5.1 Indices d'intention (perception)

Calculés dans l'extension, à partir des rôles et du texte nettoyé déjà extrait par `detect/forms.ts` :

- présence et nombre de champs `current_password` et `new_password` ;
- champ `otp` seul ;
- champs carte (`cc_*`), champs adresse ;
- classes des boutons (section 4.1) : un bouton `Pay` ou `Create` est un signal fort ;
- mots du lexique (`detect/lexicon.ts`) dans le titre de la page, le texte des boutons et les titres proches : connexion, inscription, mot de passe oublié, paiement, livraison ;
- formulaires à ignorer : recherche, newsletter seule, commentaire.

### 5.2 Décision d'intention (core)

Une table de règles ordonnées dans `fill_plan::intent`, la première qui s'applique gagne :

1. aucun champ remplissable ou formulaire marqué à ignorer : `Ignore` ;
2. au moins un champ carte : `Checkout` ;
3. deux champs `new_password`, ou `current_password` + `new_password` : `Reset` ;
4. au moins un `new_password` : `Signup`, avec un bouton `Create`, un mot ou un indice d'inscription (`kind` du détecteur), et aussi sans aucun d'eux (un e-mail, un nouveau mot de passe et « Continuer ») ; un nouveau mot de passe n'est jamais une connexion, donc jamais un envoi automatique ;
5. `otp` seul : `Otp` ;
6. `current_password` ou identifiant seul : `Login` ;
7. champs d'adresse ou d'identité seulement : `Address`.

### 5.3 Étapes

La séquence d'étapes d'une connexion reste gérée par `chain/machine.ts`. Changements :

- la chaîne reçoit l'élément du plan au lieu de le demander ;
- sur une étape qu'elle ne reconnaît pas, la chaîne rappelle `plan_fill` avec le nouveau `PageContext` ;
- quand un mot de passe est refusé (`repeat`), le plan suivant pour ce site perd un niveau de confiance, donc l'utilisateur voit le menu.

## 6. Classement et confiance

### 6.1 Filtre dur

Un élément n'est jamais candidat si : la règle de correspondance (origine exacte, site, règle de l'utilisateur) ne passe pas ; le domaine est un sosie ; l'élément est caché ; l'origine est en `http` hors des hôtes locaux. Ces règles sont celles d'aujourd'hui, déplacées dans le module partagé.

### 6.2 Note

Fonctions pures, poids fixes dans une seule table (`fill_plan::weights`) :

| Signal | Effet |
|---|---|
| précision de l'origine | exacte > site > domaine associé |
| mémoire du site | élément utilisé ici la dernière fois, bonus si même forme de formulaire |
| identifiant tapé égal à celui de l'élément | décisif |
| type d'élément adapté à l'intention | connexion : Login ; paiement : carte + identité |
| favori, récence, fréquence | départage seulement |

### 6.3 Confiance

- **Haute** : un seul candidat, ou le premier devance le second d'au moins la marge `MARGIN` et s'appuie sur la mémoire du site ou sur l'identifiant tapé ; et chaque champ du plan a une confiance du classifieur au moins égale à `ROLE_MIN`.
- **Moyenne** : plan valable, mais égalité ou signal faible. Le clic remplit, n'envoie jamais.
- **Basse** : le menu s'ouvre, meilleur choix en tête.

`MARGIN` et `ROLE_MIN` sont des constantes de `fill_plan::weights`, fixées par le laboratoire avant la fusion et consignées dans les rulings du plan.

### 6.4 Composition

- **Paiement** : carte utilisée la dernière fois sur ce site, sinon la favorite puis la plus récente (le modèle n'a pas de carte par défaut) ; identité utilisée ici, sinon celle dont le pays correspond au domaine de premier niveau de la page ; sans mémoire ni pays qui correspond, le classement seul : plusieurs identités à égalité donnent le menu, jamais la première par règle ; e-mail de l'identité, sinon celui du Login du site.
- **Inscription** : mot de passe généré par `generator.rs` selon les règles du site quand la page les donne (`pattern`, `maxlength`), plus l'identité choisie comme pour le paiement, dont l'e-mail va aussi dans un champ identifiant (`username`). Sans identité à choisir (aucune, ou plusieurs à égalité), le plan garde le mot de passe généré seul, sans perdre de confiance. L'enregistrement passe par le flux de sauvegarde existant (`chain/save-flow.ts`).
- **Code à usage unique** : seuls les Login qui ont un secret TOTP sont candidats ; la mémoire du site (« utilisé ici la dernière fois ») se compte parmi eux.
- **Réinitialisation** : mot de passe actuel du Login du site plus un nouveau mot de passe généré.

## 7. Mémoire du site

Mémoire par élément, dans une seconde remorque scellée de l'élément (`UsageTrailer`, ruling R1), après la remorque d'historique (`ItemTrailer`) :

```
UsageTrailer { sites: [SiteUsage], forgotten: [(site, forgotten_at)] }

SiteUsage {
  site: String,               // eTLD+1
  form_shape_hash: [u8; 16],  // rôles et ordre des champs, sans texte
  intent: Intent,
  step_seq: [StepKind],
  count: u32,
  last_at: Timestamp,
}
```

- Chiffrée et synchronisée avec l'élément, sous sa clé : pas de nouveau type d'enregistrement (les listes signées sont lisibles par le serveur). Un élément sans usage s'encode à l'octet près comme avant ; une remorque illisible ouvre l'élément sans usage.
- Une écriture d'usage ne change jamais `updated_at`, et un changement local qui ne touche que l'usage perd toujours le rebase face à une modification distante, quelles que soient les horloges ; le rebase reporte l'usage local sur l'élément gagnant (union par site, `merge_trailers`).
- Écrite seulement après un remplissage réussi : chaîne arrivée à `done`, ou sauvegarde confirmée, ou remplissage sans envoi suivi d'une navigation du même site. Et seulement si le site est nouveau pour l'élément, si `form_shape_hash` ou `intent` a changé, ou si le dernier usage date de plus d'une heure (ruling R3).
- Au plus 20 sites par élément, les plus récents (ruling R2) ; une entrée sans usage depuis un an est supprimée à l'écriture suivante.
- Jamais exposé comme liste de sites par le MCP ni par la CLI (hors de la forme serde de l'élément) : les règles du guard restent les mêmes.
- Supprimé avec l'élément ; effaçable par site depuis les réglages des apps et de l'extension (`Repository::forget_site_usage`).
- Effacer un site laisse une pierre tombale `(site, forgotten_at)` dans la remorque : la fusion écarte toute entrée de ce site dont `last_at` n'est pas plus récent, un usage postérieur revient ; pierres tombales expirées après un an, au plus 20 (les plus récentes).

## 8. Ce que fait un clic

### 8.1 Par intention

| Intention | Confiance haute | Moyenne | Basse |
|---|---|---|---|
| Login | `OpenChain` : la chaîne remplit, envoie, suit mot de passe, code et fournisseur SSO jusqu'à `done` | remplit cette étape, n'envoie pas | menu |
| Otp seul | TOTP du Login avec code utilisé ici la dernière fois, envoi ; sans cette mémoire, remplit sans envoyer | remplit, n'envoie pas | menu |
| Signup | identité + mot de passe généré, jamais d'envoi, sauvegarde armée | idem | menu |
| Reset | actuel + nouveau généré, jamais d'envoi | idem | menu |
| Checkout | carte + identité + e-mail, jamais d'appui sur payer | idem | menu |
| Address | identité, jamais d'envoi | idem | menu |
| Ignore | icône du champ masquée, rien n'est rempli | | |

### 8.2 Déclencheurs dans l'extension

L'icône du champ, le bouton Remplir de la barre d'outils et le raccourci clavier appellent tous `plan_fill` puis exécutent le plan. La fenêtre de l'extension montre le plan en une ligne ("Se connecter en tant que tom@… en 2 étapes") avec les alternatives dessous.

### 8.3 AutoFill système d'iPhone, iPad et Mac

`ASCredentialProviderViewController` ne reçoit que le domaine ou l'URL et le type de demande (mot de passe, passkey, code à usage unique), jamais la page. Périmètre honnête :

- même classement, contexte partiel : origine, type de demande, mémoire du site ; pas d'intention de formulaire, pas de remplissage de toute la page ;
- les suggestions de la barre QuickType sont écrites dans `ASCredentialIdentityStore` depuis les premiers candidats du plan, classés par la mémoire du site : le compte utilisé en dernier sur un site arrive en tête sur le téléphone aussi ;
- code à usage unique : TOTP de l'élément de la mémoire du site ;
- l'extension Safari sur iPhone, iPad et Mac reçoit le plan complet, page entière et plusieurs étapes, comme Chrome ;
- la mémoire du site est synchronisée : un Login utilisé sur le Mac fait choisir ce compte sur l'iPhone.

## 9. Sécurité

- Les refus passent avant le plan et de nouveau avant la livraison, et le plan ne peut en lever aucun : iframe d'un autre site (R-10), champs pièges invisibles, sosies de domaine, nouvelle vérification d'origine par l'hôte, `same_origin` pour les cadres enfants.
- Envoi automatique seulement à confiance haute, pour `Login`, ou pour `Otp` seul avec l'élément utilisé ici la dernière fois ; un seul formulaire planifié ; jamais avec un bouton `Pay` ou `Create` dans un formulaire planifié (revérifié au moment du clic sur les pages du site) ; jamais dans un cadre enfant ; jamais quand l'utilisateur a tapé une valeur dans un champ que l'élément remplirait, sauf un identifiant tapé qui désigne l'élément choisi ; et seulement à partir d'un geste de l'utilisateur (clic sur l'icône, bouton Remplir, raccourci), jamais au focus ni au chargement.
- Le plan ne porte que des identifiants. Les valeurs ne circulent que par les opérations `fill_*` existantes.
- `PageContext` est une entrée hostile (le content script vit dans la page) : bornes de taille (au plus 32 formulaires, 64 champs par formulaire, 32 boutons), rejet de tout champ inconnu, nouvelle cible `plan_fill` dans `core/fuzz`.
- Le hachage de l'identifiant tapé utilise un sel de session : il ne permet pas de corréler un identifiant entre deux sessions.

## 10. Tests

- **Core** : un test par signal de la table de notes ; tests d'égalité et de marge ; plans de référence par intention ; tests de propriété qui prouvent que `list_for_origin` et `autofill_candidates` gardent exactement leur ordre actuel ; test de performance de `plan_fill` sur 500 éléments.
- **Extension** : tests unitaires des indices d'intention et de la construction du `PageContext` ; e2e sur les flux du laboratoire existants (connexion, paiement, inscription).
- **Laboratoire** : nouvelles mesures par flux, comparées entre le parcours actuel et le plan sur la même graine : remplissage du mauvais élément (cible 0), réussite en un clic, envois automatiques hors connexion (cible 0), fuites (cible 0).
- **Apps** : test FFI de `autofill_plan` avec contexte partiel ; test d'ordre de `ASCredentialIdentityStore` selon la mémoire du site.

## 11. Dépendances et ordre

1. Module `fill_plan` dans le core, classement partagé, enveloppes des deux fonctions existantes (aucun changement visible).
2. `SiteUsage` dans le coffre et la synchronisation.
3. Opération `plan_fill` dans le pont et l'hôte natif ; fonction FFI.
4. Perception dans l'extension (`PageContext`, indices d'intention), puis exécution du plan et branchement de la chaîne.
5. AutoFill système : ordre de `ASCredentialIdentityStore` et codes depuis la mémoire du site.
6. Mesures du laboratoire et réglage de `MARGIN` et `ROLE_MIN`.

Le classifieur du dataset (`feat/autofill-dataset`) n'est pas un préalable : le moteur lit la confiance par l'interface `FieldClassifier`, remplie par les heuristiques en attendant le modèle.

## 12. Hors périmètre

LLM de toute sorte, télémétrie, service distant, appui sur un bouton de paiement ou de création de compte, remplissage d'un cadre d'un autre site, remplissage de toute la page par l'AutoFill système (l'API ne donne pas la page).
