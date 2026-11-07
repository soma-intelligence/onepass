# Remplissage web pour les agents : logins et cartes dans le navigateur d'un agent

Date : 2026-11-07
Statut : design validé avec le fondateur le 2026-11-07 (navigateur, accord, onglet, approche A). Spec à relire avant le plan d'implémentation.
Portée : un agent IA qui navigue (Claude in Chrome, Codex, un script Playwright local) demande à OnePass de remplir un login ou une carte dans la page où il se trouve, sans que la valeur passe par l'agent. S'appuie sur le serveur MCP (`2026-10-28-agent-ready-design.md`), le pont navigateur (`BrowserBridge`, `onepass-bridge`) et le remplissage intelligent (`2026-10-28-smart-fill-design.md`).

## 1. Compréhension

Ce que le fondateur veut : que les agents utilisent automatiquement ses logins, mots de passe et cartes, avec la sécurité de OnePass. Le terminal est déjà couvert (`run_with_secrets`, `fill_template`, `totp_code`, agent SSH). Il manque le web : un agent qui navigue n'a aujourd'hui aucun moyen de faire remplir une page par OnePass.

Décisions prises le 2026-11-07 :

- Navigateurs : les deux. Phase 1, le vrai Chrome du titulaire avec l'extension OnePass. Phase 2, les navigateurs pilotés par CDP en local (Playwright, Puppeteer, navigateur headless).
- Accord pour un login : premier remplissage d'un site par un agent approuvé avec Touch ID ou Face ID, puis fenêtre de 5, 15 ou 60 minutes pour ce site et cet agent, au choix dans le panneau.
- Accord pour une carte : à chaque fois, geste fort, sans fenêtre. OnePass n'appuie jamais sur Payer.
- Onglet ciblé dans Chrome : l'onglet actif de la fenêtre Chrome au premier plan, seulement si son domaine correspond à l'URL donnée par l'agent et au site de l'item.
- Canal app vers extension : port natif gardé ouvert par l'extension, l'app pousse la demande dans la session chiffrée existante (approche A, section 2).

Ce qui existe déjà et reste :

- Serveur MCP dans l'app Mac, 10 outils (`core/onepass-mcp/src/tools/schema.rs`), ordre de contrôle fixe (schéma, appairage, visibilité, portée, débit, autorisation, demande, geste fort, action, journal ; `tools/mod.rs:1-13`).
- Portées par coffre dans une politique signée (`policy.rs`), autorisations courtes signées et révocables (`onepass-guard/src/grants.rs`), journal chaîné et signé (`onepass-guard/src/audit.rs`).
- Approbation sur le panneau du Mac et sur l'iPhone, code de 4 lettres, première réponse valide gagne (`PromptBridge`, `RemoteApprover`).
- Pont navigateur : Chrome et Firefox par `onepass-relay`, Safari en direct, appelant authentifié par signature de code et identifiant d'extension, session chiffrée par la clé d'appairage. Demandes `FillLogin` et `FillCard` (`onepass-bridge/src/api.rs`), contrôles de cible dans `extension/src/background/frames.ts` (HTTPS, même origine et même `documentId` qu'au geste, sous-cadre du même site que le cadre principal).
- Moteur `fill_plan` qui renvoie un plan d'identifiants de champs, sans valeur.

Ce qui manque, et que cette spec ajoute :

1. Un outil MCP qui demande un remplissage de page.
2. Une portée qui l'autorise coffre par coffre.
3. Un canal par lequel l'app envoie une demande à l'extension (aujourd'hui le protocole ne va que de l'extension vers l'app).
4. Une règle de choix d'onglet sans geste du titulaire dans la page.
5. Un chemin CDP pour les navigateurs sans extension.

Critère de réussite : dans Claude in Chrome, l'agent ouvre `https://github.com/login` et appelle `fill_in_browser` avec l'item GitHub. Le panneau du Mac (ou l'iPhone) montre l'agent, `github.com`, le titre de l'onglet et le code. Après Touch ID, les deux champs sont remplis, la connexion part si `submit` est vrai, et la réponse de l'outil ne contient que `["username", "password"]`. Un second appel dans la fenêtre choisie passe sans panneau. Le journal porte une entrée par remplissage. Un appel sur un onglet d'un autre domaine est refusé sans panneau.

## 2. Approches pour le canal app vers extension

1. **Port natif gardé ouvert (retenue).** Au démarrage, et à chaque réveil du service worker, l'extension ouvre un port `connectNative` vers le relais et le garde. L'app pousse un message `AgentFill` dans la session chiffrée. Un port natif ouvert garde le service worker de Chrome en vie.
2. Interrogation périodique. L'extension demande à l'app toutes les quelques secondes s'il y a une demande. Simple, mais lent, coûteux, et le service worker MV3 s'endort entre deux appels.
3. Tout par CDP, sans extension. Couvre aussi la phase 2, mais le Chrome du titulaire ne tourne pas en mode débogage, donc ne marche pas avec Claude in Chrome.

Ruling: port natif gardé ouvert - réutilise l'authentification et le chiffrement du pont, latence nulle - coût si faux : passer à l'interrogation, le message `AgentFill` et les contrôles ne changent pas.

À vérifier en tâche 1 du plan : qu'un port `connectNative` ouvert garde bien le service worker de la version de Chrome visée en vie, et ce qui se passe quand Chrome le tue quand même (reconnexion au réveil suivant, demande en attente refusée après 10 s).

Safari : son extension parle directement au socket. Le même message pourra y passer plus tard. La phase 1 vise Chrome (et les navigateurs Chromium que l'extension couvre déjà). Firefox suit le même chemin que Chrome, sans engagement de test en phase 1.

## 3. L'outil MCP `fill_in_browser`

Paramètres :

- `item_id` (chaîne) ou `query` (chaîne). Avec `query`, l'outil choisit l'item seulement s'il y en a exactement un qui correspond au domaine de `url` dans les coffres visibles avec la portée `fill`. Sinon il renvoie la liste des candidats (métadonnées seulement) et ne remplit rien.
- `url` (chaîne, HTTPS obligatoire) : la page où l'agent se trouve.
- `kind` : `login` ou `card`.
- `submit` (booléen, défaut faux) : pour `login` seulement, appuyer sur le bouton de connexion trouvé par le plan. Refusé pour `card`.
- `target` : `{"browser": "chrome"}` (phase 1) ou `{"cdp": "ws://127.0.0.1:<port>/devtools/page/<id>"}` (phase 2).

Réponse : `{"filled": ["username", "password"], "submitted": true}` ou une erreur nommée. Jamais de valeur, jamais de longueur de valeur.

Erreurs nommées : `not_https`, `no_item`, `ambiguous_item`, `scope_denied`, `denied`, `timeout`, `no_browser`, `tab_mismatch`, `origin_mismatch`, `cross_site_frame`, `no_fields`, `submit_not_allowed`, `cdp_not_local`.

Ordre de contrôle, identique aux outils existants : schéma, appairage du client, visibilité du coffre, portée `fill`, débit, autorisation en cours, demande d'accord, geste fort, action, journal.

## 4. Portée et accord

Nouvelle portée `Fill` dans `policy.rs`, distincte de `Use` :

- Éteinte par défaut pour chaque coffre. Le titulaire l'active coffre par coffre dans Réglages > Développeur, ce qui réécrit et resigne la politique.
- Conseil affiché : un coffre « Agents » dédié.

Accord pour un login :

- Pas d'autorisation en cours pour (client, item, site) : panneau. Il montre le nom de l'agent, l'item, le domaine enregistrable (eTLD+1) en gros, le titre de l'onglet, le code de 4 lettres. Touch ID sur le Mac ou Face ID sur l'iPhone.
- Le panneau propose « Une fois », « 5 min », « 15 min », « 60 min ». L'autorisation est signée, liée à l'identité de code du client, à l'item et au site, révocable, plafonnée à 60 minutes comme les autres.
- Dans la fenêtre : pas de panneau, une entrée au journal à chaque remplissage.

Accord pour une carte :

- Panneau à chaque fois, geste fort obligatoire, pas de fenêtre proposée.
- Le panneau montre la marque et les 4 derniers chiffres, le domaine, l'agent et le code.
- `submit` est refusé. OnePass ne clique jamais sur un bouton de paiement, conforme au remplissage intelligent (§8.1 de sa spec).

Journal : une entrée par remplissage avec client, action `fill_login` ou `fill_card`, coffre, item, origine de la page, décision, approbateur (`mac` ou `phone:<id>`), `submitted`. Pas de titre d'onglet ni d'URL complète, seulement l'origine.

Mac verrouillé : le déverrouillage pour agents par l'iPhone (`AgentOnly`) ne suffit pas pour la phase 1. Le pont refuse aujourd'hui une session ouverte à distance (`ffi/bridge.rs:148`), et un remplissage dans Chrome demande une session Mac ouverte. Ruling: phase 1 exige le Mac déverrouillé - pas d'élargissement de `AgentOnly` au pont sans revue de sécurité - coût si faux : l'agent attend le titulaire quand le Mac est verrouillé.

## 5. Phase 1 : Chrome avec l'extension

Flux :

1. L'agent appelle `fill_in_browser` avec `target: {"browser": "chrome"}`.
2. L'app vérifie schéma, portée, item et domaine de l'item par rapport au domaine de `url` (eTLD+1, crate `psl`). Pas de correspondance : `origin_mismatch`, pas de panneau.
3. L'app envoie `AgentProbe{request_id, url}` à l'extension par le port ouvert. Pas de port ouvert : `no_browser`.
4. L'extension prend la fenêtre Chrome au premier plan et son onglet actif. Elle répond `{tab_title, origin, document_id}` seulement si l'origine du cadre principal a le même eTLD+1 que `url` et est en HTTPS. Sinon `tab_mismatch`.
5. L'app demande l'accord (section 4). Le titre de l'onglet vient de l'extension, donc du navigateur, pas de l'agent.
6. Après l'accord, l'app envoie `AgentFill{request_id, item_id, kind, submit, document_id}`.
7. L'extension revérifie : même onglet actif, même `documentId`, même origine qu'à l'étape 4. Tout changement : `tab_mismatch`, rien n'est rempli.
8. L'extension demande le plan (`PlanFill`), puis les valeurs par le chemin existant `FillLogin` ou `FillCard` avec un nouveau contexte `Ctx::Agent{request_id}`. L'hôte n'accepte `Ctx::Agent` que pour un `request_id` approuvé, une seule fois, dans les 30 s.
9. L'extension remplit par le `Filler` existant (setter natif, événements `input` et `change`), puis clique le bouton de connexion si `submit` est vrai.
10. Elle renvoie la liste des champs remplis. L'app l'inscrit au journal et la rend à l'agent.

Règles :

- L'onglet doit être actif dans la fenêtre au premier plan, au probe et au remplissage. Un agent qui travaille dans un onglet en arrière-plan reçoit `tab_mismatch`.
- Sous-cadres : mêmes règles que le remplissage humain, sous-cadre du même site seulement. Les iframes de paiement d'un autre site (Stripe, Adyen, Braintree) restent refusées (`cross_site_frame`). Sujet ouvert, section 9.
- Les messages `AgentProbe` et `AgentFill` passent dans la session chiffrée du pont, jamais en clair. Les valeurs ne vont que de l'hôte vers l'extension, comme aujourd'hui.
- Débit : réutiliser `take_secret_slot` de l'hôte. Une demande `AgentFill` à la fois par client.

Protocole : le pont devient bidirectionnel pour ces deux messages seulement. L'app n'envoie rien d'autre sans demande de l'extension.

## 6. Phase 2 : navigateurs pilotés par CDP

Flux :

1. L'agent lance son navigateur avec `--remote-debugging-port` et appelle `fill_in_browser` avec `target: {"cdp": "ws://127.0.0.1:<port>/devtools/page/<id>"}`.
2. L'app refuse toute adresse qui n'est pas `127.0.0.1` ou `::1` (`cdp_not_local`). Les navigateurs dans le cloud (Browserbase et autres) sont hors périmètre : la valeur quitterait le Mac vers un tiers.
3. L'app se connecte en WebSocket, lit l'URL réelle du cadre principal (`Page.getFrameTree`) et applique la même vérification de domaine qu'en phase 1. L'URL donnée par l'agent ne sert qu'à la comparaison.
4. Accord (section 4). Le panneau indique « navigateur piloté par CDP » au lieu du titre d'onglet, et le titre lu par CDP en second.
5. L'app reconstruit le `PageContext` du moteur `fill_plan` à partir de `DOMSnapshot.captureSnapshot`, obtient le plan, puis pour chaque champ : `DOM.focus` sur le nœud, `Input.insertText` avec la valeur. Jamais de `Runtime.evaluate` qui contient une valeur.
6. Juste avant chaque champ, l'app relit l'URL du cadre principal. Tout changement d'origine arrête le remplissage.
7. `submit` : un `Input.dispatchMouseEvent` sur le bouton de connexion du plan, login seulement.

Le Mac App Store : l'app est en bac à sable. Une connexion WebSocket sortante vers `127.0.0.1` passe avec `network.client`, déjà présent. À confirmer en tâche du plan.

## 7. Limite à dire clairement

Un agent qui peut lancer du JavaScript dans la page (Claude in Chrome le peut, CDP aussi) peut lire un champ après qu'OnePass l'a rempli. Ce système :

- empêche la valeur de passer par le modèle, la conversation, les journaux de l'agent ou le presse-papiers par accident ;
- limite l'exposition au site approuvé, pour la durée choisie, dans les coffres où `Fill` est active ;
- trace chaque remplissage dans un journal signé.

Il n'empêche pas un agent malveillant qui contrôle la page de lire la valeur. La documentation, le panneau et le README le disent. `submit: true` réduit le temps pendant lequel la valeur reste dans la page, sans rien garantir.

## 8. Tests

- Rust, `onepass-mcp` : schéma de `fill_in_browser`, refus sans portée `Fill`, `query` ambiguë, `origin_mismatch` sans panneau, autorisation de fenêtre pour un login, pas de fenêtre pour une carte, `submit` refusé pour une carte, entrée de journal par remplissage.
- Rust, `onepass-bridge` : `Ctx::Agent` refusé sans `request_id` approuvé, refusé au second usage, refusé après 30 s.
- Extension : probe refusé sur un onglet d'un autre domaine, sur un onglet en arrière-plan, en HTTP ; `AgentFill` refusé si le `documentId` a changé entre probe et remplissage ; sous-cadre d'un autre site refusé.
- Phase 2 : adresse CDP non locale refusée ; navigation pendant le remplissage arrête tout ; aucune valeur dans un `Runtime.evaluate` (test sur un faux serveur CDP qui enregistre les commandes).
- Bout en bout manuel : Claude in Chrome sur une page de test locale servie en HTTPS, puis sur un vrai site avec un compte de test.

## 9. Hors périmètre et sujets ouverts

- Iframes de paiement d'un autre site (Stripe Elements et autres) : refusées en phase 1, pour l'humain comme pour l'agent. Une liste fermée de domaines de prestataires de paiement est à étudier à part.
- Safari et Firefox pour les agents.
- Remplissage quand le Mac est verrouillé (élargir `AgentOnly` au pont).
- Identités et adresses (`FillIdentity`) : même chemin plus tard.
- Navigateurs dans le cloud.
- Création de compte par un agent (`create_login` existe déjà côté MCP, pas d'enregistrement automatique depuis la page).
