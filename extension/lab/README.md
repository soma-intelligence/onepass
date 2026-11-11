# Laboratoire d'autofill

## But

Mesurer ce que l'extension remplit, et ce qu'elle ne doit jamais remplir, sur un grand nombre de sites générés au hasard mais reproductibles. Une graine donne un monde : des sites fictifs (formulaires de connexion, inscription, paiement, adresse, identité, SSO, TOTP, passkeys) avec des traits qui compliquent la détection (iframes, shadow DOM, champs retardés, noms obfusqués, champs pièges, sosies de domaine). Le laboratoire pilote Chromium avec l'extension chargée et l'hôte natif réel, et note un verdict par scénario. Il ne modifie rien dans `extension/src`.

## Architecture

- `corpus/` : extracteur passif de motifs de formulaires réels, relevés nettoyés et `patterns.json` distillé (version 2 : libellés, suites d'étapes, frameworks, poids des traits). Les libellés passent un filtre : ponctuation seule, plus de 40 caractères, captcha, recherche, lettre d'information, discussion, mots d'inscription sur un identifiant, consignes de mot de passe ; pour les pages relevées en masse, le libellé doit aussi s'accorder avec le rôle du champ. La distillation lit les 59 relevés choisis à la main (`samples/`), le top 1000 (`samples/top1000/`), les pages Common Crawl copiées (déjà nettoyées) dans `samples/commoncrawl/` (jamais `lab/out/`, pour que `patterns.json` se reconstruise depuis un dépôt propre), et les parcours enregistrés de `private/` seulement avec `--with-private` (le `patterns.json` commité n'en dépend jamais). Le générateur ne lit que `patterns.json`.
- `gen/` : générateur de mondes (PRNG `sfc32` + `cyrb128`, déterminisme par graine), rendu HTML des sites et capacités attendues (`capabilities.ts`). Langues des sites : français 0,4, anglais 0,4, puis allemand, espagnol, italien, portugais et néerlandais à parts égales dans les 0,2 restants (version 3 ; libellés de base de ces langues dans `corpus/seed-lexicon.json`). Depuis la version 2 du générateur : formulaires en plusieurs étapes (`multi_step`, une page par étape, `steps.ts`), mises en page (`layouts.ts`) et frameworks simulés en HTML et script simples, sans dépendance (`frameworks.ts`).
- `gen/policy.ts` : règles de mot de passe des sites d'inscription (environ 60 % d'entre eux). Tirage par la graine (flux `policy` du site), affichage par `attributes`, `passwordrules` ou une phrase dans la langue du site (fr, en, de, es), contrôle du serveur (raison `policy`). `node --experimental-strip-types lab/policy-stats.ts --out lab/out/<graine>` compte les refus par catégorie (catégories de `policyCategory`, dont les indices seuls en langue non lue, attendus en échec).
- `gen/population.ts` : population simulée. Un profil d'utilisateur fixe la taille du coffre (0 à 500), les doublons, les comptes multiples par site, le pays (formats d'adresse, de téléphone et de code postal : US, FR, DE, ES, GB, JP) et le comportement après le remplissage. Le profil `p0` est l'utilisateur historique (coffre du monde seul) ; les autres viennent d'un flux aléatoire séparé, donc demander plus de profils ne change ni le monde, ni les profils précédents.
- `gen/cases.ts` : cas pays et région. Les pages de commande écrites à la main de `fixtures/country-state/` (Shopify, Stripe, Amazon, boutique française, React Select) sont servies telles quelles sur un hôte `.test` chacune, en `/checkout`, et chaque cas de `cases.json` a son élément identité dans le coffre du monde (le même dans tous les mondes, hors tirage). Le test « country cases » de `run/lab.spec.ts` ouvre le menu dans le champ du nom, choisit l'élément du cas, puis lit chaque contrôle une fois le remplissage posé (valeur d'un champ, sinon texte de l'élément, jusqu'à 4 s). Verdicts `cs:<n>` dans `cases.jsonl`, comparés au smoke comme les scénarios ; un échec est rejoué une fois dans un profil neuf (réussite alors `flaky`). Pas joué avec `--site`.
- `server/` : serveur HTTPS local qui sert tous les hôtes `.test`, les trois fournisseurs d'identité (Google, Apple, Microsoft) sous leurs vrais noms d'hôte résolus en local, la partie utilisatrice (mots de passe, TOTP, WebAuthn) et le registre de fuites.
- `run/` : configuration Playwright, préparation unique (compilation, hôte natif, coffre fictif, certificats), pilotes de scénarios et oracle.
- `report.ts` et `cli.ts` : rapport Markdown et ligne de commande.

Les résultats d'un passage sont dans `lab/out/<graine>/` (ignoré par git) : `world.json`, `fixture.json` (coffre fictif), `results.jsonl` (une ligne par scénario), `cases.jsonl` (une ligne par cas pays et région) et `report.md`.

## Population simulée

Avec `--profiles <p>`, chaque scénario est joué pour chaque profil (`p0` à `p<p-1>`) :

- **Coffre** : `vaultSize` est un plancher. Le coffre garde toujours les éléments du monde (les scénarios en ont besoin) et des éléments de remplissage fictifs montent jusqu'à `vaultSize` (hôtes `*-archive.test`, jamais ceux du monde). `0` donne un coffre vide : l'extension n'a rien à proposer, les scénarios attendent `nofill`, sauf le générateur de mot de passe d'une inscription, qui n'a besoin d'aucun élément.
- **Doublons** : des identifiants de site répétés à l'identique. **Comptes multiples** : un second compte (autre identifiant, autre mot de passe, titre « <site> (2) ») pour chaque site à mot de passe.
- **Pays** : les éléments d'identité reprennent les formats du pays (code postal japonais `NNN-NNNN`, téléphone international). La langue du profil suit le pays.
- **Comportement** (pilote `menu_fill` seulement) : `partial` vide un champ rempli avant d'envoyer, `corrects_field` retape un champ, `abandons_step` s'arrête après la première étape d'un formulaire en plusieurs étapes. L'oracle juge alors ce que l'extension a rempli (instantané pris avant l'action de l'utilisateur), pas la réponse du site à l'envoi corrigé ; sous `abandons_step`, seule la première étape compte.

Chaque profil a son propre hôte natif et son cache de coffre, préparés en parallèle à l'installation du passage. Sans `--profiles`, le monde, le coffre et `smoke-expected.json` sont ceux du profil historique.

## Gestes, états de départ, plusieurs comptes

But mesuré : un seul geste délibéré de l'utilisateur, et il est connecté.

- **Gestes** (`run/gestures.ts`) : chaque pilote note chaque geste qu'un humain ferait. Vers OnePass : `field_icon` (icône du champ), `toolbar` (bouton Remplir), `shortcut` (commande `fill-smart`), `overlay_row` (« Se connecter » de l'overlay), `menu_key` (flèche bas dans un champ), `menu_row`, `picker_open` et `picker` (autres identifiants, fenêtre passkey), `unlock_button` (« Déverrouiller dans OnePass »). Vers le site : `site_submit` (son bouton d'envoi ou de suite), `site_button` (son bouton passkey), `site_type` (un champ tapé ou corrigé à la main). `unlock_approval` est l'approbation du déverrouillage (Touch ID, jouée par le banc) : comptée à part, « +1 biométrie ». L'appui sur le bouton du site ne compte que si l'utilisateur doit vraiment le faire (pas quand le site l'a déjà connecté ni quand une chaîne de connexion s'en charge).
- **`results.jsonl`** garde par scénario : `gestures` (nombre de gestes délibérés), `gestureList` (leurs natures dans l'ordre, jamais une valeur), `biometric`, `signedIn` (l'oracle a vu la session du bon compte ; seulement pour les flux dont le but est une session), `oneGesture` (`signedIn` et `gestures == 1`), `startState`, `trigger`, et pour un départ verrouillé `unlock` (`instant` ou `deferred`). `oneClick` garde son ancien calcul (l'envoi par l'utilisateur n'y compte pas), pour comparer avec les anciens passages.
- **États de départ** (`--starts unlocked_warm,locked,cold`, `run/start-state.ts`) : `unlocked_warm` est le départ historique (rien n'est touché). `cold` : l'hôte natif du profil est arrêté quand l'utilisateur arrive sur la page, et de nouveau juste avant son geste si le chargement l'a relancé. `locked` : l'hôte est relancé verrouillé (`unlocked: false`) et sa session rouverte sans déverrouiller ; le déverrouillage est approuvé par le banc à la place de Touch ID. À l'arrivée verrouillée l'overlay est une carte générique (aucun compte nommé), aussi sur une page à passkey seule : le pilote `one_click` appuie sur son bouton (`overlay_row`), puis suit la chaîne (ou la signature par passkey), ou choisit sa ligne dans le menu quand le plan ne peut pas choisir (`menu_row`). Le geste lui-même demande le déverrouillage (ou le lancement) : le menu ou la carte attend puis reprend seul, soit un geste et « +1 biométrie » ; seul le bouton de repli du menu (« Déverrouiller dans OnePass », « Ouvrir OnePass ») est un geste de plus (`unlock_button`). Seuls les scénarios avec un but sont rejoués ; identifiant `<scénario>@<état>`. Un lot (un profil de navigateur) n'a qu'un état de départ.
- **Clics sur les cadres de l'extension** (`run/browser.ts`, `userClick`) : un cadre ignore un clic qui arrive moins de 300 ms après l'affichage de son contenu, et ce délai repart quand le navigateur déclare le cadre visible (IntersectionObserver v2 : mesuré 110 à 210 ms après l'apparition des lignes d'un menu, plus tard sur une machine chargée). Le banc ne voit pas cet instant : un clic après une attente fixe tombait avant ou après par hasard (lignes de menu, carte générique, autres identifiants), d'où des scénarios « instables » sans cause produit. L'extension montre alors le contrôle enfoncé (`held`) pour que l'utilisateur retape ; le banc fait pareil et retape une fois le contrôle relâché. Cela reste un seul geste.
- **Touch ID du banc** (`run/host-control.ts`, `UnlockStandIn`) : l'approbation arrive après un délai humain (`LAB_UNLOCK_DELAY_MS`, 800 ms par défaut, `0` pour tout de suite) et jamais avant qu'un hôte ait écrit `unlock-pending`. Une fois donnée, elle vaut pour tous les processus hôte du profil jusqu'à la fin du scénario : le profil en a deux (la session principale et le canal agent, rouvert toutes les quelques secondes), chacun avec son propre verrou, et le premier qui lit les fichiers d'approbation les retire. L'app, elle, n'a qu'un coffre pour toutes ses connexions : le banc remet donc les deux fichiers tant que le scénario dure. Sans cela le canal agent prenait parfois l'approbation, la session principale restait verrouillée et la carte attendait jusqu'à l'échéance.
- **Contrôles de l'hôte** (`run/host-control.ts`) : l'arrêt passe par la liste des processus (chemin de configuration propre au profil). L'hôte de développement approuve `unlock` tout de suite (`unlock: instant`) ; l'application réelle répond encore verrouillée puis s'ouvre après Touch ID. Pour jouer ce chemin, l'hôte doit accepter la clé de configuration `"unlock": "file"` (fichiers `unlock-pending` et `unlock-approved` dans son dossier de données) : le banc la détecte et approuve alors par fichier (`unlock: deferred`). Un état de départ impossible à mettre en place donne le verdict `skipped` et la cause `host lacks control <nom> (...)`, hors de tous les taux.
- **Déclencheurs** (`--triggers icon,shortcut`) : `smart_fill` démarre par l'icône du champ (défaut) ou par la commande clavier `fill-smart`, que le banc lance dans le service worker (le gestionnaire du raccourci, sans passer par le clavier du système). Identifiant `<scénario>/shortcut`.
- **Profils de comptes** (`--accounts p0,p1,p2,p3`, `gen/population.ts`, jamais avec `--profiles`) : sur chaque site à simple mot de passe, `p1` a deux comptes sans mémoire du site, `p2` deux comptes dont le second a servi en dernier sur ce site (le pilote crée cette mémoire par une première connexion OnePass, hors des gestes mesurés), `p3` un élément limité à l'hôte exact et un élément valable pour tout le domaine, enregistré sous un autre hôte du même domaine (`https://www.<hôte>` : sous la même URL les deux seraient des correspondances d'hôte exact et le plan répondrait le menu, à raison). Avec exactement deux comptes, l'overlay montre l'autre compte sous le premier : un geste (`picker`), plus de liste à ouvrir. Chaque scénario porte le compte voulu et le résultat attendu (`ACCOUNT_OUTCOME`) ; le site n'accepte que le compte voulu, et l'autre compte rempli donne la cause `wrong_account`.
- **Rapport** : « Un geste, connecté » par état de départ, déclencheur et famille de flux, à côté de « Réussite en un clic », puis « Connecté, quel que soit le nombre de gestes » et, avec des profils de comptes, « Plusieurs comptes sur un site ».

Ne jamais relancer un passage dans un dossier de résultats existant : `--out <dossier>` (ou `LAB_OUT`) en donne un neuf.

## Garde-fous du corpus

Le relevé du corpus (`npm run lab:corpus`) touche le réseau réel. Il est passif et prudent :

- un seul `GET` par page, aucun clic, aucune soumission de formulaire, aucune interaction ; seule la première étape d'un formulaire en plusieurs étapes est donc relevée ;
- `robots.txt` est respecté pour les groupes `*` et `OnePassLabCorpus` ; une page interdite est sautée et notée ;
- débit limité : au moins 5 secondes entre deux requêtes de page ;
- nettoyage avant écriture (`sanitize.ts`) : aucune adresse, aucun nombre long, aucun contenu personnel ne survit dans les relevés commités.

Le passage du laboratoire lui-même n'utilise aucun réseau externe : tous les hôtes générés sont en `.test` (RFC 6761) et des filets réseau empêchent toute sortie.

## Commandes

À lancer depuis `extension/`.

| Commande | Effet |
| --- | --- |
| `npm run check` | typage, tests unitaires (dont `test/lab/`), compilation. Sans navigateur. |
| `npm run lab:smoke` | navigateur, graine fixe `lab-smoke-17`, 16 sites couvrant chacun des quinze flux et les pièges structurels (cadre inter-sites, shadow DOM fermé, rerendu SPA, OTP découpé, sosie) ; compare au résultat épinglé `smoke-expected.json` |
| `npm run lab -- --seed <s> [--sites <n>] [--drivers current,smart_fill] [--workers 4] [--report <md>]` | passage complet (200 sites par défaut, pilotes actuels par défaut) ; rapport dans `lab/out/<s>/report.md`, copié dans `<md>` si demandé. Code de sortie 1 si le passage est rouge (fuite, mauvais élément ou envoi automatique hors connexion). |
| `npm run lab:repro -- --seed <s> --site <i> [--sites <n>] [--drivers ...]` | rejoue un seul site du monde ; résultats dans `lab/out/<s>-repro-<i>/` |
| `npm run lab -- --seed <s> --sites <n> --drivers current,smart_fill --starts unlocked_warm,locked,cold --triggers icon,shortcut --accounts p0,p1,p2,p3 --out lab/out/<neuf>` | même passage avec les états de départ, le raccourci clavier et les profils de comptes (chaque option est indépendante ; les défauts sont le passage historique) |
| `npm run lab -- --seed <s> --sites <n> --profiles <p>` | même passage joué par `p` utilisateurs simulés (défaut 1, le profil historique). Chaque profil a son coffre et son navigateur : le temps de passage est multiplié par `p`. Le rapport ajoute le tableau « Par profil ». |
| `npm run lab:corpus` | relevé du corpus (réseau réel, lent, rarement) puis distillation |
| `npm run lab:label` | outil d'étiquetage à la main du jeu de test réel : formulaire sur `127.0.0.1` (port libre affiché), 200 pages tirées par graine, sites entiers en nombre minimal, catégories rares d'abord (`corpus/real-test-hosts.json` : graine, hôtes, nombre de pages), étiquettes dans `corpus/labels/<hôte>.<n>.json` (celles des flux enregistrés dans `corpus/private/labels/`, non commitées) |
| `npm run lab:real` | compte les champs étiquetés du jeu réel (`real_test: 0 labels` tant qu'aucune étiquette n'existe) ; `-- --pick` retire les hôtes (200 pages au moins). La distillation écarte ces hôtes (tous les sites des relevés) pour que `patterns.json` ne contienne jamais leurs libellés |
| `node --experimental-strip-types lab/corpus/distill.ts [--with-private]` | distillation seule, sans réseau : réécrit `patterns.json` |
| `node --experimental-strip-types lab/cli.ts report --out <dossier> [--md <fichier>]` | refait le rapport d'un dossier de résultats existant |
| `npm run lab -- --seed <s> --sites <n> --classifier heuristic\|gbm\|encoder [--model-dir <dossier>]` | même passage avec ce classifieur de champs (construction `ONEPASS_CLASSIFIER`, modèle pris dans `--model-dir`, obligatoire sauf pour `heuristic`) ; résultats dans `lab/out/<s>-<classifieur>/`, extension construite dans son propre dossier `dist-lab/<s>-<classifieur>/chromium` (jamais `dist/chromium`, et vérifiée avant le passage : CSP du manifeste et empreinte sha256 du modèle), avec `classifier.json` (marqueur de construction, taille du modèle, F1 hors ligne lus dans `<modèle>-eval.json`, temps de classement médian par formulaire mesuré dans le service worker) |
| `node --experimental-strip-types lab/cli.ts compare --out <dossier1> <dossier2> <dossier3> --md <fichier> [--real-rows <lignes.jsonl>]` | comparaison des trois classifieurs sur la même graine : tableaux par flux, trait, langue (et profil), fuites, métriques hors ligne, puis verdict de la règle de la spec (7.3). `--real-rows` donne les lignes `real_test` sur lesquelles l'heuristique est notée ; sans lignes étiquetées le verdict reste « heuristic », provisoire. Les passages doivent avoir même graine, mêmes sites, mêmes profils, classifieurs distincts ; le critère real_test fusionne `password` et `new_password` (R23) et exige les mêmes lignes des deux côtés (empreinte) |

Le passage complet demande Chromium (Playwright), `cargo` pour l'hôte natif et une dizaine de secondes de préparation.

## Lire le rapport

- **Résumé** : nombre de sites et de scénarios, taux de réussite global, fuites. Le taux est (réussis + instables) sur le total sans les échecs attendus, les réussites inattendues et les erreurs du labo.
- **Taux par flux, trait, langue, pilote** : un site à plusieurs traits compte une fois sous chacun de ses traits.
- **Réussite en un clic** : par flux, les pilotes actuels (overlay pour la connexion, menu du champ pour les formulaires) face à `smart_fill` (clic de confiance sur l'icône OnePass du champ, ou le bouton Remplir de la barre d'outils quand la page n'a pas de champ, puis ce que fait le plan). Un clic = le but atteint avec un seul geste vers OnePass ; ouvrir le menu puis choisir une ligne fait deux gestes ; la frappe de l'utilisateur et son appui sur le bouton du formulaire ne comptent pas. Ainsi, quand un clic `smart_fill` remplit un formulaire (paiement, adresse, identité, inscription), l'utilisateur appuie lui-même sur le bouton du formulaire et cet envoi ne compte pas ; il ne compte pas non plus après le menu des pilotes actuels. Le rapport donne à côté le taux de but atteint par flux pour les deux ensembles de pilotes, quel que soit le nombre de gestes. Les deux ensembles de pilotes ne partagent jamais un profil : la mémoire du site de l'un n'aide pas l'autre.
- **Mauvais élément** (`wrong_item`) : un champ contient une valeur d'un autre élément du coffre que celui du scénario, ou le site a connecté un autre compte. Les valeurs sont lues par le pilote dans la page et restent dans sa mémoire ; seuls les noms des champs sortent. Échec, et le passage est rouge.
- **Envoi automatique hors connexion** (`auto_submit_outside_login`) : le site a reçu un envoi avant que le pilote (l'utilisateur) n'appuie sur le bouton, sur un flux dont l'intention vraie n'est pas la connexion (l'étape du code fait partie de la connexion). Échec, et le passage est rouge.
- **Autre personne remplie** (`other_person_filled`) : sur une page de formulaire à plusieurs personnes, un champ du passager 2 ou suivant est non vide dans l'instantané pris après le remplissage, avant que l'utilisateur ne tape ces passagers. Échec définitif, jamais rejoué, et le passage est rouge.
- **Échecs** : chaque ligne donne le site, le flux, le pilote, les traits, la cause et la commande de rejeu.
- **Réussites inattendues** (`xpass`) : une capacité attendue manquante est arrivée ; retirer l'attente d'échec dans `gen/capabilities.ts`.
- **Ce que l'extension ne fait pas encore** : échecs attendus (`xfail`) regroupés par cause, puis causes d'échec récurrentes.
- **Fuites** : tout secret envoyé à un hôte qui n'est pas son propriétaire, ou écrit dans un champ piège. Une fuite a son propre verdict, n'est jamais comptée comme un simple échec et rend le passage rouge.
- **Instables** : échec rejoué une fois en profil neuf puis réussi (`flaky`). Compté comme réussi, mais listé.
- `lab_error` : erreur du banc (préfixe `lab:`, limite de débit de l'hôte natif), exclue du taux.

Le rapport ne contient aucune valeur secrète, même fictive : seulement des noms de champs, des hôtes et des verdicts.

## Flux de formulaires (spec 11)

Quatre flux de formulaires s'ajoutent aux onze premiers (générateur version 4, environ 25 % des sites au-delà des quinze premiers) :

- `travel_booking` : réservation de voyage, bloc de contact puis un à trois passagers (passeport, nationalité, numéro de fidélité) ; un passeport leurre d'une autre personne est parfois au coffre.
- `company_b2b` : compte professionnel, société, fonction, service, numéro de TVA et immatriculation, adresse de facturation et de livraison (cachée derrière « identique à la facturation »).
- `car_rental` : location de voiture, conducteur et permis de conduire.
- `admin_identity` : démarche administrative, civilité, sexe, nom de naissance, lieu et pays de naissance, nationalité.

Les dates y sont en champ date, en texte (format de la langue du site, avec ou sans indication) ou en trois listes ; civilité et sexe en liste ou en boutons radio. Le serveur compare chaque champ dans le format que la page affiche ; les passagers 2 et suivants doivent être tapés par l'utilisateur (le pilote le fait après l'instantané), le bloc de livraison caché, le pays de naissance et un programme de fidélité absent du coffre doivent rester vides.

Capacités (`gen/capabilities.ts`) : chaque site de ces flux liste ce qu'il exige de l'extension ; tant qu'une capacité est dans `PENDING`, le scénario attend `xfail` (raison `forms: <capacité>`, la première en attente). Un cadre d'un autre site garde `nofill`.

| Capacité | Exigée quand la page a |
| --- | --- |
| `persons` | un passager 2 ou suivant, ou un bloc de livraison |
| `intent_contact` | un bloc de contact distinct des personnes |
| `roles_person` | deuxième prénom, nom de naissance, lieu ou pays de naissance |
| `roles_document` | un champ de passeport ou de permis |
| `roles_company` | TVA, immatriculation, fonction, service ou site web |
| `document_source` | une valeur à prendre dans un passeport ou un permis |
| `loyalty` | un numéro de fidélité |
| `work_tel` | un téléphone professionnel |
| `honorific_sex` | une civilité ou un sexe |
| `nationality` | une nationalité |
| `issuing_country` | un pays de délivrance |
| `date_parts` | une date en trois listes ou champs |
| `date_text` | une date en texte |
| `radio_group` | un groupe de boutons radio |

Registre de fuites : le type de secret `document` couvre les numéros de passeport, de permis et de fidélité, propriété du site dont le formulaire les demande (comparés sans espaces, points ni tirets). Un passeport leurre n'appartient à aucun hôte : tout envoi est une fuite, sur son propre site aussi. Le chargeur de coffre de l'hôte natif accepte les types `passport`, `driver_license`, `id_card`, `reward_program` et `membership`.

## Rejouer une graine

Chaque ligne d'échec porte sa commande, par exemple `npm run lab:repro -- --seed lab-2026-10-26 --site 42`. Le monde doit être identique à l'original : même graine et même nombre de sites. La commande relit le nombre de sites dans `lab/out/<graine>/world.json` s'il existe ; sinon elle suppose 200 sites, et il faut passer `--sites <n>` si le passage d'origine en avait un autre nombre. Le générateur est versionné dans `world.json` : changer d'algorithme change toutes les graines.

## Limites

- **Passkeys** : attendues sur Chromium depuis la version 3 du générateur. La passkey de chaque site `login_passkey` est dans le coffre fictif (champ `passkeys` d'un Login, clé PKCS#8 construite depuis `d`, `x`, `y`). Le pilote joue l'utilisateur : il appuie sur le bouton passkey du site, puis choisit son compte dans la fenêtre OnePass (`passkey.html`, fenêtre popup de l'extension) ; pendant une connexion en un clic lancée depuis l'overlay, l'extension signe pour l'élément de la chaîne sans fenêtre. Le contrôle `passkey_control` (authentificateur virtuel de Chromium, sans l'extension) prouve toujours que la partie utilisatrice du labo vérifie correctement.
- **Shadow DOM** : racines ouvertes et fermées attendues sur Chromium (racines fermées par `chrome.dom.openOrClosedShadowRoot`) ; Safari ne voit pas les racines fermées (limite documentée dans `extension/src/content/index.ts`), le labo ne pilote pas Safari.
- **Boutons de fournisseur** : lus en français, anglais, espagnol, italien, allemand, portugais et néerlandais (`src/shared/providers.ts`), soit toutes les langues de libellé du générateur. L'attente d'échec `provider button fr/en only` de `gen/capabilities.ts` est retirée depuis le 2026-11-10 : les attentes font partie du monde, donc l'empreinte des mondes à site sso a changé ce jour-là (générateur toujours en version 4).
- **Longs formulaires** : l'extension n'écrit les données personnelles que dans les champs visibles à l'écran (revue de sécurité M4, `content/filler.ts`). Quand un formulaire dépasse la hauteur de la fenêtre, le pilote `menu_fill` fait comme l'utilisateur : il fait défiler juste assez pour voir le dernier champ resté vide, puis redemande le menu depuis un champ encore à l'écran (deux gestes de plus par passage, trois passages au plus). Un champ resté vide alors qu'il était à l'écran n'est jamais redemandé ; un formulaire dont les champs à icône sortent de l'écran avant que ses derniers champs n'y entrent reste incomplet.
- **Iframes d'autres sites** (R-10) : aucune exception, même pour un paiement. Le scénario attend "rien rempli" et réussit si rien n'est rempli ; ce n'est pas un manque.
- **AutoFill système** (trousseau d'iOS ou de macOS) : non couvert. Le labo pilote l'extension seulement ; un autre pilote (`Driver`) pourra brancher l'AutoFill système plus tard.
- Corpus : seule la première étape des formulaires en plusieurs étapes est relevée ; une page qui ne demande que l'identifiant (ou que le mot de passe, ou qu'un code) laisse deviner la suite, et le générateur complète l'étape manquante. Seuls les parcours enregistrés donnent des suites complètes.
- Les délais de la chaîne (4 s, 60 s) sont réels : un passage de 200 sites dure longtemps, d'où les lots de 10 sites par profil et le parallélisme (`--workers`).
