# Ouvrir et se connecter (Open and sign in)

Date : 2026-11-04. Statut : livré.

## Demande

Dans l'app, sur un login, toucher le lien du site web (par exemple Google) ouvre la page de connexion, remplit l'identifiant, le mot de passe et le code à usage unique si l'item a un TOTP, et l'utilisateur est connecté. Comme "Open & Fill" de 1Password.

## Parcours

1. App (Mac, iPhone, iPad), fiche d'un login, carte des sites web : toucher le lien, ou "Ouvrir et se connecter" dans le menu de la ligne et dans le menu Actions de la fiche. Le menu de la ligne garde "Ouvrir" (sans connexion) et "Copier".
2. L'app écrit une connexion en attente (`OpenAndSignIn.prepare`, Rust `record_pending_sign_in`) puis ouvre l'URL dans le navigateur par défaut (Safari sur iPhone).
3. L'extension, sur une page HTTPS du cadre principal qui montre un formulaire de connexion, demande à l'hôte du pont `take_sign_in` (origine et origine du cadre principal lues dans `sender`). L'hôte rend l'identifiant d'item une seule fois si la page est du même domaine enregistrable, dans les 60 s.
4. Vault verrouillé : Face ID dans l'extension Safari sur iPhone (`unlock_biometric`), sinon l'`unlock` de l'app.
5. L'extension démarre la chaîne de connexion existante (`chain/driver.ts`, spec 8.6) : identifiant, mot de passe, code TOTP, chacun sur sa page, chaque valeur demandée juste à temps par `fill_login` (qui refait la règle de correspondance de l'item), chaque étape envoyée. CAPTCHA, validation sur téléphone, mot de passe refusé, changement de domaine ou 60 s écoulées : la chaîne s'arrête et rend la main, sans boucle.

## Entrée en attente

Fichier `pending-sign-in.json` dans le dossier du magasin (`SharedContainer.databaseFolder`, conteneur App Group), 0600, écrit par fichier temporaire et renommage :

```json
{"v":1,"item_id":"<uuid>","site":"google.com","host":"accounts.google.com","created":1800000000,"expires":1800000060}
```

- Une seule entrée : un nouveau toucher remplace l'ancienne. "Ouvrir" seul l'efface.
- Jamais de secret ni de nom d'utilisateur. Ne quitte jamais l'appareil.
- Prise par renommage atomique : de deux hôtes qui la prennent en même temps, un seul gagne.
- Refus : page `http`, origine du cadre différente de celle du cadre principal, autre domaine enregistrable (l'entrée reste), entrée expirée, venue du futur (plus de 5 s de décalage), durée de vie supérieure à 60 s ou illisible (supprimée).
- URL d'item `http` : l'app ouvre la page sans rien écrire. URL sans schéma : lue en `https`.
- L'hôte ne rend que l'identifiant ; déverrouillé, il vérifie que l'item est un login éligible.

## Protocole du pont

Nouvelle opération, compatible : un hôte plus ancien répond `invalid`, que l'extension lit comme "rien".

```json
{"id":7,"op":"take_sign_in","origin":"https://www.atlas-cloud.test","top_origin":"https://www.atlas-cloud.test"}
{"id":7,"ok":{"item_id":"0192f1a0-5a1e-7000-8000-00000000a7a5"}}
{"id":7,"ok":{"item_id":null}}
```

Servie verrouillée aussi (seul un identifiant sort), non comptée dans la limite de débit des secrets, journalisée (`take_sign_in`, contexte `chain`) quand elle rend un item. Vecteurs : `core/onepass-bridge/tests/vectors/sign_in.json` (requête, réponses, règles de prise), relus par l'extension.

Hôtes : l'app Mac (`BrowserBridge`, `BridgeServer.setPendingDir`), l'extension Safari iOS (`SafariExtensionVault`), l'hôte de développement (`data_dir`, sous-commande `onepass-native-host sign-in <item> <url>` qui joue le rôle de l'app dans les tests de bout en bout).

## Décisions

- Navigateur par défaut sur Mac (Chrome et Firefox passent aussi par l'app), Safari par défaut sur iPhone : l'entrée n'est pas liée à un navigateur. Coût si faux : une autre extension appairée qui charge le même site dans les 60 s prendrait l'entrée ; elle ne remplit que le même login sur le même site.
- La demande `take_sign_in` part seulement d'une page avec un formulaire de connexion, une fois par document du cadre principal : pas d'aller-retour vers l'app à chaque page. Une URL d'item qui mène à une page d'accueil sans formulaire attend que l'utilisateur atteigne le formulaire dans les 60 s.
- Envoi automatique : la préférence par item de la chaîne (R-12, active par défaut) s'applique.
- iPhone : aucune API ne dit si une extension Safari est activée. Sans appairage Safari dans le trousseau partagé (l'extension s'appaire seule à sa première exécution), l'app montre une ligne : activer l'extension Safari de OnePass permet de se connecter automatiquement. Rien n'est copié.
- Mac, build Debug : l'extension Safari préfère l'hôte de développement embarqué, qui lit son propre `data_dir`, pas le conteneur App Group ; le parcours complet demande un build signé par l'équipe (comme le pont).
