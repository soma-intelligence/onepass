# Quatre langues et clés stables : conception

Date : 2026-11-02. Statut : approuvée en autonomie (course parallèle du 2026-11-02, rulings en section 7). Point 17 du retour iOS du 2026-11-02 (`.superpowers/briefs/2026-11-02-ios-feedback.md`).

## 1. But

Anglais, français, espagnol et italien partout où un utilisateur lit un texte : apps Apple (iPhone, iPad, Mac, Watch, Vision), extensions d'app (AutoFill, widgets, notifications, raccourcis), extension de navigateur. Ajouter une cinquième langue doit être une étape mécanique : exporter ce qui manque, traduire un fichier, l'importer, lancer le contrôle. Aucune passe dans le code.

## 2. Existant (audit du 2026-11-02)

- **Swift.** Catalogues `Localizable.xcstrings` par cible, langue source `fr`, clés = texte français extrait par Xcode (`Text("Réglages")`). App : 1 494 entrées, VaultKit 231, DesignKit 79, AutoFill 89, Watch 12, Widgets 15, notifications 2, raccourcis 4, `InfoPlist` 6. Anglais presque complet, ni espagnol ni italien. `CoreLabels.xcstrings` (454 libellés des modèles du core) a déjà des clés sémantiques (`field.login.password`) et est généré par `apple/scripts/core_labels/gen.py`.
- **Conséquence des clés en français.** Corriger une virgule du français change la clé : toutes les traductions de l'entrée deviennent orphelines et l'anglais retombe sur le français. Un même mot (« Annuler », « Coffre ») est traduit autant de fois qu'il a d'entrées.
- **Extension.** 306 appels `tr("français", "english")` dans le code, choix binaire fr/en, sans pluriel (`n > 1 ? tr(...) : tr(...)`). `_locales` (fr, en) pour les trois chaînes du manifeste.
- **CLI, MCP.** Rust, anglais seulement, sortie lue par des scripts et des agents.
- **Ton.** Le français tutoie (« Saisis ton mot de passe maître ») : l'espagnol tutoie (tú), l'italien aussi (tu).

## 3. Schéma de clés

1. **Clé sémantique, stable.** `zone.écran.élément` en lowerCamelCase séparé par des points : `settings.general.autoLock`, `items.empty.title`. La clé ne change jamais quand le texte change ; le texte français est la valeur `fr` de l'entrée (`extractionState: manual`). Une clé avec des arguments garde ses spécificateurs en fin de clé, dans l'ordre : `items.addTo %@`.
2. **Symboles générés.** `STRING_CATALOG_GENERATE_SYMBOLS = YES` : Xcode génère `LocalizedStringResource.settingsGeneralAutoLock` et `.itemsAddTo(_:)`. Le code nouveau écrit `Text(.settingsGeneralAutoLock)` ou `String(localized: .itemsAddTo(name))` : une clé absente est une erreur de compilation. Les vues qui prennent un `LocalizedStringKey` gardent la clé en littéral (`Button("common.cancel")`).
3. **Glossaire, source unique.** `scripts/i18n/glossary.json` porte les termes du produit (`term.vault`, `term.passkey`, `term.watchtower`, `term.travelMode`...) et les actions communes (`common.cancel`, `common.done`...) dans les quatre langues. Les entrées `term.*` et `common.*` des catalogues sont recopiées depuis le glossaire par `i18n.py sync` (jamais traduites à la main) ; le contrôle refuse un écart. À l'intérieur d'une phrase, le terme n'est pas inséré par composition (accords, articles) : le traducteur écrit la forme du glossaire, et le contrôle signale une phrase qui contient le terme anglais sans le terme de sa langue.
4. **Composition.** Interdit : coller des fragments de phrase (`"Supprimer " + nom`, `tr("Autre compte ") + nom`), choisir un mot selon le nombre par code. Permis : un argument qui est un nom propre ou une donnée (`%@` = nom d'un site, d'un coffre, un nombre), une liste mise en forme par `ListFormatter`, une phrase entière par cas. Pluriels : variations `plural` du String Catalog (Swift) et `Intl.PluralRules` (extension), jamais `n > 1 ?`.
5. **Clés héritées.** Les clés en texte français restent valides pendant la migration ; `i18n.py rekey` les remplace par des clés sémantiques (catalogue et littéraux Swift d'une cible, en une fois, traductions conservées).
6. **Extension.** `extension/src/shared/l10n/{fr,en,es,it}.json`, clés sémantiques à plat, arguments nommés `{site}`, pluriels `{ "one": ..., "other": ... }`. `t(key, args)` et `tn(key, n, args)`. Le type `Key` vient de `fr.json` : une langue à qui il manque une clé ne compile pas. `tr(fr, en)` disparaît.

## 4. Langues et repli

- Langues : `fr` (source), `en`, `es`, `it` dans tous les catalogues, `knownRegions` et `_locales`.
- Repli pour une langue non prise en charge : anglais (`CFBundleDevelopmentRegion = en` dans les `Info.plist`, langue par défaut de l'extension `en`). La langue source des catalogues reste le français.
- CLI et MCP : anglais seulement (ruling R3).

## 5. Contrôle

`python3 -I scripts/i18n/i18n.py check` (CI : `.github/workflows/i18n.yml`, local : `make -C apple i18n-check`) échoue quand :

- une entrée traduisible n'a pas de valeur dans une des quatre langues (ou garde l'état `new`) ;
- les spécificateurs (`%@`, `%lld`, `%1$@`, `${applicationName}`, `{site}`, `$1`) diffèrent entre le français et une autre langue (la catégorie `one`/`zero` d'un pluriel peut omettre le nombre) ;
- un pluriel n'a pas `one` et `other` dans chaque langue ;
- une entrée `term.*`/`common.*` diffère du glossaire ;
- un catalogue de l'extension n'a pas exactement les clés du français ;
- un texte contient un tiret cadratin ;
- l'extension appelle encore `tr(`.

Il avertit (sans échouer) pour les termes du glossaire absents d'une traduction et pour les clés héritées restantes.

## 6. Ajouter une langue

`docs/i18n.md` : ajouter le code à `scripts/i18n/config.json`, `i18n.py export de` écrit un fichier de travail (français, anglais, commentaire, valeur vide) par catalogue, on traduit le fichier, `i18n.py import`, compléter le glossaire, `i18n.py check`, `knownRegions` et `_locales`. Rien d'autre.

## 7. Rulings

- R1 : clés sémantiques avec symboles générés plutôt qu'un fichier Swift généré à la main (SwiftGen) - Xcode 27 les génère dans l'app et dans les paquets, sans étape de plus pour les autres agents - si faux : un générateur maison, les clés restent.
- R2 : les entrées `term.*`/`common.*` sont recopiées dans chaque catalogue au lieu d'être lues dans un paquet partagé - une recherche dans un autre bundle demande de changer les signatures des vues ; la recopie est mécanique et contrôlée - si faux : quelques octets de plus par cible.
- R3 : CLI et MCP restent en anglais - outils de terminal et d'agents, sortie analysée par des scripts - si faux : un catalogue Rust plus tard.
- R4 : repli en anglais pour une langue non prise en charge, source toujours française - « anglais par défaut » du retour - si faux : une ligne par `Info.plist`.
- R5 : espagnol et italien tutoient, comme le français - ton de la maison - si faux : une passe de traduction.
- R6 : termes du glossaire en espagnol et en italien alignés sur Apple (Ajustes, Impostazioni, llave de acceso, passkey, Autorrelleno, Riempimento automatico) ; noms de fonctions gardés en anglais comme en français (Watchtower, Travel Mode, Secret Key, Emergency Kit) - cohérence avec le système et avec le français - si faux : une ligne du glossaire, puis `sync`.
- R7 : contrôle en CI et en `make`, pas en phase de build Xcode - ne pas casser le build des agents qui ajoutent des chaînes en cours de course ; le balayage final traduit leurs chaînes - si faux : une phase de build plus tard.
- R8 : les clés héritées de l'app et de VaultKit sont migrées en fin de course, après les autres agents - éviter des conflits de rebase sur des centaines de fichiers en cours d'édition - si faux : le schéma reste mixte jusqu'au passage suivant de `rekey`.
