# Extension : couverture des formulaires (voyage, entreprise, location de voiture, identité administrative)

Date : 2026-11-06. Branche : `main` (checkout principal). Statut : approuvée en autonomie, rulings en section 12 et dans `.superpowers/sdd/2026-11-06-forms-coverage/progress.md`. Plan : `docs/superpowers/plans/2026-11-06-forms-coverage.md`.

## 1. But et critère de fin

L'extension remplit aujourd'hui la connexion, l'inscription, le paiement, l'adresse et une identité réduite (prénom, nom, e-mail, téléphone, date de naissance, entreprise, adresse). Le but : remplir aussi les formulaires qui demandent une personne au complet et ses papiers, comme le ferait la personne elle-même :

- réservation de vol ou de train (passeport tiré du coffre, plusieurs passagers, programme de fidélité) ;
- coordonnées d'entreprise (raison sociale, poste, service, numéro de TVA, SIRET, adresse de facturation et de livraison) ;
- location de voiture (permis de conduire) ;
- formulaires administratifs (civilité, nom de naissance, sexe, lieu de naissance, nationalité).

Critère de fin, mesuré par le laboratoire (`extension/lab`) :

1. deux passages complets de 200 sites (graines `forms-2026-11-06-a` et `forms-2026-11-06-b`, pilotes `current,smart_fill`) à 95 % ou plus hors échecs attendus, chacun ;
2. sur chaque graine, chacun des quatre nouveaux flux à 90 % ou plus (petits effectifs : la marge absorbe un site) ;
3. zéro fuite, zéro `wrong_item`, zéro `auto_submit_outside_login`, zéro `other_person_filled` (section 11.4) ;
4. aucune capacité en attente (`PENDING` vide, section 11.4) : plus aucun échec attendu propre aux nouveaux flux ;
5. aucune régression : les flux existants restent au moins à leur taux du passage de référence (tâche 4 du plan) moins un site ; `npm run check`, `npm run lab:smoke`, les e2e S1 à S21 (`npm run e2e`) et `cargo test` restent verts.

## 2. Ce qui existe, ce qui manque

### 2.1 Détection (extension)

| Sujet | Aujourd'hui | Manque |
| --- | --- | --- |
| Rôles de champ | 25 rôles (`FieldRole`, `shared/messages.ts`) : identifiants, mots de passe, code, carte, `given_name`, `family_name`, `full_name`, `tel`, `organization`, `bday`, adresse, `region`, `country`, `remember_me` | civilité, deuxième prénom, nom de naissance, sexe, lieu et pays de naissance, nationalité, numéro, dates et pays de délivrance du passeport et du permis, numéro de fidélité, poste, service, TVA, immatriculation d'entreprise, site web |
| `autocomplete` | jetons de nom, contact, carte, adresse, `bday` | `honorific-prefix`, `additional-name`, `sex`, `bday-day`, `bday-month`, `bday-year`, `organization-title`, `url` sont ignorés |
| Lexique | fr, en, puis de, es, it, pt, nl pour les rôles actuels | aucun terme pour les nouveaux rôles ; « nom de naissance » compte aujourd'hui pour `family_name` (faux pour un formulaire qui demande les deux) |
| Pièges de sens | « expiration » est une date de carte | « date d'expiration » à côté d'un numéro de passeport est celle du passeport ; « pays de naissance », « pays de délivrance » et « nationalité » ne sont pas le pays de l'adresse ; « département » à côté d'une entreprise est un service |
| Groupes | cellules d'un code découpé (`parts`) | trois listes jour, mois, année sous un libellé commun ; boutons radio de civilité ou de sexe (pris un par un, sans groupe) |
| Personnes | un formulaire est une seule personne : `fillOnce` remplit chaque champ de chaque rôle répété | blocs « Passager 2 », « Adulte 3 » : aucune notion de personne, donc le titulaire serait copié dans chaque passager |
| Facturation et livraison | deux blocs d'adresse remplis tous les deux (rôle répété) | rien à changer, à garder quand les blocs de personne arrivent |
| Modèles (gbm, encoder) | 21 classes figées (`MODEL_ROLES`, `ml/onepass_ml/labels.py`) | les nouveaux rôles restent heuristiques (ruling R13) |

### 2.2 Remplissage (extension, pont, cœur)

| Sujet | Aujourd'hui | Manque |
| --- | --- | --- |
| Éléments exposés | le pont ne résume et ne remplit que Login, CreditCard et Identity (`policy.rs` `summary_kind`, `service.rs` `fill_other`) | Passport, DriverLicense, RewardProgram et Membership ne sortent jamais de l'hôte |
| Valeurs d'identité | `identity_values` : prénom, nom, e-mail, un téléphone, entreprise, date de naissance, adresse | civilité, deuxième prénom, nom de naissance, sexe, lieu de naissance, nationalité, poste, service, site web, téléphone pro, TVA, immatriculation |
| Dates | `bday` part en `AAAA-MM-JJ` dans le champ, quel qu'il soit | listes séparées, champ texte `JJ/MM/AAAA` ou `MM/DD/YYYY`. Le traitement existe sur `origin/main` (commit `0e6272ce`, `extension/src/content/date.ts`) mais pas dans ce checkout, qui ne fusionne pas (ruling R10) |
| Listes | pays et région intelligents (`content/geo`), mois et année de carte | civilité, sexe, nationalité, pays de délivrance ; options en démonymes (« Française », « German ») ; groupes radio |
| Planificateur | groupes `login`, `card`, `identity`, `generated_password` ; règle 6 de `intent_of` : un identifiant présent sans mot de passe donne `Login` | un formulaire de réservation avec e-mail de contact et nom risque `Login` ; les nouveaux rôles ne sont dans aucun `wants` |
| Coffre | Identity (sections `main` et `work`), Passport, DriverLicense, IdCard, Membership, RewardProgram existent (`templates.rs`) | TVA et immatriculation d'entreprise n'ont aucun champ |

### 2.3 Laboratoire

`FlowId` n'a que onze flux (`gen/model.ts`) ; les libellés viennent du corpus (`patterns.json`), qui n'a aucun des nouveaux rôles ; la fixture de l'hôte natif (`onepass-native-host/src/fixture.rs`, `item_type`) ne connaît que login, password, credit_card, identity, secure_note et crypto_wallet ; le registre de fuites ne connaît que mots de passe, TOTP, cartes et CVC ; l'oracle ne connaît qu'une personne par formulaire.

## 3. Vocabulaire des champs

Chaque nouveau rôle de l'extension, son jeton `autocomplete` quand le standard HTML en a un, et le lexique (texte normalisé par `normalizeText` : minuscules, sans accents, « ß » lu « ss »). Les listes sont des minimums : l'implémenteur ajoute les variantes que les témoins du labo révèlent, jamais en recopiant le lexique du générateur.

### 3.1 Identité administrative

| Rôle | `autocomplete` | fr | en | de | es | it | pt | nl |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `honorific_prefix` | `honorific-prefix` | civilite, titre | title, salutation, honorific, prefix | anrede, titel | tratamiento, titulo | titolo, appellativo | tratamento, titulo | aanhef, titel |
| `additional_name` | `additional-name` | deuxieme prenom, autres prenoms, second prenom | middle name, middle initial | zweiter vorname, weitere vornamen | segundo nombre | secondo nome | nome do meio, segundo nome | tweede voornaam (voir R14) |
| `birth_name` | aucun | nom de naissance, nom de jeune fille | birth name, maiden name, name at birth | geburtsname, madchenname | apellido de nacimiento, apellido de soltera | cognome di nascita, cognome da nubile | nome de nascimento, nome de solteira | geboortenaam, meisjesnaam |
| `sex` | `sex` | sexe, genre | sex, gender | geschlecht | sexo, genero | sesso, genere | sexo, genero | geslacht |
| `birth_place` | aucun | lieu de naissance, ville de naissance, commune de naissance | place of birth, birthplace, city of birth | geburtsort | lugar de nacimiento, ciudad de nacimiento | luogo di nascita, comune di nascita | local de nascimento, naturalidade | geboorteplaats |
| `birth_country` | aucun | pays de naissance | country of birth | geburtsland | pais de nacimiento | paese di nascita, stato di nascita | pais de nascimento | geboorteland |
| `nationality` | aucun | nationalite, citoyennete | nationality, citizenship | staatsangehorigkeit, nationalitat | nacionalidad | nazionalita, cittadinanza | nacionalidade | nationaliteit |
| `bday` (parties) | `bday`, `bday-day`, `bday-month`, `bday-year` | date de naissance, jour, mois, annee | date of birth, day, month, year | geburtsdatum, tag, monat, jahr | fecha de nacimiento, dia, mes, ano | data di nascita, giorno, mese, anno | data de nascimento, dia, mes, ano | geboortedatum, dag, maand, jaar |

`birth_country` est un rôle de détection seulement : le coffre n'a pas de pays de naissance, le champ reste vide (ruling R5). Le reconnaître empêche le pays de l'adresse d'y entrer.

### 3.2 Voyage

| Rôle | `autocomplete` | fr | en | de | es | it | pt | nl |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `passport_number` | aucun | numero de passeport, n passeport | passport number, passport no | reisepassnummer, passnummer, pass nr | numero de pasaporte | numero di passaporto | numero do passaporte | paspoortnummer |
| `passport_issue_date` | aucun | date de delivrance, delivre le | date of issue, issue date | ausstellungsdatum, ausgestellt am | fecha de expedicion, fecha de emision | data di rilascio, data di emissione | data de emissao | afgiftedatum, datum van afgifte |
| `passport_expiry` | aucun | date d'expiration, valable jusqu'au | expiry date, expiration date, valid until | ablaufdatum, gultig bis | fecha de caducidad, fecha de vencimiento | data di scadenza, valido fino al | data de validade, valido ate | vervaldatum, geldig tot |
| `passport_issuing_country` | aucun | pays de delivrance, pays emetteur | issuing country, country of issue | ausstellungsland, ausstellender staat | pais de expedicion, pais emisor | paese di rilascio, stato di rilascio | pais emissor, pais de emissao | land van afgifte |
| `loyalty_number` | aucun | numero de fidelite, carte de fidelite, numero grand voyageur | frequent flyer number, loyalty number, rewards number, membership number | vielfliegernummer, bonusnummer, kundenkartennummer | numero de viajero frecuente, numero de socio | numero frequent flyer, codice fedelta, numero socio | numero de passageiro frequente, numero de fidelidade | frequent flyer nummer, lidmaatschapsnummer |

Les rôles de date et de pays d'un document (`*_issue_date`, `*_expiry`, `*_issuing_country`) se décident par le contexte (ruling R6) : les termes de date et de pays de délivrance comptent pour le passeport quand le formulaire contient un `passport_number`, pour le permis quand il contient un `license_number` ; sans numéro de document, « expiration » garde ses poids de carte d'aujourd'hui. Les mots « passeport », « permis », « Reisepass », « Führerschein » (et leurs équivalents) dans le libellé tranchent quand les deux numéros sont présents.

### 3.3 Location de voiture

| Rôle | `autocomplete` | fr | en | de | es | it | pt | nl |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `license_number` | aucun | numero de permis, n permis de conduire | driver's license number, driving licence number, licence number | fuhrerscheinnummer, fuhrerschein nr | numero de permiso de conducir, numero de carne de conducir | numero di patente | numero da carta de conducao | rijbewijsnummer |
| `license_issue_date` | aucun | date de delivrance du permis, permis delivre le | license issue date, date of issue | ausstellungsdatum des fuhrerscheins | fecha de expedicion del permiso | data di rilascio della patente | data de emissao da carta | afgiftedatum rijbewijs |
| `license_expiry` | aucun | date d'expiration du permis | license expiry date | fuhrerschein gultig bis | fecha de caducidad del permiso | scadenza patente | validade da carta | vervaldatum rijbewijs |
| `license_issuing_country` | aucun | pays de delivrance du permis | country of issue, issuing country | ausstellungsland | pais de expedicion | paese di rilascio | pais emissor | land van afgifte |

### 3.4 Entreprise

| Rôle | `autocomplete` | fr | en | de | es | it | pt | nl |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `organization` (existant) | `organization` | societe, entreprise, raison sociale | company, company name, organization | firma, firmenname, unternehmen | empresa, razon social | azienda, ragione sociale | empresa, razao social | bedrijf, bedrijfsnaam |
| `job_title` | `organization-title` | poste, fonction, intitule du poste | job title, position, role | position, berufsbezeichnung, funktion | cargo, puesto | ruolo, posizione, qualifica | cargo, funcao | functie, functietitel |
| `department` | aucun | service, departement (avec une entreprise) | department, division | abteilung | departamento | reparto, dipartimento | departamento | afdeling |
| `vat_number` | aucun | numero de tva, tva intracommunautaire | vat number, vat id, vat registration number | ust idnr, umsatzsteuer id | numero de iva, nif iva | partita iva, p iva | numero de iva, nif | btw nummer, btw id |
| `company_id` | aucun | siret, siren, numero rcs, numero d'immatriculation | company number, company registration number | handelsregisternummer, hrb | cif, numero de registro mercantil | numero rea, codice fiscale azienda | nipc, numero de matricula | kvk nummer, kvk |
| `website` | `url` | site web, site internet | website, homepage | webseite, homepage | sitio web, pagina web | sito web | site, website | website |
| `tel` (pro) | `work tel` | telephone professionnel, telephone pro | work phone, business phone, office phone | telefon geschaftlich, diensttelefon | telefono del trabajo | telefono di lavoro, telefono ufficio | telefone do trabalho | zakelijk telefoonnummer, werktelefoon |

« département » seul reste `region` (France) ; il devient `department` quand le formulaire a un champ `organization` ou `job_title` et aucun champ d'adresse dans le même bloc (ruling R6). Le téléphone pro garde le rôle `tel` ; le qualificatif `work` (jeton `autocomplete`, ou les mots ci-dessus) passe par un drapeau `work` du `FieldInfo` (ruling R7).

## 4. Quel élément remplit quel champ

Le principe : **l'identité choisie est la personne**. Le planificateur et le menu choisissent une Identity comme aujourd'hui (mémoire du site, pays du domaine, classement, menu en cas d'égalité) ; le pont lui associe ses papiers et la carte de fidélité du site, sans autre choix de l'utilisateur. Aucun nouveau groupe de plan, aucune nouvelle ligne de menu (ruling R1).

| Rôle | Source | Règle |
| --- | --- | --- |
| `honorific_prefix` | Identity `honorific`, sinon `sex` | section 7 |
| `given_name`, `family_name`, `full_name` | Passport `first_names` et `last_name` quand le formulaire a un rôle de passeport et que le passeport associé les a ; sinon Identity `first_name`, `last_name` | le nom du billet doit être celui du passeport |
| `additional_name` | Identity `middle_name` | |
| `birth_name` | Identity `birth_name` | vide s'il n'existe pas (jamais le nom actuel à sa place) |
| `sex` | Identity `sex`, sinon Passport `sex` | section 7 |
| `bday` | Identity `birth_date`, sinon Passport `birth_date` | section 6 |
| `birth_place` | Identity `birth_place`, sinon Passport `birth_place` | texte tel quel |
| `nationality` | Identity `nationality`, sinon Passport `nationality` | section 8 |
| `passport_number`, `passport_issue_date`, `passport_expiry`, `passport_issuing_country` | Passport associé : `number`, `issued_on`, `expiry`, `issuing_country` | section 9 pour le numéro |
| `license_number`, `license_issue_date`, `license_expiry`, `license_issuing_country` | DriverLicense associé : `number`, `issued_on`, `expiry`, `country` | |
| `loyalty_number` | RewardProgram ou Membership du site : `member_number` | un seul élément éligible dont une URL correspond à l'origine (règle des Login, `item_match`) ; plusieurs ou aucun : vide |
| `organization`, `job_title`, `department`, `website` | Identity section `work` : `company`, `job_title`, `department`, `website` | |
| `vat_number`, `company_id` | Identity section `work` : `vat_number`, `company_registration` (nouveaux, section 5) | |
| `tel` avec drapeau `work` | Identity `work_phone`, sinon le téléphone d'aujourd'hui | |
| e-mail, téléphone, adresse | comme aujourd'hui | facturation et livraison reçoivent la même adresse (R17) |
| `birth_country` | aucune | toujours vide |

**Association d'un document à l'identité** (ruling R2), pour Passport, puis DriverLicense, dans le coffre éligible (`eligible` : ni archivé, ni à la corbeille, ni caché de l'autoremplissage) :

1. les documents dont le titulaire est la personne : nom de famille égal, et prénom de l'identité égal au premier des prénoms du passeport (Passport `last_name`, `first_names`) ou contenu dans le nom complet du permis (DriverLicense `full_name`), comparaison repliée (casse, accents, tirets et espaces) ;
2. exactement un tel document : c'est lui ; deux ou plus : le plus récent par `updated_at` parmi ceux qui ne sont pas expirés, sinon aucun ;
3. aucun : si le coffre éligible a exactement une Identity et exactement un document de ce type, c'est lui ; sinon aucun ;
4. aucun document associé : ses rôles restent vides, le reste de l'identité se remplit.

**Plusieurs passagers** (ruling R3) : le premier passager est le titulaire (identité choisie, passeport associé, fidélité du site). Les passagers suivants restent vides, toujours, même quand le coffre contient d'autres identités et d'autres passeports : rien dans une page ne dit qui voyage avec la personne, et un remplissage deviné écrit les papiers d'un tiers chez un site. L'utilisateur remplit lui-même les autres passagers (une ligne de menu « remplir ce passager avec » est hors périmètre). Le bloc de contact (e-mail, téléphone de la réservation) est celui du titulaire.

**Blocs de personne** : dans un formulaire, un bloc (conteneur avec légende, titre ou libellé de groupe) dont le texte dit un voyageur avec un rang 2 ou plus (« Passager 2 », « 2e passager », « Passenger 2 », « Adult 2 », « Reisender 2 », « Pasajero 2 », « Passeggero 2 », « Passageiro 2 », « Passagier 2 », « second passenger »), ou dont les noms de champs portent un index de voyageur après le premier (`passengers[1]`, `pax_2_`, `traveller2`, `adult-2`), donne `person` = rang moins un à ses champs. Des rôles de nom, de date ou de document répétés dans des blocs sans aucun de ces signes : seul le premier bloc se remplit. Des rôles d'adresse répétés sans signe de personne restent remplis tous (facturation, livraison).

## 5. Changements du coffre

**Ruling R4 : deux champs texte dans la section `work` d'Identity, pas de nouveau type Company.** Après `department` : `tx("vat_number", "Numéro de TVA")` et `tx("company_registration", "Immatriculation (SIRET, RCS)")`. Raisons :

- un type `Company` touche `ItemType::ALL` (26 types, testé), l'énumération FFI, les icônes, les écrans de création de chaque application, la recherche et l'import ; deux champs n'ajoutent que deux libellés ;
- le modèle garde les champs par identifiant : un élément créé avant n'a pas ces champs et `item.field("vat_number")` rend `None`, ce que `identity_values` traite déjà comme vide ;
- la fonction FFI `template` ne change pas de signature (même somme de contrôle uniffi) ; les applications lisent le modèle par elle. Elles demandent seulement les libellés traduits : `apple/scripts/core_labels/{en,es,it}_core.py` puis `gen.py`, qui réécrit `apple/VaultKit/Sources/VaultKit/Resources/CoreLabels.xcstrings`. Android n'a pas de table de libellés du cœur.

Un indépendant ou une entreprise unipersonnelle est déjà « une personne avec une entreprise » : c'est le cas que vise un formulaire B2B rempli par une personne. Plusieurs sociétés pour une personne se font par plusieurs identités, comme plusieurs adresses aujourd'hui.

Aucun autre changement de modèle : Passport, DriverLicense, RewardProgram et Membership ont déjà les champs de la section 4 ; `sex` est un menu (`Féminin`, `Masculin`, `Autre`) ; `honorific`, `nationality`, `issuing_country` et `country` sont du texte (ruling R8 : valeur canonique alpha-2 pour les deux pays et la nationalité, texte libre toléré).

## 6. Dates

Le pont envoie toute date en `AAAA-MM-JJ` (déjà le cas de `birthday`). Le content script l'écrit selon le champ, pour tout rôle de date (`bday`, `passport_issue_date`, `passport_expiry`, `license_issue_date`, `license_expiry`). Comportement, repris de `0e6272ce` et généralisé à ces rôles :

1. `input type=date` : `AAAA-MM-JJ` tel quel. `type=month` n'est jamais une date de naissance ni de document : rien.
2. **Champ d'une partie** : jeton `bday-day`, `bday-month`, `bday-year`, libellé ou nom (jour, day, tag, dia, giorno, dag ; mois, month, monat, mes, mese, maand ; année, year, jahr, ano, anno, jaar), ou options d'une liste (1 à 31 : jour ; 12 options de mois ou noms de mois : mois ; années à quatre chiffres : année). Jour sans zéro si les options n'en ont pas ; mois par numéro ou par nom dans les langues fr, en, de, es, it, pt, nl (abréviations comprises : « janv. », « Jan », « Mär », « ene », « gen », « fev », « mrt ») ; année à quatre chiffres, ou deux si le champ a `maxlength=2`.
3. **Champ texte** : le format que le placeholder ou l'attribut `pattern` écrit (`JJ/MM/AAAA`, `DD/MM/YYYY`, `MM/DD/YYYY`, `TT.MM.JJJJ`, `DD.MM.YYYY`, `dd-mm-jjjj`, `gg/mm/aaaa`, `dd/mm/aaaa`, `AAAA-MM-JJ`), séparateur compris ; sinon l'ordre de la langue de la page : `en-US`, et `en` sans région sur un domaine `.us`, en `MM/DD/YYYY` ; autres `en` en `DD/MM/YYYY` ; `de` en `DD.MM.YYYY` ; `nl` en `DD-MM-YYYY` ; `fr`, `es`, `it`, `pt` en `DD/MM/YYYY`.
4. Trois champs consécutifs sous un libellé de date commun (légende, titre du bloc ou libellé d'un `fieldset`) forment un groupe : chacun prend le rôle de date du groupe et sa partie (ruling R9). Une partie qu'aucun signe ne désigne reste vide.

Le jour et le mois d'un texte sans format ni langue connue suivent `DD/MM/YYYY` : c'est l'ordre de six des sept langues couvertes.

## 7. Civilité et sexe

Valeurs canoniques internes (jamais envoyées) : sexe `f`, `m`, `x` ; civilité `mr`, `mrs`, `ms`, `miss`, `mx`, `dr`.

- Sexe du coffre : `Féminin` donne `f`, `Masculin` donne `m`, `Autre` donne `x` ; toute autre saisie est lue par la table ci-dessous, sinon rien.
- Civilité du coffre (texte libre) : lue par la table, valeur exacte ; « Dr » ne devient jamais une autre civilité.
- Sans civilité, elle se déduit du sexe : `m` donne `mr` ; `f` donne la première option présente parmi `ms`, puis les équivalents de « madame » (`Mme`, `Frau`, `Sra.`, `Sig.ra`, `Sra.` portugaise, `Mevr.`), puis `mrs` ; jamais `miss` ni `Mlle` (l'état civil ne se devine pas) ; `x` donne `mx` s'il existe, sinon rien.

| Canonique | Options reconnues (texte ou valeur, repliés, point final ignoré) |
| --- | --- |
| `m` (sexe) | m, h, homme, masculin, male, man, mannlich, hombre, masculino, maschio, uomo, maschile, mannelijk |
| `f` (sexe) | f, femme, feminin, female, woman, weiblich, mujer, femenino, femmina, donna, femminile, feminino, mulher, vrouw, vrouwelijk |
| `x` (sexe) | x, autre, other, divers, diverse, otro, altro, outro, anders, non binaire, non binary |
| `mr` | m, monsieur, mr, mister, herr, sr, senor, sig, signor, signore, senhor, dhr, de heer |
| `ms` | ms |
| `mrs` | mrs, madame, mme, frau, sra, senora, sig ra, signora, senhora, mevr, mevrouw |
| `miss` | miss, mlle, mademoiselle, srta, senorita, signorina, menina, mej, mejuffrouw |
| `mx` | mx |
| `dr` | dr, docteur, doctor, doktor, dott, dottore |

Une option « M » est un sexe dans une liste de sexe, et « Monsieur » dans une liste de civilité : la table se lit par rôle. Listes et **groupes de boutons radio** sont traités de la même façon : un groupe radio (même `name`, même formulaire) dont la question (légende, libellé du groupe, texte qui précède) donne `honorific_prefix` ou `sex` est un champ logique dont les `parts` sont les boutons ; le remplisseur coche le bouton dont le libellé correspond (événements `click`, `input`, `change`) et ne touche pas un groupe que l'utilisateur a déjà coché. Égalité de deux options : rien.

## 8. Nationalité et pays de délivrance

Pays de délivrance (`passport_issuing_country`, `license_issuing_country`) : exactement le chemin du rôle `country` (`content/geo`, `pickCountry`, combobox compris), sans la région ni le code postal. Nationalité : la valeur est résolue en alpha-2 (`resolveCountry` : code, alpha-3, nom dans la langue de la page, fr, en) puis, si rien, par une table de démonymes ; l'option se choisit par le nom du pays (`pickCountry`), puis par le démonyme dans la langue de la page, fr et en, avec la même règle d'égalité (deux meilleures options de valeurs différentes : rien).

Table de démonymes (`content/geo/demonyms.ts`, ruling R8) : au moins les pays de l'UE, GB, CH, NO, IS, US, CA, MX, BR, AR, JP, CN, IN, AU, MA, DZ, TN, SN, en fr, en, de, es, it, pt, nl, formes masculine et féminine (« Française », « Français », « French », « Deutsch », « Deutsche », « Española », « Italiana », « Portuguesa », « Nederlandse »). Un champ texte de nationalité reçoit le démonyme dans la langue de la page (forme du sexe de l'identité quand la langue en a deux, masculine sinon), à défaut le nom du pays.

## 9. Sécurité des numéros de document

Les numéros de passeport et de permis suivent la règle des cartes (ruling R11) :

1. **Champ caché ou piège** : jamais remplis dans un champ invisible ni un champ piège (`isVisible`, mêmes gardes que les cartes ; l'exception des listes cachées des combobox pays et région ne s'étend jamais à ces rôles).
2. **Cadre d'un autre site** : jamais (R-10, `checkFillTarget`, sans exception).
3. **Geste de l'utilisateur** : seulement après un geste (ligne du menu, icône, bouton Remplir, raccourci) ; jamais à l'ouverture automatique du menu au clic dans un champ, au focus ou au chargement. Un formulaire qui contient un numéro de document n'est jamais envoyé par OnePass (déjà vrai hors connexion ; un test le fixe).
4. **Rôle exact** : seul un champ de rôle `passport_number` ou `license_number` reçoit le numéro, jamais un champ `unknown`, un identifiant, un code ou un champ d'un formulaire d'intention `Login`, `Signup`, `Otp` ou `Reset`.
5. **Autre personne** : jamais dans le bloc d'un autre passager (`person > 0`).
6. **Pont** : `fill_identity` ne renvoie un numéro de document que si la requête le demande (`extras`, section 10.2) ; chaque document fourni est inscrit au journal d'audit (`fill_document`, `fill_loyalty`) avec l'origine ; un document qui exige une nouvelle saisie du mot de passe maître (`reprompt`) la déclenche comme son identité. Le numéro reste `Concealed` dans le coffre et `SecretString` (zéroïsé) dans le pont.
7. **Journal et registre** : aucune valeur dans les événements, rapports et journaux, seulement des noms de champ (déjà la règle). Le registre de fuites du labo apprend le type `document` (section 11.4).
8. **Sosies** : une identité, un passeport et une carte ne sont liés à aucun domaine ; un sosie d'un site de voyage reçoit ce qu'y recevrait l'utilisateur, comme pour les cartes aujourd'hui. La fidélité, elle, est liée à l'URL du programme et ne sort jamais sur un sosie.

## 10. Contrats

### 10.1 Cœur (`onepass-core`, Rust)

- `FieldRole` : variantes ajoutées après `RememberMe`, avant `Unknown`, avec leurs noms serde (`honorific_prefix`, `additional_name`, `birth_name`, `sex`, `birth_place`, `birth_country`, `nationality`, `passport_number`, `passport_issue_date`, `passport_expiry`, `passport_issuing_country`, `license_number`, `license_issue_date`, `license_expiry`, `license_issuing_country`, `loyalty_number`, `job_title`, `department`, `vat_number`, `company_id`, `website`). `form_shape_hash` lit les noms : l'ajout ne change aucune empreinte existante.
- `is_identity_or_address` couvre les rôles de personne et d'entreprise ; nouveau `is_document` (numéros, dates et pays de document, fidélité). `wants(_, Identity)` prend les deux familles pour `Checkout` et `Address`, et les rôles de personne et d'entreprise seulement pour `Signup` (jamais un document à l'inscription).
- `intent_of`, règle 5 bis avant la règle 6 (ruling R12) : sans mot de passe ni code, un formulaire qui a au moins deux rôles d'identité, d'adresse ou de document hors identifiants est `Address` (ou `Checkout` s'il a une carte, règle 2 inchangée), même avec un e-mail. Un e-mail seul, ou un identifiant et un bouton suivant, reste `Login`.
- `templates.rs` : section 5. Aucun changement de `Intent`, `GroupKind`, `ReasonCode` ni de la FFI.

### 10.2 Pont et hôte natif

- `Request::FillIdentity` gagne `extras: Vec<Extra>` (`#[serde(default)]`), `Extra` = `passport`, `driver_license`, `loyalty`. L'extension ne demande que les extras dont le formulaire a les rôles.
- `Response::Identity` gagne des champs optionnels (absents si vides) : `honorific`, `middle_name`, `birth_name`, `sex` (canonique `f`, `m`, `x`), `birth_place`, `nationality`, `job_title`, `department`, `website`, `work_tel`, `vat_number`, `company_registration`, et `passport: Option<PassportOut>` (`first_names`, `last_name`, `number` secret, `issuing_country`, `issued_on`, `expiry`, `nationality`, `sex`, `birth_date`, `birth_place`), `driver_license: Option<LicenseOut>` (`number` secret, `country`, `issued_on`, `expiry`), `loyalty: Option<LoyaltyOut>` (`number` secret, `program`).
- `fixture.rs` (hôte natif, fixture du labo) : types `passport`, `driver_license`, `id_card`, `reward_program`, `membership`.
- FFI et applications : rien hors libellés (section 5).

### 10.3 Extension

- `FieldRole` TypeScript, `FIELD_ROLES` du routeur, `AUTOCOMPLETE_ROLES`, `TERMS` : section 3.
- `FieldInfo` gagne `person?: number` (0 ou absent : le titulaire), `work?: true` et, pour les groupes, `parts` (dates en trois champs, radios).
- `PageContext` : un champ `person > 0` part avec `role: null` (le planificateur ne le voit pas) ; aucun nouveau champ de contexte.
- `fill.ts` `fillIdentity` : extras selon les rôles du formulaire ; valeurs par rôle selon la section 4.

## 11. Laboratoire

### 11.1 Flux et générateur (version 4)

`GENERATOR_VERSION` passe à 4 (toutes les graines changent de monde, ruling R15). Quatre `FlowId` :

| Flux | Champs (ordre de base, variantes tirées) |
| --- | --- |
| `travel_booking` | contact (e-mail, téléphone), passager 1 (civilité 70 %, prénom, nom, date de naissance, nationalité 60 %, sexe 40 %, numéro de passeport, pays de délivrance 60 %, date de délivrance 30 %, date d'expiration, numéro de fidélité 50 %), passagers 2 à 3 (40 % des sites : mêmes rôles sans contact) |
| `company_b2b` | prénom, nom, e-mail, téléphone pro, raison sociale, poste 70 %, service 40 %, TVA 80 %, immatriculation 60 % (SIRET pour fr), site web 30 %, adresse de facturation, bloc de livraison 50 % (case « identique à la facturation » cochée sur la moitié : bloc caché, attendu vide) |
| `car_rental` | civilité 50 %, prénom, nom, date de naissance, e-mail, téléphone, numéro de permis, pays de délivrance 60 %, date de délivrance 70 %, date d'expiration 40 % ; pas de carte (ruling R16) |
| `admin_identity` | civilité, prénom, deuxième prénom 30 %, nom, nom de naissance 60 %, sexe 70 %, date de naissance, lieu de naissance, pays de naissance 40 % (attendu vide), nationalité, adresse 60 % |

Tirage : les quinze premiers sites couvrent les quinze flux dans l'ordre (`FLOWS` gagne les quatre en fin) ; au-delà, un flux propre au site (`fork("forms-flow")`) remplace le tirage d'aujourd'hui par un des quatre nouveaux flux avec une probabilité 0,25 (parts égales). Les flux d'avant gardent leurs poids relatifs.

Rendu des dates par site : `type=date` 30 %, texte avec placeholder dans la langue du site 25 %, texte sans indication 15 % (ordre de la langue), trois listes 30 % (jour avec ou sans zéro, mois en chiffres ou en noms de la langue du libellé, années). Civilité et sexe : liste 60 %, radios 40 %. Nationalité et pays : liste de noms de pays dans la langue du site 60 %, démonymes 20 % (nationalité seulement), texte 20 %. `autocomplete` posé selon une table propre (jetons de la section 3 quand ils existent, taux 0,5) ; `no_autocomplete` et `obfuscated_names` s'appliquent comme aux autres flux.

Libellés : `lab/gen/forms-lexicon.ts`, écrit à la main, au moins trois variantes par rôle et par langue (fr, en, de, es, it, pt, nl), dont une forme abrégée (« N° passeport », « Pass-Nr. », « Nº pasaporte ») ; jamais dérivé du lexique de l'extension (le labo ne se note pas avec ses propres mots). `mixed_language` s'applique.

Traits : ceux des formulaires d'aujourd'hui (`honeypot` sur un rôle de document la moitié du temps pour ces flux, `iframe_same_origin`, `iframe_cross_site`, `shadow_*`, `spa_rerender`, `delayed_fields`) ; `decoy_form` et `lookalike` restent réservés aux connexions.

### 11.2 Données synthétiques (`lab/gen/forms-data.ts`)

Tout est tiré du `Rng` du site, rien de réel :

- passeport : numéro au format du pays de l'identité (FR `\d{2}[A-Z]{2}\d{5}`, DE `C[0-9CFGHJKLMNPRTVWXYZ]{8}`, ES `[A-Z]{3}\d{6}`, IT `[A-Z]{2}\d{7}`, PT `[A-Z]\d{6}`, NL `[A-NP-Z]{2}[A-NP-Z0-9]{6}\d`, US et autres `\d{9}`), dates de délivrance et d'expiration cohérentes (10 ans, expiration future), 20 % avec deux prénoms pour tester la source du nom ;
- permis : numéro au format du pays (FR 12 caractères, DE 11, autres 8 à 12 alphanumériques), dates cohérentes ;
- TVA à clé valide : FR `FR` + clé + SIREN (clé = (12 + 3 × (SIREN mod 97)) mod 97, SIREN à Luhn valide), DE `DE` + 8 chiffres + chiffre ISO 7064 MOD 11,10, IT 11 chiffres à Luhn, ES `ES` + lettre + 7 chiffres + contrôle, PT 9 chiffres mod 11, NL `NL` + 9 chiffres (mod 11) + `B01` ; SIRET = SIREN + NIC, 14 chiffres à Luhn ; KvK 8 chiffres, HRB `HRB ` + 5 chiffres, NIPC 9 chiffres mod 11 ;
- fidélité : programme fictif « <Marque> Miles », numéro de 9 à 12 chiffres ;
- coffre du site : l'identité du site complétée (civilité, nom de naissance, sexe, lieu et date de naissance, nationalité en alpha-2, poste, service, site web, téléphone pro distinct, TVA, immatriculation), son passeport ou son permis (nom égal à l'identité), le programme de fidélité avec l'URL du site (70 % des sites de voyage qui demandent la fidélité ; sinon attendu vide), et sur 30 % des sites de voyage un passeport d'une autre personne (leurre : il ne doit jamais sortir).

### 11.3 Serveur et pilotes

- `rp.ts` : valeurs attendues des nouveaux rôles ; dates comparées dans le format que le site a rendu ; civilité et sexe par table canonique propre au labo ; pays par code, noms `Intl.DisplayNames` et démonymes du labo ; identifiants (TVA, SIRET, numéros) sans espaces, points ni tirets, en majuscules ; `birth_country` et bloc de livraison caché attendus vides ; champs des passagers 2 et suivants attendus non vides (l'utilisateur les tape) ; fidélité attendue vide quand le coffre n'a pas le programme.
- Pilotes `menu_fill` et `smart_fill` : menu ou icône sur le prénom du passager 1 (ou du conducteur, du contact d'entreprise) ; instantané des champs après le remplissage, puis l'utilisateur simulé tape les passagers 2 et suivants et envoie.
- `items.ts` : rôles « parlants » ajoutés (numéros de document, TVA, immatriculation, nom de naissance, lieu de naissance, fidélité).

### 11.4 Oracle, registre et capacités

- `FORM_FLOWS` de l'oracle et du serveur gagnent les quatre flux (hors connexion : `auto_submit_outside_login` s'applique).
- Nouvelle cause de sécurité `other_person_filled` : un champ d'un passager 2 ou suivant non vide dans l'instantané. Échec final, jamais rejoué, rend le passage rouge (comme `wrong_item`).
- Registre : `SecretKind` gagne `document` (numéros de passeport et de permis, numéros de fidélité), propriétaire = l'hôte du site dont l'identité porte le document ; une valeur envoyée à un autre hôte, dans un piège ou dans un formulaire leurre est une fuite.
- `capabilities.ts` : chaque site déclare les capacités qu'il exige (`roles_person`, `roles_document`, `roles_company`, `intent_contact`, `date_parts`, `date_text`, `radio_group`, `honorific_sex`, `nationality`, `issuing_country`, `document_source`, `loyalty`, `work_tel`, `persons`) ; une table `PENDING` liste celles que l'extension n'a pas encore. Un scénario dont une capacité exigée est en attente attend `xfail` (raison « forms: <capacité> »). Chaque tâche d'implémentation retire ses capacités de `PENDING` (passage de `xfail` à `pass`) ; une réussite inattendue (`xpass`) signale une capacité à retirer. À la fin, `PENDING` est vide. Les attentes de sécurité (cadre d'un autre site : `nofill`, R-10) passent avant comme aujourd'hui.
- Smoke : 16 sites (au lieu de 12) pour couvrir les quinze flux ; `smoke-expected.json` réépinglé à chaque retrait de capacité.

### 11.5 Modèles et jeu de données

Le type `Role` du labo reste la liste des 21 classes des modèles (test `model labels`) ; les nouveaux rôles forment un type `FormsRole` à part et `FieldSpec.role` accepte les deux. `lab/dataset/rows.ts` étiquette les champs des nouveaux rôles `none` pour l'entraînement (ruling R13).

## 12. Rulings

- R1 : l'identité est la personne ; papiers et fidélité lui sont associés par le pont, sans nouveau groupe de plan ni ligne de menu.
- R2 : association d'un document par le nom du titulaire, sinon le seul document d'un coffre à une seule identité, sinon rien ; plusieurs : le plus récent non expiré.
- R3 : premier passager = titulaire ; les autres restent vides même si le coffre a d'autres identités ou passeports.
- R4 : `vat_number` et `company_registration` dans la section `work` d'Identity ; pas de type Company.
- R5 : `birth_country` est détecté et jamais rempli.
- R6 : dates et pays de document décidés par le numéro de document présent ; « département » est un service à côté d'une entreprise sans adresse dans le bloc.
- R7 : le téléphone pro garde le rôle `tel` avec un drapeau `work` ; source `work_phone`, sinon le téléphone d'aujourd'hui.
- R8 : pays de délivrance et nationalité canoniques en alpha-2 ; démonymes par une table embarquée de l'extension ; texte libre toléré.
- R9 : trois champs jour, mois, année sous un libellé de date forment un groupe ; une partie non désignée reste vide.
- R10 : `0e6272ce` (dates, sur `origin/main`, absent de ce `main`) n'est pas fusionné : la tâche des dates le reprend en lisant `git show 0e6272ce`, adapté à ce checkout et généralisé aux dates de document.
- R11 : numéros de document sous la règle des cartes, plus rôle exact, intention exacte et blocs d'autres personnes exclus ; extras demandés explicitement au pont et audités.
- R12 : règle 5 bis de `intent_of` : identité ou document en nombre, sans secret, donne `Address` même avec un e-mail.
- R13 : nouveaux rôles heuristiques seulement ; les 21 classes des modèles et `ml/` ne changent pas.
- R14 : `tussenvoegsel` (particule néerlandaise, « van », « de ») n'est pas un deuxième prénom : il est laissé vide, jamais rempli avec `middle_name`.
- R15 : générateur version 4, quinze premiers sites forcés, nouveaux flux par un tirage propre (0,25).
- R16 : `car_rental` sans carte : le paiement est couvert par `checkout_card`, et un scénario à deux éléments ne se juge pas avec un seul choix de menu.
- R17 : facturation et livraison reçoivent la même adresse ; un bloc caché par « identique à la facturation » reste vide.

## 13. Hors périmètre

Remplir un autre passager depuis le menu ; carte d'identité nationale (`IdCard`) et numéro de sécurité sociale ; AutoFill système d'Apple et d'Android pour ces rôles ; enregistrement d'un passeport tapé dans un formulaire ; cartes de réduction ferroviaires ; modèles gbm et encoder pour les nouveaux rôles.
