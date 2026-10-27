# Rapport du laboratoire d'autofill

- Graine du monde : `lab-2026-10-26`
- Date : 2026-10-26
- Commit : `2f4d288`
- Durée : 18 min

## Lecture

Ce qui échoue aujourd'hui dans l'extension (59 échecs, hors attendus), par cause racine :

- Pages SSO seules : pas d'overlay sur le bouton du fournisseur (21 `no_overlay`, plus 2 `handoff:unknown`) ; le flux sso tombe à 30,3 %.
- Re-rendu SPA : le formulaire est recloné pendant le remplissage et les champs détachés ne reçoivent rien (16 échecs `spa_rerender`, taux 0 %) : 7 `wrong_fill` sur formulaires, 5 `no_menu`, 2 `handoff:repeat` en connexion (site 141 : e-mail rempli, mot de passe jamais).
- Champs différés : apparus après le chargement, ils ne sont pas repris (11 échecs `delayed_fields`, taux 35,3 %), surtout `no_menu` sur inscription et adresse.
- Connexion dans un iframe de même origine : jamais proposée (6 `no_overlay` en un clic, trait à 35,7 %).
- Identifiant seul sans `autocomplete` : l'étape n'est pas reconnue (sites 123, 179, 63 : `no_overlay`).
- Code TOTP libellé "Security code" : lu comme le CVC d'une carte, la chaîne se termine sans le remplir (site 3, `chain_ended:done`) ; login_totp à 36,4 %.
- Libellés allemands et espagnols plus faibles : de 35,7 %, es 50,0 % contre fr 75,3 % (site 120 : "Nueva contraseña" non lu, seul le champ de confirmation reçoit le mot de passe généré).

Le contrôle du banc (22 passkeys sans extension) passe à 100 % : les 22 échecs passkey attendus viennent de l'extension (R-16), pas de la RP.

## Résumé

- Sites : 200
- Scénarios : 207 (plus 22 de contrôle du banc, comptés à part)
- Taux de réussite global (hors attendus, inattendus et erreurs du labo) : 63.8 %
- Réussis : 104, échecs : 59, instables : 0, échecs attendus : 44, réussites inattendues : 0, erreurs du labo : 0
- Fuites : 0

## Taux de réussite

### Par flux

| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| address | 25 | 15 | 5 | 0 | 5 | 0 | 0 | 0 | 75.0 % |
| checkout_card | 17 | 10 | 3 | 0 | 4 | 0 | 0 | 0 | 76.9 % |
| identity | 33 | 26 | 4 | 0 | 3 | 0 | 0 | 0 | 86.7 % |
| login_email_then_password | 16 | 7 | 7 | 0 | 2 | 0 | 0 | 0 | 50.0 % |
| login_passkey | 23 | 1 | 0 | 0 | 22 | 0 | 0 | 0 | 100.0 % |
| login_single | 16 | 11 | 1 | 0 | 4 | 0 | 0 | 0 | 91.7 % |
| login_totp | 11 | 4 | 7 | 0 | 0 | 0 | 0 | 0 | 36.4 % |
| login_username_first | 17 | 13 | 3 | 0 | 1 | 0 | 0 | 0 | 81.3 % |
| signup | 16 | 7 | 6 | 0 | 3 | 0 | 0 | 0 | 53.8 % |
| sso | 33 | 10 | 23 | 0 | 0 | 0 | 0 | 0 | 30.3 % |

### Par trait

| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| (aucun) | 58 | 37 | 12 | 0 | 9 | 0 | 0 | 0 | 75.5 % |
| decoy_form | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0 % |
| delayed_fields | 21 | 6 | 11 | 0 | 4 | 0 | 0 | 0 | 35.3 % |
| honeypot | 19 | 12 | 3 | 0 | 4 | 0 | 0 | 0 | 80.0 % |
| iframe_cross_site | 11 | 11 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0 % |
| iframe_same_origin | 15 | 5 | 9 | 0 | 1 | 0 | 0 | 0 | 35.7 % |
| lookalike | 14 | 9 | 3 | 0 | 2 | 0 | 0 | 0 | 75.0 % |
| mixed_language | 48 | 22 | 18 | 0 | 8 | 0 | 0 | 0 | 55.0 % |
| no_autocomplete | 28 | 15 | 6 | 0 | 7 | 0 | 0 | 0 | 71.4 % |
| obfuscated_names | 26 | 16 | 7 | 0 | 3 | 0 | 0 | 0 | 69.6 % |
| shadow_closed | 11 | 1 | 0 | 0 | 10 | 0 | 0 | 0 | 100.0 % |
| shadow_open | 13 | 1 | 0 | 0 | 12 | 0 | 0 | 0 | 100.0 % |
| spa_rerender | 20 | 0 | 16 | 0 | 4 | 0 | 0 | 0 | 0.0 % |
| split_otp | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 33.3 % |

### Par langue

| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| de | 15 | 5 | 9 | 0 | 1 | 0 | 0 | 0 | 35.7 % |
| en | 80 | 37 | 25 | 0 | 18 | 0 | 0 | 0 | 59.7 % |
| es | 18 | 7 | 7 | 0 | 4 | 0 | 0 | 0 | 50.0 % |
| fr | 94 | 55 | 18 | 0 | 21 | 0 | 0 | 0 | 75.3 % |

### Par pilote

| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lookalike | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0 % |
| menu_fill | 91 | 58 | 18 | 0 | 15 | 0 | 0 | 0 | 76.3 % |
| one_click | 109 | 39 | 41 | 0 | 29 | 0 | 0 | 0 | 48.8 % |
| passkey_control | 22 | 22 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0 % |

## Contrôle du banc

Scénarios `passkey_control` : sans l'extension, l'authentificateur virtuel de Chromium tient la clé du site et la RP du labo doit accepter l'assertion. Hors des taux ci-dessus (sauf par pilote).

- Scénarios : 22, réussis : 22, échecs : 0, instables : 0, erreurs du labo : 0

Aucun échec : la RP du labo vérifie les passkeys comme prévu.

## Échecs

- site 2 (login_email_then_password, one_click, traits : spa_rerender, delayed_fields, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 2`
- site 3 (login_totp, one_click, traits : aucun, langue en) : chain_ended:done. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 3`
- site 5 (sso, one_click, traits : aucun, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 5`
- site 10 (identity, menu_fill, traits : spa_rerender, delayed_fields, langue en) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 10`
- site 16 (login_username_first, one_click, traits : delayed_fields, langue en) : chain_ended:done. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 16`
- site 18 (sso, one_click, traits : aucun, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 18`
- site 19 (signup, menu_fill, traits : spa_rerender, no_autocomplete, obfuscated_names, langue en) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 19`
- site 20 (address, menu_fill, traits : iframe_same_origin, spa_rerender, delayed_fields, langue en) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 20`
- site 23 (sso, one_click, traits : mixed_language, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 23`
- site 24 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 24`
- site 38 (sso, one_click, traits : aucun, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 38`
- site 45 (signup, menu_fill, traits : delayed_fields, langue fr) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 45`
- site 48 (sso, one_click, traits : mixed_language, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 48`
- site 63 (login_email_then_password, one_click, traits : no_autocomplete, lookalike, mixed_language, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 63`
- site 73 (checkout_card, menu_fill, traits : spa_rerender, obfuscated_names, langue en) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 73`
- site 76 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 76`
- site 79 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 79`
- site 81 (login_totp, one_click, traits : iframe_same_origin, obfuscated_names, split_otp, langue de) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 81`
- site 83 (checkout_card, menu_fill, traits : iframe_same_origin, spa_rerender, langue fr) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 83`
- site 84 (login_totp, one_click, traits : iframe_same_origin, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 84`
- site 86 (sso, one_click, traits : aucun, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 86`
- site 92 (identity, menu_fill, traits : spa_rerender, honeypot, langue de) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 92`
- site 95 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 95`
- site 97 (signup, menu_fill, traits : delayed_fields, langue en) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 97`
- site 99 (sso, one_click, traits : mixed_language, langue fr) : handoff:unknown. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 99`
- site 100 (login_email_then_password, one_click, traits : honeypot, lookalike, langue de) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 100`
- site 101 (sso, one_click, traits : aucun, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 101`
- site 104 (login_single, one_click, traits : iframe_same_origin, obfuscated_names, lookalike, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 104`
- site 106 (login_totp, one_click, traits : aucun, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 106`
- site 110 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 110`
- site 116 (login_totp, one_click, traits : spa_rerender, langue fr) : handoff:repeat. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 116`
- site 119 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 119`
- site 120 (signup, menu_fill, traits : aucun, langue es) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 120`
- site 121 (identity, menu_fill, traits : iframe_same_origin, spa_rerender, langue fr) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 121`
- site 122 (login_totp, one_click, traits : delayed_fields, langue de) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 122`
- site 123 (login_username_first, one_click, traits : no_autocomplete, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 123`
- site 126 (login_totp, one_click, traits : iframe_same_origin, no_autocomplete, split_otp, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 126`
- site 127 (identity, menu_fill, traits : delayed_fields, obfuscated_names, langue de) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 127`
- site 128 (login_email_then_password, one_click, traits : iframe_same_origin, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 128`
- site 135 (signup, menu_fill, traits : spa_rerender, mixed_language, langue fr) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 135`
- site 141 (login_email_then_password, one_click, traits : spa_rerender, langue en) : handoff:repeat. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 141`
- site 145 (login_email_then_password, one_click, traits : spa_rerender, delayed_fields, langue es) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 145`
- site 156 (address, menu_fill, traits : delayed_fields, langue fr) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 156`
- site 160 (address, menu_fill, traits : spa_rerender, obfuscated_names, langue en) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 160`
- site 163 (sso, one_click, traits : mixed_language, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 163`
- site 166 (sso, one_click, traits : mixed_language, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 166`
- site 168 (signup, menu_fill, traits : spa_rerender, langue en) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 168`
- site 169 (address, menu_fill, traits : no_autocomplete, langue de) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 169`
- site 172 (sso, one_click, traits : mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 172`
- site 176 (sso, one_click, traits : aucun, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 176`
- site 179 (login_username_first, one_click, traits : no_autocomplete, obfuscated_names, mixed_language, langue en) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 179`
- site 182 (sso, one_click, traits : aucun, langue de) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 182`
- site 188 (sso, one_click, traits : mixed_language, langue en) : handoff:unknown. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 188`
- site 190 (sso, one_click, traits : aucun, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 190`
- site 192 (sso, one_click, traits : mixed_language, langue de) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 192`
- site 193 (sso, one_click, traits : aucun, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 193`
- site 195 (checkout_card, menu_fill, traits : spa_rerender, langue fr) : wrong_fill. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 195`
- site 196 (address, menu_fill, traits : spa_rerender, delayed_fields, langue de) : no_menu. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 196`
- site 199 (login_email_then_password, one_click, traits : iframe_same_origin, honeypot, mixed_language, langue fr) : no_overlay. Rejeu : `npm run lab:repro -- --seed lab-2026-10-26 --site 199`

## Réussites inattendues

Aucune.

## Ce que l'extension ne fait pas encore

Échecs attendus, regroupés par raison documentée (à défaut, par cause) :

- R-16 passkeys : 22 scénario(s), flux : login_passkey, traits : delayed_fields, honeypot, iframe_same_origin, mixed_language, no_autocomplete, obfuscated_names, spa_rerender
- shadow DOM (content/index.ts) : 22 scénario(s), flux : address, checkout_card, identity, login_email_then_password, login_single, login_username_first, signup, traits : delayed_fields, honeypot, lookalike, no_autocomplete, shadow_closed, shadow_open, spa_rerender

Causes d'échec récurrentes (hors attendus) :

- no_overlay : 35 scénario(s)
- wrong_fill : 10 scénario(s)
- no_menu : 8 scénario(s)
- chain_ended:done : 2 scénario(s)
- handoff:repeat : 2 scénario(s)
- handoff:unknown : 2 scénario(s)

## Fuites

Aucune.

## Instables

Aucun.
