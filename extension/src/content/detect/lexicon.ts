// Hand-set weights for field classification (spec 8.2, ruling R-09).
// Every number lives in a table here so that weights stay readable and
// testable. Texts are matched after `normalizeText` (lowercase, accents
// stripped, camelCase split, separators turned into spaces).

import type { FieldRole } from "../../shared/messages";

export type ScoredRole = Exclude<FieldRole, "unknown">;
export type Weights = Partial<Record<ScoredRole, number>>;

/** Scoring order; on a tie the earlier role wins. */
export const SCORED_ROLES: readonly ScoredRole[] = [
  "username",
  "email",
  "current_password",
  "new_password",
  "confirm_password",
  "otp",
  "cc_name",
  "cc_number",
  "cc_exp",
  "cc_exp_month",
  "cc_exp_year",
  "cc_csc",
  "given_name",
  "family_name",
  "full_name",
  "tel",
  "organization",
  "bday",
  "address_line1",
  "address_line2",
  "city",
  "postal_code",
  "region",
  "country",
  "remember_me",
];

/** Minimum score for a field to get a role; below it the field is `unknown`. */
export const SCORE_THRESHOLD = 2.5;

/** Score given to the role named by a recognized `autocomplete` token. */
export const AUTOCOMPLETE_SCORE = 100;

/** Normalized `autocomplete` field names that decide the role directly. */
export const AUTOCOMPLETE_ROLES: Readonly<Record<string, ScoredRole>> = {
  username: "username",
  email: "email",
  "current-password": "current_password",
  "new-password": "new_password",
  "one-time-code": "otp",
  "cc-name": "cc_name",
  "cc-given-name": "cc_name",
  "cc-family-name": "cc_name",
  "cc-number": "cc_number",
  "cc-exp": "cc_exp",
  "cc-exp-month": "cc_exp_month",
  "cc-exp-year": "cc_exp_year",
  "cc-csc": "cc_csc",
  "given-name": "given_name",
  "family-name": "family_name",
  name: "full_name",
  tel: "tel",
  "tel-national": "tel",
  organization: "organization",
  bday: "bday",
  "street-address": "address_line1",
  "address-line1": "address_line1",
  "address-line2": "address_line2",
  "address-line3": "address_line2",
  "postal-code": "postal_code",
  "address-level2": "city",
  "address-level1": "region",
  country: "country",
  "country-name": "country",
};

/** `autocomplete` tokens that qualify the field name and are skipped. */
export const AUTOCOMPLETE_QUALIFIERS: ReadonlySet<string> = new Set([
  "shipping",
  "billing",
  "home",
  "work",
  "mobile",
  "fax",
  "pager",
  "webauthn",
]);

/** Multiplier per text source of the field. */
export const SOURCE_WEIGHTS = {
  name: 1,
  id: 1,
  placeholder: 1.2,
  ariaLabel: 1.2,
  label: 1.5,
  title: 1,
  nearby: 0.6,
} as const;

export type Source = keyof typeof SOURCE_WEIGHTS;

/** Longest attribute or text read from the page per source (hostile pages). */
export const MAX_SOURCE_CHARS = 200;

export interface Term {
  re: RegExp;
  w: Weights;
  /**
   * Weights used instead of `w` when the field's form holds no other card
   * field: an ambiguous "security code" is a card code next to a card number,
   * a one-time code on its own.
   */
  alone?: Weights;
}

/**
 * Term table. A term matched in a source adds its weights (times the source
 * multiplier) to each listed role; negative weights push competing roles down.
 * Each term counts at most once per source.
 */
export const TERMS: readonly Term[] = [
  // Passwords.
  {
    re: /\b(password|passwort|passwd|pwd|pass|mot de passe|mdp|passcode)\b/,
    w: { current_password: 3, new_password: 1, confirm_password: 1 },
  },
  {
    re: /\b(new|nouveau|nouvel|nouvelle|create|creer|creez|choose|choisissez|choisir|definir|definissez)\b/,
    w: { new_password: 3, current_password: -3 },
  },
  {
    re: /\b(confirm|confirmer|confirmez|confirmation|repeat|repeter|retype|re ?enter|again|retapez|ressaisir|ressaisissez)\b/,
    w: { confirm_password: 5, current_password: -4, new_password: -2 },
  },
  { re: /\b(current|actuel|old|ancien|existing|existant)\b/, w: { current_password: 2, new_password: -2 } },

  // Identifiers.
  {
    re: /\b(user ?name|user ?id|login|log ?in|identifiant|identifier|utilisateur|pseudo|account|compte|member)\b/,
    w: { username: 3, family_name: -3, full_name: -3 },
  },
  { re: /\b(e ?mail|courriel|adresse electronique|mail)\b/, w: { email: 3, address_line1: -4 } },

  // One-time codes. "code" alone is weak: postal and card codes subtract it.
  {
    re: /\b(otp|one ?time|2fa|mfa|totp|authenticator|authentification|verification|code recu|digit|chiffres)\b/,
    w: { otp: 3 },
  },
  { re: /\bcode\b/, w: { otp: 1.5 } },
  // Promo, referral and gift codes are not one-time codes (nor card codes).
  {
    re: /\b(promo\w*|coupon|voucher|gift|parrain\w*|referral|reduction|cadeau|discount|remise)\b/,
    w: { otp: -6, cc_csc: -8, cc_number: -6 },
  },

  // Cards.
  {
    re: /\b(card ?number|card ?no|card ?num|credit ?card|debit ?card|numero de (la )?carte|cc ?num(ber)?|pan)\b/,
    w: { cc_number: 5 },
  },
  {
    re: /\b(card ?holder|holder|name on (the )?card|titulaire|nom sur la carte|cc ?name)\b/,
    w: { cc_name: 6, full_name: -3, family_name: -3 },
  },
  {
    re: /\b(cvc|cvv|cvv2|cvc2|csc|cid|cryptogramme|crypto|card code|code de la carte|card verification)\b/,
    w: { cc_csc: 6, otp: -6 },
  },
  // "Security code" names a card code in a card form and a one-time code elsewhere.
  {
    re: /\b(security code|code de securite|sicherheits ?code|codigo de seguridad|codice di sicurezza|codigo de seguranca|beveiligings ?code|veiligheids ?code)\b/,
    w: { cc_csc: 6, otp: -6 },
    alone: { otp: 6, cc_csc: -6 },
  },
  {
    re: /\b(expir\w*|exp|expiry|expires|valid thru|valid until|validite|date d expiration|date de validite)\b/,
    w: { cc_exp: 3, cc_exp_month: 1.5, cc_exp_year: 1.5 },
  },
  { re: /\b(month|mois|mm)\b/, w: { cc_exp_month: 3, cc_exp: -1 } },
  { re: /\b(year|annee|yy|yyyy|aa|aaaa)\b/, w: { cc_exp_year: 3, cc_exp: -1 } },
  { re: /\b(mm ?(yy|aa|yyyy|aaaa))\b/, w: { cc_exp: 5, cc_exp_month: -4, cc_exp_year: -4 } },

  // Identity. "nom" alone is weak so "nom d'utilisateur" and "nom du titulaire" lose.
  {
    re: /\b(first ?name|given ?name|prenom|fname|forename)\b/,
    w: { given_name: 5, full_name: -3, family_name: -3 },
  },
  {
    re: /\b(last ?name|family ?name|surname|lname|nom de famille|nom de naissance)\b/,
    w: { family_name: 5, full_name: -3 },
  },
  { re: /\bnom\b/, w: { family_name: 2.5 } },
  { re: /\b(full ?name|nom complet|your name|votre nom|name)\b/, w: { full_name: 2.5 } },
  { re: /\b(phone|telephone|tel|mobile|portable|cell|gsm)\b/, w: { tel: 5 } },
  {
    re: /\b(company|organi[sz]ation|entreprise|societe|org|employer|employeur)\b/,
    w: { organization: 5, full_name: -3 },
  },
  {
    re: /\b(birth ?day|birth ?date|birth|date of birth|dob|bday|date de naissance|naissance|anniversaire)\b/,
    w: { bday: 5, cc_exp: -3, cc_exp_month: -3, cc_exp_year: -3 },
  },

  // Address.
  {
    re: /\b(address|adresse|addr|street|rue|voie|address ?1|adresse ?1|line ?1|ligne ?1)\b/,
    w: { address_line1: 3 },
  },
  {
    re: /\b(address ?2|adresse ?2|addr ?2|line ?2|ligne ?2|apartment|apt|suite|appartement|batiment|complement|etage|unit)\b/,
    w: { address_line2: 6, address_line1: -4 },
  },
  {
    re: /\b(zip|zipcode|postal|postcode|post code|code postal|cp|plz)\b/,
    w: { postal_code: 5, otp: -5 },
  },
  { re: /\b(city|ville|town|locality|localite|commune)\b/, w: { city: 5 } },
  { re: /\b(state|region|province|county|departement)\b/, w: { region: 4 } },
  { re: /\b(country|pays)\b/, w: { country: 5 } },

  // German, Spanish, Italian, Portuguese and Dutch. Kept in terms of their own
  // so that the French and English weights above stay as they are; the texts
  // are normalized (accents stripped, "ß" read as "ss").

  // Passwords.
  {
    re: /\b(kennwort|contrasena|senha|palavra passe|wachtwoord)\b/,
    w: { current_password: 3, new_password: 1, confirm_password: 1 },
  },
  {
    re: /\b(neu|neue|neues|neuer|neuen|erstellen|wahlen|nueva|nuevo|crea|crear|elige|nuova|nuovo|scegli|nova|novo|crie|criar|escolha|nieuw|nieuwe|kies|maak|aanmaken)\b/,
    w: { new_password: 3, current_password: -3 },
  },
  {
    re: /\b(bestatigen|bestatigung|wiederholen|erneut|confirmar|confirma|confirme|confirmacion|confirmacao|repetir|repite|repita|conferma|confermare|ripeti|ripetere|bevestig|bevestigen|herhaal|herhalen|opnieuw)\b/,
    w: { confirm_password: 5, current_password: -4, new_password: -2 },
  },
  {
    re: /\b(aktuell\w*|bisherig\w*|alte|altes|alten|(contrasena|clave|senha) (actual|atual)|antigua|anterior|attuale|vecchia|antiga|huidig\w*|oud|oude)\b/,
    w: { current_password: 2, new_password: -2 },
  },

  // Identifiers, with the usual field names of identifier-only steps.
  {
    re: /\b(benutzer\w*|nutzername|anmeldename|kennung|usuario|identificador|utente|utilizador|gebruiker\w*|loginfmt|login ?fmt|uname)\b/,
    w: { username: 3, given_name: -3, family_name: -3, full_name: -3 },
  },
  // A field named or labelled just "user". Whole text only: Rails and Django
  // attribute names such as user[first_name] or user[email] are not identifiers.
  { re: /^user$/, w: { username: 3, given_name: -3, family_name: -3, full_name: -3 } },
  // "Email, phone or Skype": one field that takes any account identifier. Only
  // an email first: "phone or email" stays a phone, "mobile phone" too.
  {
    re: /\b(e ?mail|correo|user ?name)( (or|ou|oder|o|of))? (phone|telephone|mobile|skype|telefon\w*|telefono|telefone|telefoon\w*)\b/,
    w: { username: 6, tel: -6, email: -3 },
  },
  {
    re: /\b(correo|correo electronico|correio eletronico|correio electronico|posta elettronica|e ?mailadres|e ?mail ?adres)\b/,
    w: { email: 3, address_line1: -4 },
  },

  // One-time codes. "codigo" and "codice" alone are weak, like "code".
  {
    re: /\b(bestatigungscode|verifizierungscode|einmalcode|einmal ?kennwort|einmal ?passwort|verificacion|verificacao|verifica|verificatie ?code|verificatie|un solo uso|uso unico|eenmalig\w*|zwei faktor\w*|dos pasos|due fattori|dois fatores|tweestaps\w*|ziffern|digitos|cifre)\b/,
    w: { otp: 3 },
  },
  { re: /\b(codigo|codice)\b/, w: { otp: 1.5 } },

  // Cards.
  {
    re: /\b(kartennummer|kreditkartennummer|numero de (la )?tarjeta|numero (della |di )?carta|numero do cartao|numero de cartao|kaartnummer|creditcardnummer)\b/,
    w: { cc_number: 5 },
  },
  {
    re: /\b(karteninhaber\w*|name auf der karte|titular (de la tarjeta|do cartao)|nombre del titular|nome do titular|nombre en la tarjeta|titolare|intestatario|nome sulla carta|nome no cartao|naam op (de )?kaart|kaarthouder)\b/,
    w: { cc_name: 6, full_name: -3, family_name: -3, given_name: -3 },
  },
  { re: /\b(prufziffer|prufnummer|kartenprufnummer)\b/, w: { cc_csc: 6, otp: -6 } },
  {
    re: /\b(ablauf\w*|gultig bis|gultigkeit|caducidad|vencimiento|expiracion|scadenza|validade|vencimento|vervaldatum|geldig tot)\b/,
    w: { cc_exp: 3, cc_exp_month: 1.5, cc_exp_year: 1.5 },
  },
  { re: /\b(monat|ablaufmonat|mes|mese|maand)\b/, w: { cc_exp_month: 3, cc_exp: -1 } },
  { re: /\b(jahr|ablaufjahr|ano de (vencimiento|caducidad|expiracion|validade|vencimento)|anno|jaar|jj|jjjj)\b/, w: { cc_exp_year: 3, cc_exp: -1 } },
  { re: /\b(mm ?(jj|jjjj))\b/, w: { cc_exp: 5, cc_exp_month: -4, cc_exp_year: -4 } },

  // Identity. "nombre" and "nome" alone are weak, like "nom".
  {
    re: /\b(vorname|nombre de pila|primer nombre|primeiro nome|voornaam)\b/,
    w: { given_name: 5, full_name: -3, family_name: -3 },
  },
  { re: /\b(nombre|nome)\b/, w: { given_name: 2.5 } },
  {
    re: /\b(nachname|familienname|apellido|apellidos|cognome|sobrenome|apelido|achternaam)\b/,
    w: { family_name: 5, full_name: -3, given_name: -3 },
  },
  {
    re: /\b(vollstandiger name|nombre completo|nombre y apellidos?|nome completo|nome e cognome|volledige naam)\b/,
    w: { full_name: 8, given_name: -5, family_name: -8 },
  },
  {
    re: /\b(telefon\w*|telefono|telefone|telefoon\w*|handy\w*|mobilnummer|mobiltelefon|movil|celular|cellulare|telemovel|mobiel\w*)\b/,
    w: { tel: 5 },
  },
  {
    re: /\b(firma|firmenname|unternehmen|empresa|compania|azienda|societa|organizacao|organizacion|organizzazione|bedrijf\w*|organisatie)\b/,
    w: { organization: 5, full_name: -3, given_name: -3 },
  },
  {
    re: /\b(geburtsdatum|geburtstag|nacimiento|cumpleanos|nascita|compleanno|nascimento|aniversario|geboortedatum|verjaardag)\b/,
    w: { bday: 5, cc_exp: -3, cc_exp_month: -3, cc_exp_year: -3 },
  },

  // Address.
  {
    re: /\b(anschrift|strasse|hausnummer|direccion|calle|domicilio|indirizzo|endereco|morada|straat|straatnaam|adres|linea ?1|riga ?1|linha ?1)\b/,
    w: { address_line1: 3 },
  },
  {
    re: /\b(adresszeile ?2|adresszusatz|zusatz|piso|puerta|escalera|linea ?2|interno|scala|riga ?2|complemento|apartamento|andar|linha ?2|toevoeging)\b/,
    w: { address_line2: 6, address_line1: -4 },
  },
  { re: /\b(postleitzahl|codice postale)\b/, w: { postal_code: 5, otp: -5 } },
  {
    re: /\b(wohnort|stadt|ciudad|localidad|poblacion|citta|localita|comune|cidade|localidade|plaats|woonplaats|stad)\b/,
    w: { city: 5 },
  },
  { re: /\b(bundesland|provincia|estado|regione|distrito|provincie)\b/, w: { region: 4 } },
  { re: /\b(land (oder )?region|pais|paese|nazione)\b/, w: { country: 5 } },
  // Short words that are also English words ("Spending cap", "Land line") or
  // fragments of other phrases count only when they are the whole text.
  { re: /^(cap|cep)$/, w: { postal_code: 5, otp: -5 } },
  { re: /^ort$/, w: { city: 5 } },
  { re: /^land$/, w: { country: 5 } },
  { re: /^ano$/, w: { cc_exp_year: 3, cc_exp: -1 } },
  { re: /^rua$/, w: { address_line1: 3 } },
  { re: /^titular$/, w: { cc_name: 6, full_name: -3, family_name: -3, given_name: -3 } },
  {
    re: /\b(angemeldet bleiben|eingeloggt bleiben|merken|recordarme|recuerdame|mantener la sesion|ricordami|resta connesso|lembrar|manter sessao|mantenha me conectado|onthoud|ingelogd blijven|aangemeld blijven)\b/,
    w: { remember_me: 5 },
  },

  // "Remember me" (checkboxes only, see TYPE rules in fields.ts).
  {
    re: /\b(remember|stay signed|keep me|trust this|se souvenir|souviens|rester connecte|memoriser|faire confiance)\b/,
    w: { remember_me: 5 },
  },
];

/** Weights added by the control type. */
export const TYPE_WEIGHTS: Readonly<Record<string, Weights>> = {
  password: { current_password: 3, new_password: 2, confirm_password: 2 },
  email: { email: 5, username: 1 },
  tel: { tel: 4, otp: 0.5 },
  number: { otp: 0.5, cc_number: 0.5, postal_code: 0.5 },
  date: { bday: 3 },
};

/** Added to the three password roles when the control is not type=password. */
export const NON_PASSWORD_TYPE_PENALTY = -6;

/** Roles a type=password control may take; every other role scores 0. */
export const PASSWORD_TYPE_ROLES: ReadonlySet<ScoredRole> = new Set([
  "current_password",
  "new_password",
  "confirm_password",
  "otp",
]);

/** Weights from other attributes. */
export const ATTRIBUTE_WEIGHTS = {
  /**
   * `maxlength = 1`: maybe one cell of a split code, maybe a middle initial.
   * Kept below the threshold on purpose: a split code is only recognized as a
   * run of 4 to 8 such cells (forms.ts).
   */
  maxLengthOne: { otp: 1 },
  /** `inputmode = numeric` (or `decimal`). */
  numericInputMode: { otp: 1, cc_number: 0.5, postal_code: 0.5, tel: 0.5 },
  /** `maxlength` between 4 and 8 together with a numeric input mode. */
  shortNumeric: { otp: 1 },
  /** `pattern` that only accepts digits. */
  digitPattern: { otp: 0.5 },
} as const satisfies Record<string, Weights>;

/** Lowercase, strip accents, read "ß" as "ss", split camelCase, keep only letters and digits. */
export function normalizeText(s: string): string {
  return s
    .slice(0, MAX_SOURCE_CHARS)
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}
