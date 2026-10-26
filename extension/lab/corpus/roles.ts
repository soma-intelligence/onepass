// Rule table that guesses the role of a captured field: autocomplete token
// first, then input type, then words of the label, name and id (fr en de es it pt nl).
import type { Role } from "../gen/model.ts";

export interface RoleInput { type?: string; name?: string; id?: string; autocomplete?: string; label?: string; }

const AUTOCOMPLETE: Record<string, Role> = {
  "username": "username", "email": "email", "current-password": "password", "new-password": "new_password",
  "one-time-code": "otp", "cc-name": "cc_name", "cc-number": "cc_number", "cc-exp": "cc_exp",
  "cc-exp-month": "cc_exp_month", "cc-exp-year": "cc_exp_year", "cc-csc": "cc_csc",
  "given-name": "given_name", "family-name": "family_name", "tel": "tel", "tel-national": "tel",
  "bday": "birth_date", "organization": "organization", "address-line1": "address_line1",
  "street-address": "address_line1", "address-line2": "address_line2", "postal-code": "postal_code",
  "address-level2": "city", "country": "country", "country-name": "country",
};

// Order matters: the first matching rule wins.
const WORDS: [Role, RegExp][] = [
  ["cc_number", /(card|cc|kreditkarte|tarjeta|carta|cartao) ?(number|num|nummer|numero|no)\b|\bcardnumber|numero de (la )?(carte|tarjeta)|kartennummer/],
  ["cc_csc", /\b(cvv|cvc|csc|cvn)\b|security code|code de securite|pruefziffer|kartenpruefnummer|codigo de seguridad|codice di sicurezza/],
  ["cc_exp_month", /(exp|expiry|expiration|ablauf|vencimiento|scadenza|validade).*(month|mois|monat|mes|mese)|\b(mm|exp month)\b/],
  ["cc_exp_year", /(exp|expiry|expiration|ablauf|vencimiento|scadenza|validade).*(year|annee|jahr|ano|anno)|\b(yy|yyyy|exp year)\b/],
  ["cc_exp", /expir|ablaufdatum|gueltig bis|vencimiento|scadenza|validade|date d exp/],
  ["cc_name", /name on card|card ?holder|titulaire|karteninhaber|titular de la tarjeta|intestatario/],
  ["postal_code", /postal|\bzip|\bplz\b|postleitzahl|\bcap\b|\bcep\b|postcode|postnummer/],
  ["email", /e ?mail|courriel|correo|posta elettronica|correio/],
  ["otp", /one time|\botp\b|verification code|code de verification|sms code|\b2fa\b|verifizierungscode|bestaetigungscode|codigo de verificacion|codice di verifica|totp/],
  ["username", /user ?name|\blogin\b|identifiant|benutzer|nutzername|usuario|nome utente|\butente\b|gebruikersnaam|utilizador|nom d utilisateur|\buid\b/],
  ["password", /passw|mot de passe|kennwort|contrasena|\bsenha\b|wachtwoord|parola chiave|\bpwd\b/],
  ["given_name", /first ?name|given|prenom|vorname|voornaam|\bnombre\b|\bnome\b/],
  ["family_name", /last ?name|surname|family|nom de famille|nom d usage|nachname|familienname|apellido|cognome|sobrenome|achternaam|^nom$/],
  ["tel", /phone|telephone|\btel\b|telefon|telefono|mobile|\bhandy\b|celular|telefoon/],
  ["birth_date", /birth|naissance|geburt|nacimiento|nascita|nascimento|geboorte|\bbday\b|\bdob\b/],
  ["organization", /company|organi[sz]ation|societe|entreprise|\bfirma\b|unternehmen|empresa|azienda|bedrijf/],
  ["address_line2", /address ?(line)? ?2|adresse 2|complement|apartment|\bapt\b|\bsuite\b|adresszusatz|\bpiso\b|\bunit\b/],
  ["address_line1", /address|adresse|anschrift|strasse|street|direccion|\bcalle\b|indirizzo|\bvia\b|endereco|\brua\b|straat/],
  ["city", /\bcity\b|\bville\b|\bstadt\b|\bort\b|ciudad|\bcitta\b|cidade|\bstad\b|\btown\b|localite/],
  ["country", /country|\bpays\b|\bland\b|\bpais\b|\bpaese\b/],
];

// Words that turn a password field into a new-password (or confirmation) field.
const NEW_PASSWORD = /confirm|repeat|retype|re ?enter|\bagain\b|\bnew\b|nouveau|nouvelle|neues|neue|wiederhol|bestatig|nueva|nuevo|repetir|nuova|nuovo|\bnovo\b|\bnova\b|bevestig|nieuw/;

function normalize(s: string): string {
  return s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/[_\-.\[\]'’]/g, " ").replace(/\s+/g, " ").trim();
}

export function classifyRole(f: RoleInput): Role | "unknown" {
  if (f.autocomplete) {
    for (const tok of f.autocomplete.toLowerCase().split(/\s+/).reverse()) {
      const r = AUTOCOMPLETE[tok];
      if (r) return r;
    }
  }
  const type = (f.type ?? "").toLowerCase();
  const hay = normalize([f.label, f.name, f.id].filter(Boolean).join(" | "));
  if (type === "password") return NEW_PASSWORD.test(hay) ? "new_password" : "password";
  if (type === "email") return "email";
  if (type === "tel") return "tel";
  for (const part of hay.split(" | ")) {
    for (const [role, re] of WORDS) {
      if (!re.test(part)) continue;
      return role === "password" && NEW_PASSWORD.test(part) ? "new_password" : role;
    }
  }
  return "unknown";
}
