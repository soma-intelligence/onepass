//! Field roles and button classes, ported from the extension's detector
//! (`extension/src/content/detect/lexicon.ts` and `fields.ts`, and
//! `content/context.ts` for confidences and button classes).
//!
//! Same numbers as the extension: autocomplete decides at 100, text terms
//! times their source weight, control type weights, threshold 2.5, ceiling
//! 4.5, type-only confidence capped at 0.5. The term table is the part that
//! names login and card fields (identifiers, passwords, one-time codes,
//! cards, remember me) in English and French; identity and address fields
//! are only told by `autocomplete` here. Patterns are word sequences over
//! normalized text: `*` ends a word prefix.

use onepass_core::fill_plan::context::{ButtonClass, FieldRole};
use unicode_normalization::UnicodeNormalization;

/// Longest text read per source (hostile pages).
pub(crate) const MAX_SOURCE_CHARS: usize = 200;
const SCORE_THRESHOLD: f32 = 2.5;
const AUTOCOMPLETE_SCORE: f32 = 100.0;
const SCORE_CEILING: f32 = 4.5;
const TYPE_ONLY_CONFIDENCE: f32 = 0.5;
const NON_PASSWORD_TYPE_PENALTY: f32 = -6.0;

/// Scoring order (the extension's `SCORED_ROLES`): on a tie the earlier wins.
const ROLES: [FieldRole; 46] = [
    FieldRole::Username,
    FieldRole::Email,
    FieldRole::CurrentPassword,
    FieldRole::NewPassword,
    FieldRole::ConfirmPassword,
    FieldRole::Otp,
    FieldRole::CcName,
    FieldRole::CcNumber,
    FieldRole::CcExp,
    FieldRole::CcExpMonth,
    FieldRole::CcExpYear,
    FieldRole::CcCsc,
    FieldRole::GivenName,
    FieldRole::FamilyName,
    FieldRole::FullName,
    FieldRole::Tel,
    FieldRole::Organization,
    FieldRole::Bday,
    FieldRole::AddressLine1,
    FieldRole::AddressLine2,
    FieldRole::City,
    FieldRole::PostalCode,
    FieldRole::Region,
    FieldRole::Country,
    FieldRole::RememberMe,
    FieldRole::HonorificPrefix,
    FieldRole::AdditionalName,
    FieldRole::BirthName,
    FieldRole::Sex,
    FieldRole::BirthPlace,
    FieldRole::BirthCountry,
    FieldRole::Nationality,
    FieldRole::PassportNumber,
    FieldRole::PassportIssueDate,
    FieldRole::PassportExpiry,
    FieldRole::PassportIssuingCountry,
    FieldRole::LicenseNumber,
    FieldRole::LicenseIssueDate,
    FieldRole::LicenseExpiry,
    FieldRole::LicenseIssuingCountry,
    FieldRole::LoyaltyNumber,
    FieldRole::JobTitle,
    FieldRole::Department,
    FieldRole::VatNumber,
    FieldRole::CompanyId,
    FieldRole::Website,
];

fn slot(role: FieldRole) -> usize {
    ROLES.iter().position(|r| *r == role).unwrap_or(0)
}

type Weights = &'static [(FieldRole, f32)];

struct Term {
    pats: &'static [&'static str],
    w: Weights,
    alone: Option<Weights>,
}

use FieldRole as R;

const TERMS: &[Term] = &[
    // Passwords.
    Term {
        pats: &[
            "password",
            "passwort",
            "passwd",
            "pwd",
            "pass",
            "mot de passe",
            "mdp",
            "passcode",
            "kennwort",
            "contrasena",
            "senha",
            "palavra passe",
            "wachtwoord",
        ],
        w: &[
            (R::CurrentPassword, 3.0),
            (R::NewPassword, 1.0),
            (R::ConfirmPassword, 1.0),
        ],
        alone: None,
    },
    Term {
        pats: &[
            "new",
            "nouveau",
            "nouvel",
            "nouvelle",
            "create",
            "creer",
            "creez",
            "choose",
            "choisissez",
            "choisir",
            "definir",
            "definissez",
        ],
        w: &[(R::NewPassword, 3.0), (R::CurrentPassword, -3.0)],
        alone: None,
    },
    Term {
        pats: &[
            "confirm",
            "confirmer",
            "confirmez",
            "confirmation",
            "repeat",
            "repeter",
            "retype",
            "reenter",
            "re enter",
            "again",
            "retapez",
            "ressaisir",
            "ressaisissez",
        ],
        w: &[
            (R::ConfirmPassword, 5.0),
            (R::CurrentPassword, -4.0),
            (R::NewPassword, -2.0),
        ],
        alone: None,
    },
    Term {
        pats: &["current", "actuel", "old", "ancien", "existing", "existant"],
        w: &[(R::CurrentPassword, 2.0), (R::NewPassword, -2.0)],
        alone: None,
    },
    // Identifiers.
    Term {
        pats: &[
            "username",
            "user name",
            "userid",
            "user id",
            "login",
            "log in",
            "identifiant",
            "identifier",
            "utilisateur",
            "pseudo",
            "account",
            "compte",
            "member",
        ],
        w: &[
            (R::Username, 3.0),
            (R::FamilyName, -3.0),
            (R::FullName, -3.0),
        ],
        alone: None,
    },
    Term {
        pats: &[
            "email",
            "e mail",
            "courriel",
            "adresse electronique",
            "mail",
        ],
        w: &[(R::Email, 3.0), (R::AddressLine1, -4.0)],
        alone: None,
    },
    // One-time codes.
    Term {
        pats: &[
            "otp",
            "onetime",
            "one time",
            "2fa",
            "mfa",
            "totp",
            "authenticator",
            "authentification",
            "verification",
            "code recu",
            "digit",
            "chiffres",
        ],
        w: &[(R::Otp, 3.0)],
        alone: None,
    },
    Term {
        pats: &["code"],
        w: &[(R::Otp, 1.5)],
        alone: None,
    },
    Term {
        pats: &[
            "promo*",
            "coupon",
            "voucher",
            "gift",
            "parrain*",
            "referral",
            "reduction",
            "cadeau",
            "discount",
            "remise",
        ],
        w: &[(R::Otp, -6.0), (R::CcCsc, -8.0), (R::CcNumber, -6.0)],
        alone: None,
    },
    // Cards.
    Term {
        pats: &[
            "cardnumber",
            "card number",
            "cardno",
            "card no",
            "cardnum",
            "card num",
            "creditcard",
            "credit card",
            "debitcard",
            "debit card",
            "numero de carte",
            "numero de la carte",
            "ccnum",
            "cc num",
            "ccnumber",
            "cc number",
            "pan",
        ],
        w: &[(R::CcNumber, 5.0)],
        alone: None,
    },
    Term {
        pats: &[
            "cardholder",
            "card holder",
            "holder",
            "name on card",
            "name on the card",
            "titulaire",
            "nom sur la carte",
            "ccname",
            "cc name",
        ],
        w: &[(R::CcName, 6.0), (R::FullName, -3.0), (R::FamilyName, -3.0)],
        alone: None,
    },
    Term {
        pats: &[
            "cvc",
            "cvv",
            "cvv2",
            "cvc2",
            "csc",
            "cid",
            "cryptogramme",
            "crypto",
            "card code",
            "code de la carte",
            "card verification",
        ],
        w: &[(R::CcCsc, 6.0), (R::Otp, -6.0)],
        alone: None,
    },
    Term {
        pats: &["security code", "code de securite"],
        w: &[(R::CcCsc, 6.0), (R::Otp, -6.0)],
        alone: Some(&[(R::Otp, 6.0), (R::CcCsc, -6.0)]),
    },
    Term {
        pats: &[
            "expir*",
            "exp",
            "expiry",
            "expires",
            "valid thru",
            "valid until",
            "validite",
            "date d expiration",
            "date de validite",
        ],
        w: &[(R::CcExp, 3.0), (R::CcExpMonth, 1.5), (R::CcExpYear, 1.5)],
        alone: None,
    },
    Term {
        pats: &["month", "mois", "mm"],
        w: &[(R::CcExpMonth, 3.0), (R::CcExp, -1.0)],
        alone: None,
    },
    Term {
        pats: &["year", "annee", "yy", "yyyy", "aa", "aaaa"],
        w: &[(R::CcExpYear, 3.0), (R::CcExp, -1.0)],
        alone: None,
    },
    Term {
        pats: &[
            "mmyy", "mm yy", "mmaa", "mm aa", "mmyyyy", "mm yyyy", "mmaaaa", "mm aaaa",
        ],
        w: &[(R::CcExp, 5.0), (R::CcExpMonth, -4.0), (R::CcExpYear, -4.0)],
        alone: None,
    },
    // Names a card form also holds, so a cardholder field is not read as one.
    Term {
        pats: &[
            "firstname",
            "first name",
            "givenname",
            "given name",
            "prenom",
            "fname",
            "forename",
        ],
        w: &[
            (R::GivenName, 5.0),
            (R::FullName, -3.0),
            (R::FamilyName, -3.0),
        ],
        alone: None,
    },
    Term {
        pats: &[
            "lastname",
            "last name",
            "familyname",
            "family name",
            "surname",
            "lname",
            "nom de famille",
        ],
        w: &[(R::FamilyName, 5.0), (R::FullName, -3.0)],
        alone: None,
    },
    Term {
        pats: &[
            "zip",
            "zipcode",
            "postal",
            "postcode",
            "post code",
            "code postal",
            "cp",
            "plz",
        ],
        w: &[(R::PostalCode, 5.0), (R::Otp, -5.0)],
        alone: None,
    },
    Term {
        pats: &[
            "remember",
            "stay signed",
            "keep me",
            "trust this",
            "se souvenir",
            "souviens",
            "rester connecte",
            "memoriser",
            "faire confiance",
        ],
        w: &[(R::RememberMe, 5.0)],
        alone: None,
    },
];

fn type_weights(t: &str) -> Weights {
    match t {
        "password" => &[
            (R::CurrentPassword, 3.0),
            (R::NewPassword, 2.0),
            (R::ConfirmPassword, 2.0),
        ],
        "email" => &[(R::Email, 5.0), (R::Username, 1.0)],
        "tel" => &[(R::Tel, 4.0), (R::Otp, 0.5)],
        "number" => &[(R::Otp, 0.5), (R::CcNumber, 0.5), (R::PostalCode, 0.5)],
        "date" => &[(R::Bday, 3.0)],
        "url" => &[(R::Website, 3.0)],
        "select" => &[
            (R::PassportNumber, -10.0),
            (R::LicenseNumber, -10.0),
            (R::LoyaltyNumber, -10.0),
        ],
        _ => &[],
    }
}

fn autocomplete_role(token: &str) -> Option<FieldRole> {
    Some(match token {
        "username" => R::Username,
        "email" => R::Email,
        "current-password" => R::CurrentPassword,
        "new-password" => R::NewPassword,
        "one-time-code" => R::Otp,
        "cc-name" | "cc-given-name" | "cc-family-name" => R::CcName,
        "cc-number" => R::CcNumber,
        "cc-exp" => R::CcExp,
        "cc-exp-month" => R::CcExpMonth,
        "cc-exp-year" => R::CcExpYear,
        "cc-csc" => R::CcCsc,
        "given-name" => R::GivenName,
        "family-name" => R::FamilyName,
        "name" => R::FullName,
        "tel" | "tel-national" => R::Tel,
        "organization" => R::Organization,
        "bday" | "bday-day" | "bday-month" | "bday-year" => R::Bday,
        "honorific-prefix" => R::HonorificPrefix,
        "additional-name" => R::AdditionalName,
        "sex" => R::Sex,
        "organization-title" => R::JobTitle,
        "url" => R::Website,
        "street-address" | "address-line1" => R::AddressLine1,
        "address-line2" | "address-line3" => R::AddressLine2,
        "postal-code" => R::PostalCode,
        "address-level2" => R::City,
        "address-level1" => R::Region,
        "country" | "country-name" => R::Country,
        _ => return None,
    })
}

const QUALIFIERS: [&str; 8] = [
    "shipping", "billing", "home", "work", "mobile", "fax", "pager", "webauthn",
];

fn autocomplete_of(raw: &str) -> Option<FieldRole> {
    let raw: String = raw
        .chars()
        .take(MAX_SOURCE_CHARS)
        .collect::<String>()
        .to_lowercase();
    let last = raw
        .split_whitespace()
        .rfind(|t| !t.starts_with("section-") && !QUALIFIERS.contains(t))?;
    autocomplete_role(last)
}

/// Lowercase, accents stripped, `ß` read as `ss`, camelCase split, only
/// letters and digits kept (the extension's `normalizeText`).
pub(crate) fn normalize(s: &str) -> String {
    let mut split = String::new();
    let mut prev_lower = false;
    for c in s.chars().take(MAX_SOURCE_CHARS) {
        if prev_lower && c.is_ascii_uppercase() {
            split.push(' ');
        }
        prev_lower = c.is_ascii_lowercase();
        split.push(c);
    }
    let folded: String = split
        .nfd()
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c))
        .collect::<String>()
        .to_lowercase()
        .replace('ß', "ss");
    let mut out = String::with_capacity(folded.len());
    for c in folded.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with(' ') {
            out.push(' ');
        }
    }
    out.trim().to_owned()
}

/// Whether one of `pats` occurs as whole consecutive words of `text`
/// (normalized). A pattern word ending in `*` matches any word it begins.
pub(crate) fn has_words(text: &str, pats: &[&str]) -> bool {
    let words: Vec<&str> = text.split(' ').filter(|w| !w.is_empty()).collect();
    pats.iter().any(|p| {
        let pw: Vec<&str> = p.split(' ').collect();
        if pw.len() > words.len() {
            return false;
        }
        words.windows(pw.len()).any(|win| {
            win.iter().zip(&pw).all(|(w, p)| match p.strip_suffix('*') {
                Some(prefix) => w.starts_with(prefix),
                None => w == p,
            })
        })
    })
}

/// Whether `text` ends with one of `pats` (glued to what is before it).
fn ends_with_words(text: &str, pats: &[&str]) -> bool {
    pats.iter().any(|p| text.ends_with(p))
}

/// What the scorer reads of one control. All text is from attributes or
/// the page's own labels, never a value.
pub(crate) struct FieldFacts {
    pub control_type: String,
    pub autocomplete: String,
    /// (source weight, raw text).
    pub sources: Vec<(f32, String)>,
    pub max_length: Option<i64>,
    pub numeric: bool,
    pub digit_pattern: bool,
}

pub(crate) const W_NAME: f32 = 1.0;
pub(crate) const W_ID: f32 = 1.0;
pub(crate) const W_PLACEHOLDER: f32 = 1.2;
pub(crate) const W_ARIA: f32 = 1.2;
pub(crate) const W_LABEL: f32 = 1.5;
pub(crate) const W_TITLE: f32 = 1.0;
pub(crate) const W_SIBLING: f32 = 1.2;
pub(crate) const W_NEARBY: f32 = 0.6;

type Scores = [f32; ROLES.len()];

fn add(scores: &mut Scores, w: Weights, factor: f32) {
    for (r, v) in w {
        scores[slot(*r)] += v * factor;
    }
}

/// The extension's `scoreField`.
fn score(f: &FieldFacts, card_form: bool) -> Scores {
    let mut s: Scores = [0.0; ROLES.len()];
    let t = f.control_type.as_str();
    if t == "checkbox" {
        for (w, text) in &f.sources {
            let n = normalize(text);
            for term in TERMS {
                if let Some((_, rw)) = term.w.iter().find(|(r, _)| *r == R::RememberMe)
                    && has_words(&n, term.pats)
                {
                    s[slot(R::RememberMe)] += rw * w;
                }
            }
        }
        return s;
    }
    if let Some(role) = autocomplete_of(&f.autocomplete) {
        s[slot(role)] = AUTOCOMPLETE_SCORE;
        return s;
    }
    for (w, text) in &f.sources {
        let n = normalize(text);
        if n.is_empty() {
            continue;
        }
        for term in TERMS {
            if has_words(&n, term.pats) {
                let ws = if card_form {
                    term.w
                } else {
                    term.alone.unwrap_or(term.w)
                };
                add(&mut s, ws, *w);
            }
        }
    }
    add(&mut s, type_weights(t), 1.0);
    if t != "password" {
        for r in [R::CurrentPassword, R::NewPassword, R::ConfirmPassword] {
            s[slot(r)] += NON_PASSWORD_TYPE_PENALTY;
        }
    }
    if f.max_length == Some(1) {
        add(&mut s, &[(R::Otp, 1.0)], 1.0);
    }
    if f.numeric {
        add(
            &mut s,
            &[
                (R::Otp, 1.0),
                (R::CcNumber, 0.5),
                (R::PostalCode, 0.5),
                (R::Tel, 0.5),
            ],
            1.0,
        );
        if matches!(f.max_length, Some(4..=8)) {
            add(&mut s, &[(R::Otp, 1.0)], 1.0);
        }
    }
    if f.digit_pattern {
        add(&mut s, &[(R::Otp, 0.5)], 1.0);
    }
    s[slot(R::RememberMe)] = 0.0;
    if t == "password" {
        for r in ROLES {
            if !matches!(
                r,
                R::CurrentPassword | R::NewPassword | R::ConfirmPassword | R::Otp
            ) {
                s[slot(r)] = 0.0;
            }
        }
    }
    s
}

/// Role and confidence of a control (`classifyField`, then `confidenceOf`
/// over `evidenceScore` as `context.ts` does).
pub(crate) fn classify(f: &FieldFacts, card_form: bool) -> (FieldRole, f32) {
    let s = score(f, card_form);
    let mut best = None;
    let mut best_score = 0.0f32;
    for (i, r) in ROLES.iter().enumerate() {
        if s[i] > best_score {
            best = Some(*r);
            best_score = s[i];
        }
    }
    let Some(mut role) = best.filter(|_| best_score >= SCORE_THRESHOLD) else {
        return (R::Unknown, 0.0);
    };
    if role == R::Username && f.control_type == "email" && s[slot(R::Email)] >= SCORE_THRESHOLD {
        role = R::Email;
    }
    // `evidenceScore`: an e-mail control named as an identifier.
    let evidence = if role == R::Email {
        s[slot(R::Email)].max(s[slot(R::Username)])
    } else {
        s[slot(role)]
    };
    let type_weight = type_weights(&f.control_type)
        .iter()
        .find(|(r, _)| *r == role)
        .map_or(0.0, |(_, w)| *w);
    (role, confidence_of(evidence, type_weight))
}

/// The extension's `confidenceOf`.
fn confidence_of(score: f32, type_weight: f32) -> f32 {
    if score.is_nan() {
        return 0.0;
    }
    if score >= AUTOCOMPLETE_SCORE {
        return 1.0;
    }
    let raw = (score / SCORE_CEILING).clamp(0.0, 1.0);
    if score - type_weight <= 0.0 {
        raw.min(TYPE_ONLY_CONFIDENCE)
    } else {
        raw
    }
}

// ---- Page intent words (lexicon.ts), on normalized text ----

const PAY: &[&str] = &[
    "pay",
    "pay now",
    "payer",
    "place order",
    "place your order",
    "place my order",
    "complete order",
    "complete your order",
    "complete my order",
    "complete purchase",
    "complete your purchase",
    "complete my purchase",
    "buy",
    "buy now",
    "purchase",
    "acheter",
    "commander",
    "bezahlen",
    "kaufen",
    "jetzt kaufen",
    "pagar",
    "comprar",
    "paga",
    "acquista",
    "betalen",
    "bestellen",
];
const CREATE: &[&str] = &[
    "create",
    "creer",
    "get started",
    "start trial",
    "start a trial",
    "start your trial",
    "start free trial",
    "start a free trial",
    "start your free trial",
    "signup",
    "sign up",
    "register",
    "registration",
    "join",
    "join now",
    "s inscrire",
    "inscription",
    "inscrivez vous",
    "registrieren",
    "konto erstellen",
    "registrarse",
    "crear cuenta",
    "crear una cuenta",
    "crear mi cuenta",
    "registrati",
    "crea account",
    "crea un account",
    "criar conta",
    "criar uma conta",
    "criar a minha conta",
    "registreren",
    "account aanmaken",
];
const PASSKEY: &[&str] = &[
    "passkey",
    "passkeys",
    "pass key",
    "pass keys",
    "cle d acces",
    "cles d acces",
    "cle d identification",
    "hauptschlussel",
    "clave de acceso",
    "chiave di accesso",
    "chave de acesso",
    "toegangssleutel",
];
const NEXT: &[&str] = &[
    "next",
    "continue",
    "continuer",
    "suivant",
    "suivante",
    "etape suivante",
    "weiter",
    "fortfahren",
    "siguiente",
    "continuar",
    "avanti",
    "continua",
    "prosegui",
    "proximo",
    "seguinte",
    "volgende",
    "doorgaan",
    "verder",
];
const SIGN_IN: &[&str] = &[
    "signin",
    "sign in",
    "login",
    "log in",
    "se connecter",
    "connexion",
    "anmelden",
    "einloggen",
    "iniciar sesion",
    "acceder",
    "accedi",
    "entrar",
    "iniciar sessao",
    "inloggen",
    "aanmelden",
];
const SIGN_IN_TAIL: &[&str] = &[
    "signin",
    "sign in",
    "login",
    "log in",
    "se connecter",
    "anmelden",
    "einloggen",
    "inloggen",
];
const SIGNUP: &[&str] = &[
    "signup",
    "sign up",
    "register",
    "registration",
    "create account",
    "create an account",
    "create your account",
    "create my account",
    "create free account",
    "create a free account",
    "create profile",
    "create your profile",
    "already have an account",
    "new customer",
    "new user",
    "new here",
    "creer compte",
    "creer un compte",
    "creer mon compte",
    "creer votre compte",
    "s inscrire",
    "inscription",
    "deja un compte",
    "registrieren",
    "konto erstellen",
    "registrarse",
    "crear cuenta",
    "crear una cuenta",
    "crear mi cuenta",
    "registrati",
    "crea account",
    "crea un account",
    "criar conta",
    "criar uma conta",
    "registreren",
    "account aanmaken",
];
const RESET: &[&str] = &[
    "reset",
    "forgot",
    "forgotten",
    "recover",
    "recovery",
    "mot de passe oublie",
    "reinitialiser",
    "reinitialisation",
    "passwort vergessen",
    "zurucksetzen",
    "restablecer",
    "recuperar",
    "olvidaste",
    "reimposta",
    "dimenticata",
    "wachtwoord vergeten",
    "herstellen",
    "redefinir",
    "esqueceu",
];
const CHECKOUT: &[&str] = &[
    "checkout",
    "check out",
    "payment",
    "billing",
    "order summary",
    "paiement",
    "facturation",
    "commande",
    "panier",
    "zahlung",
    "kasse",
    "rechnungsadresse",
    "pago",
    "facturacion",
    "pagamento",
    "pedido",
    "betaling",
    "afrekenen",
];
const SEARCH: &[&str] = &[
    "search",
    "rechercher",
    "recherche",
    "chercher",
    "suche",
    "suchen",
    "buscar",
    "busqueda",
    "cerca",
    "ricerca",
    "zoeken",
    "pesquisar",
    "pesquisa",
];
const NEWSLETTER: &[&str] = &[
    "newsletter",
    "subscribe",
    "subscription",
    "mailing list",
    "stay in the loop",
    "stay updated",
    "get updates",
    "s abonner",
    "abonnez vous",
    "abonnement",
    "abonnieren",
    "suscribirse",
    "suscripcion",
    "iscriviti",
    "inschrijven",
    "subscrever",
];

pub(crate) fn signup_words(t: &str) -> bool {
    has_words(t, SIGNUP)
}
pub(crate) fn reset_words(t: &str) -> bool {
    has_words(t, RESET)
}
pub(crate) fn checkout_words(t: &str) -> bool {
    has_words(t, CHECKOUT)
}
pub(crate) fn search_words(t: &str) -> bool {
    has_words(t, SEARCH)
}
pub(crate) fn newsletter_words(t: &str) -> bool {
    has_words(t, NEWSLETTER)
}

/// The extension's `buttonClass`, from the normalized label and whether the
/// control is a submit (`button` without another type, `input` submit or image).
pub(crate) fn button_class(label: &str, submit_type: bool) -> ButtonClass {
    let sign_in = has_words(label, SIGN_IN);
    if has_words(label, PASSKEY) && !sign_in {
        return ButtonClass::Passkey;
    }
    if has_words(label, PAY) {
        return ButtonClass::Pay;
    }
    if has_words(label, CREATE) {
        return if sign_in || ends_with_words(label, SIGN_IN_TAIL) {
            ButtonClass::Submit
        } else {
            ButtonClass::Create
        };
    }
    if has_words(label, NEXT) && !sign_in {
        return ButtonClass::Next;
    }
    if submit_type || sign_in {
        return ButtonClass::Submit;
    }
    ButtonClass::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(t: &str, ac: &str, sources: &[(f32, &str)]) -> FieldFacts {
        FieldFacts {
            control_type: t.into(),
            autocomplete: ac.into(),
            sources: sources.iter().map(|(w, s)| (*w, (*s).to_owned())).collect(),
            max_length: None,
            numeric: false,
            digit_pattern: false,
        }
    }

    #[test]
    fn normalizes_as_the_extension() {
        assert_eq!(normalize("  Mot de passe  "), "mot de passe");
        assert_eq!(normalize("userName"), "user name");
        assert_eq!(normalize("E-mail"), "e mail");
        assert_eq!(normalize("Prénom"), "prenom");
        assert_eq!(normalize("Straße"), "strasse");
        assert_eq!(normalize("cc_number"), "cc number");
    }

    #[test]
    fn words_match_whole_words_only() {
        assert!(has_words("enter your password", &["password"]));
        assert!(!has_words("passwords", &["password"]));
        assert!(has_words("promocode here", &["promo*"]));
        assert!(has_words("mot de passe", &["mot de passe"]));
        assert!(!has_words("mot de", &["mot de passe"]));
    }

    #[test]
    fn login_and_card_roles() {
        let pw = facts("password", "", &[(W_NAME, "password")]);
        assert_eq!(classify(&pw, true), (R::CurrentPassword, 1.0));
        // A bare type=password is held below the planner's floor.
        let bare = facts("password", "", &[]);
        assert_eq!(classify(&bare, true), (R::CurrentPassword, 0.5));
        let user = facts("text", "", &[(W_NAME, "login")]);
        assert_eq!(classify(&user, true).0, R::Username);
        let mail = facts("email", "", &[(W_NAME, "login")]);
        assert_eq!(classify(&mail, true).0, R::Email);
        let ac = facts("text", "section-a billing cc-number", &[]);
        assert_eq!(classify(&ac, true), (R::CcNumber, 1.0));
        let csc = facts("text", "", &[(W_LABEL, "Security code")]);
        assert_eq!(classify(&csc, true).0, R::CcCsc);
        assert_eq!(classify(&csc, false).0, R::Otp);
        let promo = facts("text", "", &[(W_LABEL, "Promo code")]);
        assert_eq!(classify(&promo, true).0, R::Unknown);
        let remember = facts("checkbox", "", &[(W_LABEL, "Remember me")]);
        assert_eq!(classify(&remember, true).0, R::RememberMe);
    }

    #[test]
    fn button_classes() {
        assert_eq!(button_class("sign in", false), ButtonClass::Submit);
        assert_eq!(button_class("next", false), ButtonClass::Next);
        assert_eq!(button_class("create account", true), ButtonClass::Create);
        assert_eq!(
            button_class("sign in or create account", true),
            ButtonClass::Submit
        );
        assert_eq!(button_class("pay now", true), ButtonClass::Pay);
        assert_eq!(button_class("show", false), ButtonClass::Other);
        assert_eq!(button_class("show", true), ButtonClass::Submit);
    }
}
