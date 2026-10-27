// HTML renderer of the autofill lab: turns a generated Site into the pages of
// its flow (spec 4.3) with its traits (spec 4.4), and renders the neutral mock
// identity provider pages (spec 5.2). A pure function of its inputs: the lab
// server (rp.ts, idp.ts) serves the strings as they are. DOM conventions the
// driver and the server rely on: main form `form#lab-form` (POST, action =
// PAGE_PATH of the page), submit `#lab-submit`, status `#lab-status`, honeypot
// `[data-lab-honeypot]`, decoy `form[data-lab-decoy]`, provider link
// `#lab-sso`, passkey button `#lab-passkey`.
import type { FieldSpec, IdpAccount, Lang, LoginStyle, ProviderId, Site } from "./model.ts";
import {
  CSS, decoyHtml, esc, formHtml, passkeyScript, postedNames, relayHtml, runtimeScript,
} from "./render-forms.ts";
import type { FormSpec, RuntimeConfig } from "./render-forms.ts";

export type PageId = "entry" | "password" | "otp" | "passkey" | "home" | "frame" | "trap";
export interface PageContext { error?: string; challenge?: string; status?: string; asHost?: string }
export type IdpPageId = "chooser" | "identifier" | "password";
export interface IdpContext { accounts?: IdpAccount[]; email?: string; error?: string; client?: string }

/** Paths the site pages are served at and post to (entry, trap and home share "/"-rooted paths). */
export const PAGE_PATH = {
  entry: "/", password: "/password", otp: "/otp", passkey: "/passkey", home: "/home", frame: "/frame", decoy: "/decoy",
} as const;
/** Paths of the mock identity provider pages; each form posts back to the path of its page. */
export const IDP_PATH: Record<IdpPageId, string> = {
  chooser: "/o/oauth2/auth", identifier: "/signin/identifier", password: "/signin/password",
};
export const IDP_HOST: Record<ProviderId, string> = {
  google: "accounts.google.com", apple: "appleid.apple.com", microsoft: "login.microsoftonline.com",
};
const PROVIDER_NAME: Record<ProviderId, string> = { google: "Google", apple: "Apple", microsoft: "Microsoft" };
/** Shown in #lab-status when the WebAuthn ceremony or its verification fails. */
export const PASSKEY_REFUSED = "Clé d'accès refusée";

type Text = "signin" | "password" | "otp" | "passkey" | "signup" | "checkout" | "address" | "identity" | "home"
  | "verify" | "passkeyButton" | "newPassword" | "confirmPassword";
const TEXT: Record<"en" | "fr" | "de" | "es", Record<Text, string>> = {
  en: {
    signin: "Sign in", password: "Enter your password", otp: "Two-step verification", passkey: "Use your passkey",
    signup: "Create your account", checkout: "Payment", address: "Shipping address", identity: "Your profile",
    home: "Welcome", verify: "Verify", passkeyButton: "Use passkey", newPassword: "New password",
    confirmPassword: "Confirm password",
  },
  fr: {
    signin: "Connexion", password: "Saisissez votre mot de passe", otp: "Vérification en deux étapes",
    passkey: "Utilisez votre clé d'accès", signup: "Créer votre compte", checkout: "Paiement",
    address: "Adresse de livraison", identity: "Votre profil", home: "Bienvenue", verify: "Vérifier",
    passkeyButton: "Utiliser une clé d'accès", newPassword: "Nouveau mot de passe", confirmPassword: "Confirmer le mot de passe",
  },
  de: {
    signin: "Anmelden", password: "Passwort eingeben", otp: "Bestätigung in zwei Schritten", passkey: "Passkey verwenden",
    signup: "Konto erstellen", checkout: "Zahlung", address: "Lieferadresse", identity: "Ihr Profil", home: "Willkommen",
    verify: "Bestätigen", passkeyButton: "Passkey verwenden", newPassword: "Neues Passwort",
    confirmPassword: "Passwort bestätigen",
  },
  es: {
    signin: "Iniciar sesión", password: "Introduce tu contraseña", otp: "Verificación en dos pasos",
    passkey: "Usa tu llave de acceso", signup: "Crea tu cuenta", checkout: "Pago", address: "Dirección de envío",
    identity: "Tu perfil", home: "Bienvenido", verify: "Verificar", passkeyButton: "Usar llave de acceso",
    newPassword: "Nueva contraseña", confirmPassword: "Confirmar contraseña",
  },
};
const t = (lang: Lang, key: Text) => (TEXT[lang as keyof typeof TEXT] ?? TEXT.en)[key];

// A label that asks to type the new password again, in the corpus languages.
const CONFIRM_LABEL = /confirm|bestätig|wiederhol|repeat|retype|again|répét|repet|vérif/i;

function styleOf(site: Site): LoginStyle {
  if (site.flow === "login_username_first") return "username_first";
  if (site.flow === "login_email_then_password") return "email_then_password";
  return site.loginStyle ?? "single";
}

/** Fields shown by a page, in order. Entry-like pages (entry, frame, trap) hold the first step. */
function pageFields(site: Site, page: PageId): FieldSpec[] {
  if (page === "password") return site.fields.filter((f) => f.role === "password");
  if (page === "otp") return site.fields.filter((f) => f.role === "otp");
  if (page !== "entry" && page !== "frame" && page !== "trap") return [];
  const first = site.fields.filter((f) => f.role !== "otp");
  if (styleOf(site) === "username_first") return first.filter((f) => f.role !== "password");
  return first;
}

/**
 * Signup labels are drawn independently per field, so the first new-password
 * field can read "Confirm password": present a new-password label first and a
 * confirmation label second, swapping the drawn labels or falling back to the
 * label language's defaults.
 */
function signupLabels(site: Site): Map<FieldSpec, string> {
  const out = new Map<FieldSpec, string>();
  const [a, b] = site.fields.filter((f) => f.role === "new_password");
  if (!a || !b) return out;
  const confirmA = CONFIRM_LABEL.test(a.label);
  const confirmB = CONFIRM_LABEL.test(b.label);
  out.set(a, !confirmA ? a.label : !confirmB ? b.label : t(site.labelLang, "newPassword"));
  out.set(b, confirmB ? b.label : confirmA ? a.label : t(site.labelLang, "confirmPassword"));
  return out;
}

function headingOf(site: Site, page: PageId): string {
  switch (page) {
    case "password": return t(site.lang, "password");
    case "otp": return t(site.lang, "otp");
    case "passkey": return t(site.lang, "passkey");
    case "home": return t(site.lang, "home");
    default:
      switch (site.flow) {
        case "signup": return t(site.lang, "signup");
        case "checkout_card": return t(site.lang, "checkout");
        case "address": return t(site.lang, "address");
        case "identity": return t(site.lang, "identity");
        default: return t(site.lang, "signin");
      }
  }
}

function statusHtml(ctx: { error?: string; status?: string }): string {
  if (ctx.error) return `<p id="lab-status" class="status error" role="alert">${esc(ctx.error)}</p>`;
  return `<p id="lab-status" class="status" role="status">${esc(ctx.status ?? "")}</p>`;
}

function documentHtml(lang: Lang, title: string, brand: string, body: string): string {
  return `<!doctype html>
<html lang="${esc(lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<header class="top"><a class="brand" href="/">${esc(brand)}</a></header>
<main>
${body}
</main>
<footer>&copy; ${esc(brand)}</footer>
</body>
</html>
`;
}

/** The form of a page with its structural traits (delay, shadow root, rerender) and traps (honeypot, decoy). */
function mountedForm(site: Site, page: PageId, action: string): string {
  const fields = pageFields(site, page);
  const entryLike = page === "entry" || page === "frame" || page === "trap";
  const style = styleOf(site);
  const has = (trait: Site["traits"][number]) => site.traits.includes(trait);
  const hasPassword = site.fields.some((f) => f.role === "password");
  const reveal = entryLike && style === "email_then_password" && hasPassword;
  const firstStep = entryLike && style === "username_first" && hasPassword;
  const hp = site.honeypot && fields.some((f) => f.role === site.honeypot!.role) ? site.honeypot : undefined;
  const spec: FormSpec = {
    action, fields, labels: site.flow === "signup" ? signupLabels(site) : undefined, honeypot: hp,
    noAutocomplete: has("no_autocomplete"), splitOtp: page === "otp" && site.totpCells === true, reveal,
    submit: page === "otp" ? t(site.lang, "verify") : firstStep ? site.buttons.next ?? site.buttons.submit : site.buttons.submit,
    next: site.buttons.next,
  };
  const form = formHtml(spec);
  const shadow = has("shadow_open") ? "open" : has("shadow_closed") ? "closed" : undefined;
  const cfg: RuntimeConfig = {
    spa: has("spa_rerender"), reveal, split: spec.splitOtp,
    ...(shadow ? { shadow } : {}), ...(site.delayMs !== undefined && has("delayed_fields") ? { delayMs: site.delayMs } : {}),
  };
  let decoy = "";
  if (entryLike && has("decoy_form")) {
    const id = site.fields.find((f) => f.role === "username" || f.role === "email");
    decoy = decoyHtml(id, site.fields.find((f) => f.role === "password"), site.buttons.submit);
  }
  let markup: string;
  if (shadow) {
    markup = `<lab-shell></lab-shell><template id="lab-tpl"><style>${CSS}</style>${form}</template>${relayHtml(action, postedNames(spec))}`;
  } else if (cfg.delayMs !== undefined) {
    markup = `<div id="lab-mount"></div><template id="lab-tpl">${form}</template>`;
  } else {
    markup = form;
  }
  const scripted = shadow !== undefined || cfg.delayMs !== undefined || cfg.spa || cfg.reveal || cfg.split;
  return decoy + markup + (scripted ? runtimeScript(cfg) : "");
}

function passkeyBlock(site: Site, host: string, ctx: PageContext): string {
  const label = site.buttons.passkey ?? t(site.labelLang, "passkeyButton");
  return `<button type="button" id="lab-passkey">${esc(label)}</button>` + passkeyScript({
    challenge: ctx.challenge ?? "", rpId: host, credentialId: site.account?.passkey?.credentialId ?? "",
    endpoint: PAGE_PATH.passkey, next: PAGE_PATH.home, refused: PASSKEY_REFUSED,
  });
}

export function renderSitePage(site: Site, page: PageId, ctx: PageContext): string {
  // The lookalike copy keeps the brand (that is the phishing point) but lives on its own host.
  const host = page === "trap" ? ctx.asHost ?? site.lookalike?.host ?? site.host : site.host;
  const heading = headingOf(site, page);
  const parts = [`<h1>${esc(heading)}</h1>`, statusHtml(ctx)];
  const framed = site.traits.includes("iframe_same_origin") || site.traits.includes("iframe_cross_site");
  switch (page) {
    case "home":
      parts.push(`<p class="muted">${esc(site.brand)}</p>`);
      break;
    case "passkey":
      parts.push(passkeyBlock(site, host, ctx));
      break;
    case "password":
      parts.push(mountedForm(site, page, PAGE_PATH.password));
      break;
    case "otp":
      parts.push(mountedForm(site, page, PAGE_PATH.otp));
      break;
    case "frame":
      parts.push(mountedForm(site, page, `https://${site.frameHost ?? site.host}${PAGE_PATH.frame}`));
      break;
    case "entry":
    case "trap":
      if (site.flow === "sso" && site.sso) {
        const idp = IDP_HOST[site.sso.provider];
        const href = `https://${idp}/o/oauth2/auth?client=${host}&redirect_uri=https://${host}/oauth/callback`;
        // An sso site may also show a password form; the provider button stays.
        if (site.fields.length > 0) parts.push(mountedForm(site, page, PAGE_PATH.entry));
        parts.push(`<a id="lab-sso" class="btn" href="${esc(href)}">${esc(site.buttons.sso ?? PROVIDER_NAME[site.sso.provider])}</a>`);
      } else if (site.flow === "login_passkey" && site.passkeyOnly) {
        parts.push(passkeyBlock(site, host, ctx));
      } else if (framed && page === "entry") {
        const src = `https://${site.frameHost ?? site.host}${PAGE_PATH.frame}?site=${site.index}`;
        parts.push(`<iframe src="${esc(src)}" title="${esc(heading)}"></iframe>`);
      } else {
        parts.push(mountedForm(site, page, PAGE_PATH.entry));
      }
      break;
  }
  return documentHtml(site.lang, `${heading} | ${site.brand}`, site.brand, parts.join("\n"));
}

const IDP_TITLE: Record<IdpPageId, string> = { chooser: "Choisir un compte", identifier: "Connexion", password: "Mot de passe" };

export function renderIdpPage(provider: ProviderId, page: IdpPageId, ctx: IdpContext): string {
  const name = PROVIDER_NAME[provider];
  const parts = [`<h1>${esc(IDP_TITLE[page])}</h1>`];
  if (ctx.client) parts.push(`<p class="muted">pour continuer vers ${esc(ctx.client)}</p>`);
  parts.push(statusHtml(ctx));
  const client = `<input type="hidden" name="client" value="${esc(ctx.client ?? "")}">`;
  const email = (readonly: boolean) => `<div class="field"><label for="idp-email">Adresse e-mail</label>`
    + `<input type="email" id="idp-email" name="email" autocomplete="username" value="${esc(ctx.email ?? "")}"${readonly ? " readonly" : ""}></div>`;
  const password = `<div class="field"><label for="idp-password">Mot de passe</label>`
    + `<input type="password" id="idp-password" name="password" autocomplete="current-password"></div>`;
  let inner: string;
  switch (page) {
    case "chooser":
      // A list of accounts, as real provider choosers show them (one email per entry).
      inner = `<ul class="accounts">${(ctx.accounts ?? []).map((a) => `<li><button type="submit" class="account" name="email"`
        + ` value="${esc(a.email)}" data-email="${esc(a.email)}" data-lab-account="${esc(a.email)}">${esc(a.name)}`
        + `<small>${esc(a.email)}</small></button></li>`).join("")}</ul>`
        + `<button type="submit" class="account" name="email" value="" id="lab-other">Utiliser un autre compte</button>`;
      break;
    case "identifier":
      // Microsoft asks for the email and the password on two pages; the others on one.
      inner = provider === "microsoft"
        ? `${email(false)}<button type="submit" id="lab-submit">Suivant</button>`
        : `${email(false)}${password}<button type="submit" id="lab-submit">Se connecter</button>`;
      break;
    case "password":
      inner = `${email(true)}${password}<button type="submit" id="lab-submit">Se connecter</button>`;
      break;
  }
  parts.push(`<form id="lab-form" method="post" action="${IDP_PATH[page]}">${client}${inner}</form>`);
  return documentHtml("fr", `${IDP_TITLE[page]} | Compte ${name}`, `Compte ${name}`, parts.join("\n"));
}
