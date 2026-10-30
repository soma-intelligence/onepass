// Form grouping and classification (spec 8.2), and the page analysis entry point.

import type { FieldInfo, FieldRole, FormInfo, FormKind, PageAnalysis } from "../../shared/messages";
import { providerForHost } from "../../shared/providers";
import { detectCaptcha, detectPush } from "./captcha";
import { classifyField, FIELD_SELECTOR, type FieldElement, isFieldCandidate } from "./fields";
import { AUTOCOMPLETE_SCORE, normalizeText } from "./lexicon";
import { buttonLabel, detectAccountChooser, detectProviderButtons, providerOfButton } from "./provider";
import type { RefRegistry } from "./refs";
import { ownText } from "./text";
import { domGeometry, type Geometry, isRendered, isVisible } from "./visibility";

/** Most form controls inspected per page (hostile pages may create thousands). */
const MAX_FIELDS = 500;
/** Most buttons inspected per page. */
const MAX_BUTTONS = 1000;
/** Split OTP: number of consecutive one-character cells forming one code. */
const SPLIT_OTP_MIN = 4;
const SPLIT_OTP_MAX = 8;
/** Longest button label considered a "Next" / "Sign in" button. */
const MAX_NEXT_LABEL = 40;

/** Labels of buttons that move a sign-in forward (French, English, German, Spanish, Italian, Portuguese, Dutch). */
const NEXT_TEXT =
  /\b(next|continue|continuer|suivant|suivante|etape suivante|sign in|log in|login|se connecter|connexion|valider|verify|verifier|weiter|fortfahren|anmelden|einloggen|bestatigen|siguiente|continuar|iniciar sesion|acceder|entrar|verificar|avanti|continua|prosegui|accedi|verifica|proximo|seguinte|iniciar sessao|volgende|doorgaan|verder|inloggen|aanmelden)\b/;

/**
 * Words that make a page or a button a sign-in one. An identifier-only step
 * needs one of them (or a "forgot password" link, or a field read as a user
 * name) so that a newsletter or search box with a "Continue" button is not
 * taken for a login.
 */
const SIGN_IN_TEXT =
  /\b(sign ?in|signin|log ?in|login|logon|auth|authenticate|authentication|authentifi\w*|authorize|oauth|sso|connexion|se connecter|identifi\w*|anmelden|anmeldung|einloggen|iniciar sesion|acceder|accedi|accesso|entrar|iniciar sessao|inloggen|aanmelden)\b/;
/** "Forgot password" wording, matched on link texts. */
const FORGOT_TEXT =
  /\b(forgot|forgotten|mot de passe oublie|passwort vergessen|kennwort vergessen|olvidaste|olvido|password dimenticata|esqueceu|esqueci|wachtwoord vergeten)\b/;
/** Links read for the "forgot password" wording. */
const MAX_FORGOT_LINKS = 300;
/** Headings read for sign-in wording. */
const MAX_HEADINGS = 5;

/**
 * Controls that may submit a group. Links that navigate are excluded in the
 * selector itself so that the cap applies to real candidates (a page may hold
 * thousands of navigation links).
 */
export const BUTTON_SELECTOR =
  'button, input[type="submit" i], input[type="image" i], input[type="button" i], [role="button"], ' +
  'a:not([href]), a[href^="#"], a[href^="javascript:" i]';

const IDENTIFIERS: ReadonlySet<FieldRole> = new Set(["username", "email"]);
const CARD: ReadonlySet<FieldRole> = new Set([
  "cc_name",
  "cc_number",
  "cc_exp",
  "cc_exp_month",
  "cc_exp_year",
  "cc_csc",
]);
const IDENTITY: ReadonlySet<FieldRole> = new Set([
  "given_name",
  "family_name",
  "full_name",
  "tel",
  "organization",
  "bday",
  "email",
]);
const ADDRESS: ReadonlySet<FieldRole> = new Set([
  "address_line1",
  "address_line2",
  "city",
  "postal_code",
  "region",
  "country",
]);

export interface AnalyzeOptions {
  /** Page URL; defaults to `doc.URL`. The host decides account chooser reporting. */
  url?: string;
  /** Layout function; defaults to the real DOM geometry. */
  geometry?: Geometry;
}

interface Classified {
  el: FieldElement;
  role: FieldRole;
  /** Role decided by `autocomplete`, not by scoring. */
  direct: boolean;
  /** One cell of a split OTP (a run of 4 to 8 one-character inputs). */
  cell: boolean;
}

interface Group {
  container: Element;
  fields: Classified[];
}

export function controlForm(el: Element): HTMLFormElement | null {
  if (
    el instanceof HTMLInputElement ||
    el instanceof HTMLSelectElement ||
    el instanceof HTMLButtonElement
  ) {
    return el.form;
  }
  return el.closest("form");
}

function isNextLabel(el: Element): boolean {
  const t = normalizeText(buttonLabel(el));
  return t !== "" && t.length <= MAX_NEXT_LABEL && NEXT_TEXT.test(t);
}

export function isSubmitType(el: Element): boolean {
  if (el instanceof HTMLButtonElement) return el.type === "submit";
  return el instanceof HTMLInputElement && (el.type === "submit" || el.type === "image");
}

/** A link only acts as a button when it does not navigate somewhere. */
export function isNavigatingLink(el: Element): boolean {
  if (!(el instanceof HTMLAnchorElement) || el.getAttribute("role") === "button") return false;
  const href = (el.getAttribute("href") ?? "").trim();
  return href !== "" && !href.startsWith("#") && !/^javascript:/i.test(href);
}

/** Buttons that may submit a form group, in document order. */
function submitCandidates(doc: Document, geometry: Geometry): Element[] {
  return Array.from(doc.querySelectorAll(BUTTON_SELECTOR))
    .slice(0, MAX_BUTTONS)
    .filter(
      (el) =>
        !isNavigatingLink(el) &&
        (isSubmitType(el) || isNextLabel(el)) &&
        providerOfButton(el) === null &&
        !el.matches(":disabled") &&
        isRendered(el, geometry),
    );
}

/** Submit control of a group: a submit-type button first, else a "Next" style label. */
function findSubmit(group: Group, buttons: Element[], isForm: boolean): Element | undefined {
  const inside = buttons.filter((b) =>
    isForm ? controlForm(b) === group.container : group.container.contains(b) && controlForm(b) === null,
  );
  return inside.find(isSubmitType) ?? inside.find(isNextLabel);
}

/** Nearest ancestor of `el` (inclusive of body) for which `pred` holds. */
function climb(el: Element, pred: (a: Element) => boolean): Element | null {
  for (let a = el.parentElement; a; a = a.parentElement) {
    if (pred(a)) return a;
    if (a === el.ownerDocument.body) break;
  }
  return null;
}

function depth(el: Element): number {
  let d = 0;
  for (let a = el.parentElement; a; a = a.parentElement) d++;
  return d;
}

/**
 * Groups fields outside any <form>: first around each submit-like button (the
 * nearest ancestor of the button holding a classified field, innermost first),
 * then the remaining fields by the highest ancestor that holds no field of
 * another group.
 */
function groupOrphans(orphans: Classified[], buttons: Element[]): Group[] {
  const groups: Group[] = [];
  const assigned = new Set<Classified>();
  const containers = buttons
    .filter((b) => controlForm(b) === null)
    .map((b) => climb(b, (a) => orphans.some((f) => a.contains(f.el))))
    .filter((c): c is Element => c !== null)
    .sort((a, b) => depth(b) - depth(a));
  for (const container of containers) {
    const fields = orphans.filter((f) => !assigned.has(f) && container.contains(f.el));
    if (fields.length === 0) continue;
    for (const f of fields) assigned.add(f);
    groups.push({ container, fields });
  }
  for (const f of orphans) {
    if (assigned.has(f)) continue;
    const others = (a: Element) => groups.some((g) => g.fields.some((x) => a.contains(x.el)));
    let container: Element = f.el.parentElement ?? f.el;
    for (let a = container.parentElement; a && !others(a); a = a.parentElement) {
      container = a;
      if (a === f.el.ownerDocument.body) break;
    }
    const fields = orphans.filter((x) => !assigned.has(x) && container.contains(x.el));
    for (const x of fields) assigned.add(x);
    groups.push({ container, fields });
  }
  return groups;
}

const CELL_TYPES: ReadonlySet<string> = new Set(["text", "tel", "number", "password"]);

function isOneCharInput(el: FieldElement): el is HTMLInputElement {
  return el instanceof HTMLInputElement && el.maxLength === 1 && CELL_TYPES.has(el.type);
}

/** Same form, or (outside forms) same grandparent: cells are often wrapped one per element. */
function sameCellGroup(a: HTMLInputElement, b: HTMLInputElement): boolean {
  if (a.form !== b.form) return false;
  if (a.form !== null) return true;
  return a.parentElement === b.parentElement || a.parentElement?.parentElement === b.parentElement?.parentElement;
}

/**
 * Inputs that belong to a split OTP: runs of 4 to 8 consecutive visible
 * one-character inputs of the same group. A lone one-character input (middle
 * initial) is not one.
 */
function splitOtpCells(fields: FieldElement[]): Set<FieldElement> {
  const out = new Set<FieldElement>();
  for (let i = 0; i < fields.length; ) {
    const first = fields[i] as FieldElement;
    if (!isOneCharInput(first)) {
      i++;
      continue;
    }
    let j = i + 1;
    for (let next = fields[j]; next !== undefined && isOneCharInput(next) && sameCellGroup(first, next); next = fields[++j]);
    const run = j - i;
    if (run >= SPLIT_OTP_MIN && run <= SPLIT_OTP_MAX) for (const el of fields.slice(i, j)) out.add(el);
    i = j;
  }
  return out;
}

/** Merges runs of 4 to 8 consecutive one-character OTP cells into one logical field. */
function mergeSplitOtp(fields: Classified[], refs: RefRegistry): FieldInfo[] {
  const out: FieldInfo[] = [];
  const isCell = (f: Classified | undefined) => f?.cell === true;
  for (let i = 0; i < fields.length; ) {
    let j = i;
    while (isCell(fields[j])) j++;
    const run = j - i;
    if (run >= SPLIT_OTP_MIN && run <= SPLIT_OTP_MAX) {
      const parts = fields.slice(i, j).map((f) => refs.refFor(f.el));
      out.push({ ref: parts[0] as string, role: "otp", parts });
      i = j;
      continue;
    }
    const f = fields[i] as Classified;
    out.push({ ref: refs.refFor(f.el), role: f.role });
    i++;
  }
  return out;
}

/**
 * An ambiguous "security code" is a card code only next to another card field
 * (number, name, expiry); alone it is read again as a one-time code.
 * Accepted limit: a card code alone in its own frame (hosted card fields)
 * without `autocomplete="cc-csc"` reads as a one-time code.
 */
function resolveSecurityCodes(fields: Classified[]): void {
  if (fields.some((f) => CARD.has(f.role) && f.role !== "cc_csc")) return;
  for (const f of fields) {
    if (f.role !== "cc_csc" || f.direct || f.cell) continue;
    const { role } = classifyField(f.el, false);
    if (role !== "unknown") f.role = role;
  }
}

/** Roles of unlabelled password fields, by how many there are in the group. */
const UNLABELLED_PASSWORDS: Readonly<Record<number, readonly FieldRole[]>> = {
  2: ["new_password", "confirm_password"],
  3: ["current_password", "new_password", "confirm_password"],
};

/**
 * Password roles inside one group: a second "new password" is its
 * confirmation; unlabelled password fields read as new + confirm (two) or
 * current + new + confirm (three).
 */
function resolvePasswords(fields: Classified[]): void {
  const pw = fields.filter(
    (f) => f.role === "current_password" || f.role === "new_password" || f.role === "confirm_password",
  );
  const news = pw.filter((f) => f.role === "new_password");
  if (news.length >= 2 && !pw.some((f) => f.role === "confirm_password")) {
    for (const f of news.slice(1)) f.role = "confirm_password";
    return;
  }
  const allCurrentGuessed = pw.every((f) => f.role === "current_password" && !f.direct);
  if (!allCurrentGuessed) return;
  const roles = UNLABELLED_PASSWORDS[pw.length];
  if (roles === undefined) return;
  pw.forEach((f, i) => {
    f.role = roles[i] as FieldRole;
  });
}

function count(roles: FieldRole[], set: ReadonlySet<FieldRole>): number {
  return roles.filter((r) => set.has(r)).length;
}

/**
 * Form kind from its field roles (spec 8.2), or null when it is none of them.
 * `nextButton`: the group's button moves a sign-in forward, in a sign-in context.
 */
export function formKind(roles: FieldRole[], nextButton: boolean): FormKind | null {
  const has = (r: FieldRole) => roles.includes(r);
  const ident = count(roles, IDENTIFIERS) > 0;
  const fresh = has("new_password") || has("confirm_password");
  if (has("current_password") && fresh) return "change_password";
  if (fresh) return ident ? "signup" : "change_password";
  if (has("current_password")) return "login";
  // A one-time code makes an otp form only alone or with the account identifier;
  // next to card or identity fields it is something else (promo code...).
  if (has("otp") && roles.every((r) => r === "otp" || IDENTIFIERS.has(r) || r === "remember_me")) return "otp";
  const others = roles.filter((r) => !IDENTIFIERS.has(r) && r !== "remember_me");
  if (count(roles, IDENTIFIERS) === 1 && others.length === 0 && nextButton) return "login";
  if (count(roles, CARD) >= 2) return "card";
  if (count(roles, IDENTITY) >= 2) return "identity";
  if (count(roles, ADDRESS) >= 2) return "address";
  return null;
}

/** Page-level sign-in wording: title, URL, first headings or a "forgot password" link. */
function signInPage(doc: Document, url: string): boolean {
  const headings = Array.from(doc.querySelectorAll("h1, h2"))
    .slice(0, MAX_HEADINGS)
    .map((h) => ownText(h, 100));
  const texts = [doc.title, url, ...headings];
  if (texts.some((t) => SIGN_IN_TEXT.test(normalizeText(t)))) return true;
  return Array.from(doc.querySelectorAll("a"))
    .slice(0, MAX_FORGOT_LINKS)
    .some((a) => FORGOT_TEXT.test(normalizeText(ownText(a, 100))));
}

/**
 * A lone identifier with a "Next" style button is a sign-in step only in a
 * sign-in context: a field read as a user name, a sign-in button label, or a
 * sign-in page (computed lazily, once per document).
 */
function identifierStep(fields: Classified[], submit: Element, page: () => boolean): boolean {
  if (fields.some((f) => f.role === "username")) return true;
  if (SIGN_IN_TEXT.test(normalizeText(buttonLabel(submit)))) return true;
  return page();
}

function documentOrder(a: Element, b: Element): number {
  if (a === b) return 0;
  return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
}

/** Classified forms and field groups of the document, in document order. `url` defaults to `doc.URL`. */
export function detectForms(
  doc: Document,
  refs: RefRegistry,
  geometry: Geometry = domGeometry,
  url: string = doc.URL,
): FormInfo[] {
  const visible: FieldElement[] = [];
  for (const el of Array.from(doc.querySelectorAll(FIELD_SELECTOR)).slice(0, MAX_FIELDS)) {
    if (isFieldCandidate(el) && isVisible(el, geometry)) visible.push(el);
  }
  const cells = splitOtpCells(visible);
  const classified: Classified[] = [];
  for (const el of visible) {
    if (cells.has(el)) {
      classified.push({ el, role: "otp", direct: false, cell: true });
      continue;
    }
    const { role, score } = classifyField(el);
    if (role !== "unknown") classified.push({ el, role, direct: score === AUTOCOMPLETE_SCORE, cell: false });
  }

  const byForm = new Map<HTMLFormElement, Classified[]>();
  const orphans: Classified[] = [];
  for (const f of classified) {
    const form = f.el.form;
    if (form === null) orphans.push(f);
    else byForm.set(form, [...(byForm.get(form) ?? []), f]);
  }

  const buttons = submitCandidates(doc, geometry);
  const groups: { group: Group; isForm: boolean }[] = [
    ...Array.from(byForm, ([container, fields]) => ({ group: { container, fields }, isForm: true })),
    ...groupOrphans(orphans, buttons).map((group) => ({ group, isForm: false })),
  ];
  groups.sort((a, b) => documentOrder(a.group.fields[0]!.el, b.group.fields[0]!.el));

  let page: boolean | undefined;
  const isSignInPage = () => (page ??= signInPage(doc, url));
  const out: FormInfo[] = [];
  for (const { group, isForm } of groups) {
    group.fields.sort((a, b) => documentOrder(a.el, b.el));
    resolveSecurityCodes(group.fields);
    resolvePasswords(group.fields);
    const submit = findSubmit(group, buttons, isForm);
    const kind = formKind(
      group.fields.map((f) => f.role),
      submit !== undefined && isNextLabel(submit) && identifierStep(group.fields, submit, isSignInPage),
    );
    if (kind === null) continue;
    const info: FormInfo = { ref: refs.refFor(group.container), kind, fields: mergeSplitOtp(group.fields, refs) };
    if (submit !== undefined) info.submitRef = refs.refFor(submit);
    out.push(info);
  }
  return out;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/**
 * Full page analysis sent to the service worker. Pure over its inputs: the URL
 * is passed in (or read from `doc.URL`), never from `location`.
 */
export function analyzeDocument(doc: Document, refs: RefRegistry, opts: AnalyzeOptions = {}): PageAnalysis {
  const geometry = opts.geometry ?? domGeometry;
  const url = opts.url ?? doc.URL;
  const host = hostOf(url);
  const onProvider = host !== null && providerForHost(host) !== null;
  return {
    url,
    forms: detectForms(doc, refs, geometry, url),
    captcha: detectCaptcha(doc, geometry),
    push: detectPush(doc),
    providerButtons: detectProviderButtons(doc, refs, geometry),
    accountChooser: onProvider ? detectAccountChooser(doc, refs, geometry) : [],
  };
}
