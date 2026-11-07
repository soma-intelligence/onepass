// Form grouping and classification (spec 8.2), and the page analysis entry point.

import {
  FORMS_ROLES,
  type FieldInfo,
  type FieldRole,
  type FormInfo,
  type FormKind,
  MAX_PERSON,
  type PageAnalysis,
} from "../../shared/messages";
import { providerForHost } from "../../shared/providers";
import { detectCaptcha, detectPush } from "./captcha";
import { applySafetyRules, type ModelHook, type RoleScore } from "./classifier";
import { extractFeatures, type FieldFeatures } from "./features";
import { birthdayPart } from "../date";
import { autocompleteRole, classifyField, FIELD_SELECTOR, type FieldElement, isFieldCandidate, textRole } from "./fields";
import { AUTOCOMPLETE_SCORE, CREATE_WORDS, normalizeText, SIGN_IN_WORDS } from "./lexicon";
import { buttonLabel, detectAccountChooser, detectProviderButtons, providerOfButton } from "./provider";
import type { RefRegistry } from "./refs";
import { collectShadowRoots, composedOrder, queryAll } from "./shadow";
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
  // Forms coverage: people, documents and companies are identity forms too.
  ...FORMS_ROLES,
]);
/** Roles the models never yield (ruling R13): a model answer never replaces them. */
const HEURISTIC_ONLY: ReadonlySet<FieldRole> = new Set(FORMS_ROLES);
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
  /**
   * Shadow roots queried with the document (spec D1, D2); defaults to the
   * open roots of the page (`collectShadowRoots`).
   */
  shadowRoots?: readonly ShadowRoot[];
  /** Model classifier of a model build (classifier.ts); absent: the heuristics alone, as before. */
  model?: ModelHook;
}

interface Classified {
  el: FieldElement;
  role: FieldRole;
  /** Role decided by `autocomplete`, not by scoring. */
  direct: boolean;
  /** One cell of a split OTP (a run of 4 to 8 one-character inputs). */
  cell: boolean;
  /** The controls of a date or radio group, in page order; `el` is the first. */
  parts?: FieldElement[];
  /** A date group: its controls classified one by one, used when the group is not a date after all. */
  fallback?: Classified[];
  /** A radio group (its parts are radio buttons). */
  radio?: boolean;
  /** Person of the field (0: the owner), set by `assignPersons`. */
  person?: number;
  /** A work phone. */
  work?: boolean;
}

/** Most buttons of one radio group, and most controls of a date group. */
const MAX_GROUP_PARTS = 8;
const DATE_PART_TYPES: ReadonlySet<string> = new Set(["text", "number", "tel"]);
/** Roles a date group's legend may name; `cc_exp` is an expiry until the form shows a document. */
const DATE_GROUP_ROLES: ReadonlySet<FieldRole> = new Set(["bday", "cc_exp", "passport_issue_date"]);
const RADIO_GROUP_ROLES: ReadonlySet<FieldRole> = new Set(["honorific_prefix", "sex"]);

/** The question of a group: its own legend, ARIA label, or a heading that is one of its children. */
function groupLabel(a: Element): string {
  const parts: string[] = [];
  const legend = a.querySelector(":scope > legend");
  if (legend) parts.push(ownText(legend, 100));
  const aria = a.getAttribute("aria-label");
  if (aria) parts.push(aria.slice(0, 100));
  const ids = (a.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter((x) => x !== "").slice(0, 3);
  const root = a.getRootNode() as Document | ShadowRoot;
  for (const id of ids) {
    const ref = typeof root.getElementById === "function" ? root.getElementById(id) : null;
    if (ref) parts.push(ownText(ref, 100));
  }
  if (parts.length === 0) {
    const h = a.querySelector(":scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > h5, :scope > h6");
    if (h) parts.push(ownText(h, 100));
  }
  return parts.join(" ");
}

/**
 * Two or three controls under one date legend (spec section 6, ruling R9): a fieldset or group
 * whose question names a birth date, an expiry or an issue date, holding only lists or short text
 * boxes, two or more of them a day, a month or a year. Keyed by the group's first control.
 */
function findDateGroups(visible: readonly FieldElement[]): Map<FieldElement, { role: FieldRole; parts: FieldElement[] }> {
  const out = new Map<FieldElement, { role: FieldRole; parts: FieldElement[] }>();
  const seen = new Set<Element>();
  for (const el of visible) {
    const box = el.closest("fieldset, [role=group]");
    if (box === null || seen.has(box)) continue;
    seen.add(box);
    const role = textRole(groupLabel(box));
    if (!DATE_GROUP_ROLES.has(role)) continue;
    const parts = visible.filter((x) => box.contains(x));
    if (parts.length < 2 || parts.length > 3) continue;
    if (!parts.every((x) => x instanceof HTMLSelectElement || (x instanceof HTMLInputElement && DATE_PART_TYPES.has(x.type)))) continue;
    const kinds = parts.map((x) => birthdayPart(x)).filter((p) => p !== null);
    if (kinds.length < 2 || new Set(kinds).size !== kinds.length) continue;
    out.set(parts[0] as FieldElement, { role, parts });
  }
  return out;
}

/**
 * Radio groups that ask a civility or a sex (spec section 7): the visible radios of one name in one
 * form, whose question (the fieldset legend or group label around them all) names the role.
 */
function findRadioGroups(doc: Document, roots: readonly ShadowRoot[], geometry: Geometry): Classified[] {
  const byName = new Map<string, HTMLInputElement[]>();
  const forms = new Map<HTMLFormElement | null, number>();
  for (const el of queryAll(doc, roots, 'input[type="radio" i]', MAX_FIELDS)) {
    if (!(el instanceof HTMLInputElement) || el.name === "" || !isVisible(el, geometry)) continue;
    const f = forms.get(el.form) ?? forms.size;
    forms.set(el.form, f);
    const key = `${f}\u0000${el.name}`;
    byName.set(key, [...(byName.get(key) ?? []), el]);
  }
  const out: Classified[] = [];
  for (const radios of byName.values()) {
    if (radios.length < 2 || radios.length > MAX_GROUP_PARTS) continue;
    const first = radios[0] as HTMLInputElement;
    let box: Element | null = first.closest("fieldset, [role=radiogroup], [role=group]");
    if (box !== null && !radios.every((r) => box?.contains(r))) box = null;
    const role = box ? textRole(groupLabel(box)) : "unknown";
    if (!RADIO_GROUP_ROLES.has(role)) continue;
    out.push({ el: first, role, direct: false, cell: false, parts: radios, radio: true });
  }
  return out;
}

/**
 * A date group stays one field when it is a birth date, or a document's expiry or issue date in a
 * group that has the document number (an expiry next to card fields only when its words name the
 * document); otherwise its controls are classified one by one, as before.
 */
function settleDateGroups(fields: Classified[]): Classified[] {
  const doc = fields.some((f) => f.role === "passport_number" || f.role === "license_number");
  const card = fields.some((f) => CARD_OWN.has(f.role));
  const out: Classified[] = [];
  for (const f of fields) {
    if (f.fallback === undefined) {
      out.push(f);
      continue;
    }
    const words = fieldWords(f.el);
    const named = PASSPORT_WORDS.test(words) || LICENSE_WORDS.test(words);
    const keep = f.role === "bday" || (doc && (f.role === "passport_issue_date" || (f.role === "cc_exp" && (!card || named))));
    if (keep) out.push(f);
    else out.push(...f.fallback);
  }
  return out;
}

/** Words naming a traveller of a booking, singular and plural, in the seven languages. */
const TRAVELLER =
  "(passagers?|passengers?|passagiers?|pasajeros?|passeggeri|passeggero|passageiros?|voyageurs?|travell?ers?|reisender?|reisende|mitreisender?|fluggast|fluggaste|viajeros?|viaggiatori|viaggiatore|viajantes?|reizigers?|adultes?|adults?|erwachsener?|erwachsene|adultos?|adulti|volwassenen?|enfants?|child|children|kinder|ninos?|bambini|bambino|criancas?|kinderen|occupants?|guests?|huespedes|huesped|ospiti|ospite|hospedes?|personnes?|persons?|personas?|persone|pessoas?|personen|persoon)";
const RANK_AFTER = new RegExp(`\\b${TRAVELLER}\\s+(?:n|no|nr|num|numero)?\\s*(\\d{1,2})\\b`);
const RANK_BEFORE = new RegExp(`\\b(\\d{1,2})\\s*(?:e|er|eme|nd|rd|th|st|o|a|de|ste|te)?\\s+${TRAVELLER}\\b`);
const TRAVELLER_WORD = new RegExp(`\\b${TRAVELLER}\\b`);
const ORDINALS: readonly [RegExp, number][] = [
  [/\b(second|seconde|deuxieme|zweite[rn]?|segund[oa]|second[oa]|tweede)\b/, 2],
  [/\b(third|troisieme|dritte[rn]?|tercer[oa]?|terz[oa]|terceir[oa]|derde)\b/, 3],
  [/\b(fourth|quatrieme|vierte[rn]?|cuart[oa]|quart[oa]|vierde)\b/, 4],
];
/** A traveller index in a field name: `passengers[1]` counts from 0, `pax_2_`, `traveller2`, `adult-2` from 1. */
const NAME_TRAVELLER = "(?:passengers?|pax|travell?ers?|adults?|guests?|persons?|occupants?|passagers?|voyageurs?|reisende[rn]?|pasajeros?|passeggeri|passageiros?|passagiers?)";
const NAME_INDEX_0 = new RegExp(`${NAME_TRAVELLER}\\[(\\d{1,2})\\]`, "i");
const NAME_INDEX_1 = new RegExp(`${NAME_TRAVELLER}[-_.]?(\\d{1,2})(?![0-9])`, "i");

/** Rank (1 for the first) of a traveller that `text` (normalized) names, or null. */
function rankOfText(text: string): number | null {
  const after = RANK_AFTER.exec(text);
  if (after) return Number(after[2]);
  const before = RANK_BEFORE.exec(text);
  if (before) return Number(before[1]);
  if (TRAVELLER_WORD.test(text)) for (const [re, n] of ORDINALS) if (re.test(text)) return n;
  return null;
}

/**
 * Rank of the traveller a field belongs to, by its name, else by the label of a block around it
 * (inside the group, and holding one person only: "2 adultes" over the whole form is a count);
 * null when nothing says.
 */
function travellerRank(el: Element, container: Element, several: (a: Element) => boolean): number | null {
  for (const attr of ["name", "id"]) {
    const v = (el.getAttribute(attr) ?? "").slice(0, MAX_SOURCE_NAME);
    const zero = NAME_INDEX_0.exec(v);
    if (zero) return Number(zero[1]) + 1;
    const one = NAME_INDEX_1.exec(v);
    if (one) return Math.max(1, Number(one[1]));
  }
  for (let a = el.parentElement; a && a !== container; a = a.parentElement) {
    if (several(a)) break;
    const rank = rankOfText(normalizeText(groupLabel(a)));
    if (rank !== null) return rank;
  }
  return null;
}
const MAX_SOURCE_NAME = 200;

/** Roles whose repetition across blocks with no traveller sign means another person (spec section 4). */
const PERSON_ANCHORS: readonly FieldRole[] = ["given_name", "family_name", "full_name", "passport_number", "license_number"];

/**
 * Persons of a group (ruling R3): a block or field name naming traveller 2 or later gives
 * `person` = rank - 1 to its fields. Without any sign, name, date or document roles repeated in
 * other blocks are other people: each later block (the highest ancestor holding the repeat and
 * not the first one) is person 1, 2... Address roles stay the owner's (billing, shipping).
 */
function assignPersons(fields: Classified[], container: Element): void {
  const signed = new Set<Classified>();
  const several = (a: Element) =>
    PERSON_ANCHORS.some((r) => fields.filter((f) => f.role === r && a.contains(f.el)).length >= 2);
  for (const f of fields) {
    const rank = travellerRank(f.el, container, several);
    if (rank === null) continue;
    signed.add(f);
    if (rank >= 2) f.person = rank - 1;
  }
  for (const role of PERSON_ANCHORS) {
    const repeats = fields.filter((f) => f.role === role && !signed.has(f) && f.person === undefined);
    const [first, ...later] = repeats;
    if (first === undefined || later.length === 0) continue;
    later.forEach((o, k) => {
      let block: Element = o.el;
      for (let a = o.el.parentElement; a && a !== container && !a.contains(first.el); a = a.parentElement) block = a;
      // A block is a person's only when it holds more than the repeated field (a wrapper per field is not one).
      if (fields.filter((f) => block.contains(f.el)).length < 2) return;
      for (const f of fields) {
        if (signed.has(f) || f.person !== undefined || ADDRESS.has(f.role) || !block.contains(f.el)) continue;
        f.person = k + 1;
      }
    });
  }
}

/** A phone of the work kind: the `work` autocomplete qualifier, or work words in its own label or names. */
const WORK_TEL =
  /\b(professionnel\w*|pro|work|business|office|bureau|geschaftlich\w*|dienst\w*|buro|trabajo|oficina|lavoro|ufficio|trabalho|escritorio|zakelijk\w*|werk\w*|kantoor)\b/;
function markWork(fields: Classified[]): void {
  for (const f of fields) {
    if (f.role !== "tel") continue;
    const ac = (f.el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
    if (ac.includes("work") || WORK_TEL.test(ownWords(f.el))) f.work = true;
  }
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

/**
 * Buttons that may submit a form group, the document's first, then each root's: the enabled ones,
 * and apart the disabled ones (a page often disables "Continue" until the identifier is typed).
 */
function submitCandidates(doc: Document, roots: readonly ShadowRoot[], geometry: Geometry): { enabled: Element[]; disabled: Element[] } {
  const all = queryAll(doc, roots, BUTTON_SELECTOR, MAX_BUTTONS).filter(
    (el) =>
      !isNavigatingLink(el) &&
      (isSubmitType(el) || isNextLabel(el)) &&
      providerOfButton(el) === null &&
      isRendered(el, geometry),
  );
  return { enabled: all.filter((el) => !el.matches(":disabled")), disabled: all.filter((el) => el.matches(":disabled")) };
}

/** Submit control of a group: a submit-type button first, else a "Next" style label. */
function findSubmit(group: Group, buttons: Element[], isForm: boolean): Element | undefined {
  const inside = buttons.filter((b) =>
    isForm ? controlForm(b) === group.container : group.container.contains(b) && controlForm(b) === null,
  );
  return inside.find(isSubmitType) ?? inside.find(isNextLabel);
}

/**
 * A "Next" style button outside any form, placed after a <form> that holds no button of its own
 * (the form wraps the field only, the page's script reads it on click). It counts only when the
 * nearest ancestor holding both holds no field of another group, so a page-wide button never
 * becomes a form's submit.
 */
function trailingNext(form: Element, buttons: Element[], groups: readonly Group[]): Element | undefined {
  const others = groups.filter((g) => g.container !== form).flatMap((g) => g.fields.map((f) => f.el));
  let best: { button: Element; depth: number } | undefined;
  for (const b of buttons) {
    if (controlForm(b) !== null || !isNextLabel(b)) continue;
    if (!(form.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)) continue;
    const shared = climb(b, (a) => a.contains(form));
    if (shared === null || others.some((el) => shared.contains(el))) continue;
    const d = depth(shared);
    if (best === undefined || d > best.depth) best = { button: b, depth: d };
  }
  return best?.button;
}

/**
 * A lone password guessed as the current one (no `autocomplete`) is a new password when the group
 * has a signup's shape: the submit says the form makes an account ("Register", "Create account")
 * and not a sign-in, and the group asks for two or more identity fields beside the password (a
 * user name and an e-mail, a name and an e-mail...). A sign-in asks for one identifier: a create
 * word in a noisy sign-in label ("create imagelog in", lab g5) never turns its password into a new one.
 */
function resolveSignupPassword(fields: Classified[], submit: Element | undefined): void {
  const pw = fields.filter((f) => f.role === "current_password" || f.role === "new_password" || f.role === "confirm_password");
  const [only] = pw;
  if (pw.length !== 1 || only === undefined || only.role !== "current_password" || only.direct || submit === undefined) return;
  const identity = fields.filter((f) => IDENTIFIERS.has(f.role) || IDENTITY.has(f.role)).length;
  if (identity < 2) return;
  const label = normalizeText(buttonLabel(submit));
  if (CREATE_WORDS.test(label) && !SIGN_IN_WORDS.test(label)) only.role = "new_password";
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

/** The field of `f` as the analysis gives it: groups with their parts, person and work flags. */
function infoOf(f: Classified, refs: RefRegistry): FieldInfo {
  const info: FieldInfo = { ref: refs.refFor(f.el), role: f.role };
  if (f.parts) info.parts = f.parts.slice(0, MAX_GROUP_PARTS).map((el) => refs.refFor(el));
  if (f.person !== undefined && f.person > 0) info.person = Math.min(f.person, MAX_PERSON);
  if (f.work) info.work = true;
  return info;
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
    out.push(infoOf(fields[i] as Classified, refs));
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
  // A confirmation confirms a new password: a guessed "password" before it,
  // with no new one in the group, is that new password (a signup).
  const [first, second] = pw;
  if (pw.length === 2 && first?.role === "current_password" && !first.direct && second?.role === "confirm_password") {
    first.role = "new_password";
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

const CARD_EXPIRY: ReadonlySet<FieldRole> = new Set(["cc_exp", "cc_exp_month", "cc_exp_year"]);
/** Card fields other than the expiry: with one of them, an unqualified expiry is the card's. */
const CARD_OWN: ReadonlySet<FieldRole> = new Set(["cc_number", "cc_name", "cc_csc"]);
const PASSPORT_WORDS = /\b(passeport|passport|reisepass|pass|pasaporte|passaporto|passaporte|paspoort)\b/;
const LICENSE_WORDS =
  /\b(permis|licen[cs]e|fuhrerschein\w*|permiso|carne|patente|carta|conducao|conducir|rijbewijs\w*)\b/;

type Doc = "passport" | "license";

/** The words of a field that name it (names, label, placeholder), normalized; never its value. */
function ownWords(el: FieldElement): string {
  const parts = ["name", "id", "placeholder", "aria-label", "title"].map((a) => el.getAttribute(a) ?? "");
  for (const l of Array.from(el.labels ?? []).slice(0, 3)) parts.push(ownText(l));
  return normalizeText(parts.join(" ").slice(0, 400));
}

/** `ownWords` and the legend of the field's fieldset. */
function fieldWords(el: FieldElement): string {
  const fs = el.closest("fieldset");
  const legend = fs?.querySelector(":scope > legend");
  return legend ? `${ownWords(el)} ${normalizeText(ownText(legend, 100))}` : ownWords(el);
}

/**
 * Dates and countries of a document (spec section 3.2, ruling R6): an expiry, an issue date or an
 * issuing country belongs to the passport when the group has a passport number, to the license
 * when it has a license number; with both, the field's own words (or legend) say which, else the
 * nearest number before it. An expiry stays the card's next to another card field unless its
 * words name a document; an issue date or issuing country with no document number is dropped.
 */
function resolveDocuments(fields: Classified[]): void {
  const passport = fields.some((f) => f.role === "passport_number");
  const license = fields.some((f) => f.role === "license_number");
  const card = fields.some((f) => CARD_OWN.has(f.role));
  const docOf = (f: Classified, i: number): Doc | null => {
    const words = fieldWords(f.el);
    const p = passport && PASSPORT_WORDS.test(words);
    const l = license && LICENSE_WORDS.test(words);
    if (p !== l) return p ? "passport" : "license";
    if (passport !== license) return passport ? "passport" : license ? "license" : null;
    if (!passport) return null;
    for (let k = i - 1; k >= 0; k--) {
      const r = (fields[k] as Classified).role;
      if (r === "passport_number") return "passport";
      if (r === "license_number") return "license";
    }
    return "passport";
  };
  fields.forEach((f, i) => {
    if (f.direct || f.cell) return;
    if (CARD_EXPIRY.has(f.role)) {
      if (!passport && !license) return;
      const words = fieldWords(f.el);
      const named = (passport && PASSPORT_WORDS.test(words)) || (license && LICENSE_WORDS.test(words));
      if (card && !named) return;
      f.role = docOf(f, i) === "license" ? "license_expiry" : "passport_expiry";
      return;
    }
    if (f.role === "passport_issue_date" || f.role === "passport_issuing_country") {
      const doc = docOf(f, i);
      const date = f.role === "passport_issue_date";
      f.role = doc === null ? "unknown" : doc === "license" ? (date ? "license_issue_date" : "license_issuing_country") : f.role;
    }
  });
}

/** The block of a field: its nearest fieldset, else the whole group. */
function blockOf(el: Element, group: Element): Element {
  const fs = el.closest("fieldset");
  return fs !== null && group.contains(fs) ? fs : group;
}

/**
 * A "département" or "departamento" read as a region is a company's department when its block
 * holds a company name or a job title and no other address field (spec section 3.4, ruling R6).
 */
function resolveDepartments(fields: Classified[], container: Element): void {
  for (const f of fields) {
    if (f.role !== "region" || f.direct || !/\b(departement|departamento)\b/.test(fieldWords(f.el))) continue;
    const block = blockOf(f.el, container);
    const mates = fields.filter((x) => x !== f && block.contains(x.el));
    const company = mates.some((x) => x.role === "organization" || x.role === "job_title");
    if (company && !mates.some((x) => ADDRESS.has(x.role))) f.role = "department";
  }
}

/**
 * An Italian tax code read as a company registration ("Codice fiscale", "Cod. fisc.") is a
 * person's own code unless the group holds a company name or a VAT number: there it is dropped.
 */
function resolveTaxCodes(fields: Classified[]): void {
  const company = fields.some((x) => x.role === "organization" || x.role === "vat_number");
  if (company) return;
  for (const f of fields) {
    if (f.role !== "company_id" || f.direct) continue;
    const words = fieldWords(f.el);
    if (/\b(codice fiscale|cod fisc|cod fiscale)\b/.test(words) && !/\b(azienda|societa|impresa|ditta)\b/.test(words)) f.role = "unknown";
  }
}

/**
 * A guessed full name followed by a family name, with no given name in the
 * group, is the given name ("Name" then "Family name").
 */
function resolveNames(fields: Classified[]): void {
  if (fields.some((f) => f.role === "given_name")) return;
  const family = fields.findIndex((f) => f.role === "family_name");
  if (family < 0) return;
  const full = fields.findIndex((f) => f.role === "full_name" && !f.direct);
  if (full >= 0 && full < family) (fields[full] as Classified).role = "given_name";
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
function signInPage(doc: Document, roots: readonly ShadowRoot[], url: string): boolean {
  const headings = queryAll(doc, roots, "h1, h2", MAX_HEADINGS).map((h) => ownText(h, 100));
  const texts = [doc.title, url, ...headings];
  if (texts.some((t) => SIGN_IN_TEXT.test(normalizeText(t)))) return true;
  return queryAll(doc, roots, "a", MAX_FORGOT_LINKS).some((a) => FORGOT_TEXT.test(normalizeText(ownText(a, 100))));
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

/** Order in the flattened page: shadow content sits where its host does. */
const documentOrder = composedOrder;

/**
 * Model roles of the visible fields, after the safety rules (classifier.ts). Features come from the
 * shared extractor without the page-supplied lab mark. A field absent from the map keeps its
 * heuristic role (no features, e.g. a checkbox, or no answer yet); a field mapped to `unknown`
 * stays unknown. Never consulted in a cross-site frame, nor for a field whose autocomplete token
 * the detector recognizes (R21).
 */
function modelRoles(doc: Document, roots: readonly ShadowRoot[], geometry: Geometry, model: ModelHook): Map<Element, RoleScore> {
  const out = new Map<Element, RoleScore>();
  if (model.crossSite) return out;
  const elOf = new Map<FieldFeatures, Element>();
  // The shadow roots' forms are read as the document's (spec D1, D2).
  const page = extractFeatures(doc, { maxFields: MAX_FIELDS, roots, onField: (el, f) => elOf.set(f, el) });
  for (const form of page.forms) {
    // Ruling R21: a recognized autocomplete token decides (spec 8.2); such a field is never sent to the model.
    const asked = form.fields.filter((f) => autocompleteRole(elOf.get(f) as FieldElement) === null);
    if (asked.length === 0) continue;
    const els = asked.map((f) => elOf.get(f) as FieldElement);
    const roles = model.lookup(asked);
    if (roles === null || model.crossSite) continue;
    const safe = applySafetyRules(els, roles, { crossSite: model.crossSite }, { geometry, features: asked });
    els.forEach((el, i) => out.set(el, safe[i] as RoleScore));
  }
  return out;
}

/**
 * Classified forms and field groups of the document and of `roots` (its
 * shadow roots), in page order. `url` defaults to `doc.URL`.
 */
export function detectForms(
  doc: Document,
  refs: RefRegistry,
  geometry: Geometry = domGeometry,
  url: string = doc.URL,
  roots: readonly ShadowRoot[] = [],
  model?: ModelHook,
): FormInfo[] {
  const visible: FieldElement[] = [];
  for (const el of queryAll(doc, roots, FIELD_SELECTOR, MAX_FIELDS)) {
    if (isFieldCandidate(el) && isVisible(el, geometry)) visible.push(el);
  }
  // Split OTP runs are read in page order: roots come after the document.
  if (roots.length > 0) visible.sort(documentOrder);
  const cells = splitOtpCells(visible);
  // Order (Task 15): features, classifier, safety rules, then the existing logic below.
  const fromModel = model ? modelRoles(doc, roots, geometry, model) : null;
  const single = (el: FieldElement): Classified | null => {
    if (cells.has(el)) return { el, role: "otp", direct: false, cell: true };
    const heuristic = classifyField(el);
    const direct = heuristic.score === AUTOCOMPLETE_SCORE;
    // R21: an autocomplete-decided role is never replaced by the model, nor a role no model has (R13).
    const keep = direct || HEURISTIC_ONLY.has(heuristic.role);
    const { role } = (keep ? undefined : fromModel?.get(el)) ?? heuristic;
    return role === "unknown" ? null : { el, role, direct, cell: false };
  };
  // Date groups (one field with its parts), kept with their one-by-one reading (settleDateGroups).
  const dates = findDateGroups(visible.filter((el) => !cells.has(el)));
  const inDate = new Set<FieldElement>([...dates.values()].flatMap((g) => g.parts));
  const classified: Classified[] = [];
  for (const el of visible) {
    const date = dates.get(el);
    if (date) {
      const fallback = date.parts.map(single).filter((c): c is Classified => c !== null);
      classified.push({ el, role: date.role, direct: false, cell: false, parts: date.parts, fallback });
      continue;
    }
    if (inDate.has(el)) continue;
    const c = single(el);
    if (c) classified.push(c);
  }
  classified.push(...findRadioGroups(doc, roots, geometry));

  const byForm = new Map<HTMLFormElement, Classified[]>();
  const orphans: Classified[] = [];
  for (const f of classified) {
    const form = f.el.form;
    if (form === null) orphans.push(f);
    else byForm.set(form, [...(byForm.get(form) ?? []), f]);
  }

  const { enabled: buttons, disabled: idleButtons } = submitCandidates(doc, roots, geometry);
  const groups: { group: Group; isForm: boolean }[] = [
    ...Array.from(byForm, ([container, fields]) => ({ group: { container, fields }, isForm: true })),
    ...groupOrphans(orphans, buttons).map((group) => ({ group, isForm: false })),
  ];
  groups.sort((a, b) => documentOrder(a.group.fields[0]!.el, b.group.fields[0]!.el));

  let page: boolean | undefined;
  const isSignInPage = () => (page ??= signInPage(doc, roots, url));
  const out: FormInfo[] = [];
  for (const { group, isForm } of groups) {
    group.fields.sort((a, b) => documentOrder(a.el, b.el));
    group.fields = settleDateGroups(group.fields);
    resolveSecurityCodes(group.fields);
    resolvePasswords(group.fields);
    resolveNames(group.fields);
    resolveDocuments(group.fields);
    resolveDepartments(group.fields, group.container);
    resolveTaxCodes(group.fields);
    group.fields = group.fields.filter((f) => f.role !== "unknown");
    if (group.fields.length === 0) continue;
    assignPersons(group.fields, group.container);
    // Names again per person: passenger 2's "Name" before "Family name" is its given name, as the
    // owner's would be (resolveNames reads the group, where passenger 1's given name hid it).
    for (const p of new Set(group.fields.map((f) => f.person ?? 0))) resolveNames(group.fields.filter((f) => (f.person ?? 0) === p));
    markWork(group.fields);
    const submit =
      findSubmit(group, buttons, isForm) ??
      (isForm ? trailingNext(group.container, buttons, groups.map((g) => g.group)) : undefined);
    resolveSignupPassword(group.fields, submit);
    // A disabled "Continue" (enabled once the identifier is typed) still marks the step, but is
    // never the submit OnePass presses.
    const step = submit ?? findSubmit(group, idleButtons, isForm);
    const kind = formKind(
      group.fields.map((f) => f.role),
      step !== undefined && isNextLabel(step) && identifierStep(group.fields, step, isSignInPage),
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
    forms: detectForms(doc, refs, geometry, url, opts.shadowRoots ?? collectShadowRoots(doc), opts.model),
    captcha: detectCaptcha(doc, geometry),
    push: detectPush(doc),
    providerButtons: detectProviderButtons(doc, refs, geometry),
    accountChooser: onProvider ? detectAccountChooser(doc, refs, geometry) : [],
  };
}
