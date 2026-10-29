// The single `runtime.onMessage` listener of the service worker.
//
// Every message is classified by its browser-reported sender first:
// - an extension page (sender.url under our extension origin, our id) may
//   only send `UiToBg`, and each family only from its own page (`menu_*`
//   from menu.html, `popup_*` from popup.html, ...);
// - a content script (our id, a web page URL, a tab and a frame) may only
//   send `CsToBg`, after full field validation.
// Anything else, malformed or without a handler, is dropped without a reply.
// Messages are rebuilt from validated fields only: unknown keys (a forged
// `origin`, say) never reach a handler.
import {
  type ButtonClass,
  type ButtonContext,
  type CsToBg,
  type FieldContext,
  type FieldInfo,
  type FieldRole,
  type FormContext,
  type FormInfo,
  type FormKind,
  type IntentHints,
  PAGE_CONTEXT_MAX_BUTTONS,
  PAGE_CONTEXT_MAX_FIELDS,
  PAGE_CONTEXT_MAX_FORMS,
  type PageAnalysis,
  type PlanContextBody,
  type Prefilled,
  type ProviderId,
  type SaveEdits,
  type UiToBg,
} from "../shared/messages";
import type { BgExt, MessageListener } from "./ext";
import { type CsContext, type UiContext, contentSender, extensionSender } from "./frames";
import { toBgError } from "./session";

// ---- limits ----

export const MAX_REF = 64;
const MAX_URL = 4096;
const MAX_EMAIL = 320;
const MAX_USERNAME = 1024;
const MAX_PASSWORD = 4096;
const MAX_ITEM_ID = 128;
const MAX_QUERY = 256;
const MAX_FORMS = 64;
const MAX_FIELDS = 128;
const MAX_PARTS = 8;
const MAX_BUTTONS = 32;
const MAX_TITLE = 256;
const MAX_TAGS = 32;
const MAX_TAG = 64;

const REF_RE = /^[A-Za-z0-9_-]+$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/;

const FORM_KINDS: ReadonlySet<string> = new Set<FormKind>([
  "login",
  "signup",
  "change_password",
  "otp",
  "card",
  "identity",
  "address",
]);

const FIELD_ROLES: ReadonlySet<string> = new Set<FieldRole>([
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
  "unknown",
]);

const PROVIDER_IDS: ReadonlySet<string> = new Set<ProviderId>([
  "google",
  "apple",
  "microsoft",
  "github",
  "facebook",
  "x",
  "linkedin",
  "discord",
  "slack",
]);

// ---- validation helpers (throw on any mismatch) ----

class Invalid extends Error {}

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Invalid();
  return v as Obj;
}

function str(v: unknown, max: number, min = 0): string {
  if (typeof v !== "string" || v.length < min || v.length > max) throw new Invalid();
  return v;
}

function bool(v: unknown): boolean {
  if (typeof v !== "boolean") throw new Invalid();
  return v;
}

function ref(v: unknown): string {
  const s = str(v, MAX_REF, 1);
  if (!REF_RE.test(s)) throw new Invalid();
  return s;
}

function token(v: unknown): string {
  const s = str(v, 22, 22);
  if (!TOKEN_RE.test(s)) throw new Invalid();
  return s;
}

function member<T extends string>(v: unknown, set: ReadonlySet<string>): T {
  if (typeof v !== "string" || !set.has(v)) throw new Invalid();
  return v as T;
}

function list<T>(v: unknown, max: number, each: (x: unknown) => T): T[] {
  if (!Array.isArray(v) || v.length > max) throw new Invalid();
  return v.map(each);
}

function field(v: unknown): FieldInfo {
  const o = obj(v);
  const f: FieldInfo = { ref: ref(o.ref), role: member<FieldRole>(o.role, FIELD_ROLES) };
  if (o.parts !== undefined) f.parts = list(o.parts, MAX_PARTS, ref);
  return f;
}

function form(v: unknown): FormInfo {
  const o = obj(v);
  const f: FormInfo = {
    ref: ref(o.ref),
    kind: member<FormKind>(o.kind, FORM_KINDS),
    fields: list(o.fields, MAX_FIELDS, field),
  };
  if (o.submitRef !== undefined) f.submitRef = ref(o.submitRef);
  return f;
}

function analysis(v: unknown): PageAnalysis {
  const o = obj(v);
  return {
    // Page-influenced hint, never used for policy: the origin comes from sender.
    url: str(o.url, MAX_URL),
    forms: list(o.forms, MAX_FORMS, form),
    captcha: bool(o.captcha),
    push: bool(o.push),
    providerButtons: list(o.providerButtons, MAX_BUTTONS, (b) => {
      const x = obj(b);
      return { provider: member<ProviderId>(x.provider, PROVIDER_IDS), ref: ref(x.ref) };
    }),
    accountChooser: list(o.accountChooser, MAX_BUTTONS, (b) => {
      const x = obj(b);
      return { email: str(x.email, MAX_EMAIL), ref: ref(x.ref) };
    }),
  };
}

// ---- plan_context (smart fill) ----
// Bounds of the bridge's `PageContext` (it checks them again); the origins
// and frame kind the content script may add are dropped, never read.

const PREFILLED: ReadonlySet<string> = new Set<Prefilled>(["empty", "typed", "ours"]);
const BUTTON_CLASSES: ReadonlySet<string> = new Set<ButtonClass>(["submit", "next", "pay", "create", "other"]);
/** serde `[u8; 32]`. */
const USERNAME_HASH_LEN = 32;

function byte(v: unknown, max = 255): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > max) throw new Invalid();
  return v;
}

function hints(v: unknown): IntentHints {
  const o = obj(v);
  return {
    kind: o.kind === null ? null : member<FormKind>(o.kind, FORM_KINDS),
    signup_words: bool(o.signup_words),
    reset_words: bool(o.reset_words),
    checkout_words: bool(o.checkout_words),
    ignore: bool(o.ignore),
  };
}

function fieldContext(v: unknown): FieldContext {
  const o = obj(v);
  const c = o.confidence;
  if (typeof c !== "number" || !Number.isFinite(c) || c < 0 || c > 1) throw new Invalid();
  return {
    field_ref: ref(o.field_ref),
    role: o.role === null ? null : member<FieldRole>(o.role, FIELD_ROLES),
    confidence: c,
    visible: bool(o.visible),
    prefilled: member<Prefilled>(o.prefilled, PREFILLED),
  };
}

function buttonContext(v: unknown): ButtonContext {
  const o = obj(v);
  return { button_ref: ref(o.button_ref), class: member<ButtonClass>(o.class, BUTTON_CLASSES) };
}

function formContext(v: unknown): FormContext {
  const o = obj(v);
  return {
    form_ref: ref(o.form_ref),
    intent_hints: hints(o.intent_hints),
    step_index: o.step_index === null ? null : byte(o.step_index),
    fields: list(o.fields, PAGE_CONTEXT_MAX_FIELDS, fieldContext),
    buttons: list(o.buttons, PAGE_CONTEXT_MAX_BUTTONS, buttonContext),
  };
}

/** A page context body a content script replied to `plan_request`, rebuilt and bounded; null when malformed. */
export function parsePlanContextBody(v: unknown): PlanContextBody | null {
  try {
    return planContext(v);
  } catch {
    return null;
  }
}

function planContext(v: unknown): PlanContextBody {
  const o = obj(v);
  let hash: number[] | null = null;
  if (o.typed_username_hash !== null) {
    hash = list(o.typed_username_hash, USERNAME_HASH_LEN, (b) => byte(b));
    if (hash.length !== USERNAME_HASH_LEN) throw new Invalid();
  }
  return { forms: list(o.forms, PAGE_CONTEXT_MAX_FORMS, formContext), typed_username_hash: hash };
}

/** A fully validated, rebuilt content script message, or null. */
export function parseCsToBg(m: unknown): CsToBg | null {
  try {
    const o = obj(m);
    switch (o.type) {
      case "page_analysis":
        return { type: "page_analysis", analysis: analysis(o.analysis) };
      case "open_menu": {
        const r: CsToBg = {
          type: "open_menu",
          fieldRef: ref(o.fieldRef),
          formRef: ref(o.formRef),
          formKind: member<FormKind>(o.formKind, FORM_KINDS),
        };
        if (o.auto !== undefined) r.auto = bool(o.auto);
        return r;
      }
      case "close_menu":
        return { type: "close_menu" };
      case "submitted_credentials":
        return {
          type: "submitted_credentials",
          formRef: ref(o.formRef),
          username: str(o.username, MAX_USERNAME),
          password: str(o.password, MAX_PASSWORD, 1),
          isNew: bool(o.isNew),
        };
      case "provider_click":
        return { type: "provider_click", provider: member<ProviderId>(o.provider, PROVIDER_IDS), ref: ref(o.ref) };
      case "account_click":
        return { type: "account_click", email: str(o.email, MAX_EMAIL), ref: ref(o.ref) };
      case "menu_key":
        return { type: "menu_key", key: member(o.key, MENU_KEYS) };
      case "fill_salt":
        return { type: "fill_salt" };
      case "plan_context": {
        const r: CsToBg = { type: "plan_context", context: planContext(o.context) };
        if (o.formRef !== undefined) r.formRef = ref(o.formRef);
        if (o.fieldRef !== undefined) r.fieldRef = ref(o.fieldRef);
        return r;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

function edits(v: unknown): SaveEdits {
  const o = obj(v);
  return {
    title: str(o.title, MAX_TITLE),
    username: str(o.username, MAX_USERNAME),
    password: str(o.password, MAX_PASSWORD),
    vaultId: str(o.vaultId, MAX_ITEM_ID, 1),
    rule: member<SaveEdits["rule"]>(o.rule, new Set(["domain", "exact_host", "exact_url", "never"])),
    tags: list(o.tags, MAX_TAGS, (t) => str(t, MAX_TAG, 1)),
  };
}

const itemId = (v: unknown) => str(v, MAX_ITEM_ID, 1);

const MENU_KEYS: ReadonlySet<string> = new Set(["down", "up", "enter"]);
/** Frame heights a page may ask for (the content script clamps again per kind). */
const MAX_FRAME_HEIGHT = 2000;

function height(v: unknown): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > MAX_FRAME_HEIGHT) throw new Invalid();
  return v;
}

const GEN_KINDS: ReadonlySet<string> = new Set(["smart", "random", "memorable", "pin"]);

/** A fully validated, rebuilt extension page message, or null. */
export function parseUiToBg(m: unknown): UiToBg | null {
  try {
    const o = obj(m);
    switch (o.type) {
      case "menu_init":
      case "menu_generate":
      case "menu_new_login":
      case "menu_unlock":
      case "menu_close":
      case "menu_keys":
      case "overlay_init":
      case "overlay_state":
      case "overlay_stop":
      case "overlay_close":
      case "save_init":
      case "save_reveal":
      case "save_generate":
      case "save_close":
        return { type: o.type, token: token(o.token) };
      case "menu_pick":
        return { type: o.type, token: token(o.token), itemId: itemId(o.itemId) };
      case "menu_signin": {
        const s: UiToBg = {
          type: o.type,
          token: token(o.token),
          itemId: itemId(o.itemId),
          provider: member<ProviderId>(o.provider, PROVIDER_IDS),
        };
        if (o.accountId !== undefined) s.accountId = itemId(o.accountId);
        return s;
      }
      case "overlay_start": {
        const s: UiToBg = { type: o.type, token: token(o.token), itemId: itemId(o.itemId) };
        if (o.provider !== undefined) s.provider = member<ProviderId>(o.provider, PROVIDER_IDS);
        if (o.accountId !== undefined) {
          if (s.provider === undefined) throw new Invalid();
          s.accountId = itemId(o.accountId);
        }
        return s;
      }
      case "menu_resize":
      case "overlay_resize":
      case "save_resize":
        return { type: o.type, token: token(o.token), height: height(o.height) };
      case "save_decide": {
        const d: UiToBg = {
          type: "save_decide",
          token: token(o.token),
          decision: member(o.decision, new Set(["save", "update", "never", "dismiss"])),
        };
        if (o.edits !== undefined) d.edits = edits(o.edits);
        if (o.itemId !== undefined) d.itemId = itemId(o.itemId);
        return d;
      }
      case "popup_status":
      case "popup_unlock":
      case "popup_suggestions":
      case "popup_history":
      case "popup_pair_start":
      case "popup_pair_approve":
      case "popup_pair_cancel":
      case "popup_forget":
      case "popup_smart_fill":
      case "popup_forget_site":
        return { type: o.type };
      case "popup_search":
        return { type: "popup_search", query: str(o.query, MAX_QUERY) };
      case "popup_fill":
      case "popup_totp":
      case "popup_item":
      case "popup_reveal":
        return { type: o.type, itemId: itemId(o.itemId) };
      case "popup_generate": {
        const g: UiToBg = { type: o.type, kind: member(o.kind, GEN_KINDS) };
        if (o.length !== undefined) {
          if (typeof o.length !== "number" || !Number.isInteger(o.length) || o.length < 4 || o.length > 128) throw new Invalid();
          g.length = o.length;
        }
        if (o.symbols !== undefined) g.symbols = bool(o.symbols);
        return g;
      }
      case "popup_fill_generated":
        return { type: o.type, password: str(o.password, MAX_PASSWORD, 1) };
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** The extension page each UI message family must come from. */
function pageFor(type: UiToBg["type"]): string {
  const family = type.slice(0, type.indexOf("_"));
  return `${family}.html`;
}

// ---- dispatch ----

export type CsHandler<K extends CsToBg["type"]> = (m: Extract<CsToBg, { type: K }>, from: CsContext) => Promise<unknown>;
export type UiHandler<K extends UiToBg["type"]> = (m: Extract<UiToBg, { type: K }>, from: UiContext) => Promise<unknown>;

/** Handler table; later tasks add entries (popup, chain, save flow). */
export interface Handlers {
  cs: { [K in CsToBg["type"]]?: CsHandler<K> };
  ui: { [K in UiToBg["type"]]?: UiHandler<K> };
}

/** Reply envelope: `{ok}` or `{err: <stable code>}`, never a raw host message. */
export type Reply = { ok: unknown } | { err: string };

function run(p: Promise<unknown>, sendResponse: (r: Reply) => void): void {
  p.then(
    (ok) => sendResponse({ ok: ok ?? null }),
    (e) => sendResponse({ err: toBgError(e).code }),
  );
}

export function createRouter(runtime: Pick<BgExt["runtime"], "id" | "getURL">, handlers: Handlers): MessageListener {
  return (message, sender, sendResponse) => {
    const ui = extensionSender(runtime, sender);
    if (ui) {
      const m = parseUiToBg(message);
      if (!m || ui.page !== pageFor(m.type)) return undefined;
      const h = handlers.ui[m.type] as UiHandler<typeof m.type> | undefined;
      if (!h) return undefined;
      run(Promise.resolve().then(() => h(m as never, ui)), sendResponse);
      return true;
    }
    const cs = contentSender(runtime, sender);
    if (!cs) return undefined;
    const m = parseCsToBg(message);
    if (!m) return undefined;
    const h = handlers.cs[m.type] as CsHandler<typeof m.type> | undefined;
    if (!h) return undefined;
    run(Promise.resolve().then(() => h(m as never, cs)), sendResponse);
    return true;
  };
}
