// Validation of service worker replies before rendering. A malformed reply
// renders as an internal error, never partially.
import type { FormKind, GhostMetrics, ProviderId, MenuPreview, SaveOutcome, SuggestionPreview } from "../shared/messages";
import {
  CHAIN_PHASES,
  CUSTOM_MAX_LENGTH,
  CUSTOM_MIN_LENGTH,
  STEP_WHATS,
  type StepWhat,
  type ChainPhase,
  type ChainStepView,
  type ChainView,
  type GeneratorEntry,
  type GeneratorKind,
  type MenuInit,
  type MenuNotice,
  type OverlayAccount,
  type OverlayInit,
  type PopupItem,
  type PopupPlanLine,
  type PendingSave,
  type PopupStatus,
  type PopupSuggestions,
  type ProviderChoice,
  type SaveInit,
  type SignInChoice,
  STOP_REASONS,
  type StepState,
  type StopReason,
  type Summary,
} from "../shared/ui";

class Bad extends Error {}
type Obj = Record<string, unknown>;

const MAX_TEXT = 1024;
const MAX_ITEMS = 500;

function obj(v: unknown): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Bad();
  return v as Obj;
}
function str(v: unknown, max = MAX_TEXT): string {
  if (typeof v !== "string" || v.length > max) throw new Bad();
  return v;
}
function bool(v: unknown): boolean {
  if (typeof v !== "boolean") throw new Bad();
  return v;
}
function num(v: unknown): number {
  if (typeof v !== "number" || !Number.isFinite(v)) throw new Bad();
  return v;
}
function oneOf<T extends string>(v: unknown, set: readonly string[]): T {
  if (typeof v !== "string" || !set.includes(v)) throw new Bad();
  return v as T;
}
function list<T>(v: unknown, each: (x: unknown) => T, max = MAX_ITEMS): T[] {
  if (!Array.isArray(v) || v.length > max) throw new Bad();
  return v.map(each);
}
function guard<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

const PROVIDERS = ["google", "apple", "microsoft", "github", "facebook", "x", "linkedin", "discord", "slack"];
const FORM_KINDS = ["login", "signup", "change_password", "otp", "card", "identity", "address"];
const origin = (v: unknown) => {
  const s = str(v, 2048);
  if (!/^https?:\/\/[^/\s]+$/.test(s)) throw new Bad();
  return s;
};

export function summary(v: unknown): Summary {
  const o = obj(v);
  return {
    item_id: str(o.item_id, 128),
    vault_id: str(o.vault_id, 128),
    vault_name: str(o.vault_name),
    title: str(o.title),
    subtitle: str(o.subtitle),
    kind: oneOf(o.kind, ["login", "card", "identity"]),
    icon_letter: str(o.icon_letter, 8),
    icon_color: str(o.icon_color, 32),
    has_password: bool(o.has_password),
    has_totp: bool(o.has_totp),
    methods: list(o.methods, (m) => {
      const x = obj(m);
      return { provider: oneOf<ProviderId>(x.provider, PROVIDERS), account_email: str(x.account_email, 320) };
    }, 32),
    match: o.match === null || o.match === undefined ? null : oneOf<"exact_host" | "domain">(o.match, ["exact_host", "domain"]),
    ...accountNoteOf(o),
  };
}

/** The optional account label and associated-site flag of a summary or an overlay account: absent, or well formed. */
function accountNoteOf(o: Record<string, unknown>): { account?: string; associated?: true } {
  const out: { account?: string; associated?: true } = {};
  if (o.account !== undefined) out.account = str(o.account, 256);
  // Only ever true: the host leaves it out otherwise.
  if (o.associated !== undefined) {
    if (o.associated !== true) throw new Bad();
    out.associated = true;
  }
  return out;
}

export const parseMenuInit = (v: unknown): MenuInit | null =>
  guard(() => {
    const o = obj(v);
    const m: MenuInit = { origin: origin(o.origin), formKind: oneOf<FormKind>(o.formKind, FORM_KINDS), items: list(o.items, summary) };
    if (o.linked !== undefined) {
      const l = obj(o.linked);
      m.linked = { itemId: str(l.itemId, 128), site: str(l.site, 253) };
    }
    if (o.choices !== undefined) m.choices = list(o.choices, signInChoice, 64);
    if (o.best !== undefined) m.best = str(o.best, 128);
    if (o.notice !== undefined) m.notice = oneOf<MenuNotice>(o.notice, ["site_refused"]);
    if (o.signup !== undefined) {
      if (obj(o.signup).passkey !== true) throw new Error("signup");
      m.signup = { passkey: true };
    }
    return m;
  });

function providerChoice(v: unknown): ProviderChoice {
  const o = obj(v);
  return { itemId: str(o.itemId, 128), email: str(o.email, 320), title: str(o.title, 256) };
}

function signInChoice(v: unknown): SignInChoice {
  const o = obj(v);
  const c: SignInChoice = {
    itemId: str(o.itemId, 128),
    provider: oneOf<ProviderId>(o.provider, PROVIDERS),
    accounts: list(o.accounts, providerChoice, 32),
  };
  if (o.accountId !== undefined) c.accountId = str(o.accountId, 128);
  return c;
}

function step(v: unknown): ChainStepView {
  const o = obj(v);
  const s: ChainStepView = { label: str(o.label, 256), state: oneOf<StepState>(o.state, ["pending", "active", "done", "stopped"]) };
  if (o.detail !== undefined) s.detail = str(o.detail, 256);
  if (o.what !== undefined) s.what = oneOf<StepWhat>(o.what, STEP_WHATS);
  if (o.onProvider !== undefined) s.onProvider = bool(o.onProvider);
  return s;
}

function chain(v: unknown): ChainView | null {
  if (v === null) return null;
  const o = obj(v);
  const c: ChainView = {
    itemId: str(o.itemId, 128),
    status: oneOf(o.status, ["running", "done", "stopped", "handoff"]),
    steps: list(o.steps, step, 64),
  };
  if (o.reason !== undefined) c.reason = oneOf<StopReason>(o.reason, STOP_REASONS);
  if (o.host !== undefined) c.host = str(o.host, 253);
  if (o.title !== undefined) c.title = str(o.title, 256);
  if (o.site !== undefined) c.site = str(o.site, 253);
  if (o.provider !== undefined) c.provider = oneOf<ProviderId>(o.provider, PROVIDERS);
  if (o.email !== undefined) c.email = str(o.email, 1024);
  if (o.phase !== undefined) c.phase = oneOf<ChainPhase>(o.phase, CHAIN_PHASES);
  return c;
}

function account(v: unknown): OverlayAccount {
  const o = obj(v);
  const a: OverlayAccount = {
    itemId: str(o.itemId, 128),
    title: str(o.title),
    subtitle: str(o.subtitle),
    iconLetter: str(o.iconLetter, 8),
    iconColor: str(o.iconColor, 32),
  };
  if (o.provider !== undefined) a.provider = oneOf<ProviderId>(o.provider, PROVIDERS);
  if (o.email !== undefined) a.email = str(o.email, 320);
  if (o.accountId !== undefined) a.accountId = str(o.accountId, 128);
  if (o.accounts !== undefined) a.accounts = list(o.accounts, providerChoice, 32);
  if (o.totp !== undefined) a.totp = bool(o.totp);
  Object.assign(a, accountNoteOf(o));
  if (o.vault !== undefined) {
    const v = obj(o.vault);
    a.vault = { id: str(v.id, 128), name: str(v.name, 256) };
  }
  return a;
}

/** What a card that asked for an unlock waits for: the unlock in the app, or the app itself. */
export type OverlayWaiting = "locked" | "host_missing";
const OVERLAY_WAITS = ["locked", "host_missing"];

/** `waiting`: a card that came up for a chain stopped `locked` on its page (no list while locked). */
export const parseOverlayInit = (v: unknown): (OverlayInit & { waiting?: OverlayWaiting }) | null =>
  guard(() => {
    const o = obj(v);
    const init: OverlayInit & { waiting?: OverlayWaiting } = { origin: origin(o.origin), accounts: list(o.accounts, account, 64), chain: chain(o.chain) };
    if (o.waiting !== undefined) init.waiting = oneOf<OverlayWaiting>(o.waiting, OVERLAY_WAITS);
    if (o.generic !== undefined) {
      // Only ever true, and never beside an account.
      if (o.generic !== true || init.accounts.length > 0) throw new Bad();
      init.generic = true;
    }
    return init;
  });

/** `waiting`: the app was asked to unlock for this card; the sign-in goes on by itself after it. */
export const parseOverlayState = (v: unknown): { chain: ChainView | null; waiting?: OverlayWaiting } | null =>
  guard(() => {
    const o = obj(v);
    const s: { chain: ChainView | null; waiting?: OverlayWaiting } = { chain: chain(o.chain) };
    if (o.waiting !== undefined) s.waiting = oneOf<OverlayWaiting>(o.waiting, OVERLAY_WAITS);
    return s;
  });

/** Reply of `overlay_start`: started, or `waiting` for the unlock the click asked. */
export const parseOverlayStart = (v: unknown): { waiting?: OverlayWaiting } | null =>
  guard(() => {
    const o = obj(v);
    return o.waiting === undefined ? {} : { waiting: oneOf<OverlayWaiting>(o.waiting, OVERLAY_WAITS) };
  });

export const parseSaveInit = (v: unknown): SaveInit | null =>
  guard(() => {
    const o = obj(v);
    const s: SaveInit = {
      origin: origin(o.origin),
      site: str(o.site, 253),
      kind: oneOf(o.kind, ["login", "provider_link", "card", "identity"]),
      status: oneOf(o.status, ["new", "update"]),
      title: str(o.title, 256),
      username: str(o.username),
      vaults: list(o.vaults, (x) => {
        const vv = obj(x);
        const out: SaveInit["vaults"][number] = { id: str(vv.id, 128), name: str(vv.name, 256) };
        if (vv.account !== undefined) out.account = str(vv.account, 256);
        return out;
      }, 64),
    };
    if (o.defaultVault !== undefined) s.defaultVault = str(o.defaultVault, 128);
    if (o.locked !== undefined) s.locked = o.locked === true;
    if (o.update !== undefined) {
      const u = obj(o.update);
      s.update = { itemId: str(u.itemId, 128), title: str(u.title, 256) };
    }
    if (o.provider !== undefined) {
      const p = obj(o.provider);
      s.provider = { id: oneOf<ProviderId>(p.id, PROVIDERS), email: str(p.email, 320) };
      if (p.title !== undefined) s.provider.title = str(p.title, 256);
    }
    if (o.view !== undefined) s.view = oneOf<"edit" | "saved" | "toast">(o.view, ["edit", "saved", "toast"]);
    if (o.undo !== undefined) s.undo = o.undo === true;
    if (o.folded === true) s.folded = true;
    if (o.card !== undefined) {
      const c = obj(o.card);
      s.card = { last4: str(c.last4, 4) };
      if (c.exp !== undefined) s.card.exp = str(c.exp, 8);
      if (c.holder !== undefined) s.card.holder = str(c.holder, 256);
    }
    if (o.identity !== undefined) {
      const i = obj(o.identity);
      s.identity = {};
      if (i.name !== undefined) s.identity.name = str(i.name, 512);
      if (i.email !== undefined) s.identity.email = str(i.email, 320);
      if (i.place !== undefined) s.identity.place = str(i.place, 800);
    }
    return s;
  });

export const parsePassword = (v: unknown): { password: string } | null =>
  guard(() => ({ password: str(obj(v).password, 4096) }));

const MENU_KEYS = ["down", "up", "enter"];

export const parseKeys = (v: unknown): { keys: ("down" | "up" | "enter")[] } | null =>
  guard(() => ({ keys: list(obj(v).keys, (k) => oneOf<"down" | "up" | "enter">(k, MENU_KEYS), 8) }));

export const parseEmpty = (v: unknown): object | null => guard(() => obj(v));

/** Reply of a save or an update: what it did (an empty reply reads as "done"). */
export const parseOutcome = (v: unknown): SaveOutcome | null =>
  guard(() => {
    const o = obj(v);
    const out: SaveOutcome = { outcome: o.outcome === undefined ? "done" : oneOf<SaveOutcome["outcome"]>(o.outcome, ["saved", "updated", "already", "done"]) };
    if (o.vault !== undefined) out.vault = str(o.vault, 256);
    return out;
  });

export const parsePending = (v: unknown): PendingSave[] | null =>
  guard(() =>
    list(obj(v).pending, (x) => {
      const o = obj(x);
      const p: PendingSave = {
        id: str(o.id, 22),
        origin: origin(o.origin),
        site: str(o.site, 253),
        username: str(o.username),
        status: oneOf(o.status, ["new", "update"]),
      };
      if (o.title !== undefined) p.title = str(o.title, 256);
      if (o.vault !== undefined) p.vault = str(o.vault, 256);
      return p;
    }, 16),
  );

/** The iOS native vault for the unlock sheet (background/safari.ts `NativeVault`). */
export interface NativeVaultState {
  locked: boolean;
  account: string;
  biometry: "faceID" | "touchID" | "opticID" | "none";
  error?: "password_required" | "wrong_password" | "cancelled" | "locked_out" | "no_account" | "failed";
  message?: string;
}

const BIOMETRY_KINDS = ["faceID", "touchID", "opticID", "none"];
const VAULT_ERRORS = ["password_required", "wrong_password", "cancelled", "locked_out", "no_account", "failed"];

export const parseNativeVaultState = (v: unknown): NativeVaultState | null =>
  guard(() => {
    const o = obj(v);
    const s: NativeVaultState = {
      locked: bool(o.locked),
      account: str(o.account, 320),
      biometry: oneOf<NativeVaultState["biometry"]>(o.biometry, BIOMETRY_KINDS),
    };
    if (o.error !== undefined) s.error = oneOf<NonNullable<NativeVaultState["error"]>>(o.error, VAULT_ERRORS);
    if (o.message !== undefined) s.message = str(o.message, 512);
    return s;
  });

export const parseLocked = (v: unknown): { locked: boolean } | null => guard(() => ({ locked: bool(obj(v).locked) }));

export const parseStatus = (v: unknown): PopupStatus | null =>
  guard(() => {
    const o = obj(v);
    const s: PopupStatus = { locked: bool(o.locked), account: str(o.account, 320), vaults: num(o.vaults) };
    if (o.connected === true) s.connected = true;
    return s;
  });

export const parsePaired = (v: unknown): { paired: boolean } | null => guard(() => ({ paired: bool(obj(v).paired) }));

export const parseSas = (v: unknown): { sas: string } | null =>
  guard(() => {
    const sas = str(obj(v).sas, 16);
    if (!/^\d{3} \d{3}$/.test(sas)) throw new Bad();
    return { sas };
  });

export const parseItems = (v: unknown): { items: Summary[] } | null => guard(() => ({ items: list(obj(v).items, summary) }));

const LINE_INTENTS = ["login", "signup", "reset", "otp", "checkout", "address"];

function planLine(v: unknown): PopupPlanLine {
  const o = obj(v);
  const steps = num(o.steps);
  if (!Number.isInteger(steps) || steps < 1 || steps > 9) throw new Bad();
  return {
    intent: oneOf<PopupPlanLine["intent"]>(o.intent, LINE_INTENTS),
    label: str(o.label, 320),
    steps,
    mode: oneOf<PopupPlanLine["mode"]>(o.mode, ["chain", "fill"]),
  };
}

export const parseSuggestions = (v: unknown): PopupSuggestions | null =>
  guard(() => {
    const o = obj(v);
    const s: PopupSuggestions = { domain: o.domain === null ? null : str(o.domain, 253), items: list(o.items, summary) };
    if (o.plan !== undefined) s.plan = planLine(o.plan);
    return s;
  });

export const parseForgotSite = (v: unknown): { domain: string; items: number } | null =>
  guard(() => {
    const o = obj(v);
    return { domain: str(o.domain, 253), items: num(o.items) };
  });

export const parseItem = (v: unknown): PopupItem | null =>
  guard(() => {
    const o = obj(v);
    const it: PopupItem = { summary: summary(o.summary) };
    if (o.website !== undefined) it.website = origin(o.website);
    return it;
  });

export const parseValue = (v: unknown): { value: string } | null => guard(() => ({ value: str(obj(v).value, 4096) }));

export const parseTotp = (v: unknown): { code: string; remaining: number } | null =>
  guard(() => {
    const o = obj(v);
    const code = str(o.code, 16);
    if (!/^\d{4,10}$/.test(code)) throw new Bad();
    return { code, remaining: num(o.remaining) };
  });

export const parseFilled = (v: unknown): { domain: string } | null => guard(() => ({ domain: str(obj(v).domain, 253) }));

const GEN_KINDS = ["smart", "random", "memorable", "pin"];

export const parseGenerated = (v: unknown): { password: string; entropy_bits: number } | null =>
  guard(() => {
    const o = obj(v);
    return { password: str(o.password, 4096), entropy_bits: num(o.entropy_bits) };
  });

export const parseHistory = (v: unknown): { entries: GeneratorEntry[] } | null =>
  guard(() => ({
    entries: list(obj(v).entries, (e) => {
      const o = obj(e);
      return { password: str(o.password, 4096), kind: oneOf<GeneratorKind>(o.kind, GEN_KINDS), at: num(o.at) };
    }, 20),
  }));

const TEXT_ALIGNS = ["left", "right", "center"];
/** Longest password the router takes (router.ts MAX_PASSWORD). */
const MAX_PASSWORD = 4096;
/** Largest metric the worker accepts for a field (router.ts MAX_METRIC). */
const MAX_METRIC = 100_000;
const metric = (v: unknown, min = 0) => {
  const n = num(v);
  if (n < min || n > MAX_METRIC) throw new Bad();
  return n;
};

function previewOf(o: Obj): SuggestionPreview {
  const strength = num(o.strength);
  if (!Number.isInteger(strength) || strength < 0 || strength > 4) throw new Bad();
  // The router's password bounds (1 to MAX_PASSWORD), and the length is its character count.
  const password = str(o.password, MAX_PASSWORD);
  const length = num(o.length);
  if (!Number.isInteger(length) || length < 1 || length > MAX_PASSWORD || length !== [...password].length) throw new Bad();
  return { password, strength: strength as SuggestionPreview["strength"], length };
}

/**
 * The menu's `menu_preview`, `menu_regenerate` and `menu_profile` reply: the preview and the stored
 * custom profile (an integer length within the custom bounds, a boolean).
 */
export const parseMenuPreview = (v: unknown): MenuPreview | null =>
  guard(() => {
    const o = obj(v);
    const p = obj(o.profile);
    const length = num(p.length);
    if (!Number.isInteger(length) || length < CUSTOM_MIN_LENGTH || length > CUSTOM_MAX_LENGTH) throw new Bad();
    return { ...previewOf(o), profile: { length, symbols: bool(p.symbols) } };
  });

/** The ghost page's `ghost_init` reply: the held password, its strength and the field's metrics. */
export const parseGhostInit = (v: unknown): (SuggestionPreview & { metrics: GhostMetrics }) | null =>
  guard(() => {
    const o = obj(v);
    const m = obj(o.metrics);
    const b = obj(m.box);
    return {
      ...previewOf(o),
      metrics: {
        fontSize: metric(m.fontSize),
        lineHeight: metric(m.lineHeight),
        paddingLeft: metric(m.paddingLeft),
        paddingRight: metric(m.paddingRight),
        textAlign: oneOf<GhostMetrics["textAlign"]>(m.textAlign, TEXT_ALIGNS),
        fontFamily: m.fontFamily === null ? null : str(m.fontFamily, 256),
        box: { x: metric(b.x, -MAX_METRIC), y: metric(b.y, -MAX_METRIC), width: metric(b.width), height: metric(b.height) },
      },
    };
  });
