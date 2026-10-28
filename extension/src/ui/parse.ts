// Validation of service worker replies before rendering. A malformed reply
// renders as an internal error, never partially.
import type { FormKind, ProviderId } from "../shared/messages";
import {
  CHAIN_PHASES,
  STEP_WHATS,
  type StepWhat,
  type ChainPhase,
  type ChainStepView,
  type ChainView,
  type GeneratorEntry,
  type GeneratorKind,
  type MenuInit,
  type OverlayAccount,
  type OverlayInit,
  type PopupItem,
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
  };
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
  return a;
}

export const parseOverlayInit = (v: unknown): OverlayInit | null =>
  guard(() => {
    const o = obj(v);
    return { origin: origin(o.origin), accounts: list(o.accounts, account, 64), chain: chain(o.chain) };
  });

export const parseOverlayState = (v: unknown): { chain: ChainView | null } | null =>
  guard(() => ({ chain: chain(obj(v).chain) }));

export const parseSaveInit = (v: unknown): SaveInit | null =>
  guard(() => {
    const o = obj(v);
    const s: SaveInit = {
      origin: origin(o.origin),
      site: str(o.site, 253),
      kind: oneOf(o.kind, ["login", "provider_link"]),
      status: oneOf(o.status, ["new", "update"]),
      title: str(o.title, 256),
      username: str(o.username),
      vaults: list(o.vaults, (x) => {
        const vv = obj(x);
        return { id: str(vv.id, 128), name: str(vv.name, 256) };
      }, 64),
    };
    if (o.update !== undefined) {
      const u = obj(o.update);
      s.update = { itemId: str(u.itemId, 128), title: str(u.title, 256) };
    }
    if (o.provider !== undefined) {
      const p = obj(o.provider);
      s.provider = { id: oneOf<ProviderId>(p.id, PROVIDERS), email: str(p.email, 320) };
      if (p.title !== undefined) s.provider.title = str(p.title, 256);
    }
    if (o.view !== undefined) s.view = oneOf<"edit">(o.view, ["edit"]);
    return s;
  });

export const parsePassword = (v: unknown): { password: string } | null =>
  guard(() => ({ password: str(obj(v).password, 4096) }));

const MENU_KEYS = ["down", "up", "enter"];

export const parseKeys = (v: unknown): { keys: ("down" | "up" | "enter")[] } | null =>
  guard(() => ({ keys: list(obj(v).keys, (k) => oneOf<"down" | "up" | "enter">(k, MENU_KEYS), 8) }));

export const parseEmpty = (v: unknown): object | null => guard(() => obj(v));

export const parseLocked = (v: unknown): { locked: boolean } | null => guard(() => ({ locked: bool(obj(v).locked) }));

export const parseStatus = (v: unknown): PopupStatus | null =>
  guard(() => {
    const o = obj(v);
    return { locked: bool(o.locked), account: str(o.account, 320), vaults: num(o.vaults) };
  });

export const parseSas = (v: unknown): { sas: string } | null =>
  guard(() => {
    const sas = str(obj(v).sas, 16);
    if (!/^\d{3} \d{3}$/.test(sas)) throw new Bad();
    return { sas };
  });

export const parseItems = (v: unknown): { items: Summary[] } | null => guard(() => ({ items: list(obj(v).items, summary) }));

export const parseSuggestions = (v: unknown): PopupSuggestions | null =>
  guard(() => {
    const o = obj(v);
    return { domain: o.domain === null ? null : str(o.domain, 253), items: list(o.items, summary) };
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
