// Inline menu tokens (spec 8.3). The content script never receives the
// list of items: it asks for a menu for (tab, frame, field) and gets
// `menu.html#<token>`. The token is bound to the tab, frame, document and
// origin reported by the browser for that content script; the menu frame
// presents it to obtain summaries and trigger a fill.
//
// Records hold no secret. They live in memory and in `storage.session` (the
// service worker may be restarted between `open_menu` and the pick), and die
// after 10 minutes, on a navigation of their frame, on tab removal, and when
// a new menu opens in the same frame.
import type { Summary } from "../bridge/client";
import type { FieldRole, FillIntent, FormKind, MenuKey, ProviderId } from "../shared/messages";
import { newToken } from "../shared/tokens";
import type { BgExt, StorageArea } from "./ext";
import type { CsContext, UiContext } from "./frames";

export const MENU_TTL_MS = 10 * 60 * 1000;
const PREFIX = "menu:";
const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/;

export interface MenuField {
  formRef: string;
  fieldRef: string;
  /** Page-influenced hint: picks which list is shown, never a policy input. */
  formKind: FormKind;
  /** Opened after a fill plan that could not choose: its alternatives, best first (from the bridge). */
  first?: string[];
  /** That plan's main form roles and intent: a pick is noted for the site memory (notes.ts). */
  planned?: { roles: FieldRole[]; intent: FillIntent };
}

export interface MenuRecord extends MenuField {
  tabId: number;
  frameId: number;
  origin: string;
  documentId?: string;
  createdAt: number;
  /** Items shown by `menu_init`, with their kind as reported by the host. */
  offered?: Record<string, Summary["kind"]>;
  /** Provider methods shown per item ("Continuer avec ..."). */
  methods?: Record<string, ProviderId[]>;
  /** Provider accounts shown per provider (inline picker); a picked one must be among them. */
  accounts?: Record<string, string[]>;
}

export class MenuTokens {
  private readonly mem = new Map<string, MenuRecord>();

  constructor(
    private readonly area: StorageArea,
    private readonly now: () => number = Date.now,
  ) {}

  /** Wire invalidation to browser events (call once, at top level). */
  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      // A new top document takes every child frame with it.
      void (d.frameId === 0 ? this.revokeTab(d.tabId) : this.revokeFrame(d.tabId, d.frameId));
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.revokeTab(tabId));
  }

  async register(cs: CsContext, field: MenuField): Promise<string> {
    // One live menu per frame: a page cannot pile up tokens.
    await this.revokeFrame(cs.tabId, cs.frameId);
    const token = newToken();
    const rec: MenuRecord = {
      tabId: cs.tabId,
      frameId: cs.frameId,
      origin: cs.origin,
      formRef: field.formRef,
      fieldRef: field.fieldRef,
      formKind: field.formKind,
      createdAt: this.now(),
    };
    if (field.first) rec.first = [...field.first];
    if (field.planned) rec.planned = { roles: [...field.planned.roles], intent: field.planned.intent };
    if (cs.documentId !== undefined) rec.documentId = cs.documentId;
    this.mem.set(token, rec);
    await this.area.set({ [PREFIX + token]: rec });
    return token;
  }

  /**
   * The record of `token` if the caller is our extension page in the same
   * tab and the token is still live; null otherwise.
   */
  async resolve(token: string, ui: UiContext): Promise<MenuRecord | null> {
    if (!TOKEN_RE.test(token)) return null;
    const rec = await this.load(token);
    if (!rec) return null;
    if (this.now() - rec.createdAt > MENU_TTL_MS || this.now() < rec.createdAt) {
      await this.drop([token]);
      return null;
    }
    if (ui.tabId === undefined || ui.tabId !== rec.tabId) return null;
    return rec;
  }

  /** Remember what the menu showed (the pick must be one of these). */
  async setOffered(
    token: string,
    offered: Record<string, Summary["kind"]>,
    methods: Record<string, ProviderId[]> = {},
    accounts: Record<string, string[]> = {},
  ): Promise<void> {
    const rec = await this.load(token);
    if (!rec) return;
    rec.offered = offered;
    rec.methods = methods;
    rec.accounts = accounts;
    this.mem.set(token, rec);
    await this.area.set({ [PREFIX + token]: rec });
  }

  /** The live menu token of a frame (one per frame), for keys relayed by its content script. */
  async forFrame(tabId: number, frameId: number, documentId?: string): Promise<string | null> {
    for (const [t, r] of await this.all()) {
      if (r.tabId !== tabId || r.frameId !== frameId) continue;
      if (documentId !== undefined && r.documentId !== undefined && r.documentId !== documentId) continue;
      if (this.now() - r.createdAt > MENU_TTL_MS || this.now() < r.createdAt) continue;
      return t;
    }
    return null;
  }

  /** A live menu token exists in this tab (the overlay is not offered over it). */
  async hasTab(tabId: number): Promise<boolean> {
    for (const [, r] of await this.all()) {
      if (r.tabId === tabId && this.now() - r.createdAt <= MENU_TTL_MS && this.now() >= r.createdAt) return true;
    }
    return false;
  }

  private async all(): Promise<[string, MenuRecord][]> {
    const out = new Map<string, MenuRecord>(this.mem);
    for (const [k, v] of Object.entries(await this.area.get(null))) {
      if (!k.startsWith(PREFIX)) continue;
      const t = k.slice(PREFIX.length);
      const r = out.has(t) ? null : parseRecord(v);
      if (r) out.set(t, r);
    }
    return [...out];
  }

  revokeFrame(tabId: number, frameId: number): Promise<void> {
    return this.revokeWhere((r) => r.tabId === tabId && r.frameId === frameId);
  }

  revokeTab(tabId: number): Promise<void> {
    return this.revokeWhere((r) => r.tabId === tabId);
  }

  private async load(token: string): Promise<MenuRecord | null> {
    const m = this.mem.get(token);
    if (m) return m;
    const raw = (await this.area.get(PREFIX + token))[PREFIX + token];
    const rec = parseRecord(raw);
    if (rec) this.mem.set(token, rec);
    return rec;
  }

  private async revokeWhere(pred: (r: MenuRecord) => boolean): Promise<void> {
    const doomed = new Set<string>();
    for (const [t, r] of this.mem) if (pred(r)) doomed.add(t);
    // Records written by a previous service worker instance.
    const all = await this.area.get(null);
    for (const [k, v] of Object.entries(all)) {
      if (!k.startsWith(PREFIX)) continue;
      const r = parseRecord(v);
      if (!r || pred(r)) doomed.add(k.slice(PREFIX.length));
    }
    await this.drop([...doomed]);
  }

  private async drop(tokens: string[]): Promise<void> {
    if (tokens.length === 0) return;
    for (const t of tokens) this.mem.delete(t);
    await this.area.remove(tokens.map((t) => PREFIX + t));
  }
}

function parseRecord(raw: unknown): MenuRecord | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const int = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!int(r.tabId) || !int(r.frameId) || !int(r.createdAt)) return null;
  for (const k of ["origin", "formRef", "fieldRef", "formKind"]) if (typeof r[k] !== "string") return null;
  if (r.documentId !== undefined && typeof r.documentId !== "string") return null;
  if (r.first !== undefined && !(Array.isArray(r.first) && r.first.length <= 8 && r.first.every((x) => typeof x === "string"))) return null;
  if (r.planned !== undefined) {
    const p = r.planned as Record<string, unknown> | null;
    if (typeof p !== "object" || p === null || typeof p.intent !== "string" || !Array.isArray(p.roles) || !p.roles.every((x) => typeof x === "string")) return null;
  }
  return r as unknown as MenuRecord;
}

/** A `menu_keys` request is answered empty after this long without a key. */
export const KEY_WAIT_MS = 20_000;
/** Keys kept for a menu that is not asking right now. */
const MAX_QUEUED = 8;

/**
 * Keys relayed from a field to the menu under it (spec 8.3, keyboard): the
 * content script reports trusted keys (`menu_key`), the menu page asks for
 * them (`menu_keys`, answered when one arrives). Keyed by menu token; no
 * secret, memory only (a lost key after a worker restart is harmless).
 */
export class KeyRelay {
  private readonly waiting = new Map<string, (keys: MenuKey[]) => void>();
  private readonly queued = new Map<string, MenuKey[]>();

  constructor(
    private readonly timers: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void } = {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
    },
    private readonly waitMs = KEY_WAIT_MS,
  ) {}

  push(token: string, key: MenuKey): void {
    const w = this.waiting.get(token);
    if (w) {
      this.waiting.delete(token);
      w([key]);
      return;
    }
    const q = this.queued.get(token) ?? [];
    if (q.length < MAX_QUEUED) q.push(key);
    this.queued.set(token, q);
  }

  wait(token: string): Promise<MenuKey[]> {
    const q = this.queued.get(token);
    if (q && q.length > 0) {
      this.queued.delete(token);
      return Promise.resolve(q);
    }
    // One request per menu: an older one gets an empty answer.
    this.waiting.get(token)?.([]);
    return new Promise((resolve) => {
      const done = (keys: MenuKey[]) => {
        this.timers.clearTimeout(timer);
        if (this.waiting.get(token) === done) this.waiting.delete(token);
        resolve(keys);
      };
      const timer = this.timers.setTimeout(() => done([]), this.waitMs);
      this.waiting.set(token, done);
    });
  }

  drop(token: string): void {
    this.queued.delete(token);
    this.waiting.get(token)?.([]);
    this.waiting.delete(token);
  }
}
