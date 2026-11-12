// Tokens of the top-frame extension pages (overlay, save prompt), bound like
// menu tokens (menu.ts) to the tab, frame, document and origin reported by
// the browser. One live token per tab and kind. A token dies after its TTL,
// on any navigation of the top frame, and on tab removal.
//
// Records are kept in memory and, when `area` is given, mirrored in
// `storage.session` to survive a service worker restart. A record that holds
// a secret (the save prompt's password) is given no area: memory only.
import { newToken } from "../shared/tokens";
import type { BgExt, StorageArea } from "./ext";
import type { UiContext } from "./frames";

const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/;

export interface BoundRecord {
  tabId: number;
  frameId: number;
  origin: string;
  documentId?: string;
  createdAt: number;
}

export interface FrameTokenOptions<R extends BoundRecord> {
  prefix: string;
  /** Lifetime of a record: one value, or one per record (a folded save card lives longer). */
  ttlMs: number | ((rec: R) => number);
  now?: () => number;
  /** Mirror for worker restarts; omit for records holding secrets. */
  area?: StorageArea;
  /** Rebuilds a record read back from `area`, or null when malformed. */
  parse?: (raw: unknown) => R | null;
  /**
   * Revoke each record by timer at its TTL, not only when it is next
   * resolved, and run this first (wipe a secret it holds).
   */
  onExpire?: (rec: R) => void | Promise<void>;
  /** Runs when a live record is dropped (decision, close, navigation, tab removal). */
  onDrop?: (rec: R) => void;
  /**
   * A top-frame navigation of the record's tab: true keeps the record (it is then given back to
   * `onKept` once the new document has loaded), false drops it as usual.
   */
  keepOnNavigate?: (rec: R, url: string) => boolean;
  /** A record kept through a navigation: the new top document finished loading. */
  onKept?: (token: string, rec: R) => void | Promise<void>;
}

/** Common checks of a stored bound record. */
export function isBoundRecord(raw: unknown): raw is BoundRecord {
  if (typeof raw !== "object" || raw === null) return false;
  const r = raw as Record<string, unknown>;
  const int = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!int(r.tabId) || !int(r.frameId) || !int(r.createdAt)) return false;
  if (typeof r.origin !== "string") return false;
  return r.documentId === undefined || typeof r.documentId === "string";
}

export class FrameTokens<R extends BoundRecord> {
  private readonly mem = new Map<string, R>();
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  /** Kept through a navigation, waiting for the new document to load. */
  private readonly awaitingLoad = new Set<string>();
  private readonly now: () => number;

  constructor(private readonly opts: FrameTokenOptions<R>) {
    this.now = opts.now ?? Date.now;
  }

  private ttl(rec: R): number {
    return typeof this.opts.ttlMs === "function" ? this.opts.ttlMs(rec) : this.opts.ttlMs;
  }

  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId === 0) void this.navigated(d.tabId, d.url);
    });
    ext.webNavigation.onCompleted.addListener((d) => {
      if (d.frameId === 0) void this.loaded(d.tabId);
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.revokeTab(tabId));
  }

  async register(rec: Omit<R, "createdAt">): Promise<string> {
    await this.revokeTab(rec.tabId);
    const token = newToken();
    const full = { ...rec, createdAt: this.now() } as R;
    this.mem.set(token, full);
    await this.opts.area?.set({ [this.opts.prefix + token]: full });
    this.armExpiry(token, full);
    return token;
  }

  private armExpiry(token: string, rec: R): void {
    const onExpire = this.opts.onExpire;
    const old = this.timers.get(token);
    if (old !== undefined) clearTimeout(old);
    this.timers.delete(token);
    if (!onExpire) return;
    this.timers.set(
      token,
      setTimeout(() => {
        this.timers.delete(token);
        const live = this.mem.get(token);
        void (async () => {
          if (live) await onExpire(live);
          await this.drop(token);
        })().catch(() => undefined);
      }, this.ttl(rec)),
    );
  }

  /**
   * The record's lifetime starts again from now, with the TTL its current state gives it (a save
   * card that folds into a pill, or unfolds again).
   */
  async rearm(token: string, rec: R): Promise<void> {
    if (!this.mem.has(token)) return;
    rec.createdAt = this.now();
    this.mem.set(token, rec);
    await this.opts.area?.set({ [this.opts.prefix + token]: rec });
    this.armExpiry(token, rec);
  }

  /** The live record of `token` if `ui` is one of our pages in the same tab. */
  async resolve(token: string, ui: UiContext): Promise<R | null> {
    if (!TOKEN_RE.test(token)) return null;
    const rec = await this.load(token);
    if (!rec) return null;
    const age = this.now() - rec.createdAt;
    if (age > this.ttl(rec) || age < 0) {
      await this.drop(token);
      return null;
    }
    if (ui.tabId === undefined || ui.tabId !== rec.tabId) return null;
    return rec;
  }

  /** Persist a change made to a resolved record. */
  async update(token: string, rec: R): Promise<void> {
    if (!this.mem.has(token)) return;
    this.mem.set(token, rec);
    await this.opts.area?.set({ [this.opts.prefix + token]: rec });
  }

  async drop(token: string): Promise<void> {
    const t = this.timers.get(token);
    if (t !== undefined) clearTimeout(t);
    this.timers.delete(token);
    const rec = this.mem.get(token);
    this.mem.delete(token);
    this.awaitingLoad.delete(token);
    if (rec) this.opts.onDrop?.(rec);
    await this.opts.area?.remove(this.opts.prefix + token);
  }

  /** The live token of `tabId` and its record, if any (one per tab and kind). */
  async forTab(tabId: number): Promise<{ token: string; rec: R } | null> {
    const live = (r: BoundRecord) => r.tabId === tabId && this.now() - r.createdAt <= this.ttl(r as R) && this.now() >= r.createdAt;
    for (const [token, r] of this.mem) if (live(r)) return { token, rec: r };
    const area = this.opts.area;
    if (!area) return null;
    for (const k of Object.keys(await area.get(null))) {
      if (!k.startsWith(this.opts.prefix)) continue;
      const token = k.slice(this.opts.prefix.length);
      const rec = await this.load(token);
      if (rec && live(rec)) return { token, rec };
    }
    return null;
  }

  /** A live (unexpired) token of `tabId` exists. */
  async hasTab(tabId: number): Promise<boolean> {
    const live = (r: BoundRecord) => r.tabId === tabId && this.now() - r.createdAt <= this.ttl(r as R) && this.now() >= r.createdAt;
    for (const r of this.mem.values()) if (live(r)) return true;
    const area = this.opts.area;
    if (!area) return false;
    for (const [k, v] of Object.entries(await area.get(null))) {
      if (k.startsWith(this.opts.prefix) && isBoundRecord(v) && live(v)) return true;
    }
    return false;
  }

  /** A top-frame navigation of `tabId` to `url`: records that opt in stay, the rest go. */
  private async navigated(tabId: number, url: string): Promise<void> {
    const keep = new Set<string>();
    const decide = this.opts.keepOnNavigate;
    if (decide) {
      for (const [t, r] of this.mem) if (r.tabId === tabId && decide(r, url)) keep.add(t);
    }
    for (const t of keep) this.awaitingLoad.add(t);
    await this.revokeTab(tabId, keep);
  }

  /** The new top document of `tabId` loaded: the records kept through the navigation show again. */
  private async loaded(tabId: number): Promise<void> {
    for (const t of [...this.awaitingLoad]) {
      const rec = this.mem.get(t);
      if (!rec) {
        this.awaitingLoad.delete(t);
        continue;
      }
      if (rec.tabId !== tabId) continue;
      this.awaitingLoad.delete(t);
      await this.opts.onKept?.(t, rec);
    }
  }

  async revokeTab(tabId: number, except: ReadonlySet<string> = new Set()): Promise<void> {
    const doomed = new Set<string>();
    for (const [t, r] of this.mem) if (r.tabId === tabId && !except.has(t)) doomed.add(t);
    const area = this.opts.area;
    if (area) {
      for (const [k, v] of Object.entries(await area.get(null))) {
        if (!k.startsWith(this.opts.prefix)) continue;
        const t = k.slice(this.opts.prefix.length);
        if (except.has(t)) continue;
        if (!isBoundRecord(v) || v.tabId === tabId) doomed.add(t);
      }
    }
    for (const t of doomed) await this.drop(t);
  }

  private async load(token: string): Promise<R | null> {
    const m = this.mem.get(token);
    if (m) return m;
    const area = this.opts.area;
    if (!area || !this.opts.parse) return null;
    const raw = (await area.get(this.opts.prefix + token))[this.opts.prefix + token];
    const rec = isBoundRecord(raw) ? this.opts.parse(raw) : null;
    if (rec) this.mem.set(token, rec);
    return rec;
  }
}
