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
  ttlMs: number;
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
  private readonly now: () => number;

  constructor(private readonly opts: FrameTokenOptions<R>) {
    this.now = opts.now ?? Date.now;
  }

  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId === 0) void this.revokeTab(d.tabId);
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.revokeTab(tabId));
  }

  async register(rec: Omit<R, "createdAt">): Promise<string> {
    await this.revokeTab(rec.tabId);
    const token = newToken();
    const full = { ...rec, createdAt: this.now() } as R;
    this.mem.set(token, full);
    await this.opts.area?.set({ [this.opts.prefix + token]: full });
    const onExpire = this.opts.onExpire;
    if (onExpire) {
      this.timers.set(
        token,
        setTimeout(() => {
          this.timers.delete(token);
          const rec = this.mem.get(token);
          void (async () => {
            if (rec) await onExpire(rec);
            await this.drop(token);
          })().catch(() => undefined);
        }, this.opts.ttlMs),
      );
    }
    return token;
  }

  /** The live record of `token` if `ui` is one of our pages in the same tab. */
  async resolve(token: string, ui: UiContext): Promise<R | null> {
    if (!TOKEN_RE.test(token)) return null;
    const rec = await this.load(token);
    if (!rec) return null;
    const age = this.now() - rec.createdAt;
    if (age > this.opts.ttlMs || age < 0) {
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
    if (rec) this.opts.onDrop?.(rec);
    await this.opts.area?.remove(this.opts.prefix + token);
  }

  /** A live (unexpired) token of `tabId` exists. */
  async hasTab(tabId: number): Promise<boolean> {
    const live = (r: BoundRecord) => r.tabId === tabId && this.now() - r.createdAt <= this.opts.ttlMs && this.now() >= r.createdAt;
    for (const r of this.mem.values()) if (live(r)) return true;
    const area = this.opts.area;
    if (!area) return false;
    for (const [k, v] of Object.entries(await area.get(null))) {
      if (k.startsWith(this.opts.prefix) && isBoundRecord(v) && live(v)) return true;
    }
    return false;
  }

  async revokeTab(tabId: number): Promise<void> {
    const doomed = new Set<string>();
    for (const [t, r] of this.mem) if (r.tabId === tabId) doomed.add(t);
    const area = this.opts.area;
    if (area) {
      for (const [k, v] of Object.entries(await area.get(null))) {
        if (!k.startsWith(this.opts.prefix)) continue;
        if (!isBoundRecord(v) || v.tabId === tabId) doomed.add(k.slice(this.opts.prefix.length));
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
