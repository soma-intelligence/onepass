// When to propose saving a login (spec 8.5, 8.8): submitted credentials are
// kept in memory (never in a storage area) for at most 2 minutes, with the
// origin given by `sender`. After the top frame navigated and finished
// loading, or 1.5 s without navigation, the host is asked `check_credentials`;
// `new` or `update` opens the save prompt (save.ts) in the top frame, unless
// the site is in the "Ne jamais proposer" list.
//
// A submission without an identifier is not proposed (the password step of a
// multi-step sign-in would always look `new`), except when its password is
// one OnePass just generated and filled in this tab (spec 8.8): a signup or
// change-password form often has no identifier field.
//
// Also here: the per item auto-submit preference of the chain (R-12), in
// `storage.local` key `autoSubmit:<itemId>`, true unless set to false.
import { parseOrigin, sameSite } from "../../shared/domain";
import type { CsToBg } from "../../shared/messages";
import type { StorageArea } from "../ext";
import type { CsContext } from "../frames";
import type { NeverSave } from "../never-save";
import type { SavePending, SavePrompts } from "../save";
import type { Session } from "../session";

export const SUBMIT_TTL_MS = 2 * 60 * 1000;
export const CHECK_DELAY_MS = 1500;
/** A generated password feeds the proposal of a submission this recent. */
export const GENERATED_TTL_MS = 10 * 60 * 1000;

const AUTO_SUBMIT_PREFIX = "autoSubmit:";

export async function autoSubmitFor(area: StorageArea, itemId: string): Promise<boolean> {
  const k = AUTO_SUBMIT_PREFIX + itemId;
  return (await area.get(k))[k] !== false;
}

export async function setAutoSubmit(area: StorageArea, itemId: string, on: boolean): Promise<void> {
  if (on) await area.remove(AUTO_SUBMIT_PREFIX + itemId);
  else await area.set({ [AUTO_SUBMIT_PREFIX + itemId]: false });
}

export interface Timers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
}

const realTimers: Timers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
};

interface Pending {
  origin: string;
  username: string;
  password: string;
  at: number;
  navigated: boolean;
  check: unknown;
  expire: unknown;
}

interface Generated {
  site: string;
  password: string;
  at: number;
}

export interface SaveFlowDeps {
  session: Pick<Session, "request">;
  saves: Pick<SavePrompts, "open">;
  neverSave: Pick<NeverSave, "has">;
  /**
   * The top frame of a tab as the browser reports it now
   * (`webNavigation.getFrame`): its URL, and its document where supported.
   */
  topFrame: (tabId: number) => Promise<{ url: string; documentId?: string } | null>;
  /** A sign-in chain runs in this tab: its submissions are not proposed. */
  chainRunning?: (tabId: number) => Promise<boolean>;
  now?: () => number;
  timers?: Timers;
}

export class SaveFlow {
  private readonly pending = new Map<number, Pending>();
  private readonly generated = new Map<number, Generated>();
  private readonly now: () => number;
  private readonly timers: Timers;

  constructor(private readonly deps: SaveFlowDeps) {
    this.now = deps.now ?? Date.now;
    this.timers = deps.timers ?? realTimers;
  }

  /** A password OnePass generated and filled in `tabId` (menu or popup). */
  rememberGenerated(tabId: number, origin: string, password: string): void {
    const site = parseOrigin(origin)?.site;
    if (!site || password === "") return;
    const prev = this.generated.get(tabId);
    if (prev) prev.password = "";
    this.generated.set(tabId, { site, password, at: this.now() });
  }

  /** The vault locked: forget every generated password still waiting for a submission. */
  clearGenerated(): void {
    for (const g of this.generated.values()) g.password = "";
    this.generated.clear();
  }

  private takeGenerated(tabId: number, origin: string, password: string): boolean {
    const g = this.generated.get(tabId);
    if (!g) return false;
    const fresh = this.now() - g.at <= GENERATED_TTL_MS;
    const match = fresh && g.site === parseOrigin(origin)?.site && g.password === password;
    if (match || !fresh) {
      g.password = "";
      this.generated.delete(tabId);
    }
    return match;
  }

  async onSubmitted(m: Extract<CsToBg, { type: "submitted_credentials" }>, cs: CsContext): Promise<void> {
    if (parseOrigin(cs.origin)?.https !== true) return;
    const generated = this.takeGenerated(cs.tabId, cs.origin, m.password);
    if (m.username.trim() === "" && !generated) return;
    if (await this.deps.chainRunning?.(cs.tabId)) return;
    this.drop(cs.tabId);
    const p: Pending = {
      origin: cs.origin,
      username: m.username,
      password: m.password,
      at: this.now(),
      navigated: false,
      check: null,
      expire: null,
    };
    p.check = this.timers.setTimeout(() => void this.check(cs.tabId), CHECK_DELAY_MS);
    // Spec 8.5: kept at most 2 minutes.
    p.expire = this.timers.setTimeout(() => this.drop(cs.tabId), SUBMIT_TTL_MS);
    this.pending.set(cs.tabId, p);
  }

  /** The top frame of `tabId` committed a new document: wait for it to load. */
  onNavigation(tabId: number): void {
    const p = this.pending.get(tabId);
    if (!p || p.navigated) return;
    p.navigated = true;
    this.timers.clearTimeout(p.check);
    p.check = null;
  }

  /** The new top document is loaded (its content script can show the prompt). */
  async onReady(tabId: number): Promise<void> {
    const p = this.pending.get(tabId);
    if (p?.navigated) await this.check(tabId);
  }

  onTabRemoved(tabId: number): void {
    this.drop(tabId);
    this.generated.delete(tabId);
  }

  private drop(tabId: number): void {
    const p = this.pending.get(tabId);
    if (!p) return;
    this.timers.clearTimeout(p.check);
    this.timers.clearTimeout(p.expire);
    p.password = "";
    this.pending.delete(tabId);
  }

  /** Ask the host, then prompt. One check per submission. */
  async check(tabId: number): Promise<void> {
    const p = this.pending.get(tabId);
    if (!p) return;
    const { origin, username, password, at } = p;
    this.drop(tabId);
    if (this.now() - at > SUBMIT_TTL_MS) return;
    const site = parseOrigin(origin)?.site;
    if (!site || (await this.deps.neverSave.has(site))) return;
    // The prompt goes to the top frame: it must show this site (checked
    // again below, after the host answered).
    if (!(await this.verifiedTop(tabId, origin))) return;
    let r: { status: "new" | "same" | "update"; item_id?: string; title?: string };
    try {
      r = await this.deps.session.request({ op: "check_credentials", ctx: "save_prompt", origin, username, password });
    } catch {
      return;
    }
    if (r.status === "same") return;
    // The top frame may have moved during the host request (or before the
    // submission was even registered): read it again and pin the prompt to
    // that very document, of this site.
    const top = await this.verifiedTop(tabId, origin);
    if (!top) return;
    const pending: SavePending = { tabId, origin, kind: "login", status: r.status, username, password, topOrigin: top.origin };
    if (top.documentId !== undefined) pending.documentId = top.documentId;
    if (r.status === "update" && r.item_id !== undefined) pending.update = { itemId: r.item_id, title: r.title ?? "" };
    try {
      await this.deps.saves.open(pending);
    } catch {
      // Content script gone (tab closed, navigated again): nothing to show.
    }
  }

  /**
   * The current top document of `tabId` if it is HTTPS and of the same
   * registrable domain as `origin`: its origin and, where the browser
   * reports it, its documentId (the prompt is delivered to exactly it).
   */
  private async verifiedTop(tabId: number, origin: string): Promise<{ origin: string; documentId?: string } | null> {
    let f: { url: string; documentId?: string } | null;
    try {
      f = await this.deps.topFrame(tabId);
    } catch {
      return null;
    }
    const top = f ? parseOrigin(f.url) : null;
    if (!f || !top?.https || !sameSite(f.url, origin)) return null;
    return f.documentId !== undefined ? { origin: top.origin, documentId: f.documentId } : { origin: top.origin };
  }

  /** Menu "Enregistrer un nouveau login": the edit view, site prefilled, nothing typed. */
  async openNewLogin(tabId: number, origin: string, documentId?: string): Promise<void> {
    const pending: SavePending = { tabId, origin, kind: "login", status: "new", username: "", password: "", view: "edit" };
    if (documentId !== undefined) pending.documentId = documentId;
    await this.deps.saves.open(pending);
  }

  /** For tests: submissions currently held. */
  get size(): number {
    return this.pending.size;
  }
}
