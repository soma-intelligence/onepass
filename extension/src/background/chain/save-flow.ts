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
// Pending save (spec 7): right after a generated password went into a signup
// or reset form, `savePending` writes it to the vault as a Login tagged
// `onepass:pending` (and `onepass:weak-by-site` when the site imposed a weak
// one), so a lock or a closed tab loses nothing. Per tab, only the item id,
// site and username are kept here, in memory: never the password. A new
// generation on the same tab and site replaces the item's password
// (`update_password`, the old one goes to its history). The submission of
// that password confirms the item (`confirm_pending`) instead of opening the
// save prompt; when nothing was saved or the host refuses, the prompt stays.
//
// Also here: the per item auto-submit preference of the chain (R-12), in
// `storage.local` key `autoSubmit:<itemId>`, true unless set to false.
import { parseOrigin, sameSite } from "../../shared/domain";
import type { CsToBg } from "../../shared/messages";
import type { StorageArea } from "../ext";
import type { CsContext } from "../frames";
import type { NeverSave } from "../never-save";
import { type SavePending, type SavePrompts, titleFromSite } from "../save";
import { BgError, type Session } from "../session";

export const SUBMIT_TTL_MS = 2 * 60 * 1000;
export const CHECK_DELAY_MS = 1500;
/** A generated password feeds the proposal of a submission this recent. */
export const GENERATED_TTL_MS = 10 * 60 * 1000;

/** Tag of a Login saved before its form was sent (onepass_core::model::PENDING_TAG). */
export const PENDING_TAG = "onepass:pending";
/** Tag of a Login whose password the site forced to be weak (onepass_core::model::WEAK_BY_SITE_TAG). */
export const WEAK_BY_SITE_TAG = "onepass:weak-by-site";

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

/** A pending Login saved for a tab: no password. */
interface Saved {
  site: string;
  itemId: string;
  username: string;
}

export interface PendingOptions {
  /** The identifier known at fill time; empty when none. */
  username?: string;
  /** The site's rules forced a weak password (report `weak_by_site`). */
  weak?: boolean;
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
  private readonly saved = new Map<number, Saved>();
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

  /**
   * Save `password`, just generated and filled in `tabId`, as a pending
   * Login of the site of `origin`; a pending item of this tab and site gets
   * the new password instead. True once the vault holds it. Never throws: a
   * locked vault or a refusal leaves the save prompt as the fallback.
   */
  async savePending(tabId: number, origin: string, password: string, opts: PendingOptions = {}): Promise<boolean> {
    const page = parseOrigin(origin);
    if (page?.https !== true || password === "") return false;
    const prev = this.saved.get(tabId);
    if (prev && prev.site === page.site) {
      try {
        await this.deps.session.request({ op: "update_password", ctx: "save_prompt", item_id: prev.itemId, origin, password });
        return true;
      } catch (e) {
        // Locked: the item is still there, try again on the next generation.
        if (e instanceof BgError && e.code === "locked") return false;
        // Gone or edited elsewhere: a new pending item.
        if (this.saved.get(tabId) === prev) this.saved.delete(tabId);
      }
    }
    const username = opts.username?.trim() ?? "";
    try {
      const { vaults } = await this.deps.session.request({ op: "vaults" });
      const vault = vaults[0];
      if (!vault) return false;
      const saved = await this.deps.session.request({
        op: "save_login",
        ctx: "save_prompt",
        origin,
        title: titleFromSite(page.site),
        username,
        password,
        vault_id: vault.id,
        rule: "domain",
        tags: opts.weak === true ? [PENDING_TAG, WEAK_BY_SITE_TAG] : [PENDING_TAG],
      });
      this.saved.set(tabId, { site: page.site, itemId: saved.item_id, username });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * The pending item of `tabId` for the site of `origin` was sent: drop its
   * tag, complete its username. `itemId`, when given, must be that item.
   * False when there is none or the host refused (the prompt then applies).
   */
  private async confirm(tabId: number, origin: string, username: string, itemId?: string): Promise<boolean> {
    const s = this.saved.get(tabId);
    if (!s || s.site !== parseOrigin(origin)?.site || (itemId !== undefined && itemId !== s.itemId)) return false;
    try {
      await this.deps.session.request({
        op: "confirm_pending",
        ctx: "save_prompt",
        item_id: s.itemId,
        origin,
        username: username.trim() !== "" ? username : s.username,
      });
    } catch {
      return false;
    }
    if (this.saved.get(tabId) === s) this.saved.delete(tabId);
    return true;
  }

  /**
   * The vault locked: forget every generated password still waiting for a
   * submission. Pending items stay known (they hold no secret): once
   * unlocked, the host recognizes their password at the submission.
   */
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
    // The password OnePass generated and already saved: confirmed, no prompt.
    if (generated && (await this.confirm(cs.tabId, cs.origin, m.username))) {
      this.drop(cs.tabId);
      return;
    }
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

  /**
   * The top frame of `tabId` committed a new document (at `url`): wait for
   * it to load. Another site: the tab's pending item is no longer followed.
   */
  onNavigation(tabId: number, url?: string): void {
    const s = this.saved.get(tabId);
    if (s && url !== undefined && parseOrigin(url)?.site !== s.site) this.saved.delete(tabId);
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
    this.saved.delete(tabId);
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
    // The pending item's own password (the generated one, forgotten here by a
    // lock): the host found it, the submission confirms it.
    if (r.status === "same") {
      if (r.item_id !== undefined) await this.confirm(tabId, origin, username, r.item_id);
      return;
    }
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
