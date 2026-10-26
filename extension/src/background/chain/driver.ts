// Adapter of the chain machine (machine.ts) to the service worker (spec 8.6).
//
// - Input: page analyses of the top frame of the chain's tab (frame 0 only,
//   origin from `sender`), `webNavigation.onCommitted` / `onCompleted` of that
//   frame, and timers (deadline, unknown page, settled done).
// - Output: fills through the single fill path (fill.ts, secrets fetched
//   just in time per step, only the fields the step needs), `click` and
//   `submit` messages pinned to the verified origin, and the overlay.
// - State: `storage.session` key `chain:<tabId>` (no secret), so a restarted
//   worker resumes without submitting a page twice: the machine records each
//   step with the page signature and navigation counter, and the state is
//   written before the step's actions run. Timers are plain `setTimeout`s
//   re-armed from the persisted due times on any event (the overlay polls
//   `state` every 500 ms while a chain runs).
//
// Also here, since it shares the page analysis of the top frame: showing the
// overlay on a recognized sign-in page of a site that has logins (once per
// document), and on every page of a running chain.
import type { Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { BgToCs, PageAnalysis, ProviderId } from "../../shared/messages";
import type { ChainView } from "../../shared/ui";
import type { PageAnalyses } from "../analyses";
import type { BgExt, StorageArea } from "../ext";
import type { FillTarget, Filler } from "../fill";
import type { CsContext, Frames } from "../frames";
import { BgError, type Session, toBgError } from "../session";
import {
  type ChainAction,
  type ChainState,
  chainView,
  navigated,
  nextDue,
  parseChainState,
  settled,
  startChain,
  step,
  stopChain,
  tick,
} from "./machine";
import { autoSubmitFor } from "./save-flow";
import type { ChainDriver } from "./types";

const PREFIX = "chain:";
/** An ended chain stays on the overlay this long (its reason, "Connecté"). */
export const ENDED_VIEW_MS = 2 * 60 * 1000;

export interface OverlayPort {
  open(cs: CsContext): Promise<string>;
  hasTab(tabId: number): Promise<boolean>;
}

export interface ChainDeps {
  ext: Pick<BgExt, "tabs" | "webNavigation">;
  area: StorageArea;
  /** `storage.local`: the auto-submit preference (R-12). */
  local: StorageArea;
  session: Pick<Session, "request">;
  frames: Pick<Frames, "frameOrigin" | "checkFillTarget">;
  filler: Pick<Filler, "fillLogin" | "fillProvider">;
  analyses: Pick<PageAnalyses, "top" | "onAnalysis">;
  overlays: OverlayPort;
  now?: () => number;
  timers?: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void };
}

const SIGN_IN_ROLES = new Set(["username", "email", "current_password"]);

/** A sign-in form the overlay can offer to complete. */
function isSignInPage(a: PageAnalysis): boolean {
  return a.forms.some((f) => f.kind === "login" && f.fields.some((x) => SIGN_IN_ROLES.has(x.role)));
}

function canSignIn(it: Summary): boolean {
  return it.kind === "login" && (it.has_password || it.methods.length > 0);
}

export class ChainRunner implements ChainDriver {
  private readonly mem = new Map<number, ChainState>();
  private readonly queues = new Map<number, Promise<unknown>>();
  private readonly armed = new Map<number, unknown>();
  /** Per tab: the document the overlay was offered on (once per document). */
  private readonly offered = new Map<number, string>();
  /** Per tab: top frame commits, to key documents where `documentId` is absent. */
  private readonly navs = new Map<number, number>();
  private readonly now: () => number;
  private readonly timers: NonNullable<ChainDeps["timers"]>;

  constructor(private readonly deps: ChainDeps) {
    this.now = deps.now ?? Date.now;
    this.timers = deps.timers ?? {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
    };
  }

  /** Register listeners (synchronously, at worker start) and re-arm persisted chains. */
  install(ext: Pick<BgExt, "webNavigation" | "tabs">): void {
    ext.webNavigation.onCommitted.addListener((d) => {
      if (d.frameId !== 0) return;
      this.navs.set(d.tabId, (this.navs.get(d.tabId) ?? 0) + 1);
      void this.serial(d.tabId, () => this.onCommit(d.tabId, d.url));
    });
    ext.webNavigation.onCompleted.addListener((d) => {
      if (d.frameId === 0) void this.serial(d.tabId, () => this.onLoaded(d.tabId));
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.serial(tabId, () => this.forget(tabId)));
    this.deps.analyses.onAnalysis((a, cs) => {
      if (cs.frameId === 0) void this.serial(cs.tabId, () => this.onAnalysis(a, cs));
    });
    void this.rearmAll();
  }

  // ---- ChainDriver ----

  async start(tabId: number, itemId: string, viaProvider?: ProviderId): Promise<void> {
    const origin = await this.deps.frames.frameOrigin(tabId, 0);
    if (!origin || parseOrigin(origin)?.https !== true) throw new BgError("insecure_origin");
    const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "chain", origin });
    const item = items.find((x) => x.item_id === itemId && x.kind === "login");
    if (!item) throw new BgError("not_found");
    let providerAccount: Summary | undefined;
    if (viaProvider) {
      const method = item.methods.find((m) => m.provider === viaProvider);
      if (!method) throw new BgError("invalid");
      const r = await this.deps.session.request({ op: "provider_accounts", ctx: "chain", provider: viaProvider, origin });
      const email = method.account_email.trim().toLowerCase();
      providerAccount =
        r.accounts.find((a) => a.subtitle.trim().toLowerCase() === email) ?? r.accounts.find((a) => a.item_id === r.linked_item_id);
      if (!providerAccount) throw new BgError("not_found");
    } else if (!item.has_password) {
      throw new BgError("invalid");
    }
    const autoSubmit = await autoSubmitFor(this.deps.local, itemId);
    await this.serial(tabId, async () => {
      let s = startChain({
        tabId,
        item,
        siteOrigin: origin,
        ...(viaProvider ? { provider: viaProvider } : {}),
        ...(providerAccount ? { providerAccount } : {}),
        autoSubmit,
        now: this.now(),
      });
      await this.save(s);
      // The page the click came from: act on it now.
      const top = await this.deps.analyses.top(tabId);
      const cs: CsContext = { tabId, frameId: 0, origin };
      if (top && top.origin === origin) {
        if (top.documentId !== undefined) cs.documentId = top.documentId;
        s = await this.advance(s, step(s, top.analysis, origin, this.now()), cs);
      }
      await this.showOverlay(cs);
      this.arm(s);
    });
  }

  async stop(tabId: number): Promise<void> {
    await this.serial(tabId, async () => {
      const s = await this.load(tabId);
      if (!s) return;
      const n = stopChain(s, "user", this.now());
      if (n !== s) await this.save(n);
      this.disarm(tabId);
    });
  }

  async state(tabId: number): Promise<ChainView | null> {
    return this.serial(tabId, async () => {
      let s = await this.load(tabId);
      if (!s) return null;
      s = await this.onTick(s);
      if (s.status !== "running" && s.endedAt !== undefined && this.now() - s.endedAt > ENDED_VIEW_MS) return null;
      return chainView(s);
    });
  }

  /** A chain is running in this tab (the save and link proposals stay quiet). */
  async isRunning(tabId: number): Promise<boolean> {
    return (await this.load(tabId))?.status === "running";
  }

  // ---- events ----

  private async onAnalysis(a: PageAnalysis, cs: CsContext): Promise<void> {
    const s = await this.load(cs.tabId);
    if (s?.status === "running") {
      const n = await this.advance(s, step(s, a, cs.origin, this.now()), cs);
      await this.showOverlay(cs);
      this.arm(n);
      return;
    }
    await this.offerOverlay(a, cs);
  }

  private async onCommit(tabId: number, url: string): Promise<void> {
    const s = await this.load(tabId);
    if (s?.status !== "running") return;
    const n = navigated(s, url, this.now());
    await this.save(n);
    this.arm(n);
  }

  private async onLoaded(tabId: number): Promise<void> {
    const s = await this.load(tabId);
    if (s?.status !== "running") return;
    const n = settled(s, this.now());
    if (n !== s) await this.save(n);
    this.arm(n);
  }

  private async onTick(s: ChainState): Promise<ChainState> {
    const r = tick(s, this.now());
    if (r.state === s) return s;
    await this.save(r.state);
    this.arm(r.state);
    return r.state;
  }

  private async forget(tabId: number): Promise<void> {
    this.disarm(tabId);
    this.mem.delete(tabId);
    this.offered.delete(tabId);
    this.navs.delete(tabId);
    await this.deps.area.remove(PREFIX + tabId);
  }

  // ---- actions ----

  /** Persist the new state first, then run its actions; a failure stops the chain. */
  private async advance(prev: ChainState, r: { state: ChainState; actions: ChainAction[] }, cs: CsContext): Promise<ChainState> {
    if (r.state !== prev) await this.save(r.state);
    try {
      for (const a of r.actions) await this.run(r.state, a, cs);
      return r.state;
    } catch (e) {
      const code = toBgError(e).code;
      const n = stopChain(r.state, code === "locked" ? "locked" : "unknown", this.now());
      await this.save(n);
      return n;
    }
  }

  private target(cs: CsContext, formRef: string): FillTarget {
    const t: FillTarget = { tabId: cs.tabId, frameId: 0, origin: cs.origin, formRef };
    if (cs.documentId !== undefined) t.documentId = cs.documentId;
    return t;
  }

  private async run(s: ChainState, a: ChainAction, cs: CsContext): Promise<void> {
    switch (a.type) {
      case "fill":
        await this.deps.filler.fillLogin(this.target(cs, a.formRef), s.itemId, a.fields, "chain");
        return;
      case "fill_provider":
        if (!s.account || !s.provider) throw new BgError("invalid");
        await this.deps.filler.fillProvider(this.target(cs, a.formRef), s.account.itemId, s.provider, s.siteOrigin, a.fields);
        return;
      case "click":
      case "submit": {
        const c = await this.deps.frames.checkFillTarget(cs.tabId, 0, cs.origin, cs.documentId);
        if (!c.ok) throw new BgError(c.code);
        const msg: BgToCs = { type: a.type, origin: cs.origin, ref: a.type === "click" ? a.ref : a.formRef };
        const opts = cs.documentId !== undefined ? { documentId: cs.documentId } : { frameId: 0 };
        await this.deps.ext.tabs.sendMessage(cs.tabId, msg, opts);
        return;
      }
      case "stop":
      case "done":
        return;
    }
  }

  // ---- overlay ----

  private async showOverlay(cs: CsContext): Promise<void> {
    try {
      if (!(await this.deps.overlays.hasTab(cs.tabId))) await this.deps.overlays.open(cs);
    } catch {
      // Content script not there (yet): the next analysis retries.
    }
  }

  /** Spec 8.6: the overlay on a recognized sign-in page of a site with logins, once per document. */
  private async offerOverlay(a: PageAnalysis, cs: CsContext): Promise<void> {
    if (!isSignInPage(a) || parseOrigin(cs.origin)?.https !== true) return;
    const key = cs.documentId ?? `${cs.origin}#${this.navs.get(cs.tabId) ?? 0}`;
    if (this.offered.get(cs.tabId) === key) return;
    this.offered.set(cs.tabId, key);
    try {
      const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "overlay", origin: cs.origin });
      if (items.some(canSignIn)) await this.showOverlay(cs);
    } catch {
      // Locked, unpaired, host missing: no overlay.
    }
  }

  // ---- state and timers ----

  private serial<T>(tabId: number, fn: () => Promise<T>): Promise<T> {
    const prev = this.queues.get(tabId) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    const settledNext = next.catch(() => undefined);
    this.queues.set(tabId, settledNext);
    void settledNext.then(() => {
      if (this.queues.get(tabId) === settledNext) this.queues.delete(tabId);
    });
    return next;
  }

  private async load(tabId: number): Promise<ChainState | null> {
    const m = this.mem.get(tabId);
    if (m) return m;
    const s = parseChainState((await this.deps.area.get(PREFIX + tabId))[PREFIX + tabId]);
    if (!s || s.tabId !== tabId) return null;
    this.mem.set(tabId, s);
    return s;
  }

  private async save(s: ChainState): Promise<void> {
    this.mem.set(s.tabId, s);
    await this.deps.area.set({ [PREFIX + s.tabId]: s });
  }

  private disarm(tabId: number): void {
    const t = this.armed.get(tabId);
    if (t !== undefined) this.timers.clearTimeout(t);
    this.armed.delete(tabId);
  }

  private arm(s: ChainState): void {
    this.disarm(s.tabId);
    const due = nextDue(s);
    if (due === null) return;
    const id = this.timers.setTimeout(() => {
      this.armed.delete(s.tabId);
      void this.serial(s.tabId, async () => {
        const cur = await this.load(s.tabId);
        if (cur) await this.onTick(cur);
      });
    }, Math.max(0, due - this.now()));
    this.armed.set(s.tabId, id);
  }

  private async rearmAll(): Promise<void> {
    try {
      for (const [k, v] of Object.entries(await this.deps.area.get(null))) {
        if (!k.startsWith(PREFIX)) continue;
        const s = parseChainState(v);
        if (s?.status === "running") {
          this.mem.set(s.tabId, s);
          this.arm(s);
        }
      }
    } catch {
      // Storage unavailable: the next event re-arms.
    }
  }
}
