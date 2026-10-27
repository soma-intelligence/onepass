// Adapter of the chain machine (machine.ts) to the service worker (spec 8.6).
//
// - Input: page analyses of the chain's tab (origin from `sender`): the top
//   frame's, or, when it holds nothing to act on, those of a child frame of
//   exactly the top frame's origin that holds a sign-in or code form (spec
//   C1; origin and document read again from `webNavigation`, a frame of
//   another origin, even of the same site, never counts: R-10);
//   `webNavigation.onCommitted` / `onCompleted` of the top frame and of the
//   frame the last step acted in; and timers (deadline, unknown page,
//   settled done).
// - Output: fills through the single fill path (fill.ts, secrets fetched
//   just in time per step, only the fields the step needs), `click` and
//   `submit` messages pinned to the verified origin, all to the frame and
//   document of the analysis acted on, and the overlay (always in the top
//   frame).
// - State: `storage.session` key `chain:<tabId>` (no secret), so a restarted
//   worker resumes without submitting a page twice: the machine records each
//   step with the page signature and navigation counter, and the state is
//   written before the step's actions run. Timers are plain `setTimeout`s
//   re-armed from the persisted due times on any event (the overlay polls
//   `state` every 500 ms while a chain runs).
//
// Also here, since it shares the same analyses: showing the overlay on a
// recognized sign-in page of a site that has logins (once per sign-in form of
// a top document, so a form built late is offered too, and a form in a frame
// of the same origin), and on every page of a running chain.
import type { Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { BgToCs, FormInfo, PageAnalysis, ProviderId } from "../../shared/messages";
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
  submitMissed,
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
  frames: Pick<Frames, "frameOrigin" | "checkFillTarget" | "details" | "ancestorsOfOrigin">;
  filler: Pick<Filler, "fillLogin" | "fillProvider">;
  analyses: Pick<PageAnalyses, "top" | "children" | "onAnalysis">;
  overlays: OverlayPort;
  now?: () => number;
  timers?: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void };
}

/** Sign-in forms offered per document, at most (a page cannot reopen it at will). */
const MAX_OFFERS = 8;

const SIGN_IN_ROLES = new Set(["username", "email", "current_password"]);

function isSignInForm(f: FormInfo): boolean {
  return f.kind === "login" && f.fields.some((x) => SIGN_IN_ROLES.has(x.role));
}

/**
 * The sign-in forms of a page as the user sees them (kinds and roles, no
 * refs): a re-render of the same form keeps it, a new step changes it.
 */
function signInShape(a: PageAnalysis): string | null {
  const forms = a.forms.filter(isSignInForm);
  return forms.length === 0 ? null : JSON.stringify(forms.map((f) => [f.kind, f.fields.map((x) => x.role)]));
}

/** A form the chain can act on (machine.ts `decide`): sign-in or code. */
function isChainForm(f: FormInfo): boolean {
  return f.fields.some((x) => x.role === "otp") || ((f.kind === "login" || f.kind === "otp") && f.fields.some((x) => SIGN_IN_ROLES.has(x.role)));
}

/**
 * The top frame's analysis has something for the chain: a form, an account
 * chooser, a stop, or the button of the provider a chain signs in with.
 */
function actionable(a: PageAnalysis, provider: ProviderId | undefined): boolean {
  return (
    a.forms.some(isChainForm) ||
    a.accountChooser.length > 0 ||
    a.captcha ||
    a.push ||
    (provider !== undefined && a.providerButtons.some((b) => b.provider === provider))
  );
}

/** Same document, when both sides know it. */
function sameDoc(a: string | undefined, b: string | undefined): boolean {
  return a === undefined || b === undefined || a === b;
}

/** The analysis the chain and the overlay go by, and the frame it is from. */
interface Acting {
  cs: CsContext;
  analysis: PageAnalysis;
}

function canSignIn(it: Summary): boolean {
  return it.kind === "login" && (it.has_password || it.methods.length > 0);
}

export class ChainRunner implements ChainDriver {
  private readonly mem = new Map<number, ChainState>();
  private readonly queues = new Map<number, Promise<unknown>>();
  private readonly armed = new Map<number, unknown>();
  /** Per tab: the document the overlay was offered on, its sign-in forms offered, a close by the user. */
  private readonly offered = new Map<number, { doc: string; shapes: Set<string>; closed: boolean }>();
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
      if (d.frameId !== 0) {
        void this.serial(d.tabId, () => this.onFrameCommit(d.tabId, d.frameId, d.url));
        return;
      }
      this.navs.set(d.tabId, (this.navs.get(d.tabId) ?? 0) + 1);
      void this.serial(d.tabId, () => this.onCommit(d.tabId, d.url));
    });
    ext.webNavigation.onCompleted.addListener((d) => {
      void this.serial(d.tabId, () => this.onLoaded(d.tabId, d.frameId));
    });
    ext.tabs.onRemoved.addListener((tabId) => void this.serial(tabId, () => this.forget(tabId)));
    this.deps.analyses.onAnalysis((_a, cs) => {
      // Child frames: only HTTPS ones may be of the top frame's origin.
      if (cs.frameId === 0 || cs.origin.startsWith("https://")) void this.serial(cs.tabId, () => this.onAnalysis(cs));
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
      const view = await this.view(tabId, viaProvider);
      if (view?.at && view.top.origin === origin) {
        s = await this.advance(s, step(s, view.at.analysis, view.at.cs.origin, this.now(), view.at.cs.frameId), view.at.cs);
      }
      await this.showOverlay(view?.top ?? { tabId, frameId: 0, origin });
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

  /** The user closed the overlay: no more offers in that document. */
  async closed(tabId: number, origin: string, documentId?: string): Promise<void> {
    await this.serial(tabId, async () => this.seen(tabId, documentId ?? `${origin}#${this.navs.get(tabId) ?? 0}`).closed = true);
  }

  /** A chain is running in this tab (the save and link proposals stay quiet). */
  async isRunning(tabId: number): Promise<boolean> {
    return (await this.load(tabId))?.status === "running";
  }

  // ---- events ----

  private async onAnalysis(from: CsContext): Promise<void> {
    const s = await this.load(from.tabId);
    const view = await this.view(from.tabId, s?.status === "running" ? s.provider : undefined);
    // A child frame of another origin than the top frame: never (R-10, spec C1).
    if (!view || (from.frameId !== 0 && from.origin !== view.top.origin)) return;
    if (s?.status === "running") {
      let n = s;
      if (view.at) n = await this.advance(s, step(s, view.at.analysis, view.at.cs.origin, this.now(), view.at.cs.frameId), view.at.cs);
      await this.showOverlay(view.top);
      this.arm(n);
      return;
    }
    if (view.at) await this.offerOverlay(view.at.analysis, view.top);
  }

  /**
   * The top frame as the browser reports it now, and the analysis to go by
   * (spec C1): the top frame's when it has something for the chain (signing
   * in with `provider`, if any); else the first child frame of exactly the
   * top frame's origin whose analysis holds a sign-in or code form, its
   * origin and document read again from
   * `webNavigation` (an analysis of a document since replaced is ignored),
   * every frame above it up to the top frame of that origin too;
   * else the top frame's. A CAPTCHA or push prompt of the top frame still
   * counts with a child frame's form.
   */
  private async view(tabId: number, provider?: ProviderId): Promise<{ top: CsContext; at: Acting | null } | null> {
    const f = await this.deps.frames.details(tabId, 0);
    const p = f ? parseOrigin(f.url) : null;
    if (!f || !p) return null;
    const rec = await this.deps.analyses.top(tabId);
    const recOk = rec !== null && rec.origin === p.origin && sameDoc(rec.documentId, f.documentId);
    const top: CsContext = { tabId, frameId: 0, origin: p.origin };
    const doc = f.documentId ?? (recOk ? rec.documentId : undefined);
    if (doc !== undefined) top.documentId = doc;
    const topA = recOk ? rec.analysis : null;
    if (topA && actionable(topA, provider)) return { top, at: { cs: top, analysis: topA } };
    if (p.https) {
      for (const c of await this.deps.analyses.children(tabId)) {
        if (c.origin !== p.origin || !c.analysis.forms.some(isChainForm)) continue;
        const cf = await this.deps.frames.details(tabId, c.frameId);
        if (!cf || parseOrigin(cf.url)?.origin !== c.origin || !sameDoc(c.documentId, cf.documentId)) continue;
        // Nested: every frame between it and the top frame has the same origin.
        if (!(await this.deps.frames.ancestorsOfOrigin(tabId, c.frameId, p.origin))) continue;
        const cs: CsContext = { tabId, frameId: c.frameId, origin: c.origin };
        const cdoc = c.documentId ?? cf.documentId;
        if (cdoc !== undefined) cs.documentId = cdoc;
        const analysis = topA ? { ...c.analysis, captcha: c.analysis.captcha || topA.captcha, push: c.analysis.push || topA.push } : c.analysis;
        return { top, at: { cs, analysis } };
      }
    }
    return { top, at: topA ? { cs: top, analysis: topA } : null };
  }

  private async onCommit(tabId: number, url: string): Promise<void> {
    const s = await this.load(tabId);
    if (s?.status !== "running") return;
    const n = navigated(s, url, this.now());
    await this.save(n);
    this.arm(n);
  }

  /** The frame the last step acted in committed a new document of the same origin: the chain's page moved. */
  private async onFrameCommit(tabId: number, frameId: number, url: string): Promise<void> {
    const s = await this.load(tabId);
    if (s?.status !== "running" || s.steps.at(-1)?.frameId !== frameId) return;
    // Left for another origin: no longer the chain's page (its analyses no longer count).
    const top = await this.deps.frames.frameOrigin(tabId, 0);
    if (top === null || parseOrigin(url)?.origin !== top) return;
    const n = navigated(s, url, this.now());
    await this.save(n);
    this.arm(n);
  }

  private async onLoaded(tabId: number, frameId: number): Promise<void> {
    const s = await this.load(tabId);
    if (s?.status !== "running") return;
    if (frameId !== 0 && s.steps.at(-1)?.frameId !== frameId) return;
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
      let missed = false;
      for (const a of r.actions) if ((await this.run(r.state, a, cs)) === "missed") missed = true;
      if (!missed) return r.state;
      // The content script found no form to submit (re-rendered meanwhile).
      const n = submitMissed(r.state);
      if (n !== r.state) await this.save(n);
      return n;
    } catch (e) {
      const code = toBgError(e).code;
      const n = stopChain(r.state, code === "locked" ? "locked" : "unknown", this.now());
      await this.save(n);
      return n;
    }
  }

  private target(cs: CsContext, formRef: string): FillTarget {
    const t: FillTarget = { tabId: cs.tabId, frameId: cs.frameId, origin: cs.origin, formRef, sameOriginAsTop: true };
    if (cs.documentId !== undefined) t.documentId = cs.documentId;
    return t;
  }

  private async run(s: ChainState, a: ChainAction, cs: CsContext): Promise<"missed" | undefined> {
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
        const c = await this.deps.frames.checkFillTarget(cs.tabId, cs.frameId, cs.origin, cs.documentId, "same_origin");
        if (!c.ok) throw new BgError(c.code);
        const msg: BgToCs = { type: a.type, origin: cs.origin, ref: a.type === "click" ? a.ref : a.formRef };
        const opts = cs.documentId !== undefined ? { documentId: cs.documentId } : { frameId: cs.frameId };
        const reply: unknown = await this.deps.ext.tabs.sendMessage(cs.tabId, msg, opts);
        return a.type === "submit" && (reply as { ok?: unknown } | null | undefined)?.ok === false ? "missed" : undefined;
      }
      case "stop":
      case "done":
        return;
    }
  }

  // ---- overlay ----

  /** True when the overlay is (now) in the tab; `cs` is the top frame. */
  private async showOverlay(cs: CsContext): Promise<boolean> {
    try {
      if (!(await this.deps.overlays.hasTab(cs.tabId))) await this.deps.overlays.open(cs);
      return true;
    } catch {
      // Content script not there (yet): the next analysis retries.
      return false;
    }
  }

  private seen(tabId: number, doc: string): { doc: string; shapes: Set<string>; closed: boolean } {
    let seen = this.offered.get(tabId);
    if (seen?.doc !== doc) {
      seen = { doc, shapes: new Set(), closed: false };
      this.offered.set(tabId, seen);
    }
    return seen;
  }

  /**
   * Spec 8.6: the overlay on a recognized sign-in page of a site with logins.
   * Spec B1: any analysis may offer it, not just the first of the document,
   * once per sign-in form (a form built late, or the next step of the same
   * document); a re-render of a form already offered does not offer again,
   * and nothing is offered in a document where the user closed the overlay.
   */
  private async offerOverlay(a: PageAnalysis, cs: CsContext): Promise<void> {
    const shape = signInShape(a);
    if (shape === null || parseOrigin(cs.origin)?.https !== true) return;
    const seen = this.seen(cs.tabId, cs.documentId ?? `${cs.origin}#${this.navs.get(cs.tabId) ?? 0}`);
    if (seen.closed || seen.shapes.has(shape) || seen.shapes.size >= MAX_OFFERS) return;
    seen.shapes.add(shape);
    let shown = true;
    try {
      const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "overlay", origin: cs.origin });
      if (items.some(canSignIn)) shown = await this.showOverlay(cs);
    } catch {
      // Locked, unpaired, host missing: no overlay.
      shown = false;
    }
    // Not shown for want of the host or the content script: the next analysis may retry.
    if (!shown) seen.shapes.delete(shape);
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
