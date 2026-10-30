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
// Smart fill (spec 5.3, 7): an unknown page is planned again once
// (`replan`, through `ChainDeps.replan`); at the end of a chain, `done`
// clears the site's penalty and notes the fill (`note_fill`), `repeat` sets
// the penalty (penalty.ts).
//
// Also here, since it shares the same analyses: showing the overlay on a
// recognized sign-in page of a site that has logins (once per sign-in form of
// a top document, so a form built late is offered too, and a form in a frame
// of the same origin), and on every page of a running chain.
import type { Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { BgToCs, FieldRole, FormInfo, PageAnalysis, ProviderId } from "../../shared/messages";
import type { ChainView } from "../../shared/ui";
import type { PageAnalyses } from "../analyses";
import type { BgExt, StorageArea } from "../ext";
import type { FillTarget, Filler } from "../fill";
import type { CsContext, Frames } from "../frames";
import { noteFill } from "../notes";
import { clearPenalty, setPenalty } from "../penalty";
import { BgError, type Session, toBgError } from "../session";
import {
  type ChainAction,
  type ChainState,
  chainView,
  navigated,
  nextDue,
  noteShape,
  noteSteps,
  type PlannedStep,
  planStep,
  parseChainState,
  settled,
  startChain,
  step,
  stopChain,
  submitMissed,
  tick,
} from "./machine";
import { defaultAccount, rememberAccount, rememberedAccount } from "./choices";
import { autoSubmitFor } from "./save-flow";
import type { ChainDriver, StartOptions } from "./types";

const PREFIX = "chain:";
/** An ended chain stays on the overlay this long (its reason, "Connecté"). */
export const ENDED_VIEW_MS = 2 * 60 * 1000;
/** A chain that ended this recently shows its outcome on the next page if the overlay is gone. */
export const END_SHOWN_MS = 10_000;

export interface OverlayPort {
  /** Shows the overlay in the top frame `cs`, under the field `anchorRef` when given. */
  open(cs: CsContext, anchorRef?: string): Promise<string>;
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
  /** An inline menu is open in this tab: the overlay is not offered over it (one surface). */
  menuOpen?: (tabId: number) => Promise<boolean>;
  /**
   * A plan of the page in frame `cs` for the chain's item (`plan_fill` on the
   * page context the content script reports), or null when the plan has no
   * login group of that item. Absent: an unknown page stops the chain.
   */
  replan?: (cs: CsContext, itemId: string) => Promise<(PlannedStep & { url: string }) | null>;
  /**
   * Roles of form `formRef` in frame `cs` with the filter of the bridge's
   * `main_roles` (visible, with a role, page order), from the page context;
   * null when the content script does not answer.
   */
  formRoles?: (cs: CsContext, formRef: string) => Promise<FieldRole[] | null>;
  /** A chain started or ended `done` in this tab (the site memory drops the tab's pending fill). */
  onChain?: (tabId: number, event: "start" | "done") => void;
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
  /** Per tab: the end (endedAt) whose outcome was shown again after the page changed. */
  private readonly endShown = new Map<number, number>();
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

  async start(tabId: number, itemId: string, viaProvider?: ProviderId, opts: StartOptions = {}): Promise<void> {
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
      // A picked account must be one of the provider's (the host checks it again on fill).
      providerAccount =
        opts.accountId !== undefined
          ? r.accounts.find((a) => a.item_id === opts.accountId)
          : defaultAccount(r.accounts, method.account_email, await rememberedAccount(this.deps.local, origin, viaProvider), r.linked_item_id);
      if (!providerAccount) throw new BgError("not_found");
    } else if (!item.has_password) {
      throw new BgError("invalid");
    }
    const autoSubmit = await autoSubmitFor(this.deps.local, itemId);
    if (viaProvider && providerAccount) await rememberAccount(this.deps.local, origin, viaProvider, providerAccount.item_id);
    await this.serial(tabId, async () => {
      let s = startChain({
        tabId,
        item,
        siteOrigin: origin,
        ...(viaProvider ? { provider: viaProvider } : {}),
        ...(providerAccount ? { providerAccount } : {}),
        ...(opts.planned ? { planned: opts.planned } : {}),
        autoSubmit,
        now: this.now(),
      });
      await this.save(s);
      this.deps.onChain?.(tabId, "start");
      // The page the click came from: act on it now.
      const view = await this.view(tabId, viaProvider);
      if (view?.at && view.top.origin === origin) {
        s = await this.advance(s, step(s, view.at.analysis, view.at.cs.origin, this.now(), view.at.cs.frameId), view.at.cs);
      }
      await this.showOverlay(view?.top ?? { tabId, frameId: 0, origin }, opts.anchorRef);
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

  async state(tabId: number, opening = false): Promise<ChainView | null> {
    return this.serial(tabId, async () => {
      let s = await this.load(tabId);
      if (!s) return null;
      s = await this.onTick(s);
      const keep = opening ? END_SHOWN_MS : ENDED_VIEW_MS;
      if (s.status !== "running" && s.endedAt !== undefined && this.now() - s.endedAt > keep) return null;
      return chainView(s);
    });
  }

  /** The user closed the overlay: no more offers in that document. */
  async closed(tabId: number, origin: string, documentId?: string): Promise<void> {
    await this.serial(tabId, async () => {
      this.seen(tabId, documentId ?? `${origin}#${this.navs.get(tabId) ?? 0}`).closed = true;
      // An ended chain the user closed is not shown again on the next page.
      const s = await this.load(tabId);
      if (s?.endedAt !== undefined) this.endShown.set(tabId, s.endedAt);
    });
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
    // A chain that just ended as the page left (another domain, say): its
    // outcome shows once on the page it led to, so the user knows why.
    if (s && from.frameId === 0 && s.endedAt !== undefined && this.now() - s.endedAt <= END_SHOWN_MS && this.endShown.get(from.tabId) !== s.endedAt) {
      this.endShown.set(from.tabId, s.endedAt);
      if (await this.showOverlay(view.top)) return;
      this.endShown.delete(from.tabId);
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
    let n = r.state;
    if (r.actions.some((a) => a.type === "replan")) n = await this.replan(n);
    this.arm(n);
    return n;
  }

  /**
   * Spec 5.3: the page went unknown; plan it again. The plan's login group of
   * the chain's item is acted on as a step; no plan, no such group, or a
   * failure: the chain stops (`unknown`).
   */
  private async replan(s: ChainState): Promise<ChainState> {
    const stop = async () => {
      const n = stopChain(s, "unknown", this.now());
      await this.save(n);
      return n;
    };
    if (!this.deps.replan || s.status !== "running") return stop();
    const view = await this.view(s.tabId, s.provider);
    const cs = view?.at?.cs ?? view?.top;
    if (!cs) return stop();
    let p: (PlannedStep & { url: string }) | null;
    try {
      p = await this.deps.replan(cs, s.itemId);
    } catch {
      p = null;
    }
    if (!p) return stop();
    const { url, ...planned } = p;
    return this.advance(s, planStep(s, planned, url, cs.origin, this.now(), cs.frameId), cs);
  }

  private async forget(tabId: number): Promise<void> {
    this.disarm(tabId);
    this.mem.delete(tabId);
    this.offered.delete(tabId);
    this.navs.delete(tabId);
    this.endShown.delete(tabId);
    await this.deps.area.remove(PREFIX + tabId);
  }

  // ---- actions ----

  /** Persist the new state first, then run its actions; a failure stops the chain. */
  private async advance(prev: ChainState, r: { state: ChainState; actions: ChainAction[] }, cs: CsContext): Promise<ChainState> {
    if (r.state !== prev) await this.save(r.state);
    try {
      let missed = false;
      for (const a of r.actions) if ((await this.run(r.state, a, cs)) === "missed") missed = true;
      let n = await this.exactRoles(prev, r, cs);
      if (!missed) return n;
      // The content script found no form to submit (re-rendered meanwhile).
      const m = submitMissed(n);
      if (m !== n) await this.save(m);
      n = m;
      return n;
    } catch (e) {
      const code = toBgError(e).code;
      const n = stopChain(r.state, code === "locked" ? "locked" : "unknown", this.now());
      await this.save(n);
      return n;
    }
  }

  /**
   * The first form a chain without a plan filled: its roles read again from
   * the page context, with the filter of the bridge's `main_roles`, so the
   * note's `form_shape_hash` matches the plans'. Kept from the analysis when
   * the content script does not answer.
   */
  private async exactRoles(prev: ChainState, r: { state: ChainState; actions: ChainAction[] }, cs: CsContext): Promise<ChainState> {
    const s = r.state;
    if (s.planned || s.roles === undefined || prev.roles !== undefined || !this.deps.formRoles) return s;
    const fill = r.actions.find((a): a is Extract<ChainAction, { type: "fill" }> => a.type === "fill");
    if (!fill) return s;
    let roles: FieldRole[] | null = null;
    try {
      roles = await this.deps.formRoles(cs, fill.formRef);
    } catch {
      roles = null;
    }
    if (roles === null) return s;
    const n: ChainState = { ...s, roles };
    await this.save(n);
    return n;
  }

  private target(cs: CsContext, formRef: string): FillTarget {
    const t: FillTarget = { tabId: cs.tabId, frameId: cs.frameId, origin: cs.origin, formRef, sameOriginAsTop: true };
    if (cs.documentId !== undefined) t.documentId = cs.documentId;
    return t;
  }

  private async run(s: ChainState, a: ChainAction, cs: CsContext): Promise<"missed" | undefined> {
    switch (a.type) {
      case "fill":
        await this.deps.filler.fillLogin(this.target(cs, a.formRef), s.itemId, a.fields, "chain", a.roles);
        return;
      case "fill_provider":
        if (!s.account || !s.provider) throw new BgError("invalid");
        await this.deps.filler.fillProvider(this.target(cs, a.formRef), s.account.itemId, s.provider, s.siteOrigin, a.fields);
        return;
      case "click":
      case "submit": {
        const c = await this.deps.frames.checkFillTarget(cs.tabId, cs.frameId, cs.origin, cs.documentId, "same_origin");
        if (!c.ok) throw new BgError(c.code);
        const msg: BgToCs =
          a.type === "click"
            ? { type: "click", origin: cs.origin, ref: a.ref }
            : { type: "submit", origin: cs.origin, ref: a.formRef, ...(a.planned ? { planned: true as const } : {}) };
        const opts = cs.documentId !== undefined ? { documentId: cs.documentId } : { frameId: cs.frameId };
        const reply: unknown = await this.deps.ext.tabs.sendMessage(cs.tabId, msg, opts);
        return a.type === "submit" && (reply as { ok?: unknown } | null | undefined)?.ok === false ? "missed" : undefined;
      }
      case "stop":
      case "done":
      case "replan":
        return;
    }
  }

  // ---- overlay ----

  /** True when the overlay is (now) in the tab; `cs` is the top frame. */
  private async showOverlay(cs: CsContext, anchorRef?: string): Promise<boolean> {
    try {
      if (!(await this.deps.overlays.hasTab(cs.tabId))) await this.deps.overlays.open(cs, anchorRef);
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
    // One surface: the user is in the inline menu, which offers the same sign-ins.
    if (await this.deps.menuOpen?.(cs.tabId)) return;
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
    const prev = this.mem.get(s.tabId);
    this.mem.set(s.tabId, s);
    await this.deps.area.set({ [PREFIX + s.tabId]: s });
    // The chain just ended (this very chain: same start).
    if (prev?.status === "running" && s.status !== "running" && prev.startedAt === s.startedAt) await this.ended(s);
  }

  /** `done`: the penalty goes, the fill is noted. `repeat`: the site is penalized. Never fails. */
  private async ended(s: ChainState): Promise<void> {
    try {
      if (s.status === "done") {
        this.deps.onChain?.(s.tabId, "done");
        await clearPenalty(this.deps.area, s.site);
        const { roles, intent } = noteShape(s);
        await noteFill(this.deps.session, { ctx: "chain", item_id: s.itemId, origin: s.siteOrigin, roles, intent, steps: noteSteps(s) });
      } else if (s.reason === "repeat") {
        await setPenalty(this.deps.area, s.site, this.now());
      }
    } catch {
      // Storage gone: the memory is a hint, the chain's outcome stands.
    }
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
