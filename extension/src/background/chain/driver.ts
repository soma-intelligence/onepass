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
// A locked vault mid-chain (spec 8.6 stop `locked`) does not cost another
// click: the chain stops as before, the state it had before the step it
// could not run is kept (`unlock-chain:<tabId>` in `storage.session`, no
// secret, with the top document and the time), the app is asked to unlock
// through the overlay, and `resumeLocked` continues from that step, once, if
// the vault opens inside the shared deadline in that same document.
//
// A provider button that opens a popup WINDOW (most "Continue with ..."
// buttons do): when the chain itself clicked that button, the tab the
// chain's tab opens right after is followed for that chain (`openerTabId`; where the browser
// has `webNavigation.onCreatedNavigationTarget`, the opening frame must be the clicked one).
// The provider's pages are acted on there, on its exact hosts only; the
// popup may end on the site (its callback page) where nothing is done; any
// other host stops the chain. Same deadline as the rest of the chain.
//
// A chain that leaves the site's registrable domain for a host that is no
// provider host stops (`domain`) as ever. The driver then asks the bridge
// for a plan of the page it landed on (`ChainDeps.cross`): only when that
// plan names the chain's own item as a normal match (never a first use
// through Apple's shared-credentials list) does the chain go on, with that
// exact host added to its own allow-list.
//
// Also here, since it shares the same analyses: showing the overlay on a
// recognized sign-in page of a site that has logins (once per sign-in form of
// a top document, so a form built late is offered too, and a form in a frame
// of the same origin), on a page with only provider buttons when a login of
// the site signs in with one of those providers (spec E1), and on every page
// of a running chain.
import type { Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { BgToCs, FieldRole, FormInfo, PageAnalysis, ProviderId } from "../../shared/messages";
import { providerForHost } from "../../shared/providers";
import type { ChainView } from "../../shared/ui";
import { UNLOCK_WAIT_MS } from "../../shared/unlock";
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
  DEADLINE_MS,
  chainView,
  crossTo,
  followPopup,
  navigated,
  nextDue,
  noteShape,
  noteSteps,
  type PlannedStep,
  planStep,
  parseChainState,
  popupClosed,
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
/** The chain to continue after an unlock, per tab (never under `PREFIX`: not a chain state). */
const WAIT_PREFIX = "unlock-chain:";

/** A chain stopped `locked`: its state before the step that failed, where and when. */
interface LockedChain {
  state: ChainState;
  at: number;
  /** The top frame's origin and document at the stop: it resumes there only. */
  origin: string;
  documentId?: string;
}

function parseLockedChain(raw: unknown): LockedChain | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const state = parseChainState(r.state);
  if (!state || typeof r.at !== "number" || !Number.isSafeInteger(r.at) || r.at < 0 || typeof r.origin !== "string") return null;
  if (r.documentId !== undefined && typeof r.documentId !== "string") return null;
  const w: LockedChain = { state, at: r.at, origin: r.origin };
  if (r.documentId !== undefined) w.documentId = r.documentId;
  return w;
}
/** A tab the chain's tab opens this soon after the chain clicked the provider's button is that button's popup. */
export const POPUP_ADOPT_MS = 5_000;
/** After a `domain` stop, the page the chain landed on may still be checked with the bridge this long. */
export const CROSS_CHECK_MS = 10_000;

/** What the bridge's plan says of the chain's item on an origin outside its site. */
export type CrossVerdict = "match" | "first_use" | "no";

/** An ended chain stays on the overlay this long (its reason, "Connecté"). */
export const ENDED_VIEW_MS = 2 * 60 * 1000;
/** A chain that ended this recently shows its outcome on the next page if the overlay is gone. */
export const END_SHOWN_MS = 10_000;

export interface OverlayPort {
  /**
   * Shows the overlay in the top frame `cs`, under the field `anchorRef` when given. `generic`: a
   * card for a locked vault, which names no account and holds nothing of the vault.
   */
  open(cs: CsContext, anchorRef?: string, generic?: boolean): Promise<string>;
  hasTab(tabId: number): Promise<boolean>;
  /**
   * The chain of `tabId` stopped `locked`: the app is asked to unlock and the tab's overlay
   * waits, to call `resumeLocked` once the vault opens. False when nothing will (no overlay
   * there, the app could not be asked). Absent: a locked chain just stops.
   */
  awaitUnlock?(tabId: number): Promise<boolean>;
}

export interface ChainDeps {
  ext: Pick<BgExt, "tabs" | "webNavigation">;
  area: StorageArea;
  /**
   * The bridge's plan of top frame `cs`, a page outside the chain's site, for the chain's item:
   * `match` when its login group names that very item as a normal match, `first_use` when the
   * item is only offered there through Apple's shared-credentials list (`associated_domain`),
   * else `no`. Absent: a chain never leaves its site.
   */
  cross?: (cs: CsContext, itemId: string) => Promise<CrossVerdict>;
  /** `storage.local`: the auto-submit preference (R-12). */
  local: StorageArea;
  session: Pick<Session, "request">;
  frames: Pick<Frames, "frameOrigin" | "checkFillTarget" | "details" | "ancestorsOfOrigin">;
  filler: Pick<Filler, "fillLogin" | "fillProvider">;
  analyses: Pick<PageAnalyses, "top" | "children" | "onAnalysis">;
  overlays: OverlayPort;
  /** An inline menu is open in this tab: the overlay is not offered over it (one surface). */
  menuOpen?: (tabId: number) => Promise<boolean>;
  /** The user set "never offer here" for this registrable domain (never-save.ts): no generic card there. */
  neverOffer?: (site: string) => Promise<boolean>;
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

/**
 * The providers whose sign-in buttons a page shows, when it has no sign-in
 * form (spec E1: a provider-only page), as an offer shape; else null.
 */
function providerShape(a: PageAnalysis): { shape: string; providers: Set<ProviderId> } | null {
  const providers = new Set(a.providerButtons.map((b) => b.provider));
  if (providers.size === 0) return null;
  return { shape: JSON.stringify(["providers", [...providers].sort()]), providers };
}

/**
 * A page with no sign-in form and no provider button whose one button reads as a passkey sign-in:
 * a sign-in page all the same. Nothing is offered on it while the vault is open (the site's
 * button and the passkey window serve it); locked, it gets the generic card like any sign-in page.
 */
const PASSKEY_SHAPE = JSON.stringify(["passkey"]);

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

/** The item signs in with one of `providers` (a sign-in method linked to it). */
function signsInWith(it: Summary, providers: ReadonlySet<ProviderId>): boolean {
  return it.kind === "login" && it.methods.some((m) => providers.has(m.provider));
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
  /**
   * Per tab: the end (endedAt) a live overlay already displayed, and its top document. Once seen
   * there, the outcome does not follow the user to the next page (founder review 2026-11-09:
   * "CAPTCHA détecté" stayed on the page after the CAPTCHA page).
   */
  private readonly endSeen = new Map<number, { endedAt: number; doc: string }>();
  /** Tabs with a chain kept for an unlock (`WAIT_PREFIX`); complete once `waitsKnown`. */
  private readonly waits = new Set<number>();
  /** `waits` was read from storage (a worker restart may have left some behind). */
  private waitsKnown = false;
  /** Popup tabs followed, by tab id: the tab of the chain that opened each (`ChainState.popupTabId`). */
  private readonly popups = new Map<number, number>();
  /** Per tab: the chain as it was before its last `domain` stop, and the document it left for. */
  private readonly crossings = new Map<number, { prev: ChainState; url: string; at: number }>();
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
    const committed = (d: { tabId: number; frameId: number; url: string }): void => {
      if (d.frameId !== 0) {
        void this.serial(d.tabId, () => this.onFrameCommit(d.tabId, d.frameId, d.url));
        return;
      }
      this.navs.set(d.tabId, (this.navs.get(d.tabId) ?? 0) + 1);
      void this.serial(d.tabId, () => this.onCommit(d.tabId, d.url));
    };
    const analysed = (cs: CsContext): void => {
      // Child frames: only HTTPS ones may be of the top frame's origin.
      if (cs.frameId === 0 || parseOrigin(cs.origin)?.page === true) void this.serial(cs.tabId, () => this.onAnalysis(cs));
    };
    ext.webNavigation.onCommitted.addListener((d) => {
      const owner = this.popups.get(d.tabId);
      // A followed popup (or a tab that may be one): on its chain's queue, which knows by then.
      if (owner !== undefined) void this.serial(owner, async () => ((await this.following(owner, d.tabId)) ? (d.frameId === 0 ? this.onPopupCommit(owner, d.tabId, d.url) : undefined) : committed(d)));
      else committed(d);
    });
    ext.webNavigation.onCompleted.addListener((d) => {
      const owner = this.popups.get(d.tabId);
      if (owner !== undefined) {
        void this.serial(owner, async () => {
          if (!(await this.following(owner, d.tabId))) void this.serial(d.tabId, () => this.onLoaded(d.tabId, d.frameId));
          else if (d.frameId === 0) await this.onLoaded(owner, 0);
        });
        return;
      }
      void this.serial(d.tabId, () => this.onLoaded(d.tabId, d.frameId));
    });
    ext.tabs.onRemoved.addListener((tabId) => {
      const owner = this.popups.get(tabId);
      if (owner !== undefined) void this.serial(owner, () => this.onPopupClosed(owner, tabId));
      void this.serial(tabId, () => this.forget(tabId));
    });
    // Noted at once: the tab's first events may come before the chain's state is read. `onOpened`
    // runs first on the opener's queue and drops the note unless the chain adopts the tab.
    const opened = (id: unknown, opener: unknown, frameId?: number): void => {
      if (typeof id !== "number" || typeof opener !== "number" || id === opener) return;
      this.popups.set(id, opener);
      void this.serial(opener, () => this.onOpened(opener, id, frameId));
    };
    const targets = ext.webNavigation.onCreatedNavigationTarget;
    // Where the browser names the frame that opened a tab (Chromium, Firefox; the event comes
    // before the tab's first commit), only the frame of the chain's own click has its tab
    // followed: a frame embedded in the page cannot slip its window under the chain. Elsewhere
    // (Safari): the opener tab and the moment, as before.
    if (targets) targets.addListener((d) => opened(d.tabId, d.sourceTabId, typeof d.sourceFrameId === "number" ? d.sourceFrameId : -1));
    else ext.tabs.onCreated?.addListener((tab) => opened(tab.id, tab.openerTabId));
    this.deps.analyses.onAnalysis((_a, cs) => {
      const owner = this.popups.get(cs.tabId);
      if (owner !== undefined) void this.serial(owner, async () => ((await this.following(owner, cs.tabId)) ? (cs.frameId === 0 ? this.onPopupAnalysis(owner, cs) : undefined) : analysed(cs)));
      else analysed(cs);
    });
    void this.rearmAll();
  }

  // ---- ChainDriver ----

  async start(tabId: number, itemId: string, viaProvider?: ProviderId, opts: StartOptions = {}): Promise<void> {
    const origin = await this.deps.frames.frameOrigin(tabId, 0);
    if (!origin || parseOrigin(origin)?.page !== true) throw new BgError("insecure_origin");
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
      // A new chain: nothing older waits for an unlock.
      await this.dropWait(tabId);
      let s = startChain({
        tabId,
        item,
        siteOrigin: origin,
        ...(viaProvider ? { provider: viaProvider } : {}),
        ...(providerAccount ? { providerAccount } : {}),
        ...(opts.planned ? { planned: opts.planned } : {}),
        ...(opts.picked ? { picked: opts.picked } : {}),
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
      // "Annuler" while the chain waits for an unlock: it stays stopped.
      await this.dropWait(tabId);
      const s = await this.load(tabId);
      if (!s) return;
      const n = stopChain(s, "user", this.now());
      if (n !== s) await this.save(n);
      this.disarm(tabId);
    });
  }

  async state(tabId: number, opening = false, documentId?: string): Promise<ChainView | null> {
    return this.serial(tabId, async () => {
      let s = await this.load(tabId);
      if (!s) return null;
      s = await this.onTick(s);
      const keep = opening ? END_SHOWN_MS : ENDED_VIEW_MS;
      if (s.status !== "running" && s.endedAt !== undefined) {
        if (this.now() - s.endedAt > keep) return null;
        // An overlay opening on another document: an outcome already seen gives way to the offer.
        if (opening && this.seenElsewhere(tabId, s.endedAt, documentId)) return null;
        // An overlay that gets the outcome shows it (at its opening, or polling): seen in that document.
        if (documentId !== undefined) this.endSeen.set(tabId, { endedAt: s.endedAt, doc: documentId });
      }
      return chainView(s);
    });
  }

  /** The outcome of the end `endedAt` was already displayed, in another top document than `doc`. */
  private seenElsewhere(tabId: number, endedAt: number, doc: string | undefined): boolean {
    const seen = this.endSeen.get(tabId);
    return seen !== undefined && seen.endedAt === endedAt && seen.doc !== doc;
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

  /**
   * Spec E1: the providers of the top document `documentId` when it is a
   * provider-only page (no sign-in form, provider buttons); null otherwise,
   * or when the tab shows another document by now. The overlay then lists
   * only the logins linked to one of them.
   */
  async providerOnly(tabId: number, documentId?: string): Promise<ProviderId[] | null> {
    return this.serial(tabId, async () => {
      const view = await this.view(tabId);
      const a = view?.at?.analysis;
      if (!view || !a || !sameDoc(view.top.documentId, documentId) || signInShape(a) !== null) return null;
      const sso = providerShape(a);
      return sso ? [...sso.providers] : null;
    });
  }

  async providersShown(tabId: number, documentId?: string): Promise<ProviderId[]> {
    return this.serial(tabId, async () => {
      const view = await this.view(tabId);
      const a = view?.at?.analysis;
      if (!view || !a || !sameDoc(view.top.documentId, documentId)) return [];
      return [...new Set(a.providerButtons.map((b) => b.provider))];
    });
  }

  /** Top document `documentId` of `tabId` reads as a sign-in page: a sign-in form (its own, or in a child frame of its origin), or provider buttons. */
  async signInPage(tabId: number, documentId?: string): Promise<boolean> {
    return this.serial(tabId, async () => {
      const view = await this.view(tabId);
      const a = view?.at?.analysis;
      if (!view || !a || !sameDoc(view.top.documentId, documentId)) return false;
      return signInShape(a) !== null || providerShape(a) !== null || a.passkeySignIn === true;
    });
  }

  async acting(tabId: number): Promise<CsContext | null> {
    return this.serial(tabId, async () => {
      const view = await this.view(tabId);
      return view ? (view.at?.cs ?? view.top) : null;
    });
  }

  /** A chain is running in this tab (the save and link proposals stay quiet). */
  async isRunning(tabId: number): Promise<boolean> {
    return (await this.load(tabId))?.status === "running";
  }

  /**
   * The vault opened after the chain of `tabId` stopped `locked`: the chain goes on from the step
   * it could not run, with a fresh deadline. One attempt (the kept state goes first), only inside
   * the shared deadline, only while that very chain is still the tab's, stopped `locked`, and the
   * top frame still holds the https document it stopped in. Locked again: it stops for good.
   * False when refused.
   */
  async resumeLocked(tabId: number): Promise<boolean> {
    return this.serial(tabId, async () => {
      const key = WAIT_PREFIX + tabId;
      const w = parseLockedChain((await this.deps.area.get(key))[key]);
      await this.deps.area.remove(key);
      if (!w || w.state.tabId !== tabId) return false;
      const t = this.now();
      if (t < w.at || t - w.at > UNLOCK_WAIT_MS) return false;
      const cur = await this.load(tabId);
      if (!cur || cur.status === "running" || cur.reason !== "locked" || cur.startedAt !== w.state.startedAt) return false;
      const view = await this.view(tabId, w.state.provider);
      if (!view || parseOrigin(view.top.origin)?.page !== true || view.top.origin !== w.origin) return false;
      if (w.documentId !== undefined && view.top.documentId !== undefined && view.top.documentId !== w.documentId) return false;
      let s: ChainState = { ...w.state, deadline: t + DEADLINE_MS };
      await this.save(s);
      if (view.at) s = await this.advance(s, step(s, view.at.analysis, view.at.cs.origin, t, view.at.cs.frameId), view.at.cs, false);
      await this.showOverlay(view.top);
      this.arm(s);
      return true;
    });
  }

  // ---- events ----

  private async onAnalysis(from: CsContext): Promise<void> {
    let s = await this.load(from.tabId);
    const view = await this.view(from.tabId, s?.status === "running" ? s.provider : undefined);
    // A child frame of another origin than the top frame: never (R-10, spec C1).
    if (!view || (from.frameId !== 0 && from.origin !== view.top.origin)) return;
    if (s && from.frameId === 0) s = await this.maybeCross(s, view.top);
    if (s?.status === "running") {
      // The provider's pages are in the popup the chain follows: this tab's page waits for it.
      if (s.popupTabId !== undefined) {
        await this.showOverlay(view.top);
        this.arm(s);
        return;
      }
      let n = s;
      if (view.at) n = await this.advance(s, step(s, view.at.analysis, view.at.cs.origin, this.now(), view.at.cs.frameId), view.at.cs);
      await this.showOverlay(view.top);
      this.arm(n);
      return;
    }
    // A chain that just ended as the page left (another domain, say): its
    // outcome shows once on the page it led to, so the user knows why.
    if (s && from.frameId === 0 && s.endedAt !== undefined && this.now() - s.endedAt <= END_SHOWN_MS && this.endShown.get(from.tabId) !== s.endedAt && !this.seenElsewhere(from.tabId, s.endedAt, view.top.documentId)) {
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
    if (p.page) {
      for (const c of await this.deps.analyses.children(tabId)) {
        if (c.origin !== p.origin || !c.analysis.forms.some(isChainForm)) continue;
        const cf = await this.deps.frames.details(tabId, c.frameId);
        if (!cf || parseOrigin(cf.url)?.origin !== c.origin || !sameDoc(c.documentId, cf.documentId)) continue;
        // Nested: every frame between it and the top frame has the same origin.
        if (!(await this.deps.frames.ancestorsOfOrigin(tabId, c.frameId, p.origin))) continue;
        const cs: CsContext = { tabId, frameId: c.frameId, origin: c.origin };
        const cdoc = c.documentId ?? cf.documentId;
        if (cdoc !== undefined) cs.documentId = cdoc;
        const analysis = topA
          ? { ...c.analysis, captcha: c.analysis.captcha || topA.captcha, push: c.analysis.push || topA.push, ...(c.analysis.captchaWidget || topA.captchaWidget ? { captchaWidget: true } : {}) }
          : c.analysis;
        return { top, at: { cs, analysis } };
      }
    }
    return { top, at: topA ? { cs: top, analysis: topA } : null };
  }

  private async onCommit(tabId: number, url: string): Promise<void> {
    // A new top document: a chain that waited for an unlock in the old one does not resume.
    await this.dropWait(tabId);
    this.crossings.delete(tabId);
    const s = await this.load(tabId);
    if (s?.status !== "running") return;
    const n = navigated(s, url, this.now());
    // Left the site: stopped, and kept as it was until the bridge has said whose page this is.
    if (n.status !== "running" && n.reason === "domain" && this.deps.cross) this.crossings.set(tabId, { prev: s, url, at: this.now() });
    await this.save(n);
    this.arm(n);
  }

  /**
   * The chain of this tab just stopped `domain` on the document `top` now shows: the bridge's plan
   * of that page decides. The chain's own item as a normal match there: the chain goes on, that
   * host allowed. A first use through Apple's shared credentials: it stays stopped, and the
   * page's own offer shows instead of the stop. One check per stop, in time, https only.
   */
  private async maybeCross(s: ChainState, top: CsContext): Promise<ChainState> {
    const c = this.crossings.get(s.tabId);
    if (!c) return s;
    this.crossings.delete(s.tabId);
    const t = this.now();
    const to = parseOrigin(c.url);
    if (!this.deps.cross || s.status === "running" || s.reason !== "domain" || s.startedAt !== c.prev.startedAt) return s;
    if (!to?.https || to.origin !== top.origin || t < c.at || t - c.at > CROSS_CHECK_MS) return s;
    let verdict: CrossVerdict;
    try {
      verdict = await this.deps.cross(top, c.prev.itemId);
    } catch {
      verdict = "no";
    }
    if (verdict === "first_use" && s.endedAt !== undefined) {
      this.endShown.set(s.tabId, s.endedAt);
      return s;
    }
    const n = verdict === "match" ? crossTo(c.prev, c.url, this.now()) : null;
    if (!n) return s;
    // The page is there (it was just analysed): the unknown-page wait runs from now.
    n.page.settledAt = this.now();
    await this.save(n);
    return n;
  }

  // ---- the provider's popup window ----

  /**
   * `popupTab` was opened by the chain's tab: followed when the chain itself just clicked the
   * provider's button, in the frame that opened it (`frameId`, where the browser names it).
   */
  private async onOpened(tabId: number, popupTab: number, frameId?: number): Promise<void> {
    const s = await this.load(tabId);
    const last = s?.steps.at(-1);
    const own =
      last?.kind === "provider_click" &&
      this.now() >= last.at &&
      this.now() - last.at <= POPUP_ADOPT_MS &&
      (frameId === undefined || frameId === (last.frameId ?? 0));
    const n = s && own ? followPopup(s, popupTab) : s;
    if (!s || !n || n === s) {
      // Not the chain's popup: an ordinary tab.
      if (s?.popupTabId !== popupTab) this.popups.delete(popupTab);
      return;
    }
    await this.save(n);
    this.arm(n);
  }

  /** The chain of `tabId` while it follows `popupTab`; else the popup is forgotten. */
  private async following(tabId: number, popupTab: number): Promise<ChainState | null> {
    const s = await this.load(tabId);
    if (s?.status === "running" && s.popupTabId === popupTab) return s;
    this.popups.delete(popupTab);
    return null;
  }

  private async onPopupCommit(tabId: number, popupTab: number, url: string): Promise<void> {
    const s = await this.following(tabId, popupTab);
    if (!s) return;
    // The chain's allow-list as ever: the provider's exact hosts, and the site (its callback page).
    const n = navigated(s, url, this.now());
    await this.save(n);
    this.arm(n);
  }

  /** The popup's top frame reported an analysis: acted on only on an exact host of the chain's provider. */
  private async onPopupAnalysis(tabId: number, from: CsContext): Promise<void> {
    const s = await this.following(tabId, from.tabId);
    if (!s) return;
    const f = await this.deps.frames.details(from.tabId, 0);
    const p = f ? parseOrigin(f.url) : null;
    const rec = await this.deps.analyses.top(from.tabId);
    if (!f || !p?.https || !rec || rec.origin !== p.origin || !sameDoc(rec.documentId, f.documentId)) return;
    if (providerForHost(p.host) !== s.provider) return;
    const cs: CsContext = { tabId: from.tabId, frameId: 0, origin: p.origin };
    const doc = f.documentId ?? rec.documentId;
    if (doc !== undefined) cs.documentId = doc;
    const n = await this.advance(s, step(s, rec.analysis, p.origin, this.now(), 0), cs);
    this.arm(n);
  }

  /**
   * The followed popup closed: the chain is back on its tab. A page there that still shows the
   * provider's button did not sign in: stopped (`unknown`, never a second click, the site's
   * password is not blamed). Else the page is read as any page of the chain.
   */
  private async onPopupClosed(tabId: number, popupTab: number): Promise<void> {
    this.popups.delete(popupTab);
    const s = await this.load(tabId);
    if (!s || s.popupTabId !== popupTab) return;
    let n = popupClosed(s, this.now());
    await this.save(n);
    if (n.status !== "running") return;
    const view = await this.view(tabId, n.provider);
    const a = view?.at?.analysis;
    if (view?.at && a) {
      if (a.providerButtons.some((b) => b.provider === n.provider)) {
        n = stopChain(n, "unknown", this.now());
        await this.save(n);
      } else n = await this.advance(n, step(n, a, view.at.cs.origin, this.now(), view.at.cs.frameId), view.at.cs);
    }
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
    // In a followed popup an unknown page is the user's (a consent screen, a second factor).
    if (!this.deps.replan || s.status !== "running" || s.popupTabId !== undefined) return stop();
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
    this.endSeen.delete(tabId);
    this.crossings.delete(tabId);
    for (const [popup, owner] of this.popups) if (owner === tabId) this.popups.delete(popup);
    await this.deps.area.remove([PREFIX + tabId, WAIT_PREFIX + tabId]);
    this.waits.delete(tabId);
  }

  // ---- actions ----

  /**
   * Persist the new state first, then run its actions; a failure stops the chain. A locked vault
   * also asks the app to unlock so the chain can go on from `prev` (`resumeLocked`), unless this
   * step is itself that resume (`mayWait` false: no second request, no loop).
   */
  private async advance(prev: ChainState, r: { state: ChainState; actions: ChainAction[] }, cs: CsContext, mayWait = true): Promise<ChainState> {
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
      if (code === "locked" && mayWait && prev.status === "running") await this.awaitUnlock(prev);
      return n;
    }
  }

  /**
   * The chain stopped `locked` at a step of `prev`: keep `prev` with the top document it stopped
   * in, and have the app asked to unlock (the chain is the continuation of the user's click).
   * Nothing is kept when nothing will wait for it.
   */
  private async awaitUnlock(prev: ChainState): Promise<void> {
    const ask = this.deps.overlays.awaitUnlock;
    if (!ask) return;
    const key = WAIT_PREFIX + prev.tabId;
    try {
      const f = await this.deps.frames.details(prev.tabId, 0);
      const o = f ? parseOrigin(f.url) : null;
      if (!f || !o?.page) return;
      const w: LockedChain = { state: prev, at: this.now(), origin: o.origin };
      const top: CsContext = { tabId: prev.tabId, frameId: 0, origin: o.origin };
      if (f.documentId !== undefined) {
        w.documentId = f.documentId;
        top.documentId = f.documentId;
      }
      // The overlay is where the wait shows and what asks to go on: on this page first (a later
      // page of the chain does not have it yet).
      if (!(await this.showOverlay(top))) return;
      await this.deps.area.set({ [key]: w });
      this.waits.add(prev.tabId);
      if (!(await ask.call(this.deps.overlays, prev.tabId))) await this.dropWait(prev.tabId);
    } catch {
      await this.dropWait(prev.tabId).catch(() => undefined);
    }
  }

  /** Forgets the chain kept for an unlock in `tabId`, if any. */
  private async dropWait(tabId: number): Promise<void> {
    if (!this.waits.delete(tabId) && this.waitsKnown) return;
    await this.deps.area.remove(WAIT_PREFIX + tabId);
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
      case "fill": {
        // Truthful to the bridge: the first fill of a chain the user started by clicking this
        // item's row in the menu is that pick; every other fill is the chain's own.
        const first = s.steps.filter((x) => x.kind === "fill" || x.kind === "otp").length <= 1;
        const ctx = s.pick !== undefined && first ? s.pick : "chain";
        // Nothing to write (the host gave no value for this step): never a submit of an empty form.
        if ((await this.deps.filler.fillLogin(this.target(cs, a.formRef), s.itemId, a.fields, ctx, a.roles)) === 0) throw new BgError("not_found");
        return;
      }
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
  private async showOverlay(cs: CsContext, anchorRef?: string, generic = false): Promise<boolean> {
    try {
      if (!(await this.deps.overlays.hasTab(cs.tabId))) await this.deps.overlays.open(cs, anchorRef, generic);
      return true;
    } catch {
      // Content script not there (yet): the next analysis retries.
      return false;
    }
  }

  /** "Never offer here" for `site`; unreadable: as if set (no card). */
  private async neverOffer(site: string): Promise<boolean> {
    try {
      return (await this.deps.neverOffer?.(site)) === true;
    } catch {
      return true;
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
   * Spec E1: a page with no sign-in form but buttons of known providers
   * offers it too, when a login of the site signs in with one of them (the
   * chain then starts with the click on that button).
   */
  private async offerOverlay(a: PageAnalysis, cs: CsContext): Promise<void> {
    const form = signInShape(a);
    const sso = form === null ? providerShape(a) : null;
    const passkey = form === null && sso === null && a.passkeySignIn === true;
    const shape = form ?? sso?.shape ?? (passkey ? PASSKEY_SHAPE : null);
    if (shape === null || parseOrigin(cs.origin)?.page !== true) return;
    // A passkey-only page: no card of accounts (an open vault offers nothing there), the generic card when locked.
    const offers = sso ? (it: Summary) => signsInWith(it, sso.providers) : passkey ? () => false : canSignIn;
    const seen = this.seen(cs.tabId, cs.documentId ?? `${cs.origin}#${this.navs.get(cs.tabId) ?? 0}`);
    if (seen.closed || seen.shapes.has(shape) || seen.shapes.size >= MAX_OFFERS) return;
    seen.shapes.add(shape);
    // One surface: the user is in the inline menu, which offers the same sign-ins.
    if (await this.deps.menuOpen?.(cs.tabId)) return;
    let shown = true;
    try {
      const { items } = await this.deps.session.request({ op: "list_for_origin", ctx: "overlay", origin: cs.origin });
      if (items.some(offers)) shown = await this.showOverlay(cs);
    } catch (e) {
      // Unpaired, host missing: no overlay. Locked: the vault cannot say who matches, so a
      // generic card (no account, nothing of the vault) whose click unlocks; never where the user
      // set "never offer here".
      shown = false;
      const site = parseOrigin(cs.origin)?.site;
      if (toBgError(e).code === "locked" && site !== undefined && !(await this.neverOffer(site))) shown = await this.showOverlay(cs, undefined, true);
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
    if (s.status !== "running") for (const [popup, owner] of this.popups) if (owner === s.tabId) this.popups.delete(popup);
  }

  /**
   * `done`: the penalty goes, the fill is noted. `repeat`: the site is penalized. So is it after a
   * `captcha` that follows a submit of the chain: the site answered what was sent with its
   * challenge, the next click there fills and sends nothing. Never fails.
   */
  private async ended(s: ChainState): Promise<void> {
    try {
      if (s.status === "done") {
        this.deps.onChain?.(s.tabId, "done");
        await clearPenalty(this.deps.area, s.site);
        const { roles, intent } = noteShape(s);
        await noteFill(this.deps.session, { ctx: "chain", item_id: s.itemId, origin: s.siteOrigin, roles, intent, steps: noteSteps(s) });
      } else if (s.reason === "repeat" || (s.reason === "captcha" && s.steps.some((x) => x.submittedAt !== undefined))) {
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
        if (k.startsWith(WAIT_PREFIX)) {
          const tabId = Number(k.slice(WAIT_PREFIX.length));
          if (Number.isSafeInteger(tabId)) this.waits.add(tabId);
          continue;
        }
        if (!k.startsWith(PREFIX)) continue;
        const s = parseChainState(v);
        if (s?.status === "running") {
          this.mem.set(s.tabId, s);
          if (s.popupTabId !== undefined) this.popups.set(s.popupTabId, s.tabId);
          this.arm(s);
        }
      }
      this.waitsKnown = true;
    } catch {
      // Storage unavailable: the next event re-arms.
    }
  }
}
