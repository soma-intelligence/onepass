// Wiring of the service worker: one session, the pairing flow, menu,
// overlay and save prompt tokens, the fill pipeline, the popup backend, the
// sign-in chain, the save and provider-link proposals, and the router.
//
// Smart fill (Task 10): the content script's `plan_context` (icon click, or
// `smart_fill` from the popup's Fill and the `fill-smart` command) is
// planned and run; "menu" registers the plan's alternatives for the menu the
// content script opens next. The chain's unknown pages are planned again on
// a context the content script replies to `plan_request`. Fills are noted
// for the site memory (notes.ts), the penalty lives in penalty.ts.
//
// One gesture when the vault is locked or the app is not running: the
// gesture's own requests (`fill_salt`, `plan_context`) launch a missing app
// and ask it to unlock at once; the menu the content script opens next is
// linked to that request and resumes its field's plan by itself (`menu_resume`
// on the Mac, the sheet's automatic Face ID on iOS). Nothing but a trusted
// gesture ever opens the app, a resume stays bound to its tab, frame,
// document, https origin and token, and runs once inside `UNLOCK_WAIT_MS`.
//
// One sign-in path: the field icon, the command, the toolbar's Fill, a row of
// the menu and the overlay's account all end in the same chain. The plan
// decides for the first three (planner.ts `signIn`, the bridge's auto-submit
// rules); where it signs nobody in but the page shows the button of the one
// provider the site's login uses, that provider chain starts, as the overlay
// would. The overlay lists first the account the plan would pick. A gesture
// that has no field to open a menu under (a provider-only page, the command)
// and finds the vault locked waits in a card of the page instead.
import { BridgeClient, type Summary } from "../bridge/client";
import { isPage, parseOrigin, sameSite } from "../shared/domain";
import type { BgToCs, FieldRole, FillIntent, PageContext, PlanContextBody, PlanOut, ProviderId } from "../shared/messages";
import type { MenuInit, MenuNotice } from "../shared/ui";
import { UNLOCK_WAIT_MS } from "../shared/unlock";
import { signInChoices } from "./chain/choices";
import { PageAnalyses } from "./analyses";
import { ChainRunner, type CrossVerdict } from "./chain/driver";
import { ProviderFlows } from "./chain/provider-flow";
import { SaveFlow } from "./chain/save-flow";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { BgExt } from "./ext";
import { type FillTarget, Filler, ownerRoles } from "./fill";
import { FormGenerator } from "./generate";
import { AutofillHistory, type BrowserKind, browserKind } from "./history";
import { type CsContext, Frames } from "./frames";
import { KeyRelay, type MenuField, type MenuRecord, MenuTokens } from "./menu";
import { isSafari, openApp as openAppNative, openTransport } from "./native";
import { type NativeVault, type NativeVaultCall, nativeVault } from "./safari";
import { NeverSave } from "./never-save";
import { FillNotes } from "./notes";
import { HostCompat } from "./host-compat";
import { Overlays, type UnlockAsked, removeFrame, resizeFrame } from "./overlay";
import { PairingFlow } from "./pairing";
import { type PasskeyDeps, type PasskeyWindows, Passkeys, createPasskeyRouter } from "./passkey";
import { clearPenalty, hasPenalty, siteOf } from "./penalty";
import { Planner, type PlanOrigins, type RunOutcome, framesFromSender, mainRoles } from "./planner";
import { PopupBackend, alternativesFirst, loginFields, rankedIds } from "./popup";
import { type Handlers, createRouter, parsePlanContextBody } from "./router";
import { type SavePending, SavePrompts } from "./save";
import { type SuggestionRecord, Suggestions } from "./suggest";
import type { ModelSession } from "./model";
import { BgError, type BridgeLike, Session, toBgError } from "./session";
import { IdbPairingStore, type PairingStore, Store } from "./store";

export interface BackgroundOptions {
  /** Pairing record storage; IndexedDB of the extension origin by default. */
  pairings?: PairingStore;
  newClient?: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  browser?: string;
  /** Sign-in chain; the real driver (`ChainRunner`) by default. */
  chain?: ChainDriver;
  /** Brings the app forward (launching it if needed) for an unlock; `openApp` of native.ts by default. */
  openApp?: () => Promise<boolean>;
  /** Browser kind for the autofill history; from `navigator` by default. */
  browserKind?: BrowserKind;
  /**
   * The native vault of the iOS Safari handler (unlock sheet); `nativeVault` of safari.ts in
   * Safari by default, none elsewhere. Null: no native vault (macOS, other browsers).
   */
  nativeVault?: (call: NativeVaultCall) => Promise<NativeVault | null>;
}

/** The browser kind from the worker's `navigator` ("unknown" without one). */
function navigatorKind(): BrowserKind {
  const nav = (globalThis as { navigator?: { userAgent?: string; brave?: unknown; userAgentData?: { brands?: { brand: string }[] } } }).navigator;
  if (!nav || typeof nav.userAgent !== "string") return "unknown";
  return browserKind({ userAgent: nav.userAgent, brave: nav.brave, brands: nav.userAgentData?.brands ?? [] });
}

/** The command of manifests/base.json that runs smart fill in the active tab. */
export const FILL_SMART_COMMAND = "fill-smart";
/** A menu opened this soon after a plan answered "menu" lists that plan's alternatives first. */
export const PLAN_MENU_MS = 30_000;

/** Forms the menu offers sign-ins on (provider methods start the chain there). */
const SIGN_IN_FORMS: ReadonlySet<string> = new Set(["login", "signup", "change_password", "otp"]);
/** Forms where picking a login runs the whole sign-in (chain) rather than a fill of the page. */
const CHAIN_FORMS: ReadonlySet<string> = new Set(["login", "otp"]);
/** Forms where the menu offers to generate a password, items or not. */
const NEW_PASSWORD_FORMS: ReadonlySet<string> = new Set(["signup", "change_password"]);

/** The autofill history's key of the menu of a frame. */
function menuList(tabId: number, frameId: number): string {
  return `menu:${tabId}:${frameId}`;
}

/** The frame a menu was opened in. */
function menuFrame(rec: MenuRecord): CsContext {
  const cs: CsContext = { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin };
  if (rec.documentId !== undefined) cs.documentId = rec.documentId;
  return cs;
}

function targetOf(rec: MenuRecord): FillTarget {
  const t: FillTarget = { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin, formRef: rec.formRef };
  if (rec.documentId !== undefined) t.documentId = rec.documentId;
  return t;
}

/** What a plan that answered "menu" left for the menu of its frame. */
interface PlanForMenu {
  alternatives: string[];
  planned: { roles: FieldRole[]; intent: FillIntent };
  documentId: string | undefined;
  at: number;
  /** The run refused: the page's `pattern` took no generated password. */
  notice?: MenuNotice;
  /** A signup plan whose form can make a passkey: the menu asks password or passkey. */
  signup?: PlanOut;
}

/** A menu may resume its fill this long after its user asked to unlock (Touch ID in the app, the sheet). */
export const RESUME_WINDOW_MS = UNLOCK_WAIT_MS;
/** A menu opened this soon after a gesture that found the vault locked (or no app) is that gesture's menu. */
export const GESTURE_MENU_MS = 10_000;
/** The plan a resume replays reaches the worker within this long: it is no gesture of its own. */
const REPLAY_MS = 10_000;
/** One launch of the app per gesture: its requests come within this long of each other. */
const WAKE_ONCE_MS = 2_000;
/** Per tab and minute: gestures that may bring the app forward (the shape of PASSKEY_WINDOWS_PER_MIN). */
export const APP_ASKS_PER_MIN = 3;
const MINUTE_MS = 60_000;
/** The `unlock` owed after a gesture's launch is sent by that gesture's plan, which follows within this long. */
const UNLOCK_OWED_MS = 20_000;
/** `storage.session` mirror of the unlock requests (`UnlockAsk`): a time and a binding, no secret. */
const ASKED_PREFIX = "unlock:";

/** A gesture that found the vault locked, or no app: what the menu its content script opens next inherits. */
interface LockedGesture {
  documentId: string | undefined;
  /** The field of an icon click; absent for the popup's Fill and the command. */
  fieldRef: string | undefined;
  at: number;
  /** The app got the unlock request (false: still launching, asked once it answers). */
  sent: boolean;
}

/** An unlock asked for a menu, by its token: when, and the frame and document the menu was bound to. */
interface UnlockAsk {
  at: number;
  sent: boolean;
  tabId: number;
  frameId: number;
  origin: string;
  documentId?: string;
}

function parseAsk(raw: unknown): UnlockAsk | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const int = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!int(r.at) || !int(r.tabId) || !int(r.frameId) || typeof r.sent !== "boolean" || typeof r.origin !== "string") return null;
  if (r.documentId !== undefined && typeof r.documentId !== "string") return null;
  const a: UnlockAsk = { at: r.at, sent: r.sent, tabId: r.tabId, frameId: r.frameId, origin: r.origin };
  if (r.documentId !== undefined) a.documentId = r.documentId;
  return a;
}

export function createBackground(ext: BgExt, opts: BackgroundOptions = {}) {
  const now = opts.now ?? Date.now;
  const store = new Store(ext, opts.pairings ?? new IdbPairingStore());
  const newClient = opts.newClient ?? (() => new BridgeClient(openTransport(ext.runtime)));
  const openApp = opts.openApp ?? (() => openAppNative(ext.runtime));
  const vaultOf: (call: NativeVaultCall) => Promise<NativeVault | null> =
    opts.nativeVault ??
    ((call) => {
      const send = ext.runtime.sendNativeMessage;
      if (typeof send !== "function" || !isSafari(ext.runtime)) return Promise.resolve(null);
      return nativeVault({ sendNativeMessage: (app, msg) => send.call(ext.runtime, app, msg) }, call);
    });
  /** A native vault call for the unlock sheet; "invalid" where there is no native vault. */
  const vaultCall = async (call: NativeVaultCall): Promise<NativeVault> => {
    const v = await vaultOf(call);
    if (!v) throw new BgError("invalid");
    return v;
  };
  // Without a pairing, the session first asks the app to pair without a code
  // (spec 2026-11-02-browser-auto-pairing).
  const session: Session = new Session({
    store,
    newClient,
    autoPair: (): Promise<boolean> => pairing.autoPair(),
    ...(opts.sleep ? { sleep: opts.sleep } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  const pairing: PairingFlow = new PairingFlow({
    store,
    session,
    newClient,
    ...(opts.browser ? { browser: opts.browser } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  // One memory of the app's age for every sender of `unlock` and `vaults`.
  const host = new HostCompat(session);
  /** iOS keeps its vault in the Safari handler: its sheet unlocks, there is no app to bring forward. */
  const hasNativeVault = async (): Promise<boolean> => (await vaultOf({ op: "vault_state" }).catch(() => null)) !== null;
  /**
   * The top-frame origin of `tabId` when it is a page (https, or http on a loopback host): what
   * the bridge `unlock` of a gesture in that tab names. Never a child frame's origin.
   */
  const topOrigin = async (tabId: number): Promise<string | undefined> => {
    const f = await frames.details(tabId, 0).catch(() => null);
    const o = f ? parseOrigin(f.url) : null;
    return o?.page ? o.origin : undefined;
  };
  /** The active tab of a focused window (focus: where the browser tells). Unknown: no. */
  const frontTab = async (tabId: number): Promise<boolean> => {
    try {
      const tab = await ext.tabs.get?.(tabId);
      if (tab?.active !== true) return false;
      if (typeof ext.windows?.get !== "function" || typeof tab.windowId !== "number") return true;
      return (await ext.windows.get(tab.windowId))?.focused === true;
    } catch {
      return false;
    }
  };
  /** Per tab: when its gestures were let bring the app forward, within the last minute. */
  const asks = new Map<number, number[]>();
  /**
   * May a gesture of `tabId` bring the app forward (the launch link, the bridge `unlock`)? Only
   * from the active tab of a focused window, APP_ASKS_PER_MIN times a minute per tab: a page that
   * gets clicks out of its user cannot keep pulling the app over the browser, and a tab in the
   * back never does. The requests of one gesture share its grant unless `fresh` (a click of its own).
   */
  const mayAsk = async (tabId: number, fresh = false): Promise<boolean> => {
    const t = now();
    const list = (asks.get(tabId) ?? []).filter((x) => x <= t && t - x < MINUTE_MS);
    asks.set(tabId, list);
    const last = list[list.length - 1];
    if (!fresh && last !== undefined && t - last <= WAKE_ONCE_MS) return true;
    if (list.length >= APP_ASKS_PER_MIN) return false;
    if (!(await frontTab(tabId))) return false;
    list.push(t);
    return true;
  };
  let lastWake: { at: number; done: Promise<boolean> } | undefined;
  /**
   * Brings the app forward on its lock screen, launching it when it is not running. Only ever for
   * a trusted user gesture (the icon, a row or a button of ours, the command): never a page load,
   * a poll or a timer. One launch per gesture (its requests share it) unless `fresh`, a click of
   * its own. False when nothing could open it.
   */
  const wakeApp = (fresh = false): Promise<boolean> => {
    const t = now();
    if (!fresh && lastWake && t >= lastWake.at && t - lastWake.at <= WAKE_ONCE_MS) return lastWake.done;
    const done = (async () => !(await hasNativeVault()) && (await openApp().catch(() => false)))();
    lastWake = { at: t, done };
    return done;
  };
  /**
   * Contract with the Mac app: after a trusted gesture brought it forward (launched through the
   * link, or found locked), the bridge `unlock` goes to it exactly once for that gesture as soon
   * as it answers, even when it is unlocked by then. The app takes it, within 10 s of an unlock
   * done through the launch link, as its cue to hide and give the front back to the browser; the
   * link alone never does. On a vault open before the gesture it is harmless.
   *
   * `unlockOwed`: when the gesture's own requests launched the app; its plan sends the op if
   * nothing else did (the app answered within the gesture and was open already).
   */
  let unlockOwed: { at: number; tabId: number } | undefined;
  /**
   * The bridge `unlock` for a gesture in `tabId`: true while the vault stays locked. It names the
   * tab's top-frame origin (`topOrigin`). Whatever was owed is paid.
   */
  const unlockOp = async (tabId: number): Promise<boolean> => {
    const { locked } = await host.unlock(await topOrigin(tabId));
    unlockOwed = undefined;
    return locked;
  };
  /** The wake of a gesture's requests in `tabId` (`Session.withWake`): launched, its `unlock` is owed. */
  const gestureWake = async (tabId: number): Promise<void> => {
    if (!(await mayAsk(tabId))) return;
    if (await wakeApp()) unlockOwed = { at: now(), tabId };
  };
  /** The app answered the gesture that launched it without being asked to unlock: the op, once. */
  const payUnlockOwed = async (): Promise<void> => {
    const owed = unlockOwed;
    unlockOwed = undefined;
    if (owed === undefined || now() < owed.at || now() - owed.at > UNLOCK_OWED_MS) return;
    await unlockOp(owed.tabId).catch(() => undefined);
  };
  /**
   * After a trusted gesture found the vault locked or the app missing (never on iOS): the app
   * comes forward and is asked to unlock (Touch ID; it gives the front back to the browser once
   * unlocked). "unlocked": open already; "asked": its unlock shows; "launching": opened, not
   * answering yet (the unlock is asked once it does); "failed": neither opened nor reached, or
   * `tabId` may not ask (`mayAsk`: not the tab in front, or too many asks this minute).
   */
  const askAppUnlock = async (tabId: number, fresh = false): Promise<UnlockAsked> => {
    if (!(await mayAsk(tabId, fresh))) return "failed";
    const opened = await wakeApp(fresh);
    try {
      if (!(await unlockOp(tabId))) return "unlocked";
      return opened ? "asked" : "failed";
    } catch {
      return opened ? "launching" : "failed";
    }
  };
  const frames = new Frames(ext.webNavigation);
  // The on-device autofill history of the app (history.ts): reports only.
  const history = new AutofillHistory({ session, area: ext.storage.local, browser: opts.browserKind ?? navigatorKind() });
  const menus = new MenuTokens(store.session, opts.now ?? Date.now);
  const keys = new KeyRelay();
  const filler = new Filler(ext.tabs, frames, session);
  const generator = new FormGenerator({ tabs: ext.tabs, session, area: ext.storage.local });
  const neverSave = new NeverSave(ext.storage.local);
  const analyses = new PageAnalyses(store.session);
  // The overlay starts and stops the chain; the chain shows the overlay.
  const chainRef: { current: ChainDriver | null } = { current: null };
  const lateChain: ChainDriver = {
    start: (...a) => (chainRef.current ? chainRef.current.start(...a) : Promise.resolve()),
    stop: (t) => (chainRef.current ? chainRef.current.stop(t) : Promise.resolve()),
    state: (t, o, d) => (chainRef.current ? chainRef.current.state(t, o, d) : Promise.resolve(null)),
    closed: (t, o, d) => chainRef.current?.closed?.(t, o, d) ?? Promise.resolve(),
    providerOnly: (t, d) => chainRef.current?.providerOnly?.(t, d) ?? Promise.resolve(null),
    providersShown: (t, d) => chainRef.current?.providersShown?.(t, d) ?? Promise.resolve([]),
    acting: (t) => chainRef.current?.acting?.(t) ?? Promise.resolve(null),
  };
  const overlays: Overlays = new Overlays({
    ext,
    area: store.session,
    local: ext.storage.local,
    session,
    chain: lateChain,
    frames,
    // A click on the card: Face ID right there on iOS (the click is the one attempt), the app elsewhere.
    askUnlock: async (tabId) => {
      const state = await vaultOf({ op: "vault_state" }).catch(() => null);
      if (!state) return askAppUnlock(tabId, true);
      if (!state.locked) return "unlocked";
      const after = await vaultOf({ op: "unlock_biometric" }).catch(() => null);
      return after !== null && !after.locked ? "unlocked" : "failed";
    },
    // A chain locked mid-way: the app is asked; on iOS the worker never prompts by itself.
    askUnlockChain: async (tabId) => ((await hasNativeVault()) ? "failed" : askAppUnlock(tabId)),
    unlockOp: (tabId) => unlockOp(tabId),
    resumeChain: (tabId) => (runner ? runner.resumeLocked(tabId) : Promise.resolve(false)),
    resumePage: (rec) => resumePage(rec),
    primary: (tabId, origin, documentId) => primaryLogin(tabId, origin, documentId),
    ...(opts.now ? { now: opts.now } : {}),
  });
  // The chain plans unknown pages; the planner starts chains.
  const plannerRef: { current: Planner | null } = { current: null };
  const notesRef: { current: FillNotes | null } = { current: null };
  const runner: ChainRunner | null = opts.chain
    ? null
    : new ChainRunner({
        ext,
        area: store.session,
        local: ext.storage.local,
        session,
        frames,
        filler,
        analyses,
        overlays: {
          open: (cs, anchor, generic) => overlays.open(cs, anchor, generic),
          hasTab: (t) => overlays.tokens.hasTab(t),
          awaitUnlock: (t) => overlays.awaitUnlock(t),
        },
        neverOffer: (site) => neverSave.has(site),
        cross: (cs, itemId) => crossForChain(cs, itemId),
        menuOpen: (t) => menus.hasTab(t),
        replan: (cs, itemId) => replanForChain(cs, itemId),
        formRoles: (cs, formRef) => pageFormRoles(cs, formRef),
        // One note per fill: a chain notes its own at done.
        onChain: (tabId) => notesRef.current?.forget(tabId),
        ...(opts.now ? { now: opts.now } : {}),
      });
  const chain: ChainDriver = opts.chain ?? (runner as ChainRunner);
  chainRef.current = chain;
  const chainRunning = async (tabId: number) => (runner ? runner.isRunning(tabId) : false);
  const notes = new FillNotes({ session, now });
  notesRef.current = notes;
  const savePrompts = new SavePrompts({
    ext,
    session,
    generator,
    neverSave,
    onSaved: (tabId, origin, itemId) => notes.onSaved(tabId, origin, itemId),
    area: ext.storage.local,
    openApp,
    unlockOrigin: (tabId) => topOrigin(tabId),
    host,
    nativeUnlock: async () => {
      const state = await vaultOf({ op: "vault_state" });
      if (!state) return null;
      if (!state.locked) return true;
      const after = await vaultOf({ op: "unlock_biometric" });
      return after !== null && !after.locked;
    },
    ...(opts.now ? { now: opts.now } : {}),
  });
  // One surface: a save prompt takes the place of an offered overlay (both sit at the top right).
  const saves = {
    open: async (p: SavePending) => {
      await overlays.yieldTo(p.tabId).catch(() => false);
      return savePrompts.open(p);
    },
    recentlyDismissed: (origin: string, key: string) => savePrompts.recentlyDismissed(origin, key),
    /** A new login saved at once (spec 4.1): its toast, or the card, takes the overlay's place too. */
    autoSave: async (p: SavePending) => {
      await overlays.yieldTo(p.tabId).catch(() => false);
      return savePrompts.autoSave(p);
    },
  };
  const saveFlow = new SaveFlow({
    session,
    host,
    saves,
    neverSave,
    topFrame: (t) => frames.details(t, 0),
    chainRunning,
    // A private window keeps the card (spec 4.3); a browser that does not say counts as not private.
    incognito: async (tabId) => (await ext.tabs.get?.(tabId))?.incognito === true,
    ...(opts.now ? { now: opts.now } : {}),
  });
  filler.onFilled = (tabId, origin, kind, itemId) => saveFlow.noteFilled(tabId, origin, kind, itemId);
  const providerFlows = new ProviderFlows({
    area: store.session,
    session,
    saves,
    neverSave,
    chainRunning,
    ...(opts.now ? { now: opts.now } : {}),
  });
  // Suggested passwords held for the ghost and the menu's preview (suggest.ts): memory only.
  const suggestions = new Suggestions({ generator, filler, saveFlow, area: ext.storage.local, ...(opts.now ? { now: opts.now } : {}) });
  /** Menu token to the suggestion its preview row shows (opened from the ghost, or on the menu's first preview). */
  const menuSuggestions = new Map<string, string>();
  session.onLocked(() => {
    saveFlow.clearGenerated();
    suggestions.clear();
    menuSuggestions.clear();
  });
  /** Frames (`tab:frame`) whose last run found every generated password refused by the page. */
  const refusedRuns = new Set<string>();
  const planner = new Planner(session, filler, chain, saveFlow, generator, {
    penalized: (origin) => hasPenalty(store.session, origin),
    onGenerateRefused: (t) => void refusedRuns.add(`${t.tabId}:${t.frameId}`),
    onFilled: async (t, note) => notes.filled(t.tabId, t.origin, note, (await frames.details(t.tabId, 0))?.url ?? null),
    beforePlan: () => history.ensureClient(),
  });
  plannerRef.current = planner;
  /** Smart fill origins of a content script frame; null for a cross-origin child (or an unknown top). */
  const planOrigins = async (from: CsContext) =>
    framesFromSender(from, from.frameId === 0 ? from.origin : await frames.frameOrigin(from.tabId, 0));
  const fillTarget = (cs: CsContext, formRef: string): FillTarget => {
    const t: FillTarget = { tabId: cs.tabId, frameId: cs.frameId, origin: cs.origin, formRef };
    if (cs.documentId !== undefined) t.documentId = cs.documentId;
    if (cs.frameId !== 0) t.sameOriginAsTop = true;
    return t;
  };
  /** The top frame of the tab of `from` when `from` is it, or a child of exactly its origin; null otherwise. */
  const topOf = async (from: CsContext): Promise<CsContext | null> => {
    if (from.frameId === 0) return from;
    const f = await frames.details(from.tabId, 0);
    if (!f || parseOrigin(f.url)?.origin !== from.origin) return null;
    const top: CsContext = { tabId: from.tabId, frameId: 0, origin: from.origin };
    if (f.documentId !== undefined) top.documentId = f.documentId;
    return top;
  };
  /** Top document `top` reads as a sign-in page: a sign-in form (its own, or in a child of its origin), or provider buttons. */
  const signInPageOf = async (top: CsContext): Promise<boolean> => (runner ? runner.signInPage(top.tabId, top.documentId) : false);
  /** Per frame (`tab:frame`): the alternatives of a plan that answered "menu". */
  const planMenus = new Map<string, PlanForMenu>();
  /** Per frame: the gesture that found the vault locked or the app missing, for the menu opened next. */
  const lockedGestures = new Map<string, LockedGesture>();
  /** Per frame: when a resume replayed its menu's plan there (`smart_fill` after an unlock). */
  const replays = new Map<string, number>();
  const replaying = (key: string): boolean => {
    const at = replays.get(key);
    if (at === undefined) return false;
    if (now() >= at && now() - at <= REPLAY_MS) return true;
    replays.delete(key);
    return false;
  };

  /**
   * The one resume after an unlock the user asked for in a menu (MS-03, IOSSAF-02): the menu goes
   * and its own field runs its plan again, in the menu's own frame and document (the content
   * script checks the field and the origin again), so the right form fills, once. Callers check
   * the vault is open. Only within RESUME_WINDOW_MS of the unlock request, and only while that
   * frame still holds the https document of the menu's origin (same document id where the
   * browser gives one): no fill handed to a page that committed meanwhile, none to another frame.
   * False when refused (the menu stays).
   */
  const resumeAfterUnlock = async (rec: MenuRecord, askedAt: number): Promise<boolean> => {
    const t = now();
    if (t < askedAt || t - askedAt > RESUME_WINDOW_MS) return false;
    const f = await frames.details(rec.tabId, rec.frameId);
    const o = f ? parseOrigin(f.url) : null;
    if (!f || !o?.page || o.origin !== rec.origin) return false;
    if (rec.documentId !== undefined && f.documentId !== undefined && f.documentId !== rec.documentId) return false;
    await menus.revokeFrame(rec.tabId, rec.frameId);
    await removeFrame(ext.tabs, rec, "menu");
    // The plan this replays is no new gesture: locked again, it asks nothing.
    replays.set(`${rec.tabId}:${rec.frameId}`, now());
    const msg: BgToCs = { type: "smart_fill", fieldRef: rec.fieldRef, formRef: rec.formRef, origin: rec.origin };
    try {
      await ext.tabs.sendMessage(rec.tabId, msg, rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: rec.frameId });
    } catch {
      // The page went away: nothing to fill.
    }
    return true;
  };

  /**
   * The page context of frame `cs`, asked of its content script
   * (`plan_request`, delivered to that very document) and rebuilt and bounded
   * as a `plan_context` is; null when it does not answer.
   */
  const requestContext = async (cs: CsContext): Promise<PlanContextBody | null> => {
    const msg: BgToCs = { type: "plan_request" };
    const where = cs.documentId !== undefined ? { documentId: cs.documentId } : { frameId: cs.frameId };
    let reply: unknown;
    try {
      reply = await ext.tabs.sendMessage(cs.tabId, msg, where);
    } catch {
      return null;
    }
    const ctx = (reply as { ok?: unknown; context?: unknown } | null | undefined)?.context;
    return ctx === undefined ? null : parsePlanContextBody(ctx);
  };

  /** A plan of frame `cs` on a context its content script replied (no click: nothing typed is hashed). */
  const planWithoutGesture = async (cs: CsContext, from: "popup" | "overlay" | "chain"): Promise<{ t: FillTarget; plan: PlanOut } | null> => {
    const origins: PlanOrigins | null = await planOrigins(cs);
    if (!origins) return null;
    const body = await requestContext(cs);
    if (!body) return null;
    const t = fillTarget(cs, body.forms[0]?.form_ref ?? "");
    const context: PageContext = { ...body, ...origins };
    // `from`: who asks (a running chain for an unknown page or a host it left for, the card for its first account, the popup for its line).
    return { t, plan: await planner.plan(t, context, from) };
  };

  /** Roles of form `formRef` in frame `cs` as the bridge's `main_roles` reads them (visible, with a role, page order). */
  async function pageFormRoles(cs: CsContext, formRef: string): Promise<FieldRole[] | null> {
    const body = await requestContext(cs);
    const f = body?.forms.find((x) => x.form_ref === formRef);
    return f ? mainRoles(body as PlanContextBody, [{ form_ref: formRef, kind: "login", item_id: null, fields: [] }]) : null;
  }

  /** Spec 5.3: a chain's unknown page planned again; the plan's login group of the chain's item, if any. */
  async function replanForChain(cs: CsContext, itemId: string) {
    if (!plannerRef.current) return null;
    const r = await planWithoutGesture(cs, "chain");
    if (!r || (r.plan.intent !== "login" && r.plan.intent !== "otp")) return null;
    const g = r.plan.groups.find((x) => x.kind === "login" && x.item_id === itemId && x.fields.length > 0);
    if (!g) return null;
    const f = await frames.details(cs.tabId, cs.frameId);
    if (!f) return null;
    return { formRef: g.form_ref, roles: g.fields.map((x) => x.role), submit: planner.submits(r.t, r.plan), url: f.url };
  }

  /** Spec 6: where a chain left its site for, what the bridge's plan of that page says of the chain's own item. */
  async function crossForChain(cs: CsContext, itemId: string): Promise<CrossVerdict> {
    if (!plannerRef.current || cs.frameId !== 0 || parseOrigin(cs.origin)?.https !== true) return "no";
    const r = await planWithoutGesture(cs, "chain");
    if (!r) return "no";
    const mine = r.plan.groups.some((g) => g.kind === "login" && g.item_id === itemId && g.fields.length > 0);
    // Offered there through Apple's shared-credentials list only: never without the user picking it.
    if (r.plan.reasons.includes("associated_domain")) return mine || r.plan.alternatives.includes(itemId) ? "first_use" : "no";
    // A normal match the plan itself would send there (every guard of the planner passed).
    return mine && (r.plan.intent === "login" || r.plan.intent === "otp") && plannerRef.current.submits(r.t, r.plan) ? "match" : "no";
  }

  /** The frame of `tabId` a gesture without a field runs smart fill in: the one a sign-in would act in (spec C1), else the top frame. */
  const gestureFrame = async (tabId: number): Promise<{ frameId: number; documentId?: string } | null> => {
    const f = await frames.details(tabId, 0);
    if (!f || parseOrigin(f.url)?.page !== true) return null;
    const at = await chain.acting?.(tabId).catch(() => null);
    if (at && at.frameId !== 0) return at.documentId !== undefined ? { frameId: at.frameId, documentId: at.documentId } : { frameId: at.frameId };
    const top = f.documentId !== undefined ? { frameId: 0, documentId: f.documentId } : { frameId: 0 };
    // The top frame holds no form at all: the first child frame of exactly its origin that holds
    // one (an identity or card form in a frame of the site), each frame up to it of that origin too.
    const origin = parseOrigin(f.url)?.origin;
    const own = await analyses.top(tabId);
    if (origin === undefined || !own || own.origin !== origin || own.analysis.forms.length > 0) return top;
    for (const c of await analyses.children(tabId)) {
      if (c.origin !== origin || c.analysis.forms.length === 0) continue;
      const cf = await frames.details(tabId, c.frameId);
      if (!cf || parseOrigin(cf.url)?.origin !== origin) continue;
      if (c.documentId !== undefined && cf.documentId !== undefined && c.documentId !== cf.documentId) continue;
      if (!(await frames.ancestorsOfOrigin(tabId, c.frameId, origin))) continue;
      const doc = c.documentId ?? cf.documentId;
      return doc !== undefined ? { frameId: c.frameId, documentId: doc } : { frameId: c.frameId };
    }
    return top;
  };

  /**
   * A gesture without a field on a top document with no form (a passkey-only sign-in page): when
   * the vault holds passkeys of exactly one login for this site, that item is armed for the
   * page's next passkey request (passkey.ts `armGet`) and the page's one passkey sign-in button
   * is pressed. False (nothing armed) when the vault has none or several accounts to choose
   * from, or the page has no such button: the user presses it and picks in the window as ever.
   */
  async function passkeySignIn(from: CsContext): Promise<boolean> {
    const o = parseOrigin(from.origin);
    if (from.frameId !== 0 || !o?.https) return false;
    const items = new Set<string>();
    // The page may ask under its host or its registrable domain: both are looked at.
    for (const rpId of new Set([o.host, o.site])) {
      try {
        for (const p of (await session.request({ op: "passkey_list", ctx: "passkey", origin: o.origin, rp_id: rpId })).passkeys) items.add(p.item_id);
      } catch (e) {
        // A locked vault is the gesture's to handle; an rpId the host refuses lists nothing.
        if (toBgError(e).code === "locked" || toBgError(e).code === "host_missing") throw e;
      }
    }
    const [itemId] = [...items];
    if (items.size !== 1 || itemId === undefined) return false;
    passkeys.armGet(from, itemId);
    const msg: BgToCs = { type: "click_passkey_signin", origin: o.origin };
    let reply: unknown;
    try {
      reply = await ext.tabs.sendMessage(from.tabId, msg, from.documentId !== undefined ? { documentId: from.documentId } : { frameId: 0 });
    } catch {
      reply = null;
    }
    if ((reply as { ok?: unknown } | null | undefined)?.ok === true) return true;
    passkeys.disarmGet(from.tabId);
    return false;
  }

  /** The popup's Fill and the command: the tab's page runs smart fill as if its user clicked (in the frame that holds its sign-in form). */
  const smartFillTab = async (tabId: number): Promise<void> => {
    const at = await gestureFrame(tabId);
    if (!at) throw new BgError("insecure_origin");
    const msg: BgToCs = { type: "smart_fill" };
    await ext.tabs.sendMessage(tabId, msg, at.documentId !== undefined ? { documentId: at.documentId } : { frameId: at.frameId });
  };

  /**
   * The unlock a card asked for its page ended (overlay.ts, which checked the card's document):
   * the page runs smart fill as the gesture that asked would have. The plan it sends is that
   * gesture resumed, not a new one: it asks the app nothing. Bound to the card's record: the top
   * frame must still hold its origin and its document (where the browser names it), the message
   * goes to that document, and it carries the origin for the content script to check again. A
   * page committed in between gets nothing.
   */
  async function resumePage(rec: { tabId: number; origin: string; documentId?: string }): Promise<void> {
    const tabId = rec.tabId;
    const at = await gestureFrame(tabId);
    if (!at) return;
    const check = await frames.checkFillTarget(tabId, 0, rec.origin, rec.documentId);
    if (!check.ok) return;
    // A child frame the sign-in acts in is of exactly the top frame's origin (`gestureFrame`).
    const doc = at.frameId === 0 ? (rec.documentId ?? at.documentId) : at.documentId;
    replays.set(`${tabId}:${at.frameId}`, now());
    const msg: BgToCs = { type: "smart_fill", origin: rec.origin };
    try {
      await ext.tabs.sendMessage(tabId, msg, doc !== undefined ? { documentId: doc } : { frameId: at.frameId });
    } catch {
      // The page went away: nothing to fill.
    }
  }

  /** The login the page's plan would sign in with in top document `documentId` of `tabId` (the overlay's first account). */
  async function primaryLogin(tabId: number, origin: string, documentId: string | undefined): Promise<string | null> {
    if (!plannerRef.current) return null;
    const f = await frames.details(tabId, 0);
    if (!f || parseOrigin(f.url)?.origin !== origin) return null;
    if (documentId !== undefined && f.documentId !== undefined && f.documentId !== documentId) return null;
    const at = (await chain.acting?.(tabId).catch(() => null)) ?? null;
    const cs: CsContext = at ?? { tabId, frameId: 0, origin, ...(f.documentId !== undefined ? { documentId: f.documentId } : {}) };
    const r = await planWithoutGesture(cs, "overlay");
    return r ? (plannerRef.current.signIn(r.t, r.plan)?.itemId ?? null) : null;
  }
  const popup = new PopupBackend({
    ext,
    area: store.session,
    session,
    host,
    pairing,
    openApp,
    nativeVault: vaultCall,
    filler,
    analyses,
    onLock: () => saveFlow.clearGenerated(),
    generator,
    onGenerated: async (t, kind, g) => {
      saveFlow.rememberGenerated(t.tabId, t.origin, g.password);
      // A signup form: in the vault before it is sent (spec 7.1), as from the planner.
      if (kind === "signup") await saveFlow.savePending(t.tabId, t.origin, g.password, { weak: g.report?.weak_by_site === true });
    },
    plan: async (tabId, origin) => {
      const f = await frames.details(tabId, 0);
      if (!f || parseOrigin(f.url)?.origin !== origin) return null;
      const cs: CsContext = { tabId, frameId: 0, origin };
      if (f.documentId !== undefined) cs.documentId = f.documentId;
      return (await planWithoutGesture(cs, "popup"))?.plan ?? null;
    },
    smartFill: smartFillTab,
    history,
    onForgetSite: async (origin) => {
      // The computed site and the raw host: whichever key the chain filed the penalty under.
      const keys = new Set<string>();
      const site = siteOf(origin);
      if (site !== null) keys.add(site);
      const host = parseOrigin(origin)?.host;
      if (host !== undefined) keys.add(host);
      for (const k of keys) await clearPenalty(store.session, k);
    },
    ...(opts.now ? { now: opts.now } : {}),
  });

  /** The menu would list something for this form on `origin` (locked, unpaired: no). */
  const offersAnything = async (origin: string, formKind: string): Promise<boolean> => {
    try {
      if (formKind === "card" || formKind === "identity" || formKind === "address") {
        const kind = formKind === "card" ? "card" : "identity";
        return (await session.request({ op: "list_fillable", ctx: "menu", origin, kind })).items.length > 0;
      }
      return (await session.request({ op: "list_for_origin", ctx: "menu", origin })).items.length > 0;
    } catch {
      return false;
    }
  };

  const menuRecord = async (token: string, from: Parameters<MenuTokens["resolve"]>[1]): Promise<MenuRecord> => {
    const rec = await menus.resolve(token, from);
    if (!rec) throw new BgError("invalid");
    return rec;
  };

  /**
   * Unlocks asked for a menu (MS-03, Touch ID on the Mac), by token: by the gesture that opened
   * it on a locked vault, or by its button. Once unlocked, the menu may resume the fill once
   * (`menu_resume`; on iOS the sheet's unlock resumes in its own call). Mirrored in
   * `storage.session` so a worker restarted during the wait still knows the request: its time and
   * the menu's binding only, never a secret.
   */
  const unlockAsked = new Map<string, UnlockAsk>();
  const askExpired = (a: UnlockAsk): boolean => now() < a.at || now() - a.at > RESUME_WINDOW_MS;
  const dropAsked = async (token: string): Promise<void> => {
    unlockAsked.delete(token);
    await store.session.remove(ASKED_PREFIX + token).catch(() => undefined);
  };
  const askedUnlock = async (token: string, rec: Pick<MenuRecord, "tabId" | "frameId" | "origin" | "documentId">, at: number, sent: boolean): Promise<void> => {
    for (const [t, a] of unlockAsked) if (askExpired(a)) unlockAsked.delete(t);
    const ask: UnlockAsk = { at, sent, tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin };
    if (rec.documentId !== undefined) ask.documentId = rec.documentId;
    unlockAsked.set(token, ask);
    try {
      // Requests left by menus long gone.
      const stale: string[] = [];
      for (const [k, v] of Object.entries(await store.session.get(null))) {
        if (!k.startsWith(ASKED_PREFIX)) continue;
        const a = parseAsk(v);
        if (!a || askExpired(a)) stale.push(k);
      }
      if (stale.length > 0) await store.session.remove(stale);
      await store.session.set({ [ASKED_PREFIX + token]: ask });
    } catch {
      // No session storage: the request lives as long as this worker.
    }
  };
  /** The live unlock request of the menu `rec` of `token`: in time, and bound to that very menu. */
  const askedFor = async (token: string, rec: MenuRecord): Promise<UnlockAsk | null> => {
    let a = unlockAsked.get(token) ?? null;
    if (!a) {
      try {
        a = parseAsk((await store.session.get(ASKED_PREFIX + token))[ASKED_PREFIX + token]);
      } catch {
        a = null;
      }
    }
    if (!a) return null;
    const bound = a.tabId === rec.tabId && a.frameId === rec.frameId && a.origin === rec.origin && a.documentId === rec.documentId;
    if (!bound || askExpired(a)) {
      await dropAsked(token);
      return null;
    }
    unlockAsked.set(token, a);
    return a;
  };
  /** Tokens whose resume is being decided: a second call meanwhile waits its turn (one attempt). */
  const resuming = new Set<string>();

  /** The owner's roles of the menu's form in the frame's last analysis (same origin), if known. */
  const formRolesOf = async (rec: MenuRecord): Promise<FieldRole[] | undefined> => {
    const a =
      rec.frameId === 0
        ? await analyses.top(rec.tabId)
        : (await analyses.children(rec.tabId)).find((x) => x.frameId === rec.frameId);
    if (!a || a.origin !== rec.origin) return undefined;
    const form = a.analysis.forms.find((f) => f.ref === rec.formRef);
    return form ? ownerRoles(form) : undefined;
  };

  /** The suggestion record of a menu's field; a planned signup counts as one. */
  const suggestionOf = (rec: MenuRecord): SuggestionRecord => {
    const s: SuggestionRecord = {
      tabId: rec.tabId,
      frameId: rec.frameId,
      origin: rec.origin,
      formKind: rec.planned?.intent === "signup" ? "signup" : rec.formKind,
      fieldRef: rec.fieldRef,
    };
    if (rec.documentId !== undefined) s.documentId = rec.documentId;
    return s;
  };
  /** The live suggestion of the menu `token`, opened now when it has none (the menu shown instead of the ghost). */
  const menuSuggestion = async (token: string, rec: MenuRecord): Promise<string> => {
    const held = menuSuggestions.get(token);
    if (held !== undefined && suggestions.recordOf(held)) return held;
    const opened = await suggestions.open(targetOf(rec), suggestionOf(rec));
    if (!opened) throw new BgError("site_refused");
    for (const [m, st] of menuSuggestions) if (!suggestions.recordOf(st)) menuSuggestions.delete(m);
    menuSuggestions.set(token, opened.token);
    return opened.token;
  };
  /** Sends `msg` to the exact frame (document when known) of a suggestion; a gone document gets nothing. */
  const sendToFrame = async (rec: Pick<SuggestionRecord, "tabId" | "frameId" | "documentId">, msg: BgToCs): Promise<void> => {
    const to = rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: rec.frameId };
    try {
      await ext.tabs.sendMessage(rec.tabId, msg, to);
    } catch {
      // Document gone: nothing to show there.
    }
  };
  /** The suggestion the ghost of this content script's frame shows, bound to its document and origin. */
  const frameSuggestion = (from: CsContext): string => {
    const token = suggestions.forFrame(from.tabId, from.frameId, from.documentId);
    if (token === null || suggestions.recordOf(token)?.origin !== from.origin) throw new BgError("invalid");
    return token;
  };

  const handlers: Handlers = {
    cs: {
      page_analysis: async (m, from) => {
        await analyses.record(m.analysis, from);
        return {};
      },
      open_menu: async (m, from) => {
        if (!isPage(from.origin)) throw new BgError("insecure_origin");
        // A click into the field opens the menu only when it has something to offer there.
        if (m.auto && !NEW_PASSWORD_FORMS.has(m.formKind) && !(await offersAnything(from.origin, m.formKind))) throw new BgError("not_found");
        // One surface: the menu replaces an offered overlay; a running chain keeps the page.
        if (await overlays.yieldTo(from.tabId)) throw new BgError("not_allowed");
        const field: MenuField = { formRef: m.formRef, fieldRef: m.fieldRef, formKind: m.formKind };
        // Right after a plan of this very document answered "menu": its alternatives first.
        const key = `${from.tabId}:${from.frameId}`;
        const left = m.auto ? undefined : planMenus.get(key);
        // An auto menu (click into the field) leaves it for the gesture's own menu.
        if (!m.auto) planMenus.delete(key);
        if (left && now() - left.at <= PLAN_MENU_MS && left.documentId === from.documentId) {
          field.first = left.alternatives;
          field.planned = left.planned;
          if (left.notice) field.notice = left.notice;
          if (left.signup) field.signup = left.signup;
        }
        // Right after a gesture of this very document found the vault locked or the app missing:
        // its menu, which waits for the unlock already asked and resumes by itself (once).
        const gesture = m.auto ? undefined : lockedGestures.get(key);
        if (!m.auto) lockedGestures.delete(key);
        const token = await menus.register(from, field);
        if (
          gesture &&
          now() >= gesture.at &&
          now() - gesture.at <= GESTURE_MENU_MS &&
          gesture.documentId === from.documentId &&
          (gesture.fieldRef === undefined || gesture.fieldRef === m.fieldRef)
        ) {
          await askedUnlock(token, from, gesture.at, gesture.sent);
        }
        return { url: `${ext.runtime.getURL("menu.html")}#${token}` };
      },
      close_menu: async (_m, from) => {
        void history.dismissed(menuList(from.tabId, from.frameId));
        await menus.revokeFrame(from.tabId, from.frameId);
      },
      submitted_credentials: async (m, from) => {
        await saveFlow.onSubmitted(m, from);
        return {};
      },
      submitted_identifier: async (m, from) => {
        saveFlow.onIdentifier(m, from);
        return {};
      },
      submitted_form: async (m, from) => {
        saveFlow.onForm(m, from);
        return {};
      },
      provider_click: async (m, from) => {
        await providerFlows.onProviderClick(from, m.provider);
        return {};
      },
      account_click: async (m, from) => {
        await providerFlows.onAccountClick(from, m.email);
        return {};
      },
      fill_salt: async (_m, from) => {
        if (!isPage(from.origin)) throw new BgError("insecure_origin");
        if (!(await planOrigins(from))) throw new BgError("cross_site_frame");
        // The first request of a gesture (never sent otherwise): a missing app is launched for it.
        const salt = () => session.fillSalt();
        return { salt: await (replaying(`${from.tabId}:${from.frameId}`) ? salt() : session.withWake(() => gestureWake(from.tabId), salt)) };
      },
      plan_context: async (m, from) => {
        if (!isPage(from.origin)) throw new BgError("insecure_origin");
        const origins = await planOrigins(from);
        // A cross-origin child frame gets no plan: the menu, as before.
        if (!origins) return { outcome: "menu" };
        const key = `${from.tabId}:${from.frameId}`;
        const attempt = async (): Promise<{ outcome: RunOutcome }> => {
          const t = fillTarget(from, m.formRef ?? m.context.forms[0]?.form_ref ?? "");
          const plan = await planner.plan(t, { ...m.context, ...origins });
          const run: { form?: string; anchorRef?: string } = {};
          // An icon click: its form only (the popup and the command run the whole plan).
          if (m.formRef !== undefined) run.form = m.formRef;
          if (m.fieldRef !== undefined) run.anchorRef = m.fieldRef;
          refusedRuns.delete(key);
          let outcome = await planner.run(t, plan, run);
          // The plan signs nobody in, on a sign-in page or one without a form: the overlay's one
          // sign-in through a provider whose button the page shows, if there is exactly one way.
          const signInPage = plan.intent === "login" || m.context.forms.length === 0;
          if ((outcome === "nothing" || outcome === "menu") && signInPage) {
            const top = await topOf(from);
            // A way it cannot take (an account the provider no longer has, a refusal): the plan's own answer stands.
            if (top && (await overlays.providerSignIn(top).catch(() => false))) outcome = "chain";
          }
          // Still nothing, on a page without a form, for a gesture without a field: its passkey sign-in.
          if (outcome === "nothing" && m.formRef === undefined && m.context.forms.length === 0 && (await passkeySignIn(from).catch(() => false))) outcome = "filled";
          // A login the plan wrote without sending it: the page's passkey step, if it has one, signs with that item (once, in this document).
          const wrote = outcome === "filled" ? plan.groups.find((g) => g.kind === "login" && g.item_id !== null && (run.form === undefined || g.form_ref === run.form)) : undefined;
          if (wrote?.item_id && from.frameId === 0) passkeys.armGet(from, wrote.item_id);
          const refused = refusedRuns.delete(key);
          if (outcome === "menu") {
            const ctx = planner.contextOf(plan);
            const left: PlanForMenu = {
              alternatives: rankedIds(plan).slice(0, 8),
              planned: { roles: ctx ? mainRoles(ctx, plan.groups) : [], intent: plan.intent },
              documentId: from.documentId,
              at: now(),
            };
            if (refused) left.notice = "site_refused";
            if (plan.intent === "signup" && plan.passkey) left.signup = plan;
            planMenus.set(key, left);
          }
          return { outcome };
        };
        lockedGestures.delete(key);
        // The plan a resume replays after its unlock: no gesture of its own, it asks nothing.
        if (replaying(key)) {
          replays.delete(key);
          return attempt();
        }
        try {
          const done = await session.withWake(() => gestureWake(from.tabId), attempt);
          // Launched by this gesture and open when it answered: its `unlock` still goes, once.
          await payUnlockOwed();
          return done;
        } catch (e) {
          const code = toBgError(e).code;
          if (code !== "locked" && code !== "host_missing") {
            await payUnlockOwed();
            throw e;
          }
          // The gesture found the vault locked, or no app (launched above): the unlock is asked
          // now, not by a second click, and the menu the content script opens next waits for it.
          const gesture: LockedGesture = { documentId: from.documentId, fieldRef: m.fieldRef, at: now(), sent: true };
          if (await hasNativeVault()) {
            // iOS: the menu's sheet unlocks (Face ID by itself, once) and carries this fill.
            if (code === "locked") lockedGestures.set(key, gesture);
            throw e;
          }
          const asked = await askAppUnlock(from.tabId);
          // Sent just now, or carried by the gesture's menu (`sent` false) until the app answers.
          unlockOwed = undefined;
          if (asked === "unlocked") return attempt();
          // Not opened: no waiting state, the menu keeps its button.
          if (asked === "failed") throw e;
          if (m.bare === true) {
            // No field here to open a menu under: on a sign-in page a card waits and runs the
            // page's plan after the unlock; on any other page nothing shows.
            const top = await topOf(from);
            if (top && (await signInPageOf(top))) await overlays.pageWait(top, gesture.at, asked === "asked").catch(() => undefined);
          } else lockedGestures.set(key, { ...gesture, sent: asked === "asked" });
          throw e;
        }
      },
      ghost_open: async (m, from) => {
        if (!isPage(from.origin)) throw new BgError("insecure_origin");
        // Spec 3.1: a new password on a signup or change-password form only.
        if (!NEW_PASSWORD_FORMS.has(m.formKind)) throw new BgError("invalid");
        // A cross-origin child frame gets the menu instead (spec 3.4).
        if (!(await topOf(from))) throw new BgError("cross_site_frame");
        const rec: SuggestionRecord = { tabId: from.tabId, frameId: from.frameId, origin: from.origin, formKind: m.formKind, fieldRef: m.fieldRef, metrics: m.metrics };
        if (from.documentId !== undefined) rec.documentId = from.documentId;
        const opened = await suggestions.open(fillTarget(from, m.formRef), rec);
        if (!opened) throw new BgError("site_refused");
        return { url: `${ext.runtime.getURL("ghost.html")}#${opened.token}` };
      },
      ghost_accept: async (_m, from) => {
        // Tab or Enter in the field while its ghost shows (trusted keys, read by the content script).
        await suggestions.accept(frameSuggestion(from));
        return {};
      },
      ghost_dismiss: async (_m, from) => {
        const token = suggestions.forFrame(from.tabId, from.frameId, from.documentId);
        if (token !== null) suggestions.dismiss(token);
        return {};
      },
      ghost_menu: async (_m, from) => {
        // The ghost goes, the menu opens on its suggestion (the same password, previewed).
        const held = frameSuggestion(from);
        const rec = suggestions.recordOf(held);
        if (!rec?.fieldRef) throw new BgError("invalid");
        const token = await menus.register(from, { formRef: rec.formRef, fieldRef: rec.fieldRef, formKind: rec.formKind });
        menuSuggestions.set(token, held);
        return { url: `${ext.runtime.getURL("menu.html")}#${token}` };
      },
      menu_key: async (m, from) => {
        // Only to the menu of this very frame (and document).
        const token = await menus.forFrame(from.tabId, from.frameId, from.documentId);
        if (token) keys.push(token, m.key);
        return {};
      },
    },
    ui: {
      menu_init: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        let items: Summary[];
        if (rec.formKind === "card" || rec.formKind === "identity" || rec.formKind === "address") {
          const kind = rec.formKind === "card" ? "card" : "identity";
          items = (await session.request({ op: "list_fillable", ctx: "menu", origin: rec.origin, kind })).items;
        } else {
          items = (await session.request({ op: "list_for_origin", ctx: "menu", origin: rec.origin })).items;
        }
        // The gesture that opened this menu asked the app to unlock, and the vault is open by its
        // first look (a fast Touch ID): the gesture's own fill resumes now, there is no row to pick.
        const asked = resuming.has(m.token) ? null : await askedFor(m.token, rec);
        if (asked) {
          resuming.add(m.token);
          try {
            // Launched by that gesture and never asked since: its `unlock` still goes, once.
            if (!asked.sent) await unlockOp(rec.tabId).catch(() => undefined);
            await dropAsked(m.token);
            if (await resumeAfterUnlock(rec, asked.at)) return { origin: rec.origin, formKind: rec.formKind, items: [] } satisfies MenuInit;
          } finally {
            resuming.delete(m.token);
          }
        }
        // Opened after a plan that could not choose: its alternatives first, the best on top.
        if (rec.first && rec.first.length > 0) items = alternativesFirst(items, rec.first);
        const out: MenuInit = { origin: rec.origin, formKind: rec.formKind, items };
        const best = rec.first?.[0];
        if (best !== undefined && items[0]?.item_id === best) out.best = best;
        if (rec.notice) out.notice = rec.notice;
        // One-click signup: password or passkey, asked first.
        if (rec.signup?.passkey && rec.frameId === 0) out.signup = { passkey: true };
        // On a provider's pages during a sign-in to a site: the account linked to it.
        const flow = rec.frameId === 0 ? await providerFlows.signingInto(rec.tabId, rec.origin) : null;
        if (flow) {
          try {
            const r = await session.request({ op: "provider_accounts", ctx: "menu", provider: flow.provider, origin: flow.siteOrigin });
            if (r.linked_item_id !== undefined && items.some((x) => x.item_id === r.linked_item_id)) {
              out.linked = { itemId: r.linked_item_id, site: parseOrigin(flow.siteOrigin)?.site ?? flow.siteOrigin };
            }
          } catch {
            // No highlight.
          }
        }
        // Sign-in forms: which provider account each method uses, and the others (inline picker).
        const accounts: Record<string, string[]> = {};
        if (!flow && SIGN_IN_FORMS.has(rec.formKind) && items.some((x) => x.methods.length > 0)) {
          out.choices = await signInChoices(session, ext.storage.local, "menu", rec.origin, items);
          for (const c of out.choices) {
            const ids = (accounts[c.provider] ??= []);
            for (const a of c.accounts) if (!ids.includes(a.itemId)) ids.push(a.itemId);
          }
        }
        const offered: Record<string, Summary["kind"]> = {};
        const methods: Record<string, ProviderId[]> = {};
        for (const it of items) {
          offered[it.item_id] = it.kind;
          methods[it.item_id] = it.methods.map((x) => x.provider);
        }
        await menus.setOffered(m.token, offered, methods, accounts);
        void history.shown(menuList(rec.tabId, rec.frameId), "menu", rec.origin, items.map((x) => x.item_id));
        return out;
      },
      menu_pick: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        // Only an item the menu showed; its kind comes from the host.
        const kind = rec.offered && Object.hasOwn(rec.offered, m.itemId) ? rec.offered[m.itemId] : undefined;
        // A login on a sign-in form of the top document: the sign-in runs to its
        // end (identifier, password, code), as the overlay's button does; a fill
        // of the one page left the user on the next step. Where no chain can run
        // (an http page, an item without a password), the fill as before.
        // The menu's frame: the top frame, or a child of exactly its origin (decided like it).
        const top = kind === "login" && CHAIN_FORMS.has(rec.formKind) ? await topOf(menuFrame(rec)) : null;
        if (top) {
          // Still the document the menu was opened in (as the fill checks it).
          const check = await frames.checkFillTarget(rec.tabId, rec.frameId, rec.origin, rec.documentId, "same_origin");
          if (!check.ok) throw new BgError(check.code);
          await menus.revokeFrame(rec.tabId, rec.frameId);
          await removeFrame(ext.tabs, rec, "menu");
          const start: StartOptions = rec.frameId === 0 ? { anchorRef: rec.fieldRef } : {};
          if (rec.planned) start.planned = rec.planned;
          // The row the user clicked: the chain's first fill is this pick.
          start.picked = "menu";
          try {
            // Locked, or no app: asked at once, and a card waits where the menu was.
            await overlays.signIn(top, m.itemId, undefined, start);
            return {};
          } catch (e) {
            const code = toBgError(e).code;
            if (code !== "insecure_origin" && code !== "invalid") throw e;
          }
        }
        const t = targetOf(rec);
        // The choice and its rank, before the fill (a close racing it is no dismissal).
        if (kind !== undefined) void history.picked(menuList(rec.tabId, rec.frameId), m.itemId);
        let written: number;
        if (kind === "login") written = await filler.fillLogin(t, m.itemId, loginFields(rec.formKind));
        else if (kind === "card") written = await filler.fillCard(t, m.itemId);
        else if (kind === "identity") {
          // The documents and loyalty the menu's form asks (its owner's roles in the last analysis).
          const roles = await formRolesOf(rec);
          if (roles) t.formRoles = roles;
          written = await filler.fillIdentity(t, m.itemId);
        }
        else throw new BgError("invalid");
        // A pick in a menu a plan opened: the site memory learns it once the page moves on.
        if (rec.planned && written > 0) {
          notes.filled(rec.tabId, rec.origin, { items: [m.itemId], ...rec.planned }, (await frames.details(rec.tabId, 0))?.url ?? null);
        }
        return {};
      },
      menu_generate: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        // The suggestion the menu previews: that very password is filled (and saved).
        const held = menuSuggestions.get(m.token);
        if (held !== undefined && suggestions.recordOf(held)) {
          menuSuggestions.delete(m.token);
          await suggestions.accept(held, { signup: rec.planned?.intent === "signup" });
          return {};
        }
        const t = targetOf(rec);
        // The page's rules for the menu's form; a page that refuses all three: nothing filled.
        const g = await generator.generateForForm(t, "menu");
        if (g === null) throw new BgError("site_refused");
        await filler.fillGenerated(t, g.password);
        saveFlow.rememberGenerated(rec.tabId, rec.origin, g.password);
        // A signup form: in the vault before it is sent (spec 7.1), as from the planner.
        const intent = rec.planned?.intent ?? (rec.formKind === "signup" ? "signup" : undefined);
        if (intent === "signup") await saveFlow.savePending(rec.tabId, rec.origin, g.password, { weak: g.report?.weak_by_site === true });
        return {};
      },
      menu_preview: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const p = suggestions.preview(await menuSuggestion(m.token, rec), from);
        if (!p) throw new BgError("invalid");
        return p;
      },
      menu_regenerate: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const st = await menuSuggestion(m.token, rec);
        if (!(await suggestions.regenerate(st))) throw new BgError("site_refused");
        const p = suggestions.preview(st, from);
        if (!p) throw new BgError("invalid");
        return p;
      },
      menu_profile: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const st = await menuSuggestion(m.token, rec);
        if (!(await suggestions.setProfile(st, m.length, m.symbols))) throw new BgError("site_refused");
        const p = suggestions.preview(st, from);
        if (!p) throw new BgError("invalid");
        return p;
      },
      ghost_init: async (m, from) => {
        const p = suggestions.preview(m.token, from);
        const metrics = suggestions.metrics(m.token);
        if (!p || !metrics) throw new BgError("invalid");
        return { ...p, metrics };
      },
      ghost_accept: async (m, from) => {
        // The ghost's "Use" pill: only the ghost page of the suggestion's own tab.
        if (!suggestions.peek(m.token, from)) throw new BgError("invalid");
        const rec = suggestions.recordOf(m.token);
        await suggestions.accept(m.token);
        // Filled: the ghost has nothing left to show over the field.
        if (rec) await removeFrame(ext.tabs, rec, "ghost");
        return {};
      },
      ghost_menu: async (m, from) => {
        // The ghost's chevron: the ghost goes, the menu opens at its field on the same suggestion.
        if (!suggestions.peek(m.token, from)) throw new BgError("invalid");
        const rec = suggestions.recordOf(m.token);
        if (!rec?.fieldRef) throw new BgError("invalid");
        const cs: CsContext = { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin };
        if (rec.documentId !== undefined) cs.documentId = rec.documentId;
        const token = await menus.register(cs, { formRef: rec.formRef, fieldRef: rec.fieldRef, formKind: rec.formKind });
        menuSuggestions.set(token, m.token);
        await removeFrame(ext.tabs, rec, "ghost");
        await sendToFrame(rec, { type: "show_frame", kind: "menu", url: `${ext.runtime.getURL("menu.html")}#${token}`, ref: rec.fieldRef });
        return {};
      },
      ghost_pill: async (m, from) => {
        // The pill's box, to the content script of the ghost's own frame (pointer pass-through).
        if (!suggestions.peek(m.token, from)) throw new BgError("invalid");
        const rec = suggestions.recordOf(m.token);
        if (!rec) throw new BgError("invalid");
        await sendToFrame(rec, { type: "ghost_pill", rect: m.rect, over: m.over });
        return {};
      },
      menu_signup: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const plan = rec.signup;
        const offer = plan?.passkey;
        // Only the choice the menu showed: a signup plan of this top document with its passkey button.
        if (!plan || !offer || rec.frameId !== 0) throw new BgError("invalid");
        const t = targetOf(rec);
        await planner.runSignup(t, plan, m.mode);
        if (m.mode === "passkey") {
          // The site's own button starts the ceremony (it owns the challenge); the
          // creation it asks for opens OnePass's window, which still asks (spec 2.3).
          const cs: CsContext = { tabId: rec.tabId, frameId: 0, origin: rec.origin };
          if (rec.documentId !== undefined) cs.documentId = rec.documentId;
          passkeys.armCreate(cs);
          const msg: BgToCs = { type: "click_passkey", origin: rec.origin, ref: offer.button_ref };
          await ext.tabs.sendMessage(rec.tabId, msg, rec.documentId !== undefined ? { documentId: rec.documentId } : { frameId: 0 });
        }
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        return {};
      },
      menu_new_login: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        if (rec.formKind === "card" || rec.formKind === "identity" || rec.formKind === "address") throw new BgError("invalid");
        // The prompt goes to the top frame: a subframe menu needs a top frame of the same site.
        const top = await frames.frameOrigin(rec.tabId, 0);
        if (!top || !sameSite(top, rec.origin)) throw new BgError("cross_site_frame");
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        await saveFlow.openNewLogin(rec.tabId, rec.origin, rec.frameId === 0 ? rec.documentId : undefined);
        return {};
      },
      menu_signin: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const offered = rec.methods && Object.hasOwn(rec.methods, m.itemId) ? rec.methods[m.itemId] : undefined;
        if (!offered?.includes(m.provider)) throw new BgError("invalid");
        if (m.accountId !== undefined) {
          const shown = rec.accounts && Object.hasOwn(rec.accounts, m.provider) ? rec.accounts[m.provider] : undefined;
          if (!shown?.includes(m.accountId)) throw new BgError("invalid");
        }
        // The menu goes first: its place is where the progress shows (one surface).
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        const start: StartOptions = {};
        if (m.accountId !== undefined) start.accountId = m.accountId;
        if (rec.planned) start.planned = rec.planned;
        if (rec.frameId === 0) start.anchorRef = rec.fieldRef;
        const top = await topOf(menuFrame(rec));
        // Locked, or no app: asked at once, and a card of the page waits to start it.
        if (top) await overlays.signIn(top, m.itemId, m.provider, start);
        else await chain.start(rec.tabId, m.itemId, m.provider, start);
        return {};
      },
      menu_unlock: async (m, from) => {
        // The menu's button ("Déverrouiller dans OnePass", "Ouvrir OnePass"): a click of its own.
        const rec = await menuRecord(m.token, from);
        const at = now();
        // Not the tab in front, or too many asks this minute: the app stays where it is.
        if (!(await mayAsk(rec.tabId, true))) throw new BgError("refused");
        const opened = await openApp().catch(() => false);
        let locked = true;
        let sent = true;
        try {
          locked = await unlockOp(rec.tabId);
        } catch (e) {
          // Launched and not answering yet: the menu waits, the unlock is asked once it does.
          const code = toBgError(e).code;
          if (!opened || (code !== "host_missing" && code !== "timeout")) throw e;
          sent = false;
        }
        await askedUnlock(m.token, rec, at, sent);
        return { locked };
      },
      menu_pair: async (m, from) => {
        // The menu of an unpaired extension: its button opens the popup, where pairing happens.
        const rec = await menuRecord(m.token, from);
        keys.drop(m.token);
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        try {
          if (!ext.action?.openPopup) throw new Error("no openPopup");
          await ext.action.openPopup();
          return {};
        } catch {
          // Chromium before 127, Firefox without a user gesture, a window without a toolbar: the
          // popup page in its own window pairs the same way.
          if (!ext.windows?.create) throw new BgError("refused");
          await ext.windows.create({ url: ext.runtime.getURL("popup.html"), type: "popup", width: 420, height: 600, focused: true });
          return {};
        }
      },
      menu_vault: async (m, from) => {
        await menuRecord(m.token, from);
        return vaultCall({ op: "vault_state" });
      },
      menu_unlock_biometric: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const at = now();
        const v = await vaultCall({ op: "unlock_biometric" });
        if (v.locked) return v;
        // A tap on the Face ID button resumes the fill. So does the menu's automatic Face ID when
        // a trusted gesture opened that menu on the locked vault (the icon, the command): the
        // gesture's own fill, once, inside its deadline. The automatic Face ID of any other menu
        // is no gesture: it unlocks and the menu loads, nothing fills.
        const asked = await askedFor(m.token, rec);
        await dropAsked(m.token);
        if (m.gesture === true) await resumeAfterUnlock(rec, at);
        else if (asked) await resumeAfterUnlock(rec, asked.at);
        return v;
      },
      menu_unlock_password: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const at = now();
        const v = await vaultCall({ op: "unlock_password", password: m.password });
        if (!v.locked) {
          await dropAsked(m.token);
          await resumeAfterUnlock(rec, at);
        }
        return v;
      },
      menu_resume: async (m, from) => {
        // The unlock in the app (Touch ID on the Mac) ends out of the worker's sight: the menu that
        // waits for it asks. Not asked for this menu (or too late): "invalid". Still locked, or the
        // app still starting: "locked" / "host_missing", the menu keeps waiting and nothing is used
        // up. Open: the request is spent first, then the same resume as the sheet's, once.
        const rec = await menuRecord(m.token, from);
        const asked = await askedFor(m.token, rec);
        if (!asked) throw new BgError("invalid");
        if (resuming.has(m.token)) throw new BgError("locked");
        resuming.add(m.token);
        try {
          let locked: boolean;
          if (asked.sent) locked = (await session.request({ op: "status" })).locked;
          else {
            // The app launched for this menu answers now: its `unlock` goes, once, open already
            // or not (it hands the front back to the browser). Not answering yet: it throws.
            locked = await unlockOp(rec.tabId);
            await askedUnlock(m.token, rec, asked.at, true);
          }
          if (locked) throw new BgError("locked");
          await dropAsked(m.token);
          if (!(await resumeAfterUnlock(rec, asked.at))) throw new BgError("invalid");
          return {};
        } finally {
          resuming.delete(m.token);
        }
      },
      menu_keys: async (m, from) => {
        await menuRecord(m.token, from);
        return { keys: await keys.wait(m.token) };
      },
      menu_resize: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        await resizeFrame(ext.tabs, rec, "menu", m.height);
        return {};
      },
      menu_close: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        void history.dismissed(menuList(rec.tabId, rec.frameId));
        keys.drop(m.token);
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        return {};
      },
      overlay_init: async (m, from) => overlays.init(m.token, from),
      overlay_state: async (m, from) => overlays.state(m.token, from),
      overlay_start: async (m, from) => overlays.start(m.token, from, m.itemId, m.provider, m.accountId),
      overlay_unlock: async (m, from) => overlays.unlock(m.token, from),
      overlay_resize: async (m, from) => overlays.resize(m.token, from, m.height),
      overlay_stop: async (m, from) => overlays.stop(m.token, from),
      overlay_close: async (m, from) => overlays.close(m.token, from),
      save_init: async (m, from) => savePrompts.init(m.token, from),
      save_reveal: async (m, from) => savePrompts.reveal(m.token, from),
      save_generate: async (m, from) => savePrompts.generate(m.token, from),
      save_decide: async (m, from) => savePrompts.decide(m.token, from, m.decision, m.edits),
      save_close: async (m, from) => savePrompts.close(m.token, from),
      save_undo: async (m, from) => savePrompts.undo(m.token, from),
      save_edit: async (m, from) => savePrompts.edit(m.token, from),
      save_resize: async (m, from) => savePrompts.resize(m.token, from, m.height),
      ...popup.handlers(),
      popup_pending: async () => ({ pending: await savePrompts.pendingList() }),
      popup_pending_decide: async (m) => savePrompts.decidePending(m.id, m.decision),
    },
  };

  // Field classifier model (Task 15): model builds only. In the default build the branch, the
  // dynamic import and everything behind it (model code, onnxruntime-web) are dropped by esbuild.
  let modelSession: (() => Promise<ModelSession | null>) | null = null;
  if (__CLASSIFIER__ !== "heuristic") {
    const kind = __CLASSIFIER__;
    const service = import("./model-service");
    let loaded: Promise<ModelSession | null> | null = null;
    const load = () => (loaded ??= service.then((m) => m.loadClassifierModel(ext, kind)).catch(() => null));
    modelSession = load;
    // One handler (and so one budget per tab) for the worker's lifetime.
    const handler = service.then((m) => m.createClassifyHandler({ kind, frames, session: load }));
    handlers.cs.classify = async (m, from) => (await handler)(m, from);
  }

  // Passkeys (spec 3.2): their own listener beside the router.
  const passkeys = new Passkeys({
    session,
    host,
    frames,
    chain,
    runtime: ext.runtime,
    tabs: ext.tabs as unknown as PasskeyDeps["tabs"],
    ...((ext as unknown as { windows?: PasskeyWindows }).windows ? { windows: (ext as unknown as { windows: PasskeyWindows }).windows } : {}),
  });

  return {
    store,
    session,
    passkeys,
    pairing,
    frames,
    menus,
    keys,
    filler,
    chain,
    runner,
    saveFlow,
    planner,
    notes,
    providerFlows,
    neverSave,
    overlays,
    saves: savePrompts,
    analyses,
    popup,
    handlers,
    /** The classifier model of a model build (loaded on first use), null in the default build. */
    modelSession,
    /** Register every listener; call synchronously at service worker start. */
    install(): void {
      store.restrictLocal();
      // Connect at install and browser start, so that the first popup is already connected.
      const connect = () => void session.getClient().catch(() => undefined);
      ext.runtime.onInstalled?.addListener(connect);
      ext.runtime.onStartup?.addListener(connect);
      menus.install(ext);
      overlays.tokens.install(ext);
      savePrompts.tokens.install(ext);
      analyses.install(ext);
      runner?.install(ext);
      analyses.onAnalysis((a, cs) => {
        // The sign that a sign-in worked (or failed) comes from the submitting frame too.
        saveFlow.onAnalysis(a, cs);
        if (cs.frameId !== 0) return;
        void providerFlows.onAnalysis(a, cs).catch(() => undefined);
      });
      ext.webNavigation.onCommitted.addListener((d) => {
        // A new document takes its held suggestions with it (a new top one, every frame's).
        if (d.frameId === 0) suggestions.drop(d.tabId);
        else suggestions.dropFrame(d.tabId, d.frameId);
        if (d.frameId !== 0) return;
        void notes.onNavigation(d.tabId, d.url).catch(() => undefined);
        saveFlow.onNavigation(d.tabId, d.url);
        void providerFlows.onNavigation(d.tabId, d.url).catch(() => undefined);
      });
      ext.webNavigation.onCompleted.addListener((d) => {
        if (d.frameId === 0) saveFlow.onReady(d.tabId);
      });
      ext.tabs.onRemoved.addListener((tabId) => {
        saveFlow.onTabRemoved(tabId);
        suggestions.drop(tabId);
        for (const [m, st] of menuSuggestions) if (!suggestions.recordOf(st)) menuSuggestions.delete(m);
        savePrompts.forgetTab(tabId);
        notes.onTabRemoved(tabId);
        for (const k of planMenus.keys()) if (k.startsWith(`${tabId}:`)) planMenus.delete(k);
        for (const k of lockedGestures.keys()) if (k.startsWith(`${tabId}:`)) lockedGestures.delete(k);
        for (const k of replays.keys()) if (k.startsWith(`${tabId}:`)) replays.delete(k);
        asks.delete(tabId);
        void providerFlows.drop(tabId).catch(() => undefined);
      });
      ext.runtime.onMessage.addListener(createRouter(ext.runtime, handlers));
      passkeys.install(ext);
      ext.runtime.onMessage.addListener(createPasskeyRouter(ext.runtime, passkeys));
      // Ctrl+Shift+L / Command+Shift+L: smart fill in the active tab (a gesture of the user).
      ext.commands?.onCommand.addListener((command) => {
        if (command !== FILL_SMART_COMMAND) return;
        void (async () => {
          const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
          if (typeof tab?.id === "number") await smartFillTab(tab.id);
        })().catch(() => undefined);
      });
    },
  };
}
