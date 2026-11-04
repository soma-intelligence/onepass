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
import { BridgeClient, type Summary } from "../bridge/client";
import { parseOrigin, sameSite } from "../shared/domain";
import type { BgToCs, FieldRole, FillIntent, PageContext, PlanContextBody, PlanOut, ProviderId } from "../shared/messages";
import type { MenuInit, MenuNotice } from "../shared/ui";
import { signInChoices } from "./chain/choices";
import { PageAnalyses } from "./analyses";
import { ChainRunner } from "./chain/driver";
import { ProviderFlows } from "./chain/provider-flow";
import { SaveFlow } from "./chain/save-flow";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { FormGenerator } from "./generate";
import { AutofillHistory, type BrowserKind, browserKind } from "./history";
import { type CsContext, Frames } from "./frames";
import { KeyRelay, type MenuField, type MenuRecord, MenuTokens } from "./menu";
import { isSafari, openApp as openAppNative, openTransport } from "./native";
import { type NativeVault, type NativeVaultCall, nativeVault } from "./safari";
import { NeverSave } from "./never-save";
import { FillNotes } from "./notes";
import { Overlays, removeFrame, resizeFrame } from "./overlay";
import { PairingFlow } from "./pairing";
import { type PasskeyDeps, type PasskeyWindows, Passkeys, createPasskeyRouter } from "./passkey";
import { clearPenalty, hasPenalty, siteOf } from "./penalty";
import { Planner, type PlanOrigins, framesFromSender, mainRoles } from "./planner";
import { PopupBackend, alternativesFirst, loginFields, rankedIds } from "./popup";
import { type Handlers, createRouter, parsePlanContextBody } from "./router";
import { type SavePending, SavePrompts } from "./save";
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
  /** Brings the app forward for "Déverrouiller dans OnePass"; `openApp` of native.ts by default. */
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
export const RESUME_WINDOW_MS = 3 * 60 * 1000;

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
  });
  const pairing: PairingFlow = new PairingFlow({
    store,
    session,
    newClient,
    ...(opts.browser ? { browser: opts.browser } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
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
    state: (t, o) => (chainRef.current ? chainRef.current.state(t, o) : Promise.resolve(null)),
    closed: (t, o, d) => chainRef.current?.closed?.(t, o, d) ?? Promise.resolve(),
    providerOnly: (t, d) => chainRef.current?.providerOnly?.(t, d) ?? Promise.resolve(null),
  };
  const overlays = new Overlays({
    ext,
    area: store.session,
    local: ext.storage.local,
    session,
    chain: lateChain,
    ...(opts.now ? { now: opts.now } : {}),
  });
  // The chain plans unknown pages; the planner starts chains.
  const plannerRef: { current: Planner | null } = { current: null };
  const notesRef: { current: FillNotes | null } = { current: null };
  const runner = opts.chain
    ? null
    : new ChainRunner({
        ext,
        area: store.session,
        local: ext.storage.local,
        session,
        frames,
        filler,
        analyses,
        overlays: { open: (cs, anchor) => overlays.open(cs, anchor), hasTab: (t) => overlays.tokens.hasTab(t) },
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
  };
  const saveFlow = new SaveFlow({
    session,
    saves,
    neverSave,
    topFrame: (t) => frames.details(t, 0),
    chainRunning,
    ...(opts.now ? { now: opts.now } : {}),
  });
  const providerFlows = new ProviderFlows({
    area: store.session,
    session,
    saves,
    neverSave,
    chainRunning,
    ...(opts.now ? { now: opts.now } : {}),
  });
  session.onLocked(() => saveFlow.clearGenerated());
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
  /** Per frame (`tab:frame`): the alternatives of a plan that answered "menu". */
  const planMenus = new Map<string, PlanForMenu>();

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
    if (!f || !o?.https || o.origin !== rec.origin) return false;
    if (rec.documentId !== undefined && f.documentId !== undefined && f.documentId !== rec.documentId) return false;
    await menus.revokeFrame(rec.tabId, rec.frameId);
    await removeFrame(ext.tabs, rec, "menu");
    const msg: BgToCs = { type: "smart_fill", fieldRef: rec.fieldRef, origin: rec.origin };
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
  const planWithoutGesture = async (cs: CsContext): Promise<{ t: FillTarget; plan: PlanOut } | null> => {
    const origins: PlanOrigins | null = await planOrigins(cs);
    if (!origins) return null;
    const body = await requestContext(cs);
    if (!body) return null;
    const t = fillTarget(cs, body.forms[0]?.form_ref ?? "");
    const context: PageContext = { ...body, ...origins };
    return { t, plan: await planner.plan(t, context) };
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
    const r = await planWithoutGesture(cs);
    if (!r || (r.plan.intent !== "login" && r.plan.intent !== "otp")) return null;
    const g = r.plan.groups.find((x) => x.kind === "login" && x.item_id === itemId && x.fields.length > 0);
    if (!g) return null;
    const f = await frames.details(cs.tabId, cs.frameId);
    if (!f) return null;
    return { formRef: g.form_ref, roles: g.fields.map((x) => x.role), submit: planner.submits(r.t, r.plan), url: f.url };
  }

  /** The popup's Fill and the command: the tab's top frame runs smart fill as if its user clicked. */
  const smartFillTab = async (tabId: number): Promise<void> => {
    const f = await frames.details(tabId, 0);
    if (!f || parseOrigin(f.url)?.https !== true) throw new BgError("insecure_origin");
    const msg: BgToCs = { type: "smart_fill" };
    await ext.tabs.sendMessage(tabId, msg, f.documentId !== undefined ? { documentId: f.documentId } : { frameId: 0 });
  };
  const popup = new PopupBackend({
    ext,
    area: store.session,
    session,
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
      return (await planWithoutGesture(cs))?.plan ?? null;
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
   * Menus whose user asked to unlock in the app (MS-03, Touch ID on the Mac), by token, with the
   * time: once unlocked, the menu may resume the fill once (`menu_resume`). The iOS sheet's
   * unlocks resume in their own call and never land here. Memory only, no secret.
   */
  const unlockAsked = new Map<string, number>();
  const askedUnlock = (token: string): void => {
    for (const [t, at] of unlockAsked) if (now() - at > RESUME_WINDOW_MS) unlockAsked.delete(t);
    unlockAsked.set(token, now());
  };

  const handlers: Handlers = {
    cs: {
      page_analysis: async (m, from) => {
        await analyses.record(m.analysis, from);
        return {};
      },
      open_menu: async (m, from) => {
        if (!from.origin.startsWith("https://")) throw new BgError("insecure_origin");
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
        const token = await menus.register(from, field);
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
      provider_click: async (m, from) => {
        await providerFlows.onProviderClick(from, m.provider);
        return {};
      },
      account_click: async (m, from) => {
        await providerFlows.onAccountClick(from, m.email);
        return {};
      },
      fill_salt: async (_m, from) => {
        if (!from.origin.startsWith("https://")) throw new BgError("insecure_origin");
        if (!(await planOrigins(from))) throw new BgError("cross_site_frame");
        return { salt: await session.fillSalt() };
      },
      plan_context: async (m, from) => {
        if (!from.origin.startsWith("https://")) throw new BgError("insecure_origin");
        const origins = await planOrigins(from);
        // A cross-origin child frame gets no plan: the menu, as before.
        if (!origins) return { outcome: "menu" };
        const t = fillTarget(from, m.formRef ?? m.context.forms[0]?.form_ref ?? "");
        const plan = await planner.plan(t, { ...m.context, ...origins });
        const run: { form?: string; anchorRef?: string } = {};
        // An icon click: its form only (the popup and the command run the whole plan).
        if (m.formRef !== undefined) run.form = m.formRef;
        if (m.fieldRef !== undefined) run.anchorRef = m.fieldRef;
        const key = `${from.tabId}:${from.frameId}`;
        refusedRuns.delete(key);
        const outcome = await planner.run(t, plan, run);
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
        if (kind === "login" && CHAIN_FORMS.has(rec.formKind) && rec.frameId === 0) {
          // Still the document the menu was opened in (as the fill checks it).
          const check = await frames.checkFillTarget(rec.tabId, 0, rec.origin, rec.documentId);
          if (!check.ok) throw new BgError(check.code);
          await menus.revokeFrame(rec.tabId, rec.frameId);
          await removeFrame(ext.tabs, rec, "menu");
          const start: StartOptions = { anchorRef: rec.fieldRef };
          if (rec.planned) start.planned = rec.planned;
          try {
            await chain.start(rec.tabId, m.itemId, undefined, start);
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
        else if (kind === "identity") written = await filler.fillIdentity(t, m.itemId);
        else throw new BgError("invalid");
        // A pick in a menu a plan opened: the site memory learns it once the page moves on.
        if (rec.planned && written > 0) {
          notes.filled(rec.tabId, rec.origin, { items: [m.itemId], ...rec.planned }, (await frames.details(rec.tabId, 0))?.url ?? null);
        }
        return {};
      },
      menu_generate: async (m, from) => {
        const rec = await menuRecord(m.token, from);
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
        await chain.start(rec.tabId, m.itemId, m.provider, start);
        return {};
      },
      menu_unlock: async (m, from) => {
        await menuRecord(m.token, from);
        askedUnlock(m.token);
        await openApp();
        return session.request({ op: "unlock" });
      },
      menu_vault: async (m, from) => {
        await menuRecord(m.token, from);
        return vaultCall({ op: "vault_state" });
      },
      menu_unlock_biometric: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const at = now();
        const v = await vaultCall({ op: "unlock_biometric" });
        // The menu's automatic Face ID is no gesture: it unlocks and the menu loads, nothing fills.
        // A tap on the Face ID button resumes the fill.
        if (m.gesture === true && !v.locked) await resumeAfterUnlock(rec, at);
        return v;
      },
      menu_unlock_password: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const at = now();
        const v = await vaultCall({ op: "unlock_password", password: m.password });
        if (!v.locked) await resumeAfterUnlock(rec, at);
        return v;
      },
      menu_resume: async (m, from) => {
        // The unlock in the app (Touch ID on the Mac) ends out of the worker's sight: the menu that
        // asked for it says when it sees the vault open. The same resume as the sheet's, once.
        const rec = await menuRecord(m.token, from);
        const at = unlockAsked.get(m.token);
        unlockAsked.delete(m.token);
        if (at === undefined) throw new BgError("invalid");
        const s = await session.request({ op: "status" });
        if (s.locked) throw new BgError("locked");
        if (!(await resumeAfterUnlock(rec, at))) throw new BgError("invalid");
        return {};
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
      overlay_resize: async (m, from) => overlays.resize(m.token, from, m.height),
      overlay_stop: async (m, from) => overlays.stop(m.token, from),
      overlay_close: async (m, from) => overlays.close(m.token, from),
      save_init: async (m, from) => savePrompts.init(m.token, from),
      save_reveal: async (m, from) => savePrompts.reveal(m.token, from),
      save_generate: async (m, from) => savePrompts.generate(m.token, from),
      save_decide: async (m, from) => savePrompts.decide(m.token, from, m.decision, m.edits),
      save_close: async (m, from) => savePrompts.close(m.token, from),
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
        savePrompts.forgetTab(tabId);
        notes.onTabRemoved(tabId);
        for (const k of planMenus.keys()) if (k.startsWith(`${tabId}:`)) planMenus.delete(k);
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
