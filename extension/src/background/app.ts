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
import type { MenuInit } from "../shared/ui";
import { signInChoices } from "./chain/choices";
import { PageAnalyses } from "./analyses";
import { ChainRunner } from "./chain/driver";
import { ProviderFlows } from "./chain/provider-flow";
import { SaveFlow } from "./chain/save-flow";
import type { ChainDriver, StartOptions } from "./chain/types";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { type CsContext, Frames } from "./frames";
import { KeyRelay, type MenuField, type MenuRecord, MenuTokens } from "./menu";
import { openTransport } from "./native";
import { NeverSave } from "./never-save";
import { FillNotes } from "./notes";
import { Overlays, removeFrame, resizeFrame } from "./overlay";
import { PairingFlow } from "./pairing";
import { clearPenalty, hasPenalty, siteOf } from "./penalty";
import { Planner, type PlanOrigins, framesFromSender, mainRoles } from "./planner";
import { PopupBackend, alternativesFirst, loginFields, rankedIds } from "./popup";
import { type Handlers, createRouter, parsePlanContextBody } from "./router";
import { type SavePending, SavePrompts } from "./save";
import { BgError, type BridgeLike, Session } from "./session";
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
}

/** The command of manifests/base.json that runs smart fill in the active tab. */
export const FILL_SMART_COMMAND = "fill-smart";
/** A menu opened this soon after a plan answered "menu" lists that plan's alternatives first. */
export const PLAN_MENU_MS = 30_000;

/** Forms the menu offers sign-ins on (provider methods start the chain there). */
const SIGN_IN_FORMS: ReadonlySet<string> = new Set(["login", "signup", "change_password", "otp"]);
/** Forms where the menu offers to generate a password, items or not. */
const NEW_PASSWORD_FORMS: ReadonlySet<string> = new Set(["signup", "change_password"]);

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
}

export function createBackground(ext: BgExt, opts: BackgroundOptions = {}) {
  const now = opts.now ?? Date.now;
  const store = new Store(ext, opts.pairings ?? new IdbPairingStore());
  const newClient = opts.newClient ?? (() => new BridgeClient(openTransport(ext.runtime)));
  const session = new Session({ store, newClient, ...(opts.sleep ? { sleep: opts.sleep } : {}) });
  const pairing = new PairingFlow({ store, session, newClient, ...(opts.browser ? { browser: opts.browser } : {}) });
  const frames = new Frames(ext.webNavigation);
  const menus = new MenuTokens(store.session, opts.now ?? Date.now);
  const keys = new KeyRelay();
  const filler = new Filler(ext.tabs, frames, session);
  const neverSave = new NeverSave(ext.storage.local);
  const analyses = new PageAnalyses(store.session);
  // The overlay starts and stops the chain; the chain shows the overlay.
  const chainRef: { current: ChainDriver | null } = { current: null };
  const lateChain: ChainDriver = {
    start: (...a) => (chainRef.current ? chainRef.current.start(...a) : Promise.resolve()),
    stop: (t) => (chainRef.current ? chainRef.current.stop(t) : Promise.resolve()),
    state: (t, o) => (chainRef.current ? chainRef.current.state(t, o) : Promise.resolve(null)),
    closed: (t, o, d) => chainRef.current?.closed?.(t, o, d) ?? Promise.resolve(),
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
    neverSave,
    onSaved: (tabId, origin, itemId) => notes.onSaved(tabId, origin, itemId),
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
  const planner = new Planner(session, filler, chain, saveFlow, {
    penalized: (origin) => hasPenalty(store.session, origin),
    onFilled: async (t, note) => notes.filled(t.tabId, t.origin, note, (await frames.details(t.tabId, 0))?.url ?? null),
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
    filler,
    analyses,
    onLock: () => saveFlow.clearGenerated(),
    onGenerated: (tabId, origin, password) => saveFlow.rememberGenerated(tabId, origin, password),
    plan: async (tabId, origin) => {
      const f = await frames.details(tabId, 0);
      if (!f || parseOrigin(f.url)?.origin !== origin) return null;
      const cs: CsContext = { tabId, frameId: 0, origin };
      if (f.documentId !== undefined) cs.documentId = f.documentId;
      return (await planWithoutGesture(cs))?.plan ?? null;
    },
    smartFill: smartFillTab,
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
        }
        const token = await menus.register(from, field);
        return { url: `${ext.runtime.getURL("menu.html")}#${token}` };
      },
      close_menu: async (_m, from) => {
        await menus.revokeFrame(from.tabId, from.frameId);
      },
      submitted_credentials: async (m, from) => {
        await saveFlow.onSubmitted(m, from);
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
        const outcome = await planner.run(t, plan, run);
        if (outcome === "menu") {
          const ctx = planner.contextOf(plan);
          planMenus.set(`${from.tabId}:${from.frameId}`, {
            alternatives: rankedIds(plan).slice(0, 8),
            planned: { roles: ctx ? mainRoles(ctx, plan.groups) : [], intent: plan.intent },
            documentId: from.documentId,
            at: now(),
          });
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
        return out;
      },
      menu_pick: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        // Only an item the menu showed; its kind comes from the host.
        const kind = rec.offered && Object.hasOwn(rec.offered, m.itemId) ? rec.offered[m.itemId] : undefined;
        const t = targetOf(rec);
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
        const g = await session.request({ op: "generate", ctx: "menu", recipe: { kind: "smart" } });
        await filler.fillGenerated(targetOf(rec), g.password);
        saveFlow.rememberGenerated(rec.tabId, rec.origin, g.password);
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
        return session.request({ op: "unlock" });
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
    },
  };

  return {
    store,
    session,
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
    /** Register every listener; call synchronously at service worker start. */
    install(): void {
      store.restrictLocal();
      menus.install(ext);
      overlays.tokens.install(ext);
      savePrompts.tokens.install(ext);
      analyses.install(ext);
      runner?.install(ext);
      analyses.onAnalysis((a, cs) => {
        if (cs.frameId !== 0) return;
        void providerFlows.onAnalysis(a, cs).catch(() => undefined);
        void saveFlow.onReady(cs.tabId).catch(() => undefined);
      });
      ext.webNavigation.onCommitted.addListener((d) => {
        if (d.frameId !== 0) return;
        void notes.onNavigation(d.tabId, d.url).catch(() => undefined);
        saveFlow.onNavigation(d.tabId);
        void providerFlows.onNavigation(d.tabId, d.url).catch(() => undefined);
      });
      ext.webNavigation.onCompleted.addListener((d) => {
        if (d.frameId === 0) void saveFlow.onReady(d.tabId).catch(() => undefined);
      });
      ext.tabs.onRemoved.addListener((tabId) => {
        saveFlow.onTabRemoved(tabId);
        notes.onTabRemoved(tabId);
        for (const k of planMenus.keys()) if (k.startsWith(`${tabId}:`)) planMenus.delete(k);
        void providerFlows.drop(tabId).catch(() => undefined);
      });
      ext.runtime.onMessage.addListener(createRouter(ext.runtime, handlers));
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
