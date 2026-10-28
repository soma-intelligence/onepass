// Wiring of the service worker: one session, the pairing flow, menu,
// overlay and save prompt tokens, the fill pipeline, the popup backend, the
// sign-in chain, the save and provider-link proposals, and the router.
import { BridgeClient, type Summary } from "../bridge/client";
import { parseOrigin, sameSite } from "../shared/domain";
import type { ProviderId } from "../shared/messages";
import type { MenuInit } from "../shared/ui";
import { signInChoices } from "./chain/choices";
import { PageAnalyses } from "./analyses";
import { ChainRunner } from "./chain/driver";
import { ProviderFlows } from "./chain/provider-flow";
import { SaveFlow } from "./chain/save-flow";
import type { ChainDriver } from "./chain/types";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { Frames } from "./frames";
import { KeyRelay, type MenuRecord, MenuTokens } from "./menu";
import { openTransport } from "./native";
import { NeverSave } from "./never-save";
import { Overlays, removeFrame, resizeFrame } from "./overlay";
import { PairingFlow } from "./pairing";
import { PopupBackend, loginFields } from "./popup";
import { type Handlers, createRouter } from "./router";
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

/** Forms the menu offers sign-ins on (provider methods start the chain there). */
const SIGN_IN_FORMS: ReadonlySet<string> = new Set(["login", "signup", "change_password", "otp"]);
/** Forms where the menu offers to generate a password, items or not. */
const NEW_PASSWORD_FORMS: ReadonlySet<string> = new Set(["signup", "change_password"]);

function targetOf(rec: MenuRecord): FillTarget {
  const t: FillTarget = { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin, formRef: rec.formRef };
  if (rec.documentId !== undefined) t.documentId = rec.documentId;
  return t;
}

export function createBackground(ext: BgExt, opts: BackgroundOptions = {}) {
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
        ...(opts.now ? { now: opts.now } : {}),
      });
  const chain: ChainDriver = opts.chain ?? (runner as ChainRunner);
  chainRef.current = chain;
  const chainRunning = async (tabId: number) => (runner ? runner.isRunning(tabId) : false);
  const savePrompts = new SavePrompts({ ext, session, neverSave, ...(opts.now ? { now: opts.now } : {}) });
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
  const popup = new PopupBackend({
    ext,
    area: store.session,
    session,
    pairing,
    filler,
    analyses,
    onLock: () => saveFlow.clearGenerated(),
    onGenerated: (tabId, origin, password) => saveFlow.rememberGenerated(tabId, origin, password),
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
        const token = await menus.register(from, { formRef: m.formRef, fieldRef: m.fieldRef, formKind: m.formKind });
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
        const out: MenuInit = { origin: rec.origin, formKind: rec.formKind, items };
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
        if (kind === "login") await filler.fillLogin(t, m.itemId, loginFields(rec.formKind));
        else if (kind === "card") await filler.fillCard(t, m.itemId);
        else if (kind === "identity") await filler.fillIdentity(t, m.itemId);
        else throw new BgError("invalid");
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
        const start: { accountId?: string; anchorRef?: string } = {};
        if (m.accountId !== undefined) start.accountId = m.accountId;
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
        saveFlow.onNavigation(d.tabId);
        void providerFlows.onNavigation(d.tabId, d.url).catch(() => undefined);
      });
      ext.webNavigation.onCompleted.addListener((d) => {
        if (d.frameId === 0) void saveFlow.onReady(d.tabId).catch(() => undefined);
      });
      ext.tabs.onRemoved.addListener((tabId) => {
        saveFlow.onTabRemoved(tabId);
        void providerFlows.drop(tabId).catch(() => undefined);
      });
      ext.runtime.onMessage.addListener(createRouter(ext.runtime, handlers));
    },
  };
}
