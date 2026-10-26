// Wiring of the service worker: one session, the pairing flow, menu,
// overlay and save prompt tokens, the fill pipeline, the popup backend and
// the router. The chain driver (Task 17) plugs in through `opts.chain`; the
// save flow opens prompts with `saves.open`.
import { BridgeClient, type Summary } from "../bridge/client";
import type { ProviderId } from "../shared/messages";
import { PageAnalyses } from "./analyses";
import { type ChainDriver, idleChainDriver } from "./chain/types";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { Frames } from "./frames";
import { type MenuRecord, MenuTokens } from "./menu";
import { NATIVE_HOST, nativeTransport } from "./native";
import { NeverSave } from "./never-save";
import { Overlays, removeFrame } from "./overlay";
import { PairingFlow } from "./pairing";
import { PopupBackend, loginFields } from "./popup";
import { type Handlers, createRouter } from "./router";
import { SavePrompts } from "./save";
import { BgError, type BridgeLike, Session } from "./session";
import { IdbPairingStore, type PairingStore, Store } from "./store";

export interface BackgroundOptions {
  /** Pairing record storage; IndexedDB of the extension origin by default. */
  pairings?: PairingStore;
  newClient?: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  browser?: string;
  /** Sign-in chain (Task 17); none by default. */
  chain?: ChainDriver;
}

function targetOf(rec: MenuRecord): FillTarget {
  const t: FillTarget = { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin, formRef: rec.formRef };
  if (rec.documentId !== undefined) t.documentId = rec.documentId;
  return t;
}

export function createBackground(ext: BgExt, opts: BackgroundOptions = {}) {
  const store = new Store(ext, opts.pairings ?? new IdbPairingStore());
  const newClient = opts.newClient ?? (() => new BridgeClient(nativeTransport(NATIVE_HOST, ext.runtime)));
  const session = new Session({ store, newClient, ...(opts.sleep ? { sleep: opts.sleep } : {}) });
  const pairing = new PairingFlow({ store, session, newClient, ...(opts.browser ? { browser: opts.browser } : {}) });
  const frames = new Frames(ext.webNavigation);
  const menus = new MenuTokens(store.session, opts.now ?? Date.now);
  const filler = new Filler(ext.tabs, frames, session);
  const chain = opts.chain ?? idleChainDriver;
  const neverSave = new NeverSave(ext.storage.local);
  const overlays = new Overlays({ ext, area: store.session, session, chain, ...(opts.now ? { now: opts.now } : {}) });
  const saves = new SavePrompts({ ext, session, neverSave, ...(opts.now ? { now: opts.now } : {}) });
  const analyses = new PageAnalyses(store.session);
  const popup = new PopupBackend({
    ext,
    area: store.session,
    session,
    pairing,
    filler,
    analyses,
    ...(opts.now ? { now: opts.now } : {}),
  });

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
        const token = await menus.register(from, { formRef: m.formRef, fieldRef: m.fieldRef, formKind: m.formKind });
        return { url: `${ext.runtime.getURL("menu.html")}#${token}` };
      },
      close_menu: async (_m, from) => {
        await menus.revokeFrame(from.tabId, from.frameId);
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
        const offered: Record<string, Summary["kind"]> = {};
        const methods: Record<string, ProviderId[]> = {};
        for (const it of items) {
          offered[it.item_id] = it.kind;
          methods[it.item_id] = it.methods.map((x) => x.provider);
        }
        await menus.setOffered(m.token, offered, methods);
        return { origin: rec.origin, formKind: rec.formKind, items };
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
        return {};
      },
      menu_signin: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        const offered = rec.methods && Object.hasOwn(rec.methods, m.itemId) ? rec.methods[m.itemId] : undefined;
        if (!offered?.includes(m.provider)) throw new BgError("invalid");
        await chain.start(rec.tabId, m.itemId, m.provider);
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        return {};
      },
      menu_unlock: async (m, from) => {
        await menuRecord(m.token, from);
        return session.request({ op: "unlock" });
      },
      menu_close: async (m, from) => {
        const rec = await menuRecord(m.token, from);
        await menus.revokeFrame(rec.tabId, rec.frameId);
        await removeFrame(ext.tabs, rec, "menu");
        return {};
      },
      overlay_init: async (m, from) => overlays.init(m.token, from),
      overlay_state: async (m, from) => overlays.state(m.token, from),
      overlay_start: async (m, from) => overlays.start(m.token, from, m.itemId, m.provider),
      overlay_stop: async (m, from) => overlays.stop(m.token, from),
      overlay_close: async (m, from) => overlays.close(m.token, from),
      save_init: async (m, from) => saves.init(m.token, from),
      save_reveal: async (m, from) => saves.reveal(m.token, from),
      save_generate: async (m, from) => saves.generate(m.token, from),
      save_decide: async (m, from) => saves.decide(m.token, from, m.decision, m.edits),
      save_close: async (m, from) => saves.close(m.token, from),
      ...popup.handlers(),
    },
  };

  return {
    store,
    session,
    pairing,
    frames,
    menus,
    filler,
    chain,
    neverSave,
    overlays,
    saves,
    analyses,
    popup,
    handlers,
    /** Register every listener; call synchronously at service worker start. */
    install(): void {
      store.restrictLocal();
      menus.install(ext);
      overlays.tokens.install(ext);
      saves.tokens.install(ext);
      analyses.install(ext);
      ext.runtime.onMessage.addListener(createRouter(ext.runtime, handlers));
    },
  };
}
