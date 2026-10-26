// Wiring of the service worker: one session, the pairing flow, menu tokens,
// the fill pipeline and the router with the handlers of this layer. Later
// layers (popup, chain, save flow) add entries to `handlers`.
import { BridgeClient, type FillField, type Summary } from "../bridge/client";
import type { FormKind } from "../shared/messages";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { Frames } from "./frames";
import { type MenuRecord, MenuTokens } from "./menu";
import { NATIVE_HOST, nativeTransport } from "./native";
import { PairingFlow } from "./pairing";
import { type Handlers, createRouter } from "./router";
import { BgError, type BridgeLike, Session } from "./session";
import { IdbPairingStore, type PairingStore, Store } from "./store";

export interface BackgroundOptions {
  /** Pairing record storage; IndexedDB of the extension origin by default. */
  pairings?: PairingStore;
  newClient?: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  browser?: string;
}

/** Fields of a login item disclosed for each form kind (least disclosure). */
function loginFields(kind: FormKind): FillField[] {
  switch (kind) {
    case "otp":
      return ["totp"];
    case "change_password":
      return ["password"];
    case "signup":
      return ["username"];
    default:
      return ["username", "password"];
  }
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

  const menuRecord = async (token: string, from: Parameters<MenuTokens["resolve"]>[1]): Promise<MenuRecord> => {
    const rec = await menus.resolve(token, from);
    if (!rec) throw new BgError("invalid");
    return rec;
  };

  const handlers: Handlers = {
    cs: {
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
        for (const it of items) offered[it.item_id] = it.kind;
        await menus.setOffered(m.token, offered);
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
      popup_status: async () => session.request({ op: "status" }),
      popup_unlock: async () => session.request({ op: "unlock" }),
      popup_pair_start: async () => pairing.startPairing(),
      popup_pair_approve: async () => {
        await pairing.confirmPairing();
        return {};
      },
      popup_pair_cancel: async () => {
        pairing.cancelPairing();
        return {};
      },
    },
  };

  return {
    store,
    session,
    pairing,
    frames,
    menus,
    filler,
    handlers,
    /** Register every listener; call synchronously at service worker start. */
    install(): void {
      store.restrictLocal();
      menus.install(ext);
      ext.runtime.onMessage.addListener(createRouter(ext.runtime, handlers));
    },
  };
}
