// Background handlers of the in-page extension pages: menu extras, overlay
// and save prompt.
import type { NativeVault, NativeVaultCall } from "../../src/background/safari";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBackground } from "../../src/background/app";
import type { ChainDriver } from "../../src/background/chain/types";
import { contentSender } from "../../src/background/frames";
import { NEVER_SAVE_KEY } from "../../src/background/never-save";
import { DISMISS_QUIET_MS, SAVE_TTL_MS, cardQuietKey, loginQuietKey, titleFromSite } from "../../src/background/save";
import { BgError } from "../../src/background/session";
import { MemoryPairingStore, Store } from "../../src/background/store";
import type { ChainView } from "../../src/shared/ui";
import { UNLOCK_WAIT_MS } from "../../src/shared/unlock";
import { BridgeAppError } from "../../src/bridge/client";
import { type Answer, FakeClient, record } from "./fake-client";
import { EXT_ID, FakeExt, NO_REPLY, csSender, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

const summary = (id: string, extra: Record<string, unknown> = {}) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
  ...extra,
});

/** The vault has nothing for any site (a click into a field must not open an empty menu). */
let emptyVault = false;
/** What `status` and `unlock` say of the vault; null: the defaults (open). Reset after each test. */
let appLocked: boolean | null = null;
/** Runs when the app is asked to unlock. */
let onUnlock: (() => void) | null = null;
/** The vault answers `locked` to what needs it open (lists, plans). */
let listLocked = false;
/** The plan the bridge gives (and a third login, "used last"); null: no plan. */
let planFor: Record<string, unknown> | null = null;
/** The app does not answer `unlock` (it could not be opened). */
let client_unlock_fails = false;
/** What `vaults` answers for a request (the routed list of a page); null: the two default vaults. */
let vaultsFor: ((r: Record<string, unknown>) => unknown) | null = null;
/** What `undo_save` answers; null: done. */
let undoAnswer: unknown = null;
afterEach(() => {
  vaultsFor = null;
  undoAnswer = null;
  appLocked = null;
  onUnlock = null;
  client_unlock_fails = false;
  listLocked = false;
  planFor = null;
});

const answer: Answer = (r) => {
  if (emptyVault && (r.op === "list_for_origin" || r.op === "list_fillable")) return { items: [] };
  if (listLocked && (r.op === "list_for_origin" || r.op === "plan_fill")) return new BridgeAppError("locked", "vault locked");
  switch (r.op) {
    case "plan_fill":
      return planFor ? { plan: planFor } : {};
    case "list_for_origin":
      return {
        items: [
          summary("it_01"),
          summary("it_02", {
            title: "Atlas Perso",
            has_password: false,
            methods: [{ provider: "google", account_email: "alex.perso@example.com" }],
          }),
          ...(planFor ? [summary("it_03", { title: "Atlas Team", subtitle: "team@atlas.dev" })] : []),
        ],
      };
    case "vaults":
      if (vaultsFor) return vaultsFor(r);
      return { vaults: [{ id: "v1", name: "Personnel", color: null }, { id: "v2", name: "Projet Atlas", color: "#0E7490" }] };
    case "generate":
      return { password: "Gen-Pass-123", entropy_bits: 90 };
    case "undo_save":
      return undoAnswer ?? {};
    case "unlock":
      if (client_unlock_fails) return new BridgeAppError("host_missing", "no app");
      onUnlock?.();
      return { locked: appLocked ?? false };
    case "status":
      return appLocked === null ? {} : { locked: appLocked, account: "Camille", vaults: 1 };
    case "check_credentials":
      return checkAnswer;
    case "save_login":
    case "link_provider":
      return { item_id: "it_new" };
    case "provider_accounts":
      return {
        accounts: [
          summary("g_perso", { title: "Google perso", subtitle: "alex.perso@example.com" }),
          summary("g_pro", { title: "Google pro", subtitle: "alex.pro@example.com" }),
        ],
        linked_item_id: "g_perso",
      };
    default:
      return {};
  }
};

/** What `check_credentials` answers (the save prompt's locked path asks again after unlocking). */
let checkAnswer: Record<string, unknown> = { status: "new" };

class FakeChain implements ChainDriver {
  readonly calls: unknown[][] = [];
  readonly opts: unknown[] = [];
  view: ChainView | null = null;
  /** `start` fails with this code (a locked vault, no app), starting nothing. */
  fail: "locked" | "host_missing" | "not_found" | null = null;
  async start(tabId: number, itemId: string, viaProvider?: string, opts?: unknown) {
    if (this.fail) throw new BgError(this.fail);
    this.calls.push(["start", tabId, itemId, viaProvider]);
    this.opts.push(opts);
  }
  async stop(tabId: number) {
    this.calls.push(["stop", tabId]);
  }
  async state() {
    return this.view;
  }
}

async function setup(clock = { t: 1_000_000 }, nativeVault?: (call: NativeVaultCall) => Promise<NativeVault | null>, opens = true) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(answer);
  const chain = new FakeChain();
  const opened = { n: 0 };
  const bg = createBackground(ext, {
    pairings,
    newClient: () => client,
    sleep: async () => undefined,
    chain,
    now: () => clock.t,
    openApp: async () => {
      opened.n++;
      return opens;
    },
    ...(nativeVault ? { nativeVault } : {}),
  });
  bg.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  const top = contentSender(ext.runtime, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }))!;
  return { ext, client, chain, bg, top, clock, opened };
}

const hashOf = (url: string) => url.slice(url.indexOf("#") + 1);

describe("menu extras", () => {
  async function menu(ext: FakeExt) {
    const r = (await ext.send(
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = hashOf(r.ok.url);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    return { token, ui };
  }

  it("menu_signin starts the chain for an offered provider method and closes the menu", async () => {
    const { ext, chain } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "google" }, ui)).toEqual({ ok: {} });
    expect(chain.calls).toEqual([["start", 7, "it_02", "google"]]);
    // The progress shows where the menu was: under its field.
    expect(chain.opts).toEqual([{ anchorRef: "e1" }]);
    expect(ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "remove_frame").at(-1)).toEqual({
      tabId: 7,
      message: { type: "remove_frame", kind: "menu" },
      options: { documentId: "doc-1" },
    });
    // The token is spent.
    expect(await ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "invalid" });
  });

  it("menu_pick of a login on a sign-in form runs the sign-in to its end (chain), from where the menu was", async () => {
    const { ext, chain, client } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    // Identifier, password, then the code: the chain, not a one-page fill.
    expect(chain.calls).toEqual([["start", 7, "it_01", undefined]]);
    expect(chain.opts).toEqual([{ anchorRef: "e1", picked: "menu" }]);
    expect(client.requests.some((r) => r.op === "fill_login")).toBe(false);
    expect(ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    expect(await ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "invalid" });
  });

  it("menu_pick on a password change form only fills (no chain)", async () => {
    const { ext, chain } = await setup();
    const r = (await ext.send(
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "change_password" },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = hashOf(r.ok.url);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui);
    expect(chain.calls).toEqual([]);
  });

  it("menu_pick falls back to a fill where no chain can run", async () => {
    const { ext, chain, client } = await setup();
    chain.start = async () => {
      throw new BgError("insecure_origin");
    };
    const { token, ui } = await menu(ext);
    await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui);
    expect(client.requests.some((r) => r.op === "fill_login")).toBe(true);
  });

  describe("a menu row whose sign-in finds the vault locked or the app missing: no second click", () => {
    const cards = (ext: FakeExt) => ext.sentToTabs.filter((x) => (x.message as { type: string; kind?: string }).type === "show_frame" && (x.message as { kind?: string }).kind === "overlay");
    const cardOf = (ext: FakeExt) => {
      const m = cards(ext).at(-1)?.message as { url: string; ref?: string };
      const token = hashOf(m.url);
      return { token, ref: m.ref, ui: uiSender(`overlay.html#${token}`, 7) };
    };

    it("a login row: the app is asked at once, a card waits where the menu was, the sign-in starts after the unlock, once", async () => {
      const { ext, chain, client, opened, clock } = await setup();
      const { token, ui } = await menu(ext);
      chain.fail = "locked";
      appLocked = true;
      listLocked = true;
      expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
      expect(opened.n).toBe(1);
      expect(client.requests.filter((r) => r.op === "unlock")).toHaveLength(1);
      expect(chain.calls).toEqual([]);
      const card = cardOf(ext);
      expect(card.ref).toBe("e1");
      expect(ext.session.data.get(`overlay:${card.token}`)).toMatchObject({ tabId: 7, origin: SITE, documentId: "doc-1", pending: { kind: "start", itemId: "it_01", sent: true } });
      // The card loads while locked: it waits, it lists nothing.
      expect(await ext.send({ type: "overlay_init", token: card.token }, card.ui)).toEqual({ ok: { origin: SITE, accounts: [], chain: null, waiting: "locked" } });
      chain.fail = null;
      appLocked = false;
      listLocked = false;
      clock.t += 1500;
      expect(await ext.send({ type: "overlay_state", token: card.token }, card.ui)).toEqual({ ok: { chain: null } });
      expect(chain.calls).toEqual([["start", 7, "it_01", undefined]]);
      clock.t += 1500;
      await ext.send({ type: "overlay_state", token: card.token }, card.ui);
      expect(chain.calls).toHaveLength(1);
      expect(opened.n).toBe(1);
    });

    it("a provider row waits and resumes with its provider and the picked account", async () => {
      const { ext, chain, clock } = await setup();
      const { token, ui } = await menu(ext);
      chain.fail = "host_missing";
      appLocked = true;
      expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "google", accountId: "g_pro" }, ui)).toEqual({ ok: {} });
      const card = cardOf(ext);
      expect(ext.session.data.get(`overlay:${card.token}`)).toMatchObject({ pending: { kind: "start", itemId: "it_02", provider: "google", accountId: "g_pro" } });
      chain.fail = null;
      appLocked = false;
      clock.t += 1500;
      await ext.send({ type: "overlay_state", token: card.token }, card.ui);
      expect(chain.calls).toEqual([["start", 7, "it_02", "google"]]);
      expect(chain.opts).toEqual([{ accountId: "g_pro" }]);
    });

    it("the app cannot be opened: the error as before, no card", async () => {
      const { ext, chain } = await setup(undefined, undefined, false);
      const { token, ui } = await menu(ext);
      chain.fail = "locked";
      client_unlock_fails = true;
      expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ err: "locked" });
      expect(cards(ext)).toEqual([]);
    });
  });

  it("menu_pick in a child frame of exactly the top frame's origin runs the chain too; of another origin of the site it fills", async () => {
    const { ext, chain, client } = await setup();
    const open = async (url: string, doc: string) => {
      ext.setFrame(7, 4, url, doc);
      const r = (await ext.send({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" }, csSender(url, 7, 4, { documentId: doc }))) as { ok: { url: string } };
      const token = hashOf(r.ok.url);
      const ui = uiSender(`menu.html#${token}`, 7);
      await ext.send({ type: "menu_init", token }, ui);
      return { token, ui };
    };
    const same = await open(`${SITE}/frame`, "doc-4");
    expect(await ext.send({ type: "menu_pick", token: same.token, itemId: "it_01" }, same.ui)).toEqual({ ok: {} });
    expect(chain.calls).toEqual([["start", 7, "it_01", undefined]]);
    // No anchor in the top frame: the field lives in the child.
    expect(chain.opts).toEqual([{ picked: "menu" }]);
    const other = await open("https://login.atlas-cloud.test/frame", "doc-5");
    await ext.send({ type: "menu_pick", token: other.token, itemId: "it_01" }, other.ui);
    expect(chain.calls).toHaveLength(1);
    expect(client.requests.some((r) => r.op === "fill_login")).toBe(true);
  });

  it("menu_signin takes a picked account only among those the menu showed, and anchors the progress", async () => {
    const { ext, chain } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "google", accountId: "it_01" }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "google", accountId: "g_pro" }, ui)).toEqual({ ok: {} });
    expect(chain.opts).toEqual([{ accountId: "g_pro", anchorRef: "e1" }]);
  });

  it("menu_init gives each provider method its default account and the others", async () => {
    const { ext } = await setup();
    const r = (await ext.send(
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = hashOf(r.ok.url);
    const init = (await ext.send({ type: "menu_init", token }, uiSender(`menu.html#${token}`, 7))) as { ok: { choices: unknown } };
    expect(init.ok.choices).toEqual([
      {
        itemId: "it_02",
        provider: "google",
        accountId: "g_perso",
        accounts: [
          { itemId: "g_perso", email: "alex.perso@example.com", title: "Google perso" },
          { itemId: "g_pro", email: "alex.pro@example.com", title: "Google pro" },
        ],
      },
    ]);
  });

  it("keys from the field reach the menu of that very frame", async () => {
    const { ext } = await setup();
    const { token, ui } = await menu(ext);
    const field = csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });
    expect(await ext.send({ type: "menu_key", key: "down" }, field)).toEqual({ ok: {} });
    expect(await ext.send({ type: "menu_keys", token }, ui)).toEqual({ ok: { keys: ["down"] } });
    // Waiting: answered by the next key.
    const waiting = ext.send({ type: "menu_keys", token }, ui);
    await ext.send({ type: "menu_key", key: "enter" }, field);
    expect(await waiting).toEqual({ ok: { keys: ["enter"] } });
    // Another frame's keys do not reach it.
    await ext.send({ type: "menu_key", key: "up" }, csSender(`${SITE}/login`, 7, 3, { documentId: "doc-9" }));
    const other = ext.send({ type: "menu_keys", token }, ui);
    await ext.send({ type: "menu_close", token }, ui);
    expect(await other).toEqual({ ok: { keys: [] } });
    expect(await ext.send({ type: "menu_keys", token }, ui)).toEqual({ err: "invalid" });
  });

  it("menu_signin refuses a provider the item does not use", async () => {
    const { ext, chain } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "apple" }, ui)).toEqual({
      err: "invalid",
    });
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_01", provider: "google" }, ui)).toEqual({
      err: "invalid",
    });
    expect(chain.calls).toEqual([]);
  });

  it("iOS: the menu reads and unlocks the native vault with its token, nowhere else", async () => {
    const calls: NativeVaultCall[] = [];
    const vault = async (call: NativeVaultCall): Promise<NativeVault | null> => {
      calls.push(call);
      return { locked: call.op === "vault_state", account: "Camille", biometry: "faceID" };
    };
    const { ext } = await setup(undefined, vault);
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_vault", token }, ui)).toEqual({ ok: { locked: true, account: "Camille", biometry: "faceID" } });
    expect(await ext.send({ type: "menu_unlock_biometric", token }, ui)).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(await ext.send({ type: "menu_unlock_password", token, password: "pw" }, ui)).toEqual({
      ok: { locked: false, account: "Camille", biometry: "faceID" },
    });
    expect(calls).toEqual([{ op: "vault_state" }, { op: "unlock_biometric" }, { op: "unlock_password", password: "pw" }]);
    // A wrong token reaches nothing.
    expect(await ext.send({ type: "menu_unlock_biometric", token: "A".repeat(22) }, ui)).toHaveProperty("err");
    expect(calls).toHaveLength(3);
  });

  it("no native vault (macOS, other browsers): menu_vault is refused", async () => {
    const { ext } = await setup(undefined, async () => null);
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_vault", token }, ui)).toEqual({ err: "invalid" });
  });

  it("MS-03: after an unlock this menu asked for in the app, menu_resume closes it and runs its field's plan once", async () => {
    const { ext, clock } = await setup();
    const { token, ui } = await menu(ext);
    // Never without an unlock asked from this menu.
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    await ext.send({ type: "menu_unlock", token }, ui);
    clock.t += 10_000;
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    const sent = ext.sentToTabs.map((x) => x.message as { type: string });
    expect(sent.at(-2)).toEqual({ type: "remove_frame", kind: "menu" });
    expect(ext.sentToTabs.at(-1)).toEqual({
      tabId: 7,
      message: { type: "smart_fill", fieldRef: "e1", formRef: "f1", origin: SITE },
      options: { documentId: "doc-1" },
    });
    // Once: the token died with the menu, and a second resume is refused.
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "smart_fill")).toHaveLength(1);
  });

  it("MS-03: menu_resume is refused too late and from another tab; a frame's menu fills that frame only", async () => {
    const { ext, clock } = await setup();
    const { token, ui } = await menu(ext);
    await ext.send({ type: "menu_unlock", token }, ui);
    expect(await ext.send({ type: "menu_resume", token }, uiSender(`menu.html#${token}`, 8))).toEqual({ err: "invalid" });
    clock.t += UNLOCK_WAIT_MS + 1;
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(ext.sentToTabs.some((x) => (x.message as { type: string }).type === "smart_fill")).toBe(false);

    ext.setFrame(7, 3, `${SITE}/frame`, "doc-3");
    const r = (await ext.send(
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" },
      csSender(`${SITE}/frame`, 7, 3, { documentId: "doc-3" }),
    )) as { ok: { url: string } };
    const t3 = hashOf(r.ok.url);
    const ui3 = uiSender(`menu.html#${t3}`, 7);
    await ext.send({ type: "menu_unlock", token: t3 }, ui3);
    expect(await ext.send({ type: "menu_resume", token: t3 }, ui3)).toEqual({ ok: {} });
    const fills = ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "smart_fill");
    // The frame that asked, pinned to its document: never the top frame, never a whole-page fill.
    expect(fills).toEqual([{ tabId: 7, message: { type: "smart_fill", fieldRef: "e1", formRef: "f1", origin: SITE }, options: { documentId: "doc-3" } }]);
  });

  it("MS-03: menu_resume is refused once the menu's document changed", async () => {
    const { ext } = await setup();
    const { token, ui } = await menu(ext);
    await ext.send({ type: "menu_unlock", token }, ui);
    ext.setFrame(7, 0, "https://other.example/login", "doc-2");
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(ext.sentToTabs.some((x) => (x.message as { type: string }).type === "smart_fill")).toBe(false);
  });

  it("MS-03: same origin, new document id: refused too", async () => {
    const { ext } = await setup();
    const { token, ui } = await menu(ext);
    await ext.send({ type: "menu_unlock", token }, ui);
    ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(ext.sentToTabs.some((x) => (x.message as { type: string }).type === "smart_fill")).toBe(false);
  });

  it("MS-03: an unlock in the iOS sheet resumes in its own call; menu_resume after it is refused", async () => {
    const vault = async (call: NativeVaultCall): Promise<NativeVault | null> => ({ locked: call.op === "vault_state", account: "Camille", biometry: "faceID" });
    const { ext } = await setup(undefined, vault);
    const { token, ui } = await menu(ext);
    await ext.send({ type: "menu_unlock", token }, ui);
    await ext.send({ type: "menu_unlock_biometric", token, gesture: true }, ui);
    expect(await ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "smart_fill")).toHaveLength(1);
  });

  it("IOSSAF-01: the popup reads and unlocks the native vault; refused where there is none", async () => {
    const calls: NativeVaultCall[] = [];
    const vault = async (call: NativeVaultCall): Promise<NativeVault | null> => {
      calls.push(call);
      return { locked: call.op === "vault_state", account: "Camille", biometry: "faceID" };
    };
    const { ext } = await setup(undefined, vault);
    const popup = uiSender("popup.html");
    expect(await ext.send({ type: "popup_vault" }, popup)).toEqual({ ok: { locked: true, account: "Camille", biometry: "faceID" } });
    expect(await ext.send({ type: "popup_unlock_biometric" }, popup)).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(await ext.send({ type: "popup_unlock_password", password: "pw" }, popup)).toHaveProperty("ok");
    expect(calls).toEqual([{ op: "vault_state" }, { op: "unlock_biometric" }, { op: "unlock_password", password: "pw" }]);
    // Only from the popup page.
    expect(await ext.send({ type: "popup_unlock_biometric" }, uiSender("menu.html#x", 7))).toBe(NO_REPLY);
    expect(calls).toHaveLength(3);

    const mac = await setup(undefined, async () => null);
    expect(await mac.ext.send({ type: "popup_vault" }, popup)).toEqual({ err: "invalid" });
  });

  it("menu_pair closes the menu and opens the popup, else the popup page in a window", async () => {
    const { ext } = await setup();
    let opened = 0;
    const windows: unknown[] = [];
    (ext as unknown as { action: unknown }).action = { openPopup: async () => void opened++ };
    let { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_pair", token }, ui)).toEqual({ ok: {} });
    expect(opened).toBe(1);
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    // The browser refuses openPopup: the popup page in its own window.
    (ext as unknown as { action: unknown }).action = { openPopup: async () => Promise.reject(new Error("no")) };
    (ext as unknown as { windows: unknown }).windows = { getLastFocused: async () => ({}), create: async (o: unknown) => void windows.push(o) };
    ({ token, ui } = await menu(ext));
    expect(await ext.send({ type: "menu_pair", token }, ui)).toEqual({ ok: {} });
    expect(windows).toEqual([{ url: `${ext.runtime.getURL("popup.html")}`, type: "popup", width: 420, height: 600, focused: true }]);
    // A spent token cannot open it again.
    expect(await ext.send({ type: "menu_pair", token }, ui)).toHaveProperty("err");
  });

  it("menu_unlock asks the host, menu_close removes the frame", async () => {
    const { ext, client, opened } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_unlock", token }, ui)).toEqual({ ok: { locked: false } });
    expect(client.requests.at(-1)).toEqual({ op: "unlock", origin: SITE });
    // The click's process brings the app forward (macOS ignores the app's own activation).
    expect(opened.n).toBe(1);
    expect(await ext.send({ type: "menu_close", token }, ui)).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
  });
});

describe("overlay", () => {
  it("open shows overlay.html with a token in the top frame", async () => {
    const { ext, bg, top } = await setup();
    const token = await bg.overlays.open(top);
    expect(ext.sentToTabs).toEqual([
      {
        tabId: 7,
        message: { type: "show_frame", kind: "overlay", url: `chrome-extension://${EXT_ID}/overlay.html#${token}` },
        options: { documentId: "doc-1" },
      },
    ]);
    // Under the field the user clicked from, when given.
    const again = await bg.overlays.open(top, "e1");
    expect(ext.sentToTabs.at(-1)?.message).toEqual({
      type: "show_frame",
      kind: "overlay",
      url: `chrome-extension://${EXT_ID}/overlay.html#${again}`,
      ref: "e1",
    });
  });

  it("init lists password and provider sign-ins; start must be one of them", async () => {
    const { ext, bg, top, chain, client } = await setup();
    const token = await bg.overlays.open(top);
    const ui = uiSender(`overlay.html#${token}`, 7);
    const init = (await ext.send({ type: "overlay_init", token }, ui)) as { ok: Record<string, unknown> };
    expect(client.requests).toEqual([
      { op: "list_for_origin", ctx: "overlay", origin: SITE },
      { op: "provider_accounts", ctx: "overlay", provider: "google", origin: SITE },
    ]);
    expect(init.ok).toEqual({
      origin: SITE,
      chain: null,
      accounts: [
        { itemId: "it_01", title: "Atlas Cloud", subtitle: "alex@atlas.dev", iconLetter: "A", iconColor: "#14532D", vault: { id: "v1", name: "Personnel" } },
        {
          itemId: "it_02",
          title: "Atlas Perso",
          subtitle: "alex.perso@example.com",
          iconLetter: "A",
          iconColor: "#14532D",
          vault: { id: "v1", name: "Personnel" },
          provider: "google",
          email: "alex.perso@example.com",
          accountId: "g_perso",
          accounts: [
            { itemId: "g_perso", email: "alex.perso@example.com", title: "Google perso" },
            { itemId: "g_pro", email: "alex.pro@example.com", title: "Google pro" },
          ],
        },
      ],
    });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02" }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_99" }, ui)).toEqual({ err: "invalid" });
    // A picked account must be one the overlay showed for that provider.
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02", provider: "google", accountId: "it_01" }, ui)).toEqual({ err: "invalid" });
    // A password sign-in takes no account: dropped by the router.
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_01", accountId: "g_pro" }, ui)).toBe((await import("./fake-ext")).NO_REPLY);
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02", provider: "google" }, ui)).toEqual({ ok: {} });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02", provider: "google", accountId: "g_pro" }, ui)).toEqual({ ok: {} });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    expect(await ext.send({ type: "overlay_stop", token }, ui)).toEqual({ ok: {} });
    expect(chain.calls).toEqual([
      ["start", 7, "it_02", "google"],
      ["start", 7, "it_02", "google"],
      ["start", 7, "it_01", undefined],
      ["stop", 7],
    ]);
    expect(chain.opts).toEqual([{}, { accountId: "g_pro" }, {}]);
  });

  describe("a click on the card with the vault locked: asked at once, the sign-in starts by itself after the unlock", () => {
    /** The card, opened and listed while unlocked; then the vault locks. */
    async function lockedCard(nativeVault?: (call: NativeVaultCall) => Promise<NativeVault | null>, opens = true) {
      const t = await setup(undefined, nativeVault, opens);
      const token = await t.bg.overlays.open(t.top);
      const ui = uiSender(`overlay.html#${token}`, 7);
      await t.ext.send({ type: "overlay_init", token }, ui);
      t.chain.fail = "locked";
      appLocked = true;
      const unlock = () => {
        t.chain.fail = null;
        appLocked = false;
      };
      const state = () => t.ext.send({ type: "overlay_state", token }, ui);
      const unlocks = () => t.client.requests.filter((r) => r.op === "unlock").length;
      return { ...t, token, ui, unlock, state, unlocks };
    }

    it("the app comes forward with its unlock; the card waits; unlocked, the chain starts once with what was clicked", async () => {
      const t = await lockedCard();
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_02", provider: "google", accountId: "g_pro" }, t.ui)).toEqual({ ok: { waiting: "locked" } });
      expect(t.opened.n).toBe(1);
      expect(t.unlocks()).toBe(1);
      expect(t.chain.calls).toEqual([]);
      // What is kept: ids and a time on the card's own token, in storage.session (a restart keeps it).
      expect(t.ext.session.data.get(`overlay:${t.token}`)).toMatchObject({
        tabId: 7,
        origin: SITE,
        documentId: "doc-1",
        pending: { kind: "start", itemId: "it_02", provider: "google", accountId: "g_pro", at: 1_000_000, sent: true },
      });
      expect(await t.state()).toEqual({ ok: { chain: null, waiting: "locked" } });
      // Polled twice a second: the app is asked for its state once a second at most.
      const before = t.client.requests.filter((r) => r.op === "status").length;
      await t.state();
      await t.state();
      expect(t.client.requests.filter((r) => r.op === "status")).toHaveLength(before);
      t.unlock();
      t.clock.t += 1500;
      expect(await t.state()).toEqual({ ok: { chain: null } });
      expect(t.chain.calls).toEqual([["start", 7, "it_02", "google"]]);
      expect(t.chain.opts).toEqual([{ accountId: "g_pro" }]);
      // One attempt.
      t.clock.t += 1500;
      await t.state();
      expect(t.chain.calls).toHaveLength(1);
      expect((t.ext.session.data.get(`overlay:${t.token}`) as { pending?: unknown }).pending).toBeUndefined();
      expect(t.opened.n).toBe(1);
      expect(t.unlocks()).toBe(1);
    });

    it("the app unlocks at once (or Face ID on iOS in the click): the chain starts in the click's own call", async () => {
      let t = await lockedCard();
      onUnlock = t.unlock;
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ ok: {} });
      expect(t.chain.calls).toEqual([["start", 7, "it_01", undefined]]);

      // iOS: the vault of the handler, unlocked by the click's Face ID; the app is never opened.
      const calls: string[] = [];
      let vaultLocked = true;
      t = await lockedCard(async (call) => {
        calls.push(call.op);
        if (call.op === "unlock_biometric") {
          vaultLocked = false;
          t.unlock();
        }
        return { locked: vaultLocked, account: "Camille", biometry: "faceID" };
      });
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ ok: {} });
      expect(calls).toEqual(["vault_state", "unlock_biometric"]);
      expect(t.chain.calls).toEqual([["start", 7, "it_01", undefined]]);
      expect(t.opened.n).toBe(0);

      // iOS, Face ID cancelled: locked, nothing waits.
      t = await lockedCard(async () => ({ locked: true, account: "Camille", biometry: "faceID" }));
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ err: "locked" });
      expect(await t.state()).toEqual({ ok: { chain: null } });
    });

    it("the app cannot be opened: locked as before, nothing waits; another start error is not an unlock", async () => {
      let t = await lockedCard(undefined, false);
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ err: "locked" });
      t.unlock();
      t.clock.t += 1500;
      expect(await t.state()).toEqual({ ok: { chain: null } });
      expect(t.chain.calls).toEqual([]);

      t = await lockedCard();
      t.chain.fail = "not_found";
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ err: "not_found" });
      expect(t.opened.n).toBe(0);
    });

    it("nothing starts past 90 s, in another document or origin, from another tab, or after Annuler", async () => {
      let t = await lockedCard();
      await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui);
      t.unlock();
      t.clock.t += UNLOCK_WAIT_MS + 1;
      expect(await t.state()).toEqual({ ok: { chain: null } });
      expect(t.chain.calls).toEqual([]);
      // Too late once, too late for good.
      t.clock.t -= UNLOCK_WAIT_MS;
      await t.state();
      expect(t.chain.calls).toEqual([]);

      for (const [url, doc] of [[`${SITE}/login`, "doc-2"], ["https://other.example/login", "doc-1"], ["http://atlas-cloud.test/login", "doc-1"]] as const) {
        t = await lockedCard();
        await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui);
        t.unlock();
        t.clock.t += 1500;
        t.ext.setFrame(7, 0, url, doc);
        expect(await t.state()).toEqual({ ok: { chain: null } });
        // Refused once: the page coming back changes nothing.
        t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
        t.clock.t += 1500;
        await t.state();
        expect(t.chain.calls).toEqual([]);
      }

      t = await lockedCard();
      await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui);
      t.unlock();
      t.clock.t += 1500;
      expect(await t.ext.send({ type: "overlay_state", token: t.token }, uiSender(`overlay.html#${t.token}`, 8))).toEqual({ err: "invalid" });
      expect(t.chain.calls).toEqual([]);

      t = await lockedCard();
      await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui);
      await t.ext.send({ type: "overlay_stop", token: t.token }, t.ui);
      t.unlock();
      t.clock.t += 1500;
      expect(await t.state()).toEqual({ ok: { chain: null } });
      expect(t.chain.calls).toEqual([["stop", 7]]);
    });

    it("the app is not running: launched by the click, the card waits for it, asks its unlock once it answers, then starts", async () => {
      const t = await lockedCard();
      t.chain.fail = "host_missing";
      // Launched, not answering yet.
      const down = vi.spyOn(t.bg.session, "request").mockRejectedValue(new BgError("host_missing"));
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ ok: { waiting: "host_missing" } });
      expect(t.opened.n).toBe(1);
      expect(await t.state()).toEqual({ ok: { chain: null, waiting: "host_missing" } });
      // It runs, locked: its unlock is asked now, once.
      down.mockRestore();
      t.clock.t += 1500;
      expect(await t.state()).toEqual({ ok: { chain: null, waiting: "locked" } });
      t.clock.t += 1500;
      await t.state();
      expect(t.unlocks()).toBe(1);
      t.unlock();
      t.clock.t += 1500;
      expect(await t.state()).toEqual({ ok: { chain: null } });
      expect(t.chain.calls).toEqual([["start", 7, "it_01", undefined]]);
      expect(t.opened.n).toBe(1);
    });
  });

  describe("a generic card on a sign-in page reached with the vault locked", () => {
    async function generic(opens = true) {
      const t = await setup(undefined, undefined, opens);
      appLocked = true;
      listLocked = true;
      const token = await t.bg.overlays.open(t.top, undefined, true);
      const ui = uiSender(`overlay.html#${token}`, 7);
      const unlock = () => {
        appLocked = false;
        listLocked = false;
      };
      return { ...t, token, ui, unlock };
    }
    const smart = (ext: FakeExt) => ext.sentToTabs.filter((x) => (x.message as { type: string }).type === "smart_fill");

    it("the tab committed another page between the card's own check and the resume: nothing is sent there", async () => {
      const t = await generic();
      await t.ext.send({ type: "overlay_init", token: t.token }, t.ui);
      await t.ext.send({ type: "overlay_unlock", token: t.token }, t.ui);
      t.unlock();
      t.clock.t += 1500;
      // The first look at the top frame after the vault answered open is the card's check: the
      // page commits right after it.
      const statuses = () => t.client.requests.filter((r) => r.op === "status").length;
      const before = statuses();
      const real = t.ext.webNavigation.getFrame;
      let moved = false;
      t.ext.webNavigation.getFrame = async (d) => {
        const f = await real(d);
        if (!moved && d.frameId === 0 && statuses() > before) {
          moved = true;
          t.ext.setFrame(7, 0, "https://evil.test/login", "doc-9");
        }
        return f;
      };
      await t.ext.send({ type: "overlay_state", token: t.token }, t.ui);
      expect(moved).toBe(true);
      expect(smart(t.ext)).toEqual([]);
    });

    it("says nothing of the vault: no account, no item, only that it is generic", async () => {
      const t = await generic();
      expect(await t.ext.send({ type: "overlay_init", token: t.token }, t.ui)).toEqual({ ok: { origin: SITE, accounts: [], chain: null, generic: true } });
      // Nothing can be started from it by id.
      expect(await t.ext.send({ type: "overlay_start", token: t.token, itemId: "it_01" }, t.ui)).toEqual({ err: "invalid" });
    });

    it("its click asks the app once; unlocked, the page's own plan runs once (the chain, or the menu), in the card's document", async () => {
      const t = await generic();
      await t.ext.send({ type: "overlay_init", token: t.token }, t.ui);
      expect(await t.ext.send({ type: "overlay_unlock", token: t.token }, t.ui)).toEqual({ ok: { waiting: "locked" } });
      expect(t.opened.n).toBe(1);
      expect(t.client.requests.filter((r) => r.op === "unlock")).toHaveLength(1);
      expect(t.ext.session.data.get(`overlay:${t.token}`)).toMatchObject({ pending: { kind: "page", sent: true } });
      expect(await t.ext.send({ type: "overlay_state", token: t.token }, t.ui)).toEqual({ ok: { chain: null, waiting: "locked" } });
      expect(smart(t.ext)).toEqual([]);
      t.unlock();
      t.clock.t += 1500;
      expect(await t.ext.send({ type: "overlay_state", token: t.token }, t.ui)).toEqual({ ok: { chain: null } });
      // Bound to the card's document and origin: the content script checks the origin again.
      expect(smart(t.ext)).toEqual([{ tabId: 7, message: { type: "smart_fill", origin: SITE }, options: { documentId: "doc-1" } }]);
      t.clock.t += 1500;
      await t.ext.send({ type: "overlay_state", token: t.token }, t.ui);
      expect(smart(t.ext)).toHaveLength(1);
      // The plan that smart fill sends is the resumed gesture: it asks the app nothing more.
      expect(t.opened.n).toBe(1);
      // Open now: the card lists the site's sign-ins like any card.
      const init = (await t.ext.send({ type: "overlay_init", token: t.token }, t.ui)) as { ok: { accounts: unknown[]; generic?: boolean } };
      expect(init.ok.accounts).toHaveLength(2);
      expect(init.ok.generic).toBeUndefined();
    });

    it("nothing runs past 90 s, in another document, or when the app cannot be opened; only a generic card unlocks", async () => {
      let t = await generic();
      await t.ext.send({ type: "overlay_unlock", token: t.token }, t.ui);
      t.unlock();
      t.clock.t += UNLOCK_WAIT_MS + 1;
      await t.ext.send({ type: "overlay_state", token: t.token }, t.ui);
      expect(smart(t.ext)).toEqual([]);

      t = await generic();
      await t.ext.send({ type: "overlay_unlock", token: t.token }, t.ui);
      t.unlock();
      t.ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
      t.clock.t += 1500;
      await t.ext.send({ type: "overlay_state", token: t.token }, t.ui);
      expect(smart(t.ext)).toEqual([]);

      t = await generic(false);
      client_unlock_fails = true;
      expect(await t.ext.send({ type: "overlay_unlock", token: t.token }, t.ui)).toEqual({ err: "locked" });
      client_unlock_fails = false;

      const plain = await setup();
      const token = await plain.bg.overlays.open(plain.top);
      expect(await plain.ext.send({ type: "overlay_unlock", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({ err: "invalid" });
    });
  });

  it("the card's first account is the one the page's plan would sign in with (used last on this site)", async () => {
    const { ext, bg, top } = await setup();
    planFor = { intent: "login", action: "open_chain", confidence: "high", alternatives: ["it_01"], reasons: ["last_on_site"], groups: [{ form_ref: "f1", kind: "login", item_id: "it_03", fields: [{ field_ref: "f1e0", role: "username" }, { field_ref: "f1e1", role: "current_password" }] }] };
    ext.tabReply = (_tab, m) =>
      (m as { type: string }).type === "plan_request"
        ? { ok: true, context: { forms: [{ form_ref: "f1", intent_hints: { kind: "login", signup_words: false, reset_words: false, checkout_words: false, ignore: false }, step_index: null, fields: [{ field_ref: "f1e0", role: "username", confidence: 1, visible: true, prefilled: "empty" }, { field_ref: "f1e1", role: "current_password", confidence: 1, visible: true, prefilled: "empty" }], buttons: [] }], typed_username_hash: null } }
        : undefined;
    const token = await bg.overlays.open(top);
    const init = (await ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))) as { ok: { accounts: { itemId: string }[] } };
    expect(init.ok.accounts.map((a) => a.itemId)).toEqual(["it_03", "it_01", "it_02"]);
    // A plan that cannot choose (the menu), or none: the order of the list as it is.
    planFor = { ...planFor, action: "show_menu", confidence: "low", reasons: ["tie"] };
    const again = await bg.overlays.open(top);
    const init2 = (await ext.send({ type: "overlay_init", token: again }, uiSender(`overlay.html#${again}`, 7))) as { ok: { accounts: { itemId: string }[] } };
    expect(init2.ok.accounts.map((a) => a.itemId)).toEqual(["it_01", "it_02", "it_03"]);
  });

  it("contract with the Mac app: a card's cold launch sends `unlock` once when the app answers, even already unlocked", async () => {
    const t = await setup();
    const token = await t.bg.overlays.open(t.top);
    const ui = uiSender(`overlay.html#${token}`, 7);
    await t.ext.send({ type: "overlay_init", token }, ui);
    t.chain.fail = "host_missing";
    const down = vi.spyOn(t.bg.session, "request").mockRejectedValue(new BgError("host_missing"));
    expect(await t.ext.send({ type: "overlay_start", token, itemId: "it_01" }, ui)).toEqual({ ok: { waiting: "host_missing" } });
    // The app runs, unlocked through its launch link before the bridge connected.
    down.mockRestore();
    t.chain.fail = null;
    appLocked = false;
    t.clock.t += 1500;
    expect(await t.ext.send({ type: "overlay_state", token }, ui)).toEqual({ ok: { chain: null } });
    expect(t.client.requests.filter((r) => r.op === "unlock")).toHaveLength(1);
    expect(t.chain.calls).toEqual([["start", 7, "it_01", undefined]]);
    t.clock.t += 1500;
    await t.ext.send({ type: "overlay_state", token }, ui);
    expect(t.client.requests.filter((r) => r.op === "unlock")).toHaveLength(1);
  });

  it("the provider account last picked on a site is the default there", async () => {
    const { ext, bg, top } = await setup();
    await ext.storage.local.set({ "signin:atlas-cloud.test|google": "g_pro" });
    const token = await bg.overlays.open(top);
    const ui = uiSender(`overlay.html#${token}`, 7);
    const init = (await ext.send({ type: "overlay_init", token }, ui)) as { ok: { accounts: { accountId?: string; email?: string }[] } };
    expect(init.ok.accounts[1]).toMatchObject({ accountId: "g_pro", email: "alex.pro@example.com" });
  });

  it("one surface: opening the menu removes an offered overlay, and is refused while a chain runs", async () => {
    const { ext, bg, top, chain } = await setup();
    await bg.overlays.open(top);
    const open = () =>
      ext.send({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    expect(await open()).toEqual({ ok: { url: expect.stringContaining("menu.html#") } });
    expect(ext.sentToTabs.at(-1)).toEqual({ tabId: 7, message: { type: "remove_frame", kind: "overlay" }, options: { documentId: "doc-1" } });
    expect(await bg.overlays.tokens.hasTab(7)).toBe(false);
    // While a chain runs, its progress stays and no menu opens over it.
    await bg.overlays.open(top);
    chain.view = { itemId: "it_01", status: "running", steps: [] };
    expect(await open()).toEqual({ err: "not_allowed" });
    expect(await bg.overlays.tokens.hasTab(7)).toBe(true);
  });

  it("a click into an empty field opens the menu only when it has something to offer", async () => {
    const { ext } = await setup();
    const auto = (formKind: string) =>
      ext.send({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind, auto: true }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    expect(await auto("login")).toEqual({ ok: { url: expect.stringContaining("menu.html#") } });
    emptyVault = true;
    try {
      expect(await auto("login")).toEqual({ err: "not_found" });
      expect(await auto("card")).toEqual({ err: "not_found" });
      // A new password form always offers to generate one.
      expect(await auto("signup")).toEqual({ ok: { url: expect.stringContaining("menu.html#") } });
    } finally {
      emptyVault = false;
    }
  });

  it("resize relays the page's height to its own frame only", async () => {
    const { ext, bg, top } = await setup();
    const token = await bg.overlays.open(top);
    expect(await ext.send({ type: "overlay_resize", token, height: 188 }, uiSender(`overlay.html#${token}`, 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)).toEqual({ tabId: 7, message: { type: "resize_frame", kind: "overlay", height: 188 }, options: { documentId: "doc-1" } });
    expect(await ext.send({ type: "overlay_resize", token, height: 188 }, uiSender(`overlay.html#${token}`, 8))).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "overlay_resize", token, height: 1.5 }, uiSender(`overlay.html#${token}`, 7))).toBe((await import("./fake-ext")).NO_REPLY);
  });

  it("state relays the chain view; other tabs and other pages are refused", async () => {
    const { ext, bg, top, chain } = await setup();
    const token = await bg.overlays.open(top);
    chain.view = { itemId: "it_01", status: "stopped", reason: "captcha", steps: [{ label: "Identifiant rempli", state: "done" }] };
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({
      ok: { chain: chain.view },
    });
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`overlay.html#${token}`, 8))).toEqual({
      err: "invalid",
    });
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`menu.html#${token}`, 7))).toBe(
      (await import("./fake-ext")).NO_REPLY,
    );
  });

  it("dies with a navigation of the top frame; close removes the frame", async () => {
    const { ext, bg, top } = await setup();
    let token = await bg.overlays.open(top);
    ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(await ext.send({ type: "overlay_state", token }, uiSender("overlay.html", 7))).toEqual({ err: "invalid" });
    token = await bg.overlays.open(top);
    expect(await ext.send({ type: "overlay_close", token }, uiSender("overlay.html", 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "overlay" });
  });
});

describe("save prompt", () => {
  const pending = {
    tabId: 7,
    origin: SITE,
    documentId: "doc-1",
    kind: "login" as const,
    status: "new" as const,
    username: "alex@atlas.dev",
    password: "typed-Secret-1",
  };
  const edits = { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v2", rule: "exact_host", tags: ["Travail"] };

  it("titleFromSite", () => {
    expect(titleFromSite("atlas-cloud.test")).toBe("Atlas Cloud");
  });

  it("init never carries the password; reveal does", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    expect(ext.sentToTabs[0]?.message).toEqual({
      type: "show_frame",
      kind: "save",
      url: `chrome-extension://${EXT_ID}/save.html#${token}`,
    });
    const ui = uiSender(`save.html#${token}`, 7);
    const init = await ext.send({ type: "save_init", token }, ui);
    expect(init).toEqual({
      ok: {
        origin: SITE,
        site: "atlas-cloud.test",
        kind: "login",
        status: "new",
        title: "Atlas Cloud",
        username: "alex@atlas.dev",
        vaults: [
          { id: "v1", name: "Personnel" },
          { id: "v2", name: "Projet Atlas" },
        ],
        defaultVault: "v1",
      },
    });
    expect(JSON.stringify(init)).not.toContain("typed-Secret-1");
    expect(await ext.send({ type: "save_reveal", token }, ui)).toEqual({ ok: { password: "typed-Secret-1" } });
    // Memory only: nothing in storage.
    expect(JSON.stringify([...ext.session.data.values(), ...ext.local.data.values()])).not.toContain("typed-Secret-1");
  });

  it("without a documentId, the prompt carries an origin pin and goes to frame 0", async () => {
    const { ext, bg } = await setup();
    const { documentId: _drop, ...rest } = pending;
    const token = await bg.saves.open({ ...rest, topOrigin: SITE });
    expect(ext.sentToTabs[0]?.message).toEqual({
      type: "show_frame",
      kind: "save",
      url: `chrome-extension://${EXT_ID}/save.html#${token}`,
      origin: SITE,
    });
    expect(ext.sentToTabs[0]?.options).toEqual({ frameId: 0 });
  });

  it("save uses the typed password unless one was generated", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open(pending);
    const ui = uiSender(`save.html#${token}`, 7);
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ ok: { outcome: "saved", vault: "Projet Atlas" } });
    expect(client.requests.at(-1)).toEqual({
      op: "save_login",
      ctx: "save_prompt",
      origin: SITE,
      title: "Atlas Cloud",
      username: "alex@atlas.dev",
      password: "typed-Secret-1",
      vault_id: "v2",
      rule: "exact_host",
      tags: ["Travail"],
    });
    // Decided: no second save, no reveal; close still works.
    expect(await ext.send({ type: "save_reveal", token }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "save_close", token }, ui)).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });

    const t2 = await bg.saves.open(pending);
    const ui2 = uiSender(`save.html#${t2}`, 7);
    expect(await ext.send({ type: "save_generate", token: t2 }, ui2)).toEqual({ ok: { password: "Gen-Pass-123" } });
    await ext.send({ type: "save_decide", token: t2, decision: "save", edits }, ui2);
    expect(client.requests.at(-1)).toMatchObject({ op: "save_login", password: "Gen-Pass-123" });
  });

  it("tags only OnePass sets are dropped from the prompt's edits", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open(pending);
    const ui = uiSender(`save.html#${token}`, 7);
    const tags = ["Travail", "onepass:pending", " onepass:weak-by-site "];
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits: { ...edits, tags } }, ui)).toEqual({ ok: { outcome: "saved", vault: "Projet Atlas" } });
    expect(client.requests.at(-1)).toMatchObject({ op: "save_login", tags: ["Travail"] });
  });

  it("update targets only the item check_credentials named", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open({ ...pending, status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } });
    const ui = uiSender(`save.html#${token}`, 7);
    expect(await ext.send({ type: "save_decide", token, decision: "update", itemId: "it_evil" }, ui)).toEqual({ ok: { outcome: "updated" } });
    expect(client.requests.at(-1)).toEqual({
      op: "update_password",
      ctx: "save_prompt",
      item_id: "it_01",
      origin: SITE,
      password: "typed-Secret-1",
    });
  });

  it("never stores the registrable domain in storage.local neverSave", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open({ ...pending, origin: "https://admin.atlas-cloud.test" });
    expect(await ext.send({ type: "save_decide", token, decision: "never" }, uiSender("save.html", 7))).toEqual({ ok: { outcome: "done" } });
    expect(ext.local.data.get(NEVER_SAVE_KEY)).toEqual(["atlas-cloud.test"]);
    expect(await bg.neverSave.has("atlas-cloud.test")).toBe(true);
  });

  it("the password is blanked as soon as the prompt is saved", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    const ui = uiSender(`save.html#${token}`, 7);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    expect(rec?.password).toBe("typed-Secret-1");
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ ok: { outcome: "saved", vault: "Projet Atlas" } });
    expect(rec?.password).toBe("");
  });

  it("the password is blanked when an expired record is dropped on resolve", async () => {
    const { bg, clock } = await setup();
    const token = await bg.saves.open(pending);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    clock.t += SAVE_TTL_MS + 1;
    expect(await bg.saves.tokens.resolve(token, { tabId: 7 } as never)).toBeNull();
    expect(rec?.password).toBe("");
  });

  it("the password is blanked as soon as the prompt is dismissed or closed", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
    expect(rec?.password).toBe("");
    const t2 = await bg.saves.open(pending);
    const rec2 = await bg.saves.tokens.resolve(t2, { tabId: 7 } as never);
    await ext.send({ type: "save_close", token: t2 }, uiSender("save.html", 7));
    expect(rec2?.password).toBe("");
  });

  it("dismiss removes the frame; the prompt expires after 2 minutes", async () => {
    const { ext, bg, clock } = await setup();
    let token = await bg.saves.open(pending);
    expect(await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });
    token = await bg.saves.open(pending);
    clock.t += SAVE_TTL_MS + 1;
    expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
  });

  it("the record holding the password is purged by timer after 2 minutes", async () => {
    vi.useFakeTimers();
    try {
      const { ext, bg } = await setup();
      const token = await bg.saves.open(pending);
      const rec = await bg.saves.tokens.resolve(token, { page: "save.html", tabId: 7 });
      expect(rec?.password).toBe("typed-Secret-1");
      await vi.advanceTimersByTimeAsync(SAVE_TTL_MS - 1);
      expect(rec?.password).toBe("typed-Secret-1");
      await vi.advanceTimersByTimeAsync(1);
      // Wiped and revoked without anyone resolving the token.
      expect(rec?.password).toBe("");
      expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });
      expect(await ext.send({ type: "save_reveal", token }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("a dismissed prompt cancels its purge timer", async () => {
    vi.useFakeTimers();
    try {
      const { ext, bg } = await setup();
      const token = await bg.saves.open(pending);
      await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  describe("automatic save and its toast (spec 4.1)", () => {
    const tokenOf = (ext: FakeExt) => {
      const m = ext.sentToTabs.filter((x) => (x.message as { type?: string }).type === "show_frame").at(-1)?.message as { url: string };
      return hashOf(m.url);
    };

    it("autoSave saves in the default vault, then opens the toast; init names it a toast with undo", async () => {
      const { ext, bg, client } = await setup();
      expect(await bg.saves.autoSave(pending)).toEqual({ itemId: "it_new" });
      expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({ origin: SITE, username: "alex@atlas.dev", password: "typed-Secret-1", vault_id: "v1" });
      const token = tokenOf(ext);
      const init = (await ext.send({ type: "save_init", token }, uiSender("save.html", 7))) as { ok: Record<string, unknown> };
      expect(init.ok).toMatchObject({ view: "toast", undo: true, username: "alex@atlas.dev" });
      expect(JSON.stringify(init)).not.toContain("typed-Secret-1");
    });

    it("a shared target vault: nothing saved, the card instead", async () => {
      const { ext, bg, client } = await setup();
      vaultsFor = () => ({ vaults: [{ id: "vs", name: "Équipe", color: null, shared: true }] });
      expect(await bg.saves.autoSave(pending)).toBeNull();
      expect(client.requests.some((r) => r.op === "save_login")).toBe(false);
      const init = (await ext.send({ type: "save_init", token: tokenOf(ext) }, uiSender("save.html", 7))) as { ok: Record<string, unknown> };
      expect(init.ok.view).toBeUndefined();
    });

    it("undo marks the credential quiet", async () => {
      const { ext, bg, client } = await setup();
      await bg.saves.autoSave(pending);
      const token = tokenOf(ext);
      expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-1"))).toBe(false);
      expect(await ext.send({ type: "save_undo", token }, uiSender("save.html", 7))).toEqual({ ok: {} });
      expect(client.requests.at(-1)).toEqual({ op: "undo_save", ctx: "save_prompt", item_id: "it_new", origin: SITE });
      // The same submission gets nothing now (save-flow asks recentlyDismissed first).
      expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-1"))).toBe(true);
      // Done: the record holds no password any more, a second undo is refused.
      expect(await ext.send({ type: "save_undo", token }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
    });

    it("undo refused by the bridge: not_found, nothing quieted", async () => {
      const { ext, bg } = await setup();
      await bg.saves.autoSave(pending);
      const token = tokenOf(ext);
      undoAnswer = new BridgeAppError("not_found", "gone");
      expect(await ext.send({ type: "save_undo", token }, uiSender("save.html", 7))).toEqual({ err: "not_found" });
      expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-1"))).toBe(false);
    });

    it("Edit then Save: the auto-saved login is replaced by the edited one", async () => {
      const { ext, bg, client } = await setup();
      await bg.saves.autoSave(pending);
      const token = tokenOf(ext);
      const ui = uiSender("save.html", 7);
      // Not in edit mode yet: a toast takes no save.
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ err: "invalid" });
      expect(await ext.send({ type: "save_edit", token }, ui)).toEqual({ ok: {} });
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ ok: { outcome: "saved", vault: "Projet Atlas" } });
      // The edited login is written first, then the saved one goes.
      const ops = client.requests.map((r) => r.op);
      expect(ops.slice(ops.lastIndexOf("save_login") - 1)).toEqual(["vaults", "save_login", "undo_save"]);
      expect(client.requests.at(-2)).toMatchObject({ op: "save_login", password: "typed-Secret-1", vault_id: "v2", rule: "exact_host" });
      expect(client.requests.at(-1)).toEqual({ op: "undo_save", ctx: "save_prompt", item_id: "it_new", origin: SITE });
    });
  });

  it("the vault used last for the site is picked first next time", async () => {
    const { ext, bg } = await setup();
    let token = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender("save.html", 7));
    expect(ext.local.data.get("saveVaults")).toEqual({ last: "v2", sites: { "atlas-cloud.test": "v2" } });
    token = await bg.saves.open(pending);
    expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toMatchObject({ ok: { defaultVault: "v2" } });
  });

  describe("several accounts: a save goes to the account its page routes to", () => {
    // The app lists the routed account's vaults first when the request names the page.
    const perso = { id: "v1", name: "Personnel", color: null, account: "Camille" };
    const work = { id: "w1", name: "Equipe", color: null, account: "Atlas SAS" };
    const routed = (r: Record<string, unknown>) => ({ vaults: r.origin === SITE ? [work, perso] : [perso, work] });

    it("the save sheet lists the vaults for its page and defaults to the first of that list", async () => {
      vaultsFor = routed;
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open(pending);
      expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toMatchObject({ ok: { defaultVault: "w1", vaults: [{ id: "w1" }, { id: "v1" }] } });
      expect(client.requests.filter((r) => r.op === "vaults")).toEqual([{ op: "vaults", origin: SITE }]);
    });

    it("the vault last used on another site, in another account, is not the default here; this site's own last choice is", async () => {
      vaultsFor = routed;
      const { ext, bg } = await setup();
      await ext.local.set({ saveVaults: { last: "v1", sites: { "other.test": "v1" } } });
      let token = await bg.saves.open(pending);
      expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toMatchObject({ ok: { defaultVault: "w1" } });
      await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
      // The user once chose the personal vault for this very site: kept.
      await ext.local.set({ saveVaults: { last: "v1", sites: { "atlas-cloud.test": "v1" } } });
      token = await bg.saves.open(pending);
      expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toMatchObject({ ok: { defaultVault: "v1" } });
    });

    it("Save sends the user's explicit vault as it is; a choice that is not listed falls to the page's default", async () => {
      vaultsFor = routed;
      const { ext, bg, client } = await setup();
      let token = await bg.saves.open(pending);
      await ext.send({ type: "save_decide", token, decision: "save", edits: { ...edits, vaultId: "v1" } }, uiSender("save.html", 7));
      expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({ vault_id: "v1" });
      client.requests.length = 0;
      await ext.local.remove("saveVaults");
      token = await bg.saves.open({ ...pending, username: "other@atlas.dev" });
      await ext.send({ type: "save_decide", token, decision: "save", edits: { ...edits, username: "other@atlas.dev", vaultId: "" } }, uiSender("save.html", 7));
      expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({ vault_id: "w1" });
      expect(client.requests.filter((r) => r.op === "vaults").every((r) => r.origin === SITE)).toBe(true);
    });

    it("no list to choose from: `vault_id` is empty, the app's default vault for the page", async () => {
      vaultsFor = () => ({ vaults: [] });
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open(pending);
      await ext.send({ type: "save_decide", token, decision: "save", edits: { ...edits, vaultId: "" } }, uiSender("save.html", 7));
      expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({ vault_id: "", origin: SITE });
      expect(ext.local.data.get("saveVaults")).toBeUndefined();
    });

    it("an app from before `origin` on `vaults`: asked again without it, once for the session", async () => {
      vaultsFor = (r) => ("origin" in r ? new BridgeAppError("invalid", "unknown field") : { vaults: [perso, work] });
      const { ext, bg, client } = await setup();
      let token = await bg.saves.open(pending);
      expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toMatchObject({ ok: { defaultVault: "v1" } });
      expect(client.requests.filter((r) => r.op === "vaults")).toEqual([{ op: "vaults", origin: SITE }, { op: "vaults" }]);
      await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
      token = await bg.saves.open(pending);
      await ext.send({ type: "save_init", token }, uiSender("save.html", 7));
      expect(client.requests.filter((r) => r.op === "vaults")).toEqual([{ op: "vaults", origin: SITE }, { op: "vaults" }, { op: "vaults" }]);
    });
  });

  it("left unanswered: the sign-in waits in the popup (no password there), Save from the popup saves it", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open(pending);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    expect(await ext.send({ type: "save_decide", token, decision: "later" }, uiSender("save.html", 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });
    expect(rec?.password).toBe("");
    const popup = uiSender("popup.html");
    const list = (await ext.send({ type: "popup_pending" }, popup)) as { ok: { pending: { id: string }[] } };
    expect(list.ok.pending).toEqual([
      { id: expect.any(String), origin: SITE, site: "atlas-cloud.test", username: "alex@atlas.dev", status: "new", vault: "Personnel" },
    ]);
    expect(JSON.stringify(list)).not.toContain("typed-Secret-1");
    const id = list.ok.pending[0]!.id;
    expect(await ext.send({ type: "popup_pending_decide", id, decision: "save" }, popup)).toEqual({ ok: { outcome: "saved", vault: "Personnel" } });
    expect(client.requests.at(-1)).toMatchObject({ op: "save_login", password: "typed-Secret-1", username: "alex@atlas.dev", vault_id: "v1", title: "Atlas Cloud" });
    expect(await ext.send({ type: "popup_pending" }, popup)).toEqual({ ok: { pending: [] } });
    // Gone with its tab too.
    const t2 = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token: t2, decision: "later" }, uiSender("save.html", 7));
    ext.onRemoved.emit(7);
    expect(await ext.send({ type: "popup_pending" }, popup)).toEqual({ ok: { pending: [] } });
  });

  it("opened while locked: Save unlocks, asks again, and says when the login is already there", async () => {
    const { ext, bg, client, opened } = await setup();
    const token = await bg.saves.open({ ...pending, locked: true });
    checkAnswer = { status: "same", item_id: "it_01" };
    try {
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender("save.html", 7))).toEqual({ ok: { outcome: "already" } });
      expect(opened.n).toBe(1);
      expect(client.requests.map((r) => r.op)).toEqual(expect.arrayContaining(["unlock", "check_credentials"]));
      // The card's unlock names the top origin of its tab.
      expect(client.requests.find((r) => r.op === "unlock")).toEqual({ op: "unlock", origin: SITE });
      expect(client.requests.some((r) => r.op === "save_login")).toBe(false);
      const t2 = await bg.saves.open({ ...pending, locked: true });
      checkAnswer = { status: "update", item_id: "it_01", title: "Atlas Cloud" };
      expect(await ext.send({ type: "save_decide", token: t2, decision: "save", edits }, uiSender("save.html", 7))).toEqual({ ok: { outcome: "updated" } });
      expect(client.requests.at(-1)).toEqual({ op: "update_password", ctx: "save_prompt", item_id: "it_01", origin: SITE, password: "typed-Secret-1" });
    } finally {
      checkAnswer = { status: "new" };
    }
  });

  it("iOS, opened while locked: Save unlocks the native vault with Face ID once, never the app", async () => {
    const calls: NativeVaultCall[] = [];
    let unlocked = false;
    const vault = async (call: NativeVaultCall): Promise<NativeVault | null> => {
      calls.push(call);
      if (call.op === "unlock_biometric") unlocked = true;
      return { locked: !unlocked, account: "Camille", biometry: "faceID" };
    };
    const { ext, bg, client, opened } = await setup(undefined, vault);
    const token = await bg.saves.open({ ...pending, locked: true });
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender("save.html", 7))).toMatchObject({ ok: { outcome: "saved" } });
    expect(calls).toEqual([{ op: "vault_state" }, { op: "unlock_biometric" }]);
    expect(opened.n).toBe(0);
    expect(client.requests.some((r) => r.op === "unlock")).toBe(false);
    expect(client.requests.map((r) => r.op)).toEqual(expect.arrayContaining(["check_credentials", "save_login"]));
  });

  it("iOS, opened while locked: Face ID refused leaves the card locked, nothing saved", async () => {
    const vault = async (): Promise<NativeVault | null> => ({ locked: true, account: "Camille", biometry: "faceID", error: "cancelled" });
    const { ext, bg, client, opened } = await setup(undefined, vault);
    const token = await bg.saves.open({ ...pending, locked: true });
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender("save.html", 7))).toEqual({ err: "locked" });
    expect(opened.n).toBe(0);
    expect(client.requests.some((r) => r.op === "save_login" || r.op === "unlock")).toBe(false);
  });

  it("'Pas maintenant' quiets that very credential only, for a few minutes", async () => {
    const { ext, bg, clock } = await setup();
    const token = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
    const same = loginQuietKey("ALEX@atlas.dev ", "typed-Secret-1");
    expect(await bg.saves.recentlyDismissed(SITE, same)).toBe(true);
    // Another password, another account, another site: asked as usual.
    expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-2"))).toBe(false);
    expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("sam@atlas.dev", "typed-Secret-1"))).toBe(false);
    expect(await bg.saves.recentlyDismissed("https://borealis.test", same)).toBe(false);
    // Same site, another subdomain: the same registrable domain, still quiet.
    expect(await bg.saves.recentlyDismissed("https://app.atlas-cloud.test", same)).toBe(true);
    clock.t += DISMISS_QUIET_MS + 1;
    expect(await bg.saves.recentlyDismissed(SITE, same)).toBe(false);
  });

  it("a card left alone or saved does not quiet anything; nothing secret is kept for the quiet rule", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token, decision: "later" }, uiSender("save.html", 7));
    expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-1"))).toBe(false);
    const t2 = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token: t2, decision: "save", edits }, uiSender("save.html", 7));
    expect(await bg.saves.recentlyDismissed(SITE, loginQuietKey("alex@atlas.dev", "typed-Secret-1"))).toBe(false);
    const t3 = await bg.saves.open(pending);
    await ext.send({ type: "save_decide", token: t3, decision: "dismiss" }, uiSender("save.html", 7));
    const held = JSON.stringify([...(bg.saves as unknown as { dismissed: Map<string, number> }).dismissed.keys()]);
    expect(held).not.toContain("typed-Secret-1");
    expect(held).not.toContain("alex");
  });

  it("IOSSAF-10: a login saved meanwhile (iOS's own sheet through OnePass) is not saved twice", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open(pending);
    checkAnswer = { status: "same", item_id: "it_01" };
    try {
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender("save.html", 7))).toEqual({ ok: { outcome: "already" } });
      expect(client.requests.some((r) => r.op === "save_login")).toBe(false);
    } finally {
      checkAnswer = { status: "new" };
    }
  });

  describe("card and identity typed by hand (MS-04)", () => {
    const card = { cardholder: "Alex Martin", number: "4111111111111111", exp_month: "04", exp_year: "2029" };
    const cardPending = { tabId: 7, origin: SITE, documentId: "doc-1", kind: "card" as const, status: "new" as const, username: "", password: "", card };
    const identity = {
      given_name: "Alex",
      family_name: "Martin",
      email: "alex@atlas.dev",
      tel: "",
      organization: "",
      address: { line1: "1 rue de la Paix", line2: "", city: "Paris", postal_code: "75002", region: "", country: "FR" },
    };
    const vaultOnly = { title: "", username: "", password: "", vaultId: "v2", rule: "domain", tags: [] };

    it("the card shows the last four digits and expiry, never the number; Save writes the card, no security code", async () => {
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open(cardPending);
      const ui = uiSender(`save.html#${token}`, 7);
      const init = await ext.send({ type: "save_init", token }, ui);
      expect(init).toMatchObject({ ok: { kind: "card", status: "new", card: { last4: "1111", exp: "04/29", holder: "Alex Martin" } } });
      expect(JSON.stringify(init)).not.toContain("4111111111111111");
      expect(await ext.send({ type: "save_reveal", token }, ui)).toEqual({ ok: { password: "" } });
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits: vaultOnly }, ui)).toEqual({ ok: { outcome: "saved", vault: "Projet Atlas" } });
      expect(client.requests.at(-1)).toEqual({
        op: "save_card",
        ctx: "save_prompt",
        origin: SITE,
        vault_id: "v2",
        title: "",
        cardholder: "Alex Martin",
        number: "4111111111111111",
        exp_month: "04",
        exp_year: "2029",
      });
      expect(JSON.stringify(client.requests.at(-1))).not.toContain("cvv");
    });

    it("update: only the card check_card named gets the new expiry", async () => {
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open({ ...cardPending, status: "update", update: { itemId: "card_1", title: "Visa" } });
      const ui = uiSender(`save.html#${token}`, 7);
      expect(await ext.send({ type: "save_decide", token, decision: "update" }, ui)).toEqual({ ok: { outcome: "updated" } });
      expect(client.requests.at(-1)).toMatchObject({ op: "save_card", item_id: "card_1", number: "4111111111111111", exp_month: "04" });
    });

    it("the card number is dropped with the card; 'Pas maintenant' quiets that card only", async () => {
      const { ext, bg } = await setup();
      const token = await bg.saves.open(cardPending);
      const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
      await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
      expect(rec?.card).toBeUndefined();
      expect(await bg.saves.recentlyDismissed(SITE, cardQuietKey("4111 1111 1111 1111", "04", "2029"))).toBe(true);
      // Another card, or the same with another expiry (an update): asked.
      expect(await bg.saves.recentlyDismissed(SITE, cardQuietKey("5555555555554444", "04", "2029"))).toBe(false);
      expect(await bg.saves.recentlyDismissed(SITE, cardQuietKey("4111111111111111", "05", "2031"))).toBe(false);
    });

    it("an identity: name, e-mail and city on the card; Save writes the identity", async () => {
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open({ ...cardPending, kind: "identity", card: undefined, identity } as never);
      const ui = uiSender(`save.html#${token}`, 7);
      expect(await ext.send({ type: "save_init", token }, ui)).toMatchObject({
        ok: { kind: "identity", identity: { name: "Alex Martin", email: "alex@atlas.dev", place: "1 rue de la Paix, 75002, Paris" } },
      });
      await ext.send({ type: "save_decide", token, decision: "save", edits: vaultOnly }, ui);
      expect(client.requests.at(-1)).toEqual({ op: "save_identity", ctx: "save_prompt", origin: SITE, vault_id: "v2", title: "", ...identity });
    });

    it("a card OnePass already holds but did not fill here: shown, Save writes nothing and says so", async () => {
      const { ext, bg, client } = await setup();
      const token = await bg.saves.open({ ...cardPending, known: true });
      const n = client.requests.length;
      expect(await ext.send({ type: "save_decide", token, decision: "save", edits: vaultOnly }, uiSender("save.html", 7))).toEqual({ ok: { outcome: "already" } });
      expect(client.requests.slice(n).some((r) => r.op === "save_card")).toBe(false);
    });

    it("update is refused for an identity (nothing named to update)", async () => {
      const { ext, bg } = await setup();
      const token = await bg.saves.open({ ...cardPending, kind: "identity", card: undefined, identity } as never);
      expect(await ext.send({ type: "save_decide", token, decision: "update" }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
    });
  });

  it("provider link variant calls link_provider", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open({
      ...pending,
      kind: "provider_link",
      username: "",
      password: "",
      provider: { id: "google", accountItemId: "it_g", email: "alex.perso@example.com" },
    });
    const ui = uiSender("save.html", 7);
    expect(await ext.send({ type: "save_init", token }, ui)).toMatchObject({
      ok: { kind: "provider_link", provider: { id: "google", email: "alex.perso@example.com" }, vaults: [] },
    });
    await ext.send({ type: "save_decide", token, decision: "save" }, ui);
    expect(client.requests.at(-1)).toEqual({
      op: "link_provider",
      ctx: "save_prompt",
      site_origin: SITE,
      provider: "google",
      account_item_id: "it_g",
    });
  });
});
