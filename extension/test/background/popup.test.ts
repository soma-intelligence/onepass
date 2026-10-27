import { beforeEach, describe, expect, it, vi } from "vitest";
import { BridgeAppError } from "../../src/bridge/client";
import { createBackground } from "../../src/background/app";
import { HISTORY_KEY, resetGeneratorHistoryForTests } from "../../src/background/popup";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { type Answer, FakeClient, record } from "./fake-client";
import { FakeExt, csSender, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

beforeEach(() => resetGeneratorHistoryForTests());

const summary = (id: string, kind = "login") => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind,
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: true,
  methods: [],
  match: "domain",
});

const answer: Answer = (r) => {
  switch (r.op) {
    case "status":
      return { locked: false, account: "alex@atlas.dev", vaults: 2 };
    case "list_for_origin":
      return { items: [summary("it_01")] };
    case "search":
      return { items: [summary("it_02"), summary("card_1", "card")] };
    case "reveal":
      return { value: "pw-1" };
    case "totp":
      return { code: "703083", remaining: 27 };
    case "fill_login":
      return { username: "alex@atlas.dev", password: "pw-1" };
    case "generate":
      return { password: `gen-${(r.recipe as { kind: string }).kind}`, entropy_bits: 80 };
    default:
      return {};
  }
};

const analysis = (forms: unknown[]) => ({ url: `${SITE}/login`, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] });

async function setup(a: Answer = answer, opts: { paired?: boolean; openError?: Error } = {}) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  if (opts.paired !== false) await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(a, async () => {
    if (opts.openError) throw opts.openError;
  });
  const bg = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, now: () => 42 });
  bg.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  ext.activeTab = { id: 7, url: `${SITE}/login` };
  const popup = uiSender("popup.html");
  const send = (m: unknown) => ext.send(m, popup);
  const reportForms = (forms: unknown[]) =>
    ext.send({ type: "page_analysis", analysis: analysis(forms) }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
  return { ext, client, bg, send, reportForms, pairings };
}

describe("popup background", () => {
  it("suggestions for the active tab origin, from the browser", async () => {
    const { send, client } = await setup();
    expect(await send({ type: "popup_suggestions" })).toEqual({ ok: { domain: "atlas-cloud.test", items: [summary("it_01")] } });
    expect(client.requests).toEqual([{ op: "list_for_origin", ctx: "popup", origin: SITE }]);
  });

  it("no suggestions on a non-HTTPS tab", async () => {
    const { ext, send, client } = await setup();
    ext.activeTab = { id: 7, url: "http://atlas-cloud.test/login" };
    expect(await send({ type: "popup_suggestions" })).toEqual({ ok: { domain: null, items: [] } });
    ext.activeTab = { id: 7, url: "chrome://settings" };
    expect(await send({ type: "popup_suggestions" })).toEqual({ ok: { domain: null, items: [] } });
    expect(client.requests).toEqual([]);
  });

  it("item, reveal and totp only for items the popup was shown", async () => {
    const { send, client } = await setup();
    expect(await send({ type: "popup_item", itemId: "it_01" })).toEqual({ err: "not_found" });
    await send({ type: "popup_suggestions" });
    await send({ type: "popup_search", query: "atlas" });
    expect(await send({ type: "popup_item", itemId: "it_01" })).toEqual({ ok: { summary: summary("it_01"), website: SITE } });
    expect(await send({ type: "popup_item", itemId: "it_02" })).toEqual({ ok: { summary: summary("it_02") } });
    expect(await send({ type: "popup_reveal", itemId: "it_01" })).toEqual({ ok: { value: "pw-1" } });
    expect(await send({ type: "popup_totp", itemId: "it_01" })).toEqual({ ok: { code: "703083", remaining: 27 } });
    expect(client.requests.slice(-2)).toEqual([
      { op: "reveal", ctx: "popup", item_id: "it_01", field: "password" },
      { op: "totp", ctx: "popup", item_id: "it_01" },
    ]);
  });

  it("Remplir fills the active tab's top frame, never a target named by the popup", async () => {
    const { ext, send, client, reportForms } = await setup();
    await send({ type: "popup_suggestions" });
    expect(await send({ type: "popup_fill", itemId: "it_01" })).toEqual({ err: "no_form" });
    await reportForms([{ ref: "f1", kind: "login", fields: [{ ref: "e1", role: "username" }, { ref: "e2", role: "current_password" }] }]);
    expect(await send({ type: "popup_fill", itemId: "it_01", tabId: 99, origin: "https://evil.test" })).toEqual({
      ok: { domain: "atlas-cloud.test" },
    });
    expect(client.requests.at(-1)).toEqual({
      op: "fill_login",
      ctx: "popup",
      item_id: "it_01",
      origin: SITE,
      fields: ["username", "password"],
    });
    expect(ext.sentToTabs.at(-1)).toMatchObject({ tabId: 7, options: { documentId: "doc-1" }, message: { type: "fill", formRef: "f1" } });
  });

  it("Remplir refuses when the tab navigated elsewhere since the analysis", async () => {
    const { ext, send, reportForms, client } = await setup();
    await send({ type: "popup_suggestions" });
    await reportForms([{ ref: "f1", kind: "login", fields: [{ ref: "e1", role: "username" }] }]);
    ext.activeTab = { id: 7, url: "https://evil.test/login" };
    expect(await send({ type: "popup_fill", itemId: "it_01" })).toEqual({ err: "no_form" });
    // Same origin but a new document: the fill pipeline refuses it.
    ext.activeTab = { id: 7, url: `${SITE}/login` };
    ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    expect(await send({ type: "popup_fill", itemId: "it_01" })).toEqual({ err: "origin_mismatch" });
    expect(client.requests.filter((r) => r.op === "fill_login")).toEqual([]);
  });

  it("generator: recipe kinds, history of 20 in memory, cleared on locked", async () => {
    let locked = false;
    const { ext, send } = await setup((r) => (r.op === "list_for_origin" && locked ? new BridgeAppError("locked", "x") : answer(r)));
    expect(await send({ type: "popup_generate", kind: "random", length: 24, symbols: true })).toEqual({
      ok: { password: "gen-random", entropy_bits: 80 },
    });
    for (let i = 0; i < 25; i++) await send({ type: "popup_generate", kind: "pin" });
    const h = (await send({ type: "popup_history" })) as { ok: { entries: unknown[] } };
    expect(h.ok.entries).toHaveLength(20);
    expect(h.ok.entries[0]).toEqual({ password: "gen-pin", kind: "pin", at: 42 });
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
    locked = true;
    expect(await send({ type: "popup_suggestions" })).toEqual({ err: "locked" });
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
    expect(await send({ type: "popup_history" })).toEqual({ ok: { entries: [] } });
    expect(await send({ type: "popup_generate", kind: "smart", length: 2 })).toBe((await import("./fake-ext")).NO_REPLY);
  });

  it("status locked clears the history too", async () => {
    const { ext, send } = await setup((r) => (r.op === "status" ? { locked: true, account: "alex@atlas.dev", vaults: 2 } : answer(r)));
    await send({ type: "popup_generate", kind: "memorable" });
    expect(await send({ type: "popup_history" })).toMatchObject({ ok: { entries: [{ kind: "memorable" }] } });
    await send({ type: "popup_status" });
    expect(await send({ type: "popup_history" })).toEqual({ ok: { entries: [] } });
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
  });

  it("generator Remplir targets a new password form", async () => {
    const { send, reportForms, ext } = await setup();
    await reportForms([{ ref: "f9", kind: "signup", fields: [{ ref: "e1", role: "new_password" }] }]);
    expect(await send({ type: "popup_fill_generated", password: "gen-smart" })).toEqual({ ok: { domain: "atlas-cloud.test" } });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({
      type: "fill",
      origin: SITE,
      formRef: "f9",
      values: { new_password: "gen-smart", confirm_password: "gen-smart" },
    });
  });

  it("unpaired is reported even with a stored record the host no longer knows", async () => {
    const { send } = await setup(answer, { openError: new BridgeAppError("unknown_pairing", "gone") });
    expect(await send({ type: "popup_status" })).toEqual({ err: "unpaired" });
    const fresh = await setup(answer, { paired: false });
    expect(await fresh.send({ type: "popup_status" })).toEqual({ err: "unpaired" });
  });

  it("Oublier cet appairage drops the record, the items shown and the history", async () => {
    const { ext, send, pairings, client } = await setup();
    await send({ type: "popup_suggestions" });
    await send({ type: "popup_generate", kind: "pin" });
    expect(await send({ type: "popup_item", itemId: "it_01" })).toMatchObject({ ok: { summary: { item_id: "it_01" } } });
    expect(await send({ type: "popup_forget" })).toEqual({ ok: {} });
    expect(pairings.value).toBeUndefined();
    expect(await send({ type: "popup_history" })).toEqual({ ok: { entries: [] } });
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
    expect(await send({ type: "popup_item", itemId: "it_01" })).toEqual({ err: "not_found" });
    expect(client.closed).toBe(true);
    expect(await send({ type: "popup_status" })).toEqual({ err: "unpaired" });
  });

  it("locked forgets the items the popup was shown", async () => {
    let locked = false;
    const { send } = await setup((r) => (r.op === "reveal" && locked ? new BridgeAppError("locked", "x") : answer(r)));
    await send({ type: "popup_suggestions" });
    locked = true;
    expect(await send({ type: "popup_reveal", itemId: "it_01" })).toEqual({ err: "locked" });
    expect(await send({ type: "popup_item", itemId: "it_01" })).toEqual({ err: "not_found" });
  });
});

describe("generator history memory hygiene (security hardening 6.3)", () => {
  it("never writes the history to storage.session or storage.local", async () => {
    const { ext, send } = await setup();
    await send({ type: "popup_generate", kind: "pin" });
    await send({ type: "popup_generate", kind: "smart" });
    const dump = JSON.stringify([...ext.session.data.entries(), ...ext.local.data.entries()]);
    expect(dump).not.toContain("gen-pin");
    expect(dump).not.toContain("gen-smart");
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
  });

  it("removes an old storage.session history once at startup", async () => {
    const ext = new FakeExt();
    await ext.session.set({ [HISTORY_KEY]: [{ password: "old-secret", kind: "pin", at: 1 }] });
    const pairings = new MemoryPairingStore();
    createBackground(ext, { pairings, newClient: () => new FakeClient(answer), sleep: async () => undefined, now: () => 42 });
    await new Promise((r) => setTimeout(r, 0));
    expect(ext.session.data.has(HISTORY_KEY)).toBe(false);
  });

  it("generator_history_survives_restart_as_empty", async () => {
    const mk = async () => {
      const mod = await import("../../src/background/popup");
      const { FakeArea } = await import("./fake-ext");
      return new mod.PopupBackend({
        ext: {} as never,
        area: new FakeArea(),
        session: { request: (async () => ({ password: "gen-x", entropy_bits: 1 })) as never, onLocked: () => undefined },
        pairing: {} as never,
        filler: {} as never,
        analyses: {} as never,
      });
    };
    const before = await mk();
    await before.generate("pin");
    expect((await before.history()).entries).toHaveLength(1);
    // Service worker restart: the module is evaluated again.
    vi.resetModules();
    const after = await mk();
    await expect(after.history()).resolves.toEqual({ entries: [] });
  });
});
