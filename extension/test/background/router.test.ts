import { describe, expect, it } from "vitest";
import { BridgeAppError } from "../../src/bridge/client";
import { createBackground } from "../../src/background/app";
import { parseCsToBg, parseUiToBg } from "../../src/background/router";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { type Answer, FakeClient, record } from "./fake-client";
import { EXT_ID, FakeExt, NO_REPLY, csSender, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

const login = (id: string, title: string) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title,
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#3355ff",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
});

const defaultAnswer: Answer = (r) => {
  switch (r.op) {
    case "status":
      return { locked: false, account: "alex@atlas.dev", vaults: 2 };
    case "list_for_origin":
      return { items: [login("it_01", "Atlas Cloud")] };
    case "fill_login":
      return { username: "alex@atlas.dev", password: "pw-1" };
    case "generate":
      return { password: "Gen-Pass-123", entropy_bits: 90 };
    default:
      return {};
  }
};

async function setup(answer: Answer = defaultAnswer) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(answer);
  const bg = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined });
  bg.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  return { ext, client, bg };
}

const page = () => csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });

async function openMenu(ext: FakeExt, extra: Record<string, unknown> = {}): Promise<string> {
  const r = (await ext.send({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login", ...extra }, page())) as {
    ok: { url: string };
  };
  const url = r.ok.url;
  expect(url.startsWith(`chrome-extension://${EXT_ID}/menu.html#`)).toBe(true);
  return url.slice(url.indexOf("#") + 1);
}

describe("router", () => {
  it("content_script_cannot_send_ui_messages", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext);
    for (const m of [
      { type: "popup_status" },
      { type: "menu_init", token },
      { type: "menu_pick", token, itemId: "it_01" },
      { type: "popup_pair_start" },
    ]) {
      expect(await ext.send(m, page())).toBe(NO_REPLY);
    }
    expect(client.requests).toEqual([]);
    expect(ext.sentToTabs).toEqual([]);
  });

  it("extension pages cannot send content script messages", async () => {
    const { ext, bg } = await setup();
    expect(
      await ext.send({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" }, uiSender("menu.html", 7)),
    ).toBe(NO_REPLY);
    expect(await ext.send({ type: "close_menu" }, uiSender("popup.html"))).toBe(NO_REPLY);
    void bg;
  });

  it("each UI family is accepted only from its own page", async () => {
    const { ext } = await setup();
    expect(await ext.send({ type: "popup_status" }, uiSender("popup.html"))).toEqual({
      ok: { locked: false, account: "alex@atlas.dev", vaults: 2 },
    });
    expect(await ext.send({ type: "popup_status" }, uiSender("menu.html", 7))).toBe(NO_REPLY);
    expect(await ext.send({ type: "popup_status" }, uiSender("popup.html", undefined, { id: "other-extension" }))).toBe(
      NO_REPLY,
    );
    // A web page URL claiming to be the popup is a content script, and refused.
    expect(await ext.send({ type: "popup_status" }, csSender(`${SITE}/popup.html`))).toBe(NO_REPLY);
  });

  it("origin_taken_from_sender_not_message", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext, { origin: "https://evil.test", url: "https://evil.test/" });
    const init = (await ext.send({ type: "menu_init", token }, uiSender(`menu.html#${token}`, 7))) as {
      ok: { origin: string; items: unknown[] };
    };
    expect(init.ok.origin).toBe(SITE);
    expect(client.requests).toEqual([{ op: "list_for_origin", ctx: "menu", origin: SITE }]);
    // A page analysis claiming another URL changes nothing either.
    expect(parseCsToBg({ type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login", origin: "x" })).toEqual({
      type: "open_menu",
      fieldRef: "e1",
      formRef: "f1",
      formKind: "login",
    });
  });

  it("menu open, init and pick fill the bound frame", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    expect(client.requests[1]).toEqual({
      op: "fill_login",
      ctx: "menu",
      item_id: "it_01",
      origin: SITE,
      fields: ["username", "password"],
    });
    expect(ext.sentToTabs).toEqual([
      {
        tabId: 7,
        message: {
          type: "fill",
          origin: SITE,
          formRef: "f1",
          values: { username: "alex@atlas.dev", email: "alex@atlas.dev", current_password: "pw-1" },
        },
        options: { documentId: "doc-1" },
      },
    ]);
  });

  it("a pick outside the offered items, or from another tab, is refused", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_99" }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, uiSender("menu.html", 8))).toEqual({
      err: "invalid",
    });
    expect(client.requests.filter((r) => r.op === "fill_login")).toEqual([]);
  });

  it("a pick after navigation is refused", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    // The frame changes document without a commit event reaching us.
    ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ err: "origin_mismatch" });
    expect(client.requests.filter((r) => r.op === "fill_login")).toEqual([]);
  });

  it("generate fills new and confirm password fields", async () => {
    const { ext } = await setup();
    const token = await openMenu(ext, { formKind: "signup" });
    expect(await ext.send({ type: "menu_generate", token }, uiSender(`menu.html#${token}`, 7))).toEqual({ ok: {} });
    expect((ext.sentToTabs[0]?.message as { values: unknown }).values).toEqual({
      new_password: "Gen-Pass-123",
      confirm_password: "Gen-Pass-123",
    });
  });

  it("locked surfaces as a stable code to the menu", async () => {
    const { ext } = await setup(() => new BridgeAppError("locked", "raw host text"));
    const token = await openMenu(ext);
    expect(await ext.send({ type: "menu_init", token }, uiSender(`menu.html#${token}`, 7))).toEqual({ err: "locked" });
  });

  it("refuses menus on insecure or opaque origins", async () => {
    const { ext } = await setup();
    const m = { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" };
    expect(await ext.send(m, csSender("http://atlas-cloud.test/login"))).toEqual({ err: "insecure_origin" });
    // Sandboxed frame: opaque origin, whatever its URL.
    expect(await ext.send(m, csSender(`${SITE}/x`, 7, 2, { origin: "null" }))).toBe(NO_REPLY);
    // No tab or frame: not a content script.
    expect(await ext.send(m, { id: EXT_ID, url: `${SITE}/x`, origin: SITE })).toBe(NO_REPLY);
  });

  it("unknown or malformed messages get no reply", async () => {
    const { ext } = await setup();
    for (const m of [
      null,
      "open_menu",
      { type: "nope" },
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "bank" },
      { type: "open_menu", fieldRef: "x".repeat(65), formRef: "f1", formKind: "login" },
      { type: "open_menu", fieldRef: "a b", formRef: "f1", formKind: "login" },
      { type: "open_menu", fieldRef: 3, formRef: "f1", formKind: "login" },
    ]) {
      expect(await ext.send(m, page())).toBe(NO_REPLY);
    }
    expect(await ext.send({ type: "menu_init", token: "short" }, uiSender("menu.html", 7))).toBe(NO_REPLY);
  });
});

describe("message validation", () => {
  const analysis = {
    url: `${SITE}/login`,
    forms: [{ ref: "f1", kind: "login", fields: [{ ref: "e1", role: "username" }, { ref: "e2", role: "otp", parts: ["a", "b", "c", "d"] }] }],
    captcha: false,
    push: false,
    providerButtons: [{ provider: "google", ref: "p1" }],
    accountChooser: [{ email: "alex.perso@example.com", ref: "c1" }],
  };

  it("accepts and rebuilds a page analysis, dropping unknown keys", () => {
    expect(parseCsToBg({ type: "page_analysis", analysis: { ...analysis, evil: 1 } })).toEqual({
      type: "page_analysis",
      analysis,
    });
  });

  it("rejects bad roles, kinds, booleans, providers and oversize lists", () => {
    const bad = [
      { ...analysis, forms: [{ ref: "f1", kind: "login", fields: [{ ref: "e1", role: "pin" }] }] },
      { ...analysis, forms: [{ ref: "f1", kind: "bank", fields: [] }] },
      { ...analysis, captcha: "no" },
      { ...analysis, providerButtons: [{ provider: "myspace", ref: "p1" }] },
      { ...analysis, forms: Array.from({ length: 65 }, () => analysis.forms[0]) },
      { ...analysis, forms: [{ ref: "f1", kind: "otp", fields: [{ ref: "e2", role: "otp", parts: Array(9).fill("a") }] }] },
      { ...analysis, url: "x".repeat(5000) },
    ];
    for (const a of bad) expect(parseCsToBg({ type: "page_analysis", analysis: a })).toBeNull();
    expect(parseCsToBg({ type: "submitted_credentials", formRef: "f1", username: "a", password: "", isNew: false })).toBeNull();
    expect(parseCsToBg({ type: "submitted_credentials", formRef: "f1", username: "a", password: "p", isNew: "yes" })).toBeNull();
    expect(parseCsToBg({ type: "account_click", email: "x".repeat(400), ref: "c1" })).toBeNull();
  });

  it("validates UI messages", () => {
    const token = "A".repeat(22);
    expect(parseUiToBg({ type: "menu_pick", token, itemId: "it_01", extra: 1 })).toEqual({
      type: "menu_pick",
      token,
      itemId: "it_01",
    });
    expect(parseUiToBg({ type: "menu_pick", token, itemId: "" })).toBeNull();
    expect(parseUiToBg({ type: "save_decide", token, decision: "steal" })).toBeNull();
    expect(
      parseUiToBg({
        type: "save_decide",
        token,
        decision: "save",
        edits: { title: "Atlas", username: "alex@atlas.dev", password: "p", vaultId: "v1", rule: "domain", tags: ["web"] },
      }),
    ).not.toBeNull();
    expect(parseUiToBg({ type: "popup_search", query: "q".repeat(300) })).toBeNull();
  });

  it("validates the popup messages", () => {
    expect(parseUiToBg({ type: "popup_generate", kind: "random", length: 24, symbols: true, x: 1 })).toEqual({
      type: "popup_generate",
      kind: "random",
      length: 24,
      symbols: true,
    });
    expect(parseUiToBg({ type: "popup_generate", kind: "smart" })).toEqual({ type: "popup_generate", kind: "smart" });
    expect(parseUiToBg({ type: "popup_forget", itemId: "x" })).toEqual({ type: "popup_forget" });
    for (const bad of [
      { type: "popup_generate", kind: "words" },
      { type: "popup_generate", kind: "random", length: 3 },
      { type: "popup_generate", kind: "random", length: 129 },
      { type: "popup_generate", kind: "random", length: 10.5 },
      { type: "popup_generate", kind: "random", symbols: "yes" },
      { type: "popup_fill_generated", password: "" },
      { type: "popup_item", itemId: "" },
      { type: "popup_reveal" },
    ]) {
      expect(parseUiToBg(bad)).toBeNull();
    }
    // The popup never names a fill target: extra fields are dropped.
    expect(parseUiToBg({ type: "popup_fill", itemId: "it_01", tabId: 3, origin: "https://evil.test" })).toEqual({
      type: "popup_fill",
      itemId: "it_01",
    });
    expect(parseUiToBg({ type: "popup_suggestions", origin: "https://evil.test" })).toEqual({ type: "popup_suggestions" });
  });

  it("validates the menu, overlay and save page messages", () => {
    const token = "A".repeat(22);
    expect(parseUiToBg({ type: "menu_signin", token, itemId: "it_01", provider: "google", x: 1 })).toEqual({
      type: "menu_signin",
      token,
      itemId: "it_01",
      provider: "google",
    });
    expect(parseUiToBg({ type: "menu_signin", token, itemId: "it_01", provider: "myspace" })).toBeNull();
    expect(parseUiToBg({ type: "menu_signin", token, itemId: "it_01" })).toBeNull();
    expect(parseUiToBg({ type: "overlay_start", token, itemId: "it_01" })).toEqual({ type: "overlay_start", token, itemId: "it_01" });
    expect(parseUiToBg({ type: "overlay_start", token, itemId: "it_01", provider: "x" })).toEqual({
      type: "overlay_start",
      token,
      itemId: "it_01",
      provider: "x",
    });
    expect(parseUiToBg({ type: "overlay_start", token, itemId: "it_01", provider: 3 })).toBeNull();
    for (const type of ["menu_unlock", "menu_close", "overlay_state", "overlay_close", "save_reveal", "save_generate", "save_close"]) {
      expect(parseUiToBg({ type, token, password: "x" })).toEqual({ type, token });
      expect(parseUiToBg({ type, token: "short" })).toBeNull();
    }
  });
});
