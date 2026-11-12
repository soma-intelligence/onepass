import { describe, expect, it } from "vitest";
import { BridgeAppError } from "../../src/bridge/client";
import { createBackground } from "../../src/background/app";
import { parseCsToBg, parseUiToBg } from "../../src/background/router";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { FORMS_ROLES } from "../../src/shared/messages";
import { MAX_CLASSIFY_FIELDS } from "../../src/shared/model-labels";
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
    // A sign-up form: the pick fills (on a sign-in form it runs the chain, pages.test.ts).
    const token = await openMenu(ext, { formKind: "signup" });
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    expect(await ext.send({ type: "menu_pick", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    expect(client.requests[1]).toEqual({
      op: "fill_login",
      ctx: "menu",
      item_id: "it_01",
      origin: SITE,
      fields: ["username"],
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
    // The autofill history: the browser profile once, the list, the pick at its rank. Ids only.
    await new Promise((r) => setTimeout(r, 0));
    expect(client.history[0]).toEqual(expect.objectContaining({ op: "client_info", browser: expect.any(String) }));
    const notes = client.history.filter((r) => r.op === "note_autofill");
    expect(notes.map((r) => r.action)).toEqual(["shown", "picked"]);
    expect(notes[1]).toEqual({ op: "note_autofill", ctx: "menu", origin: SITE, action: "picked", item_id: "it_01", rank: 0 });
    expect(JSON.stringify(client.history)).not.toContain("pw-1");
  });

  it("a menu closed without a pick is a dismissal of its first entry", async () => {
    const { ext, client } = await setup();
    const token = await openMenu(ext);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    await ext.send({ type: "menu_close", token }, ui);
    await new Promise((r) => setTimeout(r, 0));
    const notes = client.history.filter((r) => r.op === "note_autofill");
    expect(notes.map((r) => [r.action, r.item_id ?? null])).toEqual([
      ["shown", null],
      ["dismissed", "it_01"],
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
    // The page's rules first, from the menu's very document, then the fill.
    expect(ext.sentToTabs[0]).toEqual({
      tabId: 7,
      message: { type: "password_context", origin: SITE, formRef: "f1" },
      options: { documentId: "doc-1" },
    });
    expect((ext.sentToTabs[1]?.message as { values: unknown }).values).toEqual({
      new_password: "Gen-Pass-123",
      confirm_password: "Gen-Pass-123",
    });
  });

  it("generate on a signup form saves the password pending, not on a change-password form", async () => {
    const answer: Answer = (r) =>
      r.op === "vaults"
        ? { vaults: [{ id: "v1", name: "Perso", color: null }] }
        : r.op === "save_login"
          ? { item_id: "it_new" }
          : r.op === "generate"
            ? { password: "Gen-Pass-123", entropy_bits: 50, report: { weak_by_site: true } }
            : defaultAnswer(r);
    const { ext, client } = await setup(answer);
    const token = await openMenu(ext, { formKind: "signup" });
    expect(await ext.send({ type: "menu_generate", token }, uiSender(`menu.html#${token}`, 7))).toEqual({ ok: {} });
    expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({
      origin: SITE,
      password: "Gen-Pass-123",
      tags: ["onepass:pending", "onepass:weak-by-site"],
    });
    const other = await setup(answer);
    const reset = await openMenu(other.ext, { formKind: "change_password" });
    expect(await other.ext.send({ type: "menu_generate", token: reset }, uiSender(`menu.html#${reset}`, 7))).toEqual({ ok: {} });
    expect(other.client.requests.filter((r) => r.op === "save_login")).toEqual([]);
  });

  it("generate fills nothing when the page's pattern refuses every password", async () => {
    const { ext, client } = await setup();
    ext.tabReply = (_t, m) =>
      (m as { type?: string }).type === "password_context" ? { ok: true, context: { rules: [] }, has_pattern: true }
        : (m as { type?: string }).type === "pattern_check"
          ? { ok: true, matches: false }
          : undefined;
    const token = await openMenu(ext, { formKind: "signup" });
    expect(await ext.send({ type: "menu_generate", token }, uiSender(`menu.html#${token}`, 7))).toEqual({ err: "site_refused" });
    expect(client.requests.filter((r) => r.op === "generate").map((r) => (r.recipe as { narrow?: number }).narrow)).toEqual([undefined, 1, 2]);
    // Three candidates checked in the page's tab, none filled.
    expect(ext.sentToTabs.map((x) => (x.message as { type: string }).type)).toEqual(["password_context", "pattern_check", "pattern_check", "pattern_check"]);
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

  it("keeps the optional page flags when well formed (captchaWidget, passkeySignIn), refuses them otherwise", () => {
    const a = { ...analysis, captchaWidget: true, passkeySignIn: true };
    expect(parseCsToBg({ type: "page_analysis", analysis: a })).toEqual({ type: "page_analysis", analysis: a });
    expect(parseCsToBg({ type: "page_analysis", analysis: { ...analysis, passkeySignIn: "yes" } })).toBeNull();
    expect(parseCsToBg({ type: "page_analysis", analysis: { ...analysis, captchaWidget: 1 } })).toBeNull();
  });

  it("accepts every forms role (Task 8), still rejects an unknown string", () => {
    for (const role of FORMS_ROLES) {
      const a = { ...analysis, forms: [{ ref: "f1", kind: "identity", fields: [{ ref: "e1", role }] }] };
      expect(parseCsToBg({ type: "page_analysis", analysis: a }), role).toEqual({ type: "page_analysis", analysis: a });
    }
    const bad = { ...analysis, forms: [{ ref: "f1", kind: "identity", fields: [{ ref: "e1", role: "passport" }] }] };
    expect(parseCsToBg({ type: "page_analysis", analysis: bad })).toBeNull();
  });

  it("keeps a field's person and work flag (Task 9), rejects bad ones", () => {
    const fields = [{ ref: "e1", role: "given_name", person: 1 }, { ref: "e2", role: "tel", work: true }];
    const a = { ...analysis, forms: [{ ref: "f1", kind: "identity", fields }] };
    expect(parseCsToBg({ type: "page_analysis", analysis: a })).toEqual({ type: "page_analysis", analysis: a });
    for (const f of [{ ref: "e1", role: "given_name", person: -1 }, { ref: "e1", role: "given_name", person: 1.5 },
      { ref: "e1", role: "given_name", person: 99 }, { ref: "e1", role: "tel", work: "yes" }]) {
      const b = { ...analysis, forms: [{ ref: "f1", kind: "identity", fields: [f] }] };
      expect(parseCsToBg({ type: "page_analysis", analysis: b }), JSON.stringify(f)).toBeNull();
    }
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

  it("submitted_form: only its kind's roles, bounded, a card needs its number, never a security code", () => {
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "card", values: { cc_number: "4111111111111111", cc_exp: " ", cc_name: "A" } })).toEqual({
      type: "submitted_form",
      formRef: "f1",
      kind: "card",
      values: { cc_number: "4111111111111111", cc_name: "A" },
    });
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "card", values: { cc_number: "4111111111111111", cc_csc: "123" } })).toBeNull();
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "card", values: { cc_name: "A" } })).toBeNull();
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "identity", values: { city: "Paris", password: "x" } })).toBeNull();
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "identity", values: { city: "x".repeat(300) } })).toBeNull();
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "login", values: { city: "Paris" } })).toBeNull();
    expect(parseCsToBg({ type: "submitted_form", formRef: "f1", kind: "identity", values: {} })).toBeNull();
  });

  it("validates UI messages", () => {
    const token = "A".repeat(22);
    expect(parseUiToBg({ type: "menu_pick", token, itemId: "it_01", extra: 1 })).toEqual({
      type: "menu_pick",
      token,
      itemId: "it_01",
    });
    expect(parseUiToBg({ type: "menu_pick", token, itemId: "" })).toBeNull();
    expect(parseUiToBg({ type: "menu_signup", token, mode: "passkey", x: 1 })).toEqual({ type: "menu_signup", token, mode: "passkey" });
    expect(parseUiToBg({ type: "menu_signup", token, mode: "both" })).toBeNull();
    expect(parseUiToBg({ type: "save_decide", token, decision: "steal" })).toBeNull();
    expect(
      parseUiToBg({
        type: "save_decide",
        token,
        decision: "save",
        edits: { title: "Atlas", username: "alex@atlas.dev", password: "p", vaultId: "v1", rule: "domain", tags: ["web"] },
      }),
    ).not.toBeNull();
    // A card opened while locked has no vault list yet: no vault chosen, the default one is used.
    expect(
      parseUiToBg({
        type: "save_decide",
        token,
        decision: "save",
        edits: { title: "Atlas", username: "alex@atlas.dev", password: "", vaultId: "", rule: "domain", tags: [] },
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
    // iOS unlock sheet: the master password is text of 1 to 1024 UTF-8 bytes, nothing else.
    expect(parseUiToBg({ type: "menu_unlock_password", token, password: "mot de passe" })).toEqual({
      type: "menu_unlock_password",
      token,
      password: "mot de passe",
    });
    expect(parseUiToBg({ type: "popup_unlock_password", password: "mot de passe" })).toEqual({ type: "popup_unlock_password", password: "mot de passe" });
    expect(parseUiToBg({ type: "popup_unlock_password", password: "" })).toBeNull();
    expect(parseUiToBg({ type: "popup_unlock_password", password: "é".repeat(513) })).toBeNull();
    expect(parseUiToBg({ type: "popup_unlock_password" })).toBeNull();
    expect(parseUiToBg({ type: "popup_vault", extra: 1 })).toEqual({ type: "popup_vault" });
    expect(parseUiToBg({ type: "menu_resume", token })).toEqual({ type: "menu_resume", token });
    expect(parseUiToBg({ type: "menu_resume", token: "short" })).toBeNull();
    // The Face ID tap says so; the automatic try says nothing; any other value is refused.
    expect(parseUiToBg({ type: "menu_unlock_biometric", token, gesture: true })).toEqual({ type: "menu_unlock_biometric", token, gesture: true });
    expect(parseUiToBg({ type: "menu_unlock_biometric", token })).toEqual({ type: "menu_unlock_biometric", token });
    expect(parseUiToBg({ type: "menu_unlock_biometric", token, gesture: false })).toBeNull();
    expect(parseUiToBg({ type: "menu_unlock_biometric", token, gesture: "yes" })).toBeNull();
    expect(parseUiToBg({ type: "menu_unlock_password", token, password: "" })).toBeNull();
    expect(parseUiToBg({ type: "menu_unlock_password", token, password: 3 })).toBeNull();
    expect(parseUiToBg({ type: "menu_unlock_password", token, password: "é".repeat(513) })).toBeNull();
    expect(parseUiToBg({ type: "menu_unlock_password", token: "short", password: "x" })).toBeNull();
    for (const type of ["menu_vault", "menu_unlock_biometric", "menu_unlock", "menu_close", "overlay_state", "overlay_close", "save_reveal", "save_generate", "save_close"]) {
      expect(parseUiToBg({ type, token, password: "x" })).toEqual({ type, token });
      expect(parseUiToBg({ type, token: "short" })).toBeNull();
    }
  });
});

describe("classify message (Task 15)", () => {
  const f = {
    index: 1, tag: "input", type: "password", name: "pw", id: "pw", autocomplete: "current-password", inputmode: "text",
    maxlength: 64, hasPattern: false, required: true, label: "password", placeholder: "p", ariaLabel: "a", before: "b",
    after: "c", depth: 7, siblings: 2, visibility: "visible", width: 120, height: 30, formButtons: ["sign in"],
    pageTitle: "Login", neighbourLabels: ["email"], lab: "3",
  };

  it("rebuilds features from validated fields only: never lab, page title or geometry", () => {
    const m = parseCsToBg({ type: "classify", fields: [{ ...f, evil: 1 }] });
    expect(m).toEqual({
      type: "classify",
      fields: [{
        index: 1, tag: "input", type: "password", name: "pw", id: "pw", autocomplete: "current-password", inputmode: "text",
        maxlength: 64, hasPattern: false, required: true, label: "password", placeholder: "p", ariaLabel: "a", before: "b",
        after: "c", depth: 7, siblings: 2, visibility: "visible", width: 0, height: 0, formButtons: ["sign in"], neighbourLabels: ["email"],
      }],
    });
    expect(parseCsToBg({ type: "classify", fields: [] })).toEqual({ type: "classify", fields: [] });
  });

  it("rejects malformed or oversize features", () => {
    const bad = [
      { ...f, visibility: "hidden" },
      { ...f, index: -1 },
      { ...f, index: 1.5 },
      { ...f, depth: "3" },
      { ...f, hasPattern: 1 },
      { ...f, tag: "" },
      { ...f, name: 7 },
      { ...f, name: "x".repeat(5000) },
      { ...f, maxlength: 0 },
      { ...f, formButtons: Array(13).fill("b") },
      { ...f, neighbourLabels: Array(5).fill("n") },
      { ...f, formButtons: [3] },
    ];
    for (const b of bad) expect(parseCsToBg({ type: "classify", fields: [b] }), JSON.stringify(b).slice(0, 80)).toBeNull();
    expect(parseCsToBg({ type: "classify", fields: Array(MAX_CLASSIFY_FIELDS).fill(f) })).not.toBeNull();
    expect(parseCsToBg({ type: "classify", fields: Array(MAX_CLASSIFY_FIELDS + 1).fill(f) })).toBeNull();
    expect(parseCsToBg({ type: "classify", fields: f })).toBeNull();
  });
});

describe("ghost and preview messages (task 5)", () => {
  const METRICS = {
    fontSize: 15,
    lineHeight: 20,
    paddingLeft: 12,
    paddingRight: 8,
    textAlign: "left",
    fontFamily: "Inter",
    box: { x: 10, y: 20, width: 300, height: 40 },
  };
  /** A host whose every draw is a new password; a custom profile's length is honoured. */
  const drawing = (): Answer => {
    let n = 0;
    return (r) => {
      if (r.op !== "generate") return defaultAnswer(r);
      n++;
      const length = (r.recipe as { length?: number }).length;
      const base = `Draw-${n}-Pass-xyz!`;
      return { password: length !== undefined ? base.padEnd(length, "a").slice(0, length) : base, entropy_bits: 90 };
    };
  };
  const ghostOpen = async (ext: FakeExt, formKind = "signup") => {
    const r = (await ext.send({ type: "ghost_open", fieldRef: "e1", formRef: "f1", formKind, metrics: METRICS }, page())) as { ok: { url: string } };
    const url = r.ok.url;
    expect(url.startsWith(`chrome-extension://${EXT_ID}/ghost.html#`)).toBe(true);
    return url.slice(url.indexOf("#") + 1);
  };
  const filled = (ext: FakeExt) =>
    ext.sentToTabs.filter((x) => (x.message as { type?: string }).type === "fill").map((x) => (x.message as { values: unknown }).values);

  it("routes the ghost messages: open, init from the ghost page only, accept from the field", async () => {
    const { ext } = await setup(drawing());
    const token = await ghostOpen(ext);
    const init = await ext.send({ type: "ghost_init", token }, uiSender(`ghost.html#${token}`, 7));
    expect(init).toEqual({ ok: { password: "Draw-1-Pass-xyz!", strength: 4, length: 16, metrics: METRICS } });
    // Never to a content script, another page family or another tab.
    expect(await ext.send({ type: "ghost_init", token }, page())).toBe(NO_REPLY);
    expect(await ext.send({ type: "ghost_init", token }, uiSender(`menu.html#${token}`, 7))).toBe(NO_REPLY);
    expect(await ext.send({ type: "ghost_init", token }, uiSender(`ghost.html#${token}`, 8))).toEqual({ err: "invalid" });
    // Tab in the field: the held password is filled.
    expect(await ext.send({ type: "ghost_accept" }, page())).toEqual({ ok: {} });
    expect(filled(ext)).toEqual([{ new_password: "Draw-1-Pass-xyz!", confirm_password: "Draw-1-Pass-xyz!" }]);
    // Spent.
    expect(await ext.send({ type: "ghost_init", token }, uiSender(`ghost.html#${token}`, 7))).toEqual({ err: "invalid" });
  });

  it("the ghost page's pill accepts its token; dismiss forgets it", async () => {
    const { ext } = await setup(drawing());
    const token = await ghostOpen(ext);
    expect(await ext.send({ type: "ghost_accept", token }, uiSender(`ghost.html#${token}`, 7))).toEqual({ ok: {} });
    expect(filled(ext)).toHaveLength(1);
    const again = await ghostOpen(ext);
    expect(await ext.send({ type: "ghost_dismiss" }, page())).toEqual({ ok: {} });
    expect(await ext.send({ type: "ghost_init", token: again }, uiSender(`ghost.html#${again}`, 7))).toEqual({ err: "invalid" });
  });

  it("ghost_open only on new-password forms of a secure page", async () => {
    const { ext } = await setup(drawing());
    const m = { type: "ghost_open", fieldRef: "e1", formRef: "f1", formKind: "login", metrics: METRICS };
    expect(await ext.send(m, page())).toEqual({ err: "invalid" });
    expect(await ext.send({ ...m, formKind: "signup" }, csSender("http://atlas-cloud.test/login"))).toEqual({ err: "insecure_origin" });
  });

  it("the menu opened from the ghost previews, redraws, sets the profile and fills the held password", async () => {
    const { ext } = await setup(drawing());
    await ghostOpen(ext);
    const r = (await ext.send({ type: "ghost_menu" }, page())) as { ok: { url: string } };
    expect(r.ok.url.startsWith(`chrome-extension://${EXT_ID}/menu.html#`)).toBe(true);
    const mt = r.ok.url.slice(r.ok.url.indexOf("#") + 1);
    const ui = uiSender(`menu.html#${mt}`, 7);
    expect(await ext.send({ type: "menu_preview", token: mt }, ui)).toEqual({ ok: { password: "Draw-1-Pass-xyz!", strength: 4, length: 16 } });
    expect(await ext.send({ type: "menu_regenerate", token: mt }, ui)).toEqual({ ok: { password: "Draw-2-Pass-xyz!", strength: 4, length: 16 } });
    const p = (await ext.send({ type: "menu_profile", token: mt, length: 20, symbols: false }, ui)) as { ok: { password: string; length: number } };
    expect(p.ok.length).toBe(20);
    expect(ext.local.data.get("generator_profile")).toEqual({ kind: "custom", length: 20, symbols: false });
    expect(await ext.send({ type: "menu_generate", token: mt }, ui)).toEqual({ ok: {} });
    expect(filled(ext)).toEqual([{ new_password: p.ok.password, confirm_password: p.ok.password }]);
  });

  it("a menu opened without a ghost gets its own preview", async () => {
    const { ext } = await setup(drawing());
    const token = await openMenu(ext, { formKind: "signup" });
    const ui = uiSender(`menu.html#${token}`, 7);
    expect(await ext.send({ type: "menu_preview", token }, ui)).toEqual({ ok: { password: "Draw-1-Pass-xyz!", strength: 4, length: 16 } });
    expect(await ext.send({ type: "menu_generate", token }, ui)).toEqual({ ok: {} });
    expect(filled(ext)).toEqual([{ new_password: "Draw-1-Pass-xyz!", confirm_password: "Draw-1-Pass-xyz!" }]);
  });

  it("validates the new messages", () => {
    expect(parseCsToBg({ type: "ghost_open", fieldRef: "e1", formRef: "f1", formKind: "signup", metrics: { ...METRICS, evil: 1 } })).toEqual({
      type: "ghost_open",
      fieldRef: "e1",
      formRef: "f1",
      formKind: "signup",
      metrics: METRICS,
    });
    expect(parseCsToBg({ type: "ghost_open", fieldRef: "e1", formRef: "f1", formKind: "signup", metrics: { ...METRICS, fontFamily: null } })).not.toBeNull();
    for (const bad of [
      { ...METRICS, textAlign: "justify" },
      { ...METRICS, fontSize: Number.NaN },
      { ...METRICS, fontSize: -1 },
      { ...METRICS, fontFamily: "x".repeat(300) },
      { ...METRICS, box: { x: 0, y: 0, width: "1", height: 2 } },
    ]) {
      expect(parseCsToBg({ type: "ghost_open", fieldRef: "e1", formRef: "f1", formKind: "signup", metrics: bad })).toBeNull();
    }
    for (const t of ["ghost_accept", "ghost_dismiss", "ghost_menu"]) expect(parseCsToBg({ type: t, token: "x" })).toEqual({ type: t });
    // Page messages are never content script messages.
    expect(parseCsToBg({ type: "ghost_init", token: "A".repeat(22) })).toBeNull();
    expect(parseCsToBg({ type: "menu_preview", token: "A".repeat(22) })).toBeNull();
    const tk = "A".repeat(22);
    for (const t of ["ghost_init", "ghost_accept", "menu_preview", "menu_regenerate"]) expect(parseUiToBg({ type: t, token: tk })).toEqual({ type: t, token: tk });
    expect(parseUiToBg({ type: "menu_profile", token: tk, length: 20, symbols: false })).toEqual({ type: "menu_profile", token: tk, length: 20, symbols: false });
    for (const length of [7, 65, 20.5, "20"]) expect(parseUiToBg({ type: "menu_profile", token: tk, length, symbols: true })).toBeNull();
    expect(parseUiToBg({ type: "menu_profile", token: tk, length: 20, symbols: 1 })).toBeNull();
  });
});
