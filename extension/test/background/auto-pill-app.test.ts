// The sign-in pill that appears by itself, through the real background wiring (createBackground,
// router): the page gets the card when it is ready, its appearance fills, submits and starts
// nothing, and only the card's own click does (the chain, the unlock, the signup fill).
import { describe, expect, it } from "vitest";
import { createBackground } from "../../src/background/app";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { AUTO_PILL_KEY, AUTO_PILL_NEVER_KEY } from "../../src/shared/auto-pill";
import { BridgeAppError } from "../../src/bridge/client";
import type { FieldRole, FormContext, PageAnalysis, PlanOut } from "../../src/shared/messages";
import type { ChainView } from "../../src/shared/ui";
import { FakeClient, record } from "./fake-client";
import { FakeExt, csSender, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const A = "0b6f1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4";

function form(ref: string, roles: FieldRole[], prefilled: "empty" | "typed" = "empty"): FormContext {
  return {
    form_ref: ref,
    intent_hints: { kind: null, signup_words: false, reset_words: false, checkout_words: false, ignore: false },
    step_index: null,
    fields: roles.map((role, i) => ({ field_ref: `${ref}e${i}`, role, confidence: 1, visible: true, prefilled: i === 0 ? prefilled : "empty" })),
    buttons: [{ button_ref: `${ref}b`, class: roles.includes("new_password") ? "create" : "submit" }],
  };
}

const analysis = (kind: "login" | "signup" | null, url = `${SITE}/login`): PageAnalysis => ({
  url,
  forms:
    kind === "login"
      ? [{ ref: "f1", kind: "login", fields: [{ ref: "f1e0", role: "username" }, { ref: "f1e1", role: "current_password" }] }]
      : kind === "signup"
        ? [{ ref: "f2", kind: "signup", fields: [{ ref: "f2e0", role: "email" }, { ref: "f2e1", role: "new_password" }] }]
        : [],
  captcha: false,
  push: false,
  providerButtons: [],
  accountChooser: [],
});

const summary = (id: string) => ({
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
});

const SIGNUP_PLAN: PlanOut = {
  intent: "signup",
  action: "fill",
  confidence: "high",
  alternatives: [],
  reasons: [],
  groups: [{ form_ref: "f2", kind: "generated_password", item_id: null, fields: [{ field_ref: "f2e1", role: "new_password" }] }],
};

interface Opts {
  locked?: boolean;
  logins?: number;
  prefilled?: boolean;
}

async function setup(o: Opts = {}) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const chainCalls: unknown[][] = [];
  const chain = {
    view: null as ChainView | null,
    start: async (...a: unknown[]) => void chainCalls.push(a),
    stop: async () => undefined,
    state: async () => chain.view,
  };
  const vault = { locked: o.locked === true };
  const client = new FakeClient((r) => {
    if (r.op === "status") return { locked: vault.locked, account: "Camille", vaults: 1 };
    if (r.op === "unlock") return { locked: vault.locked };
    if (vault.locked && (r.op === "list_for_origin" || r.op === "plan_fill" || r.op === "generate")) return new BridgeAppError("locked", "vault locked");
    switch (r.op) {
      case "list_for_origin":
        return { items: Array.from({ length: o.logins ?? 1 }, (_, i) => summary(i === 0 ? A : `it_${i}`)) };
      case "plan_fill":
        return { plan: SIGNUP_PLAN };
      case "generate":
        return { password: "Gen-Secret-42!", entropy_bits: 90 };
      default:
        return {};
    }
  });
  const b = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, chain, now: () => 5_000_000, openApp: async () => true });
  b.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  const top = csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });
  /** What the content script answers: the page's forms (`plan_request`), and a fill. */
  let forms: FormContext[] = [];
  ext.tabReply = (_tab, m) => {
    const type = (m as { type: string }).type;
    if (type === "plan_request") return { ok: true, context: { forms, typed_username_hash: null } };
    if (type === "show_frame" || type === "remove_frame") return { ok: true };
    if (type === "fill") return { ok: true, written: 1 };
    return undefined;
  };
  const toTab = (type: string) => ext.sentToTabs.filter((m) => (m.message as { type: string }).type === type);
  const cards = () => toTab("show_frame").filter((m) => (m.message as { kind: string }).kind === "overlay");
  const tokenOf = (i = 0) => ((cards()[i]?.message as { url: string }).url.split("#")[1] ?? "") as string;
  /** The page of tab 7 shows `kind` and finished loading. */
  const ready = async (kind: "login" | "signup" | null) => {
    forms = kind === "login" ? [form("f1", ["username", "current_password"], o.prefilled ? "typed" : "empty")] : kind === "signup" ? [form("f2", ["email", "new_password"], o.prefilled ? "typed" : "empty")] : [];
    await ext.send({ type: "page_analysis", analysis: analysis(kind) }, top);
    ext.complete(7, 0);
    await settle();
  };
  const ops = () => client.requests.map((r) => String(r.op));
  return { ext, b, client, chain, chainCalls, top, toTab, cards, tokenOf, ready, ops, vault };
}

/** The pill's look runs off `onCompleted` (a listener): lets it finish. */
async function settle() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));
}

describe("auto sign-in pill: appears by itself", () => {
  it("case 1: a login page with a saved login gets the sign-in pill; nothing filled, submitted or started", async () => {
    const t = await setup();
    await t.ready("login");
    expect(t.cards()).toHaveLength(1);
    expect(t.cards()[0]).toMatchObject({ tabId: 7, options: { documentId: "doc-1" }, message: { type: "show_frame", kind: "overlay", auto: true } });
    expect(t.chainCalls).toEqual([]);
    expect(t.ops().some((op) => op.startsWith("fill_") || op === "generate")).toBe(false);
    expect(t.toTab("fill")).toEqual([]);
    const token = t.tokenOf();
    const ui = uiSender(`overlay.html#${token}`, 7);
    const init = (await t.ext.send({ type: "overlay_init", token }, ui)) as { ok: Record<string, unknown> };
    expect(init.ok).toMatchObject({ origin: SITE, auto: "signin", accounts: [expect.objectContaining({ itemId: A })] });
    expect(t.chainCalls).toEqual([]);
    // Its button: the same chain as any sign-in of the card.
    expect(await t.ext.send({ type: "overlay_start", token, itemId: A }, ui)).toEqual({ ok: {} });
    expect(t.chainCalls).toEqual([[7, A, undefined, {}]]);
  });

  it("case 2: a login page on a locked vault gets the generic card; its click asks the unlock", async () => {
    const t = await setup({ locked: true });
    await t.ready("login");
    expect(t.cards()).toHaveLength(1);
    const token = t.tokenOf();
    const ui = uiSender(`overlay.html#${token}`, 7);
    expect(await t.ext.send({ type: "overlay_init", token }, ui)).toEqual({ ok: { origin: SITE, accounts: [], chain: null, generic: true, auto: "signin" } });
    expect(t.ops()).not.toContain("unlock");
    expect(await t.ext.send({ type: "overlay_unlock", token }, ui)).toEqual({ ok: { waiting: "locked" } });
    expect(t.client.requests).toContainEqual({ op: "unlock", origin: SITE });
    expect(t.chainCalls).toEqual([]);
  });

  it("case 3: a signup page gets the create pill; its click fills a generated password, never submits", async () => {
    const t = await setup();
    await t.ready("signup");
    expect(t.cards()).toHaveLength(1);
    expect(t.ops()).not.toContain("generate");
    const token = t.tokenOf();
    const ui = uiSender(`overlay.html#${token}`, 7);
    expect(await t.ext.send({ type: "overlay_init", token }, ui)).toEqual({ ok: { origin: SITE, accounts: [], chain: null, auto: "signup" } });
    expect(t.ops()).not.toContain("generate");
    expect(await t.ext.send({ type: "overlay_create", token }, ui)).toEqual({ ok: {} });
    expect(t.ops()).toContain("generate");
    expect(t.toTab("fill").length).toBeGreaterThan(0);
    expect(t.chainCalls).toEqual([]);
    // Filled: the card goes, its token is spent.
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "overlay" });
    expect(await t.ext.send({ type: "overlay_init", token }, ui)).toEqual({ err: "invalid" });
  });

  it("overlay_create is refused on a card that is not the create pill", async () => {
    const t = await setup();
    await t.ready("login");
    const token = t.tokenOf();
    const ui = uiSender(`overlay.html#${token}`, 7);
    await t.ext.send({ type: "overlay_init", token }, ui);
    expect(await t.ext.send({ type: "overlay_create", token }, ui)).toEqual({ err: "invalid" });
    expect(t.ops()).not.toContain("generate");
  });

  it("a login page with nothing saved for the site shows nothing", async () => {
    const t = await setup({ logins: 0 });
    await t.ready("login");
    expect(t.cards()).toEqual([]);
  });

  it("a top frame the browser gives no document id: the card is pinned to the origin it was decided for", async () => {
    const t = await setup();
    await t.b.overlays.openAuto({ tabId: 7, frameId: 0, origin: SITE }, "signin");
    expect(t.cards()[0]).toMatchObject({ options: { frameId: 0 }, message: { auto: true, origin: SITE } });
  });

  it("a card opened by a gesture is not an auto card (no auto in its init)", async () => {
    const t = await setup();
    const token = await t.b.overlays.open({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
    const init = (await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))) as { ok: Record<string, unknown> };
    expect(init.ok.auto).toBeUndefined();
  });
});

describe("auto sign-in pill: goes away", () => {
  it("as soon as the user types in the page", async () => {
    const t = await setup();
    await t.ready("login");
    const token = t.tokenOf();
    expect(await t.ext.send({ type: "page_typed" }, t.top)).toEqual({ ok: {} });
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "overlay" });
    expect(await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({ err: "invalid" });
  });

  it("typing in a child frame, or reported for another top document, leaves it", async () => {
    const t = await setup();
    await t.ready("login");
    t.ext.setFrame(7, 3, `${SITE}/frame`, "doc-3");
    expect(await t.ext.send({ type: "page_typed" }, csSender(`${SITE}/frame`, 7, 3, { documentId: "doc-3" }))).toEqual({ ok: {} });
    expect(await t.ext.send({ type: "page_typed" }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-0" }))).toEqual({ ok: {} });
    expect(t.toTab("remove_frame")).toEqual([]);
  });

  it("typing leaves a card opened by a gesture, and a running chain, alone", async () => {
    const t = await setup();
    await t.b.overlays.open({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
    await t.ext.send({ type: "page_typed" }, t.top);
    expect(t.toTab("remove_frame")).toEqual([]);
    const u = await setup();
    await u.ready("login");
    u.chain.view = { itemId: A, status: "running", steps: [] };
    await u.ext.send({ type: "page_typed" }, u.top);
    expect(u.toTab("remove_frame")).toEqual([]);
  });

  it("when the field menu opens (the user clicked the glyph)", async () => {
    const t = await setup();
    await t.ready("login");
    await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top);
    expect(t.toTab("remove_frame").map((m) => m.message)).toContainEqual({ type: "remove_frame", kind: "overlay" });
  });

  it("when the ghost of a new password field opens", async () => {
    const t = await setup();
    await t.ready("signup");
    await t.ext.send({ type: "ghost_open", fieldRef: "f2e1", formRef: "f2", formKind: "signup", metrics: { fontSize: 16, lineHeight: 20, paddingLeft: 4, paddingRight: 4, textAlign: "left", fontFamily: null, box: { x: 0, y: 0, width: 200, height: 30 } } }, t.top);
    expect(t.toTab("remove_frame").map((m) => m.message)).toContainEqual({ type: "remove_frame", kind: "overlay" });
  });

  it("\"Never on this site\": the site is kept in the never-list and the card goes", async () => {
    const t = await setup();
    await t.ready("login");
    const token = t.tokenOf();
    expect(await t.ext.send({ type: "overlay_never", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({ ok: {} });
    expect(t.ext.local.data.get(AUTO_PILL_NEVER_KEY)).toEqual(["atlas-cloud.test"]);
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "overlay" });
    // Next page ready, in another tab: nothing.
    t.ext.setFrame(8, 0, `${SITE}/login`, "doc-8");
    await t.ext.send({ type: "page_analysis", analysis: analysis("login") }, csSender(`${SITE}/login`, 8, 0, { documentId: "doc-8" }));
    t.ext.complete(8, 0);
    await settle();
    expect(t.cards()).toHaveLength(1);
  });

  it("overlay_never is refused on a card opened by a gesture", async () => {
    const t = await setup();
    const token = await t.b.overlays.open({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
    expect(await t.ext.send({ type: "overlay_never", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({ err: "invalid" });
    expect(t.ext.local.data.get(AUTO_PILL_NEVER_KEY)).toBeUndefined();
  });
});

describe("auto sign-in pill: never shown when", () => {
  it("the setting is off", async () => {
    const t = await setup();
    await t.ext.local.set({ [AUTO_PILL_KEY]: false });
    await t.ready("login");
    expect(t.cards()).toEqual([]);
  });

  it("it already showed on this site in this tab (a reload, another page of the site)", async () => {
    const t = await setup();
    await t.ready("login");
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    t.top.documentId = "doc-2";
    await t.ready("login");
    expect(t.cards()).toHaveLength(1);
  });

  it("a chain runs in the tab", async () => {
    const t = await setup();
    t.chain.view = { itemId: A, status: "running", steps: [] };
    await t.ready("login");
    expect(t.cards()).toEqual([]);
  });

  it("a field of the form holds a value", async () => {
    const t = await setup({ prefilled: true });
    await t.ready("login");
    expect(t.cards()).toEqual([]);
  });

  it("the form is in a child frame only", async () => {
    const t = await setup();
    t.ext.setFrame(7, 3, `${SITE}/frame`, "doc-3");
    await t.ext.send({ type: "page_analysis", analysis: analysis("login", `${SITE}/frame`) }, csSender(`${SITE}/frame`, 7, 3, { documentId: "doc-3" }));
    await t.ext.send({ type: "page_analysis", analysis: analysis(null) }, t.top);
    t.ext.complete(7, 0);
    await settle();
    expect(t.cards()).toEqual([]);
  });
});
