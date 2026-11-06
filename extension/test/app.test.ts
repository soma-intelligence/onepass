// Task 10 (smart fill): the triggers, the menu a plan opens, the popup line,
// site memory notes and the penalty, through the real background wiring
// (createBackground, router) against a fake browser and host.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createBackground, FILL_SMART_COMMAND } from "../src/background/app";
import type { NativeVault, NativeVaultCall } from "../src/background/safari";
import { BridgeAppError } from "../src/bridge/client";
import { NOTE_NAV_MS } from "../src/background/notes";
import { penaltyKey } from "../src/background/penalty";
import { MemoryPairingStore, Store } from "../src/background/store";
import type { FieldRole, FormContext, PlanOut } from "../src/shared/messages";
import { FakeClient, record } from "./background/fake-client";
import { FakeExt, NO_REPLY, csSender, uiSender } from "./background/fake-ext";

const SITE = "https://atlas-cloud.test";
const A = "0b6f1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4";
const B = "1c7a2d3e-4f5b-4c6d-9e7f-8091a2b3c4d5";
const C = "3e9c4f5a-6b7d-4e8f-9a01-a2b3c4d5e6f7";
const CARD = "4fad5a6b-7c8e-4f90-8b12-b3c4d5e6f7a8";
const IDENTITY = "2d8b3e4f-5a6c-4d7e-8f90-91a2b3c4d5e6";
const NEW_LOGIN = "5abe6b7c-8d9f-4a01-9c23-c4d5e6f7a8b9";
const SECRETS = ["alex@atlas.dev", "pw-Secret-1", "4242424242424242", "Gen-Secret-42!"];

function form(ref: string, roles: FieldRole[], buttons: FormContext["buttons"] = []): FormContext {
  return {
    form_ref: ref,
    intent_hints: { kind: null, signup_words: false, reset_words: false, checkout_words: false, ignore: false },
    step_index: null,
    fields: roles.map((role, i) => ({ field_ref: `${ref}e${i}`, role, confidence: 1, visible: true, prefilled: "empty" })),
    buttons,
  };
}

const body = (forms: FormContext[]) => ({ forms, typed_username_hash: null });

function plan(over: Partial<PlanOut>): PlanOut {
  return { intent: "login", groups: [], action: "fill", confidence: "high", alternatives: [], reasons: [], ...over };
}

const loginGroup = (item: string, formRef = "f1", roles: FieldRole[] = ["username", "current_password"]) => ({
  form_ref: formRef,
  kind: "login" as const,
  item_id: item,
  fields: roles.map((role, i) => ({ field_ref: `${formRef}e${i}`, role })),
});

const summary = (id: string, subtitle: string) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle,
  kind: "login",
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
});

const LOGIN_FORM = [form("f1", ["username", "current_password"], [{ button_ref: "b1", class: "submit" }])];

async function bg(
  next: () => PlanOut,
  extra: (r: Record<string, unknown>) => unknown = () => undefined,
  nativeVault?: (call: NativeVaultCall) => Promise<NativeVault | null>,
) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const clock = { t: 5_000_000 };
  const chainCalls: unknown[][] = [];
  const chain = {
    start: async (...a: unknown[]) => void chainCalls.push(a),
    stop: async () => undefined,
    state: async () => null,
  };
  const client = new FakeClient((r) => {
    const x = extra(r);
    if (x !== undefined) return x;
    switch (r.op) {
      case "fill_salt":
        return { salt: "a".repeat(64) };
      case "plan_fill":
        return { plan: next() };
      case "list_for_origin":
        return { items: [summary(A, "alex@atlas.dev"), summary(B, "bo@atlas.dev"), summary(C, "cy@atlas.dev")] };
      case "fill_login":
        return { username: "alex@atlas.dev", password: "pw-Secret-1" };
      case "fill_card":
        return { cardholder: "Alex", number: "4242424242424242", exp_month: "04", exp_year: "2029" };
      case "fill_identity":
        return { given_name: "Alex", email: "alex@atlas.dev" };
      case "generate":
        return { password: "Gen-Secret-42!", entropy_bits: 90 };
      case "save_login":
        return { item_id: NEW_LOGIN };
      case "forget_site":
        return { items: 2 };
      default:
        return {};
    }
  });
  const b = createBackground(ext, {
    pairings,
    newClient: () => client,
    sleep: async () => undefined,
    chain,
    now: () => clock.t,
    ...(nativeVault ? { nativeVault } : {}),
  });
  b.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  const top = csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });
  const ops = () => client.requests.map((r) => r.op);
  const notes = () => client.requests.filter((r) => r.op === "note_fill");
  const toTab = (type: string) => ext.sentToTabs.filter((m) => (m.message as { type: string }).type === type);
  return { ext, b, client, clock, chainCalls, top, ops, notes, toTab };
}

describe("IOSSAF-02 + MS-03: an unlock asked in the menu resumes the menu field's plan, once", () => {
  /** The vault: locked until the menu unlocks it (unless `refuse`); the plan fails `locked` while it is. */
  async function lockedBg() {
    const vault = { locked: true, refuse: false };
    const native = async (call: NativeVaultCall): Promise<NativeVault> => {
      if (call.op !== "vault_state" && !vault.refuse) vault.locked = false;
      return { locked: vault.locked, account: "Camille", biometry: "faceID" };
    };
    const t = await bg(
      () => plan({ action: "fill", groups: [loginGroup(A)] }),
      (r) => (r.op === "plan_fill" && vault.locked ? new BridgeAppError("locked", "vault locked") : undefined),
      native,
    );
    return { ...t, vault };
  }

  async function tapThenMenu(t: Awaited<ReturnType<typeof lockedBg>>, fieldRef = "f1e0") {
    const r = await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef, context: body(LOGIN_FORM) }, t.top);
    expect(r).toEqual({ err: "locked" });
    return openMenu(t, fieldRef);
  }

  async function openMenu(t: Awaited<ReturnType<typeof lockedBg>>, fieldRef = "f1e0", from = t.top) {
    const open = (await t.ext.send({ type: "open_menu", fieldRef, formRef: "f1", formKind: "login" }, from)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    return { token, ui: uiSender(`menu.html#${token}`, 7) };
  }

  it("a tap on Face ID in the sheet: the menu goes and the tapped field's plan runs again, in its document", async () => {
    const t = await lockedBg();
    const { token, ui } = await tapThenMenu(t);
    const v = await t.ext.send({ type: "menu_unlock_biometric", token, gesture: true }, ui);
    expect(v).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    const replay = t.toTab("smart_fill");
    expect(replay).toHaveLength(1);
    expect(replay[0]).toMatchObject({ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", origin: SITE }, options: { documentId: "doc-1" } });
    // The menu's token is gone: nothing else runs from it, the app path's resume included.
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "invalid" });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(1);
  });

  it("the master password in the sheet resumes too, once", async () => {
    const t = await lockedBg();
    const { token, ui } = await tapThenMenu(t);
    await t.ext.send({ type: "menu_unlock_password", token, password: "pw" }, ui);
    expect(t.toTab("smart_fill")).toHaveLength(1);
    expect(await t.ext.send({ type: "menu_unlock_password", token, password: "pw" }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(1);
  });

  it("the menu's automatic Face ID unlocks but never fills: the menu stays and loads", async () => {
    const t = await lockedBg();
    const { token, ui } = await tapThenMenu(t);
    expect(await t.ext.send({ type: "menu_unlock_biometric", token }, ui)).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(t.toTab("smart_fill")).toHaveLength(0);
    expect(t.toTab("remove_frame")).toHaveLength(0);
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toHaveProperty("ok");
    // Nor does the app path's resume: no unlock was asked in the app.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(0);
  });

  it("always the menu's own field: a keyboard menu, or a tap on another field before it", async () => {
    // A menu from the keyboard (no locked plan before it).
    let t = await lockedBg();
    let m = await openMenu(t);
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    expect(t.toTab("smart_fill").map((x) => x.message)).toEqual([{ type: "smart_fill", fieldRef: "f1e0", origin: SITE }]);

    // The tap was on another field than the menu's: the menu's field runs.
    t = await lockedBg();
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e1", context: body(LOGIN_FORM) }, t.top);
    m = await openMenu(t, "f1e0");
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    expect(t.toTab("smart_fill").map((x) => x.message)).toEqual([{ type: "smart_fill", fieldRef: "f1e0", origin: SITE }]);
  });

  it("nothing fills once the menu's document changed, from another tab, or when the unlock fails", async () => {
    // The page committed another document meanwhile: the menu stays.
    let t = await lockedBg();
    let m = await tapThenMenu(t);
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    expect(t.toTab("smart_fill")).toHaveLength(0);
    expect(t.toTab("remove_frame")).toHaveLength(0);

    // Another origin, or plain http, in the menu's frame.
    for (const url of ["https://other.example/login", "http://atlas-cloud.test/login"]) {
      t = await lockedBg();
      m = await tapThenMenu(t);
      t.ext.setFrame(7, 0, url, "doc-1");
      await t.ext.send({ type: "menu_unlock_password", token: m.token, password: "pw" }, m.ui);
      expect(t.toTab("smart_fill")).toHaveLength(0);
    }

    // Another tab's page cannot use the menu's token.
    t = await lockedBg();
    m = await tapThenMenu(t);
    expect(await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, uiSender(`menu.html#${m.token}`, 8))).toHaveProperty("err");
    expect(t.toTab("smart_fill")).toHaveLength(0);

    // The unlock fails (still locked): nothing runs.
    t = await lockedBg();
    t.vault.refuse = true;
    m = await tapThenMenu(t);
    expect(await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui)).toEqual({
      ok: { locked: true, account: "Camille", biometry: "faceID" },
    });
    await t.ext.send({ type: "menu_unlock_password", token: m.token, password: "pw" }, m.ui);
    expect(t.toTab("smart_fill")).toHaveLength(0);
  });

  it("a frame's menu resumes in that frame only, never in the top frame", async () => {
    const t = await lockedBg();
    t.ext.setFrame(7, 3, `${SITE}/frame`, "doc-3");
    const m = await openMenu(t, "f1e0", csSender(`${SITE}/frame`, 7, 3, { documentId: "doc-3" }));
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    const replay = t.toTab("smart_fill");
    expect(replay).toHaveLength(1);
    expect(replay[0]).toMatchObject({ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", origin: SITE }, options: { documentId: "doc-3" } });
  });
});

describe("icon click (plan_context with the gesture's form and field)", () => {
  it("icon_click_with_high_login_starts_chain", async () => {
    const t = await bg(() => plan({ action: "open_chain", groups: [loginGroup(A)], alternatives: [] }));
    const r = await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    expect(r).toEqual({ ok: { outcome: "chain" } });
    // The plan's item, the progress under the clicked field, and what note_fill needs at done.
    expect(t.chainCalls).toEqual([[7, A, undefined, { anchorRef: "f1e0", planned: { roles: ["username", "current_password"], intent: "login" } }]]);
    expect(t.ops()).not.toContain("fill_login");
  });

  it("icon_click_with_tie_opens_menu_best_first", async () => {
    const t = await bg(() => plan({ action: "show_menu", confidence: "low", groups: [loginGroup(B)], alternatives: [A], reasons: ["tie"] }));
    const r = await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    expect(r).toEqual({ ok: { outcome: "menu" } });
    // The content script opens the menu next: the chosen item, then the
    // plan's alternatives (the bridge leaves the chosen one out of them).
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const init = (await t.ext.send({ type: "menu_init", token }, uiSender(`menu.html#${token}`, 7))) as { ok: { items: { item_id: string }[]; best?: string } };
    expect(init.ok.items.map((x) => x.item_id)).toEqual([B, A, C]);
    expect(init.ok.best).toBe(B);
    expect(t.chainCalls).toEqual([]);
  });

  it("a menu opened by a click into the field (auto) ignores a plan's alternatives", async () => {
    const t = await bg(() => plan({ action: "show_menu", confidence: "low", alternatives: [C, B] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top);
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login", auto: true }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const init = (await t.ext.send({ type: "menu_init", token }, uiSender(`menu.html#${token}`, 7))) as { ok: { items: { item_id: string }[]; best?: string } };
    expect(init.ok.items.map((x) => x.item_id)).toEqual([A, B, C]);
    expect(init.ok.best).toBeUndefined();
    // Fix 1.7: the auto menu leaves the plan's alternatives to the next non-auto open.
    const open2 = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token2 = open2.ok.url.split("#")[1] as string;
    const init2 = (await t.ext.send({ type: "menu_init", token: token2 }, uiSender(`menu.html#${token2}`, 7))) as { ok: { items: { item_id: string }[]; best?: string } };
    expect(init2.ok.items.map((x) => x.item_id)).toEqual([C, B, A]);
    expect(init2.ok.best).toBe(C);
  });

  it("gesture_form_scopes_the_run: an icon runs its form's groups only, none left is the menu", async () => {
    const checkout = () =>
      plan({
        intent: "checkout",
        action: "fill",
        confidence: "medium",
        groups: [
          { form_ref: "f1", kind: "card", item_id: CARD, fields: [{ field_ref: "f1e0", role: "cc_number" }] },
          { form_ref: "f2", kind: "identity", item_id: IDENTITY, fields: [{ field_ref: "f2e0", role: "given_name" }] },
        ],
      });
    const ctx = body([form("f1", ["cc_number"]), form("f2", ["given_name"])]);
    let t = await bg(checkout);
    expect(await t.ext.send({ type: "plan_context", formRef: "f2", fieldRef: "f2e0", context: ctx }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(t.ops().filter((o) => String(o).startsWith("fill_"))).toEqual(["fill_identity"]);

    t = await bg(checkout);
    expect(await t.ext.send({ type: "plan_context", formRef: "f9", fieldRef: "f9e0", context: ctx }, t.top)).toEqual({ ok: { outcome: "menu" } });
    expect(t.ops().filter((o) => String(o).startsWith("fill_"))).toEqual([]);

    // The popup and the command (no form): the whole plan.
    t = await bg(checkout);
    expect(await t.ext.send({ type: "plan_context", context: ctx }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(t.ops().filter((o) => String(o).startsWith("fill_"))).toEqual(["fill_card", "fill_identity"]);
  });

  it("a penalized site gets Medium: no chain, no submit, this step filled", async () => {
    const t = await bg(() => plan({ action: "open_chain", groups: [loginGroup(A)] }));
    await t.ext.session.set({ [penaltyKey("atlas-cloud.test")]: { at: 1 } });
    const r = await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    expect(r).toEqual({ ok: { outcome: "filled" } });
    expect(t.chainCalls).toEqual([]);
    expect(t.toTab("submit")).toEqual([]);
    expect(t.ops()).toContain("fill_login");
  });

  it("a malformed gesture field ref is refused before any plan", async () => {
    const t = await bg(() => plan({ action: "open_chain", groups: [loginGroup(A)] }));
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "a b", context: body(LOGIN_FORM) }, t.top)).toBe(NO_REPLY);
    expect(t.ops()).toEqual([]);
  });
});

describe("site memory (note_fill)", () => {
  it("fill_then_navigation_notes_once: roles in page order, the steps run, never a value", async () => {
    const t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(t.notes()).toEqual([]);
    t.clock.t += 30_000;
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([
      { op: "note_fill", ctx: "menu", item_id: A, origin: SITE, roles: ["username", "current_password"], intent: "login", steps: ["fill"] },
    ]);
    t.ext.navigate(7, 0, `${SITE}/settings`, "doc-3");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toHaveLength(1);
    expect(JSON.stringify(t.notes())).not.toMatch(new RegExp(SECRETS.map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")));
  });

  it("a reload or a redirect to the filled page (same path) is no success: no note; another path is", async () => {
    const t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top);
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    t.ext.navigate(7, 0, `${SITE}/login?error=1#top`, "doc-3");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([]);
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-4");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([expect.objectContaining({ item_id: A })]);
  });

  it("a plan's own fill_and_submit writes no memory (ruling: chain done, save, or fill then navigation)", async () => {
    const t = await bg(() => plan({ intent: "otp", action: "fill_and_submit", groups: [loginGroup(A, "f1", ["otp"])] }), (r) =>
      r.op === "fill_login" ? { totp: "123456" } : undefined,
    );
    const otp = body([form("f1", ["otp"], [{ button_ref: "b1", class: "submit" }])]);
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", context: otp }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(t.toTab("submit")).toHaveLength(1);
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([]);
  });

  it("one note per fill: a confirmed save takes the fill, a later navigation notes nothing more", async () => {
    const t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top);
    const token = await t.b.saves.open({ tabId: 7, origin: SITE, documentId: "doc-1", kind: "login", status: "update", username: "alex", password: "pw", update: { itemId: A, title: "Atlas" } });
    await t.ext.send({ type: "save_decide", token, decision: "update" }, uiSender(`save.html#${token}`, 7));
    expect(t.notes()).toHaveLength(1);
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toHaveLength(1);
  });

  it("no note for a navigation to another site, or after 2 minutes", async () => {
    let t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top);
    t.ext.navigate(7, 0, "https://elsewhere.test/", "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([]);

    t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top);
    t.clock.t += NOTE_NAV_MS + 1;
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([]);
  });

  it("a note_fill failure never breaks the fill", async () => {
    const t = await bg(
      () => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }),
      (r) => (r.op === "note_fill" ? new Error("host gone") : undefined),
    );
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "filled" } });
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toHaveLength(1);
  });

  it("a pick in the menu a plan opened runs the sign-in with that plan, noted by the chain at its end", async () => {
    const t = await bg(() => plan({ action: "show_menu", confidence: "low", groups: [loginGroup(B)], alternatives: [A] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    await t.ext.send({ type: "menu_init", token }, ui);
    expect(await t.ext.send({ type: "menu_pick", token, itemId: A }, ui)).toEqual({ ok: {} });
    expect(t.chainCalls).toEqual([[7, A, undefined, { anchorRef: "f1e0", planned: { roles: ["username", "current_password"], intent: "login" } }]]);
  });

  it("a pick in the menu a plan opened on a password change form is noted once the page moves on", async () => {
    const t = await bg(() => plan({ action: "show_menu", confidence: "low", groups: [loginGroup(B)], alternatives: [A] }));
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "change_password" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    await t.ext.send({ type: "menu_init", token }, ui);
    expect(await t.ext.send({ type: "menu_pick", token, itemId: A }, ui)).toEqual({ ok: {} });
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(t.notes()).toEqual([expect.objectContaining({ item_id: A, roles: ["username", "current_password"], intent: "login" })]);
    expect(t.chainCalls).toEqual([]);
  });

  it("save_confirmed_notes_fill: the saved login with the roles of the fill before it", async () => {
    const t = await bg(() =>
      plan({
        intent: "signup",
        action: "fill",
        groups: [{ form_ref: "f1", kind: "generated_password", item_id: null, fields: [{ field_ref: "f1e1", role: "new_password" }] }],
      }),
    );
    const signup = body([form("f1", ["email", "new_password"], [{ button_ref: "b1", class: "create" }])]);
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", context: signup }, t.top)).toEqual({ ok: { outcome: "filled" } });
    const token = await t.b.saves.open({ tabId: 7, origin: SITE, documentId: "doc-1", kind: "login", status: "new", username: "alex@atlas.dev", password: "Gen-Secret-42!" });
    const edits = { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v1", rule: "domain", tags: [] };
    expect(await t.ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender(`save.html#${token}`, 7))).toEqual({ ok: { outcome: "saved" } });
    expect(t.notes()).toEqual([
      { op: "note_fill", ctx: "save_prompt", item_id: NEW_LOGIN, origin: SITE, roles: ["email", "new_password"], intent: "signup", steps: ["fill"] },
    ]);
  });

  it("a save without a fill before it notes nothing", async () => {
    const t = await bg(() => plan({}));
    const token = await t.b.saves.open({ tabId: 7, origin: SITE, documentId: "doc-1", kind: "login", status: "new", username: "alex", password: "pw" });
    const edits = { title: "Atlas Cloud", username: "alex", password: "", vaultId: "v1", rule: "domain", tags: [] };
    await t.ext.send({ type: "save_decide", token, decision: "save", edits }, uiSender(`save.html#${token}`, 7));
    expect(t.notes()).toEqual([]);
  });
});

describe("forms coverage, Task 12: a menu pick of an identity asks the documents of the menu's form", () => {
  const analysis = (roles: FieldRole[], person2: FieldRole[] = []) => ({
    url: `${SITE}/login`,
    forms: [{
      ref: "f1",
      kind: "identity" as const,
      fields: [...roles.map((role, i) => ({ ref: `f1e${i}`, role })), ...person2.map((role, i) => ({ ref: `f1p${i}`, role, person: 1 }))],
    }],
    captcha: false,
    push: false,
    providerButtons: [],
    accountChooser: [],
  });
  const identityBg = () =>
    bg(
      () => plan({ action: "nothing", confidence: "low" }),
      (r) => (r.op === "list_fillable" ? { items: [{ ...summary(IDENTITY, "Léa Martin"), kind: "identity", has_password: false }] } : undefined),
    );
  const pick = async (t: Awaited<ReturnType<typeof bg>>) => {
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "identity" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    await t.ext.send({ type: "menu_init", token }, ui);
    expect(await t.ext.send({ type: "menu_pick", token, itemId: IDENTITY }, ui)).toEqual({ ok: {} });
    return t.client.requests.filter((r) => r.op === "fill_identity").map((r) => r.extras);
  };

  it("a passport and a loyalty number of the owner: asked; another passenger's license: not", async () => {
    const t = await identityBg();
    await t.ext.send({ type: "page_analysis", analysis: analysis(["given_name", "passport_number", "loyalty_number"], ["license_number"]) }, t.top);
    expect(await pick(t)).toEqual([["passport", "loyalty"]]);
  });

  it("no analysis of the form: no extras", async () => {
    const t = await identityBg();
    expect(await pick(t)).toEqual([undefined]);
  });
});

describe("popup and command", () => {
  const replyContext = (t: Awaited<ReturnType<typeof bg>>, forms: FormContext[]) => {
    t.ext.tabReply = (_tab, m) => ((m as { type: string }).type === "plan_request" ? { ok: true, context: body(forms) } : undefined);
  };

  it("popup_shows_plan_line: the plan in one line, its alternatives first", async () => {
    const t = await bg(() => plan({ action: "open_chain", groups: [loginGroup(B, "f1", ["email"])], alternatives: [] }));
    t.ext.activeTab = { id: 7, url: `${SITE}/login` };
    replyContext(t, [form("f1", ["email"], [{ button_ref: "b1", class: "next" }])]);
    const r = (await t.ext.send({ type: "popup_suggestions" }, uiSender("popup.html"))) as { ok: { items: { item_id: string }[]; plan: unknown } };
    expect(r.ok.plan).toEqual({ intent: "login", label: "bo@atlas.dev", steps: 2, mode: "chain" });
    expect(r.ok.items.map((x) => x.item_id)).toEqual([B, A, C]);
    // The context came from that very document; no click, so no typed username.
    expect(t.toTab("plan_request")).toEqual([expect.objectContaining({ tabId: 7, options: { documentId: "doc-1" } })]);
    expect(t.client.requests.find((x) => x.op === "plan_fill")).toEqual(
      expect.objectContaining({ context: expect.objectContaining({ origin: SITE, typed_username_hash: null }) }),
    );
    // Showing the line fills nothing.
    expect(t.ops().filter((o) => String(o).startsWith("fill_"))).toEqual([]);
    expect(t.chainCalls).toEqual([]);
  });

  it("the sign-in line only for a high open_chain; a fill (medium, or penalized) gets the fill wording", async () => {
    for (const [p, penalty] of [
      [plan({ action: "fill", confidence: "medium", groups: [loginGroup(B, "f1", ["email"])] }), false],
      [plan({ action: "open_chain", groups: [loginGroup(B, "f1", ["email"])] }), true],
    ] as const) {
      const t = await bg(() => p);
      t.ext.activeTab = { id: 7, url: `${SITE}/login` };
      if (penalty) await t.ext.session.set({ [penaltyKey("atlas-cloud.test")]: { at: 1 } });
      replyContext(t, [form("f1", ["email"])]);
      const r = (await t.ext.send({ type: "popup_suggestions" }, uiSender("popup.html"))) as { ok: { plan: unknown } };
      expect(r.ok.plan).toEqual({ intent: "login", label: "bo@atlas.dev", steps: 2, mode: "fill" });
    }
  });

  it("no content script answer: the suggestions alone", async () => {
    const t = await bg(() => plan({ action: "open_chain", groups: [loginGroup(B)] }));
    t.ext.activeTab = { id: 7, url: `${SITE}/login` };
    const r = (await t.ext.send({ type: "popup_suggestions" }, uiSender("popup.html"))) as { ok: Record<string, unknown> };
    expect(r.ok.plan).toBeUndefined();
    expect(t.ops()).not.toContain("plan_fill");
  });

  it("popup_forget_site_calls_host: the tab's site, from the popup only, the penalty goes too", async () => {
    const t = await bg(() => plan({}));
    t.ext.activeTab = { id: 7, url: `${SITE}/login?x=1` };
    await t.ext.session.set({ [penaltyKey("atlas-cloud.test")]: { at: 1 } });
    const r = await t.ext.send({ type: "popup_forget_site" }, uiSender("popup.html"));
    expect(r).toEqual({ ok: { domain: "atlas-cloud.test", items: 2 } });
    expect(t.client.requests).toContainEqual({ op: "forget_site", ctx: "popup", site: SITE });
    expect(t.ext.session.data.has(penaltyKey("atlas-cloud.test"))).toBe(false);
    // Fix 1.3: the key of the raw host goes too (a host tldts reduces differently than the bridge).
    t.ext.activeTab = { id: 7, url: "https://www.atlas-cloud.test/login" };
    await t.ext.session.set({ [penaltyKey("atlas-cloud.test")]: { at: 1 }, [penaltyKey("www.atlas-cloud.test")]: { at: 1 } });
    await t.ext.send({ type: "popup_forget_site" }, uiSender("popup.html"));
    expect(t.ext.session.data.has(penaltyKey("atlas-cloud.test"))).toBe(false);
    expect(t.ext.session.data.has(penaltyKey("www.atlas-cloud.test"))).toBe(false);
    // Another extension page cannot ask for it.
    const before = t.client.requests.length;
    await t.ext.send({ type: "popup_forget_site" }, uiSender("menu.html#AbCdEfGhIjKlMnOpQrStUv", 7));
    expect(t.client.requests.length).toBe(before);
  });

  it("a forget the host could not finish is an error, never a success", async () => {
    const t = await bg(
      () => plan({}),
      (r) => (r.op === "forget_site" ? new BridgeAppError("internal", "a vault could not be read") : undefined),
    );
    t.ext.activeTab = { id: 7, url: `${SITE}/login` };
    const r = (await t.ext.send({ type: "popup_forget_site" }, uiSender("popup.html"))) as { ok?: unknown; err?: unknown };
    expect(r.ok).toBeUndefined();
    expect(r.err).toBeDefined();
  });

  it("the popup's Fill and the fill-smart command ask the top frame to run smart fill", async () => {
    const t = await bg(() => plan({}));
    t.ext.activeTab = { id: 7, url: `${SITE}/login` };
    expect(await t.ext.send({ type: "popup_smart_fill" }, uiSender("popup.html"))).toEqual({ ok: { domain: "atlas-cloud.test" } });
    t.ext.onCommand.emit("some-other-command");
    t.ext.onCommand.emit(FILL_SMART_COMMAND);
    await new Promise((r) => setTimeout(r, 0));
    expect(t.toTab("smart_fill")).toEqual([
      { tabId: 7, message: { type: "smart_fill" }, options: { documentId: "doc-1" } },
      { tabId: 7, message: { type: "smart_fill" }, options: { documentId: "doc-1" } },
    ]);
    // Nothing planned or filled by the worker itself: the content script sends the context.
    expect(t.ops()).toEqual([]);
  });

  it("an http tab gets no smart fill", async () => {
    const t = await bg(() => plan({}));
    t.ext.activeTab = { id: 8, url: "http://atlas-cloud.test/login" };
    t.ext.setFrame(8, 0, "http://atlas-cloud.test/login");
    expect(await t.ext.send({ type: "popup_smart_fill" }, uiSender("popup.html"))).toEqual({ err: "insecure_origin" });
    expect(t.toTab("smart_fill")).toEqual([]);
  });
});

describe("manifest", () => {
  it("declares fill-smart with Ctrl+Shift+L / Command+Shift+L and no other command", () => {
    const m = JSON.parse(readFileSync(join(process.cwd(), "manifests/base.json"), "utf8")) as { commands: Record<string, unknown> };
    expect(m.commands).toEqual({
      [FILL_SMART_COMMAND]: { suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" }, description: "__MSG_fillSmartCommand__" },
    });
    for (const lang of ["en", "fr"]) {
      const msgs = JSON.parse(readFileSync(join(process.cwd(), `src/_locales/${lang}/messages.json`), "utf8")) as Record<string, { message: string }>;
      expect(msgs.fillSmartCommand?.message).toMatch(/OnePass/);
      expect(msgs.fillSmartCommand?.message).not.toContain(String.fromCharCode(0x2014));
    }
  });
});

