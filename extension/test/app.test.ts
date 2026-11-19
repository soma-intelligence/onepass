// Task 10 (smart fill): the triggers, the menu a plan opens, the popup line,
// site memory notes and the penalty, through the real background wiring
// (createBackground, router) against a fake browser and host.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { APP_ASKS_PER_MIN, createBackground, FILL_SMART_COMMAND, GESTURE_MENU_MS } from "../src/background/app";
import type { BridgeLike } from "../src/background/session";
import { BridgeError } from "../src/bridge/bytes";
import { UNLOCK_WAIT_MS } from "../src/shared/unlock";
import type { NativeVault, NativeVaultCall } from "../src/background/safari";
import { BridgeAppError } from "../src/bridge/client";
import { NOTE_NAV_MS } from "../src/background/notes";
import { penaltyKey } from "../src/background/penalty";
import { MemoryPairingStore, Store } from "../src/background/store";
import type { FieldRole, FormContext, PlanOut, ProviderId } from "../src/shared/messages";
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
  providerOnly?: () => Promise<ProviderId[] | null>,
  more: { openApp?: () => Promise<boolean>; newClient?: (c: FakeClient) => BridgeLike; ext?: FakeExt; pairings?: MemoryPairingStore; providersShown?: () => Promise<ProviderId[]> } = {},
) {
  const ext = more.ext ?? new FakeExt();
  const pairings = more.pairings ?? new MemoryPairingStore();
  if (!more.pairings) await new Store(ext, pairings).setPairing(record());
  const clock = { t: 5_000_000 };
  const chainCalls: unknown[][] = [];
  const chain = {
    start: async (...a: unknown[]) => void chainCalls.push(a),
    stop: async () => undefined,
    state: async () => null,
    ...(providerOnly ? { providerOnly } : {}),
    ...(more.providersShown ? { providersShown: more.providersShown } : {}),
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
    newClient: () => (more.newClient ? more.newClient(client) : client),
    sleep: async () => undefined,
    chain,
    now: () => clock.t,
    ...(nativeVault ? { nativeVault } : {}),
    ...(more.openApp ? { openApp: more.openApp } : {}),
  });
  b.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  const top = csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });
  const ops = () => client.requests.map((r) => r.op);
  const notes = () => client.requests.filter((r) => r.op === "note_fill");
  const toTab = (type: string) => ext.sentToTabs.filter((m) => (m.message as { type: string }).type === type);
  return { ext, b, client, clock, chainCalls, top, ops, notes, toTab, pairings };
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
    expect(replay[0]).toMatchObject({ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-1" } });
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

  it("the automatic Face ID of a menu no gesture opened unlocks but never fills: the menu stays and loads", async () => {
    // A menu from the keyboard: no tap on the icon came before it.
    const t = await lockedBg();
    const { token, ui } = await openMenu(t);
    expect(await t.ext.send({ type: "menu_unlock_biometric", token }, ui)).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(t.toTab("smart_fill")).toHaveLength(0);
    expect(t.toTab("remove_frame")).toHaveLength(0);
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toHaveProperty("ok");
    // Nor does the app path's resume: no unlock was asked in the app.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(0);
  });

  it("iOS: the menu a tap on the icon opened fills after its automatic Face ID, once", async () => {
    const t = await lockedBg();
    const { token, ui } = await tapThenMenu(t);
    expect(await t.ext.send({ type: "menu_unlock_biometric", token }, ui)).toEqual({ ok: { locked: false, account: "Camille", biometry: "faceID" } });
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    const replay = t.toTab("smart_fill");
    expect(replay).toHaveLength(1);
    expect(replay[0]).toMatchObject({ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-1" } });
    // One attempt: the token is gone, nothing else runs from it.
    expect(await t.ext.send({ type: "menu_unlock_biometric", token }, ui)).toEqual({ err: "invalid" });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(1);
  });

  it("iOS: the automatic Face ID fills only the gesture's own menu (same field, same document, opened at once)", async () => {
    // The tap was on another field than the menu's.
    let t = await lockedBg();
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e1", context: body(LOGIN_FORM) }, t.top);
    let m = await openMenu(t, "f1e0");
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token }, m.ui);
    expect(t.toTab("smart_fill")).toHaveLength(0);

    // The menu opened long after the tap.
    t = await lockedBg();
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    t.clock.t += GESTURE_MENU_MS + 1;
    m = await openMenu(t);
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token }, m.ui);
    expect(t.toTab("smart_fill")).toHaveLength(0);

    // A click into the field (auto menu) is not the icon's gesture, and leaves it to the icon's menu.
    t = await lockedBg();
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
    m = await openMenu(t);
    const second = await openMenu(t);
    await t.ext.send({ type: "menu_unlock_biometric", token: second.token }, second.ui);
    // The gesture's link was used by the first menu: a later one does not inherit it.
    expect(t.toTab("smart_fill")).toHaveLength(0);

    // The page changed between the automatic unlock's start and its end: nothing fills.
    t = await lockedBg();
    m = await tapThenMenu(t);
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token }, m.ui);
    expect(t.toTab("smart_fill")).toHaveLength(0);

    // iOS never opens the app for this: the sheet unlocks.
    expect(t.ops()).not.toContain("unlock");
  });

  it("always the menu's own field: a keyboard menu, or a tap on another field before it", async () => {
    // A menu from the keyboard (no locked plan before it).
    let t = await lockedBg();
    let m = await openMenu(t);
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    expect(t.toTab("smart_fill").map((x) => x.message)).toEqual([{ type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }]);

    // The tap was on another field than the menu's: the menu's field runs.
    t = await lockedBg();
    await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e1", context: body(LOGIN_FORM) }, t.top);
    m = await openMenu(t, "f1e0");
    await t.ext.send({ type: "menu_unlock_biometric", token: m.token, gesture: true }, m.ui);
    expect(t.toTab("smart_fill").map((x) => x.message)).toEqual([{ type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }]);
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
    expect(replay[0]).toMatchObject({ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-3" } });
  });
});

describe("one gesture on a locked vault (Mac): the app is asked at once and the menu's fill resumes", () => {
  /** A locked vault: plans fail `locked`; `unlock` asks the app (still locked unless `instant`). */
  async function lockedMac(over: { opens?: boolean; instant?: boolean } = {}) {
    const vault = { locked: true };
    const opened = { n: 0 };
    const t = await bg(
      () => plan({ action: "fill", groups: [loginGroup(A)] }),
      (r) => {
        if (r.op === "status") return { locked: vault.locked, account: "Camille", vaults: 1 };
        if (r.op === "unlock") {
          if (over.instant) vault.locked = false;
          return { locked: vault.locked };
        }
        return (r.op === "plan_fill" || r.op === "list_for_origin" || r.op === "fill_login") && vault.locked ? new BridgeAppError("locked", "vault locked") : undefined;
      },
      undefined,
      undefined,
      {
        openApp: async () => {
          opened.n++;
          return over.opens ?? true;
        },
      },
    );
    t.ext.tabReply = (_tab, m) => ((m as { type: string }).type === "fill" ? { ok: true, filled: ["username", "current_password"] } : undefined);
    return { ...t, vault, opened };
  }
  type T = Awaited<ReturnType<typeof lockedMac>>;
  /** An icon click on `fieldRef`; null: the popup's Fill or the command (no field). */
  const click = (t: T, fieldRef: string | null = "f1e0") =>
    t.ext.send({ type: "plan_context", ...(fieldRef !== null ? { formRef: "f1", fieldRef } : {}), context: body(LOGIN_FORM) }, t.top);
  async function menuOf(t: T, fieldRef = "f1e0", extra: Record<string, unknown> = {}, from = t.top) {
    const open = (await t.ext.send({ type: "open_menu", fieldRef, formRef: "f1", formKind: "login", ...extra }, from)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    return { token, ui: uiSender(`menu.html#${token}`, 7) };
  }
  const unlocks = (t: T) => t.ops().filter((o) => o === "unlock").length;
  const unlockReqs = (t: { client: FakeClient }) => t.client.requests.filter((r) => r.op === "unlock");

  describe("the app comes forward only for the tab in front, a few times a minute", () => {
    it("a tab that is not the active tab of its window: no launch, no unlock asked", async () => {
      const t = await lockedMac();
      t.ext.tabStates.set(7, { active: false, windowId: 1 });
      expect(await click(t)).toEqual({ err: "locked" });
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(0);
      // The menu's own button, a click of its own: refused too.
      const m = await menuOf(t);
      expect(await t.ext.send({ type: "menu_unlock", token: m.token }, m.ui)).toEqual({ err: "refused" });
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(0);
    });

    it("a window that is not focused: no launch, no unlock asked", async () => {
      const t = await lockedMac();
      (t.ext as unknown as { windows: unknown }).windows = { get: async (id: number) => ({ id, focused: false }) };
      expect(await click(t)).toEqual({ err: "locked" });
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(0);
    });

    it("the active tab of the focused window: asked", async () => {
      const t = await lockedMac();
      (t.ext as unknown as { windows: unknown }).windows = { get: async (id: number) => ({ id, focused: true }) };
      expect(await click(t)).toEqual({ err: "locked" });
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(1);
    });

    it("at most APP_ASKS_PER_MIN gestures of a tab bring the app forward within a minute; another tab keeps its own count", async () => {
      const t = await lockedMac();
      for (let i = 0; i < APP_ASKS_PER_MIN; i++) {
        expect(await click(t)).toEqual({ err: "locked" });
        t.clock.t += 5_000;
      }
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(APP_ASKS_PER_MIN);
      expect(await click(t)).toEqual({ err: "locked" });
      const m = await menuOf(t);
      expect(await t.ext.send({ type: "menu_unlock", token: m.token }, m.ui)).toEqual({ err: "refused" });
      expect(t.opened.n).toBe(0);
      expect(unlocks(t)).toBe(APP_ASKS_PER_MIN);
      // Another tab is not held back by this one.
      t.ext.setFrame(8, 0, `${SITE}/login`, "doc-8");
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, csSender(`${SITE}/login`, 8, 0, { documentId: "doc-8" }))).toEqual({ err: "locked" });
      expect(unlocks(t)).toBe(APP_ASKS_PER_MIN + 1);
      // A minute later the first tab may ask again.
      t.clock.t += 61_000;
      expect(await click(t)).toEqual({ err: "locked" });
      expect(unlocks(t)).toBe(APP_ASKS_PER_MIN + 2);
    });
  });

  describe("the bridge `unlock` names the page the gesture happened on: the tab's top-frame origin", () => {
    it("the locked path: the gesture's unlock carries the top origin", async () => {
      const t = await lockedMac();
      await click(t);
      expect(unlockReqs(t)).toEqual([{ op: "unlock", origin: SITE }]);
    });

    it("a menu in a child frame of another origin: its unlock button names the top frame, never the child", async () => {
      const t = await lockedMac();
      const child = "https://pay.other.example";
      t.ext.setFrame(7, 4, `${child}/card`, "doc-4");
      const m = await menuOf(t, "f1e0", {}, csSender(`${child}/card`, 7, 4, { documentId: "doc-4" }));
      await t.ext.send({ type: "menu_unlock", token: m.token }, m.ui);
      expect(unlockReqs(t)).toEqual([{ op: "unlock", origin: SITE }]);
    });

    it("an app from before `origin` on `unlock` (it answers `invalid`): asked again without it, once, then never with it this session", async () => {
      const vault = { locked: true };
      const t = await bg(
        () => plan({ action: "fill", groups: [loginGroup(A)] }),
        (r) => {
          if (r.op === "unlock") return "origin" in r ? new BridgeAppError("invalid", "unknown field") : { locked: vault.locked };
          return r.op === "plan_fill" || r.op === "list_for_origin" ? new BridgeAppError("locked", "vault locked") : undefined;
        },
        undefined,
        undefined,
        { openApp: async () => true },
      );
      const tap = () => t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
      expect(await tap()).toEqual({ err: "locked" });
      expect(unlockReqs(t)).toEqual([{ op: "unlock", origin: SITE }, { op: "unlock" }]);
      // The menu the gesture opens waits as for any app: the unlock was asked.
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      expect(open.ok.url).toContain("menu.html#");
      t.clock.t += 5_000;
      expect(await tap()).toEqual({ err: "locked" });
      expect(unlockReqs(t).slice(2)).toEqual([{ op: "unlock" }]);
    });

    it("a loopback http page is named, any other http page is not", async () => {
      const t = await lockedMac();
      const local = "http://localhost:3000";
      t.ext.setFrame(9, 0, `${local}/login`, "doc-9");
      await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, csSender(`${local}/login`, 9, 0, { documentId: "doc-9" }));
      expect(unlockReqs(t)).toEqual([{ op: "unlock", origin: local }]);
    });

    it("the generic card of a locked sign-in page: its click's unlock carries the top origin", async () => {
      const t = await lockedMac();
      const token = await t.b.overlays.open({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" }, undefined, true);
      expect(token).not.toBeNull();
      await t.ext.send({ type: "overlay_unlock", token }, uiSender(`overlay.html#${token}`, 7));
      expect(unlockReqs(t)).toEqual([{ op: "unlock", origin: SITE }]);
    });
  });

  describe("a gesture without a field, on a page with none to open a menu under (the command on a provider-only page)", () => {
    const sso = { url: `${SITE}/login`, forms: [], captcha: false, push: false, providerButtons: [{ provider: "google", ref: "g1" }], accountChooser: [] };
    const plain = { url: `${SITE}/login`, forms: [], captcha: false, push: false, providerButtons: [], accountChooser: [] };
    /** The real chain runner (it reads the page's analysis): a locked vault, the app asked by the gesture. */
    async function lockedReal() {
      const ext = new FakeExt();
      const pairings = new MemoryPairingStore();
      await new Store(ext, pairings).setPairing(record());
      const vault = { locked: true };
      const opened = { n: 0 };
      const clock = { t: 5_000_000 };
      const client = new FakeClient((r) => {
        if (r.op === "status") return { locked: vault.locked, account: "Camille", vaults: 1 };
        if (r.op === "unlock") return { locked: vault.locked };
        if (r.op === "fill_salt") return { salt: "a".repeat(64) };
        if (vault.locked) return new BridgeAppError("locked", "vault locked");
        return r.op === "list_for_origin" ? { items: [] } : r.op === "plan_fill" ? { plan: plan({ intent: "ignore" as PlanOut["intent"], action: "nothing", confidence: "low" }) } : {};
      });
      const b = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, now: () => clock.t, openApp: async () => (opened.n++, true) });
      b.install();
      ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
      const top = csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" });
      const cards = () => ext.sentToTabs.filter((m) => (m.message as { type: string; kind?: string }).type === "show_frame" && (m.message as { kind?: string }).kind === "overlay");
      const smart = () => ext.sentToTabs.filter((m) => (m.message as { type: string }).type === "smart_fill");
      return { ext, b, client, vault, opened, clock, top, cards, smart };
    }

    it("a sign-in page: the app is asked once, a card of the page waits, and the page's plan runs after the unlock, once", async () => {
      const t = await lockedReal();
      await t.ext.send({ type: "page_analysis", analysis: sso }, t.top);
      await t.b.runner?.state(7);
      const before = t.cards().length;
      expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ err: "locked" });
      expect(t.opened.n).toBe(0);
      expect(t.cards()).toHaveLength(before + 1);
      const url = (t.cards().at(-1)?.message as { url: string }).url;
      const token = url.split("#")[1] as string;
      const ui = uiSender(`overlay.html#${token}`, 7);
      expect(await t.ext.send({ type: "overlay_init", token }, ui)).toEqual({ ok: { origin: SITE, accounts: [], chain: null, waiting: "locked" } });
      expect(t.smart()).toEqual([]);
      t.vault.locked = false;
      t.clock.t += 1500;
      await t.ext.send({ type: "overlay_state", token }, ui);
      expect(t.smart()).toEqual([{ tabId: 7, message: { type: "smart_fill", origin: SITE }, options: { documentId: "doc-1" } }]);
      // The plan that page then sends is the same gesture resumed: no second launch, no second unlock.
      const unlocks = t.client.requests.filter((r) => r.op === "unlock").length;
      expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ ok: { outcome: "nothing" } });
      expect(t.opened.n).toBe(0);
      expect(t.client.requests.filter((r) => r.op === "unlock")).toHaveLength(unlocks);
      t.clock.t += 1500;
      await t.ext.send({ type: "overlay_state", token }, ui);
      expect(t.smart()).toHaveLength(1);
    });

    it("any other page: the app is asked, nothing shows and nothing resumes", async () => {
      const t = await lockedReal();
      await t.ext.send({ type: "page_analysis", analysis: plain }, t.top);
      await t.b.runner?.state(7);
      expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ err: "locked" });
      expect(t.opened.n).toBe(0);
      expect(t.cards()).toEqual([]);
      expect(t.smart()).toEqual([]);
    });
  });

  it("unlocked before the gesture's menu even loaded (a fast Touch ID): the menu's first look resumes the fill, no row to pick", async () => {
    const t = await lockedMac();
    expect(await click(t)).toEqual({ err: "locked" });
    const { token, ui } = await menuOf(t);
    // Touch ID passed while the menu frame was loading.
    t.vault.locked = false;
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toEqual({ ok: { origin: SITE, formKind: "login", items: [] } });
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    expect(t.toTab("smart_fill")).toEqual([{ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-1" } }]);
    // Once: the token is spent, and the app was asked a single time.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(1);
    expect(unlocks(t)).toBe(1);
    expect(t.opened.n).toBe(0);
  });

  it("a menu no gesture asked an unlock for just lists when the vault is open (nothing fills by itself)", async () => {
    const t = await lockedMac();
    t.vault.locked = false;
    const { token, ui } = await menuOf(t);
    const init = (await t.ext.send({ type: "menu_init", token }, ui)) as { ok: { items: unknown[] } };
    expect(init.ok.items).toHaveLength(3);
    expect(t.toTab("smart_fill")).toEqual([]);
    expect(t.toTab("remove_frame")).toEqual([]);
  });

  it("the click opens the app with its unlock; the menu it opens waits, then resumes once", async () => {
    const t = await lockedMac();
    expect(await click(t)).toEqual({ err: "locked" });
    expect(t.opened.n).toBe(0);
    expect(unlocks(t)).toBe(1);
    const { token, ui } = await menuOf(t);
    // Still locked: the menu waits, nothing is used up.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    expect(t.toTab("smart_fill")).toHaveLength(0);
    // Touch ID in the app.
    t.vault.locked = false;
    t.clock.t += 20_000;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t.toTab("remove_frame").at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
    expect(t.toTab("smart_fill")).toEqual([{ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-1" } }]);
    // One attempt per token.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(1);
    // The app was asked once, by the gesture.
    expect(t.opened.n).toBe(0);
    expect(unlocks(t)).toBe(1);
  });

  it("the replay after the unlock is no gesture: locked again, it asks nothing and waits for a click", async () => {
    const t = await lockedMac();
    await click(t);
    const { token, ui } = await menuOf(t);
    t.vault.locked = false;
    await t.ext.send({ type: "menu_resume", token }, ui);
    // The vault locked again before the replayed plan: the menu comes with its button, no app.
    t.vault.locked = true;
    expect(await click(t)).toEqual({ err: "locked" });
    expect(t.opened.n).toBe(0);
    expect(unlocks(t)).toBe(1);
    const again = await menuOf(t);
    expect(await t.ext.send({ type: "menu_resume", token: again.token }, again.ui)).toEqual({ err: "invalid" });
    // A new click on the icon is a gesture again.
    t.clock.t += 3000;
    await click(t);
    expect(unlocks(t)).toBe(2);
  });

  it("the keyboard command's menu (no field in the plan) resumes its own field", async () => {
    const t = await lockedMac();
    expect(await click(t, null)).toEqual({ err: "locked" });
    const { token, ui } = await menuOf(t, "f1e1");
    t.vault.locked = false;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t.toTab("smart_fill").map((x) => x.message)).toEqual([{ type: "smart_fill", fieldRef: "f1e1", formRef: "f1", origin: SITE }]);
  });

  it("the app unlocks at once: the plan runs in the click's own call, no menu", async () => {
    const t = await lockedMac({ instant: true });
    expect(await click(t)).toEqual({ ok: { outcome: "filled" } });
    expect(t.opened.n).toBe(0);
    expect(t.toTab("fill")).toHaveLength(1);
  });

  it("the launch link cannot open the app: no matter while it runs, the gesture's unlock waits", async () => {
    const t = await lockedMac({ opens: false });
    expect(await click(t)).toEqual({ err: "locked" });
    expect(unlocks(t)).toBe(1);
    const { token, ui } = await menuOf(t);
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    // The button: asked from the menu, it waits and resumes as before.
    expect(await t.ext.send({ type: "menu_unlock", token }, ui)).toEqual({ ok: { locked: true } });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    t.vault.locked = false;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t.toTab("smart_fill")).toHaveLength(1);
    expect(t.opened.n).toBe(0);
  });

  it("only the gesture's own menu waits: not an auto menu, another field, another document, or a late one", async () => {
    // A click into the field (auto) cannot open on a locked vault, and does not use the gesture up.
    let t = await lockedMac();
    await click(t);
    expect(await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login", auto: true }, t.top)).toEqual({ err: "not_found" });
    let m = await menuOf(t);
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "locked" });
    // The link is single-use: a second menu of the frame is not the gesture's.
    m = await menuOf(t);
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });

    t = await lockedMac();
    await click(t, "f1e1");
    m = await menuOf(t, "f1e0");
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });

    t = await lockedMac();
    await click(t);
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    m = await menuOf(t, "f1e0", {}, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-2" }));
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });

    t = await lockedMac();
    await click(t);
    t.clock.t += GESTURE_MENU_MS + 1;
    m = await menuOf(t);
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });
  });

  it("the resume keeps its binding and its deadline: 90 s, same document, https, its own tab", async () => {
    let t = await lockedMac();
    await click(t);
    let m = await menuOf(t);
    t.vault.locked = false;
    t.clock.t += UNLOCK_WAIT_MS + 1;
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(0);

    for (const [url, doc] of [[`${SITE}/login`, "doc-2"], ["https://other.example/login", "doc-1"], ["http://atlas-cloud.test/login", "doc-1"]] as const) {
      t = await lockedMac();
      await click(t);
      m = await menuOf(t);
      t.vault.locked = false;
      t.ext.setFrame(7, 0, url, doc);
      expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });
      // Refused once, refused for good.
      t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
      expect(await t.ext.send({ type: "menu_resume", token: m.token }, m.ui)).toEqual({ err: "invalid" });
      expect(t.toTab("smart_fill")).toHaveLength(0);
    }

    t = await lockedMac();
    await click(t);
    m = await menuOf(t);
    t.vault.locked = false;
    expect(await t.ext.send({ type: "menu_resume", token: m.token }, uiSender(`menu.html#${m.token}`, 8))).toEqual({ err: "invalid" });
    expect(t.toTab("smart_fill")).toHaveLength(0);
  });

  it("the request survives a worker restart: storage.session holds its time and binding, never a secret", async () => {
    const t = await lockedMac();
    await click(t);
    const { token, ui } = await menuOf(t);
    const kept = [...t.ext.session.data.entries()].filter(([k]) => k.startsWith("unlock:"));
    expect(kept).toEqual([[`unlock:${token}`, { at: t.clock.t, sent: true, tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" }]]);
    // A new worker on the same session storage.
    const ext2 = new FakeExt();
    for (const [k, v] of t.ext.session.data) ext2.session.data.set(k, structuredClone(v));
    const t2 = await bg(() => plan({ action: "fill", groups: [loginGroup(A)] }), (r) => (r.op === "status" ? { locked: false, account: "Camille", vaults: 1 } : undefined), undefined, undefined, {
      ext: ext2,
      pairings: t.pairings,
    });
    t2.clock.t = t.clock.t + 30_000;
    expect(await t2.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t2.toTab("smart_fill")).toHaveLength(1);
    expect([...ext2.session.data.keys()].filter((k) => k.startsWith("unlock:"))).toEqual([]);
    expect(await t2.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });

    // A stored request of another menu (binding mismatch) is refused and dropped.
    const t3 = await lockedMac();
    const m3 = await menuOf(t3);
    await t3.ext.session.set({ [`unlock:${m3.token}`]: { at: t3.clock.t, sent: true, tabId: 7, frameId: 2, origin: SITE, documentId: "doc-1" } });
    t3.vault.locked = false;
    expect(await t3.ext.send({ type: "menu_resume", token: m3.token }, m3.ui)).toEqual({ err: "invalid" });
    expect(t3.toTab("smart_fill")).toHaveLength(0);
  });
});

describe("one gesture when the app is not running: it is launched, then the fill resumes like an unlock", () => {
  /** No host until `app.up`; then a locked vault until `app.locked` is false. */
  async function noApp() {
    const app = { up: false, locked: true };
    const opened = { n: 0 };
    const t = await bg(
      () => plan({ action: "fill", groups: [loginGroup(A)] }),
      (r) => {
        if (r.op === "status") return { locked: app.locked, account: "Camille", vaults: 1 };
        if (r.op === "unlock") return { locked: app.locked };
        return (r.op === "plan_fill" || r.op === "list_for_origin") && app.locked ? new BridgeAppError("locked", "vault locked") : undefined;
      },
      undefined,
      undefined,
      {
        openApp: async () => {
          opened.n++;
          return true;
        },
        // A fresh port each time: it opens only once the app runs.
        newClient: (c) => ({
          get isOpen() {
            return app.up && c.isOpen;
          },
          open: async (rec) => {
            if (!app.up) throw new BridgeError("transport", "Specified native messaging host not found.");
            await c.open(rec);
          },
          pair: (...a) => c.pair(...a),
          request: (req) => c.request(req),
          close: () => undefined,
        }),
      },
    );
    return { ...t, app, opened };
  }

  it("never launched without a gesture: a page analysis, an auto menu and a menu's polls leave the app alone", async () => {
    const t = await noApp();
    await t.ext.send({ type: "page_analysis", analysis: { url: `${SITE}/login`, forms: [], captcha: false, push: false, providerButtons: [], accountChooser: [] } }, t.top);
    expect(await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login", auto: true }, t.top)).toHaveProperty("err");
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "host_missing" });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.opened.n).toBe(0);
  });

  it("the icon click launches the app once; its menu waits, asks the unlock when the app answers, then resumes", async () => {
    const t = await noApp();
    expect(await t.ext.send({ type: "fill_salt" }, t.top)).toEqual({ err: "host_missing" });
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ err: "host_missing" });
    // One launch for the whole gesture.
    expect(t.opened.n).toBe(1);
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    expect(await t.ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "host_missing" });
    // The app is starting.
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "host_missing" });
    expect(t.opened.n).toBe(1);
    // It runs, locked: the unlock is asked of it once (Touch ID), the menu keeps waiting.
    t.app.up = true;
    t.clock.t += 2000;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
    expect(t.ops().filter((o) => o === "unlock")).toHaveLength(1);
    t.app.locked = false;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t.toTab("smart_fill")).toEqual([{ tabId: 7, message: { type: "smart_fill", fieldRef: "f1e0", formRef: "f1", origin: SITE }, options: { documentId: "doc-1" } }]);
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "invalid" });
    expect(t.opened.n).toBe(1);
  });

  describe("contract with the Mac app: the bridge `unlock` goes once per gesture once the app answers, even already unlocked", () => {
    const unlockOps = (t: Awaited<ReturnType<typeof noApp>>) => t.ops().filter((o) => o === "unlock").length;
    const tick = () => new Promise((r) => setTimeout(r, 0));

    it("cold: the `unlock` sent once the launched app answers names the top origin of the gesture's tab", async () => {
      const t = await noApp();
      await t.ext.send({ type: "fill_salt" }, t.top);
      await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      const token = open.ok.url.split("#")[1] as string;
      t.app.up = true;
      await t.ext.send({ type: "menu_resume", token }, uiSender(`menu.html#${token}`, 7));
      expect(t.client.requests.filter((r) => r.op === "unlock")).toEqual([{ op: "unlock", origin: SITE }]);
    });

    it("cold, the app answers already unlocked (Touch ID through the launch link): `unlock` once from the waiting menu, then the fill", async () => {
      const t = await noApp();
      await t.ext.send({ type: "fill_salt" }, t.top);
      await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      const token = open.ok.url.split("#")[1] as string;
      const ui = uiSender(`menu.html#${token}`, 7);
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "host_missing" });
      expect(unlockOps(t)).toBe(0);
      // Launched and unlocked before the bridge connects: the op is what hands the front back.
      t.app.up = true;
      t.app.locked = false;
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
      expect(unlockOps(t)).toBe(1);
      expect(t.toTab("smart_fill")).toHaveLength(1);
      expect(t.opened.n).toBe(1);
    });

    it("cold, the app answers within the gesture itself and is open: the plan fills and `unlock` still goes, once", async () => {
      const t = await noApp();
      t.ext.tabReply = (_tab, m) => ((m as { type: string }).type === "fill" ? { ok: true, filled: ["username", "current_password"] } : undefined);
      await t.ext.send({ type: "fill_salt" }, t.top);
      await tick();
      expect(t.opened.n).toBe(1);
      t.app.up = true;
      t.app.locked = false;
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "filled" } });
      expect(unlockOps(t)).toBe(1);
      // The next gesture, the app running and open: nothing to hand back, no op.
      t.clock.t += 60_000;
      await t.ext.send({ type: "fill_salt" }, t.top);
      await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
      expect(unlockOps(t)).toBe(1);
      expect(t.opened.n).toBe(1);
    });

    it("cold, the app answers within the gesture and is locked: `unlock` once (the request), not again at the resume", async () => {
      const t = await noApp();
      await t.ext.send({ type: "fill_salt" }, t.top);
      await tick();
      t.app.up = true;
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ err: "locked" });
      expect(unlockOps(t)).toBe(1);
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      const token = open.ok.url.split("#")[1] as string;
      const ui = uiSender(`menu.html#${token}`, 7);
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "locked" });
      t.app.locked = false;
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
      expect(unlockOps(t)).toBe(1);
    });

    it("locked (the app running): `unlock` once at the gesture, none while the menu waits nor at the resume", async () => {
      const t = await noApp();
      t.app.up = true;
      await t.ext.send({ type: "fill_salt" }, t.top);
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ err: "locked" });
      expect(unlockOps(t)).toBe(1);
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      const token = open.ok.url.split("#")[1] as string;
      const ui = uiSender(`menu.html#${token}`, 7);
      await t.ext.send({ type: "menu_resume", token }, ui);
      await t.ext.send({ type: "menu_resume", token }, ui);
      t.app.locked = false;
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
      expect(unlockOps(t)).toBe(1);
      // Running: the app asks Touch ID over the browser, the launch link stays closed.
      expect(t.opened.n).toBe(0);
    });

    it("the Open OnePass button on a cold app: `unlock` once when it answers, already unlocked or not", async () => {
      const t = await noApp();
      const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
      const token = open.ok.url.split("#")[1] as string;
      const ui = uiSender(`menu.html#${token}`, 7);
      await t.ext.send({ type: "menu_unlock", token }, ui);
      await t.ext.send({ type: "menu_resume", token }, ui);
      expect(unlockOps(t)).toBe(0);
      t.app.up = true;
      t.app.locked = false;
      expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
      expect(unlockOps(t)).toBe(1);
    });
  });

  it("the menu's Open OnePass button launches it and waits the same way", async () => {
    const t = await noApp();
    const open = (await t.ext.send({ type: "open_menu", fieldRef: "f1e0", formRef: "f1", formKind: "login" }, t.top)) as { ok: { url: string } };
    const token = open.ok.url.split("#")[1] as string;
    const ui = uiSender(`menu.html#${token}`, 7);
    expect(await t.ext.send({ type: "menu_unlock", token }, ui)).toEqual({ ok: { locked: true } });
    expect(t.opened.n).toBe(1);
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ err: "host_missing" });
    t.app.up = true;
    t.app.locked = false;
    expect(await t.ext.send({ type: "menu_resume", token }, ui)).toEqual({ ok: {} });
    expect(t.toTab("smart_fill")).toHaveLength(1);
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

  describe("the plan path signs in through a provider as the overlay does", () => {
    const viaGoogle = (id: string, email: string) => ({ ...summary(id, email), has_password: false, methods: [{ provider: "google", account_email: email }] });
    const listed = (items: unknown[]) => (r: Record<string, unknown>) =>
      r.op === "list_for_origin" ? { items } : r.op === "provider_accounts" ? { accounts: [summary(C, "alex@gmail.test")], linked_item_id: C } : undefined;
    const shown = (providers: ProviderId[]) => async () => providers;

    it("an icon click on a form whose site's one login signs in with a provider the page shows: that chain, one gesture", async () => {
      const t = await bg(() => plan({ action: "show_menu", confidence: "low", reasons: ["no_candidate"] }), listed([viaGoogle(A, "alex@gmail.test")]), undefined, undefined, { providersShown: shown(["google"]) });
      const r = await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top);
      expect(r).toEqual({ ok: { outcome: "chain" } });
      expect(t.chainCalls).toEqual([[7, A, "google", { accountId: C }]]);
    });

    it("the card never offers a login reached through an associated domain (the bridge serves it to a pick in the menu or the popup only)", async () => {
      const t = await bg(() => plan({ action: "show_menu", confidence: "low", reasons: ["associated_domain"] }), (r) => (r.op === "list_for_origin" ? { items: [{ ...summary(A, "alex@atlas.dev"), associated: true }, summary(B, "bo@atlas.dev")] } : undefined));
      const token = await t.b.overlays.open({ tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
      const init = (await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))) as { ok: { accounts: { itemId: string }[] } };
      expect(init.ok.accounts.map((a) => a.itemId)).toEqual([B]);
      expect(await t.ext.send({ type: "overlay_start", token, itemId: A }, uiSender(`overlay.html#${token}`, 7))).toEqual({ err: "invalid" });
      expect(t.chainCalls).toEqual([]);
    });

    it("never a login offered through an associated domain: it is not this site's own, the user picks it", async () => {
      const t = await bg(() => plan({ action: "show_menu", confidence: "low", reasons: ["associated_domain"] }), listed([{ ...viaGoogle(A, "alex@gmail.test"), associated: true }]), undefined, undefined, { providersShown: shown(["google"]) });
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "menu" } });
      expect(t.chainCalls).toEqual([]);
    });

    it("not when the page does not show that provider, when the vault has another way in, or on a page that is no sign-in", async () => {
      // The provider's button is not on the page.
      let t = await bg(() => plan({ action: "show_menu", confidence: "low" }), listed([viaGoogle(A, "alex@gmail.test")]), undefined, undefined, { providersShown: shown(["apple"]) });
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "menu" } });
      expect(t.chainCalls).toEqual([]);
      // A password login beside it: the user chooses.
      t = await bg(() => plan({ action: "show_menu", confidence: "low", reasons: ["tie"] }), listed([viaGoogle(A, "alex@gmail.test"), summary(B, "bo@atlas.dev")]), undefined, undefined, { providersShown: shown(["google"]) });
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "menu" } });
      expect(t.chainCalls).toEqual([]);
      // A signup form.
      t = await bg(() => plan({ intent: "signup", action: "show_menu", confidence: "low" }), listed([viaGoogle(A, "alex@gmail.test")]), undefined, undefined, { providersShown: shown(["google"]) });
      expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "menu" } });
      expect(t.chainCalls).toEqual([]);
    });
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
    // A plan's own fill, and noted as one: never as the user's pick of a row ("menu").
    expect(t.ops().filter((o) => o === "fill_login")).toHaveLength(1);
    expect(t.client.requests.find((r) => r.op === "fill_login")).toMatchObject({ ctx: "chain" });
    expect(t.notes()).toEqual([
      { op: "note_fill", ctx: "chain", item_id: A, origin: SITE, roles: ["username", "current_password"], intent: "login", steps: ["fill"] },
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

  it("a fill_and_submit plan is the chain's: the planner submits nothing and writes no memory (the chain notes at done)", async () => {
    const t = await bg(() => plan({ intent: "otp", action: "fill_and_submit", groups: [loginGroup(A, "f1", ["otp"])] }), (r) =>
      r.op === "fill_login" ? { totp: "123456" } : undefined,
    );
    const otp = body([form("f1", ["otp"], [{ button_ref: "b1", class: "submit" }])]);
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", context: otp }, t.top)).toEqual({ ok: { outcome: "chain" } });
    expect(t.chainCalls).toEqual([[7, A, undefined, { planned: { roles: ["otp"], intent: "otp" } }]]);
    expect(t.toTab("submit")).toEqual([]);
    expect(t.ops()).not.toContain("fill_login");
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
    // The row the user clicked: the chain is told so (its first fill is that pick).
    expect(t.chainCalls).toEqual([[7, A, undefined, { anchorRef: "f1e0", planned: { roles: ["username", "current_password"], intent: "login" }, picked: "menu" }]]);
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

// Task 14 witness (seeds forms-2026-11-06-a sites 5, 51, 58, 158 and -b 5, 20, 28, 37, 147, 150, 181, 199):
// a page whose only way in is a provider button gave the toolbar's Fill nothing to do.
describe("smart fill on a provider-only page", () => {
  const via = (id: string, provider: string) => ({
    ...summary(id, "dorian@example.org"), has_password: false, methods: [{ provider, account_email: "dorian@example.org" }],
  });
  const nothing = () => plan({ intent: "unknown" as PlanOut["intent"], action: "nothing", confidence: "low" });

  it("the toolbar's Fill signs in through the provider of the only item that has it", async () => {
    const t = await bg(nothing, (r) => (r.op === "list_for_origin" ? { items: [via(A, "apple"), summary(B, "bo@atlas.dev")] } : undefined),
      undefined, async () => ["apple"]);
    const r = await t.ext.send({ type: "plan_context", context: body([]) }, t.top);
    expect(r).toEqual({ ok: { outcome: "chain" } });
    expect(t.chainCalls).toEqual([[7, A, "apple", {}]]);
  });

  it("two items through the page's providers, a page with forms, or an icon click: no sign-in", async () => {
    const two = await bg(nothing, (r) => (r.op === "list_for_origin" ? { items: [via(A, "apple"), via(B, "google")] } : undefined),
      undefined, async () => ["apple", "google"]);
    expect(await two.ext.send({ type: "plan_context", context: body([]) }, two.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(two.chainCalls).toEqual([]);
    const forms = await bg(nothing, (r) => (r.op === "list_for_origin" ? { items: [via(A, "apple")] } : undefined),
      undefined, async () => null);
    expect(await forms.ext.send({ type: "plan_context", context: body([]) }, forms.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(forms.chainCalls).toEqual([]);
  });
});

describe("passkeys after a gesture-started plan", () => {
  const nothing = () => plan({ intent: "ignore" as PlanOut["intent"], action: "nothing", confidence: "low" });
  const pk = (item: string, cred: string) => ({ item_id: item, vault_id: "v1", vault_name: "Personnel", title: "Atlas", user_name: "alex", credential_id: cred });
  const armed = (t: Awaited<ReturnType<typeof bg>>) => (t.b.passkeys as unknown as { armedGet: Map<number, { itemId: string; documentId?: string; origin: string }> }).armedGet.get(7);

  it("a page with no form, one account's passkey for the site, and a passkey button: the gesture presses it and that item signs", async () => {
    const t = await bg(nothing, (r) => (r.op === "passkey_list" ? { passkeys: r.rp_id === "atlas-cloud.test" ? [pk(A, "c1")] : [] } : undefined));
    t.ext.tabReply = (_tab, m) => ((m as { type: string }).type === "click_passkey_signin" ? { ok: true } : undefined);
    expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(t.toTab("click_passkey_signin")).toEqual([{ tabId: 7, message: { type: "click_passkey_signin", origin: SITE }, options: { documentId: "doc-1" } }]);
    expect(armed(t)).toMatchObject({ itemId: A, origin: SITE, documentId: "doc-1" });
  });

  it("no passkey, passkeys of two accounts, no button to press, an icon click or a page with a form: nothing pressed, nothing armed", async () => {
    // None.
    let t = await bg(nothing, (r) => (r.op === "passkey_list" ? { passkeys: [] } : undefined));
    expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(t.toTab("click_passkey_signin")).toEqual([]);
    // Two accounts: the user picks in the window.
    t = await bg(nothing, (r) => (r.op === "passkey_list" ? { passkeys: [pk(A, "c1"), pk(B, "c2")] } : undefined));
    expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(t.toTab("click_passkey_signin")).toEqual([]);
    expect(armed(t)).toBeUndefined();
    // The page has no button that reads as a passkey sign-in: disarmed.
    t = await bg(nothing, (r) => (r.op === "passkey_list" ? { passkeys: [pk(A, "c1")] } : undefined));
    t.ext.tabReply = () => ({ ok: false });
    expect(await t.ext.send({ type: "plan_context", context: body([]), bare: true }, t.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(armed(t)).toBeUndefined();
    // A page with a form.
    t = await bg(nothing, (r) => (r.op === "passkey_list" ? { passkeys: [pk(A, "c1")] } : undefined));
    expect(await t.ext.send({ type: "plan_context", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "nothing" } });
    expect(t.ops()).not.toContain("passkey_list");
  });

  it("a plan that filled a login without sending it arms that item for the page's passkey step", async () => {
    const t = await bg(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup(A)] }));
    expect(await t.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, t.top)).toEqual({ ok: { outcome: "filled" } });
    expect(armed(t)).toMatchObject({ itemId: A, documentId: "doc-1" });
    // A menu outcome chose nobody: nothing armed.
    const u = await bg(() => plan({ action: "show_menu", confidence: "low", groups: [loginGroup(B)], alternatives: [A] }));
    await u.ext.send({ type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: body(LOGIN_FORM) }, u.top);
    expect(armed(u)).toBeUndefined();
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

  it("the sign-in line for a high fill_and_submit too: one click signs in through the same chain", async () => {
    const t = await bg(() => plan({ action: "fill_and_submit", groups: [loginGroup(B, "f1", ["email"])], reasons: ["sole_exact_host"] }));
    t.ext.activeTab = { id: 7, url: `${SITE}/login` };
    replyContext(t, [form("f1", ["email"])]);
    const r = (await t.ext.send({ type: "popup_suggestions" }, uiSender("popup.html"))) as { ok: { plan: unknown } };
    expect(r.ok.plan).toEqual({ intent: "login", label: "bo@atlas.dev", steps: 2, mode: "chain" });
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

  it("the command and the popup's Fill go to the child frame of the top frame's origin that holds the sign-in form", async () => {
    const ext = new FakeExt();
    const pairings = new MemoryPairingStore();
    await new Store(ext, pairings).setPairing(record());
    const client = new FakeClient(() => ({}));
    const b = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined });
    b.install();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    ext.setFrame(7, 4, `${SITE}/frame`, "doc-4");
    const analysis = (forms: unknown[]) => ({ url: `${SITE}/login`, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] });
    await ext.send({ type: "page_analysis", analysis: analysis([]) }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    await ext.send({ type: "page_analysis", analysis: analysis([{ ref: "f1", kind: "login", fields: [{ ref: "u1", role: "username" }, { ref: "p1", role: "current_password" }] }]) }, csSender(`${SITE}/frame`, 7, 4, { documentId: "doc-4" }));
    ext.activeTab = { id: 7, url: `${SITE}/login` };
    ext.onCommand.emit(FILL_SMART_COMMAND);
    await new Promise((r) => setTimeout(r, 0));
    await b.runner?.state(7);
    await new Promise((r) => setTimeout(r, 0));
    expect(ext.sentToTabs.filter((m) => (m.message as { type: string }).type === "smart_fill")).toEqual([{ tabId: 7, message: { type: "smart_fill" }, options: { documentId: "doc-4" } }]);
  });

  it("the command reaches any form of a child frame of the top frame's origin when the top frame has none (an identity form), never another origin's", async () => {
    const make = async (frameUrl: string) => {
      const ext = new FakeExt();
      const pairings = new MemoryPairingStore();
      await new Store(ext, pairings).setPairing(record());
      const b = createBackground(ext, { pairings, newClient: () => new FakeClient(() => ({})), sleep: async () => undefined });
      b.install();
      ext.setFrame(7, 0, `${SITE}/apply`, "doc-1");
      ext.setFrame(7, 4, frameUrl, "doc-4");
      const analysis = (forms: unknown[]) => ({ url: `${SITE}/apply`, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] });
      await ext.send({ type: "page_analysis", analysis: analysis([]) }, csSender(`${SITE}/apply`, 7, 0, { documentId: "doc-1" }));
      await ext.send({ type: "page_analysis", analysis: analysis([{ ref: "f1", kind: "identity", fields: [{ ref: "g1", role: "given_name" }, { ref: "n1", role: "family_name" }] }]) }, csSender(frameUrl, 7, 4, { documentId: "doc-4" }));
      ext.activeTab = { id: 7, url: `${SITE}/apply` };
      ext.onCommand.emit(FILL_SMART_COMMAND);
      await new Promise((r) => setTimeout(r, 0));
      await b.runner?.state(7);
      await new Promise((r) => setTimeout(r, 0));
      return ext.sentToTabs.filter((m) => (m.message as { type: string }).type === "smart_fill").map((m) => m.options);
    };
    expect(await make(`${SITE}/frame`)).toEqual([{ documentId: "doc-4" }]);
    expect(await make("https://forms.atlas-cloud.test/frame")).toEqual([{ documentId: "doc-1" }]);
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

