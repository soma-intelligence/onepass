import { describe, expect, it } from "vitest";
import { SaveFlow } from "../../src/background/chain/save-flow";
import type { FillTarget } from "../../src/background/fill";
import { FormGenerator } from "../../src/background/generate";
import { SUGGESTION_TTL_MS, Suggestions, strengthOf } from "../../src/background/suggest";
import type { FormKind } from "../../src/shared/messages";
import { GENERATOR_PROFILE_KEY } from "../../src/shared/ui";
import { type Answer, FakeClient } from "./fake-client";
import { FakeExt } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

const login = (id: string) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Perso",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#3355ff",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
});

function setup(opts: { logins?: string[] } = {}) {
  const ext = new FakeExt();
  let n = 0;
  const answer: Answer = (r) => {
    switch (r.op) {
      case "generate": {
        n++;
        const recipe = r.recipe as { length?: number };
        // A distinct password per draw; a custom profile's length is honoured.
        const base = `Gen-${n}-Pass-xyz!`;
        const password = recipe.length !== undefined ? base.padEnd(recipe.length, "a").slice(0, recipe.length) : base;
        return { password, entropy_bits: 90, report: { length: password.length, weak_by_site: false, entropy_bits: 90 } };
      }
      case "list_for_origin":
        return { items: (opts.logins ?? []).map(login) };
      case "vaults":
        return { vaults: [{ id: "v1", name: "Perso", color: null }] };
      case "save_login":
        return { item_id: "it_new" };
      default:
        return {};
    }
  };
  const client = new FakeClient(answer);
  client.open_ = true;
  const generator = new FormGenerator({ tabs: ext.tabs, session: client, area: ext.local });
  const saveFlow = new SaveFlow({
    session: client,
    saves: { open: async () => "tok" },
    neverSave: { has: async () => false },
    topFrame: async () => ({ url: `${SITE}/signup`, documentId: "doc-1" }),
  });
  const fills: { t: FillTarget; password: string }[] = [];
  const filler = {
    fillGenerated: async (t: FillTarget, password: string) => {
      fills.push({ t, password });
      return 2;
    },
  };
  let now = 1_000_000;
  const s = new Suggestions({ generator, filler, saveFlow, area: ext.local, now: () => now });
  return { ext, client, saveFlow, fills, s, advance: (ms: number) => (now += ms) };
}

const target = (formRef = "f1"): FillTarget => ({ tabId: 7, frameId: 0, origin: SITE, formRef, documentId: "doc-1" });
const rec = (formKind: FormKind = "signup", fieldRef = "e1") => ({ tabId: 7, frameId: 0, origin: SITE, formKind, documentId: "doc-1", fieldRef });
const ghost = (tabId = 7) => ({ page: "ghost.html", tabId });
const menu = (tabId = 7) => ({ page: "menu.html", tabId });

describe("Suggestions", () => {
  it("open holds one suggestion per field", async () => {
    const { s } = setup();
    const a = await s.open(target(), rec());
    const b = await s.open(target(), rec());
    expect(a?.token).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(b?.token).not.toBe(a?.token);
    expect(s.peek(a!.token, ghost())).toBeNull();
    expect(s.peek(b!.token, ghost())?.password).toBe("Gen-2-Pass-xyz!");
    // Another field of the same tab keeps its own.
    const c = await s.open(target(), rec("signup", "e2"));
    expect(s.peek(b!.token, ghost())).not.toBeNull();
    expect(s.peek(c!.token, menu())).not.toBeNull();
  });

  it("peek only for ghost or menu pages of the tab", async () => {
    const { s } = setup();
    const { token } = (await s.open(target(), rec()))!;
    expect(s.peek(token, { page: "save.html", tabId: 7 })).toBeNull();
    expect(s.peek(token, { page: "popup.html" })).toBeNull();
    expect(s.peek(token, ghost(8))).toBeNull();
    expect(s.peek(token, { page: "ghost.html" })).toBeNull();
    expect(s.peek(token, ghost())).toMatchObject({ password: "Gen-1-Pass-xyz!" });
    expect(s.peek(token, menu())).toMatchObject({ password: "Gen-1-Pass-xyz!" });
  });

  it("a suggestion expires", async () => {
    const { s, advance } = setup();
    const { token } = (await s.open(target(), rec()))!;
    advance(SUGGESTION_TTL_MS + 1);
    expect(s.peek(token, ghost())).toBeNull();
  });

  it("accept fills and saves pending on signup", async () => {
    const { s, fills, client } = setup();
    const { token } = (await s.open(target(), rec("signup")))!;
    await s.accept(token);
    expect(fills).toEqual([{ t: target(), password: "Gen-1-Pass-xyz!" }]);
    expect(client.requests.find((r) => r.op === "save_login")).toMatchObject({ origin: SITE, password: "Gen-1-Pass-xyz!", tags: ["onepass:pending"] });
    // Remembered for the submission (the save flow's own memory).
    expect((s as unknown as { held: Map<string, unknown> }).held.size).toBe(0);
    const before = client.requests.length;
    await s.accept(token);
    expect(fills).toHaveLength(1);
    expect(client.requests.length).toBe(before);
    expect(s.peek(token, ghost())).toBeNull();
  });

  it("accept on change-password writes a pending update", async () => {
    const { s, fills, client } = setup({ logins: ["it_01"] });
    const { token } = (await s.open(target(), rec("change_password")))!;
    await s.accept(token);
    expect(fills.map((f) => f.password)).toEqual(["Gen-1-Pass-xyz!"]);
    expect(client.requests.filter((r) => r.op === "save_login")).toEqual([]);
    expect(client.requests.find((r) => r.op === "update_password")).toEqual({
      op: "update_password",
      ctx: "save_prompt",
      item_id: "it_01",
      origin: SITE,
      password: "Gen-1-Pass-xyz!",
      weak_by_site: false,
      pending: true,
    });
  });

  it("change-password with several logins: the one filled in this tab, else remembered only", async () => {
    const one = setup({ logins: ["it_01", "it_02"] });
    const a = (await one.s.open(target(), rec("change_password")))!;
    await one.s.accept(a.token);
    expect(one.fills).toHaveLength(1);
    expect(one.client.requests.filter((r) => r.op === "update_password")).toEqual([]);

    const two = setup({ logins: ["it_01", "it_02"] });
    two.saveFlow.noteFilled(7, SITE, "login", "it_02");
    const b = (await two.s.open(target(), rec("change_password")))!;
    await two.s.accept(b.token);
    expect(two.client.requests.find((r) => r.op === "update_password")).toMatchObject({ item_id: "it_02", password: "Gen-1-Pass-xyz!" });
  });

  it("drop on navigation", async () => {
    const { s } = setup();
    const { token } = (await s.open(target(), rec()))!;
    const other = (await s.open({ ...target(), tabId: 8 }, { ...rec(), tabId: 8 }))!;
    s.drop(7);
    expect(s.peek(token, ghost())).toBeNull();
    expect(s.peek(other.token, ghost(8))).not.toBeNull();
    s.clear();
    expect(s.peek(other.token, ghost(8))).toBeNull();
  });

  it("regenerate draws a new password for the token", async () => {
    const { s } = setup();
    const { token } = (await s.open(target(), rec()))!;
    expect(await s.regenerate(token)).toBe(true);
    expect(s.peek(token, ghost())?.password).toBe("Gen-2-Pass-xyz!");
    expect(await s.regenerate("A".repeat(22))).toBe(false);
  });

  it("menu_profile writes the custom profile", async () => {
    const { s, ext, client } = setup();
    const { token } = (await s.open(target(), rec()))!;
    expect(await s.setProfile(token, 20, false)).toBe(true);
    expect(ext.local.data.get(GENERATOR_PROFILE_KEY)).toEqual({ kind: "custom", length: 20, symbols: false });
    const p = s.peek(token, menu());
    expect(p?.password).toHaveLength(20);
    expect(client.requests.filter((r) => r.op === "generate").at(-1)?.recipe).toMatchObject({ profile: "custom", length: 20, symbols: false });
  });

  it("storedProfile: the stored custom profile, else the popup defaults", async () => {
    const { s, ext } = setup();
    expect(await s.storedProfile()).toEqual({ length: 20, symbols: true });
    ext.local.data.set(GENERATOR_PROFILE_KEY, { kind: "custom", length: 12, symbols: false });
    expect(await s.storedProfile()).toEqual({ length: 12, symbols: false });
    ext.local.data.set(GENERATOR_PROFILE_KEY, { kind: "custom", length: 3, symbols: false });
    expect(await s.storedProfile()).toEqual({ length: 20, symbols: true });
  });

  it("the password never reaches a storage area", async () => {
    const { s, ext } = setup();
    const { token } = (await s.open(target(), rec()))!;
    await s.regenerate(token);
    const dump = JSON.stringify([...ext.local.data.entries(), ...ext.session.data.entries()]);
    expect(dump).not.toContain("Pass-xyz");
  });
});

describe("strengthOf", () => {
  it("maps the report's entropy to four segments", () => {
    expect(strengthOf({ entropy_bits: 30 } as never, "x")).toBe(1);
    expect(strengthOf({ entropy_bits: 50 } as never, "x")).toBe(2);
    expect(strengthOf({ entropy_bits: 70 } as never, "x")).toBe(3);
    expect(strengthOf({ entropy_bits: 110 } as never, "x")).toBe(4);
    expect(strengthOf(null, "")).toBe(0);
    // Without a report: estimated from the password's classes and length.
    expect(strengthOf(null, "Abcdefgh1234!xyzQ")).toBe(4);
    expect(strengthOf(null, "abcd")).toBe(1);
  });
});
