// Task 10 (smart fill) in the sign-in chain: the penalty after `repeat`, the
// note and the cleared penalty at `done`, and the replan of an unknown page.
// The driver runs as wired by createBackground (real ChainRunner and
// Planner) against a fake browser and host; the machine parts are pure.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createBackground } from "../src/background/app";
import type { ChainRunner } from "../src/background/chain/driver";
import { DEADLINE_MS, UNKNOWN_MS, noteShape, noteSteps, parseChainState, planStep, startChain, step, tick } from "../src/background/chain/machine";
import { penaltyKey } from "../src/background/penalty";
import { MemoryPairingStore, Store } from "../src/background/store";
import type { FieldRole, FormContext, FormInfo, PageAnalysis, PlanOut } from "../src/shared/messages";
import { type Answer, FakeClient, record } from "./background/fake-client";
import { FakeExt, csSender } from "./background/fake-ext";

const SITE = "https://atlas-cloud.test";
const PENALTY = penaltyKey("atlas-cloud.test");

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

const loginForm: FormInfo = {
  ref: "f1",
  kind: "login",
  fields: [
    { ref: "u1", role: "email" },
    { ref: "p1", role: "current_password" },
  ],
  submitRef: "b1",
};

const page = (url: string, forms: FormInfo[] = []): PageAnalysis => ({ url, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] });

function form(ref: string, roles: FieldRole[], buttons: FormContext["buttons"] = []): FormContext {
  return {
    form_ref: ref,
    intent_hints: { kind: null, signup_words: false, reset_words: false, checkout_words: false, ignore: false },
    step_index: null,
    fields: roles.map((role, i) => ({ field_ref: `${ref}e${i}`, role, confidence: 1, visible: true, prefilled: "empty" })),
    buttons,
  };
}

function plan(over: Partial<PlanOut>): PlanOut {
  return { intent: "login", groups: [], action: "fill", confidence: "high", alternatives: [], reasons: [], ...over };
}

const loginGroup = (item: string, formRef = "f1", roles: FieldRole[] = ["email", "current_password"]) => ({
  form_ref: formRef,
  kind: "login" as const,
  item_id: item,
  fields: roles.map((role, i) => ({ field_ref: `${formRef}e${i}`, role })),
});

async function setup(next: () => PlanOut = () => plan({}), over: Partial<Record<string, (r: Record<string, unknown>) => unknown>> = {}) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const clock = { t: 1_000_000 };
  const answer: Answer = (r) => {
    const o = over[r.op as string];
    if (o) return o(r);
    switch (r.op) {
      case "list_for_origin":
        return { items: [summary("it_01")] };
      case "fill_login":
        return { username: "alex@atlas.dev", password: "Atlas-Pass-1" };
      case "fill_salt":
        return { salt: "a".repeat(64) };
      case "plan_fill":
        return { plan: next() };
      default:
        return {};
    }
  };
  const client = new FakeClient(answer);
  const bg = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, now: () => clock.t });
  bg.install();
  return { ext, client, bg, runner: bg.runner as ChainRunner, clock };
}

type T = Awaited<ReturnType<typeof setup>>;

async function analyze(t: T, url: string, a: PageAnalysis, doc: string) {
  t.ext.setFrame(7, 0, url, doc);
  await t.ext.send({ type: "page_analysis", analysis: a }, csSender(url, 7, 0, { documentId: doc }));
  await t.runner.state(7);
}

const toTab = (t: T, type: string) =>
  t.ext.sentToTabs.filter((m) => (m.message as { type: string }).type === type).map((m) => ({ ...(m.message as object), opts: m.options }));
const notes = (t: T) => t.client.requests.filter((r) => r.op === "note_fill");

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("penalty", () => {
  it("repeat_sets_penalty_and_next_plan_is_medium", async () => {
    const t = await setup(() => plan({ action: "open_chain", groups: [loginGroup("it_01")] }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-1");
    await t.runner.start(7, "it_01");
    // The password is refused: the same sign-in page comes back.
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-2");
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "repeat" });
    expect(t.ext.session.data.get(PENALTY)).toEqual({ at: t.clock.t });
    expect(notes(t)).toEqual([]);

    // The next click on that site: the plan is Medium, the step is filled, nothing is sent nor chained.
    const submitsBefore = toTab(t, "submit").length;
    const r = await t.ext.send(
      { type: "plan_context", formRef: "f1", fieldRef: "f1e0", context: { forms: [form("f1", ["email", "current_password"])], typed_username_hash: null } },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-2" }),
    );
    expect(r).toEqual({ ok: { outcome: "filled" } });
    expect(toTab(t, "submit")).toHaveLength(submitsBefore);
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "repeat" });
    expect(t.client.requests.at(-1)).toEqual(expect.objectContaining({ op: "fill_login", ctx: "menu", item_id: "it_01" }));
  });

  it("done_clears_penalty_and_notes_fill", async () => {
    const t = await setup();
    await t.ext.session.set({ [PENALTY]: { at: 1 } });
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-1");
    await t.runner.start(7, "it_01", undefined, { planned: { roles: ["email", "current_password"], intent: "login" } });
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    t.clock.t += UNKNOWN_MS;
    expect((await t.runner.state(7))?.status).toBe("done");
    expect(t.ext.session.data.has(PENALTY)).toBe(false);
    expect(notes(t)).toEqual([
      { op: "note_fill", ctx: "chain", item_id: "it_01", origin: SITE, roles: ["email", "current_password"], intent: "login", steps: ["fill"] },
    ]);
    // Once: polling the ended chain notes nothing more.
    await t.runner.state(7);
    expect(notes(t)).toHaveLength(1);
  });

  it("a chain from the menu notes the roles of the form it filled; a note_fill failure leaves it done", async () => {
    const t = await setup(undefined, { note_fill: () => new Error("host gone") });
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-1");
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    t.clock.t += UNKNOWN_MS;
    expect((await t.runner.state(7))?.status).toBe("done");
    expect(notes(t)).toEqual([expect.objectContaining({ item_id: "it_01", roles: ["email", "current_password"], intent: "login", steps: ["fill"] })]);
  });
});

describe("note roles and one note per fill (fix round 1)", () => {
  it("a chain from the menu notes its form's visible roles as the page context gives them (mainRoles filter)", async () => {
    const t = await setup();
    t.ext.tabReply = (_tab, m) => {
      if ((m as { type: string }).type !== "plan_request") return undefined;
      const f = form("f1", ["email", "current_password", "unknown", "given_name"]);
      // A hidden field: out of the shape, as in the bridge's main_roles.
      (f.fields[3] as { visible: boolean }).visible = false;
      return { ok: true, context: { forms: [f], typed_username_hash: null } };
    };
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-1");
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    t.clock.t += UNKNOWN_MS;
    expect((await t.runner.state(7))?.status).toBe("done");
    expect(notes(t)).toEqual([expect.objectContaining({ roles: ["email", "current_password", "unknown"] })]);
  });

  it("a plan fill then a chain in the same tab: one note, the chain's", async () => {
    const t = await setup(() => plan({ action: "fill", confidence: "medium", groups: [loginGroup("it_01")] }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-1");
    await t.ext.send(
      { type: "plan_context", formRef: "f1", context: { forms: [form("f1", ["email", "current_password"])], typed_username_hash: null } },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    );
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    t.clock.t += UNKNOWN_MS;
    expect((await t.runner.state(7))?.status).toBe("done");
    await vi.runAllTimersAsync();
    expect(notes(t)).toEqual([expect.objectContaining({ ctx: "chain" })]);
  });
});

describe("unknown page", () => {
  it("unknown_step_replans: the plan's group of the chain's item is filled and submitted", async () => {
    let planned = 0;
    const t = await setup(() => {
      planned++;
      return plan({ action: "open_chain", groups: [loginGroup("it_01", "f7", ["username"])] });
    });
    // The chain's page has a field the chain does not recognize.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`), "doc-1");
    t.ext.tabReply = (_tab, m) =>
      (m as { type: string }).type === "plan_request"
        ? { ok: true, context: { forms: [form("f7", ["username"], [{ button_ref: "b7", class: "next" }])], typed_username_hash: null } }
        : undefined;
    await t.runner.start(7, "it_01");
    expect(t.client.requests.map((r) => r.op)).not.toContain("plan_fill");
    t.clock.t += UNKNOWN_MS;
    const v = await t.runner.state(7);
    expect(planned).toBe(1);
    expect(v?.status).toBe("running");
    expect(toTab(t, "plan_request")).toEqual([expect.objectContaining({ opts: { documentId: "doc-1" } })]);
    expect(t.client.requests.find((r) => r.op === "fill_login")).toEqual({ op: "fill_login", ctx: "chain", item_id: "it_01", origin: SITE, fields: ["username"] });
    expect(toTab(t, "submit")).toEqual([{ type: "submit", origin: SITE, ref: "f7", planned: true, opts: { documentId: "doc-1" } }]);
  });

  it("a replan with no group of the chain's item stops the chain (unknown)", async () => {
    const t = await setup(() => plan({ action: "show_menu", confidence: "low", groups: [loginGroup("it_99")] }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`), "doc-1");
    t.ext.tabReply = (_tab, m) =>
      (m as { type: string }).type === "plan_request" ? { ok: true, context: { forms: [form("f7", ["username"])], typed_username_hash: null } } : undefined;
    await t.runner.start(7, "it_01");
    t.clock.t += UNKNOWN_MS;
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "unknown" });
    expect(t.client.requests.map((r) => r.op)).not.toContain("fill_login");
  });

  it("no content script answer: unknown, no plan", async () => {
    const t = await setup(() => plan({ action: "open_chain", groups: [loginGroup("it_01")] }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`), "doc-1");
    await t.runner.start(7, "it_01");
    t.clock.t += UNKNOWN_MS;
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "unknown" });
    expect(t.client.requests.map((r) => r.op)).not.toContain("plan_fill");
  });
});

describe("machine", () => {
  const T0 = 1_000;
  const item = summary("it_01");
  const s0 = () => startChain({ tabId: 7, item: item as never, siteOrigin: SITE, now: T0 });

  it("replans once per page, then unknown", () => {
    const r1 = tick(s0(), T0 + UNKNOWN_MS);
    expect(r1.actions).toEqual([{ type: "replan" }]);
    expect(r1.state.page.replanned).toBe(true);
    expect(tick(r1.state, T0 + UNKNOWN_MS + 1).actions).toEqual([]);
    expect(tick(r1.state, T0 + 2 * UNKNOWN_MS).actions).toEqual([{ type: "stop", reason: "unknown" }]);
  });

  it("planStep acts once per page and is a repeat when the page comes back", () => {
    const p = { formRef: "f7", roles: ["username"] as FieldRole[], submit: true };
    const r = planStep(s0(), p, `${SITE}/login`, SITE, T0 + 10);
    expect(r.actions).toEqual([
      { type: "fill", formRef: "f7", fields: ["username"], roles: ["username"] },
      { type: "submit", formRef: "f7", planned: true },
    ]);
    expect(planStep(r.state, p, `${SITE}/login`, SITE, T0 + 20).actions).toEqual([]);
    const back = { ...r.state, page: { ...r.state.page, nav: 1 } };
    expect(planStep(back, p, `${SITE}/login`, SITE, T0 + 30).actions).toEqual([{ type: "stop", reason: "repeat" }]);
    // Never on another site, never past the deadline, no submit when the plan may not.
    expect(planStep(s0(), p, "https://evil.test/login", "https://evil.test", T0 + 10).actions).toEqual([{ type: "stop", reason: "domain" }]);
    expect(planStep(s0(), p, `${SITE}/login`, SITE, T0 + DEADLINE_MS).actions).toEqual([{ type: "stop", reason: "timeout" }]);
    expect(planStep(s0(), { ...p, submit: false }, `${SITE}/login`, SITE, T0 + 10).actions).toEqual([
      { type: "fill", formRef: "f7", fields: ["username"], roles: ["username"] },
    ]);
  });

  it("a chain a plan started sends its submits as planned (click-time re-check, no re-rendered copy)", () => {
    const planned = startChain({ tabId: 7, item: item as never, siteOrigin: SITE, now: T0, planned: { roles: ["email", "current_password"], intent: "login" } });
    const r = step(planned, page(`${SITE}/login`, [loginForm]), SITE, T0 + 10);
    expect(r.actions.filter((a) => a.type === "submit")).toEqual([{ type: "submit", formRef: "f1", planned: true }]);
    // A chain from the menu or the overlay: as before.
    const plain = step(s0(), page(`${SITE}/login`, [loginForm]), SITE, T0 + 10);
    expect(plain.actions.filter((a) => a.type === "submit")).toEqual([{ type: "submit", formRef: "f1" }]);
  });

  it("note shape: planned roles first, else the first form filled; steps in order", () => {
    const planned = startChain({ tabId: 7, item: item as never, siteOrigin: SITE, now: T0, planned: { roles: ["username"], intent: "login" } });
    expect(noteShape(planned)).toEqual({ roles: ["username"], intent: "login" });
    const s = step(s0(), page(`${SITE}/login`, [loginForm]), SITE, T0 + 10).state;
    expect(noteShape(s)).toEqual({ roles: ["email", "current_password"], intent: "login" });
    expect(noteSteps(s)).toEqual(["fill"]);
    // Persisted and read back by a restarted worker.
    const back = parseChainState(JSON.parse(JSON.stringify({ ...planned, page: { ...planned.page, replanned: true } })));
    expect(back?.planned).toEqual({ roles: ["username"], intent: "login" });
    expect(back?.page.replanned).toBe(true);
    expect(parseChainState({ ...s, roles: ["a b"] })).toBeNull();
  });
});
