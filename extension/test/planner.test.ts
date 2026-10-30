import { afterEach, describe, expect, it, vi } from "vitest";
import { createBackground } from "../src/background/app";
import { type FillTarget, Filler } from "../src/background/fill";
import { Frames } from "../src/background/frames";
import { Planner, framesFromSender, loginFieldsFor } from "../src/background/planner";
import { parseCsToBg } from "../src/background/router";
import { Session } from "../src/background/session";
import { MemoryPairingStore, Store } from "../src/background/store";
import type { FieldRole, FormContext, PageContext, PlanOut } from "../src/shared/messages";
import { type Answer, FakeClient, record } from "./background/fake-client";
import { FakeExt, csSender } from "./background/fake-ext";

const SITE = "https://atlas-cloud.test";
const ITEM = "0b6f1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4";
const CARD = "1c7a2d3e-4f5b-4c6d-9e7f-8091a2b3c4d5";
const IDENTITY = "2d8b3e4f-5a6c-4d7e-8f90-91a2b3c4d5e6";

const target = (over: Partial<FillTarget> = {}): FillTarget => ({
  tabId: 7,
  frameId: 0,
  origin: SITE,
  documentId: "doc-1",
  formRef: "f1",
  ...over,
});

function form(ref: string, roles: FieldRole[], buttons: FormContext["buttons"] = []): FormContext {
  return {
    form_ref: ref,
    intent_hints: { kind: null, signup_words: false, reset_words: false, checkout_words: false, ignore: false },
    step_index: null,
    fields: roles.map((role, i) => ({ field_ref: `${ref}e${i}`, role, confidence: 1, visible: true, prefilled: "empty" })),
    buttons,
  };
}

function context(forms: FormContext[]): PageContext {
  // Origins as a hostile content script would send them: the planner replaces them.
  return { origin: "https://evil.test", top_origin: "https://evil.test", frame_kind: "top", forms, typed_username_hash: null };
}

function plan(over: Partial<PlanOut>): PlanOut {
  return { intent: "login", groups: [], action: "fill", confidence: "high", alternatives: [], reasons: [], ...over };
}

const loginGroup = (formRef = "f1", item: string | null = ITEM) => ({
  form_ref: formRef,
  kind: "login" as const,
  item_id: item,
  fields: [
    { field_ref: `${formRef}e0`, role: "username" as const },
    { field_ref: `${formRef}e1`, role: "current_password" as const },
  ],
});

interface Calls {
  requests: Record<string, unknown>[];
  filler: unknown[][];
  chain: unknown[][];
  remembered: unknown[][];
}

/** Fake session, filler, chain and save flow; `answer` scripts the bridge. */
function fakes(answer: (r: Record<string, unknown>) => unknown, failLogin = false) {
  const calls: Calls = { requests: [], filler: [], chain: [], remembered: [] };
  const session = {
    request: async (r: Record<string, unknown>) => {
      calls.requests.push(r);
      return answer(r);
    },
  };
  const rec =
    (name: string) =>
    async (...a: unknown[]) => {
      calls.filler.push([name, ...a]);
      if (name === "fillLogin" && failLogin) throw new Error("boom");
      return 1;
    };
  const filler = {
    fillLogin: rec("fillLogin"),
    fillCard: rec("fillCard"),
    fillIdentity: rec("fillIdentity"),
    fillGenerated: rec("fillGenerated"),
    submit: rec("submit"),
  };
  const chain = {
    start: async (...a: unknown[]) => {
      calls.chain.push(a);
    },
  };
  const saveFlow = {
    rememberGenerated: (...a: unknown[]) => {
      calls.remembered.push(a);
    },
  };
  const planner = new Planner(session as never, filler as never, chain as never, saveFlow as never);
  return { planner, calls };
}

/** Plan `p` for `ctx` through the fake bridge, then run it. */
async function planAndRun(p: PlanOut, ctx: PageContext, t: FillTarget = target()) {
  const f = fakes((r) => (r.op === "plan_fill" ? { plan: p } : r.op === "generate" ? { password: "Gen-Secret-42!", entropy_bits: 90 } : {}));
  const got = await f.planner.plan(t, ctx);
  const outcome = await f.planner.run(t, got);
  return { ...f, outcome, got };
}

describe("planner", () => {
  it("open_chain_starts_chain_with_plan_item", async () => {
    const { calls, outcome } = await planAndRun(
      plan({ action: "open_chain", groups: [loginGroup()] }),
      context([form("f1", ["username", "current_password"], [{ button_ref: "b1", class: "submit" }])]),
    );
    expect(outcome).toBe("chain");
    // The plan's main form roles and intent go with it (note_fill at done).
    expect(calls.chain).toEqual([[7, ITEM, undefined, { planned: { roles: ["username", "current_password"], intent: "login" } }]]);
    expect(calls.filler).toEqual([]);
    // The request carries the background's origins, never the content script's.
    expect(calls.requests[0]).toEqual({
      op: "plan_fill",
      ctx: "menu",
      origin: SITE,
      context: expect.objectContaining({ origin: SITE, top_origin: SITE, frame_kind: "top" }),
    });
  });

  it("fill_groups_in_order", async () => {
    const ctx = context([
      form("f1", ["cc_name", "cc_number", "cc_exp", "cc_csc", "given_name", "email"], [{ button_ref: "b1", class: "other" }]),
    ]);
    const { calls, outcome } = await planAndRun(
      plan({
        intent: "signup",
        action: "fill",
        groups: [
          { form_ref: "f1", kind: "identity", item_id: IDENTITY, fields: [{ field_ref: "f1e4", role: "given_name" }, { field_ref: "f1e5", role: "email" }] },
          { form_ref: "f1", kind: "card", item_id: CARD, fields: [{ field_ref: "f1e1", role: "cc_number" }] },
          { form_ref: "f1", kind: "generated_password", item_id: null, fields: [{ field_ref: "f1e9", role: "new_password" }] },
        ],
      }),
      ctx,
    );
    expect(outcome).toBe("filled");
    expect(calls.filler.map((c) => c[0])).toEqual(["fillIdentity", "fillCard", "fillGenerated"]);
    expect(calls.filler[0]).toEqual(["fillIdentity", { ...target(), formRef: "f1" }, IDENTITY, "menu", ["given_name", "email"]]);
    expect(calls.filler[1]).toEqual(["fillCard", { ...target(), formRef: "f1" }, CARD, "menu", ["cc_number"]]);
    expect(calls.filler[2]).toEqual(["fillGenerated", { ...target(), formRef: "f1" }, "Gen-Secret-42!", ["new_password"]]);
  });

  it("checkout_never_submits", async () => {
    const { calls, outcome } = await planAndRun(
      plan({
        intent: "checkout",
        action: "fill_and_submit",
        groups: [{ form_ref: "f1", kind: "card", item_id: CARD, fields: [{ field_ref: "f1e0", role: "cc_number" }] }],
      }),
      context([form("f1", ["cc_number"], [{ button_ref: "b1", class: "submit" }])]),
    );
    expect(outcome).toBe("filled");
    expect(calls.filler.map((c) => c[0])).toEqual(["fillCard"]);
    expect(calls.chain).toEqual([]);
  });

  it("child_frame_open_chain_downgraded_to_fill", async () => {
    const t = target({ frameId: 3, sameOriginAsTop: true });
    const { calls, outcome } = await planAndRun(
      plan({ action: "open_chain", groups: [loginGroup()] }),
      context([form("f1", ["username", "current_password"], [{ button_ref: "b1", class: "submit" }])]),
      t,
    );
    expect(outcome).toBe("filled");
    expect(calls.chain).toEqual([]);
    expect(calls.filler).toEqual([["fillLogin", t, ITEM, ["username", "password"], "menu", ["username", "current_password"]]]);
    expect(calls.requests[0]?.context).toEqual(expect.objectContaining({ origin: SITE, top_origin: SITE, frame_kind: "same_origin_child" }));
  });

  it("pay_button_downgrades_submit", async () => {
    for (const cls of ["pay", "create"] as const) {
      const { calls, outcome } = await planAndRun(
        plan({ intent: "otp", action: "fill_and_submit", groups: [{ ...loginGroup(), fields: [{ field_ref: "f1e0", role: "otp" }] }] }),
        context([form("f1", ["otp"], [{ button_ref: "b1", class: "submit" }, { button_ref: "b2", class: cls }])]),
      );
      expect(outcome).toBe("filled");
      expect(calls.filler.map((c) => c[0])).toEqual(["fillLogin"]);
    }
    // Without such a button the same plan submits.
    const { calls } = await planAndRun(
      plan({ intent: "otp", action: "fill_and_submit", groups: [{ ...loginGroup(), fields: [{ field_ref: "f1e0", role: "otp" }] }] }),
      context([form("f1", ["otp"], [{ button_ref: "b1", class: "submit" }])]),
    );
    expect(calls.filler.map((c) => c[0])).toEqual(["fillLogin", "submit"]);
    expect(calls.filler[0]?.[3]).toEqual(["totp"]);
  });

  it("show_menu_returns_menu", async () => {
    const { calls, outcome } = await planAndRun(plan({ action: "show_menu", confidence: "low", alternatives: [ITEM, CARD] }), context([form("f1", ["username"])]));
    expect(outcome).toBe("menu");
    expect(calls.filler).toEqual([]);
    expect(calls.chain).toEqual([]);
    const n = await planAndRun(plan({ action: "nothing", intent: "ignore" }), context([form("f1", ["username"])]));
    expect(n.outcome).toBe("nothing");
  });

  it("generated_password_remembered_for_save", async () => {
    const { calls, outcome } = await planAndRun(
      plan({
        intent: "signup",
        groups: [{ form_ref: "f1", kind: "generated_password", item_id: null, fields: [{ field_ref: "f1e1", role: "new_password" }, { field_ref: "f1e2", role: "confirm_password" }] }],
      }),
      context([form("f1", ["email", "new_password", "confirm_password"])]),
    );
    expect(outcome).toBe("filled");
    expect(calls.requests.filter((r) => r.op === "generate")).toEqual([{ op: "generate", ctx: "menu", recipe: { kind: "smart" } }]);
    expect(calls.remembered).toEqual([[7, SITE, "Gen-Secret-42!"]]);
  });

  it("a plan the planner did not make never submits", async () => {
    const { planner, calls } = fakes(() => ({}));
    const outcome = await planner.run(target(), plan({ action: "fill_and_submit", groups: [loginGroup()] }));
    expect(outcome).toBe("filled");
    expect(calls.filler.map((c) => c[0])).toEqual(["fillLogin"]);
  });

  it("refuses a cross-origin child frame before asking the bridge", async () => {
    const { planner, calls } = fakes(() => ({}));
    await expect(planner.plan(target({ frameId: 2 }), context([]))).rejects.toMatchObject({ code: "cross_site_frame" });
    expect(calls.requests).toEqual([]);
  });

  it("maps planned login roles to the fields fill_login fetches", () => {
    expect(loginFieldsFor(["email", "username", "current_password"])).toEqual(["username", "password"]);
    expect(loginFieldsFor(["otp"])).toEqual(["totp"]);
    expect(loginFieldsFor(["given_name"])).toEqual([]);
  });
});

describe("planner fix round 1", () => {
  const otpPlan = () => plan({ intent: "otp", action: "fill_and_submit", groups: [{ ...loginGroup(), fields: [{ field_ref: "f1e0", role: "otp" }] }] });
  const otpCtx = () => context([form("f1", ["otp"], [{ button_ref: "b1", class: "submit" }])]);

  it("an otp plan whose code got no value never submits", async () => {
    const ext = new FakeExt();
    ext.setFrame(7, 0, `${SITE}/otp`, "doc-1");
    const store = new Store(ext, new MemoryPairingStore());
    await store.setPairing(record());
    const client = new FakeClient((r) => (r.op === "plan_fill" ? { plan: otpPlan() } : r.op === "fill_login" ? {} : {}));
    const session = new Session({ store, newClient: () => client });
    const planner = new Planner(session, new Filler(ext.tabs, new Frames(ext.webNavigation), session), { start: async () => undefined } as never, { rememberGenerated: () => undefined } as never);
    const outcome = await planner.run(target(), await planner.plan(target(), otpCtx()));
    expect(outcome).toBe("filled");
    expect(ext.sentToTabs).toEqual([]);
  });

  it("a generated password in the page is remembered even when a later group fails", async () => {
    const f = fakes((r) => (r.op === "plan_fill" ? { plan: p } : r.op === "generate" ? { password: "Gen-Secret-42!", entropy_bits: 90 } : {}), true);
    const p = plan({
      intent: "signup",
      groups: [
        { form_ref: "f1", kind: "generated_password", item_id: null, fields: [{ field_ref: "f1e1", role: "new_password" }] },
        loginGroup(),
      ],
    });
    const got = await f.planner.plan(target(), context([form("f1", ["username", "new_password"])]));
    await expect(f.planner.run(target(), got)).rejects.toThrow();
    expect(f.calls.remembered).toEqual([[7, SITE, "Gen-Secret-42!"]]);
  });

  it("only a high-confidence single-form plan submits or opens the chain", async () => {
    const one = context([form("f1", ["username", "current_password"]), form("f2", ["username", "current_password"])]);
    const medium = await planAndRun(plan({ action: "open_chain", confidence: "medium", groups: [loginGroup()] }), one);
    expect(medium.outcome).toBe("filled");
    expect(medium.calls.chain).toEqual([]);
    const two = await planAndRun(plan({ action: "fill_and_submit", groups: [loginGroup("f1"), loginGroup("f2")] }), one);
    expect(two.outcome).toBe("filled");
    expect(two.calls.filler.map((c) => c[0])).toEqual(["fillLogin", "fillLogin"]);
    const chain2 = await planAndRun(plan({ action: "open_chain", groups: [loginGroup("f1"), loginGroup("f2")] }), one);
    expect(chain2.calls.chain).toEqual([]);
  });

  it("a plan runs only in the frame and document it was made for", async () => {
    const f = fakes((r) => (r.op === "plan_fill" ? { plan: plan({ action: "fill", groups: [loginGroup()] }) } : {}));
    const got = await f.planner.plan(target(), context([form("f1", ["username", "current_password"])]));
    for (const other of [{ tabId: 8 }, { frameId: 2, sameOriginAsTop: true }, { origin: "https://other.test" }, { documentId: "doc-2" }]) {
      expect(await f.planner.run(target(other), got)).toBe("menu");
    }
    expect(f.calls.filler).toEqual([]);
  });
});

describe("framesFromSender", () => {
  it("top frame: its own top", () => {
    expect(framesFromSender({ frameId: 0, origin: SITE }, "https://other.test")).toEqual({ origin: SITE, top_origin: SITE, frame_kind: "top" });
  });

  it("same-origin child frame", () => {
    expect(framesFromSender({ frameId: 4, origin: SITE }, SITE)).toEqual({ origin: SITE, top_origin: SITE, frame_kind: "same_origin_child" });
  });

  it("cross-origin or unknown top: no plan", () => {
    expect(framesFromSender({ frameId: 4, origin: "https://pay.atlas-cloud.test" }, SITE)).toBeNull();
    expect(framesFromSender({ frameId: 4, origin: SITE }, null)).toBeNull();
  });
});

describe("fill salt", () => {
  async function session() {
    const ext = new FakeExt();
    const store = new Store(ext, new MemoryPairingStore());
    await store.setPairing(record());
    const clients: FakeClient[] = [];
    let n = 0;
    const answer: Answer = (r) => (r.op === "fill_salt" ? { salt: String(++n).repeat(64) } : {});
    const s = new Session({ store, newClient: () => {
      const c = new FakeClient(answer);
      clients.push(c);
      return c;
    }, sleep: async () => undefined });
    return { s, clients };
  }

  it("is fetched once per bridge session", async () => {
    const { s, clients } = await session();
    expect(await s.fillSalt()).toBe("1".repeat(64));
    expect(await s.fillSalt()).toBe("1".repeat(64));
    expect(clients[0]?.requests).toEqual([{ op: "fill_salt", ctx: "menu" }]);
  });

  it("is fetched again after a reconnect", async () => {
    const { s, clients } = await session();
    await s.fillSalt();
    clients[0]?.drop();
    expect(await s.fillSalt()).toBe("2".repeat(64));
    expect(clients[1]?.requests).toEqual([{ op: "fill_salt", ctx: "menu" }]);
  });
});

describe("plan_context message", () => {
  const good = {
    type: "plan_context",
    formRef: "f1",
    context: { ...context([form("f1", ["username", "current_password"], [{ button_ref: "b1", class: "submit" }])]), typed_username_hash: Array(32).fill(7) },
  };

  it("is rebuilt from validated fields, without the content script's origins", () => {
    const m = parseCsToBg({ ...good, evil: 1 });
    expect(m).toEqual({
      type: "plan_context",
      formRef: "f1",
      context: { forms: good.context.forms, typed_username_hash: Array(32).fill(7) },
    });
  });

  it("rejects malformed contexts", () => {
    const f = good.context.forms[0] as FormContext;
    const bad: unknown[] = [
      { ...good.context, forms: Array(33).fill(f) },
      { ...good.context, forms: [{ ...f, fields: Array(65).fill(f.fields[0]) }] },
      { ...good.context, forms: [{ ...f, buttons: Array(33).fill(f.buttons[0]) }] },
      { ...good.context, forms: [{ ...f, fields: [{ ...f.fields[0], confidence: 2 }] }] },
      { ...good.context, forms: [{ ...f, fields: [{ ...f.fields[0], role: "password" }] }] },
      { ...good.context, forms: [{ ...f, buttons: [{ button_ref: "b1", class: "buy" }] }] },
      { ...good.context, forms: [{ ...f, step_index: 256 }] },
      { ...good.context, forms: [{ ...f, form_ref: "a b" }] },
      { ...good.context, typed_username_hash: Array(31).fill(1) },
      { ...good.context, typed_username_hash: Array(32).fill(256) },
    ];
    for (const c of bad) expect(parseCsToBg({ ...good, context: c })).toBeNull();
    expect(parseCsToBg({ type: "fill_salt" })).toEqual({ type: "fill_salt" });
  });
});

describe("privacy", () => {
  const spies: ReturnType<typeof vi.spyOn>[] = [];
  afterEach(() => {
    for (const s of spies.splice(0)) s.mockRestore();
  });

  it("values_never_in_plan_logs", async () => {
    const SECRETS = ["alex@atlas.dev", "pw-Secret-1", "Gen-Secret-42!", "123456", "4242424242424242", "Alex"];
    const logged: unknown[] = [];
    for (const k of ["log", "info", "warn", "error", "debug", "trace", "dir", "table"] as const) {
      spies.push(vi.spyOn(console, k).mockImplementation((...a: unknown[]) => void logged.push(...a)));
    }
    const ext = new FakeExt();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    const store = new Store(ext, new MemoryPairingStore());
    await store.setPairing(record());
    let p: PlanOut = plan({});
    const client = new FakeClient((r) => {
      if (r.op === "plan_fill") return { plan: p };
      if (r.op === "fill_login") return { username: "alex@atlas.dev", password: "pw-Secret-1", totp: "123456" };
      if (r.op === "fill_card") return { cardholder: "Alex", number: "4242424242424242", exp_month: "04", exp_year: "2029" };
      if (r.op === "generate") return { password: "Gen-Secret-42!", entropy_bits: 90 };
      return {};
    });
    const session = new Session({ store, newClient: () => client });
    const filler = new Filler(ext.tabs, new Frames(ext.webNavigation), session);
    const remembered: string[] = [];
    const planner = new Planner(session, filler, { start: async () => undefined } as never, {
      rememberGenerated: (_t: number, _o: string, pw: string) => void remembered.push(pw),
    } as never);
    const ctx = context([form("f1", ["username", "current_password", "otp", "new_password", "cc_number"], [{ button_ref: "b1", class: "submit" }])]);
    const plans: PlanOut[] = [
      plan({ action: "fill_and_submit", groups: [{ ...loginGroup(), fields: [...loginGroup().fields, { field_ref: "f1e2", role: "otp" }] }] }),
      plan({ intent: "signup", groups: [{ form_ref: "f1", kind: "generated_password", item_id: null, fields: [{ field_ref: "f1e3", role: "new_password" }] }] }),
      plan({ intent: "checkout", groups: [{ form_ref: "f1", kind: "card", item_id: CARD, fields: [{ field_ref: "f1e4", role: "cc_number" }] }] }),
    ];
    const errors: string[] = [];
    for (const x of plans) {
      p = x;
      const got = await planner.plan(target(), ctx);
      await planner.run(target(), got);
    }
    // A failure on the way (the page moved) carries a code, never a value.
    ext.setFrame(7, 0, "https://elsewhere.test/", "doc-2");
    p = plans[0] as PlanOut;
    try {
      await planner.run(target(), await planner.plan(target(), ctx));
    } catch (e) {
      errors.push(String(e), JSON.stringify(e), (e as Error).stack ?? "");
    }
    expect(errors.length).toBeGreaterThan(0);
    expect(remembered).toEqual(["Gen-Secret-42!"]);
    // The values did reach the page (the fill path), and nowhere else.
    expect(JSON.stringify(ext.sentToTabs)).toContain("pw-Secret-1");
    const nonFill = client.requests.filter((r) => !String(r.op).startsWith("fill_"));
    const text = JSON.stringify([logged.map((x) => (x instanceof Error ? `${x.message} ${x.stack}` : x)), errors, nonFill]);
    for (const s of SECRETS) expect(text).not.toContain(s);
  });
});

describe("plan_context through the router", () => {
  async function bg() {
    const ext = new FakeExt();
    const pairings = new MemoryPairingStore();
    await new Store(ext, pairings).setPairing(record());
    const client = new FakeClient((r) => {
      if (r.op === "fill_salt") return { salt: "a".repeat(64) };
      if (r.op === "plan_fill") return { plan: plan({ action: "show_menu", confidence: "low" }) };
      return {};
    });
    const b = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined });
    b.install();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    return { ext, client };
  }
  const body = { type: "plan_context", formRef: "f1", context: context([form("f1", ["username"])]) };

  it("plans with the sender's origins and answers the outcome", async () => {
    const { ext, client } = await bg();
    const r = await ext.send(body, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    expect(r).toEqual({ ok: { outcome: "menu" } });
    expect(client.requests).toEqual([
      expect.objectContaining({ op: "plan_fill", origin: SITE, context: expect.objectContaining({ origin: SITE, top_origin: SITE, frame_kind: "top" }) }),
    ]);
  });

  it("a cross-origin child frame gets the menu without a plan, nor the salt", async () => {
    const { ext, client } = await bg();
    ext.setFrame(7, 3, "https://pay.atlas-cloud.test/card");
    const sender = csSender("https://pay.atlas-cloud.test/card", 7, 3);
    expect(await ext.send(body, sender)).toEqual({ ok: { outcome: "menu" } });
    expect(await ext.send({ type: "fill_salt" }, sender)).toEqual({ err: "cross_site_frame" });
    expect(client.requests).toEqual([]);
  });

  it("a same-origin child frame gets the salt and a child plan", async () => {
    const { ext, client } = await bg();
    ext.setFrame(7, 3, `${SITE}/frame`);
    const sender = csSender(`${SITE}/frame`, 7, 3);
    expect(await ext.send({ type: "fill_salt" }, sender)).toEqual({ ok: { salt: "a".repeat(64) } });
    await ext.send(body, sender);
    expect(client.requests[1]).toEqual(expect.objectContaining({ op: "plan_fill", context: expect.objectContaining({ frame_kind: "same_origin_child", top_origin: SITE }) }));
  });
});
