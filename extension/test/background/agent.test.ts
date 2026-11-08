// The agent channel (agent.ts): probe of the front window's active tab,
// fill of the probed document only, field names out, and the loop's own
// session that reconnects.
import { describe, expect, it, vi } from "vitest";
import { type FillJob, fillForAgent, probeActiveTab, startAgentLoop } from "../../src/background/agent";
import type { BgExt, WindowTab } from "../../src/background/ext";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { BridgeError } from "../../src/bridge/bytes";
import { type Answer, FakeClient, record } from "./fake-client";
import { FakeExt } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const PASSWORD = "pw-secret-1";
const CARD_NUMBER = "4242424242424242";

/** A FakeExt with a front window whose tabs are `tabs`. */
function withWindow(tabs: WindowTab[]): FakeExt & Pick<BgExt, "windows"> {
  const ext = new FakeExt() as FakeExt & Pick<BgExt, "windows">;
  ext.windows = { getLastFocused: async () => ({ id: 1, tabs: tabs.map((t) => ({ ...t })) }) };
  return ext;
}

const loginForm = {
  form_ref: "f1",
  intent_hints: { kind: "login", signup_words: false, reset_words: false, checkout_words: false, ignore: false },
  step_index: null,
  fields: [
    { field_ref: "u", role: "username", confidence: 0.9, visible: true, prefilled: "empty" },
    { field_ref: "p", role: "current_password", confidence: 0.9, visible: true, prefilled: "empty" },
  ],
  buttons: [{ button_ref: "b", class: "submit" }],
};

const cardForm = {
  form_ref: "c1",
  intent_hints: { kind: "card", signup_words: false, reset_words: false, checkout_words: true, ignore: false },
  step_index: null,
  fields: [
    { field_ref: "n", role: "cc_number", confidence: 0.9, visible: true, prefilled: "empty" },
    { field_ref: "e", role: "cc_exp", confidence: 0.9, visible: true, prefilled: "empty" },
  ],
  buttons: [{ button_ref: "b", class: "pay" }],
};

const plans: Answer = (r) => {
  if (r.op === "plan_fill") {
    const card = (r.context as { forms: { form_ref: string }[] }).forms.some((f) => f.form_ref === "c1");
    return {
      plan: {
        intent: card ? "checkout" : "login",
        action: "fill",
        confidence: "high",
        alternatives: [],
        reasons: [],
        groups: card
          ? [{ form_ref: "c1", kind: "card", item_id: "plan-pick", fields: [{ field_ref: "n", role: "cc_number" }, { field_ref: "e", role: "cc_exp" }] }]
          : [{ form_ref: "f1", kind: "login", item_id: "plan-pick", fields: [{ field_ref: "u", role: "username" }, { field_ref: "p", role: "current_password" }] }],
      },
    };
  }
  if (r.op === "fill_login") return { username: "alex@atlas.dev", password: PASSWORD };
  if (r.op === "fill_card") return { cardholder: "Alex Martin", number: CARD_NUMBER, exp_month: "04", exp_year: "2029", cvv: "123" };
  return {};
};

/** The page of tab 7: `top` forms in its top frame; replies to fill and submit like the content script. */
function page(ext: FakeExt, top: unknown[], child?: { frameId: number; forms: unknown[] }): void {
  ext.tabReply = (_tab, message, options) => {
    const m = message as { type: string; values?: Record<string, string> };
    if (m.type === "plan_request") {
      const forms = options.frameId === child?.frameId && child ? child.forms : options.documentId === "doc-1" ? top : [];
      return { ok: true, context: { forms, typed_username_hash: null } };
    }
    if (m.type === "fill") return { ok: true, filled: Object.keys(m.values ?? {}) };
    if (m.type === "submit") return { ok: true };
    return undefined;
  };
}

async function openClient(answer: Answer): Promise<FakeClient> {
  const c = new FakeClient(answer);
  await c.open(record());
  return c;
}

const loginJob = (over: Partial<FillJob> = {}): FillJob => ({
  job: "fill",
  request_id: 7,
  item_id: "job-item",
  kind: "login",
  submit: false,
  document_id: "doc-1",
  ...over,
});

describe("agent probe", () => {
  it("reports the active tab of the front window", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    expect(await probeActiveTab(ext, `${SITE}/login`)).toEqual({ tab_title: "Atlas Cloud", origin: SITE, document_id: "doc-1" });
  });

  it("probe refuses a background tab", async () => {
    const ext = withWindow([
      { id: 7, active: false, title: "Atlas Cloud" },
      { id: 8, active: true, title: "News" },
    ]);
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    ext.setFrame(8, 0, "https://news.test/", "doc-8");
    expect(await probeActiveTab(ext, `${SITE}/login`)).toBe("tab_mismatch");
  });

  it("probe refuses another site", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, "https://atlas-cloud.evil.test/login", "doc-1");
    expect(await probeActiveTab(ext, `${SITE}/login`)).toBe("tab_mismatch");
  });

  it("probe refuses http", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, "http://atlas-cloud.test/login", "doc-1");
    expect(await probeActiveTab(ext, `${SITE}/login`)).toBe("tab_mismatch");
    // An http URL from the job is refused as well.
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    expect(await probeActiveTab(ext, "http://atlas-cloud.test/login")).toBe("tab_mismatch");
  });

  it("refuses a top frame without a document id", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, `${SITE}/login`);
    expect(await probeActiveTab(ext, `${SITE}/login`)).toBe("tab_mismatch");
  });
});

describe("agent fill", () => {
  it("fill refuses when documentId changed since the probe", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
    page(ext, [loginForm]);
    const client = await openClient(plans);
    expect(await fillForAgent({ ext, client }, loginJob())).toBe("tab_mismatch");
    expect(client.requests).toEqual([]);
    expect(ext.sentToTabs).toEqual([]);
  });

  it("refuses another tab than the probed one", async () => {
    const ext = withWindow([{ id: 9, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(9, 0, `${SITE}/login`, "doc-1");
    page(ext, [loginForm]);
    const client = await openClient(plans);
    const probes = new Map([[7, { tabId: 7, origin: SITE, documentId: "doc-1" }]]);
    expect(await fillForAgent({ ext, client, probes }, loginJob())).toBe("tab_mismatch");
    expect(client.requests).toEqual([]);
  });

  it("fill refuses a cross-site child frame", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Shop" }]);
    ext.setFrame(7, 0, `${SITE}/checkout`, "doc-1");
    ext.setFrame(7, 3, "https://js.payments.test/elements");
    page(ext, [], { frameId: 3, forms: [cardForm] });
    const client = await openClient(plans);
    expect(await fillForAgent({ ext, client }, loginJob({ kind: "card" }))).toBe("cross_site_frame");
    expect(client.requests.some((r) => r.op === "fill_card")).toBe(false);
    expect(ext.sentToTabs.some((s) => (s.message as { type: string }).type === "fill")).toBe(false);
  });

  it("refuses a same-site child frame too (top frame only)", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas" }]);
    ext.setFrame(7, 0, `${SITE}/`, "doc-1");
    ext.setFrame(7, 2, "https://login.atlas-cloud.test/frame");
    page(ext, [], { frameId: 2, forms: [loginForm] });
    const client = await openClient(plans);
    expect(await fillForAgent({ ext, client }, loginJob())).toBe("cross_site_frame");
    expect(ext.sentToTabs.some((s) => (s.message as { type: string }).type === "fill")).toBe(false);
  });

  it("answers no_fields when the page has no form of the kind", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas" }]);
    ext.setFrame(7, 0, `${SITE}/`, "doc-1");
    page(ext, [cardForm]);
    const client = await openClient(plans);
    expect(await fillForAgent({ ext, client }, loginJob())).toBe("no_fields");
  });

  it("fill reports field names, never values", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    page(ext, [loginForm]);
    const client = await openClient(plans);
    const r = await fillForAgent({ ext, client }, loginJob({ submit: true }));
    expect(r).toEqual({ filled: ["username", "current_password"], submitted: true });
    expect(JSON.stringify(r)).not.toContain(PASSWORD);
    expect(JSON.stringify(r)).not.toContain("alex@atlas.dev");
    // Planned without a typed-username hash, filled with the job's item, ctx agent and the request id.
    const plan = client.requests.find((q) => q.op === "plan_fill");
    expect(plan).toMatchObject({ ctx: "agent", agent_request: 7, origin: SITE, context: { origin: SITE, top_origin: SITE, frame_kind: "top", typed_username_hash: null } });
    expect(client.requests.find((q) => q.op === "fill_login")).toEqual({
      op: "fill_login",
      ctx: "agent",
      agent_request: 7,
      item_id: "job-item",
      origin: SITE,
      fields: ["username", "password"],
    });
    expect(client.requests.some((q) => q.op === "fill_salt")).toBe(false);
    // The values went to the top frame's document only.
    const fill = ext.sentToTabs.find((s) => (s.message as { type: string }).type === "fill");
    expect(fill?.options).toEqual({ documentId: "doc-1" });
  });

  it("card job never clicks submit", async () => {
    const ext = withWindow([{ id: 7, active: true, title: "Shop" }]);
    ext.setFrame(7, 0, `${SITE}/checkout`, "doc-1");
    page(ext, [cardForm]);
    const client = await openClient(plans);
    const r = await fillForAgent({ ext, client }, loginJob({ kind: "card", submit: true }));
    expect(r).toEqual({ filled: ["cc_number", "cc_exp"], submitted: false });
    expect(JSON.stringify(r)).not.toContain(CARD_NUMBER);
    expect(client.requests.find((q) => q.op === "fill_card")).toMatchObject({ ctx: "agent", agent_request: 7, item_id: "job-item" });
    expect(ext.sentToTabs.some((s) => (s.message as { type: string }).type === "submit")).toBe(false);
  });
});

describe("agent loop", () => {
  async function storeWith() {
    const ext = withWindow([{ id: 7, active: true, title: "Atlas Cloud" }]);
    const store = new Store(ext, new MemoryPairingStore());
    await store.setPairing(record());
    return { ext, store };
  }

  it("loop reconnects after the port closes", async () => {
    const { ext, store } = await storeWith();
    const clients: FakeClient[] = [];
    const sleeps: number[] = [];
    const newClient = () => {
      const n = clients.length;
      const c = new FakeClient((r) => {
        if (r.op !== "agent_wait") return {};
        // The first port dies under its poll; the second one waits.
        if (n === 0) return new BridgeError("closed");
        return new Promise(() => undefined);
      });
      clients.push(c);
      return c;
    };
    const loop = startAgentLoop({ ext, store, newClient, sleep: async (ms) => void sleeps.push(ms) });
    await vi.waitFor(() => expect(clients[1]?.requests.some((r) => r.op === "agent_wait")).toBe(true));
    expect(clients[0]?.closed).toBe(true);
    expect(sleeps).toEqual([1000]);
    loop.stop();
    expect(clients[1]?.closed).toBe(true);
  });

  it("answers a probe job on its own session", async () => {
    const { ext, store } = await storeWith();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    let polls = 0;
    const c = new FakeClient((r) => {
      if (r.op !== "agent_wait") return {};
      polls++;
      if (polls === 1) return { job: { job: "probe", request_id: 5, url: `${SITE}/login` } };
      return new Promise(() => undefined);
    });
    const loop = startAgentLoop({ ext, store, newClient: () => c });
    await vi.waitFor(() => expect(c.requests.some((r) => r.op === "agent_probe_result")).toBe(true));
    expect(c.requests.find((r) => r.op === "agent_probe_result")).toEqual({
      op: "agent_probe_result",
      request_id: 5,
      result: { ok: { tab_title: "Atlas Cloud", origin: SITE, document_id: "doc-1" } },
    });
    loop.stop();
  });

  it("does not start without a pairing, and stops when the pairing goes", async () => {
    const ext = withWindow([]);
    const store = new Store(ext, new MemoryPairingStore());
    const made: FakeClient[] = [];
    const loop = startAgentLoop({ ext, store, newClient: () => {
      const c = new FakeClient((r) => (r.op === "agent_wait" ? { job: null } : {}));
      made.push(c);
      return c;
    } });
    await new Promise((r) => setTimeout(r, 10));
    expect(made).toEqual([]);
    loop.stop();

    await store.setPairing(record());
    let polls = 0;
    const c = new FakeClient((r) => {
      if (r.op !== "agent_wait") return {};
      polls++;
      return polls === 1 ? store.clearPairing().then(() => ({ job: null })) : new Promise(() => undefined);
    });
    const loop2 = startAgentLoop({ ext, store, newClient: () => c });
    await vi.waitFor(() => expect(c.closed).toBe(true));
    expect(polls).toBe(1);
    loop2.stop();
  });
});
