// Save flow (spec 8.5, 8.8): submitted credentials -> check -> prompt.
import { describe, expect, it } from "vitest";
import {
  CHECK_DELAY_MS,
  SUBMIT_TTL_MS,
  SaveFlow,
  type Timers,
  autoSubmitFor,
  setAutoSubmit,
} from "../../../src/background/chain/save-flow";
import type { CsContext } from "../../../src/background/frames";
import type { SavePending } from "../../../src/background/save";
import { FakeArea } from "../fake-ext";

const SITE = "https://atlas-cloud.test";

class FakeTimers implements Timers {
  t = 0;
  private seq = 0;
  private readonly due = new Map<number, { at: number; fn: () => void }>();
  setTimeout(fn: () => void, ms: number): unknown {
    const id = ++this.seq;
    this.due.set(id, { at: this.t + ms, fn });
    return id;
  }
  clearTimeout(id: unknown): void {
    this.due.delete(id as number);
  }
  async advance(ms: number): Promise<void> {
    this.t += ms;
    for (const [id, d] of [...this.due]) {
      if (d.at <= this.t) {
        this.due.delete(id);
        d.fn();
      }
    }
    for (let i = 0; i < 10; i++) await Promise.resolve();
  }
}

function setup(status: "new" | "same" | "update" = "new", never: string[] = []) {
  const timers = new FakeTimers();
  const requests: Record<string, unknown>[] = [];
  const opened: SavePending[] = [];
  let top: string | null = `${SITE}/login`;
  let chain = false;
  let topDoc: string | null = "doc-1";
  let onCheck: (() => void) | null = null;
  const flow = new SaveFlow({
    session: {
      request: (async (r: Record<string, unknown>) => {
        requests.push(r);
        if (r.op === "check_credentials") {
          onCheck?.();
          return status === "update" ? { status, item_id: "it_01", title: "Atlas Cloud" } : { status };
        }
        return {};
      }) as never,
    },
    saves: { open: async (p: SavePending) => (opened.push(structuredClone(p)), "tok") },
    neverSave: { has: async (s: string) => never.includes(s) },
    topFrame: async () => (top === null ? null : topDoc === null ? { url: top } : { url: top, documentId: topDoc }),
    chainRunning: async () => chain,
    now: () => timers.t,
    timers,
  });
  const cs: CsContext = { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" };
  const submit = (username = "alex@atlas.dev", password = "Atlas-Pass-1", isNew = false, from = cs) =>
    flow.onSubmitted({ type: "submitted_credentials", formRef: "f1", username, password, isNew }, from);
  return {
    flow,
    timers,
    requests,
    opened,
    submit,
    setTop: (u: string | null) => (top = u),
    setChain: (v: boolean) => (chain = v),
    setTopDoc: (d: string | null) => (topDoc = d),
    /** Runs while the host answers check_credentials. */
    duringCheck: (fn: () => void) => (onCheck = fn),
  };
}

describe("save flow", () => {
  it("new: checks after 1.5 s without navigation and opens the prompt on the submitting document", async () => {
    const t = setup("new");
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS - 1);
    expect(t.requests).toEqual([]);
    await t.timers.advance(1);
    expect(t.requests).toEqual([
      { op: "check_credentials", ctx: "save_prompt", origin: SITE, username: "alex@atlas.dev", password: "Atlas-Pass-1" },
    ]);
    expect(t.opened).toEqual([
      {
        tabId: 7,
        origin: SITE,
        documentId: "doc-1",
        topOrigin: SITE,
        kind: "login",
        status: "new",
        username: "alex@atlas.dev",
        password: "Atlas-Pass-1",
      },
    ]);
    expect(t.flow.size).toBe(0);
  });

  it("update: after a navigation, once the new page is ready, names the item to update", async () => {
    const t = setup("update");
    await t.submit("alex@atlas.dev", "New-Pass-2");
    t.flow.onNavigation(7);
    await t.timers.advance(CHECK_DELAY_MS * 2);
    expect(t.requests).toEqual([]);
    t.setTop(`${SITE}/home`);
    t.setTopDoc("doc-2");
    await t.flow.onReady(7);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } });
    // The old document is gone: pinned to the new, verified one.
    expect(t.opened[0]?.documentId).toBe("doc-2");
  });

  it("a navigation committed before the submission was registered: the prompt goes to the new top document", async () => {
    const t = setup("new");
    // The commit event of the next page wins the race with the submission message.
    t.flow.onNavigation(7);
    t.setTop(`${SITE}/home`);
    t.setTopDoc("doc-2");
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.opened).toHaveLength(1);
    // Not pinned to doc-1, which is gone: to the verified new document.
    expect(t.opened[0]?.documentId).toBe("doc-2");
  });

  it("the browser reports no documentId: an origin pin instead", async () => {
    const t = setup("new");
    t.setTopDoc(null);
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.opened[0]?.documentId).toBeUndefined();
    expect(t.opened[0]?.topOrigin).toBe(SITE);
  });

  it("the top frame goes to another site during check_credentials: no prompt", async () => {
    const t = setup("new");
    await t.submit();
    t.duringCheck(() => {
      t.setTop("https://evil.test/");
      t.setTopDoc("doc-evil");
    });
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests.filter((r) => r.op === "check_credentials")).toHaveLength(1);
    expect(t.opened).toEqual([]);
  });

  it("the top frame loads a new same-site document during check_credentials: prompt pinned to it", async () => {
    const t = setup("update");
    await t.submit("alex@atlas.dev", "New-Pass-2");
    t.duringCheck(() => {
      t.setTop(`${SITE}/home`);
      t.setTopDoc("doc-3");
    });
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ documentId: "doc-3", topOrigin: SITE, status: "update" });
  });

  it("navigated path: a new top document of another site after the commit gets no prompt", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    t.setTop("https://evil.test/");
    t.setTopDoc("doc-evil");
    await t.flow.onReady(7);
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("same: nothing", async () => {
    const t = setup("same");
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests).toHaveLength(1);
    expect(t.opened).toEqual([]);
  });

  it("never: a site in the list is not proposed, and the host is not asked", async () => {
    const t = setup("new", ["atlas-cloud.test"]);
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("expires after 2 minutes", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    await t.timers.advance(SUBMIT_TTL_MS);
    expect(t.flow.size).toBe(0);
    await t.flow.onReady(7);
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("the top frame moved to another site: no prompt", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    t.setTop("https://evil.test/");
    await t.flow.onReady(7);
    expect(t.requests).toEqual([]);
  });

  it("no identifier: not proposed, unless the password is the one just generated here", async () => {
    const t = setup("new");
    await t.submit("", "Some-Pass");
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests).toEqual([]);

    t.flow.rememberGenerated(7, `${SITE}/signup`, "Gen-Pass-123");
    await t.submit("", "Gen-Pass-123", true);
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ username: "", password: "Gen-Pass-123", status: "new" });
  });

  it("a generated password from another site does not count", async () => {
    const t = setup("new");
    t.flow.rememberGenerated(7, "https://other.test", "Gen-Pass-123");
    await t.submit("", "Gen-Pass-123", true);
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.opened).toEqual([]);
  });

  it("a running chain's submissions are not proposed", async () => {
    const t = setup("new");
    t.setChain(true);
    await t.submit();
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests).toEqual([]);
  });

  it("plain HTTP submissions are ignored", async () => {
    const t = setup("new");
    await t.submit("alex@atlas.dev", "x", false, { tabId: 7, frameId: 0, origin: "http://atlas-cloud.test" });
    await t.timers.advance(CHECK_DELAY_MS);
    expect(t.requests).toEqual([]);
  });

  it("a host error drops the submission silently", async () => {
    const t = setup("new");
    const flow = new SaveFlow({
      session: { request: (async () => Promise.reject(new Error("locked"))) as never },
      saves: { open: async () => "tok" },
      neverSave: { has: async () => false },
      topFrame: async () => ({ url: `${SITE}/login`, documentId: "doc-1" }),
      now: () => t.timers.t,
      timers: t.timers,
    });
    await flow.onSubmitted({ type: "submitted_credentials", formRef: "f", username: "a", password: "b", isNew: false }, {
      tabId: 1,
      frameId: 0,
      origin: SITE,
    });
    await t.timers.advance(CHECK_DELAY_MS);
    expect(flow.size).toBe(0);
  });

  it("menu new login: edit view, site prefilled, nothing typed", async () => {
    const t = setup();
    await t.flow.openNewLogin(7, SITE, "doc-1");
    expect(t.opened).toEqual([
      { tabId: 7, origin: SITE, documentId: "doc-1", kind: "login", status: "new", username: "", password: "", view: "edit" },
    ]);
  });
});

describe("auto-submit preference (R-12)", () => {
  it("defaults to on, stored per item in storage.local", async () => {
    const area = new FakeArea();
    expect(await autoSubmitFor(area, "it_01")).toBe(true);
    await setAutoSubmit(area, "it_01", false);
    expect(area.data.get("autoSubmit:it_01")).toBe(false);
    expect(await autoSubmitFor(area, "it_01")).toBe(false);
    expect(await autoSubmitFor(area, "it_02")).toBe(true);
    await setAutoSubmit(area, "it_01", true);
    expect(await autoSubmitFor(area, "it_01")).toBe(true);
  });
});

describe("generated passwords memory hygiene", () => {
  const mk = () =>
    new SaveFlow({
      session: { request: (async () => ({})) as never },
      saves: { open: async () => "tok" },
      neverSave: { has: async () => false },
      topFrame: async () => null,
    });
  const held = (f: SaveFlow, tab: number) => (f as unknown as { generated: Map<number, { password: string }> }).generated.get(tab);

  it("blanks the replaced entry and clears every entry on lock", () => {
    const f = mk();
    f.rememberGenerated(7, "https://atlas-cloud.test", "first-Pass-1");
    const first = held(f, 7);
    f.rememberGenerated(7, "https://atlas-cloud.test", "second-Pass-2");
    expect(first?.password).toBe("");
    const second = held(f, 7);
    expect(second?.password).toBe("second-Pass-2");
    f.clearGenerated();
    expect(second?.password).toBe("");
    expect(held(f, 7)).toBeUndefined();
  });
});

