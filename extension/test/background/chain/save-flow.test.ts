// Save flow (spec 8.5, 8.8): submitted credentials -> check -> prompt.
import { describe, expect, it } from "vitest";
import {
  IDENTIFIER_TTL_MS,
  NAV_SETTLE_MS,
  SETTLE_MS,
  SUBMIT_TTL_MS,
  SaveFlow,
  type Timers,
  autoSubmitFor,
  cardFromValues,
  setAutoSubmit,
  splitExpiry,
} from "../../../src/background/chain/save-flow";
import type { FillTarget } from "../../../src/background/fill";
import type { CsContext } from "../../../src/background/frames";
import { Planner } from "../../../src/background/planner";
import type { CsToBg, FormInfo, PageAnalysis, PlanOut } from "../../../src/shared/messages";
import { PENDING_TAG, type SavePending, SavePrompts, WEAK_BY_SITE_TAG, loginQuietKey } from "../../../src/background/save";
import { BgError } from "../../../src/background/session";
import { FakeArea } from "../fake-ext";

const SITE = "https://atlas-cloud.test";

/** A page as the content script reports it: with or without a sign-in form asking for a password. */
function page(withPassword: boolean): PageAnalysis {
  const forms: FormInfo[] = withPassword
    ? [{ ref: "f1", kind: "login", fields: [{ ref: "u", role: "email" }, { ref: "p", role: "current_password" }] } as FormInfo]
    : [];
  return { url: `${SITE}/x`, forms, captcha: false, push: false, providerButtons: [], accountChooser: [] };
}

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

type Answer = (r: Record<string, unknown>) => unknown;

function setup(status: "new" | "same" | "update" = "new", never: string[] = [], answer?: Answer) {
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
        const scripted = answer?.(r);
        if (scripted instanceof Error) throw scripted;
        if (scripted !== undefined) return scripted;
        if (r.op === "vaults") return { vaults: [{ id: "v1", name: "Perso", color: null }] };
        if (r.op === "save_login") return { item_id: "it_new" };
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
    /** The submitting document drops its password form and stays so (a single-page app signed in). */
    succeed: async () => {
      flow.onAnalysis(page(false), cs);
      await timers.advance(SETTLE_MS);
    },
    /** The analysis of the top document the browser reports now (after a navigation). */
    landed: async (withPassword = false) => {
      const now: CsContext = { tabId: 7, frameId: 0, origin: SITE };
      if (topDoc !== null) now.documentId = topDoc;
      flow.onAnalysis(page(withPassword), now);
      for (let i = 0; i < 10; i++) await Promise.resolve();
    },
    page,
    cs,
  };
}

describe("save flow", () => {
  it("new: no prompt on a mere delay; once the form is gone for 1 s, checks and opens the prompt on the submitting document", async () => {
    const t = setup("new");
    await t.submit();
    await t.timers.advance(SUBMIT_TTL_MS / 2);
    expect(t.requests).toEqual([]);
    t.flow.onAnalysis(t.page(false), t.cs);
    await t.timers.advance(SETTLE_MS - 1);
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
    await t.timers.advance(SETTLE_MS * 2);
    expect(t.requests).toEqual([]);
    t.setTop(`${SITE}/home`);
    t.setTopDoc("doc-2");
    await t.landed();
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
    await t.succeed();
    expect(t.opened).toHaveLength(1);
    // Not pinned to doc-1, which is gone: to the verified new document.
    expect(t.opened[0]?.documentId).toBe("doc-2");
  });

  it("the browser reports no documentId: an origin pin instead", async () => {
    const t = setup("new");
    t.setTopDoc(null);
    await t.submit();
    await t.succeed();
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
    await t.succeed();
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
    await t.succeed();
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ documentId: "doc-3", topOrigin: SITE, status: "update" });
  });

  it("navigated path: a new top document of another site after the commit gets no prompt", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    t.setTop("https://evil.test/");
    t.setTopDoc("doc-evil");
    await t.landed();
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("same: nothing", async () => {
    const t = setup("same");
    await t.submit();
    await t.succeed();
    expect(t.requests).toHaveLength(1);
    expect(t.opened).toEqual([]);
  });

  it("never: a site in the list is not proposed, and the host is not asked", async () => {
    const t = setup("new", ["atlas-cloud.test"]);
    await t.submit();
    await t.succeed();
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("expires after 2 minutes", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    await t.timers.advance(SUBMIT_TTL_MS);
    expect(t.flow.size).toBe(0);
    await t.landed();
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("the top frame moved to another site: no prompt", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7);
    t.setTop("https://evil.test/");
    await t.landed();
    expect(t.requests).toEqual([]);
  });

  it("no identifier: not proposed, unless the password is the one just generated here", async () => {
    const t = setup("new");
    await t.submit("", "Some-Pass");
    await t.succeed();
    expect(t.requests).toEqual([]);

    t.flow.rememberGenerated(7, `${SITE}/signup`, "Gen-Pass-123");
    await t.submit("", "Gen-Pass-123", true);
    await t.succeed();
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ username: "", password: "Gen-Pass-123", status: "new" });
  });

  it("a generated password from another site does not count", async () => {
    const t = setup("new");
    t.flow.rememberGenerated(7, "https://other.test", "Gen-Pass-123");
    await t.submit("", "Gen-Pass-123", true);
    await t.succeed();
    expect(t.opened).toEqual([]);
  });

  it("a running chain's submissions are not proposed", async () => {
    const t = setup("new");
    t.setChain(true);
    await t.submit();
    await t.succeed();
    expect(t.requests).toEqual([]);
  });

  it("plain HTTP submissions are ignored", async () => {
    const t = setup("new");
    await t.submit("alex@atlas.dev", "x", false, { tabId: 7, frameId: 0, origin: "http://atlas-cloud.test" });
    await t.succeed();
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
    flow.onAnalysis(t.page(false), { tabId: 1, frameId: 0, origin: SITE });
    await t.timers.advance(SETTLE_MS);
    expect(flow.size).toBe(0);
  });

  // ---- founder bug 2026-11-03: the prompt waits for success, follows identifier-first sign-ins ----

  it("failed sign-in: the next page asks for the password again, nothing is proposed", async () => {
    const t = setup("new");
    await t.submit("alex@atlas.dev", "Wrong-Pass-1");
    t.flow.onNavigation(7, `${SITE}/login`);
    t.setTopDoc("doc-2");
    await t.landed(true);
    await t.timers.advance(NAV_SETTLE_MS * 2);
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
    expect(t.flow.size).toBe(0);
  });

  it("single-page app: the form flickers away and back with an error, nothing is proposed", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onAnalysis(t.page(false), t.cs);
    await t.timers.advance(SETTLE_MS / 2);
    t.flow.onAnalysis(t.page(true), t.cs);
    await t.timers.advance(SETTLE_MS * 4);
    expect(t.requests).toEqual([]);
    expect(t.flow.size).toBe(1);
  });

  it("identifier first, password on the next page: proposed with the identifier of the first step", async () => {
    const t = setup("new");
    t.flow.onIdentifier({ type: "submitted_identifier", formRef: "f0", username: "alex.new@atlas.dev" }, t.cs);
    t.flow.onNavigation(7, `${SITE}/multistep/password`);
    t.setTopDoc("doc-2");
    await t.submit("", "Nouv-Pass-0042", false, { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-2" });
    t.flow.onNavigation(7, `${SITE}/multistep/otp`);
    t.setTopDoc("doc-3");
    await t.landed();
    expect(t.requests).toEqual([
      { op: "check_credentials", ctx: "save_prompt", origin: SITE, username: "alex.new@atlas.dev", password: "Nouv-Pass-0042" },
    ]);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ username: "alex.new@atlas.dev", status: "new", documentId: "doc-3" });
  });

  it("an identifier of another site, or too old, is not used", async () => {
    const t = setup("new");
    t.flow.onIdentifier({ type: "submitted_identifier", formRef: "f0", username: "alex@other.test" }, { tabId: 7, frameId: 0, origin: "https://other.test" });
    await t.submit("", "Some-Pass");
    await t.succeed();
    expect(t.requests).toEqual([]);
    t.flow.onIdentifier({ type: "submitted_identifier", formRef: "f0", username: "alex@atlas.dev" }, t.cs);
    await t.timers.advance(IDENTIFIER_TTL_MS + 1);
    await t.submit("", "Some-Pass");
    await t.succeed();
    expect(t.requests).toEqual([]);
  });

  it("vault locked in the app: the card opens anyway, marked locked", async () => {
    const t = setup("new", [], (r) => (r.op === "check_credentials" ? new BgError("locked") : undefined));
    await t.submit();
    await t.succeed();
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ status: "new", locked: true, username: "alex@atlas.dev" });
  });

  it("Safari order (no documentId, commit before the submission): the new page's analysis decides", async () => {
    const t = setup("new");
    t.setTopDoc(null);
    const safari: CsContext = { tabId: 7, frameId: 0, origin: SITE };
    t.flow.onNavigation(7, `${SITE}/home`);
    await t.submit("alex@atlas.dev", "Atlas-Pass-1", false, safari);
    t.flow.onAnalysis(t.page(false), safari);
    await t.timers.advance(SETTLE_MS);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.topOrigin).toBe(SITE);
  });

  it("a new page with no analysis at all counts once loaded", async () => {
    const t = setup("new");
    await t.submit();
    t.flow.onNavigation(7, `${SITE}/home`);
    t.setTopDoc("doc-2");
    t.flow.onReady(7);
    await t.timers.advance(NAV_SETTLE_MS);
    expect(t.opened).toHaveLength(1);
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

describe("pending save of a generated password (spec 7)", () => {
  const GEN = "Gen-Pass-123";
  const signup = (): PlanOut => ({
    intent: "signup",
    groups: [
      {
        form_ref: "f1",
        kind: "generated_password",
        item_id: null,
        fields: [
          { field_ref: "f1e0", role: "new_password" },
          { field_ref: "f1e1", role: "confirm_password" },
        ],
      },
    ],
    action: "fill",
    confidence: "high",
    alternatives: [],
    reasons: [],
  });
  const target: FillTarget = { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1", formRef: "f1" };

  /** A planner over the real save flow of `t`: the filler writes, the generator gives `GEN`. */
  function plannerFor(t: ReturnType<typeof setup>, weak = false, events: string[] = []) {
    const filler = {
      fillGenerated: async () => {
        events.push("filled");
        return 2;
      },
    };
    const generator = {
      generateForForm: async () => ({ password: GEN, report: weak ? ({ weak_by_site: true } as never) : null }),
    };
    return new Planner({ request: async () => ({}) } as never, filler as never, {} as never, t.flow, generator);
  }

  const ops = (t: ReturnType<typeof setup>) => t.requests.map((r) => r.op);

  it("pending_saved_before_fill_returns", async () => {
    const t = setup();
    const outcome = await plannerFor(t, true).run(target, signup());
    expect(outcome).toBe("filled");
    // Already in the vault when the run answers: nothing left to lose.
    expect(t.requests).toEqual([
      // Listed for the page: the first vault is the default of the account it routes to.
      { op: "vaults", origin: SITE },
      {
        op: "save_login",
        ctx: "save_prompt",
        origin: SITE,
        title: "Atlas Cloud",
        username: "",
        password: GEN,
        vault_id: "v1",
        rule: "domain",
        tags: [PENDING_TAG, WEAK_BY_SITE_TAG],
      },
    ]);
    // A login page's generated fill (no signup intent) saves nothing.
    const u = setup();
    await plannerFor(u).run(target, { ...signup(), intent: "login" });
    expect(u.requests).toEqual([]);
  });

  it("reset_page_keeps_the_update_prompt", async () => {
    // A reset form: no pending item, the submission asks the host and the
    // update prompt opens for the existing Login.
    const t = setup("update");
    await plannerFor(t).run(target, { ...signup(), intent: "reset" });
    expect(t.requests).toEqual([]);
    await t.submit("", GEN, true);
    await t.succeed();
    expect(ops(t)).toEqual(["check_credentials"]);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]).toMatchObject({ status: "update", update: { itemId: "it_01" } });
  });

  it("regenerate_carries_the_weak_flag", async () => {
    const t = setup();
    await t.flow.savePending(7, SITE, "first-Pass-1", { weak: true });
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login", tags: [PENDING_TAG, WEAK_BY_SITE_TAG] });
    await t.flow.savePending(7, SITE, "second-Pass-2");
    expect(t.requests.at(-1)).toMatchObject({ op: "update_password", weak_by_site: false });
    await t.flow.savePending(7, SITE, "third-Pass-3", { weak: true });
    expect(t.requests.at(-1)).toMatchObject({ op: "update_password", weak_by_site: true });
  });

  it("regenerate_same_tab_updates_pending", async () => {
    const t = setup();
    expect(await t.flow.savePending(7, `${SITE}/signup`, "first-Pass-1")).toBe(true);
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login", tags: [PENDING_TAG] });
    expect(await t.flow.savePending(7, `${SITE}/signup`, "second-Pass-2")).toBe(true);
    expect(t.requests.at(-1)).toEqual({
      op: "update_password",
      ctx: "save_prompt",
      item_id: "it_new",
      origin: `${SITE}/signup`,
      password: "second-Pass-2",
      weak_by_site: false,
    });
    // Another tab, or another site in this tab: a pending item of its own.
    await t.flow.savePending(8, SITE, "third-Pass-3");
    await t.flow.savePending(7, "https://other.test", "fourth-Pass-4");
    expect(ops(t)).toEqual(["vaults", "save_login", "update_password", "vaults", "save_login", "vaults", "save_login"]);
  });

  /**
   * The host's `check_credentials` contract for pending items: the pending
   * item (saved with an empty username) answers `pending` for its own
   * password whatever the username, `new` otherwise.
   */
  const pendingHost = (r: Record<string, unknown>) =>
    r.op === "check_credentials" ? (r.password === GEN ? { status: "pending", item_id: "it_new", title: "Atlas Cloud" } : { status: "new" }) : undefined;

  it("lock_after_fill_keeps_item", async () => {
    const t = setup("new", [], pendingHost);
    await plannerFor(t).run(target, signup());
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login", username: "", tags: [PENDING_TAG] });
    const before = [...t.requests];
    // The vault locks before the submit: the generated password is forgotten here...
    t.flow.clearGenerated();
    // ...but it was saved before the lock, and the lock removes nothing.
    expect(t.requests).toEqual(before);
    // And the service worker restarts: no memory of the pending item at all.
    const fresh = new SaveFlow({
      session: { request: (async (r: Record<string, unknown>) => (t.requests.push(r), pendingHost(r) ?? {})) as never },
      saves: { open: async (p: SavePending) => (t.opened.push(p), "tok") },
      neverSave: { has: async () => false },
      topFrame: async () => ({ url: `${SITE}/signup`, documentId: "doc-1" }),
      now: () => t.timers.t,
      timers: t.timers,
    });
    // Unlocked again, the form goes: the host finds the pending item, it is confirmed.
    await fresh.onSubmitted({ type: "submitted_credentials", formRef: "f1", username: "alex@atlas.dev", password: GEN, isNew: true }, {
      tabId: 7,
      frameId: 0,
      origin: SITE,
    });
    fresh.onAnalysis(t.page(false), t.cs);
    await t.timers.advance(SETTLE_MS);
    expect(ops(t)).toEqual(["vaults", "save_login", "check_credentials", "confirm_pending"]);
    expect(t.requests.at(-1)).toEqual({ op: "confirm_pending", ctx: "save_prompt", item_id: "it_new", origin: SITE, username: "alex@atlas.dev" });
    // Nothing to answer: the toast (Edit only, spec 4.4) says it is saved, without the password.
    expect(t.opened).toEqual([expect.objectContaining({ view: "toast", username: "alex@atlas.dev", password: "" })]);
  });

  it("change-password: the generated password updates the login pending, its submission confirms it (spec 5.2)", async () => {
    const one = { item_id: "it_01", kind: "login" };
    const t = setup("new", [], (r) => (r.op === "list_for_origin" ? { items: [one] } : r.op === "check_credentials" ? { status: "pending", item_id: "it_01" } : undefined));
    t.flow.rememberGenerated(7, SITE, GEN);
    expect(await t.flow.savePendingUpdate(7, SITE, GEN)).toBe(true);
    expect(t.requests.find((r) => r.op === "update_password")).toEqual({
      op: "update_password",
      ctx: "save_prompt",
      item_id: "it_01",
      origin: SITE,
      password: GEN,
      weak_by_site: false,
      pending: true,
    });
    // The change form goes, often without an identifier: the login keeps its own username.
    await t.submit("", GEN, true);
    expect(t.requests.at(-1)).toEqual({ op: "confirm_pending", ctx: "save_prompt", item_id: "it_01", origin: SITE, username: "" });
    await t.succeed();
    expect(ops(t)).toEqual(["list_for_origin", "update_password", "confirm_pending"]);
    expect(t.opened).toEqual([expect.objectContaining({ view: "toast", password: "" })]);
  });

  it("change-password, memory lost: the host's pending verdict confirms the updated login", async () => {
    const one = { item_id: "it_01", kind: "login" };
    const t = setup("new", [], (r) => (r.op === "list_for_origin" ? { items: [one] } : r.op === "check_credentials" ? { status: "pending", item_id: "it_01" } : undefined));
    await t.flow.savePendingUpdate(7, SITE, GEN);
    (t.flow as unknown as { saved: Map<number, unknown> }).saved.clear();
    t.flow.rememberGenerated(7, SITE, GEN);
    await t.submit("alex@atlas.dev", GEN, true);
    await t.succeed();
    expect(ops(t)).toEqual(["list_for_origin", "update_password", "check_credentials", "confirm_pending"]);
    expect(t.requests.at(-1)).toEqual({ op: "confirm_pending", ctx: "save_prompt", item_id: "it_01", origin: SITE, username: "alex@atlas.dev" });
  });

  it("pending verdict without a username: stays pending, no prompt, no second save", async () => {
    const t = setup("new", [], pendingHost);
    await plannerFor(t).run(target, signup());
    t.flow.clearGenerated();
    t.flow.rememberGenerated(7, SITE, GEN);
    (t.flow as unknown as { saved: Map<number, unknown> }).saved.clear();
    await t.submit("", GEN, true);
    await t.succeed();
    expect(ops(t)).toEqual(["vaults", "save_login", "check_credentials"]);
    expect(t.opened).toEqual([]);
  });

  it("a refused password update keeps the pending item, unless it is gone", async () => {
    let refusal: BgError = new BgError("rate_limited");
    const t = setup("new", [], (r) => (r.op === "update_password" ? refusal : undefined));
    await t.flow.savePending(7, SITE, "first-Pass-1");
    expect(await t.flow.savePending(7, SITE, "second-Pass-2")).toBe(false);
    expect(ops(t)).toEqual(["vaults", "save_login", "update_password"]);
    refusal = new BgError("not_found");
    expect(await t.flow.savePending(7, SITE, "third-Pass-3")).toBe(true);
    expect(ops(t)).toEqual(["vaults", "save_login", "update_password", "update_password", "vaults", "save_login"]);
  });

  it("submit_confirms_pending", async () => {
    const t = setup();
    await plannerFor(t).run(target, signup());
    await t.submit("alex@atlas.dev", GEN, true);
    expect(t.requests.at(-1)).toEqual({ op: "confirm_pending", ctx: "save_prompt", item_id: "it_new", origin: SITE, username: "alex@atlas.dev" });
    // Confirmed instead of a new save prompt; once signed up, the toast shows it saved (Edit only).
    expect(t.opened).toEqual([]);
    await t.succeed();
    expect(ops(t)).toEqual(["vaults", "save_login", "confirm_pending"]);
    expect(t.opened).toEqual([
      { tabId: 7, origin: SITE, kind: "login", status: "new", username: "alex@atlas.dev", password: "", view: "toast", topOrigin: SITE, documentId: "doc-1" },
    ]);
    expect(t.flow.size).toBe(0);
    await t.flow.savePending(7, SITE, "again-Pass-5");
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login" });
  });

  it("a confirmed signup the site refuses (its form again on a new page) shows no card", async () => {
    const t = setup();
    await plannerFor(t).run(target, signup());
    await t.submit("alex@atlas.dev", GEN, true);
    t.flow.onNavigation(7, `${SITE}/signup`);
    t.setTopDoc("doc-2");
    await t.landed(true);
    await t.timers.advance(SETTLE_MS * 3);
    expect(ops(t)).toEqual(["vaults", "save_login", "confirm_pending"]);
    expect(t.opened).toEqual([]);
    expect(t.flow.size).toBe(0);
  });

  it("a submitted password other than the generated one gets the usual prompt", async () => {
    const t = setup();
    await plannerFor(t).run(target, signup());
    await t.submit("alex@atlas.dev", "Typed-Instead-9");
    await t.succeed();
    expect(ops(t)).toEqual(["vaults", "save_login", "check_credentials"]);
    expect(t.opened).toHaveLength(1);
  });

  it("vault locked at fill time: the fill happens, the old save prompt is the fallback", async () => {
    const t = setup("new", [], (r) => (r.op === "vaults" ? new Error("locked") : undefined));
    const events: string[] = [];
    expect(await plannerFor(t, false, events).run(target, signup())).toBe("filled");
    expect(events).toEqual(["filled"]);
    expect(ops(t)).toEqual(["vaults"]);
    await t.submit("", GEN, true);
    await t.succeed();
    expect(ops(t)).toEqual(["vaults", "check_credentials"]);
    expect(t.opened[0]).toMatchObject({ status: "new", username: "", password: GEN });
  });

  it("a refused confirmation falls back to the prompt", async () => {
    const t = setup("new", [], (r) => (r.op === "confirm_pending" ? new Error("invalid") : undefined));
    await plannerFor(t).run(target, signup());
    await t.submit("alex@atlas.dev", GEN, true);
    await t.succeed();
    expect(ops(t)).toEqual(["vaults", "save_login", "confirm_pending", "check_credentials"]);
    expect(t.opened).toHaveLength(1);
  });

  it("forgotten when the tab closes or goes to another site, kept on a same-site navigation", async () => {
    const t = setup();
    await t.flow.savePending(7, SITE, "first-Pass-1");
    t.flow.onNavigation(7, `${SITE}/welcome`);
    await t.flow.savePending(7, SITE, "second-Pass-2");
    expect(t.requests.at(-1)).toMatchObject({ op: "update_password" });
    t.flow.onNavigation(7, "https://elsewhere.test/");
    await t.flow.savePending(7, SITE, "third-Pass-3");
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login" });
    t.flow.onTabRemoved(7);
    await t.flow.savePending(7, SITE, "fourth-Pass-4");
    expect(t.requests.at(-1)).toMatchObject({ op: "save_login" });
  });

  it("plain HTTP or an empty password saves nothing", async () => {
    const t = setup();
    expect(await t.flow.savePending(7, "http://atlas-cloud.test", "x-Pass-1")).toBe(false);
    expect(await t.flow.savePending(7, SITE, "")).toBe(false);
    expect(t.requests).toEqual([]);
  });

  it("keeps no password: only the item id, site and username", async () => {
    const t = setup();
    await t.flow.savePending(7, SITE, "first-Pass-1", { username: "alex@atlas.dev" });
    const held = (t.flow as unknown as { saved: Map<number, unknown> }).saved.get(7);
    expect(held).toEqual({ site: "atlas-cloud.test", itemId: "it_new", username: "alex@atlas.dev" });
  });
});

// Founder, 2026-11-04: the card every time a credential OnePass does not hold is used.
describe("save every time", () => {
  interface Held {
    site: string;
    username: string;
    password: string;
    id: string;
  }

  /** A save flow over several sites, with a vault that answers check_credentials like the host. */
  function everyTime(opts: { never?: string[]; cards?: { number: string; exp: string; id: string }[]; identities?: string[] } = {}) {
    const timers = new FakeTimers();
    const vault: Held[] = [];
    const opened: SavePending[] = [];
    const requests: Record<string, unknown>[] = [];
    const dismissed = new Set<string>();
    let top = `${SITE}/login`;
    let doc = 0;
    const flow = new SaveFlow({
      session: {
        request: (async (r: Record<string, unknown>) => {
          requests.push(r);
          const site = new URL(String(r.origin)).hostname;
          if (r.op === "check_credentials") {
            const mine = vault.filter((v) => v.site === site && v.username.toLowerCase() === String(r.username).toLowerCase());
            if (mine.some((v) => v.password === r.password)) return { status: "same", item_id: mine[0]?.id };
            if (mine[0]) return { status: "update", item_id: mine[0].id, title: site };
            return { status: "new" };
          }
          if (r.op === "check_card") {
            const c = (opts.cards ?? []).find((x) => x.number === r.number);
            if (!c) return { status: "new" };
            return c.exp === `${String(r.exp_month)}/${String(r.exp_year)}` ? { status: "same", item_id: c.id } : { status: "update", item_id: c.id, title: "Visa" };
          }
          if (r.op === "check_identity") return (opts.identities ?? []).includes(String(r.email)) ? { status: "same", item_id: "id_1" } : { status: "new" };
          return {};
        }) as never,
      },
      saves: {
        open: async (p: SavePending) => (opened.push(structuredClone(p)), "tok"),
        recentlyDismissed: async (origin: string, key: string) => dismissed.has(`${new URL(origin).hostname}|${key}`),
      },
      neverSave: { has: async (s: string) => (opts.never ?? []).includes(s) },
      topFrame: async () => ({ url: top, documentId: `doc-${doc}` }),
      now: () => timers.t,
      timers,
    });
    /** The user signs in by hand on `origin`; the next page has no form. */
    const signIn = async (origin: string, username: string, password: string) => {
      doc++;
      top = `${origin}/login`;
      const cs: CsContext = { tabId: 7, frameId: 0, origin, documentId: `doc-${doc}` };
      await flow.onSubmitted({ type: "submitted_credentials", formRef: "f1", username, password, isNew: false }, cs);
      doc++;
      top = `${origin}/home`;
      flow.onNavigation(7, top);
      flow.onAnalysis(page(false), { tabId: 7, frameId: 0, origin, documentId: `doc-${doc}` });
      for (let i = 0; i < 10; i++) await Promise.resolve();
    };
    /** A card or address form sent by hand on `origin`; the next page has no form (or `still` one). */
    const sendForm = async (origin: string, m: Extract<CsToBg, { type: "submitted_form" }>, still?: PageAnalysis) => {
      doc++;
      top = `${origin}/checkout`;
      flow.onForm(m, { tabId: 7, frameId: 0, origin, documentId: `doc-${doc}` });
      doc++;
      flow.onNavigation(7, top);
      flow.onAnalysis(still ?? page(false), { tabId: 7, frameId: 0, origin, documentId: `doc-${doc}` });
      for (let i = 0; i < 10; i++) await Promise.resolve();
    };
    const save = (origin: string, username: string, password: string) =>
      vault.push({ site: new URL(origin).hostname, username, password, id: `it_${vault.length + 1}` });
    const dismiss = (origin: string, username: string, password: string) => dismissed.add(`${new URL(origin).hostname}|${loginQuietKey(username, password)}`);
    return { flow, opened, requests, signIn, sendForm, save, dismiss, dismissed };
  }

  const ATLAS = "https://atlas.test";
  const BOREALIS = "https://borealis.test";
  const COBALT = "https://cobalt.test";
  const DUNE = "https://dune.test";

  it("three sites never seen: a card on each, every time", async () => {
    const t = everyTime();
    for (const [i, origin] of [ATLAS, BOREALIS, COBALT].entries()) {
      await t.signIn(origin, `user${i}@exemple.fr`, `Pass-${i}-un`);
      expect(t.opened).toHaveLength(i + 1);
      expect(t.opened[i]).toMatchObject({ origin, kind: "login", status: "new", username: `user${i}@exemple.fr` });
      t.save(origin, `user${i}@exemple.fr`, `Pass-${i}-un`);
    }
    // Signed in again with what OnePass now holds: nothing to ask.
    await t.signIn(BOREALIS, "user1@exemple.fr", "Pass-1-un");
    expect(t.opened).toHaveLength(3);
  });

  it("a second account on a known site is a new login; a known account with another password, an update", async () => {
    const t = everyTime();
    await t.signIn(BOREALIS, "borealis@exemple.fr", "Borealis-un");
    t.save(BOREALIS, "borealis@exemple.fr", "Borealis-un");
    await t.signIn(BOREALIS, "autre@exemple.fr", "Autre-un");
    expect(t.opened[1]).toMatchObject({ status: "new", username: "autre@exemple.fr" });
    expect(t.opened[1]?.update).toBeUndefined();
    t.save(BOREALIS, "autre@exemple.fr", "Autre-un");
    await t.signIn(BOREALIS, "borealis@exemple.fr", "Borealis-deux");
    expect(t.opened[2]).toMatchObject({ status: "update", username: "borealis@exemple.fr", update: { itemId: "it_1" } });
    // The second account with a new password: an update of that one, not the first.
    await t.signIn(BOREALIS, "Autre@exemple.fr", "Autre-deux");
    expect(t.opened[3]).toMatchObject({ status: "update", update: { itemId: "it_2" } });
  });

  it("'Pas maintenant' quiets that very credential only: another account, password or site still asks", async () => {
    const t = everyTime();
    await t.signIn(DUNE, "dune@exemple.fr", "Dune-un");
    expect(t.opened).toHaveLength(1);
    t.dismiss(DUNE, "dune@exemple.fr", "Dune-un");
    await t.signIn(DUNE, "dune@exemple.fr", "Dune-un");
    expect(t.opened).toHaveLength(1);
    await t.signIn(DUNE, "dune2@exemple.fr", "Dune-deux");
    expect(t.opened).toHaveLength(2);
    await t.signIn(DUNE, "dune@exemple.fr", "Dune-deux");
    expect(t.opened).toHaveLength(3);
    await t.signIn(ATLAS, "dune@exemple.fr", "Dune-un");
    expect(t.opened).toHaveLength(4);
  });

  it("'Ne jamais proposer' still silences the whole site, and only it", async () => {
    const t = everyTime({ never: ["dune.test"] });
    await t.signIn(DUNE, "a@exemple.fr", "A-un");
    await t.signIn(DUNE, "b@exemple.fr", "B-un");
    expect(t.opened).toEqual([]);
    await t.signIn(ATLAS, "a@exemple.fr", "A-un");
    expect(t.opened).toHaveLength(1);
  });

  describe("cards and addresses typed by hand (MS-04)", () => {
    const cardForm = (values: Record<string, string>): Extract<CsToBg, { type: "submitted_form" }> => ({ type: "submitted_form", formRef: "f9", kind: "card", values });
    const addressForm = (values: Record<string, string>): Extract<CsToBg, { type: "submitted_form" }> => ({ type: "submitted_form", formRef: "f8", kind: "identity", values });

    it("a new card: check_card, then the card with its values (one expiry field read too)", async () => {
      const t = everyTime();
      await t.sendForm(ATLAS, cardForm({ cc_name: "Alex Martin", cc_number: "4111 1111 1111 1111", cc_exp: "04/29" }));
      expect(t.requests).toEqual([{ op: "check_card", ctx: "save_prompt", origin: ATLAS, number: "4111111111111111", exp_month: "04", exp_year: "29" }]);
      expect(t.opened).toEqual([
        expect.objectContaining({ kind: "card", status: "new", card: { cardholder: "Alex Martin", number: "4111111111111111", exp_month: "04", exp_year: "29" } }),
      ]);
    });

    it("the card OnePass filled here: nothing; one it holds but did not fill: shown as known (no oracle); new expiry: an update", async () => {
      const t = everyTime({ cards: [{ number: "4111111111111111", exp: "04/2029", id: "card_1" }] });
      await t.sendForm(ATLAS, cardForm({ cc_number: "4111111111111111", cc_exp_month: "04", cc_exp_year: "2029" }));
      expect(t.opened).toEqual([expect.objectContaining({ kind: "card", known: true })]);
      t.opened.length = 0;
      t.flow.noteFilled(7, ATLAS, "card", "card_1");
      await t.sendForm(ATLAS, cardForm({ cc_number: "4111111111111111", cc_exp_month: "04", cc_exp_year: "2029" }));
      expect(t.opened).toEqual([]);
      // Filled on another site, or another card filled here: no pass.
      await t.sendForm(BOREALIS, cardForm({ cc_number: "4111111111111111", cc_exp_month: "04", cc_exp_year: "2029" }));
      expect(t.opened).toEqual([expect.objectContaining({ kind: "card", known: true })]);
      t.opened.length = 0;
      await t.sendForm(ATLAS, cardForm({ cc_number: "4111111111111111", cc_exp_month: "05", cc_exp_year: "2031" }));
      expect(t.opened).toEqual([expect.objectContaining({ kind: "card", status: "update", update: { itemId: "card_1", title: "Visa" } })]);
    });

    it("the payment refused (its card form again on the next page): nothing; never-save sites: nothing", async () => {
      const t = everyTime({ never: ["dune.test"] });
      const still: PageAnalysis = { ...page(false), forms: [{ ref: "f9", kind: "card", fields: [{ ref: "n", role: "cc_number" }] } as FormInfo] };
      await t.sendForm(ATLAS, cardForm({ cc_number: "4111111111111111" }), still);
      await t.sendForm(DUNE, cardForm({ cc_number: "4111111111111111" }));
      expect(t.opened).toEqual([]);
      expect(t.requests).toEqual([]);
    });

    it("an address: check_identity with the name split; one OnePass filled here gets nothing; a contact form is no identity", async () => {
      const t = everyTime();
      await t.sendForm(ATLAS, addressForm({ full_name: "Camille Durand", email: "camille@exemple.fr", address_line1: "1 rue de la Paix", postal_code: "75002", city: "Paris" }));
      expect(t.requests.at(-1)).toEqual({
        op: "check_identity",
        ctx: "save_prompt",
        origin: ATLAS,
        given_name: "Camille",
        family_name: "Durand",
        email: "camille@exemple.fr",
        tel: "",
        organization: "",
        address: { line1: "1 rue de la Paix", line2: "", city: "Paris", postal_code: "75002", region: "", country: "" },
      });
      expect(t.opened).toEqual([expect.objectContaining({ kind: "identity", status: "new" })]);
      // Filled from OnePass, then reformatted by the page: never a duplicate offered.
      t.flow.noteFilled(7, ATLAS, "identity", "id_1");
      await t.sendForm(ATLAS, addressForm({ given_name: "Alex", family_name: "Martin", tel: "06 00 00 00 00", address_line1: "1 rue X", city: "Paris" }));
      expect(t.opened).toHaveLength(1);
      const n = t.requests.length;
      await t.sendForm(BOREALIS, addressForm({ full_name: "Sam Leroy", email: "news@exemple.fr", tel: "0600000000" }));
      await t.sendForm(BOREALIS, addressForm({ city: "Lyon", country: "FR" }));
      expect(t.requests).toHaveLength(n);
    });

    it("a sign-in waiting for its check keeps its place over a form", async () => {
      const t = everyTime();
      await t.flow.onSubmitted(
        { type: "submitted_credentials", formRef: "f1", username: "a@exemple.fr", password: "A-un", isNew: false },
        { tabId: 7, frameId: 0, origin: ATLAS, documentId: "doc-x" },
      );
      t.flow.onForm(cardForm({ cc_number: "4111111111111111" }), { tabId: 7, frameId: 0, origin: ATLAS, documentId: "doc-x" });
      expect(t.flow.size).toBe(1);
    });
  });

  it("cardFromValues and splitExpiry", () => {
    expect(splitExpiry("4 / 2031")).toEqual({ month: "04", year: "2031" });
    expect(splitExpiry("0429")).toEqual({ month: "04", year: "29" });
    expect(splitExpiry("avril")).toEqual({ month: "", year: "" });
    expect(splitExpiry("122")).toEqual({ month: "", year: "" });
    // A security code read as a year: no expiry.
    expect(cardFromValues({ cc_number: "4111111111111111", cc_exp_month: "04", cc_exp_year: "1234" })).toMatchObject({ exp_month: "", exp_year: "" });
    expect(cardFromValues({ cc_number: "4111-1111-1111-1111", cc_exp_month: "13x" })).toEqual({ cardholder: "", number: "4111111111111111", exp_month: "", exp_year: "" });
    expect(cardFromValues({ cc_number: "1234" })).toBeNull();
  });
});

describe("automatic save of a new login (spec 4.1, 4.3)", () => {
  const PASS = "Atlas-Pass-1";
  const USER = "alex@atlas.dev";

  /** The real save prompts over a scripted host; `open` is watched. */
  function auto(opts: { vaults?: { id: string; name: string; color: null; shared?: boolean }[]; locked?: boolean; status?: "new" | "update"; never?: string[]; check?: (r: Record<string, unknown>) => unknown } = {}) {
    const timers = new FakeTimers();
    const requests: Record<string, unknown>[] = [];
    const opened: SavePending[] = [];
    const incognito = new Set<number>();
    let saves = 0;
    const session = {
      request: (async (r: Record<string, unknown>) => {
        requests.push(r);
        const scripted = opts.check?.(r);
        if (scripted instanceof Error) throw scripted;
        if (scripted !== undefined) return scripted;
        if (r.op === "check_credentials") {
          if (opts.locked) throw new BgError("locked");
          return opts.status === "update" ? { status: "update", item_id: "it_01", title: "Atlas Cloud" } : { status: "new" };
        }
        if (r.op === "vaults") return { vaults: opts.vaults ?? [{ id: "v1", name: "Perso", color: null }] };
        if (r.op === "save_login") return { item_id: `it_saved_${++saves}` };
        return {};
      }) as never,
    };
    const neverSave = { has: async (s: string) => (opts.never ?? []).includes(s), add: async () => undefined, list: async () => [], remove: async () => undefined };
    const prompts = new SavePrompts({
      ext: { tabs: { sendMessage: async () => undefined }, runtime: { getURL: (p: string) => `chrome-extension://x/${p}` } } as never,
      session,
      generator: { generate: async () => ({ password: "unused" }) } as never,
      neverSave: neverSave as never,
      now: () => timers.t,
    });
    const open = prompts.open.bind(prompts);
    const tokens: string[] = [];
    prompts.open = async (p: SavePending) => {
      opened.push(structuredClone(p));
      const tok = await open(p);
      tokens.push(tok);
      return tok;
    };
    const flow = new SaveFlow({
      session,
      saves: prompts,
      neverSave,
      topFrame: async () => ({ url: `${SITE}/home`, documentId: "doc-2" }),
      incognito: async (tabId: number) => incognito.has(tabId),
      now: () => timers.t,
      timers,
    });
    const signIn = async (username = USER, password = PASS, tabId = 7) => {
      await flow.onSubmitted({ type: "submitted_credentials", formRef: "f1", username, password, isNew: false }, { tabId, frameId: 0, origin: SITE, documentId: "doc-1" });
      flow.onAnalysis(page(false), { tabId, frameId: 0, origin: SITE, documentId: "doc-1" });
      await timers.advance(SETTLE_MS);
      for (let i = 0; i < 20; i++) await Promise.resolve();
    };
    const ops = () => requests.map((r) => r.op);
    return { flow, prompts, requests, opened, tokens, incognito, signIn, ops, timers };
  }

  it("new login is saved without a card", async () => {
    const t = auto();
    await t.signIn();
    expect(t.requests.find((r) => r.op === "save_login")).toMatchObject({ op: "save_login", origin: SITE, username: USER, password: PASS, vault_id: "v1", tags: [] });
    expect(t.opened).toEqual([expect.objectContaining({ view: "toast", undo: true, savedItemId: "it_saved_1", username: USER })]);
  });

  it("update still opens the card", async () => {
    const t = auto({ status: "update" });
    await t.signIn();
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.view).toBeUndefined();
    expect(t.opened[0]).toMatchObject({ status: "update", update: { itemId: "it_01" } });
  });

  it("locked keeps the card", async () => {
    const t = auto({ locked: true });
    await t.signIn();
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toEqual([expect.objectContaining({ status: "new", locked: true })]);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("private window keeps the card", async () => {
    const t = auto();
    t.incognito.add(7);
    await t.signIn();
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("shared vault keeps the card", async () => {
    const t = auto({ vaults: [{ id: "vs", name: "Équipe", color: null, shared: true }, { id: "v1", name: "Perso", color: null }] });
    await t.signIn();
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("no username keeps the card", async () => {
    const t = auto();
    // A generated password filled here, sent without an identifier (nothing saved pending).
    t.flow.rememberGenerated(7, SITE, "Gen-Pass-9");
    await t.signIn("", "Gen-Pass-9");
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toEqual([expect.objectContaining({ status: "new", username: "" })]);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("uncertain success keeps the card (flag set by Task 11)", async () => {
    const t = auto();
    await t.flow.onSubmitted({ type: "submitted_credentials", formRef: "f1", username: USER, password: PASS, isNew: false }, { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
    (t.flow as unknown as { pending: Map<number, { uncertain?: boolean }> }).pending.get(7)!.uncertain = true;
    t.flow.onAnalysis(page(false), { tabId: 7, frameId: 0, origin: SITE, documentId: "doc-1" });
    await t.timers.advance(SETTLE_MS);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    expect(t.ops()).not.toContain("save_login");
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("the remembered vault gone, the default left is shared: the card, one vault list only", async () => {
    const t = auto({ vaults: [{ id: "vs", name: "Équipe", color: null, shared: true }] });
    await t.signIn();
    expect(t.ops()).toEqual(["check_credentials", "vaults"]);
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.view).toBeUndefined();
  });

  it("new login: one vault list, then save_login", async () => {
    const t = auto();
    await t.signIn();
    expect(t.ops()).toEqual(["check_credentials", "vaults", "save_login"]);
  });

  it("never-save site gets nothing", async () => {
    const t = auto({ never: ["atlas-cloud.test"] });
    await t.signIn();
    expect(t.requests).toEqual([]);
    expect(t.opened).toEqual([]);
  });

  it("confirmed generated password shows the toast without Undo or Edit", async () => {
    const t = auto();
    t.flow.rememberGenerated(7, SITE, "Gen-Pass-9");
    expect(await t.flow.savePending(7, SITE, "Gen-Pass-9")).toBe(true);
    await t.signIn(USER, "Gen-Pass-9");
    expect(t.ops()).toEqual(["vaults", "save_login", "confirm_pending"]);
    expect(t.opened).toEqual([expect.objectContaining({ view: "toast", password: "" })]);
    expect(t.opened[0]?.undo).toBeUndefined();
    // Its toast takes no Edit: the bridge amends only what save_login wrote moments ago.
    await expect(t.prompts.edit(t.tokens[0] as string, { page: "save.html", tabId: 7 })).rejects.toThrow();
  });

  it("undo is per tab", async () => {
    const t = auto();
    await t.signIn(USER, PASS, 7);
    await t.signIn("sam@atlas.dev", "Other-Pass-2", 8);
    expect(t.opened.map((p) => [p.tabId, p.savedItemId])).toEqual([
      [7, "it_saved_1"],
      [8, "it_saved_2"],
    ]);
    const [a, b] = t.tokens as [string, string];
    // Tab B's page cannot use tab A's toast.
    await expect(t.prompts.undo(a, { page: "save.html", tabId: 8 })).rejects.toThrow();
    await t.prompts.undo(a, { page: "save.html", tabId: 7 });
    expect(t.requests.filter((r) => r.op === "undo_save")).toEqual([{ op: "undo_save", ctx: "save_prompt", item_id: "it_saved_1", origin: SITE }]);
    expect(b).not.toBe(a);
  });
});
