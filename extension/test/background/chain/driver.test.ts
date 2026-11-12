// The chain driver and the save / link proposals wired in the background
// (createBackground with the real ChainRunner), against fake browser and host.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PAGE_ALERT_WAIT_MS, SETTLE_MS } from "../../../src/background/chain/save-flow";
import { type BackgroundOptions, createBackground } from "../../../src/background/app";
import type { ChainRunner } from "../../../src/background/chain/driver";
import { UNKNOWN_MS } from "../../../src/background/chain/machine";
import type { StartOptions } from "../../../src/background/chain/types";
import { BgError } from "../../../src/background/session";
import { BridgeAppError } from "../../../src/bridge/client";
import { MemoryPairingStore, Store } from "../../../src/background/store";
import type { FormInfo, PageAnalysis } from "../../../src/shared/messages";
import { UNLOCK_WAIT_MS } from "../../../src/shared/unlock";
import { type Answer, FakeClient, record } from "../fake-client";
import { FakeExt, csSender, uiSender } from "../fake-ext";

const SITE = "https://atlas-cloud.test";
const GOOGLE = "https://accounts.google.com";

const summary = (id: string, extra: Record<string, unknown> = {}) => ({
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
  ...extra,
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

const page = (url: string, forms: FormInfo[] = [], extra: Partial<PageAnalysis> = {}): PageAnalysis => ({
  url,
  forms,
  captcha: false,
  push: false,
  providerButtons: [],
  accountChooser: [],
  ...extra,
});

function answerWith(over: Partial<Record<string, (r: Record<string, unknown>) => unknown>> = {}): Answer {
  return (r) => {
    const o = over[r.op as string];
    if (o) return o(r);
    switch (r.op) {
      case "list_for_origin":
        return r.origin === SITE
          ? {
              items: [
                summary("it_01"),
                summary("it_02", {
                  title: "Atlas Pro",
                  has_password: false,
                  methods: [{ provider: "google", account_email: "alex.pro@example.com" }],
                }),
              ],
            }
          : { items: [] };
      case "fill_login":
        return { username: "alex@atlas.dev", password: "Atlas-Pass-1" };
      case "fill_provider":
        return { password: "Google-Pass-2" };
      case "provider_accounts":
        return {
          accounts: [
            summary("g_perso", { title: "Google", subtitle: "alex.perso@example.com" }),
            summary("g_pro", { title: "Google", subtitle: "alex.pro@example.com" }),
          ],
        };
      case "check_credentials":
        return { status: "new" };
      case "vaults":
        return { vaults: [{ id: "v1", name: "Personnel", color: null }] };
      case "generate":
        return { password: "Gen-Pass-123", entropy_bits: 90 };
      default:
        return {};
    }
  };
}

async function setup(answer: Answer = answerWith(), ext = new FakeExt(), clock = { t: 1_000_000 }, more: Partial<BackgroundOptions> = {}) {
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(answer);
  const bg = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, now: () => clock.t, ...more });
  bg.install();
  const runner = bg.runner as ChainRunner;
  return { ext, client, bg, runner, clock };
}

type T = Awaited<ReturnType<typeof setup>>;

/** The content script of the top frame reports an analysis. */
async function analyze(t: T, url: string, a: PageAnalysis, doc = "doc-1", tabId = 7) {
  t.ext.setFrame(tabId, 0, url, doc);
  await t.ext.send({ type: "page_analysis", analysis: a }, csSender(url, tabId, 0, { documentId: doc }));
  // `state` runs after the queued work of the tab.
  await t.runner.state(tabId);
}

/** The content script of a child frame reports an analysis. */
async function analyzeFrame(t: T, frameId: number, url: string, a: PageAnalysis, doc: string, tabId = 7) {
  t.ext.setFrame(tabId, frameId, url, doc);
  await t.ext.send({ type: "page_analysis", analysis: a }, csSender(url, tabId, frameId, { documentId: doc }));
  await t.runner.state(tabId);
}

const ops = (t: T) => t.client.requests.map((r) => r.op);
type Sent = { type: string; kind?: string; url?: string; opts: { frameId?: number; documentId?: string } } & Record<string, unknown>;
const toTab = (t: T, type: string): Sent[] =>
  t.ext.sentToTabs
    .filter((m) => (m.message as { type: string }).type === type)
    .map((m) => ({ ...(m.message as { type: string }), opts: m.options }));

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("chain driver", () => {
  it("one page: fills just the needed fields with ctx chain, submits, then done back on the site", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    const fill = t.client.requests.find((r) => r.op === "fill_login");
    expect(fill).toEqual({ op: "fill_login", ctx: "chain", item_id: "it_01", origin: SITE, fields: ["username", "password"] });
    expect(toTab(t, "fill").at(-1)).toMatchObject({ formRef: "f1", origin: SITE, opts: { documentId: "doc-1" } });
    expect(toTab(t, "submit")).toEqual([{ type: "submit", origin: SITE, ref: "f1", opts: { documentId: "doc-1" } }]);
    // The persisted state holds no secret.
    expect(JSON.stringify([...t.ext.session.data.entries()])).not.toContain("Atlas-Pass-1");

    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    expect((await t.runner.state(7))?.status).toBe("running");
    // Done once the page had time to build a late form (spec B1).
    t.clock.t += UNKNOWN_MS;
    const v = await t.runner.state(7);
    expect(v?.status).toBe("done");
    expect(v?.steps.map((s) => s.label)).toEqual(["Identifiant et mot de passe remplis", "Connecté"]);
  });

  it("shows the overlay on each page of a running chain", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    const before = toTab(t, "show_frame").length;
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, `${SITE}/login/code`, "doc-2");
    await analyze(t, `${SITE}/login/code`, page(`${SITE}/login/code`), "doc-2");
    const shows = toTab(t, "show_frame").slice(before);
    expect(shows.every((m) => (m as { kind: string }).kind === "overlay")).toBe(true);
    // doc-1 got the overlay when its sign-in form was reported; doc-2 because the chain runs.
    expect(before).toBe(1);
    expect(shows.map((m) => m.opts)).toEqual([{ documentId: "doc-2" }]);
  });

  it("a worker restart resumes without submitting the same page twice", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);
    // A new worker over the same storage.session (the old router is gone).
    t.ext.onMessage.listeners.length = 0;
    const t2 = await setup(answerWith(), t.ext, t.clock);
    await analyze(t2, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(ops(t2)).not.toContain("fill_login");
    expect((await t2.runner.state(7))?.status).toBe("running");
  });

  it("a commit outside the allowed domains stops the chain (domain)", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, "https://evil.test/phish", "doc-x");
    const v = await t.runner.state(7);
    expect(v).toMatchObject({ status: "handoff", reason: "domain", host: "evil.test" });
    await analyze(t, "https://evil.test/phish", page("https://evil.test/phish", [loginForm]), "doc-x");
    expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);
  });

  it("a fill the host gave no value for is never sent: the chain stops there", async () => {
    const t = await setup(answerWith({ fill_login: () => ({}) }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    expect(toTab(t, "fill")).toEqual([]);
    expect(toTab(t, "submit")).toEqual([]);
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "unknown" });
  });

  it("the bridge is told who fills: the first fill of a chain started on a row the user picked is that pick, every other fill is the chain's", async () => {
    const idOnly: FormInfo = { ref: "f0", kind: "login", fields: [{ ref: "u0", role: "email" }], submitRef: "b0" };
    const pwOnly: FormInfo = { ref: "f2", kind: "login", fields: [{ ref: "p1", role: "current_password" }], submitRef: "b2" };
    const fills = (t: T) => t.client.requests.filter((r) => r.op === "fill_login").map((r) => r.ctx);
    const twoSteps = async (opts: StartOptions) => {
      const t = await setup();
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [idOnly]));
      await t.runner.start(7, "it_01", undefined, opts);
      t.ext.navigate(7, 0, `${SITE}/password`, "doc-2");
      await analyze(t, `${SITE}/password`, page(`${SITE}/password`, [pwOnly]), "doc-2");
      return t;
    };
    // A row clicked in the menu: the bridge serves an associated-domain login to that pick only.
    expect(fills(await twoSteps({ picked: "menu" }))).toEqual(["menu", "chain"]);
    // A plan, the card's button: nobody picked a row.
    expect(fills(await twoSteps({}))).toEqual(["chain", "chain"]);
    expect(fills(await twoSteps({ planned: { roles: ["email"], intent: "login" } }))).toEqual(["chain", "chain"]);
  });

  describe("a chain that leaves the site's domain (associated domains)", () => {
    const OTHER = "https://atlas-id.test";
    /** The plan the bridge gives on the other origin. */
    const withPlan = (plan: Record<string, unknown>) =>
      setup(
        answerWith({
          list_for_origin: (r) => (r.origin === SITE || r.origin === OTHER ? { items: [summary("it_01")] } : { items: [] }),
          plan_fill: () => ({ plan: { intent: "login", action: "open_chain", confidence: "high", alternatives: [], reasons: ["single_candidate"], groups: [], ...plan } }),
        }),
      );
    const group = (item: string) => ({ form_ref: "f1", kind: "login", item_id: item, fields: [{ field_ref: "u1", role: "email" }, { field_ref: "p1", role: "current_password" }] });
    const context = { forms: [{ form_ref: "f1", intent_hints: { kind: "login", signup_words: false, reset_words: false, checkout_words: false, ignore: false }, step_index: null, fields: [], buttons: [] }], typed_username_hash: null };
    const userOnly: FormInfo = { ref: "f0", kind: "login", fields: [{ ref: "u0", role: "email" }], submitRef: "b0" };

    async function leave(t: T) {
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userOnly]));
      await t.runner.start(7, "it_01");
      t.ext.tabReply = (_tab, m) => ((m as { type: string }).type === "plan_request" ? { ok: true, context } : undefined);
      t.ext.navigate(7, 0, `${OTHER}/password`, "doc-o");
      // The stop stands until the bridge has spoken.
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain", host: "atlas-id.test" });
      await analyze(t, `${OTHER}/password`, page(`${OTHER}/password`, [loginForm]), "doc-o");
    }

    it("goes on when the bridge's plan there names the chain's own item as a normal match", async () => {
      const t = await withPlan({ groups: [group("it_01")] });
      await leave(t);
      expect(t.client.requests.find((r) => r.op === "plan_fill")).toMatchObject({ origin: OTHER });
      expect(await t.runner.state(7)).toMatchObject({ status: "running" });
      expect(t.client.requests.filter((r) => r.op === "fill_login").at(-1)).toMatchObject({ origin: OTHER, item_id: "it_01" });
      expect(toTab(t, "submit").at(-1)).toMatchObject({ origin: OTHER, ref: "f1" });
      // That host only: a third one stops as before, and is not asked about twice.
      t.ext.navigate(7, 0, "https://evil.test/x", "doc-e");
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain", host: "evil.test" });
    });

    it("stays stopped on a first use through Apple's shared credentials (associated_domain): the page's own offer shows", async () => {
      const t = await withPlan({ groups: [group("it_01")], action: "show_menu", confidence: "low", reasons: ["associated_domain"] });
      await leave(t);
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain" });
      expect(t.client.requests.filter((r) => r.op === "fill_login")).toHaveLength(1);
      expect(toTab(t, "submit").filter((m) => m.origin === OTHER)).toEqual([]);
    });

    it("stays stopped when the plan there names the item but would not send it (a fill the user sends, a menu)", async () => {
      for (const over of [{ action: "fill", confidence: "medium" }, { action: "show_menu", confidence: "low", reasons: ["tie"] }]) {
        const t = await withPlan({ groups: [group("it_01")], ...over });
        await leave(t);
        expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain" });
        expect(t.client.requests.filter((r) => r.op === "fill_login")).toHaveLength(1);
        expect(toTab(t, "submit").filter((m) => m.origin === OTHER)).toEqual([]);
      }
    });

    it("stays stopped when the plan there names another item, or none", async () => {
      for (const groups of [[group("it_77")], []]) {
        const t = await withPlan({ groups });
        await leave(t);
        expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain" });
        expect(t.client.requests.filter((r) => r.op === "fill_login")).toHaveLength(1);
      }
    });

    it("never to an http page, and never past the chain's deadline", async () => {
      const t = await withPlan({ groups: [group("it_01")] });
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userOnly]));
      await t.runner.start(7, "it_01");
      t.ext.navigate(7, 0, "http://atlas-id.test/password", "doc-o");
      await analyze(t, "http://atlas-id.test/password", page("http://atlas-id.test/password", [loginForm]), "doc-o");
      expect(t.client.requests.filter((r) => r.op === "plan_fill")).toEqual([]);
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain" });
    });
  });

  describe("a popup window the chain's own click on a provider button opened", () => {
    const sso = () => page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] });
    const pwd = page(`${GOOGLE}/pwd`, [{ ref: "gp", kind: "login", fields: [{ ref: "p", role: "current_password" }] }]);

    async function clicked() {
      const t = await setup();
      await analyze(t, `${SITE}/login`, sso());
      await t.runner.start(7, "it_02", "google");
      expect(toTab(t, "click")).toHaveLength(1);
      return t;
    }

    it("is followed: the provider's pages are filled there, the site signs in behind", async () => {
      const t = await clicked();
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      t.ext.setFrame(9, 0, `${GOOGLE}/pwd`, "doc-g");
      await t.ext.send({ type: "page_analysis", analysis: pwd }, csSender(`${GOOGLE}/pwd`, 9, 0, { documentId: "doc-g" }));
      await t.runner.state(7);
      expect(t.client.requests.find((r) => r.op === "fill_provider")).toMatchObject({ provider: "google", provider_origin: GOOGLE, site_origin: SITE });
      const fill = t.ext.sentToTabs.find((m) => (m.message as { type: string }).type === "fill");
      expect(fill).toMatchObject({ tabId: 9, options: { documentId: "doc-g" } });
      expect(t.ext.sentToTabs.filter((m) => (m.message as { type: string }).type === "submit").at(-1)).toMatchObject({ tabId: 9 });
      // No sign-in card is offered inside the popup.
      expect(t.ext.sentToTabs.filter((m) => m.tabId === 9 && (m.message as { type: string }).type === "show_frame")).toEqual([]);
      // The popup closes, the site page no longer asks to sign in: done.
      t.ext.onRemoved.emit(9);
      await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-1");
      t.clock.t += UNKNOWN_MS + 1;
      await vi.advanceTimersByTimeAsync(UNKNOWN_MS + 1);
      expect(await t.runner.state(7)).toMatchObject({ status: "done" });
    });

    describe("a browser that tells which frame opened the tab (webNavigation.onCreatedNavigationTarget)", () => {
      const follows = async (t: T) => {
        t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
        t.ext.setFrame(9, 0, `${GOOGLE}/pwd`, "doc-g");
        await t.ext.send({ type: "page_analysis", analysis: pwd }, csSender(`${GOOGLE}/pwd`, 9, 0, { documentId: "doc-g" }));
        await t.runner.state(7);
        return ops(t).includes("fill_provider");
      };
      async function clickedIn() {
        const t = await setup(answerWith(), new FakeExt().withNavigationTargets());
        await analyze(t, `${SITE}/login`, sso());
        await t.runner.start(7, "it_02", "google");
        expect(toTab(t, "click")).toHaveLength(1);
        return t;
      }

      it("follows the tab the frame of the chain's click opened", async () => {
        const t = await clickedIn();
        t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
        t.ext.onTarget.emit({ tabId: 9, sourceTabId: 7, sourceFrameId: 0, url: "about:blank" });
        expect(await follows(t)).toBe(true);
      });

      it("never a tab another frame of the chain's tab opened right then (an embedded frame racing the click)", async () => {
        const t = await clickedIn();
        t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
        t.ext.onTarget.emit({ tabId: 9, sourceTabId: 7, sourceFrameId: 4, url: `${GOOGLE}/pwd` });
        expect(await follows(t)).toBe(false);
      });

      it("never on the opener alone: no frame named, no adoption", async () => {
        const t = await clickedIn();
        t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
        expect(await follows(t)).toBe(false);
      });
    });

    it("stops on anything but the provider's exact hosts", async () => {
      const t = await clicked();
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, "https://accounts.google.com.evil.test/pwd", "doc-e");
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain", host: "accounts.google.com.evil.test" });
      t.ext.setFrame(9, 0, "https://accounts.google.com.evil.test/pwd", "doc-e");
      await t.ext.send({ type: "page_analysis", analysis: { ...pwd, url: "https://accounts.google.com.evil.test/pwd" } }, csSender("https://accounts.google.com.evil.test/pwd", 9, 0, { documentId: "doc-e" }));
      await t.runner.state(7);
      expect(ops(t)).not.toContain("fill_provider");
    });

    it("only a tab the chain's tab opened, right after the chain's own click", async () => {
      // Opened by another tab.
      let t = await clicked();
      t.ext.onCreated.emit({ id: 9, openerTabId: 8 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      await t.ext.send({ type: "page_analysis", analysis: pwd }, csSender(`${GOOGLE}/pwd`, 9, 0, { documentId: "doc-g" }));
      await t.runner.state(7);
      expect(ops(t)).not.toContain("fill_provider");
      // Opened long after the click.
      t = await clicked();
      t.clock.t += 30_000;
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      await t.ext.send({ type: "page_analysis", analysis: pwd }, csSender(`${GOOGLE}/pwd`, 9, 0, { documentId: "doc-g" }));
      await t.runner.state(7);
      expect(ops(t)).not.toContain("fill_provider");
      // A password chain (no provider click of its own) follows nothing.
      t = await setup();
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      await t.runner.start(7, "it_01");
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      await t.ext.send({ type: "page_analysis", analysis: pwd }, csSender(`${GOOGLE}/pwd`, 9, 0, { documentId: "doc-g" }));
      await t.runner.state(7);
      expect(ops(t)).not.toContain("fill_provider");
    });

    it("keeps the chain's 60 s: the deadline stops it while the popup is open", async () => {
      const t = await clicked();
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      t.clock.t += 61_000;
      await vi.advanceTimersByTimeAsync(61_000);
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "timeout" });
    });

    it("closed with the site still asking to sign in: stopped, the button is not clicked again, the site is not blamed", async () => {
      const t = await clicked();
      t.ext.onCreated.emit({ id: 9, openerTabId: 7 });
      t.ext.navigate(9, 0, `${GOOGLE}/pwd`, "doc-g");
      t.ext.onRemoved.emit(9);
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "unknown" });
      expect(toTab(t, "click")).toHaveLength(1);
    });
  });

  it("stop: Arrêter from the overlay", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await t.runner.start(7, "it_01");
    await t.runner.stop(7);
    expect(await t.runner.state(7)).toMatchObject({ status: "stopped", reason: "user" });
  });

  it("locked during a fill stops the chain (locked)", async () => {
    const t = await setup(answerWith({ fill_login: () => new BgError("locked") }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "locked" });
    expect(toTab(t, "submit")).toEqual([]);
  });

  describe("locked mid-chain: the app is asked, and the chain goes on after the unlock without another click", () => {
    /** A vault that locks before the fill; the card of the tab polls `overlay_state`. */
    async function lockedChain(more: Partial<BackgroundOptions> = {}) {
      const vault: { locked: boolean; fillLocked?: boolean } = { locked: true };
      const opened = { n: 0 };
      const t = await setup(
        answerWith({
          fill_login: () => ((vault.fillLocked ?? vault.locked) ? new BgError("locked") : { username: "alex@atlas.dev", password: "Atlas-Pass-1" }),
          status: () => ({ locked: vault.locked, account: "Camille", vaults: 1 }),
          unlock: () => ({ locked: vault.locked }),
        }),
        new FakeExt(),
        { t: 1_000_000 },
        {
          openApp: async () => {
            opened.n++;
            return true;
          },
          ...more,
        },
      );
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      await t.runner.start(7, "it_01");
      const live = await t.bg.overlays.tokens.forTab(7);
      const token = live?.token ?? "";
      const poll = () => t.ext.send({ type: "overlay_state", token }, uiSender(`overlay.html#${token}`, 7)) as Promise<{ ok: { chain: { status: string; reason?: string } | null; waiting?: string } }>;
      return { ...t, vault, opened, poll };
    }

    it("stops locked, asks the app once, waits, then fills and submits from the step it could not run", async () => {
      const t = await lockedChain();
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "locked" });
      expect(t.opened.n).toBe(1);
      expect(ops(t).filter((o) => o === "unlock")).toHaveLength(1);
      expect(toTab(t, "submit")).toEqual([]);
      // The card waits: still locked.
      expect((await t.poll()).ok).toMatchObject({ chain: { status: "handoff", reason: "locked" }, waiting: "locked" });
      // What is kept for the resume holds no secret.
      const kept = JSON.stringify([...t.ext.session.data.entries()]);
      expect(kept).toContain("unlock-chain:7");
      expect(kept).not.toContain("Atlas-Pass-1");
      // Touch ID in the app.
      t.vault.locked = false;
      t.clock.t += 5_000;
      const r = await t.poll();
      expect(r.ok.chain?.status).toBe("running");
      expect(r.ok.waiting).toBeUndefined();
      expect(toTab(t, "fill")).toHaveLength(1);
      expect(toTab(t, "submit")).toEqual([{ type: "submit", origin: SITE, ref: "f1", opts: { documentId: "doc-1" } }]);
      // Once: later polls start nothing more, and nothing is kept.
      t.clock.t += 2_000;
      await t.poll();
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(2);
      expect(toTab(t, "submit")).toHaveLength(1);
      expect([...t.ext.session.data.keys()].some((k) => k.startsWith("unlock-chain:"))).toBe(false);
      expect(await t.runner.resumeLocked(7)).toBe(false);
      expect(t.opened.n).toBe(1);
    });

    it("the resumed chain gets a fresh deadline and ends done", async () => {
      const t = await lockedChain();
      t.vault.locked = false;
      // Touch ID took most of the chain's own 60 s.
      t.clock.t += 55_000;
      expect((await t.poll()).ok.chain?.status).toBe("running");
      t.clock.t += 10_000;
      t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
      t.ext.complete(7, 0);
      await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
      t.clock.t += UNKNOWN_MS;
      expect((await t.runner.state(7))?.status).toBe("done");
    });

    it("locked again at the resumed step: stopped for good, the app is not asked twice", async () => {
      const t = await lockedChain();
      t.clock.t += 5_000;
      // The status says open, the fill still finds the vault locked (it locked again at once).
      t.vault.fillLocked = true;
      t.vault.locked = false;
      expect((await t.poll()).ok).toEqual({ chain: expect.objectContaining({ status: "handoff", reason: "locked" }) });
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(2);
      expect(t.opened.n).toBe(1);
      expect(ops(t).filter((o) => o === "unlock")).toHaveLength(1);
      expect(await t.runner.resumeLocked(7)).toBe(false);
      t.clock.t += 2_000;
      expect((await t.poll()).ok.waiting).toBeUndefined();
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(2);
    });

    it("refused past the deadline, in another document, on another origin, and after Annuler or a new chain", async () => {
      // 90 s without the unlock: the card stops waiting, the stop stays with its retry.
      let t = await lockedChain();
      t.vault.locked = false;
      t.clock.t += UNLOCK_WAIT_MS + 1;
      expect((await t.poll()).ok).toEqual({ chain: expect.objectContaining({ status: "handoff", reason: "locked" }) });
      expect(await t.runner.resumeLocked(7)).toBe(false);
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);

      // The top frame holds another document of the site (no commit seen: the binding itself refuses).
      t = await lockedChain();
      t.vault.locked = false;
      t.ext.setFrame(7, 0, `${SITE}/login`, "doc-2");
      await t.poll();
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "locked" });
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);

      // Another origin in the tab.
      t = await lockedChain();
      t.vault.locked = false;
      t.ext.setFrame(7, 0, "https://evil.test/login", "doc-1");
      expect(await t.runner.resumeLocked(7)).toBe(false);
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);

      // A navigation of the top frame drops what was kept.
      t = await lockedChain();
      t.vault.locked = false;
      t.ext.navigate(7, 0, `${SITE}/other`, "doc-9");
      await t.runner.state(7);
      expect([...t.ext.session.data.keys()].some((k) => k.startsWith("unlock-chain:"))).toBe(false);

      // "Annuler" on the waiting card.
      t = await lockedChain();
      const live = await t.bg.overlays.tokens.forTab(7);
      await t.ext.send({ type: "overlay_stop", token: live?.token }, uiSender(`overlay.html#${live?.token}`, 7));
      t.vault.locked = false;
      t.clock.t += 2_000;
      expect((await t.poll()).ok.waiting).toBeUndefined();
      expect(await t.runner.resumeLocked(7)).toBe(false);
      expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);
    });

    it("a restarted worker still resumes: the request and the chain's step live in storage.session", async () => {
      const t = await lockedChain();
      t.vault.locked = false;
      t.ext.onMessage.listeners.length = 0;
      const t2 = await setup(answerWith({ status: () => ({ locked: false, account: "Camille", vaults: 1 }) }), t.ext, t.clock);
      const live = await t2.bg.overlays.tokens.forTab(7);
      t.clock.t += 5_000;
      const r = (await t2.ext.send({ type: "overlay_state", token: live?.token }, uiSender(`overlay.html#${live?.token}`, 7))) as { ok: { chain: { status: string } } };
      expect(r.ok.chain.status).toBe("running");
      expect(ops(t2).filter((o) => o === "fill_login")).toHaveLength(1);
      expect(toTab(t2, "submit")).toHaveLength(1);
    });

    it("locked on a later page of the chain: its card comes up waiting there, and the chain goes on after the unlock", async () => {
      const vault = { locked: false };
      const idForm: FormInfo = { ref: "f1", kind: "login", fields: [{ ref: "u1", role: "email" }], submitRef: "b1" };
      const pwForm: FormInfo = { ref: "f2", kind: "login", fields: [{ ref: "p1", role: "current_password" }], submitRef: "b2" };
      const guard = (r: Record<string, unknown>, ok: unknown) => (vault.locked ? new BgError("locked") : ok);
      const t = await setup(
        answerWith({
          list_for_origin: (r) => guard(r, { items: [summary("it_01")] }),
          fill_login: (r) => guard(r, { username: "alex@atlas.dev", password: "Atlas-Pass-1" }),
          status: () => ({ locked: vault.locked, account: "Camille", vaults: 1 }),
          unlock: () => ({ locked: vault.locked }),
        }),
        new FakeExt(),
        { t: 1_000_000 },
        { openApp: async () => true },
      );
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [idForm]));
      await t.runner.start(7, "it_01");
      expect(toTab(t, "submit")).toHaveLength(1);
      // The vault locks while the site loads its password page.
      vault.locked = true;
      t.ext.navigate(7, 0, `${SITE}/login/password`, "doc-2");
      t.ext.complete(7, 0);
      await analyze(t, `${SITE}/login/password`, page(`${SITE}/login/password`, [pwForm]), "doc-2");
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "locked" });
      // The card of the new page: it cannot list the logins (locked), it waits.
      const live = await t.bg.overlays.tokens.forTab(7);
      expect(live?.rec.documentId).toBe("doc-2");
      const ui = uiSender(`overlay.html#${live?.token}`, 7);
      expect(await t.ext.send({ type: "overlay_init", token: live?.token }, ui)).toEqual({
        ok: { origin: SITE, accounts: [], chain: expect.objectContaining({ status: "handoff", reason: "locked" }), waiting: "locked" },
      });
      vault.locked = false;
      t.clock.t += 3_000;
      const r = (await t.ext.send({ type: "overlay_state", token: live?.token }, ui)) as { ok: { chain: { status: string }; waiting?: string } };
      expect(r.ok.chain.status).toBe("running");
      expect(toTab(t, "fill").at(-1)).toMatchObject({ formRef: "f2", opts: { documentId: "doc-2" } });
      expect(toTab(t, "submit").at(-1)).toEqual({ type: "submit", origin: SITE, ref: "f2", opts: { documentId: "doc-2" } });
      expect(toTab(t, "submit")).toHaveLength(2);
    });

    it("iOS: the worker never prompts by itself; the app that cannot be opened: the plain stop, retry by a click", async () => {
      let t = await lockedChain({ nativeVault: async () => ({ locked: true, account: "Camille", biometry: "faceID" }) });
      expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "locked" });
      expect(t.opened.n).toBe(0);
      expect((await t.poll()).ok.waiting).toBeUndefined();
      expect([...t.ext.session.data.keys()].some((k) => k.startsWith("unlock-chain:"))).toBe(false);

      t = await lockedChain({ openApp: async () => false });
      expect((await t.poll()).ok.waiting).toBeUndefined();
      expect([...t.ext.session.data.keys()].some((k) => k.startsWith("unlock-chain:"))).toBe(false);
    });
  });

  it("auto-submit off for the item: fills, no submit", async () => {
    const t = await setup();
    await t.ext.local.set({ "autoSubmit:it_01": false });
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    expect(toTab(t, "fill")).toHaveLength(1);
    expect(toTab(t, "submit")).toEqual([]);
  });

  it("deadline fires by timer after 60 s", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await t.runner.start(7, "it_01");
    t.ext.navigate(7, 0, `${SITE}/slow`, "doc-2");
    await t.runner.state(7);
    t.clock.t += 60_000;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "timeout" });
  });

  it("provider chain: clicks the button, the right account, fills Google with fill_provider", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }));
    await t.runner.start(7, "it_02", "google");
    expect(toTab(t, "click")).toEqual([{ type: "click", origin: SITE, ref: "g1", opts: { documentId: "doc-1" } }]);

    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g");
    const chooser = page(`${GOOGLE}/chooser`, [], {
      accountChooser: [
        { email: "alex.perso@example.com", ref: "a1" },
        { email: "alex.pro@example.com", ref: "a2" },
      ],
    });
    await analyze(t, `${GOOGLE}/chooser`, chooser, "doc-g");
    expect(toTab(t, "click").at(-1)).toMatchObject({ origin: GOOGLE, ref: "a2" });

    await analyze(t, `${GOOGLE}/pwd`, page(`${GOOGLE}/pwd`, [{ ref: "gp", kind: "login", fields: [{ ref: "p", role: "current_password" }] }]), "doc-g");
    expect(t.client.requests.find((r) => r.op === "fill_provider")).toEqual({
      op: "fill_provider",
      ctx: "chain",
      account_item_id: "g_pro",
      provider: "google",
      provider_origin: GOOGLE,
      site_origin: SITE,
      fields: ["password"],
    });
    expect(toTab(t, "submit").at(-1)).toMatchObject({ origin: GOOGLE, ref: "gp" });
  });

  it("provider chain via the linked item: the chooser picks that account, the one filled", async () => {
    // The method says alex.pro, no account has that email; the linked item is alex.perso.
    const t = await setup(
      answerWith({
        provider_accounts: () => ({
          accounts: [summary("g_perso", { title: "Google", subtitle: "alex.perso@example.com" })],
          linked_item_id: "g_perso",
        }),
      }),
    );
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }));
    await t.runner.start(7, "it_02", "google");
    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g");
    const chooser = page(`${GOOGLE}/chooser`, [], {
      accountChooser: [
        { email: "alex.perso@example.com", ref: "a1" },
        { email: "alex.pro@example.com", ref: "a2" },
      ],
    });
    await analyze(t, `${GOOGLE}/chooser`, chooser, "doc-g");
    expect(toTab(t, "click").at(-1)).toMatchObject({ origin: GOOGLE, ref: "a1" });
    await analyze(t, `${GOOGLE}/pwd`, page(`${GOOGLE}/pwd`, [{ ref: "gp", kind: "login", fields: [{ ref: "p", role: "current_password" }] }]), "doc-g");
    expect(t.client.requests.find((r) => r.op === "fill_provider")).toMatchObject({ account_item_id: "g_perso" });
  });

  it("a picked account is the one chosen on the provider and filled, then remembered for the site", async () => {
    const t = await setup();
    const chooser = page(`${GOOGLE}/chooser`, [], {
      accountChooser: [
        { email: "alex.perso@example.com", ref: "a1" },
        { email: "alex.pro@example.com", ref: "a2" },
      ],
    });
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }));
    // Not one of the provider's accounts: refused, nothing clicked.
    await expect(t.runner.start(7, "it_02", "google", { accountId: "it_01" })).rejects.toMatchObject({ code: "not_found" });
    expect(toTab(t, "click")).toEqual([]);
    await t.runner.start(7, "it_02", "google", { accountId: "g_perso" });
    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g");
    await analyze(t, `${GOOGLE}/chooser`, chooser, "doc-g");
    expect(toTab(t, "click").at(-1)).toMatchObject({ origin: GOOGLE, ref: "a1" });
    expect((await t.ext.storage.local.get("signin:atlas-cloud.test|google"))["signin:atlas-cloud.test|google"]).toBe("g_perso");

    // Next time on the site, with no pick: the remembered account, not the method's.
    await t.runner.stop(7);
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }), "doc-2");
    await t.runner.start(7, "it_02", "google");
    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g2");
    await analyze(t, `${GOOGLE}/chooser`, chooser, "doc-g2");
    expect(toTab(t, "click").at(-1)).toMatchObject({ origin: GOOGLE, ref: "a1" });
  });

  it("the view says what happens now, and names the account", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }));
    await t.runner.start(7, "it_02", "google");
    expect(await t.runner.state(7)).toMatchObject({
      status: "running",
      title: "Atlas Pro",
      provider: "google",
      email: "alex.pro@example.com",
      site: "atlas-cloud.test",
      phase: "opening",
    });
    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g");
    await analyze(t, `${GOOGLE}/chooser`, page(`${GOOGLE}/chooser`, [], { accountChooser: [{ email: "alex.pro@example.com", ref: "a2" }] }), "doc-g");
    expect((await t.runner.state(7))?.phase).toBe("choosing");
    t.ext.navigate(7, 0, `${GOOGLE}/pwd`, "doc-g2");
    expect((await t.runner.state(7))?.phase).toBe("provider");
    await analyze(t, `${GOOGLE}/pwd`, page(`${GOOGLE}/pwd`, [{ ref: "gp", kind: "login", fields: [{ ref: "p", role: "current_password" }] }]), "doc-g2");
    expect((await t.runner.state(7))?.phase).toBe("back");
  });

  it("started from the menu, the progress shows under the field; a stop on another domain shows there once", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    // The overlay offered on that page is replaced by the menu, then by the progress under the field.
    const shown = () => toTab(t, "show_frame").filter((m) => m.kind === "overlay");
    const before = shown().length;
    await t.runner.start(7, "it_01", undefined, { anchorRef: "u1" });
    expect(shown().length).toBeGreaterThanOrEqual(before);
    t.ext.navigate(7, 0, "https://evil.test/phish", "doc-x");
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "domain" });
    // The token died with the page: the next page shows why the chain stopped, once.
    const n = shown().length;
    await analyze(t, "https://evil.test/phish", page("https://evil.test/phish"), "doc-x");
    expect(shown().length).toBe(n + 1);
    expect(shown().at(-1)?.ref).toBeUndefined();
    await analyze(t, "https://evil.test/phish", page("https://evil.test/phish", [loginForm]), "doc-x");
    expect(shown().length).toBe(n + 1);
    expect(ops(t).filter((o) => o === "fill_login")).toHaveLength(1);
  });

  it("an outcome a live overlay already showed does not follow the user to the next page", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/captcha`, page(`${SITE}/captcha`, [loginForm], { captcha: true }), "doc-1");
    await t.runner.start(7, "it_01");
    expect(await t.runner.state(7)).toMatchObject({ status: "handoff", reason: "captcha" });
    // The overlay of that page opens on the ended chain and shows "CAPTCHA détecté" (no poll follows).
    expect(await t.runner.state(7, true, "doc-1")).toMatchObject({ reason: "captcha" });
    const shown = () => toTab(t, "show_frame").filter((m) => m.kind === "overlay");
    const n = shown().length;
    // The user goes on to another page of the site with no form: no outcome shown again.
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    expect(shown().length).toBe(n);
    // An overlay opening there (the offer of a sign-in form) gets no ended chain: the offer shows.
    expect(await t.runner.state(7, true, "doc-2")).toBeNull();
    // The page where it ended still shows it.
    expect(await t.runner.state(7, true, "doc-1")).toMatchObject({ reason: "captcha" });
  });

  it("no overlay offer over an open menu", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    await t.ext.send({ type: "open_menu", fieldRef: "u1", formRef: "f1", formKind: "login" }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(toTab(t, "show_frame").filter((m) => m.kind === "overlay")).toEqual([]);
  });

  it("start refuses an item the site does not have, and a provider-only item without its provider", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    await expect(t.runner.start(7, "it_99")).rejects.toMatchObject({ code: "not_found" });
    await expect(t.runner.start(7, "it_02")).rejects.toMatchObject({ code: "invalid" });
    t.ext.setFrame(7, 0, "http://atlas-cloud.test/login");
    await expect(t.runner.start(7, "it_01")).rejects.toMatchObject({ code: "insecure_origin" });
    // http on a loopback host is a page: the bridge is asked (it lists nothing of this site there).
    t.ext.setFrame(7, 0, "http://localhost:3000/login", "doc-1");
    await expect(t.runner.start(7, "it_01")).rejects.toMatchObject({ code: "not_found" });
    t.ext.setFrame(7, 0, "http://app.localhost:3000/login", "doc-1");
    await expect(t.runner.start(7, "it_01")).rejects.toMatchObject({ code: "insecure_origin" });
  });

  it("overlay_start from the overlay runs the real chain", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    const show = toTab(t, "show_frame").at(-1) as { url: string } | undefined;
    expect(show?.url).toContain("overlay.html#");
    const token = show!.url.slice(show!.url.indexOf("#") + 1);
    const ui = uiSender(`overlay.html#${token}`, 7);
    await t.ext.send({ type: "overlay_init", token }, ui);
    expect(await t.ext.send({ type: "overlay_start", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    const st = (await t.ext.send({ type: "overlay_state", token }, ui)) as { ok: { chain: { status: string } } };
    expect(st.ok.chain.status).toBe("running");
    expect(toTab(t, "submit")).toHaveLength(1);
  });
});

describe("re-rendered forms (B2)", () => {
  it("a submit that missed its re-rendered form is sent to the copy, once", async () => {
    const t = await setup();
    const send = t.ext.tabs.sendMessage;
    t.ext.tabs.sendMessage = async (tabId, message, options) => {
      await send(tabId, message, options);
      // The form was re-rendered by the fill: the old ref is gone.
      return (message as { type: string; ref?: string }).type === "submit" && (message as { ref?: string }).ref === "f1" ? { ok: false } : { ok: true };
    };
    const userOnly: FormInfo = { ref: "f1", kind: "login", fields: [{ ref: "u1", role: "email" }] };
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userOnly]));
    await t.runner.start(7, "it_01");
    expect(toTab(t, "fill")).toHaveLength(1);
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [{ ...userOnly, ref: "f9", fields: [{ ref: "u9", role: "email" }] }]));
    expect(toTab(t, "submit").map((m) => m.ref)).toEqual(["f1", "f9"]);
    expect(toTab(t, "fill")).toHaveLength(1);
    expect((await t.runner.state(7))?.status).toBe("running");
  });
});

describe("overlay offer", () => {
  it("on a sign-in page of a site with logins, once per document", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(toTab(t, "show_frame").filter((m) => (m as { kind: string }).kind === "overlay")).toHaveLength(1);
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-2");
    expect(toTab(t, "show_frame").filter((m) => (m as { kind: string }).kind === "overlay")).toHaveLength(2);
  });

  describe("a sign-in page reached with the vault locked: a generic card", () => {
    const lockedLists = () => answerWith({ list_for_origin: () => new BridgeAppError("locked", "vault locked") });
    const shown = (t: T) => toTab(t, "show_frame").filter((m) => (m as { kind: string }).kind === "overlay");
    const tokenOf = (t: T) => {
      const url = (shown(t).at(-1) as { url: string }).url;
      return url.slice(url.indexOf("#") + 1);
    };

    it("is offered once per sign-in form of the document, and holds nothing of the vault", async () => {
      const t = await setup(lockedLists());
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      expect(shown(t)).toHaveLength(1);
      const token = tokenOf(t);
      expect(await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({ ok: { origin: SITE, accounts: [], chain: null, generic: true } });
      expect(t.ext.session.data.get(`overlay:${token}`)).toMatchObject({ generic: true });
      expect(JSON.stringify(t.ext.session.data.get(`overlay:${token}`))).not.toMatch(/it_0|alex/);
    });

    it("on a page with only provider buttons too; never on a page that is no sign-in", async () => {
      const t = await setup(lockedLists());
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }] }));
      expect(shown(t)).toHaveLength(1);
      const u = await setup(lockedLists());
      await analyze(u, `${SITE}/pricing`, page(`${SITE}/pricing`, [{ ref: "s", kind: "signup", fields: [{ ref: "e", role: "email" }, { ref: "n", role: "new_password" }] }]));
      await analyze(u, `${SITE}/pricing`, page(`${SITE}/pricing`));
      expect(shown(u)).toEqual([]);
    });

    it("on a passkey-only sign-in page too (no form, one passkey button); an open vault offers no card there", async () => {
      const passkeyPage = () => page(`${SITE}/login`, [], { passkeySignIn: true });
      const t = await setup(lockedLists());
      await analyze(t, `${SITE}/login`, passkeyPage());
      expect(shown(t)).toHaveLength(1);
      expect(await t.runner.signInPage(7, "doc-1")).toBe(true);
      const u = await setup();
      await analyze(u, `${SITE}/login`, passkeyPage());
      expect(shown(u)).toEqual([]);
      // A page that is none of these is no sign-in page.
      await analyze(u, `${SITE}/about`, page(`${SITE}/about`), "doc-2");
      expect(await u.runner.signInPage(7, "doc-2")).toBe(false);
    });

    it("never on a site set to 'never offer here', nor again in a document where the user closed it, nor when the app is missing or unpaired", async () => {
      const t = await setup(lockedLists());
      await t.bg.neverSave.add("atlas-cloud.test");
      await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      expect(shown(t)).toEqual([]);

      const u = await setup(lockedLists());
      await analyze(u, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
      const token = tokenOf(u);
      await u.ext.send({ type: "overlay_close", token }, uiSender(`overlay.html#${token}`, 7));
      await analyze(u, `${SITE}/login`, page(`${SITE}/login`, [{ ...loginForm, fields: [{ ref: "u1", role: "email" }] }]));
      expect(shown(u)).toHaveLength(1);

      for (const code of ["host_missing", "unpaired"] as const) {
        const v = await setup(answerWith({ list_for_origin: () => new BridgeAppError(code, code) }));
        await analyze(v, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
        expect(shown(v)).toEqual([]);
      }
    });
  });

  const overlays = (t: T) => toTab(t, "show_frame").filter((m) => (m as { kind: string }).kind === "overlay");
  const closeOverlay = async (t: T) => {
    const url = (overlays(t).at(-1) as { url: string }).url;
    const token = url.slice(url.indexOf("#") + 1);
    await t.ext.send({ type: "overlay_close", token }, uiSender(`overlay.html#${token}`, 7));
  };
  const userForm: FormInfo = { ref: "f1", kind: "login", fields: [{ ref: "u1", role: "email" }] };

  it("overlay_offered_when_sign_in_form_appears_later", async () => {
    let locked = true;
    const t = await setup(
      answerWith({
        list_for_origin: (r) => {
          if (locked) throw new BgError("host_missing");
          return answerWith()(r);
        },
      }),
    );
    // The page loads without a form, then builds one while the app is not there (locked: a generic card, below).
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userForm]));
    expect(overlays(t)).toHaveLength(0);
    // Unlocked; the page then shows its password field: a new analysis, offered.
    locked = false;
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(overlays(t)).toHaveLength(1);
  });

  it("a closed overlay stays closed for the rest of the document, whatever forms it cycles", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userForm]));
    expect(overlays(t)).toHaveLength(1);
    await closeOverlay(t);
    // The same form re-rendered (new refs), then another sign-in form: not offered.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [{ ...userForm, ref: "f7", fields: [{ ref: "u7", role: "email" }] }]));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(overlays(t)).toHaveLength(1);
    // A new document offers again.
    t.ext.navigate(7, 0, `${SITE}/login`, "doc-2");
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]), "doc-2");
    expect(overlays(t)).toHaveLength(2);
  });

  it("an offer the content script could not show is retried by the next analysis of that form", async () => {
    const t = await setup();
    const send = t.ext.tabs.sendMessage;
    let refuse = true;
    t.ext.tabs.sendMessage = async (tabId, message, options) => {
      if (refuse && (message as { type: string }).type === "show_frame") throw new Error("no receiving end");
      return send(tabId, message, options);
    };
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userForm]));
    expect(overlays(t)).toHaveLength(0);
    refuse = false;
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [{ ...userForm, ref: "f7", fields: [{ ref: "u7", role: "email" }] }]));
    expect(overlays(t)).toHaveLength(1);
  });

  const googleOnly = (extra: Partial<PageAnalysis> = {}) => page(`${SITE}/login`, [], { providerButtons: [{ provider: "google", ref: "g1" }], ...extra });
  const tokenOf = (t: T) => {
    const url = (overlays(t).at(-1) as { url: string }).url;
    return url.slice(url.indexOf("#") + 1);
  };

  it("sso_only_page_offers_overlay_for_linked_item", async () => {
    const t = await setup();
    // No sign-in form, just "Continue with Google"; it_02 signs in with Google.
    await analyze(t, `${SITE}/login`, googleOnly());
    expect(overlays(t).map((m) => m.opts)).toEqual([{ documentId: "doc-1" }]);
    // The same buttons again: not offered twice in the document.
    await analyze(t, `${SITE}/login`, googleOnly());
    expect(overlays(t)).toHaveLength(1);
    // The overlay offers the Google sign-in of it_02.
    const token = tokenOf(t);
    const init = (await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))) as {
      ok: { accounts: { itemId: string; provider?: string }[] };
    };
    expect(init.ok.accounts.some((a) => a.itemId === "it_02" && a.provider === "google")).toBe(true);
  });

  it("sso_only_page_without_linked_item_no_overlay", async () => {
    // The site's logins have no Google method: a Google-only page offers nothing.
    const t = await setup(answerWith({ list_for_origin: (r) => ({ items: r.origin === SITE ? [summary("it_01")] : [] }) }));
    await analyze(t, `${SITE}/login`, googleOnly());
    expect(overlays(t)).toEqual([]);
    // A button of another provider than the item's method: nothing either.
    const u = await setup();
    await analyze(u, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [{ provider: "apple", ref: "a1" }] }));
    expect(overlays(u)).toEqual([]);
    // Nor on a page of another site without logins.
    await analyze(u, "https://other.test/login", page("https://other.test/login", [], { providerButtons: [{ provider: "google", ref: "g1" }] }), "doc-o");
    expect(overlays(u)).toEqual([]);
  });

  it("sso_only_overlay_lists_only_linked_items", async () => {
    // it_01 (password only), it_02 (Google), it_03 (password and Apple).
    const items = [
      summary("it_01"),
      summary("it_02", { title: "Atlas Pro", has_password: false, methods: [{ provider: "google", account_email: "alex.pro@example.com" }] }),
      summary("it_03", { title: "Atlas Team", methods: [{ provider: "apple", account_email: "team@example.com" }] }),
    ];
    const t = await setup(answerWith({ list_for_origin: (r) => ({ items: r.origin === SITE ? items : [] }) }));
    await analyze(t, `${SITE}/login`, googleOnly());
    const token = tokenOf(t);
    const ui = uiSender(`overlay.html#${token}`, 7);
    const init = (await t.ext.send({ type: "overlay_init", token }, ui)) as { ok: { accounts: { itemId: string; provider?: string }[] } };
    // Only the Google sign-in: no password login, no method of a provider the page does not show.
    expect(init.ok.accounts.map((a) => [a.itemId, a.provider])).toEqual([["it_02", "google"]]);
    // A password start is refused, nothing is filled.
    expect(await t.ext.send({ type: "overlay_start", token, itemId: "it_01" }, ui)).toEqual({ err: "invalid" });
    expect(await t.ext.send({ type: "overlay_start", token, itemId: "it_03", provider: "apple" }, ui)).toEqual({ err: "invalid" });
    expect(ops(t)).not.toContain("fill_login");
  });

  it("a sign-in page with provider buttons still lists every login", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm], { providerButtons: [{ provider: "google", ref: "g1" }] }));
    const token = tokenOf(t);
    const init = (await t.ext.send({ type: "overlay_init", token }, uiSender(`overlay.html#${token}`, 7))) as {
      ok: { accounts: { itemId: string; provider?: string }[] };
    };
    expect(init.ok.accounts.map((a) => [a.itemId, a.provider])).toEqual([
      ["it_01", undefined],
      ["it_02", "google"],
    ]);
  });

  it("chain_starts_with_provider_click", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, googleOnly());
    const token = tokenOf(t);
    const ui = uiSender(`overlay.html#${token}`, 7);
    await t.ext.send({ type: "overlay_init", token }, ui);
    expect(await t.ext.send({ type: "overlay_start", token, itemId: "it_02", provider: "google" }, ui)).toEqual({ ok: {} });
    // First step: the click on the provider's button, pinned to the site's origin and document.
    expect(toTab(t, "click")).toEqual([{ type: "click", origin: SITE, ref: "g1", opts: { documentId: "doc-1" } }]);
    expect(toTab(t, "fill")).toEqual([]);
    const v = await t.runner.state(7);
    expect(v?.status).toBe("running");
    expect(v?.steps[0]?.label).toContain("Google");
  });

  it("not without logins for the site, nor without a sign-in form", async () => {
    const t = await setup();
    await analyze(t, "https://other.test/login", page("https://other.test/login", [loginForm]));
    await analyze(t, `${SITE}/about`, page(`${SITE}/about`), "doc-2");
    expect(toTab(t, "show_frame")).toEqual([]);
  });
});

describe("same-origin frames (C1)", () => {
  const overlays = (t: T) => toTab(t, "show_frame").filter((m) => (m as { kind: string }).kind === "overlay");
  const passwordForm: FormInfo = { ref: "f2", kind: "login", fields: [{ ref: "p2", role: "current_password" }] };

  it("same_origin_frame_form_offers_overlay", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    // Shown in the top frame's document, never in the child frame.
    expect(overlays(t).map((m) => m.opts)).toEqual([{ documentId: "doc-1" }]);
    // A re-analysis of the frame does not offer again.
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    expect(overlays(t)).toHaveLength(1);
  });

  it("chain_fills_same_origin_frame", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    const userOnly: FormInfo = { ref: "f1", kind: "login", fields: [{ ref: "u1", role: "email" }] };
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [userOnly]), "fdoc-1");
    await t.runner.start(7, "it_01");
    expect(t.client.requests.find((r) => r.op === "fill_login")).toMatchObject({ origin: SITE, fields: ["username"] });
    expect(toTab(t, "fill").at(-1)).toMatchObject({ formRef: "f1", origin: SITE, opts: { documentId: "fdoc-1" } });
    expect(toTab(t, "submit")).toEqual([{ type: "submit", origin: SITE, ref: "f1", opts: { documentId: "fdoc-1" } }]);
    // A top-frame analysis without a form changes nothing while the frame holds the step.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    expect((await t.runner.state(7))?.status).toBe("running");
    // The frame moves to its password step: the chain follows it there.
    t.ext.navigate(7, 3, `${SITE}/password`, "fdoc-2");
    t.ext.complete(7, 3);
    await analyzeFrame(t, 3, `${SITE}/password`, page(`${SITE}/password`, [passwordForm]), "fdoc-2");
    expect(toTab(t, "fill").at(-1)).toMatchObject({ formRef: "f2", opts: { documentId: "fdoc-2" } });
    expect(toTab(t, "submit").at(-1)).toMatchObject({ ref: "f2", opts: { documentId: "fdoc-2" } });
    // Signed in: the frame shows the account page, no form left.
    t.ext.navigate(7, 3, `${SITE}/home`, "fdoc-3");
    t.ext.complete(7, 3);
    await analyzeFrame(t, 3, `${SITE}/home`, page(`${SITE}/home`), "fdoc-3");
    t.clock.t += UNKNOWN_MS;
    const v = await t.runner.state(7);
    expect(v?.status).toBe("done");
    expect(v?.steps.map((s) => s.label)).toEqual(["Identifiant rempli", "Mot de passe rempli", "Connecté"]);
    // The overlay stayed in the top frame.
    expect(overlays(t).every((m) => m.opts.documentId === "doc-1")).toBe(true);
  });

  it("a provider button in the top frame does not hide the frame's password form from a password chain", async () => {
    const t = await setup();
    const google = { provider: "google" as const, ref: "g1" };
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [], { providerButtons: [google] }));
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    await t.runner.start(7, "it_01");
    expect(toTab(t, "fill").at(-1)).toMatchObject({ formRef: "f1", opts: { documentId: "fdoc-1" } });
  });

  it("a frame of the site nested in a third-party frame is excluded; nested in a frame of the site, it counts", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    t.ext.setFrame(7, 5, "https://widgets.evil.test/embed", "wdoc");
    t.ext.parents.set("7:6", 5);
    await analyzeFrame(t, 6, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    expect(overlays(t)).toEqual([]);
    await t.runner.start(7, "it_01");
    expect(ops(t)).not.toContain("fill_login");
    expect(toTab(t, "fill")).toEqual([]);
    // The middle frame is of the site: the nested form counts.
    const u = await setup();
    await analyze(u, `${SITE}/login`, page(`${SITE}/login`));
    u.ext.setFrame(7, 5, `${SITE}/shell`, "sdoc");
    u.ext.parents.set("7:6", 5);
    await analyzeFrame(u, 6, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    expect(overlays(u)).toHaveLength(1);
  });

  it("a frame that moves to another origin while the host answers gets no fill", async () => {
    let t: T | null = null;
    t = await setup(
      answerWith({
        fill_login: () => {
          t?.ext.setFrame(7, 3, "https://evil.test/frame", "edoc");
          return { username: "alex@atlas.dev", password: "Atlas-Pass-1" };
        },
      }),
    );
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    await t.runner.start(7, "it_01");
    expect(ops(t)).toContain("fill_login");
    expect(toTab(t, "fill")).toEqual([]);
    expect(toTab(t, "submit")).toEqual([]);
    expect(JSON.stringify(t.ext.sentToTabs)).not.toContain("Atlas-Pass-1");
  });

  it("a frame whose document changed since its analysis is not acted on", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyzeFrame(t, 3, `${SITE}/frame`, page(`${SITE}/frame`, [loginForm]), "fdoc-1");
    // The browser now reports another document in that frame (no commit seen yet).
    t.ext.setFrame(7, 3, `${SITE}/frame`, "fdoc-9");
    await t.runner.start(7, "it_01");
    expect(ops(t)).not.toContain("fill_login");
    expect(toTab(t, "fill")).toEqual([]);
  });

  it("same_site_other_origin_frame_excluded", async () => {
    const t = await setup();
    const sub = "https://login.atlas-cloud.test";
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyzeFrame(t, 3, `${sub}/frame`, page(`${sub}/frame`, [loginForm]), "fdoc-1");
    expect(overlays(t)).toEqual([]);
    await t.runner.start(7, "it_01");
    await analyzeFrame(t, 3, `${sub}/frame`, page(`${sub}/frame`, [loginForm]), "fdoc-1");
    expect(ops(t)).not.toContain("fill_login");
    expect(toTab(t, "fill")).toEqual([]);
    expect(toTab(t, "submit")).toEqual([]);
  });

  it("cross_site_frame_still_excluded", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyzeFrame(t, 3, "https://evil.test/frame", page("https://evil.test/frame", [loginForm]), "fdoc-1");
    expect(overlays(t)).toEqual([]);
    await t.runner.start(7, "it_01");
    await analyzeFrame(t, 3, "https://evil.test/frame", page("https://evil.test/frame", [loginForm]), "fdoc-1");
    expect(ops(t)).not.toContain("fill_login");
    expect(toTab(t, "fill")).toEqual([]);
  });
});

describe("save and link proposals (wired)", () => {
  it("a submission, a navigation, the new page loaded: check, then the save prompt", async () => {
    const t = await setup();
    await t.ext.send(
      { type: "submitted_credentials", formRef: "f1", username: "alex@atlas.dev", password: "Typed-1", isNew: false },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    );
    t.ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    t.ext.complete(7, 0);
    // The new page asks for no password: the sign-in went through.
    await analyze(t, `${SITE}/home`, page(`${SITE}/home`), "doc-2");
    // It counts once PAGE_ALERT_WAIT_MS passed without a page_alert (spec 5.3).
    await vi.advanceTimersByTimeAsync(PAGE_ALERT_WAIT_MS);
    expect(t.client.requests.find((r) => r.op === "check_credentials")).toEqual({
      op: "check_credentials",
      ctx: "save_prompt",
      origin: SITE,
      username: "alex@atlas.dev",
      password: "Typed-1",
    });
    // Pinned to the new top document, verified after the host answered.
    expect(toTab(t, "show_frame").at(-1)).toMatchObject({ kind: "save", opts: { documentId: "doc-2" } });
  });

  it("menu_generate feeds the proposal of a submission without identifier", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/signup`, "doc-1");
    // A change-password form: no pending save, the proposal opens at the submission.
    const r = (await t.ext.send(
      { type: "open_menu", fieldRef: "n1", formRef: "f9", formKind: "change_password" },
      csSender(`${SITE}/signup`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = r.ok.url.slice(r.ok.url.indexOf("#") + 1);
    const ui = uiSender(`menu.html#${token}`, 7);
    await t.ext.send({ type: "menu_init", token }, ui);
    await t.ext.send({ type: "menu_generate", token }, ui);
    await t.ext.send(
      { type: "submitted_credentials", formRef: "f9", username: "", password: "Gen-Pass-123", isNew: true },
      csSender(`${SITE}/signup`, 7, 0, { documentId: "doc-1" }),
    );
    // The form went away on the same document (a single-page app).
    await analyze(t, `${SITE}/signup`, page(`${SITE}/signup`), "doc-1");
    await vi.advanceTimersByTimeAsync(SETTLE_MS);
    expect(ops(t)).toContain("check_credentials");
    expect(toTab(t, "show_frame").at(-1)).toMatchObject({ kind: "save" });
  });

  it("menu_new_login opens the save prompt in its edit view", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    const r = (await t.ext.send(
      { type: "open_menu", fieldRef: "u1", formRef: "f1", formKind: "login" },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = r.ok.url.slice(r.ok.url.indexOf("#") + 1);
    const ui = uiSender(`menu.html#${token}`, 7);
    await t.ext.send({ type: "menu_init", token }, ui);
    expect(await t.ext.send({ type: "menu_new_login", token }, ui)).toEqual({ ok: {} });
    const show = toTab(t, "show_frame").at(-1) as { kind: string; url: string };
    expect(show.kind).toBe("save");
    const saveToken = show.url.slice(show.url.indexOf("#") + 1);
    const init = (await t.ext.send({ type: "save_init", token: saveToken }, uiSender(`save.html#${saveToken}`, 7))) as {
      ok: Record<string, unknown>;
    };
    expect(init.ok).toMatchObject({ origin: SITE, username: "", status: "new", kind: "login", view: "edit" });
    // Nothing typed nor generated: a login without a password is refused.
    const edits = { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v1", rule: "domain", tags: [] };
    const saveUi = uiSender(`save.html#${saveToken}`, 7);
    expect(await t.ext.send({ type: "save_decide", token: saveToken, decision: "save", edits }, saveUi)).toEqual({ err: "invalid" });
    expect(ops(t)).not.toContain("save_login");
    expect(
      await t.ext.send({ type: "save_decide", token: saveToken, decision: "save", edits: { ...edits, password: "Typed-Pass-9" } }, saveUi),
    ).toMatchObject({ ok: { outcome: "saved" } });
    expect(ops(t)).toContain("save_login");
  });

  it("back on the site after Google without a form: Enregistrer le lien prompt", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    await t.ext.send({ type: "provider_click", provider: "google", ref: "g1" }, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }));
    t.ext.navigate(7, 0, `${GOOGLE}/chooser`, "doc-g");
    await vi.advanceTimersByTimeAsync(0);
    await t.ext.send({ type: "account_click", email: "alex.pro@example.com", ref: "a2" }, csSender(`${GOOGLE}/chooser`, 7, 0));
    t.ext.navigate(7, 0, `${SITE}/app`, "doc-3");
    await analyze(t, `${SITE}/app`, page(`${SITE}/app`), "doc-3");
    await vi.advanceTimersByTimeAsync(0);
    const show = toTab(t, "show_frame").at(-1) as { kind: string; url: string };
    expect(show.kind).toBe("save");
    const saveToken = show.url.slice(show.url.indexOf("#") + 1);
    const ui = uiSender(`save.html#${saveToken}`, 7);
    const init = (await t.ext.send({ type: "save_init", token: saveToken }, ui)) as { ok: Record<string, unknown> };
    expect(init.ok).toMatchObject({ kind: "provider_link", provider: { id: "google", email: "alex.pro@example.com" } });
    expect(await t.ext.send({ type: "save_decide", token: saveToken, decision: "save" }, ui)).toEqual({ ok: { outcome: "done" } });
    expect(t.client.requests.at(-1)).toEqual({
      op: "link_provider",
      ctx: "save_prompt",
      site_origin: SITE,
      provider: "google",
      account_item_id: "g_pro",
    });
  });
});
