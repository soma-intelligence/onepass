// The chain driver and the save / link proposals wired in the background
// (createBackground with the real ChainRunner), against fake browser and host.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createBackground } from "../../../src/background/app";
import type { ChainRunner } from "../../../src/background/chain/driver";
import { UNKNOWN_MS } from "../../../src/background/chain/machine";
import { BgError } from "../../../src/background/session";
import { MemoryPairingStore, Store } from "../../../src/background/store";
import type { FormInfo, PageAnalysis } from "../../../src/shared/messages";
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

async function setup(answer: Answer = answerWith(), ext = new FakeExt(), clock = { t: 1_000_000 }) {
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(answer);
  const bg = createBackground(ext, { pairings, newClient: () => client, sleep: async () => undefined, now: () => clock.t });
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

  it("only frame 0 analyses drive the chain", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await t.runner.start(7, "it_01");
    t.ext.setFrame(7, 3, `${SITE}/frame`);
    await t.ext.send({ type: "page_analysis", analysis: page(`${SITE}/frame`, [loginForm]) }, csSender(`${SITE}/frame`, 7, 3));
    await t.runner.state(7);
    expect(ops(t)).not.toContain("fill_login");
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

  it("start refuses an item the site does not have, and a provider-only item without its provider", async () => {
    const t = await setup();
    t.ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    await expect(t.runner.start(7, "it_99")).rejects.toMatchObject({ code: "not_found" });
    await expect(t.runner.start(7, "it_02")).rejects.toMatchObject({ code: "invalid" });
    t.ext.setFrame(7, 0, "http://atlas-cloud.test/login");
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
          if (locked) throw new BgError("locked");
          return answerWith()(r);
        },
      }),
    );
    // The page loads without a form, then builds one while OnePass is locked.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`));
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userForm]));
    expect(overlays(t)).toHaveLength(0);
    // Unlocked; the page then shows its password field: a new analysis, offered.
    locked = false;
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(overlays(t)).toHaveLength(1);
  });

  it("a later sign-in form of the same document is offered again; its re-render is not", async () => {
    const t = await setup();
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [userForm]));
    expect(overlays(t)).toHaveLength(1);
    await closeOverlay(t);
    // The same form re-rendered (new refs): the user closed the overlay, it stays closed.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [{ ...userForm, ref: "f7", fields: [{ ref: "u7", role: "email" }] }]));
    expect(overlays(t)).toHaveLength(1);
    // A different sign-in form appears in the same document.
    await analyze(t, `${SITE}/login`, page(`${SITE}/login`, [loginForm]));
    expect(overlays(t)).toHaveLength(2);
  });

  it("not without logins for the site, nor without a sign-in form", async () => {
    const t = await setup();
    await analyze(t, "https://other.test/login", page("https://other.test/login", [loginForm]));
    await analyze(t, `${SITE}/about`, page(`${SITE}/about`), "doc-2");
    expect(toTab(t, "show_frame")).toEqual([]);
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
    await vi.advanceTimersByTimeAsync(0);
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
    const r = (await t.ext.send(
      { type: "open_menu", fieldRef: "n1", formRef: "f9", formKind: "signup" },
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
    await vi.advanceTimersByTimeAsync(1500);
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
    ).toEqual({ ok: {} });
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
    expect(await t.ext.send({ type: "save_decide", token: saveToken, decision: "save" }, ui)).toEqual({ ok: {} });
    expect(t.client.requests.at(-1)).toEqual({
      op: "link_provider",
      ctx: "save_prompt",
      site_origin: SITE,
      provider: "google",
      account_item_id: "g_pro",
    });
  });
});
