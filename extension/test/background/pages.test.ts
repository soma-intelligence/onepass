// Background handlers of the in-page extension pages: menu extras, overlay
// and save prompt.
import { describe, expect, it, vi } from "vitest";
import { createBackground } from "../../src/background/app";
import type { ChainDriver } from "../../src/background/chain/types";
import { contentSender } from "../../src/background/frames";
import { NEVER_SAVE_KEY } from "../../src/background/never-save";
import { SAVE_TTL_MS, titleFromSite } from "../../src/background/save";
import { MemoryPairingStore, Store } from "../../src/background/store";
import type { ChainView } from "../../src/shared/ui";
import { type Answer, FakeClient, record } from "./fake-client";
import { EXT_ID, FakeExt, csSender, uiSender } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

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

const answer: Answer = (r) => {
  switch (r.op) {
    case "list_for_origin":
      return {
        items: [
          summary("it_01"),
          summary("it_02", {
            title: "Atlas Perso",
            has_password: false,
            methods: [{ provider: "google", account_email: "alex.perso@example.com" }],
          }),
        ],
      };
    case "vaults":
      return { vaults: [{ id: "v1", name: "Personnel", color: null }, { id: "v2", name: "Projet Atlas", color: "#0E7490" }] };
    case "generate":
      return { password: "Gen-Pass-123", entropy_bits: 90 };
    case "unlock":
      return { locked: false };
    case "save_login":
    case "link_provider":
      return { item_id: "it_new" };
    default:
      return {};
  }
};

class FakeChain implements ChainDriver {
  readonly calls: unknown[][] = [];
  view: ChainView | null = null;
  async start(tabId: number, itemId: string, viaProvider?: string) {
    this.calls.push(["start", tabId, itemId, viaProvider]);
  }
  async stop(tabId: number) {
    this.calls.push(["stop", tabId]);
  }
  async state() {
    return this.view;
  }
}

async function setup(clock = { t: 1_000_000 }) {
  const ext = new FakeExt();
  const pairings = new MemoryPairingStore();
  await new Store(ext, pairings).setPairing(record());
  const client = new FakeClient(answer);
  const chain = new FakeChain();
  const bg = createBackground(ext, {
    pairings,
    newClient: () => client,
    sleep: async () => undefined,
    chain,
    now: () => clock.t,
  });
  bg.install();
  ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
  const top = contentSender(ext.runtime, csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }))!;
  return { ext, client, chain, bg, top, clock };
}

const hashOf = (url: string) => url.slice(url.indexOf("#") + 1);

describe("menu extras", () => {
  async function menu(ext: FakeExt) {
    const r = (await ext.send(
      { type: "open_menu", fieldRef: "e1", formRef: "f1", formKind: "login" },
      csSender(`${SITE}/login`, 7, 0, { documentId: "doc-1" }),
    )) as { ok: { url: string } };
    const token = hashOf(r.ok.url);
    const ui = uiSender(`menu.html#${token}`, 7);
    await ext.send({ type: "menu_init", token }, ui);
    return { token, ui };
  }

  it("menu_signin starts the chain for an offered provider method and closes the menu", async () => {
    const { ext, chain } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "google" }, ui)).toEqual({ ok: {} });
    expect(chain.calls).toEqual([["start", 7, "it_02", "google"]]);
    expect(ext.sentToTabs.at(-1)).toEqual({
      tabId: 7,
      message: { type: "remove_frame", kind: "menu" },
      options: { documentId: "doc-1" },
    });
    // The token is spent.
    expect(await ext.send({ type: "menu_init", token }, ui)).toEqual({ err: "invalid" });
  });

  it("menu_signin refuses a provider the item does not use", async () => {
    const { ext, chain } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_02", provider: "apple" }, ui)).toEqual({
      err: "invalid",
    });
    expect(await ext.send({ type: "menu_signin", token, itemId: "it_01", provider: "google" }, ui)).toEqual({
      err: "invalid",
    });
    expect(chain.calls).toEqual([]);
  });

  it("menu_unlock asks the host, menu_close removes the frame", async () => {
    const { ext, client } = await setup();
    const { token, ui } = await menu(ext);
    expect(await ext.send({ type: "menu_unlock", token }, ui)).toEqual({ ok: { locked: false } });
    expect(client.requests.at(-1)).toEqual({ op: "unlock" });
    expect(await ext.send({ type: "menu_close", token }, ui)).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "menu" });
  });
});

describe("overlay", () => {
  it("open shows overlay.html with a token in the top frame", async () => {
    const { ext, bg, top } = await setup();
    const token = await bg.overlays.open(top);
    expect(ext.sentToTabs).toEqual([
      {
        tabId: 7,
        message: { type: "show_frame", kind: "overlay", url: `chrome-extension://${EXT_ID}/overlay.html#${token}` },
        options: { documentId: "doc-1" },
      },
    ]);
  });

  it("init lists password and provider sign-ins; start must be one of them", async () => {
    const { ext, bg, top, chain, client } = await setup();
    const token = await bg.overlays.open(top);
    const ui = uiSender(`overlay.html#${token}`, 7);
    const init = (await ext.send({ type: "overlay_init", token }, ui)) as { ok: Record<string, unknown> };
    expect(client.requests).toEqual([{ op: "list_for_origin", ctx: "overlay", origin: SITE }]);
    expect(init.ok).toEqual({
      origin: SITE,
      chain: null,
      accounts: [
        { itemId: "it_01", title: "Atlas Cloud", subtitle: "alex@atlas.dev", iconLetter: "A", iconColor: "#14532D" },
        {
          itemId: "it_02",
          title: "Atlas Perso via Google",
          subtitle: "Se connecter avec Google (alex.perso@example.com)",
          iconLetter: "A",
          iconColor: "#14532D",
          provider: "google",
          email: "alex.perso@example.com",
        },
      ],
    });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02" }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_99" }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_02", provider: "google" }, ui)).toEqual({ ok: {} });
    expect(await ext.send({ type: "overlay_start", token, itemId: "it_01" }, ui)).toEqual({ ok: {} });
    expect(await ext.send({ type: "overlay_stop", token }, ui)).toEqual({ ok: {} });
    expect(chain.calls).toEqual([
      ["start", 7, "it_02", "google"],
      ["start", 7, "it_01", undefined],
      ["stop", 7],
    ]);
  });

  it("state relays the chain view; other tabs and other pages are refused", async () => {
    const { ext, bg, top, chain } = await setup();
    const token = await bg.overlays.open(top);
    chain.view = { itemId: "it_01", status: "stopped", reason: "captcha", steps: [{ label: "Identifiant rempli", state: "done" }] };
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`overlay.html#${token}`, 7))).toEqual({
      ok: { chain: chain.view },
    });
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`overlay.html#${token}`, 8))).toEqual({
      err: "invalid",
    });
    expect(await ext.send({ type: "overlay_state", token }, uiSender(`menu.html#${token}`, 7))).toBe(
      (await import("./fake-ext")).NO_REPLY,
    );
  });

  it("dies with a navigation of the top frame; close removes the frame", async () => {
    const { ext, bg, top } = await setup();
    let token = await bg.overlays.open(top);
    ext.navigate(7, 0, `${SITE}/home`, "doc-2");
    await new Promise((r) => setTimeout(r, 0));
    expect(await ext.send({ type: "overlay_state", token }, uiSender("overlay.html", 7))).toEqual({ err: "invalid" });
    token = await bg.overlays.open(top);
    expect(await ext.send({ type: "overlay_close", token }, uiSender("overlay.html", 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "overlay" });
  });
});

describe("save prompt", () => {
  const pending = {
    tabId: 7,
    origin: SITE,
    documentId: "doc-1",
    kind: "login" as const,
    status: "new" as const,
    username: "alex@atlas.dev",
    password: "typed-Secret-1",
  };
  const edits = { title: "Atlas Cloud", username: "alex@atlas.dev", password: "", vaultId: "v2", rule: "exact_host", tags: ["Travail"] };

  it("titleFromSite", () => {
    expect(titleFromSite("atlas-cloud.test")).toBe("Atlas Cloud");
  });

  it("init never carries the password; reveal does", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    expect(ext.sentToTabs[0]?.message).toEqual({
      type: "show_frame",
      kind: "save",
      url: `chrome-extension://${EXT_ID}/save.html#${token}`,
    });
    const ui = uiSender(`save.html#${token}`, 7);
    const init = await ext.send({ type: "save_init", token }, ui);
    expect(init).toEqual({
      ok: {
        origin: SITE,
        site: "atlas-cloud.test",
        kind: "login",
        status: "new",
        title: "Atlas Cloud",
        username: "alex@atlas.dev",
        vaults: [
          { id: "v1", name: "Personnel" },
          { id: "v2", name: "Projet Atlas" },
        ],
      },
    });
    expect(JSON.stringify(init)).not.toContain("typed-Secret-1");
    expect(await ext.send({ type: "save_reveal", token }, ui)).toEqual({ ok: { password: "typed-Secret-1" } });
    // Memory only: nothing in storage.
    expect(JSON.stringify([...ext.session.data.values(), ...ext.local.data.values()])).not.toContain("typed-Secret-1");
  });

  it("without a documentId, the prompt carries an origin pin and goes to frame 0", async () => {
    const { ext, bg } = await setup();
    const { documentId: _drop, ...rest } = pending;
    const token = await bg.saves.open({ ...rest, topOrigin: SITE });
    expect(ext.sentToTabs[0]?.message).toEqual({
      type: "show_frame",
      kind: "save",
      url: `chrome-extension://${EXT_ID}/save.html#${token}`,
      origin: SITE,
    });
    expect(ext.sentToTabs[0]?.options).toEqual({ frameId: 0 });
  });

  it("save uses the typed password unless one was generated", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open(pending);
    const ui = uiSender(`save.html#${token}`, 7);
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ ok: {} });
    expect(client.requests.at(-1)).toEqual({
      op: "save_login",
      ctx: "save_prompt",
      origin: SITE,
      title: "Atlas Cloud",
      username: "alex@atlas.dev",
      password: "typed-Secret-1",
      vault_id: "v2",
      rule: "exact_host",
      tags: ["Travail"],
    });
    // Decided: no second save, no reveal; close still works.
    expect(await ext.send({ type: "save_reveal", token }, ui)).toEqual({ err: "invalid" });
    expect(await ext.send({ type: "save_close", token }, ui)).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });

    const t2 = await bg.saves.open(pending);
    const ui2 = uiSender(`save.html#${t2}`, 7);
    expect(await ext.send({ type: "save_generate", token: t2 }, ui2)).toEqual({ ok: { password: "Gen-Pass-123" } });
    await ext.send({ type: "save_decide", token: t2, decision: "save", edits }, ui2);
    expect(client.requests.at(-1)).toMatchObject({ op: "save_login", password: "Gen-Pass-123" });
  });

  it("update targets only the item check_credentials named", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open({ ...pending, status: "update", update: { itemId: "it_01", title: "Atlas Cloud" } });
    const ui = uiSender(`save.html#${token}`, 7);
    expect(await ext.send({ type: "save_decide", token, decision: "update", itemId: "it_evil" }, ui)).toEqual({ ok: {} });
    expect(client.requests.at(-1)).toEqual({
      op: "update_password",
      ctx: "save_prompt",
      item_id: "it_01",
      origin: SITE,
      password: "typed-Secret-1",
    });
  });

  it("never stores the registrable domain in storage.local neverSave", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open({ ...pending, origin: "https://admin.atlas-cloud.test" });
    expect(await ext.send({ type: "save_decide", token, decision: "never" }, uiSender("save.html", 7))).toEqual({ ok: {} });
    expect(ext.local.data.get(NEVER_SAVE_KEY)).toEqual(["atlas-cloud.test"]);
    expect(await bg.neverSave.has("atlas-cloud.test")).toBe(true);
  });

  it("the password is blanked as soon as the prompt is saved", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    const ui = uiSender(`save.html#${token}`, 7);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    expect(rec?.password).toBe("typed-Secret-1");
    expect(await ext.send({ type: "save_decide", token, decision: "save", edits }, ui)).toEqual({ ok: {} });
    expect(rec?.password).toBe("");
  });

  it("the password is blanked when an expired record is dropped on resolve", async () => {
    const { bg, clock } = await setup();
    const token = await bg.saves.open(pending);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    clock.t += SAVE_TTL_MS + 1;
    expect(await bg.saves.tokens.resolve(token, { tabId: 7 } as never)).toBeNull();
    expect(rec?.password).toBe("");
  });

  it("the password is blanked as soon as the prompt is dismissed or closed", async () => {
    const { ext, bg } = await setup();
    const token = await bg.saves.open(pending);
    const rec = await bg.saves.tokens.resolve(token, { tabId: 7 } as never);
    await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
    expect(rec?.password).toBe("");
    const t2 = await bg.saves.open(pending);
    const rec2 = await bg.saves.tokens.resolve(t2, { tabId: 7 } as never);
    await ext.send({ type: "save_close", token: t2 }, uiSender("save.html", 7));
    expect(rec2?.password).toBe("");
  });

  it("dismiss removes the frame; the prompt expires after 2 minutes", async () => {
    const { ext, bg, clock } = await setup();
    let token = await bg.saves.open(pending);
    expect(await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7))).toEqual({ ok: {} });
    expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });
    token = await bg.saves.open(pending);
    clock.t += SAVE_TTL_MS + 1;
    expect(await ext.send({ type: "save_init", token }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
  });

  it("the record holding the password is purged by timer after 2 minutes", async () => {
    vi.useFakeTimers();
    try {
      const { ext, bg } = await setup();
      const token = await bg.saves.open(pending);
      const rec = await bg.saves.tokens.resolve(token, { page: "save.html", tabId: 7 });
      expect(rec?.password).toBe("typed-Secret-1");
      await vi.advanceTimersByTimeAsync(SAVE_TTL_MS - 1);
      expect(rec?.password).toBe("typed-Secret-1");
      await vi.advanceTimersByTimeAsync(1);
      // Wiped and revoked without anyone resolving the token.
      expect(rec?.password).toBe("");
      expect(ext.sentToTabs.at(-1)?.message).toEqual({ type: "remove_frame", kind: "save" });
      expect(await ext.send({ type: "save_reveal", token }, uiSender("save.html", 7))).toEqual({ err: "invalid" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("a dismissed prompt cancels its purge timer", async () => {
    vi.useFakeTimers();
    try {
      const { ext, bg } = await setup();
      const token = await bg.saves.open(pending);
      await ext.send({ type: "save_decide", token, decision: "dismiss" }, uiSender("save.html", 7));
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("provider link variant calls link_provider", async () => {
    const { ext, bg, client } = await setup();
    const token = await bg.saves.open({
      ...pending,
      kind: "provider_link",
      username: "",
      password: "",
      provider: { id: "google", accountItemId: "it_g", email: "alex.perso@example.com" },
    });
    const ui = uiSender("save.html", 7);
    expect(await ext.send({ type: "save_init", token }, ui)).toMatchObject({
      ok: { kind: "provider_link", provider: { id: "google", email: "alex.perso@example.com" }, vaults: [] },
    });
    await ext.send({ type: "save_decide", token, decision: "save" }, ui);
    expect(client.requests.at(-1)).toEqual({
      op: "link_provider",
      ctx: "save_prompt",
      site_origin: SITE,
      provider: "google",
      account_item_id: "it_g",
    });
  });
});
