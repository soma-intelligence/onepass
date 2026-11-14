// The setup card's controller (spec section 1): target choice, the write, the fill after the
// write only, the code when no field took it, the token's life, and the seed never in storage.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Summary } from "../../../src/bridge/client";
import { Filler } from "../../../src/background/fill";
import { Frames } from "../../../src/background/frames";
import { createRouter, type Handlers } from "../../../src/background/router";
import { BgError } from "../../../src/background/session";
import { SETUP_TTL_MS, SetupCards, WATCH_MS, WATCH_PREFIX } from "../../../src/background/setup/card";
import { shallowOtpauth } from "../../../src/setup/otpauth";
import { FakeExt, csSender } from "../fake-ext";

const SITE = "https://atlas-cloud.test";
const TAB = 7;
const UI = { page: "setup.html", tabId: TAB };
const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const URI = `otpauth://totp/Atlas%20Cloud:alex%40atlas.dev?secret=${SECRET}&issuer=Atlas%20Cloud`;
const PASTED = "KRUGS4ZANFZSAYJAONSWG4TFOQQGWZLZ";
const CODES = ["ab12-cd34", "ef56-gh78", "ij90-kl12", "mn34-op56", "qr78-st90", "uv12-wx34"];

function item(id: string, username: string, extra: Partial<Summary> = {}): Summary {
  return {
    item_id: id,
    vault_id: "v1",
    vault_name: "Perso",
    title: "Atlas Cloud",
    subtitle: username,
    kind: "login",
    icon_letter: "A",
    icon_color: "#000",
    has_password: true,
    has_totp: false,
    methods: [],
    match: "domain",
    ...extra,
  };
}

interface Opts {
  items?: Summary[];
  answer?: (r: Record<string, unknown>) => unknown;
  otpForm?: boolean;
  lastUsed?: string | null;
}

function setup(o: Opts = {}) {
  const ext = new FakeExt();
  ext.setFrame(TAB, 0, `${SITE}/settings/security`, "doc-1");
  const requests: Record<string, unknown>[] = [];
  const session = {
    request: (async (r: Record<string, unknown>) => {
      requests.push(r);
      const a = o.answer?.(r);
      if (a instanceof Error) throw a;
      if (a !== undefined) return a;
      if (r.op === "list_for_origin") return { items: o.items ?? [] };
      if (r.op === "save_totp") return { status: "saved", item_id: (r.item_id as string | undefined) ?? "it_new" };
      if (r.op === "fill_login") return { totp: "123456" };
      return {};
    }) as never,
  };
  const frames = new Frames(ext.webNavigation);
  const filler = new Filler(ext.tabs, frames, session);
  const analyses = {
    top: async (tabId: number) =>
      o.otpForm
        ? {
            tabId,
            origin: SITE,
            documentId: "doc-1",
            analysis: {
              url: `${SITE}/settings/security`,
              forms: [{ ref: "f1", kind: "otp" as const, fields: [{ ref: "e1", role: "otp" as const }] }],
              captcha: false,
              push: false,
              providerButtons: [],
              accountChooser: [],
            },
          }
        : null,
  };
  const asks: number[] = [];
  const cards = new SetupCards({
    ext,
    session,
    filler,
    analyses,
    lastUsed: () => o.lastUsed ?? null,
    askUnlock: async (tabId) => {
      asks.push(tabId);
    },
  });
  cards.install(ext);
  const open = (found = shallowOtpauth(URI)) => cards.open({ tabId: TAB, origin: SITE, documentId: "doc-1", found });
  const sent = (type: string) => ext.sentToTabs.filter((s) => (s.message as { type: string }).type === type);
  const ops = () => requests.map((r) => r.op);
  /** Both storage areas and everything sent to the page. */
  const dump = () =>
    JSON.stringify({ local: [...ext.local.data], session: [...ext.session.data], page: ext.sentToTabs }).toUpperCase();
  return { ext, cards, open, sent, requests, ops, dump, asks };
}

describe("setup card", () => {
  beforeEach(() => vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] }));
  afterEach(() => vi.useRealTimers());

  it("preselects the item whose username equals the QR account", async () => {
    const h = setup({ items: [item("it_a", "sam@atlas.dev"), item("it_b", " ALEX@atlas.dev ")], lastUsed: "it_a" });
    const token = await h.open();
    const s = await h.cards.init(token, UI);
    expect(s).toMatchObject({ mode: "confirm", issuer: "Atlas Cloud", account: "alex@atlas.dev", selected: "it_b", mismatch: false });
    expect(s.candidates.map((c) => c.itemId)).toEqual(["it_a", "it_b"]);
    expect(h.requests[0]).toEqual({ op: "list_for_origin", ctx: "setup", origin: SITE });
    // Shown in the top frame of the very document scanned.
    expect(h.sent("show_frame")[0]).toMatchObject({
      tabId: TAB,
      message: { kind: "setup", url: `chrome-extension://onepassextensionid/setup.html#${token}` },
      options: { documentId: "doc-1" },
    });
  });

  it("never preselects an associated item", async () => {
    const assoc = item("it_x", "alex@atlas.dev", { associated: true });
    // Same username, and last used here: still never picked.
    let h = setup({ items: [assoc], lastUsed: "it_x" });
    let s = await h.cards.init(await h.open(), UI);
    expect(s.selected).toBeNull();
    expect(s.candidates[0]).toMatchObject({ itemId: "it_x", associated: true });
    // The last used one is associated: the first plain candidate instead.
    h = setup({ items: [assoc, item("it_p", "pat@atlas.dev")], lastUsed: "it_x" });
    s = await h.cards.init(await h.open(shallowOtpauth(URI.replace("alex%40atlas.dev", "nobody"))), UI);
    expect(s.selected).toBe("it_p");
    // The last used plain one wins over the first.
    h = setup({ items: [item("it_p", "pat@atlas.dev"), item("it_q", "quinn@atlas.dev")], lastUsed: "it_q" });
    s = await h.cards.init(await h.open(shallowOtpauth(URI.replace("alex%40atlas.dev", "nobody"))), UI);
    expect(s.selected).toBe("it_q");
  });

  it("sets mismatch when the account differs from the selected username", async () => {
    const h = setup({ items: [item("it_a", "sam@atlas.dev")] });
    const s = await h.cards.init(await h.open(), UI);
    expect(s).toMatchObject({ selected: "it_a", mismatch: true });
    // No account in the QR: nothing to differ from.
    const h2 = setup({ items: [item("it_a", "sam@atlas.dev")] });
    const s2 = await h2.cards.init(await h2.open(shallowOtpauth(`otpauth://totp/?secret=${SECRET}`)), UI);
    expect(s2).toMatchObject({ selected: "it_a", mismatch: false });
  });

  it("passes exists through, then sends replace on the second click", async () => {
    const h = setup({
      items: [item("it_a", "alex@atlas.dev", { has_totp: true })],
      otpForm: true,
      answer: (r) => (r.op === "save_totp" ? { status: r.replace === true ? "replaced" : "exists", item_id: "it_a" } : undefined),
    });
    const token = await h.open();
    await h.cards.init(token, UI);
    expect(await h.cards.save(token, UI, "it_a")).toEqual({ status: "exists" });
    expect(h.ops()).not.toContain("fill_login");
    expect(h.sent("fill")).toHaveLength(0);
    expect(await h.cards.save(token, UI, "it_a", undefined, true)).toEqual({ status: "replaced" });
    const saves = h.requests.filter((r) => r.op === "save_totp");
    expect(saves[0]).toMatchObject({ ctx: "setup", origin: SITE, uri: URI, item_id: "it_a", previous_label: "Ancien code" });
    expect(saves[0]?.replace).toBeUndefined();
    expect(saves[1]).toMatchObject({ item_id: "it_a", replace: true });
  });

  it("fills the code only after a saved, same or replaced answer", async () => {
    for (const status of ["saved", "same", "replaced"] as const) {
      const h = setup({
        items: [item("it_a", "alex@atlas.dev")],
        otpForm: true,
        answer: (r) => (r.op === "save_totp" ? { status, item_id: "it_a" } : undefined),
      });
      const token = await h.open();
      await h.cards.init(token, UI);
      expect(await h.cards.save(token, UI, "it_a")).toEqual({ status });
      expect(h.ops().indexOf("fill_login")).toBeGreaterThan(h.ops().indexOf("save_totp"));
      expect(h.requests.find((r) => r.op === "fill_login")).toEqual({ op: "fill_login", ctx: "setup", item_id: "it_a", origin: SITE, fields: ["totp"] });
      const fill = h.sent("fill");
      expect(fill).toHaveLength(1);
      expect(fill[0]?.message).toEqual({ type: "fill", origin: SITE, formRef: "f1", values: { otp: "123456" } });
      // Never submitted.
      expect(h.sent("submit")).toHaveLength(0);
    }
    // A refused write fills nothing.
    const h = setup({
      items: [item("it_a", "alex@atlas.dev")],
      otpForm: true,
      answer: (r) => (r.op === "save_totp" ? new BgError("origin_mismatch") : undefined),
    });
    const token = await h.open();
    await h.cards.init(token, UI);
    expect(await h.cards.save(token, UI, "it_a")).toEqual({ status: "refused" });
    expect(h.ops()).not.toContain("fill_login");
    expect(h.sent("fill")).toHaveLength(0);
  });

  it("returns the code when no field was filled", async () => {
    vi.setSystemTime(1_700_000_020_000);
    const h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: false });
    const token = await h.open();
    await h.cards.init(token, UI);
    const r = await h.cards.save(token, UI, "it_a");
    expect(r).toEqual({ status: "saved", code: "123456", remaining: 20 });
    expect(h.requests.find((x) => x.op === "fill_login")).toMatchObject({ ctx: "setup", fields: ["totp"] });
    // The popup's `totp` op is never used from the page's card.
    expect(h.ops()).not.toContain("totp");
    expect(h.sent("fill")).toHaveLength(0);
  });

  it("keeps nothing in storage.local or storage.session that contains the secret", async () => {
    const h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: true });
    let locked = true;
    const h2 = setup({
      items: [item("it_a", "alex@atlas.dev")],
      answer: (r) => (r.op === "save_totp" && locked ? new BgError("locked") : undefined),
    });
    const clean = (x: { dump: () => string }) => {
      expect(x.dump()).not.toContain(SECRET);
      expect(x.dump()).not.toContain(PASTED);
    };
    // Scanned seed: open, init, save, watch, codes, close.
    const token = await h.open();
    clean(h);
    const state = await h.cards.init(token, UI);
    expect(JSON.stringify(state).toUpperCase()).not.toContain(SECRET);
    clean(h);
    await h.cards.save(token, UI, "it_a");
    clean(h);
    expect(Object.keys(Object.fromEntries(h.ext.session.data))).toEqual([`${WATCH_PREFIX}${TAB}`]);
    await h.cards.codesFound({ type: "setup_codes_found", codes: CODES }, { tabId: TAB, frameId: 0, origin: SITE, documentId: "doc-1" });
    clean(h);
    const codesToken = (h.sent("show_frame").at(-1)?.message as { url: string }).url.split("#")[1] as string;
    expect(await h.cards.codesSave(codesToken, UI)).toEqual({ status: "saved" });
    clean(h);
    await h.cards.close(codesToken, UI);
    clean(h);
    // Pasted key, through a locked vault.
    const t2 = await h2.open(null);
    expect((await h2.cards.init(t2, UI)).mode).toBe("paste");
    const pasted = await h2.cards.paste(t2, UI, PASTED.toLowerCase().replace(/(.{4})/g, "$1 "));
    expect(JSON.stringify(pasted).toUpperCase()).not.toContain(PASTED);
    expect(await h2.cards.paste(t2, UI, "not a key")).toEqual({ error: "invalid" });
    clean(h2);
    expect(await h2.cards.save(t2, UI, "it_a")).toEqual({ status: "locked" });
    clean(h2);
    locked = false;
    expect((await h2.cards.save(t2, UI, "it_a")).status).toBe("saved");
    clean(h2);
    const uri = h2.requests.find((r) => r.op === "save_totp")?.uri;
    expect(uri).toBe(`otpauth://totp/atlas-cloud.test:alex%40atlas.dev?secret=${PASTED}&issuer=atlas-cloud.test`);
  });

  it("kills the token on top-frame navigation and on tab removal, and writes nothing after", async () => {
    // Navigation of the top frame.
    let h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: true });
    let token = await h.open();
    await h.cards.init(token, UI);
    h.ext.navigate(TAB, 0, `${SITE}/elsewhere`, "doc-2");
    await vi.advanceTimersByTimeAsync(0);
    await expect(h.cards.save(token, UI, "it_a")).rejects.toMatchObject({ code: "invalid" });
    expect(h.ops()).not.toContain("save_totp");
    expect(h.sent("remove_frame")).toHaveLength(0);
    // Tab removal.
    h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: true });
    token = await h.open();
    await h.cards.init(token, UI);
    h.ext.onRemoved.emit(TAB);
    await vi.advanceTimersByTimeAsync(0);
    await expect(h.cards.save(token, UI, "it_a")).rejects.toMatchObject({ code: "invalid" });
    expect(h.ops()).not.toContain("save_totp");
    // A navigation while the host writes: no fill, no watcher, nothing stored.
    let nav: (() => void) | null = null;
    h = setup({
      items: [item("it_a", "alex@atlas.dev")],
      otpForm: true,
      answer: (r) => {
        if (r.op !== "save_totp") return undefined;
        nav?.();
        return { status: "saved", item_id: "it_a" };
      },
    });
    const h3 = h;
    nav = () => h3.ext.navigate(TAB, 0, `${SITE}/next`, "doc-3");
    token = await h3.open();
    await h3.cards.init(token, UI);
    await h3.cards.save(token, UI, "it_a");
    expect(h3.ops()).not.toContain("fill_login");
    expect(h3.sent("fill")).toHaveLength(0);
    expect(h3.sent("setup_watch_codes")).toHaveLength(0);
    expect(h3.ext.session.data.size).toBe(0);
    // Expiry: 120 s.
    h = setup({ items: [item("it_a", "alex@atlas.dev")] });
    token = await h.open();
    await vi.advanceTimersByTimeAsync(SETUP_TTL_MS + 1);
    await expect(h.cards.init(token, UI)).rejects.toMatchObject({ code: "invalid" });
    expect(h.sent("remove_frame")).toHaveLength(1);
  });

  it("keeps the token through locked and retries without a new scan", async () => {
    let locked = true;
    const h = setup({
      items: [item("it_a", "alex@atlas.dev")],
      otpForm: true,
      answer: (r) => (r.op === "save_totp" && locked ? new BgError("locked") : undefined),
    });
    const token = await h.open();
    await h.cards.init(token, UI);
    expect(await h.cards.save(token, UI, "it_a")).toEqual({ status: "locked" });
    expect(h.asks).toEqual([TAB]);
    expect(h.ops()).not.toContain("fill_login");
    locked = false;
    expect(await h.cards.save(token, UI, "it_a")).toEqual({ status: "saved" });
    const saves = h.requests.filter((r) => r.op === "save_totp");
    expect(saves).toHaveLength(2);
    expect(saves[1]?.uri).toBe(URI);
    // One card, one scan: no second frame shown.
    expect(h.sent("show_frame")).toHaveLength(1);
    expect(h.sent("fill")).toHaveLength(1);
  });

  it("refuses setup_codes_found from a child frame, another site, or without a watch", async () => {
    const h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: true });
    const handlers: Handlers = { cs: { setup_codes_found: (m, from) => h.cards.codesFound(m, from) }, ui: {} };
    const route = createRouter(h.ext.runtime, handlers);
    h.ext.onMessage.addListener(route);
    const msg = { type: "setup_codes_found", codes: CODES };
    const cards = () => h.sent("show_frame").length;
    // No watch yet.
    expect(await h.ext.send(msg, csSender(`${SITE}/settings`, TAB, 0))).toEqual({ err: "invalid" });
    const token = await h.open();
    await h.cards.init(token, UI);
    await h.cards.save(token, UI, "it_a");
    expect(h.sent("setup_watch_codes")[0]).toMatchObject({ message: { type: "setup_watch_codes", ms: WATCH_MS }, options: { documentId: "doc-1" } });
    const before = cards();
    // A child frame of the same site.
    expect(await h.ext.send(msg, csSender(`${SITE}/frame`, TAB, 3))).toEqual({ err: "invalid" });
    // Another site in the top frame.
    expect(await h.ext.send(msg, csSender("https://evil.test/", TAB, 0))).toEqual({ err: "invalid" });
    // Another tab.
    expect(await h.ext.send(msg, csSender(`${SITE}/settings`, 8, 0))).toEqual({ err: "invalid" });
    // Codes the bridge would refuse never reach the handler.
    expect(await h.ext.send({ type: "setup_codes_found", codes: ["a b"] }, csSender(`${SITE}/settings`, TAB, 0))).toBeTypeOf("symbol");
    expect(cards()).toBe(before);
    // The top frame of the watched site: the codes card.
    expect(await h.ext.send(msg, csSender(`${SITE}/settings/codes`, TAB, 0, { documentId: "doc-1" }))).toEqual({ ok: {} });
    expect(cards()).toBe(before + 1);
    const codesToken = (h.sent("show_frame").at(-1)?.message as { url: string }).url.split("#")[1] as string;
    expect(await h.cards.init(codesToken, UI)).toMatchObject({ mode: "codes", codeCount: 6, selected: "it_a" });
    expect(await h.cards.codesSave(codesToken, UI)).toEqual({ status: "saved" });
    expect(h.requests.find((r) => r.op === "save_recovery_codes")).toEqual({
      op: "save_recovery_codes",
      ctx: "setup",
      origin: SITE,
      item_id: "it_a",
      codes: CODES.join("\n"),
    });
    // The watch reports once.
    expect(await h.ext.send(msg, csSender(`${SITE}/settings/codes`, TAB, 0))).toEqual({ err: "invalid" });
  });

  it("refuses a second setup_save on a spent token", async () => {
    const h = setup({ items: [item("it_a", "alex@atlas.dev")], otpForm: true });
    const token = await h.open();
    await h.cards.init(token, UI);
    expect((await h.cards.save(token, UI, "it_a")).status).toBe("saved");
    await expect(h.cards.save(token, UI, "it_a", undefined, true)).rejects.toMatchObject({ code: "invalid" });
    expect(h.requests.filter((r) => r.op === "save_totp")).toHaveLength(1);
    // An item the card never offered is refused too.
    const h2 = setup({ items: [item("it_a", "alex@atlas.dev")] });
    const t2 = await h2.open();
    await h2.cards.init(t2, UI);
    await expect(h2.cards.save(t2, UI, "it_zz")).rejects.toMatchObject({ code: "invalid" });
    expect(h2.ops()).not.toContain("save_totp");
  });
});
