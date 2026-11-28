// "Scan verification code QR" (spec section 1): the page first, one capture when it shows nothing, the
// paste card last; never on a plain http page or in a private window; no network request.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Filler } from "../../../src/background/fill";
import { Frames } from "../../../src/background/frames";
import { SetupCards } from "../../../src/background/setup/card";
import { SetupScan } from "../../../src/background/setup/scan";
import { FakeExt } from "../fake-ext";

const SITE = "https://atlas-cloud.test";
const TAB = 7;
const UI = { page: "setup.html", tabId: TAB };
const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const URI = `otpauth://totp/Atlas:alex%40atlas.dev?secret=${SECRET}&issuer=Atlas`;
const DECOY = `otpauth://totp/Ads:x?secret=${"GEZDGNBVGY3TQOJQ".repeat(2)}&issuer=Ads`;
const PNG = "data:image/png;base64,iVBORw0KGgo=";

type Reply = (frameId: number, message: { type: string; dataUrl?: string }) => unknown;

function setup(o: { url?: string; incognito?: boolean; reply?: Reply; capture?: (() => string) | null } = {}) {
  const ext = new FakeExt();
  const url = o.url ?? `${SITE}/settings/security`;
  ext.activeTab = { id: TAB, url, windowId: 4, ...(o.incognito ? { incognito: true } : {}) };
  ext.tabStates.set(TAB, { active: true, windowId: 4, ...(o.incognito ? { incognito: true } : {}) });
  ext.setFrame(TAB, 0, url, "doc-1");
  ext.setFrame(TAB, 1, `${SITE}/embed`, "doc-k");
  ext.parents.set(`${TAB}:1`, 0);
  // A third-party frame: never injected, never asked.
  ext.setFrame(TAB, 2, "https://ads.test/slot", "doc-ad");
  ext.parents.set(`${TAB}:2`, 0);
  ext.tabReply = (_tab, message, options) => o.reply?.(options.frameId ?? -1, message as { type: string });
  ext.captureImpl = o.capture === null ? undefined : (o.capture ?? (() => PNG));
  const session = {
    request: (async (r: { op: string }) => (r.op === "list_for_origin" ? { items: [] } : {})) as never,
  };
  const cards = new SetupCards({
    ext,
    session,
    filler: new Filler(ext.tabs, new Frames(ext.webNavigation), session),
    analyses: { top: async () => null },
  });
  cards.install(ext);
  const scan = new SetupScan({ ext, cards });
  const sent = (type: string) => ext.sentToTabs.filter((s) => (s.message as { type: string }).type === type);
  const token = () => (sent("show_frame").at(-1)?.message as { url: string } | undefined)?.url.split("#")[1] as string;
  return { ext, cards, scan, sent, token };
}

describe("setup scan", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchSpy = vi.fn(async () => new Response(""));
    vi.stubGlobal("fetch", fetchSpy);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("uses the DOM result and never captures when the page scan finds a code", async () => {
    const h = setup({
      reply: (frameId, m) => {
        if (m.type !== "setup_scan_dom") return undefined;
        // The child frame answers first with a decoy; the top document's code wins.
        return { found: [{ uri: frameId === 0 ? URI : DECOY, issuer: "Forged", account: "forged" }] };
      },
    });
    expect(await h.scan.scan()).toEqual({ status: "card" });
    // The top frame on its own first, then each same-origin frame on its own.
    expect(h.ext.injections).toEqual([
      { target: { tabId: TAB, frameIds: [0] }, files: ["setup-scan.js"] },
      { target: { tabId: TAB, frameIds: [1] }, files: ["setup-scan.js"] },
    ]);
    expect(h.sent("setup_scan_dom").map((s) => s.options.frameId).sort()).toEqual([0, 1]);
    expect(h.ext.captures).toHaveLength(0);
    expect(h.sent("setup_scan_capture")).toHaveLength(0);
    // Issuer and account come from the URI itself, never from the page's reply fields.
    expect(await h.cards.init(h.token(), UI)).toMatchObject({ mode: "confirm", issuer: "Atlas", account: "alex@atlas.dev" });
    expect(h.sent("show_frame")[0]).toMatchObject({ message: { kind: "setup" }, options: { documentId: "doc-1" } });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps the page scan when a child frame closed before its injection", async () => {
    const h = setup({
      reply: (frameId, m) => (m.type === "setup_scan_dom" && frameId === 0 ? { found: [{ uri: URI, issuer: "", account: "" }] } : undefined),
    });
    const inject = h.ext.scripting.executeScript;
    h.ext.scripting.executeScript = async (injection) => {
      await inject(injection);
      if (injection.target.frameIds?.includes(1)) throw new Error("No frame with id 1");
      return [];
    };
    expect(await h.scan.scan()).toEqual({ status: "card" });
    expect(h.ext.injections.map((i) => i.target.frameIds)).toEqual([[0], [1]]);
    // The closed frame is not asked; the top frame still had its scanner and answered.
    expect(h.sent("setup_scan_dom").map((s) => s.options.frameId)).toEqual([0]);
    expect(h.ext.captures).toHaveLength(0);
    expect((await h.cards.init(h.token(), UI)).mode).toBe("confirm");
  });

  it("captures once when the page scan finds nothing", async () => {
    const h = setup({
      reply: (_f, m) => {
        if (m.type === "setup_scan_dom") return { found: [] };
        if (m.type === "setup_scan_capture") return m.dataUrl === PNG ? { found: [{ uri: URI, issuer: "Atlas", account: "alex@atlas.dev" }] } : { found: [] };
        return undefined;
      },
    });
    expect(await h.scan.scan()).toEqual({ status: "card" });
    expect(h.ext.captures).toEqual([{ windowId: 4, format: "png" }]);
    const cap = h.sent("setup_scan_capture");
    expect(cap).toHaveLength(1);
    expect(cap[0]?.options).toMatchObject({ frameId: 0 });
    expect((await h.cards.init(h.token(), UI)).mode).toBe("confirm");
    // The cross-origin frame got no scanner and no question.
    expect(h.ext.injections.flatMap((i) => i.target.frameIds ?? [])).not.toContain(2);
    expect(h.sent("setup_scan_dom").map((s) => s.options.frameId)).not.toContain(2);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("captures nothing when the scanned tab is no longer the active one of its window", async () => {
    const found = { found: [{ uri: URI, issuer: "Atlas", account: "alex@atlas.dev" }] };
    const reply: Reply = (_f, m) => (m.type === "setup_scan_dom" ? { found: [] } : m.type === "setup_scan_capture" ? found : undefined);
    // Another tab came to the front.
    let h = setup({ reply });
    h.ext.tabStates.set(TAB, { active: false, windowId: 4 });
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect(h.ext.captures).toHaveLength(0);
    // The tab moved to another window.
    h = setup({ reply });
    h.ext.tabStates.set(TAB, { active: true, windowId: 9 });
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect(h.ext.captures).toHaveLength(0);
    expect(h.sent("setup_scan_capture")).toHaveLength(0);
  });

  it("shows the paste card when nothing is found and when the capture throws", async () => {
    // Nothing anywhere.
    let h = setup({ reply: (_f, m) => (m.type.startsWith("setup_scan") ? { found: [] } : undefined) });
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect(h.ext.captures).toHaveLength(1);
    expect(await h.cards.init(h.token(), UI)).toMatchObject({ mode: "paste", issuer: "atlas-cloud.test", account: "" });
    // The capture throws (no activeTab grant): the same, no capture sent to the page.
    h = setup({ reply: (_f, m) => (m.type === "setup_scan_dom" ? { found: [] } : undefined), capture: null });
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect(h.sent("setup_scan_capture")).toHaveLength(0);
    expect((await h.cards.init(h.token(), UI)).mode).toBe("paste");
    // Frames that never answer, an injection that fails: still the paste card.
    h = setup({ reply: () => undefined });
    h.ext.injectError = new Error("Cannot access contents of the page");
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect((await h.cards.init(h.token(), UI)).mode).toBe("paste");
    // A reply that is no otpauth URI is nothing found.
    h = setup({ reply: (_f, m) => (m.type.startsWith("setup_scan") ? { found: [{ uri: "https://evil.test/", issuer: "", account: "" }] } : undefined) });
    expect(await h.scan.scan()).toEqual({ status: "none" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("answers unavailable on http, on a private window, and makes no fetch at all", async () => {
    const reply: Reply = (_f, m) => (m.type === "setup_scan_dom" ? { found: [{ uri: URI, issuer: "", account: "" }] } : undefined);
    for (const h of [
      setup({ url: "http://atlas-cloud.test/settings", reply }),
      setup({ incognito: true, reply }),
      setup({ url: "chrome://settings", reply }),
    ]) {
      expect(await h.scan.scan()).toEqual({ status: "unavailable" });
      expect(h.ext.injections).toHaveLength(0);
      expect(h.ext.captures).toHaveLength(0);
      expect(h.sent("show_frame")).toHaveLength(0);
    }
    // No active tab at all.
    const h = setup({ reply });
    h.ext.activeTab = null;
    expect(await h.scan.scan()).toEqual({ status: "unavailable" });
    expect(fetchSpy).toHaveBeenCalledTimes(0);
  });
});
