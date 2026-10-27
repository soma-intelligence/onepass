import { describe, expect, it } from "vitest";
import { type FillTarget, Filler } from "../../src/background/fill";
import { Frames } from "../../src/background/frames";
import { BgError, Session } from "../../src/background/session";
import { MemoryPairingStore, Store } from "../../src/background/store";
import { type Answer, FakeClient, record } from "./fake-client";
import { FakeExt } from "./fake-ext";

const SITE = "https://atlas-cloud.test";

const answers: Answer = (r) => {
  if (r.op === "fill_login") return { username: "alex@atlas.dev", password: "pw-1", totp: undefined };
  if (r.op === "fill_card") {
    return { cardholder: "Alex Martin", number: "4242424242424242", exp_month: "04", exp_year: "2029", cvv: "123" };
  }
  if (r.op === "fill_identity") {
    return {
      given_name: "Alex",
      family_name: "Martin",
      email: "alex@atlas.dev",
      address: { line1: "1 rue de la Paix", line2: "", city: "Paris", postal_code: "75002", region: "", country: "FR" },
    };
  }
  return {};
};

async function setup() {
  const ext = new FakeExt();
  const store = new Store(ext, new MemoryPairingStore());
  await store.setPairing(record());
  const client = new FakeClient(answers);
  const session = new Session({ store, newClient: () => client });
  const filler = new Filler(ext.tabs, new Frames(ext.webNavigation), session);
  return { ext, client, filler };
}

const target = (over: Partial<FillTarget> = {}): FillTarget => ({
  tabId: 7,
  frameId: 0,
  origin: SITE,
  documentId: "doc-1",
  formRef: "f1",
  ...over,
});

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(BgError);
    return (e as BgError).code;
  }
  throw new Error("expected a refusal");
}

describe("fill pipeline", () => {
  it("fills a login into the bound frame and document", async () => {
    const { ext, client, filler } = await setup();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    await filler.fillLogin(target(), "it_01", ["username", "password"]);
    expect(client.requests).toEqual([
      { op: "fill_login", ctx: "menu", item_id: "it_01", origin: SITE, fields: ["username", "password"] },
    ]);
    expect(ext.sentToTabs).toEqual([
      {
        tabId: 7,
        message: {
          type: "fill",
          origin: SITE,
          formRef: "f1",
          values: { username: "alex@atlas.dev", email: "alex@atlas.dev", current_password: "pw-1" },
        },
        options: { documentId: "doc-1" },
      },
    ]);
  });

  it("targets frameId when the browser has no documentId", async () => {
    const { ext, filler } = await setup();
    ext.setFrame(7, 2, `https://pay.atlas-cloud.test/card`);
    ext.setFrame(7, 0, `${SITE}/checkout`);
    await filler.fillCard(target({ frameId: 2, origin: "https://pay.atlas-cloud.test", documentId: undefined }), "it_02");
    expect(ext.sentToTabs[0]?.options).toEqual({ frameId: 2 });
    expect(ext.sentToTabs[0]?.message).toEqual({
      type: "fill",
      origin: "https://pay.atlas-cloud.test",
      formRef: "f1",
      values: {
        cc_name: "Alex Martin",
        cc_number: "4242424242424242",
        cc_exp_month: "04",
        cc_exp_year: "2029",
        cc_exp: "04/29",
        cc_csc: "123",
      },
    });
  });

  it("maps identity fields and skips empty ones", async () => {
    const { ext, filler } = await setup();
    ext.setFrame(7, 0, `${SITE}/account`, "doc-1");
    await filler.fillIdentity(target(), "it_03");
    expect((ext.sentToTabs[0]?.message as { values: unknown }).values).toEqual({
      given_name: "Alex",
      family_name: "Martin",
      full_name: "Alex Martin",
      email: "alex@atlas.dev",
      address_line1: "1 rue de la Paix",
      city: "Paris",
      postal_code: "75002",
      country: "FR",
    });
  });

  it("fill_refused_after_navigation (other origin, nothing asked to the host)", async () => {
    const { ext, client, filler } = await setup();
    ext.setFrame(7, 0, "https://evil.test/login", "doc-2");
    expect(await code(filler.fillLogin(target(), "it_01", ["password"]))).toBe("origin_mismatch");
    expect(client.requests).toEqual([]);
    expect(ext.sentToTabs).toEqual([]);
  });

  it("fill_refused_after_navigation (same origin, new document)", async () => {
    const { ext, filler } = await setup();
    ext.setFrame(7, 0, `${SITE}/other`, "doc-9");
    expect(await code(filler.fillLogin(target(), "it_01", ["password"]))).toBe("origin_mismatch");
    expect(ext.sentToTabs).toEqual([]);
  });

  it("refuses when the page navigates while the host answers", async () => {
    const { ext, filler } = await setup();
    ext.setFrame(7, 0, `${SITE}/login`, "doc-1");
    const p = filler.fillLogin(target(), "it_01", ["password"]);
    // Navigation lands between the first check and the delivery.
    ext.setFrame(7, 0, "https://evil.test/", "doc-2");
    expect(await code(p)).toBe("origin_mismatch");
    expect(ext.sentToTabs).toEqual([]);
  });

  it("fill_refused_cross_site_frame", async () => {
    const { ext, client, filler } = await setup();
    ext.setFrame(7, 0, "https://evil.test/", "top");
    ext.setFrame(7, 4, `${SITE}/login`, "doc-1");
    expect(await code(filler.fillLogin(target({ frameId: 4 }), "it_01", ["password"]))).toBe("cross_site_frame");
    expect(client.requests).toEqual([]);
    expect(ext.sentToTabs).toEqual([]);
  });

  it("a chain fill (same origin as the top frame) refuses a same-site frame of another origin", async () => {
    const { ext, client, filler } = await setup();
    ext.setFrame(7, 0, `${SITE}/login`, "top");
    ext.setFrame(7, 4, "https://login.atlas-cloud.test/frame", "doc-4");
    const t = target({ frameId: 4, origin: "https://login.atlas-cloud.test", documentId: "doc-4", sameOriginAsTop: true });
    expect(await code(filler.fillLogin(t, "it_01", ["password"]))).toBe("origin_mismatch");
    expect(client.requests).toEqual([]);
    // The same frame at the top frame's origin passes.
    ext.setFrame(7, 4, `${SITE}/frame`, "doc-4");
    await filler.fillLogin(target({ frameId: 4, documentId: "doc-4", sameOriginAsTop: true }), "it_01", ["password"]);
    expect(ext.sentToTabs.at(-1)?.options).toEqual({ documentId: "doc-4" });
  });

  it("fill_refused_http", async () => {
    const { ext, client, filler } = await setup();
    ext.setFrame(7, 0, "http://atlas-cloud.test/login", "doc-1");
    expect(await code(filler.fillLogin(target({ origin: "http://atlas-cloud.test" }), "it_01", ["password"]))).toBe(
      "insecure_origin",
    );
    // A token bound on HTTPS whose frame is now plain HTTP.
    expect(await code(filler.fillLogin(target(), "it_01", ["password"]))).toBe("insecure_origin");
    // A same-site HTTPS frame in an HTTP top page.
    ext.setFrame(7, 5, `${SITE}/login`, "doc-5");
    expect(await code(filler.fillGenerated(target({ frameId: 5, documentId: "doc-5" }), "x"))).toBe("insecure_origin");
    expect(client.requests).toEqual([]);
    expect(ext.sentToTabs).toEqual([]);
  });

  it("a vanished frame is refused", async () => {
    const { filler } = await setup();
    expect(await code(filler.fillLogin(target(), "it_01", ["password"]))).toBe("origin_mismatch");
  });
});

describe("Frames.frameOrigin", () => {
  it("returns the normalized origin or null", async () => {
    const ext = new FakeExt();
    const f = new Frames(ext.webNavigation);
    ext.setFrame(1, 0, "https://Atlas-Cloud.test./x");
    ext.setFrame(1, 1, "about:blank");
    expect(await f.frameOrigin(1, 0)).toBe(SITE);
    expect(await f.frameOrigin(1, 1)).toBeNull();
    expect(await f.frameOrigin(2, 0)).toBeNull();
  });
});
