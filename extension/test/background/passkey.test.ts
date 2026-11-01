import { describe, expect, it } from "vitest";
import { BgError } from "../../src/background/session";
import { type PasskeyWindows, Passkeys, createPasskeyRouter } from "../../src/background/passkey";
import type { CsContext, UiContext } from "../../src/background/frames";
import type { ChainView } from "../../src/shared/ui";
import type { PasskeyRequest, PasskeyResult } from "../../src/shared/messages";
import { EXT_ID, EXT_ORIGIN } from "./fake-ext";

const ORIGIN = "https://login.atlas-cloud.test";
const ITEM = "0f0e0d0c-0000-4000-8000-000000000001";
const OTHER_ITEM = "0f0e0d0c-0000-4000-8000-000000000002";
const CRED = "q83vEjRWeJA";
const CRED2 = "AAECAwQFBgc";

const summary = (item: string, cred: string, user = "alex@atlas.dev") => ({
  item_id: item,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  user_name: user,
  credential_id: cred,
});

const ASSERTION = {
  credential_id: CRED,
  client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
  authenticator_data: "AAAA",
  signature: "MEUC",
  user_handle: "dXNlci0x",
};

const REGISTRATION = {
  item_id: ITEM,
  credential_id: CRED2,
  client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
  attestation_object: "o2NmbXRkbm9uZQ",
  authenticator_data: "BBBB",
  public_key: "MFkwEwYH",
  public_key_algorithm: -7,
};

const GET: PasskeyRequest = { kind: "get", challenge: "-_8BAgMEBQYHCA", allow: [] };
const CREATE: PasskeyRequest = {
  kind: "create",
  challenge: "-_8BAgMEBQYHCA",
  userId: "dXNlci0x",
  userName: "alex@atlas.dev",
  exclude: [],
  algs: [-7, -257],
};

class FakeWindows implements PasskeyWindows {
  created: { url: string }[] = [];
  removed: number[] = [];
  listeners: ((id: number) => void)[] = [];
  next = 100;
  async create(o: { url: string }) {
    this.created.push({ url: o.url });
    const id = this.next++;
    return { id, tabs: [{ id: id + 1000 }] };
  }
  async remove(id: number) {
    this.removed.push(id);
  }
  onRemoved = { addListener: (cb: (id: number) => void) => void this.listeners.push(cb) };
  close(id: number) {
    for (const l of this.listeners) l(id);
  }
}

interface Setup {
  passkeys?: ReturnType<typeof summary>[];
  chain?: ChainView | null;
  sameOriginAncestors?: boolean;
  answer?: (req: Record<string, unknown>) => unknown;
}

function setup(o: Setup = {}) {
  const requests: Record<string, unknown>[] = [];
  const session = {
    request: async (req: Record<string, unknown>) => {
      requests.push(structuredClone(req));
      const x = o.answer?.(req);
      if (x instanceof Error) throw x;
      if (x !== undefined) return x;
      switch (req.op) {
        case "passkey_list":
          return { passkeys: o.passkeys ?? [summary(ITEM, CRED)] };
        case "passkey_get":
          return ASSERTION;
        case "passkey_create":
          return REGISTRATION;
        case "vaults":
          return { vaults: [{ id: "v1", name: "Personnel", color: null }, { id: "v2", name: "Travail", color: null }] };
      }
      throw new BgError("invalid");
    },
  };
  const frames = {
    ancestorsOfOrigin: async () => o.sameOriginAncestors ?? true,
    checkFillTarget: async () => ({ ok: true }) as const,
    frameOrigin: async () => ORIGIN,
  };
  const chain = { state: async () => o.chain ?? null };
  const windows = new FakeWindows();
  const nav: ((d: { tabId: number; frameId: number; url: string }) => void)[] = [];
  const removedTabs: ((tabId: number) => void)[] = [];
  const pk = new Passkeys({
    session: session as never,
    frames,
    chain,
    windows,
    runtime: { getURL: (p: string) => EXT_ORIGIN + p },
  });
  pk.install({
    webNavigation: { onCommitted: { addListener: (cb) => void nav.push(cb) } },
    tabs: { onRemoved: { addListener: (cb) => void removedTabs.push(cb) } },
  });
  const tokenOf = (n = 0) => (windows.created[n]?.url.split("#")[1] ?? "") as string;
  const ui = (n = 0): UiContext => ({ page: "passkey.html", tabId: 100 + n + 1000 });
  const ops = () => requests.map((r) => r.op);
  return { pk, windows, requests, ops, tokenOf, ui, nav, removedTabs };
}

const cs = (extra: Partial<CsContext> = {}): CsContext => ({ tabId: 7, frameId: 0, origin: ORIGIN, documentId: "doc-1", ...extra });
const flush = () => new Promise((r) => setTimeout(r, 0));

describe("passkey request routing", () => {
  it("falls back when no passkey of OnePass matches", async () => {
    const t = setup({ passkeys: [] });
    expect(await t.pk.request(cs(), "r1", GET)).toEqual({ kind: "fallback" });
    expect(t.windows.created).toHaveLength(0);
    expect(t.requests[0]).toMatchObject({ op: "passkey_list", ctx: "passkey", origin: ORIGIN, rp_id: "login.atlas-cloud.test" });
  });

  it("falls back when allowCredentials names none of ours", async () => {
    const t = setup();
    expect(await t.pk.request(cs(), "r1", { ...GET, allow: [CRED2] })).toEqual({ kind: "fallback" });
    expect(t.windows.created).toHaveLength(0);
  });

  it("takes the origin from the sender, the rpId the page gives only as rp_id", async () => {
    const t = setup();
    void t.pk.request(cs(), "r1", { ...GET, rpId: "atlas-cloud.test" });
    await flush();
    expect(t.requests[0]).toMatchObject({ origin: ORIGIN, rp_id: "atlas-cloud.test" });
  });

  it("falls back in a frame of another site (nothing listed, nothing signed)", async () => {
    const t = setup({ sameOriginAncestors: false });
    expect(await t.pk.request(cs({ frameId: 3, origin: "https://ads.evil.test" }), "r1", GET)).toEqual({ kind: "fallback" });
    expect(t.requests).toHaveLength(0);
    expect(t.windows.created).toHaveLength(0);
  });

  it("falls back on http", async () => {
    const t = setup();
    expect(await t.pk.request(cs({ origin: "http://atlas-cloud.test" }), "r1", GET)).toEqual({ kind: "fallback" });
    expect(t.requests).toHaveLength(0);
  });

  it("falls back when the host refuses the list (rp_id of another site)", async () => {
    const t = setup({ answer: (r) => (r.op === "passkey_list" ? new BgError("origin_mismatch") : undefined) });
    expect(await t.pk.request(cs(), "r1", { ...GET, rpId: "evil.test" })).toEqual({ kind: "fallback" });
    expect(t.windows.created).toHaveLength(0);
  });

  it("falls back on create without ES256", async () => {
    const t = setup();
    expect(await t.pk.request(cs(), "r1", { ...CREATE, algs: [-257] })).toEqual({ kind: "fallback" });
    expect(t.windows.created).toHaveLength(0);
  });

  it("opens one choice window per document; a second request is refused", async () => {
    const t = setup();
    const first = t.pk.request(cs(), "r1", GET);
    await flush();
    expect(t.windows.created).toHaveLength(1);
    expect(await t.pk.request(cs(), "r2", GET)).toEqual({ kind: "error", name: "NotAllowedError" });
    expect(t.windows.created).toHaveLength(1);
    await t.pk.cancel(t.tokenOf(), t.ui());
    expect(await first).toEqual({ kind: "error", name: "NotAllowedError" });
  });
});

describe("passkey choice window", () => {
  it("signs nothing before a pick, then returns the host's assertion", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    expect(t.ops()).toEqual(["passkey_list"]);
    const init = await t.pk.init(t.tokenOf(), t.ui());
    expect(init).toEqual({
      kind: "get",
      origin: ORIGIN,
      rpId: "login.atlas-cloud.test",
      accounts: [{ itemId: ITEM, credentialId: CRED, title: "Atlas Cloud", userName: "alex@atlas.dev", vaultName: "Personnel" }],
    });
    expect(t.ops()).toEqual(["passkey_list"]);
    await t.pk.pick(t.tokenOf(), t.ui(), ITEM, CRED);
    const r = await p;
    expect(r).toEqual({
      kind: "assertion",
      credentialId: CRED,
      clientDataJSON: ASSERTION.client_data_json,
      authenticatorData: ASSERTION.authenticator_data,
      signature: ASSERTION.signature,
      userHandle: ASSERTION.user_handle,
    });
    const get = t.requests.find((x) => x.op === "passkey_get");
    expect(get).toEqual({
      op: "passkey_get",
      ctx: "passkey",
      origin: ORIGIN,
      top_origin: ORIGIN,
      rp_id: "login.atlas-cloud.test",
      item_id: ITEM,
      credential_id: CRED,
      challenge: GET.challenge,
    });
    expect(t.windows.removed).toEqual([100]);
  });

  it("refuses a pick of a passkey it did not offer", async () => {
    const t = setup();
    void t.pk.request(cs(), "r1", GET);
    await flush();
    await t.pk.init(t.tokenOf(), t.ui());
    await expect(t.pk.pick(t.tokenOf(), t.ui(), OTHER_ITEM, CRED)).rejects.toMatchObject({ code: "invalid" });
    expect(t.ops()).not.toContain("passkey_get");
  });

  it("refuses a token from another window tab", async () => {
    const t = setup();
    void t.pk.request(cs(), "r1", GET);
    await flush();
    await expect(t.pk.init(t.tokenOf(), { page: "passkey.html", tabId: 7 })).rejects.toMatchObject({ code: "invalid" });
  });

  it("cancel gives NotAllowedError", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    await t.pk.cancel(t.tokenOf(), t.ui());
    expect(await p).toEqual({ kind: "error", name: "NotAllowedError" });
    expect(t.ops()).not.toContain("passkey_get");
  });

  it("closing the window gives NotAllowedError", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    t.windows.close(100);
    expect(await p).toEqual({ kind: "error", name: "NotAllowedError" });
  });

  it("a navigation of the requesting frame cancels", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    for (const l of t.nav) l({ tabId: 7, frameId: 0, url: "https://elsewhere.test/" });
    expect(await p).toEqual({ kind: "error", name: "NotAllowedError" });
    expect(t.windows.removed).toEqual([100]);
  });

  it("the page's abort gives AbortError and closes the window", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    await t.pk.abort(cs(), "r1");
    expect(await p).toEqual({ kind: "error", name: "AbortError" });
    expect(t.windows.removed).toEqual([100]);
  });

  it("Autre appareil hands over to the browser", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", GET);
    await flush();
    await t.pk.other(t.tokenOf(), t.ui());
    expect(await p).toEqual({ kind: "fallback" });
  });

  it("a failed assertion keeps the window open with the error", async () => {
    const t = setup({ answer: (r) => (r.op === "passkey_get" ? new BgError("reprompt_required") : undefined) });
    void t.pk.request(cs(), "r1", GET);
    await flush();
    await t.pk.init(t.tokenOf(), t.ui());
    await expect(t.pk.pick(t.tokenOf(), t.ui(), ITEM, CRED)).rejects.toMatchObject({ code: "reprompt_required" });
    expect(t.windows.removed).toEqual([]);
  });
});

describe("passkey in a sign-in chain", () => {
  const running = (itemId: string, status: ChainView["status"] = "running"): ChainView => ({ itemId, status, steps: [] });

  it("signs without a window only while a chain the user started runs for the item holding it", async () => {
    const t = setup({ chain: running(ITEM) });
    const r = await t.pk.request(cs(), "r1", GET);
    expect(r.kind).toBe("assertion");
    expect(t.windows.created).toHaveLength(0);
    expect(t.requests.find((x) => x.op === "passkey_get")).toMatchObject({ ctx: "chain", item_id: ITEM, credential_id: CRED });
  });

  it("a chain for another item opens the window", async () => {
    const t = setup({ chain: running(OTHER_ITEM) });
    void t.pk.request(cs(), "r1", GET);
    await flush();
    expect(t.windows.created).toHaveLength(1);
    expect(t.ops()).not.toContain("passkey_get");
  });

  it("no chain (no click that started one) opens the window", async () => {
    const t = setup({ chain: null });
    void t.pk.request(cs(), "r1", GET);
    await flush();
    expect(t.windows.created).toHaveLength(1);
    expect(t.ops()).not.toContain("passkey_get");
  });

  it("an ended chain opens the window", async () => {
    for (const status of ["done", "stopped", "handoff"] as const) {
      const t = setup({ chain: running(ITEM, status) });
      void t.pk.request(cs(), "r1", GET);
      await flush();
      expect(t.windows.created).toHaveLength(1);
      expect(t.ops()).not.toContain("passkey_get");
    }
  });

  it("never creates a passkey from a chain", async () => {
    const t = setup({ chain: running(ITEM) });
    void t.pk.request(cs(), "r1", CREATE);
    await flush();
    expect(t.windows.created).toHaveLength(1);
    expect(t.ops()).not.toContain("passkey_create");
  });
});

describe("passkey creation", () => {
  it("creates after Enregistrer, in the vault offered", async () => {
    const t = setup({ passkeys: [] });
    const p = t.pk.request(cs(), "r1", { ...CREATE, rpId: "atlas-cloud.test" });
    await flush();
    const init = await t.pk.init(t.tokenOf(), t.ui());
    expect(init).toMatchObject({ kind: "create", userName: "alex@atlas.dev", rpId: "atlas-cloud.test", vaults: [{ id: "v1", name: "Personnel" }, { id: "v2", name: "Travail" }] });
    await expect(t.pk.save(t.tokenOf(), t.ui(), "v9")).rejects.toMatchObject({ code: "invalid" });
    await t.pk.save(t.tokenOf(), t.ui(), "v2");
    expect(await p).toEqual({
      kind: "registration",
      credentialId: CRED2,
      clientDataJSON: REGISTRATION.client_data_json,
      attestationObject: REGISTRATION.attestation_object,
      authenticatorData: REGISTRATION.authenticator_data,
      publicKey: REGISTRATION.public_key,
      publicKeyAlgorithm: -7,
    });
    expect(t.requests.find((x) => x.op === "passkey_create")).toEqual({
      op: "passkey_create",
      ctx: "passkey",
      origin: ORIGIN,
      top_origin: ORIGIN,
      rp_id: "atlas-cloud.test",
      user_name: "alex@atlas.dev",
      user_handle: "dXNlci0x",
      challenge: CREATE.challenge,
      exclude: [],
      vault_id: "v2",
    });
  });

  it("an excluded credential already in OnePass gives InvalidStateError after consent", async () => {
    const t = setup();
    const p = t.pk.request(cs(), "r1", { ...CREATE, exclude: [CRED] });
    await flush();
    await t.pk.init(t.tokenOf(), t.ui());
    await t.pk.save(t.tokenOf(), t.ui());
    expect(await p).toEqual({ kind: "error", name: "InvalidStateError" });
    expect(t.ops()).not.toContain("passkey_create");
  });
});

describe("passkey router", () => {
  const sender = (url: string, extra: Record<string, unknown> = {}) => ({ id: EXT_ID, url, tab: { id: 7 }, frameId: 0, ...extra });

  function routed(t: ReturnType<typeof setup>) {
    const router = createPasskeyRouter({ id: EXT_ID, getURL: (p) => EXT_ORIGIN + p }, t.pk);
    return (m: unknown, s: Record<string, unknown>) =>
      new Promise<unknown>((resolve) => {
        const r = router(m, s as never, resolve);
        if (r !== true) resolve("no-reply");
      });
  }

  it("refuses an invalid request shape (nothing reaches the host)", async () => {
    const t = setup();
    const send = routed(t);
    const bad = [
      { type: "passkey_request", reqId: "r1", request: { kind: "get", challenge: "", allow: [] } },
      { type: "passkey_request", reqId: "r1", request: { kind: "get", challenge: "a+b/", allow: [] } },
      { type: "passkey_request", reqId: "r1", request: { kind: "get", challenge: "AAAA", allow: "x" } },
      { type: "passkey_request", reqId: "r1", request: { kind: "get", challenge: "A".repeat(2000), allow: [] } },
      { type: "passkey_request", reqId: "r1", request: { kind: "get", challenge: "AAAA", allow: Array(65).fill("AAAA") } },
      { type: "passkey_request", reqId: "r1", request: { kind: "create", challenge: "AAAA", userId: "", userName: "a", exclude: [], algs: [-7] } },
      { type: "passkey_request", reqId: "r1", request: { kind: "create", challenge: "AAAA", userId: "A".repeat(100), userName: "a", exclude: [], algs: [-7] } },
      { type: "passkey_request", reqId: "r1", request: { kind: "sign", challenge: "AAAA" } },
      { type: "passkey_request", reqId: "../../x", request: GET },
    ];
    for (const m of bad) expect(await send(m, sender(`${ORIGIN}/`))).toBe("no-reply");
    expect(t.requests).toHaveLength(0);
  });

  it("ignores an origin the page puts in the request", async () => {
    const t = setup({ passkeys: [] });
    const send = routed(t);
    const r = await send({ type: "passkey_request", reqId: "r1", request: { ...GET, origin: "https://bank.test" }, origin: "https://bank.test" }, sender(`${ORIGIN}/`, { origin: ORIGIN }));
    expect(t.requests[0]).toMatchObject({ origin: ORIGIN });
    expect(r).toEqual({ ok: expect.anything() });
  });

  it("routes passkey.html messages only from passkey.html", async () => {
    const t = setup();
    const send = routed(t);
    expect(await send({ type: "passkey_cancel", token: "AbCdEfGhIjKlMnOpQrStUv" }, sender(`${EXT_ORIGIN}menu.html#x`))).toBe("no-reply");
    expect(await send({ type: "passkey_cancel", token: "AbCdEfGhIjKlMnOpQrStUv" }, sender(`${EXT_ORIGIN}passkey.html#x`))).toEqual({ err: "invalid" });
    expect(await send({ type: "menu_close", token: "AbCdEfGhIjKlMnOpQrStUv" }, sender(`${EXT_ORIGIN}passkey.html#x`))).toBe("no-reply");
  });

  it("answers a content request with a result", async () => {
    const t = setup({ passkeys: [] });
    const send = routed(t);
    const r = (await send({ type: "passkey_request", reqId: "r1", request: GET }, sender(`${ORIGIN}/`))) as { ok: PasskeyResult };
    expect(r.ok).toEqual({ kind: "fallback" });
  });
});
