import { describe, expect, it } from "vitest";
import { type RelayPort, RELAY_MAX_IN_FLIGHT, attachRelay } from "../../src/content/passkey";
import { type ShimPort, encodeRequest, fromB64url, toB64url, wrapCredentials } from "../../src/content/passkey-shim";
import type { PasskeyCsToBg } from "../../src/shared/messages";

const flush = () => new Promise((r) => setTimeout(r, 0));
const bytes = (...b: number[]) => new Uint8Array(b);
const text = (buf: ArrayBuffer) => new TextDecoder().decode(buf);

/** The relay end of the shim's port: records requests, answers on demand. */
class RelayEnd implements ShimPort {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  readonly got: Record<string, unknown>[] = [];
  postMessage(m: unknown): void {
    this.got.push(m as Record<string, unknown>);
  }
  answer(result: unknown, n = this.got.length - 1): void {
    this.onmessage?.({ data: { type: "result", id: this.got[n]?.id, result } });
  }
}

class Protos {
  credential = { kind: "PublicKeyCredential" };
  assertion = { kind: "AuthenticatorAssertionResponse" };
  attestation = { kind: "AuthenticatorAttestationResponse" };
}

function shim(o: { port?: boolean; secure?: boolean } = {}) {
  const calls: { kind: string; options: unknown }[] = [];
  const creds = {
    get: async (options?: unknown) => (calls.push({ kind: "get", options }), "browser-get"),
    create: async (options?: unknown) => (calls.push({ kind: "create", options }), "browser-create"),
  };
  const relay = new RelayEnd();
  const protos = new Protos();
  wrapCredentials(creds, {
    port: () => (o.port === false ? null : relay),
    secure: () => o.secure !== false,
    protos,
    DOMException,
  });
  return { creds, calls, relay, protos };
}

const getOptions = () => ({
  publicKey: {
    challenge: bytes(1, 2, 3, 4),
    rpId: "atlas-cloud.test",
    allowCredentials: [{ type: "public-key", id: bytes(9, 9).buffer }],
    timeout: 60_000,
  },
});

const createOptions = () => ({
  publicKey: {
    challenge: bytes(1, 2, 3, 4),
    rp: { id: "atlas-cloud.test", name: "Atlas" },
    user: { id: bytes(7, 7, 7), name: "alex@atlas.dev", displayName: "Alex" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    excludeCredentials: [{ type: "public-key", id: bytes(5) }],
  },
});

const CDJ = toB64url(new TextEncoder().encode('{"type":"webauthn.get"}'));
const ASSERTION = {
  kind: "assertion",
  credentialId: "q83vEjRWeJA",
  clientDataJSON: CDJ,
  authenticatorData: "AAAA",
  signature: "MEUC",
  userHandle: "dXNlci0x",
};

describe("passkey shim (MAIN world)", () => {
  it("leaves non-publicKey, conditional and malformed requests to the browser", async () => {
    const { creds, calls, relay } = shim();
    await creds.get({ password: true });
    await creds.get({ publicKey: getOptions().publicKey, mediation: "conditional" });
    await creds.get({ publicKey: { challenge: "not bytes" } });
    await creds.create({ publicKey: { ...createOptions().publicKey, authenticatorSelection: { authenticatorAttachment: "cross-platform" } } });
    expect(calls.map((c) => c.kind)).toEqual(["get", "get", "get", "create"]);
    expect(relay.got).toHaveLength(0);
  });

  it("leaves userVerification \"required\" to the browser (the bridge signs with UV=0)", async () => {
    const { creds, calls, relay } = shim();
    await creds.get({ publicKey: { ...getOptions().publicKey, userVerification: "required" } });
    await creds.create({ publicKey: { ...createOptions().publicKey, authenticatorSelection: { userVerification: "required" } } });
    expect(calls.map((c) => c.kind)).toEqual(["get", "create"]);
    expect(relay.got).toHaveLength(0);
    void creds.get({ publicKey: { ...getOptions().publicKey, userVerification: "preferred" } });
    expect(relay.got).toHaveLength(1);
  });

  it("uses the browser's API without the relay or off HTTPS", async () => {
    for (const o of [{ port: false }, { secure: false }]) {
      const { creds, calls } = shim(o);
      expect(await creds.get(getOptions())).toBe("browser-get");
      expect(calls).toHaveLength(1);
    }
  });

  it("sends only public values, base64url, never an origin", async () => {
    const { creds, relay } = shim();
    void creds.get(getOptions());
    expect(relay.got[0]).toEqual({
      type: "request",
      id: "p1",
      request: { kind: "get", challenge: "AQIDBA", rpId: "atlas-cloud.test", allow: ["CQk"], timeout: 60_000 },
    });
    void creds.create(createOptions());
    expect(relay.got[1]?.request).toEqual({
      kind: "create",
      challenge: "AQIDBA",
      rpId: "atlas-cloud.test",
      userId: "BwcH",
      userName: "alex@atlas.dev",
      exclude: ["BQ"],
      algs: [-7],
    });
  });

  it("falls back to the browser's API when the worker says so", async () => {
    const { creds, calls, relay } = shim();
    const p = creds.get(getOptions());
    relay.answer({ kind: "fallback" });
    expect(await p).toBe("browser-get");
    expect(calls).toHaveLength(1);
  });

  it("rejects with NotAllowedError on cancel", async () => {
    const { creds, relay } = shim();
    const p = creds.get(getOptions());
    relay.answer({ kind: "error", name: "NotAllowedError" });
    await expect(p).rejects.toMatchObject({ name: "NotAllowedError" });
    await expect(p).rejects.toBeInstanceOf(DOMException);
  });

  it("returns a conforming assertion", async () => {
    const { creds, relay, protos } = shim();
    const p = creds.get(getOptions());
    relay.answer(ASSERTION);
    const c = (await p) as unknown as Record<string, unknown> & { response: Record<string, unknown> };
    expect(Object.getPrototypeOf(c)).toBe(protos.credential);
    expect(Object.getPrototypeOf(c.response)).toBe(protos.assertion);
    expect(c.id).toBe("q83vEjRWeJA");
    expect(c.type).toBe("public-key");
    expect(c.authenticatorAttachment).toBe("platform");
    expect(c.rawId).toBeInstanceOf(ArrayBuffer);
    expect(toB64url(new Uint8Array(c.rawId as ArrayBuffer))).toBe("q83vEjRWeJA");
    expect(c.response.clientDataJSON).toBeInstanceOf(ArrayBuffer);
    expect(text(c.response.clientDataJSON as ArrayBuffer)).toBe('{"type":"webauthn.get"}');
    expect(c.response.authenticatorData).toBeInstanceOf(ArrayBuffer);
    expect(c.response.signature).toBeInstanceOf(ArrayBuffer);
    expect(text(c.response.userHandle as ArrayBuffer)).toBe("user-1");
    expect((c.getClientExtensionResults as () => unknown)()).toEqual({});
    expect((c.toJSON as () => unknown)()).toMatchObject({ id: "q83vEjRWeJA", rawId: "q83vEjRWeJA", response: { clientDataJSON: CDJ } });
  });

  it("returns a conforming registration with getPublicKey", async () => {
    const { creds, relay, protos } = shim();
    const p = creds.create(createOptions());
    relay.answer({
      kind: "registration",
      credentialId: "AAECAwQFBgc",
      clientDataJSON: CDJ,
      attestationObject: "o2NmbXQ",
      authenticatorData: "BBBB",
      publicKey: "MFkw",
      publicKeyAlgorithm: -7,
    });
    const c = (await p) as unknown as Record<string, unknown> & { response: Record<string, unknown> };
    expect(Object.getPrototypeOf(c.response)).toBe(protos.attestation);
    const r = c.response as Record<string, () => unknown>;
    expect(c.response.attestationObject).toBeInstanceOf(ArrayBuffer);
    expect(r.getPublicKey?.()).toBeInstanceOf(ArrayBuffer);
    expect(toB64url(new Uint8Array(r.getPublicKey?.() as ArrayBuffer))).toBe("MFkw");
    expect(r.getPublicKeyAlgorithm?.()).toBe(-7);
    expect(r.getAuthenticatorData?.()).toBeInstanceOf(ArrayBuffer);
    expect(r.getTransports?.()).toEqual(["internal", "hybrid"]);
  });

  it("an aborted signal rejects with AbortError and tells the relay", async () => {
    const { creds, relay } = shim();
    const ctl = new AbortController();
    const p = creds.get({ ...getOptions(), signal: ctl.signal });
    ctl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(relay.got[1]).toEqual({ type: "abort", id: "p1" });
  });

  it("encodes and decodes base64url", () => {
    expect(toB64url(new Uint8Array(fromB64url("-_8BAgMEBQYHCA")))).toBe("-_8BAgMEBQYHCA");
    expect(encodeRequest("get", {})).toBeNull();
  });
});

class ShimEnd implements RelayPort {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  readonly got: Record<string, unknown>[] = [];
  postMessage(m: unknown): void {
    this.got.push(m as Record<string, unknown>);
  }
  send(data: unknown): void {
    this.onmessage?.({ data });
  }
}

function relay(answer: (m: PasskeyCsToBg) => unknown = () => ({ ok: { kind: "fallback" } }), active = { now: false }) {
  const sent: PasskeyCsToBg[] = [];
  const port = new ShimEnd();
  attachRelay(
    port,
    async (m) => {
      sent.push(structuredClone(m));
      return answer(m);
    },
    () => active.now,
  );
  return { port, sent, active };
}

const GET = { kind: "get", challenge: "AQIDBA", allow: [] };

describe("passkey relay (isolated world)", () => {
  it("says ready on the port it took", () => {
    const { port } = relay();
    expect(port.got[0]).toEqual({ type: "ready" });
  });

  it("refuses an invalid request shape without reaching the worker", async () => {
    const { port, sent } = relay();
    const bad = [
      { kind: "get", challenge: "", allow: [] },
      { kind: "get", challenge: "AQ==", allow: [] },
      { kind: "get", challenge: "AQID", allow: [1] },
      { kind: "get", challenge: "A".repeat(5000), allow: [] },
      { kind: "create", challenge: "AQID", userId: "AQ", userName: "", exclude: [], algs: [-7] },
      { kind: "create", challenge: "AQID", userId: "AQ", userName: "x", exclude: [], algs: ["-7"] },
      { kind: "delete", challenge: "AQID" },
      null,
    ];
    bad.forEach((request, i) => port.send({ type: "request", id: `b${i}`, request }));
    await flush();
    expect(sent).toHaveLength(0);
    expect(port.got.slice(1).map((m) => m.result)).toEqual(bad.map(() => ({ kind: "fallback" })));
  });

  it("forwards a rebuilt request: an origin the page adds is dropped", async () => {
    const { port, sent } = relay();
    port.send({ type: "request", id: "p1", request: { ...GET, origin: "https://bank.test", top_origin: "https://bank.test" } });
    await flush();
    expect(sent).toEqual([{ type: "passkey_request", reqId: "p1", request: GET, activated: false }]);
  });

  it("tells the worker whether the page's call came with a user activation", async () => {
    const { port, sent, active } = relay();
    active.now = true;
    port.send({ type: "request", id: "p1", request: GET });
    active.now = false;
    port.send({ type: "request", id: "p2", request: GET });
    await flush();
    expect(sent.map((m) => (m.type === "passkey_request" ? m.activated : null))).toEqual([true, false]);
  });

  it("a page cannot claim the activation itself", async () => {
    const { port, sent } = relay();
    port.send({ type: "request", id: "p1", request: GET, activated: true });
    await flush();
    expect(sent[0]).toMatchObject({ activated: false });
  });

  it("passes a checked result back, a malformed one as fallback", async () => {
    let next: unknown = { ok: { kind: "error", name: "NotAllowedError" } };
    const { port } = relay(() => next);
    port.send({ type: "request", id: "p1", request: GET });
    await flush();
    expect(port.got[1]).toEqual({ type: "result", id: "p1", result: { kind: "error", name: "NotAllowedError" } });
    next = { ok: { kind: "assertion", credentialId: "x y" } };
    port.send({ type: "request", id: "p2", request: GET });
    await flush();
    expect(port.got[2]).toEqual({ type: "result", id: "p2", result: { kind: "fallback" } });
    next = { err: "internal" };
    port.send({ type: "request", id: "p3", request: GET });
    await flush();
    expect(port.got[3]?.result).toEqual({ kind: "fallback" });
  });

  it("forwards an abort", async () => {
    const { port, sent } = relay();
    port.send({ type: "abort", id: "p1" });
    await flush();
    expect(sent).toEqual([{ type: "passkey_abort", reqId: "p1" }]);
  });

  it("bounds the requests in flight", async () => {
    const { port, sent } = relay(() => new Promise(() => undefined));
    for (let i = 0; i <= RELAY_MAX_IN_FLIGHT; i++) port.send({ type: "request", id: `p${i}`, request: GET });
    await flush();
    expect(sent).toHaveLength(RELAY_MAX_IN_FLIGHT);
    expect(port.got.at(-1)).toEqual({ type: "result", id: `p${RELAY_MAX_IN_FLIGHT}`, result: { kind: "fallback" } });
  });
});
