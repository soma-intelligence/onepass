import { assert, assertEquals, assertRejects } from "@std/assert";
import * as proto from "./proto.ts";
import { Refusal } from "./errors.ts";
import { checkRequest, importCredentialKey, onCurve, verifyRequest, verifySignature } from "./verify.ts";
import { fromHex, newKey, signatureHeaderFor, signedHeaders } from "./testutil.ts";

interface Vector {
  name: string;
  public_key: string;
  method: string;
  target: string;
  body: string;
  created: number;
  keyid: string;
  content_digest: string;
  signature_input: string;
  signature_bytes: string;
  signature: string;
}

const vectors: Vector[] = JSON.parse(
  await Deno.readTextFile(
    new URL("../../../../core/onepass-mailbox-proto/tests/vectors/signature.json", import.meta.url),
  ),
).vectors;

function request(v: Vector, over: Partial<{ body: Uint8Array; signature: string; input: string }> = {}) {
  const headers = new Headers({
    "content-digest": v.content_digest,
    "signature-input": over.input ?? v.signature_input,
    "signature": over.signature ?? v.signature,
  });
  return { method: v.method, target: v.target, headers, body: over.body ?? fromHex(v.body) };
}

async function refusedWith(code: string, p: Promise<unknown>) {
  const e = await assertRejects(() => p, Refusal);
  assertEquals((e as Refusal).code, code);
}

Deno.test("frozen vectors verify with WebCrypto", async () => {
  assert(vectors.length >= 4);
  for (const v of vectors) {
    const checked = await verifyRequest(request(v), fromHex(v.public_key), v.created);
    assertEquals(checked.params.keyid, fromHex(v.keyid), v.name);
    assertEquals(checked.params.created, BigInt(v.created), v.name);
  }
});

Deno.test("one changed body byte is bad_signature", async () => {
  for (const v of vectors) {
    const body = fromHex(v.body);
    const changed = body.length ? body.slice() : new Uint8Array([0]);
    changed[0] ^= 1;
    await refusedWith("bad_signature", verifyRequest(request(v, { body: changed }), fromHex(v.public_key), v.created));
  }
});

Deno.test("created 301 s off is stale_request, 300 s passes", async () => {
  const v = vectors[0];
  const pk = fromHex(v.public_key);
  await refusedWith("stale_request", verifyRequest(request(v), pk, v.created + 301));
  await refusedWith("stale_request", verifyRequest(request(v), pk, v.created - 301));
  await verifyRequest(request(v), pk, v.created + 300);
  await verifyRequest(request(v), pk, v.created - 300);
});

Deno.test("keyid not matching the body key of POST /v1/mailboxes is bad_signature", async () => {
  const k = await newKey();
  const other = await newKey();
  const body = new Uint8Array([1, 2, 3]);
  const created = 1_793_404_800;
  const headers = await signedHeaders(k, { method: "POST", target: "/v1/mailboxes", body, created, keyid: other.id });
  await refusedWith(
    "bad_signature",
    verifyRequest({ method: "POST", target: "/v1/mailboxes", headers, body }, k.pub, created),
  );
  // The same request with the right keyid passes.
  const good = await signedHeaders(k, { method: "POST", target: "/v1/mailboxes", body, created });
  await verifyRequest({ method: "POST", target: "/v1/mailboxes", headers: good, body }, k.pub, created);
});

Deno.test("a frozen vector checked against another vector's key is bad_signature", async () => {
  await refusedWith(
    "bad_signature",
    verifyRequest(request(vectors[0]), fromHex(vectors[1].public_key), vectors[0].created),
  );
});

Deno.test("non-canonical S (S + L) is bad_signature", async () => {
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  for (const v of vectors) {
    const sig = fromHex(v.signature_bytes);
    let s = 0n;
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]);
    let t = s + L;
    assert(t < 1n << 256n);
    const bad = sig.slice();
    for (let i = 0; i < 32; i++) {
      bad[32 + i] = Number(t & 0xffn);
      t >>= 8n;
    }
    await refusedWith(
      "bad_signature",
      verifyRequest(request(v, { signature: signatureHeaderFor(bad) }), fromHex(v.public_key), v.created),
    );
  }
});

Deno.test("header values are used as given, never trimmed", async () => {
  const v = vectors[1];
  const base = request(v);
  for (
    const [name, value] of [
      ["signature-input", " " + v.signature_input],
      ["signature-input", v.signature_input + " "],
      ["signature", v.signature + "\t"],
      ["content-digest", " " + v.content_digest],
    ]
  ) {
    const headers = { get: (n: string) => (n === name ? value : base.headers.get(n)) };
    await refusedWith(
      "bad_signature",
      verifyRequest({ ...base, headers }, fromHex(v.public_key), v.created),
    );
  }
});

Deno.test("missing or doubled headers are bad_signature", async () => {
  const v = vectors[1];
  for (const name of ["signature-input", "signature", "content-digest"]) {
    const r = request(v);
    r.headers.delete(name);
    await refusedWith("bad_signature", verifyRequest(r, fromHex(v.public_key), v.created));
  }
  const r = request(v);
  r.headers.append("signature", v.signature);
  await refusedWith("bad_signature", verifyRequest(r, fromHex(v.public_key), v.created));
});

Deno.test("target the URL parser would rewrite is bad_signature", async () => {
  const k = await newKey();
  const created = 1_793_404_800;
  for (const target of ["/v1/mailboxes/../x", "/v1/%2e%2E/b", "/v1/a b", "/v1/a\\b", "/v1/x?"]) {
    // signedHeaders goes through the proto, which refuses to sign these.
    let threw = false;
    try {
      await signedHeaders(k, { method: "GET", target, created });
    } catch {
      threw = true;
    }
    assert(threw, target);
    const headers = await signedHeaders(k, { method: "GET", target: "/v1/x", created });
    await refusedWith(
      "bad_signature",
      verifyRequest({ method: "GET", target, headers, body: new Uint8Array() }, k.pub, created),
    );
  }
});

Deno.test("checkRequest touches nothing but the request", () => {
  const v = vectors[1];
  const c = checkRequest(v.method, v.target, request(v).headers, fromHex(v.body), v.created);
  assertEquals(c.sig, fromHex(v.signature_bytes));
});

Deno.test("off-curve keys are refused at import", async () => {
  const enc = (y: bigint) => {
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      b[i] = Number(y & 0xffn);
      y >>= 8n;
    }
    return b;
  };
  // y = 2, 7, 8, 11 have no x on the curve; 3, 4, 5 do (independent check:
  // Euler's criterion in Python on (y^2 - 1) / (d y^2 + 1)).
  for (const y of [2n, 7n, 8n, 11n]) {
    assert(!onCurve(enc(y)), `y=${y}`);
    await assertRejects(() => importCredentialKey(enc(y)));
  }
  for (const y of [3n, 4n, 5n, 1n]) assert(onCurve(enc(y)), `y=${y}`);
  // y >= p is not canonical, and x = 0 with the sign bit is "negative zero".
  const p = (1n << 255n) - 19n;
  assert(!onCurve(enc(p)));
  assert(!onCurve(enc(p + 1n)));
  assert(!onCurve(enc(1n | (1n << 255n))));
  for (const v of vectors) {
    assert(onCurve(fromHex(v.public_key)), v.name);
    await importCredentialKey(fromHex(v.public_key));
  }
  // A stored key that is off the curve fails as a signature, not a crash.
  const v = vectors[0];
  const c = checkRequest(v.method, v.target, request(v).headers, fromHex(v.body), v.created);
  await refusedWith("bad_signature", verifySignature(c, enc(2n)));
});

Deno.test("wasm exports used by the edge keep their shapes", () => {
  const q = proto.parseChangesQuery("after=12&limit=500&full=1");
  assertEquals(q, { after: 12n, limit: 500, full: true });
  let threw = false;
  try {
    proto.decodeCommit(new Uint8Array([1, 0]));
  } catch {
    threw = true;
  }
  assert(threw, "empty commit refused by the proto decoder");
});
