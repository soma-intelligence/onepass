import { assert, assertEquals } from "@std/assert";
import * as proto from "./proto.ts";
import { type Code, CODES } from "./errors.ts";
import type { Arg, Db, Fn, Row, Tx } from "./db.ts";
import type { Signer } from "./storage.ts";
import { type Deps, handler as makeHandler } from "./routes.ts";
import { DEFAULT_IP_SOURCE, FALLBACK_ADDRESS, ipKey } from "./ip.ts";

/**
 * The handler as the gateway reaches it: the client wrote a fake leftmost
 * X-Forwarded-For entry, the trusted proxy appended the real address.
 */
function handler(d: Deps): (req: Request, ip: string) => Promise<Response> {
  const h = makeHandler(d);
  return (req, ip) => {
    req.headers.set("x-forwarded-for", `198.51.100.99, ${ip}`);
    return h(req);
  };
}
import { edSign, newKey, signedHeaders, type TestKey, toHex } from "./testutil.ts";

const NOW = 1_793_404_800_000; // ms, 2026-11-01T00:00:00Z
const IP = "203.0.113.7";
const SECRET = new TextEncoder().encode("ip secret of the day, test only");
const M = new Uint8Array(16).fill(0x11);
const MHEX = toHex(M);

type Answer = (fn: Fn, args: Arg[]) => Row[] | Promise<Row[]>;

class FakeDb implements Db {
  calls: { fn: Fn; args: Arg[] }[] = [];
  commits = 0;
  rollbacks = 0;
  constructor(public answer: Answer = () => []) {}
  async transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    try {
      const r = await work({
        call: async (fn, args) => {
          this.calls.push({ fn, args });
          return await this.answer(fn, args);
        },
      });
      this.commits++;
      return r;
    } catch (e) {
      this.rollbacks++;
      throw e;
    }
  }
  fns(): Fn[] {
    return this.calls.map((c) => c.fn);
  }
}

class FakeSigner implements Signer {
  uploads: string[] = [];
  downloads: string[] = [];
  upload(n: string) {
    this.uploads.push(n);
    return Promise.resolve(`https://storage.test/upload/${n}?token=t`);
  }
  download(n: string) {
    this.downloads.push(n);
    return Promise.resolve(`https://storage.test/download/${n}?token=t`);
  }
}

function deps(db: FakeDb, over: Partial<Deps> = {}): Deps & { clock: { t: number }; slept: number[] } {
  const clock = { t: NOW };
  const slept: number[] = [];
  return {
    db,
    signer: new FakeSigner(),
    ipSecret: SECRET,
    ipSource: DEFAULT_IP_SOURCE,
    openSignup: false,
    publishableKey: "pk-test",
    realtimeUrl: "wss://example.test/realtime/v1",
    now: () => clock.t,
    sleep: (ms: number) => {
      slept.push(ms);
      clock.t += ms;
      return Promise.resolve();
    },
    clock,
    slept,
    ...over,
  };
}

const ok = (extra: Row = {}): Row => ({ status: "ok", retry_after: null, ...extra });

function errorBody(code: Code, retry: number | null = null): Uint8Array {
  return proto.encodeError({ code: CODES[code].wire, retry_after: retry });
}

async function bytes(r: Response): Promise<Uint8Array> {
  return new Uint8Array(await r.arrayBuffer());
}

async function assertError(r: Response, code: Code, retry: number | null = null) {
  assertEquals(r.status, CODES[code].status, `status for ${code}`);
  assertEquals(await bytes(r), errorBody(code, retry), `body for ${code}`);
}

function url(target: string): string {
  return `http://localhost/mailbox${target}`;
}

async function signed(
  key: TestKey,
  method: string,
  target: string,
  body?: Uint8Array,
  created = NOW / 1000,
): Promise<Request> {
  const headers = await signedHeaders(key, { method, target, body, created });
  return new Request(url(target), { method, headers, body: body && body.length ? (body as BodyInit) : undefined });
}

/** credential_key answers with `key`; everything else with `rest`. */
function withKey(key: TestKey, rest: Answer = () => [ok()]): Answer {
  return (fn, args) => {
    if (fn === "ip_gate") return [ok()];
    if (fn === "credential_key") return [ok({ mailbox_id: M, public_key: key.pub, revoked: false })];
    return rest(fn, args);
  };
}

// --------------------------------------------------------------- routing

Deno.test("unknown route is 404 no_route without SQL", async () => {
  const db = new FakeDb();
  const h = handler(deps(db));
  for (
    const [method, u] of [
      ["GET", url("/v1/nothing")],
      ["GET", url("/v2/config")],
      ["POST", url("/v1/config")],
      ["GET", url(`/v1/mailboxes/${"AB".repeat(16)}`)],
      ["GET", url(`/v1/mailboxes/${MHEX}/records/0/${MHEX}`)],
      ["GET", url(`/v1/mailboxes/${MHEX}/records/256/${MHEX}`)],
      ["PUT", url(`/v1/rendezvous/${MHEX}/2/0`)],
      ["PUT", url(`/v1/rendezvous/${MHEX}/0/4096`)],
      ["GET", "http://localhost/other/v1/config"],
    ]
  ) {
    await assertError(await h(new Request(u, { method }), IP), "no_route");
  }
  assertEquals(db.calls.length, 0);
});

Deno.test("GET /v1/config answers ServerConfig without the database", async () => {
  const db = new FakeDb();
  const r = await handler(deps(db, { openSignup: true }))(new Request(url("/v1/config")), IP);
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("content-type"), proto.CONTENT_TYPE);
  assertEquals(
    await bytes(r),
    proto.encodeConfig({
      realtime_url: "wss://example.test/realtime/v1",
      publishable_key: "pk-test",
      open_signup: true,
    }),
  );
  assertEquals(db.calls.length, 0);
});

Deno.test("a body of 4 MiB + 1 is 413 without SQL", async () => {
  const k = await newKey();
  const db = new FakeDb(withKey(k));
  const h = handler(deps(db));
  const big = new Uint8Array(proto.COMMIT_BODY_MAX + 1);
  const target = `/v1/mailboxes/${MHEX}/commit`;
  // Announced by Content-Length.
  await assertError(await h(await signed(k, "POST", target, big), IP), "too_large");
  // Streamed without a length: the read stops past the cap.
  let pulled = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (pulled >= big.length) return c.close();
      const n = Math.min(65536, big.length - pulled);
      pulled += n;
      c.enqueue(new Uint8Array(n));
    },
  });
  const headers = await signedHeaders(k, { method: "POST", target, body: big, created: NOW / 1000 });
  const req = new Request(url(target), { method: "POST", headers, body: stream });
  await assertError(await h(req, IP), "too_large");
  assertEquals(db.calls.length, 0);
});

Deno.test("an unsigned or badly signed request on a signed route makes no SQL call", async () => {
  const k = await newKey();
  const db = new FakeDb(withKey(k));
  const h = handler(deps(db));
  const target = `/v1/mailboxes/${MHEX}`;
  await assertError(await h(new Request(url(target)), IP), "bad_signature");
  await assertError(await h(await signed(k, "GET", target, undefined, NOW / 1000 - 301), IP), "stale_request");
  // A changed body never reaches the lookup either (digest).
  const t2 = `/v1/mailboxes/${MHEX}/commit`;
  const hs = await signedHeaders(k, { method: "POST", target: t2, body: new Uint8Array([1, 2]), created: NOW / 1000 });
  await assertError(
    await h(new Request(url(t2), { method: "POST", headers: hs, body: new Uint8Array([1, 3]) }), IP),
    "bad_signature",
  );
  assertEquals(db.calls.length, 0);

  // A well formed signature over another target needs the key to be found
  // wrong: the gate and the lookup run, never an entry point (no nonce).
  const wrongTarget = await signedHeaders(k, {
    method: "GET",
    target: `/v1/mailboxes/${MHEX}/changes?after=0&limit=1&full=0`,
    created: NOW / 1000,
  });
  await assertError(await h(new Request(url(target), { headers: wrongTarget }), IP), "bad_signature");
  assertEquals(db.fns(), ["ip_gate", "credential_key"]);
});

// ------------------------------------------------------------ SQL errors

const SQL_CODES = (Object.keys(CODES) as Code[]).filter((c) => c !== "no_route");

Deno.test("every raised OP errcode maps to its status and ErrorBody, rolled back", async () => {
  const k = await newKey();
  for (const code of SQL_CODES) {
    const db = new FakeDb(withKey(k, () => {
      throw { code: `OP${CODES[code].status}`, message: code, detail: code === "rate_limited" ? "7" : undefined };
    }));
    const r = await handler(deps(db))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP);
    await assertError(r, code, code === "rate_limited" ? 7 : null);
    assertEquals(db.rollbacks, 1, code);
  }
});

Deno.test("an unknown SQLSTATE or a mismatched OP code is 503 retry", async () => {
  const k = await newKey();
  for (
    const thrown of [
      { code: "40001", message: "could not serialize access" },
      { code: "P0001", message: "unknown mailbox error code x" },
      { code: "OP404", message: "replay" },
      { code: "OP999", message: "nope" },
      // no_route belongs to the router: SQL cannot claim it.
      { code: "OP404", message: "no_route" },
      new Error("connection reset"),
    ]
  ) {
    const db = new FakeDb(withKey(k, () => {
      throw thrown;
    }));
    await assertError(await handler(deps(db))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP), "retry");
  }
});

Deno.test("an absent record is not_found, never no_route; SQL cannot answer no_route", async () => {
  const k = await newKey();
  const target = `/v1/mailboxes/${MHEX}/records/5/${MHEX}`;
  const absent = new FakeDb(withKey(k, () => [{ status: "not_found", retry_after: null }]));
  await assertError(await handler(deps(absent))(await signed(k, "GET", target), IP), "not_found");
  const lying = new FakeDb(withKey(k, () => [{ status: "no_route", retry_after: null }]));
  await assertError(await handler(deps(lying))(await signed(k, "GET", target), IP), "retry");
});

Deno.test("in-band codes map to their status, and the transaction commits", async () => {
  const k = await newKey();
  for (const code of SQL_CODES) {
    const db = new FakeDb(withKey(k, () => [{ status: code, retry_after: code === "rate_limited" ? 9 : null }]));
    const r = await handler(deps(db))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP);
    await assertError(r, code, code === "rate_limited" ? 9 : null);
    assertEquals(db.rollbacks, 0, code);
    assertEquals(db.commits, 2, code); // gate + key, then the entry point
  }
});

Deno.test("credential_key with no row or unknown_credential is 403", async () => {
  const k = await newKey();
  for (const answer of [[], [{ status: "unknown_credential", retry_after: null }]]) {
    const db = new FakeDb((fn) => (fn === "ip_gate" ? [ok()] : answer as Row[]));
    await assertError(
      await handler(deps(db))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP),
      "unknown_credential",
    );
    assertEquals(db.fns(), ["ip_gate", "credential_key"]);
  }
});

Deno.test("the per-IP gate runs before credential_key and commits", async () => {
  const k = await newKey();
  const db = new FakeDb((fn) => (fn === "ip_gate" ? [{ status: "rate_limited", retry_after: 12 }] : [ok()]));
  const r = await handler(deps(db))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP);
  await assertError(r, "rate_limited", 12);
  assertEquals(r.headers.get("retry-after"), "12");
  assertEquals(db.fns(), ["ip_gate"]);
  assertEquals(db.commits, 1);
});

// -------------------------------------------------------------- IP key

async function expectedIpKey(ip: string, nowMs: number): Promise<Uint8Array> {
  const date = new Date(nowMs).toISOString().slice(0, 10);
  const k = await crypto.subtle.importKey("raw", SECRET, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(date + ip)));
}

function containsIp(args: Arg[]): boolean {
  const text = new TextEncoder().encode(IP);
  return args.some((a) => {
    const vs = Array.isArray(a.value) ? a.value : [a.value];
    return vs.some((v) =>
      (typeof v === "string" && (v as string).includes(IP)) ||
      (v instanceof Uint8Array && toHex(v).includes(toHex(text)))
    );
  });
}

Deno.test("the IP key is HMAC-SHA-256(secret, UTC date || ip) and the address never reaches SQL", async () => {
  assertEquals(await ipKey(SECRET, NOW, IP), await expectedIpKey(IP, NOW));
  assertEquals(await ipKey(SECRET, NOW + 86_400_000 - 1, IP), await expectedIpKey(IP, NOW));
  assert(toHex(await ipKey(SECRET, NOW + 86_400_000, IP)) !== toHex(await expectedIpKey(IP, NOW)));

  const k = await newKey();
  const created = { mailbox_id: M, incarnation: 7n, wake_topic: new Uint8Array(16).fill(2) };
  const db = new FakeDb((fn) => (fn === "api_create_mailbox" ? [ok(created)] : [ok()]));
  const create = createBody(k.pub, new Uint8Array([1, 2, 3]));
  const r = await handler(deps(db))(await signed(k, "POST", "/v1/mailboxes", create), IP);
  assertEquals(r.status, 200);
  assertEquals(await bytes(r), proto.encodeCreated(created));
  assertEquals(db.fns(), ["api_create_mailbox"]);
  const args = db.calls[0].args;
  assertEquals(args[5].value, await expectedIpKey(IP, NOW));
  assertEquals(args[0].value, k.pub);
  assertEquals(args[3].value, new Uint8Array([1, 2, 3]));
  assertEquals(args[6].value, false);
  for (const c of db.calls) assert(!containsIp(c.args));

  // Signed routes: the gate gets the same key, and nothing else sees the address.
  const db2 = new FakeDb(
    withKey(
      k,
      () => [
        ok({
          incarnation: 1n,
          wake_topic: new Uint8Array(16),
          min_cursor: 0n,
          max_bytes: 1n,
          max_records: 1,
          max_credentials: 1,
          req_per_min: 1,
          max_commit_ops: 1,
          bytes_used: 0n,
          records_count: 0,
          credentials_count: 1,
        }),
      ],
    ),
  );
  assertEquals((await handler(deps(db2))(await signed(k, "GET", `/v1/mailboxes/${MHEX}`), IP)).status, 200);
  assertEquals(db2.calls[0].args[0].value, await expectedIpKey(IP, NOW));
  for (const c of db2.calls) assert(!containsIp(c.args));
});

Deno.test("creation: the daily cap row (in-band retry) is a 503 retry without retry-after", async () => {
  const k = await newKey();
  const db = new FakeDb((fn) => (fn === "api_create_mailbox" ? [{ status: "retry", retry_after: null }] : [ok()]));
  const create = createBody(k.pub, new Uint8Array([1, 2, 3]));
  const r = await handler(deps(db))(await signed(k, "POST", "/v1/mailboxes", create), IP);
  assertEquals(r.status, 503);
  assertEquals(r.headers.get("retry-after"), null);
  await assertError(r, "retry");
});

/** CreateMailbox by hand: version, key, Some(invite), label. */
function createBody(pub: Uint8Array, invite: Uint8Array | null, label = new Uint8Array()): Uint8Array {
  const out = [1, ...pub];
  if (invite) out.push(1, invite.length, ...invite);
  else out.push(0);
  out.push(label.length, ...label);
  return new Uint8Array(out);
}

Deno.test("POST /v1/mailboxes: an off-curve body key is malformed, a keyid of another key is bad_signature", async () => {
  const k = await newKey();
  const db = new FakeDb(() => [ok()]);
  const h = handler(deps(db));
  const offCurve = new Uint8Array(32);
  offCurve[0] = 2;
  await assertError(
    await h(await signed(k, "POST", "/v1/mailboxes", createBody(offCurve, new Uint8Array([1]))), IP),
    "malformed",
  );
  const other = await newKey();
  await assertError(
    await h(await signed(k, "POST", "/v1/mailboxes", createBody(other.pub, new Uint8Array([1]))), IP),
    "bad_signature",
  );
  assertEquals(db.calls.length, 0);
});

// ------------------------------------------------------------ rendezvous

Deno.test("rdv_get waits at most 25 s in 500 ms steps, then 204; the IP key only on the first call", async () => {
  const db = new FakeDb(() => [ok({ data: null })]);
  const d = deps(db);
  const r = await handler(d)(new Request(url(`/v1/rendezvous/${MHEX}/0/3?wait=25`)), IP);
  assertEquals(r.status, 204);
  assert(d.slept.every((ms) => ms === 500));
  assertEquals(d.slept.reduce((x, y) => x + y, 0), 25_000);
  assertEquals(db.fns().length, 51);
  assert(db.fns().every((f) => f === "rdv_get"));
  assertEquals(db.calls[0].args[3].value, await expectedIpKey(IP, NOW));
  assert(db.calls.slice(1).every((c) => c.args[3].value === null));
  assertEquals(db.commits, 51);
});

Deno.test("rdv_get answers the frame as soon as it is there", async () => {
  let n = 0;
  const db = new FakeDb(() => [ok({ data: ++n === 4 ? new Uint8Array([9, 9]) : null })]);
  const d = deps(db);
  const r = await handler(d)(new Request(url(`/v1/rendezvous/${MHEX}/1/0?wait=25`)), IP);
  assertEquals(r.status, 200);
  assertEquals(await bytes(r), new Uint8Array([9, 9]));
  assertEquals(d.slept.length, 3);
  // wait above 25 or not canonical is malformed.
  for (const q of ["wait=26", "wait=025", "wait=", "x=1"]) {
    await assertError(
      await handler(deps(new FakeDb()))(new Request(url(`/v1/rendezvous/${MHEX}/1/0?${q}`)), IP),
      "malformed",
    );
  }
});

Deno.test("rdv_put: frame over 1 MiB is 413 without SQL, written frame 204, conflict 409", async () => {
  const db = new FakeDb(() => [ok()]);
  const h = handler(deps(db));
  await assertError(
    await h(
      new Request(url(`/v1/rendezvous/${MHEX}/0/0`), { method: "PUT", body: new Uint8Array(proto.RDV_FRAME_MAX + 1) }),
      IP,
    ),
    "too_large",
  );
  assertEquals(db.calls.length, 0);
  const r = await h(new Request(url(`/v1/rendezvous/${MHEX}/0/0`), { method: "PUT", body: new Uint8Array([1]) }), IP);
  assertEquals(r.status, 204);
  assertEquals(db.calls[0].args[3].value, new Uint8Array([1]));
  const c = await handler(deps(new FakeDb(() => [{ status: "conflict", retry_after: null }])))(
    new Request(url(`/v1/rendezvous/${MHEX}/0/0`), { method: "PUT", body: new Uint8Array([1]) }),
    IP,
  );
  assertEquals(c.status, 409);
});

// ---------------------------------------------------------- signed routes

Deno.test("GET changes: query parsed by the proto, page with head and more", async () => {
  const k = await newKey();
  const rows = [
    ok({
      incarnation: 3n,
      min_cursor: 0n,
      head: 9n,
      seq: 4n,
      kind: 5,
      id: M,
      version: 2n,
      deleted: false,
      data: new Uint8Array([1]),
      blob_sha256: null,
      size: 1,
    }),
    ok({
      incarnation: 3n,
      min_cursor: 0n,
      head: 9n,
      seq: 6n,
      kind: 5,
      id: new Uint8Array(16).fill(2),
      version: 1n,
      deleted: true,
      data: null,
      blob_sha256: null,
      size: 0,
    }),
    ok({
      incarnation: 3n,
      min_cursor: 0n,
      head: 9n,
      seq: 7n,
      kind: 6,
      id: M,
      version: 1n,
      deleted: false,
      data: null,
      blob_sha256: new Uint8Array(32).fill(4),
      size: 20000,
    }),
  ];
  const db = new FakeDb(withKey(k, () => rows));
  const target = `/v1/mailboxes/${MHEX}/changes?after=3&limit=3&full=1`;
  const r = await handler(deps(db))(await signed(k, "GET", target), IP);
  assertEquals(r.status, 200);
  assertEquals(
    await bytes(r),
    proto.encodeChanges({
      incarnation: 3n,
      min_cursor: 0n,
      head: 9n,
      records: [
        { seq: 4n, kind: 5, id: M, version: 2n, body: { Inline: new Uint8Array([1]) } },
        { seq: 6n, kind: 5, id: new Uint8Array(16).fill(2), version: 1n, body: null },
        { seq: 7n, kind: 6, id: M, version: 1n, body: { Blob: { sha256: new Uint8Array(32).fill(4), size: 20000 } } },
      ],
      next_after: 7n,
      more: true,
    }),
  );
  const call = db.calls[2];
  assertEquals(call.fn, "api_changes");
  assertEquals(call.args.slice(4).map((x) => x.value), [3n, 3, true]);

  // Empty page: next_after echoes after, more is false.
  const empty = new FakeDb(withKey(k, () => [ok({ incarnation: 3n, min_cursor: 0n, head: 9n, seq: null })]));
  const e = await handler(deps(empty))(
    await signed(k, "GET", `/v1/mailboxes/${MHEX}/changes?after=9&limit=10&full=0`),
    IP,
  );
  assertEquals(
    await bytes(e),
    proto.encodeChanges({ incarnation: 3n, min_cursor: 0n, head: 9n, records: [], next_after: 9n, more: false }),
  );

  // A bad query is malformed and the entry point is never called.
  const bad = new FakeDb(withKey(k));
  await assertError(
    await handler(deps(bad))(await signed(k, "GET", `/v1/mailboxes/${MHEX}/changes?after=1&limit=0&full=0`), IP),
    "malformed",
  );
  assert(!bad.fns().includes("api_changes"));
});

function commitBody(
  ops: { kind: number; id: number; version: number; put?: { expected: number | null; data: number[] } }[],
): Uint8Array {
  const out = [1, ops.length];
  for (const o of ops) {
    out.push(o.kind, ...new Array(16).fill(o.id), o.version);
    if (o.put) {
      out.push(0);
      if (o.put.expected === null) out.push(0);
      else out.push(1, o.put.expected);
      out.push(0, o.put.data.length, ...o.put.data);
    } else {
      out.push(1);
    }
  }
  return new Uint8Array(out);
}

Deno.test("POST commit: arrays to SQL, Applied with None for a no-op delete, conflict is 409", async () => {
  const k = await newKey();
  const body = commitBody([
    { kind: 5, id: 1, version: 3, put: { expected: 2, data: [7, 7] } },
    { kind: 5, id: 2, version: 4 },
    { kind: 6, id: 3, version: 1, put: { expected: null, data: [] } },
  ]);
  const db = new FakeDb(withKey(k, () => [ok({ seq: 10n }), ok({ seq: null }), ok({ seq: 11n })]));
  const target = `/v1/mailboxes/${MHEX}/commit`;
  const r = await handler(deps(db))(await signed(k, "POST", target, body), IP);
  assertEquals(r.status, 200);
  assertEquals(await bytes(r), proto.encodeCommitResponse({ Applied: { seqs: [10n, null, 11n] } }));
  const args = db.calls[2].args.slice(4).map((x) => x.value);
  assertEquals(args, [
    [5, 5, 6],
    [new Uint8Array(16).fill(1), new Uint8Array(16).fill(2), new Uint8Array(16).fill(3)],
    [3n, 4n, 1n],
    [1, 2, 1],
    [2n, null, null],
    [new Uint8Array([7, 7]), null, new Uint8Array()],
    [null, null, null],
    [2, null, 0],
  ]);

  const conflict = new FakeDb(withKey(k, () => [
    {
      status: "conflict",
      retry_after: null,
      kind: 5,
      id: new Uint8Array(16).fill(1),
      seq: 8n,
      version: 2n,
      deleted: false,
      data: new Uint8Array([1]),
      blob_sha256: null,
      size: 1,
    },
    {
      status: "conflict",
      retry_after: null,
      kind: 6,
      id: new Uint8Array(16).fill(3),
      seq: null,
      version: null,
      deleted: null,
      data: null,
      blob_sha256: null,
      size: null,
    },
  ]));
  const c = await handler(deps(conflict))(await signed(k, "POST", target, body), IP);
  assertEquals(c.status, 409);
  assertEquals(
    await bytes(c),
    proto.encodeCommitResponse({
      Conflict: {
        current: [
          {
            kind: 5,
            id: new Uint8Array(16).fill(1),
            server: {
              seq: 8n,
              kind: 5,
              id: new Uint8Array(16).fill(1),
              version: 2n,
              body: { Inline: new Uint8Array([1]) },
            },
          },
          { kind: 6, id: new Uint8Array(16).fill(3), server: null },
        ],
      },
    }),
  );
  assertEquals(conflict.commits, 2);

  // An empty batch is malformed in the proto decoder: no entry point call.
  const empty = new FakeDb(withKey(k));
  await assertError(
    await handler(deps(empty))(await signed(k, "POST", target, new Uint8Array([1, 0])), IP),
    "malformed",
  );
  assert(!empty.fns().includes("api_commit"));
});

Deno.test("blob uploads: signed URLs exactly for the object names SQL returned, sorted", async () => {
  const k = await newKey();
  const sha1 = new Uint8Array(32).fill(1);
  const sha2 = new Uint8Array(32).fill(2);
  const name = (s: Uint8Array, g: number) => `${MHEX}/${toHex(s)}.${g}`;
  const db = new FakeDb(withKey(k, () => [
    ok({ sha256: sha1, needs_upload: true, object_name: name(sha1, 41) }),
    ok({ sha256: sha2, needs_upload: false, object_name: name(sha2, 7) }),
  ]));
  const signer = new FakeSigner();
  const body = new Uint8Array([1, 2, ...sha1, 0x81, 0x80, 0x01, ...sha2, 0x81, 0x80, 0x01]);
  const r = await handler(deps(db, { signer }))(
    await signed(k, "POST", `/v1/mailboxes/${MHEX}/blobs/uploads`, body),
    IP,
  );
  assertEquals(r.status, 200);
  assertEquals(signer.uploads, [name(sha1, 41)]);
  assertEquals(
    await bytes(r),
    proto.encodeBlobUrls({ urls: [[sha1, `https://storage.test/upload/${name(sha1, 41)}?token=t`], [sha2, null]] }),
  );
  assertEquals(db.calls[2].args.slice(4).map((x) => x.value), [[sha1, sha2], [16385, 16385]]);

  // A name outside the path mailbox, or for another hash, is never signed.
  for (const bad of [`${"22".repeat(16)}/${toHex(sha1)}.1`, name(sha2, 1), `${MHEX}/${toHex(sha1)}.0`]) {
    const s = new FakeSigner();
    const d = new FakeDb(withKey(k, () => [ok({ sha256: sha1, needs_upload: true, object_name: bad })]));
    const one = new Uint8Array([1, 1, ...sha1, 0x81, 0x80, 0x01]);
    await assertError(
      await handler(deps(d, { signer: s }))(await signed(k, "POST", `/v1/mailboxes/${MHEX}/blobs/uploads`, one), IP),
      "retry",
    );
    assertEquals(s.uploads, []);
  }
});

Deno.test("blob downloads: one entry per hash asked, null when not referenced", async () => {
  const k = await newKey();
  const sha1 = new Uint8Array(32).fill(1);
  const sha2 = new Uint8Array(32).fill(2);
  const db = new FakeDb(withKey(k, () => [ok({ sha256: sha2, size: 20000, object_name: `${MHEX}/${toHex(sha2)}.3` })]));
  const signer = new FakeSigner();
  const body = new Uint8Array([1, 2, ...sha1, ...sha2]);
  const r = await handler(deps(db, { signer }))(
    await signed(k, "POST", `/v1/mailboxes/${MHEX}/blobs/downloads`, body),
    IP,
  );
  assertEquals(r.status, 200);
  assertEquals(signer.downloads, [`${MHEX}/${toHex(sha2)}.3`]);
  assertEquals(
    await bytes(r),
    proto.encodeBlobUrls({
      urls: [[sha1, null], [sha2, `https://storage.test/download/${MHEX}/${toHex(sha2)}.3?token=t`]],
    }),
  );
});

Deno.test("enroll: request signed by the ticket's new key, ticket signed by the approver", async () => {
  const approver = await newKey();
  const fresh = await newKey();
  const ticket = {
    version: 1,
    mailbox_url: "https://x.test/functions/v1/mailbox",
    mailbox_id: M,
    new_credential_pub: fresh.pub,
    expires_at: BigInt(NOW / 1000 + 600),
    nonce: new Uint8Array(16).fill(5),
  };
  const tsig = await edSign(approver, proto.ticketSignedBytes(ticket));
  const enrollBody = (sig: Uint8Array, t = ticket) => {
    const tb = proto.ticketSignedBytes(t).slice("onepass/mailbox-enroll/v1".length);
    return new Uint8Array([1, ...tb, ...approver.id, ...sig, 3, 1, 2, 3]);
  };
  const answer: Answer = (fn) => {
    if (fn === "ip_gate") return [ok()];
    if (fn === "credential_key") return [ok({ mailbox_id: M, public_key: approver.pub, revoked: false })];
    return [ok({ credential_id: fresh.id })];
  };
  const target = `/v1/mailboxes/${MHEX}/credentials`;
  const db = new FakeDb(answer);
  const r = await handler(deps(db))(await signed(fresh, "POST", target, enrollBody(tsig)), IP);
  assertEquals(r.status, 204);
  assertEquals(db.fns(), ["ip_gate", "credential_key", "api_enroll"]);
  const args = db.calls[2].args.map((x) => x.value);
  assertEquals(args[0], fresh.pub);
  assertEquals(args[3], M);
  assertEquals(args[4], approver.id);
  assertEquals((args[6] as Date).getTime(), (NOW / 1000 + 600) * 1000);
  assertEquals(args[7], new Uint8Array([1, 2, 3]));
  assertEquals(args[8], await expectedIpKey(IP, NOW));
  assertEquals(db.calls[1].args.map((x) => x.value), [M, approver.id]);

  // Ticket signature of someone else: bad_signature, no api_enroll.
  const forged = await edSign(fresh, proto.ticketSignedBytes(ticket));
  const db2 = new FakeDb(answer);
  await assertError(
    await handler(deps(db2))(await signed(fresh, "POST", target, enrollBody(forged)), IP),
    "bad_signature",
  );
  assert(!db2.fns().includes("api_enroll"));

  // Request signed by another key than the ticket's: bad_signature, no SQL.
  const db3 = new FakeDb(answer);
  await assertError(
    await handler(deps(db3))(await signed(approver, "POST", target, enrollBody(tsig)), IP),
    "bad_signature",
  );
  assertEquals(db3.calls.length, 0);

  // Ticket for another mailbox: malformed, no SQL.
  const other = { ...ticket, mailbox_id: new Uint8Array(16).fill(0x22) };
  const db4 = new FakeDb(answer);
  const osig = await edSign(approver, proto.ticketSignedBytes(other));
  await assertError(
    await handler(deps(db4))(await signed(fresh, "POST", target, enrollBody(osig, other)), IP),
    "malformed",
  );
  assertEquals(db4.calls.length, 0);
});

// ---------------------------------------------------------------- roles

/** GrantCredential: version, key, role index, put_kinds option, label. */
function grantBody(pub: Uint8Array, role: number, kinds: Uint8Array | null, label = new Uint8Array()): Uint8Array {
  const out = [1, ...pub, role];
  if (kinds) out.push(1, ...kinds);
  else out.push(0);
  out.push(label.length, ...label);
  return new Uint8Array(out);
}

/** SetCredentialRole: version, role index, put_kinds option. */
function roleBody(role: number, kinds: Uint8Array | null): Uint8Array {
  return new Uint8Array(kinds ? [1, role, 1, ...kinds] : [1, role, 0]);
}

Deno.test("grant_route_calls_one_function: POST grants is one api_grant_credential call, 204", async () => {
  const k = await newKey();
  const fresh = await newKey();
  const kinds = new Uint8Array(32);
  kinds[1] = 0xc0;
  kinds[2] = 0x03;
  const db = new FakeDb(withKey(k, () => [ok({ credential_id: fresh.id })]));
  const target = `/v1/mailboxes/${MHEX}/grants`;
  const r = await handler(deps(db))(
    await signed(k, "POST", target, grantBody(fresh.pub, 1, kinds, new Uint8Array([9]))),
    IP,
  );
  assertEquals(r.status, 204);
  assertEquals(await bytes(r), new Uint8Array());
  assertEquals(db.fns(), ["ip_gate", "credential_key", "api_grant_credential"]);
  const args = db.calls[2].args;
  assertEquals(args.slice(0, 4).map((x) => x.value), [k.id, args[1].value, args[2].value, M]);
  assertEquals(args.slice(4).map((x) => [x.type, x.value]), [
    ["bytea", fresh.pub],
    ["smallint", 2],
    ["bytea", kinds],
    ["bytea", new Uint8Array([9])],
  ]);

  // Read and Manage, no put_kinds: role 1 and 3, a null put_kinds.
  for (const [index, role] of [[0, 1], [2, 3]]) {
    const db2 = new FakeDb(withKey(k, () => [ok({ credential_id: fresh.id })]));
    const r2 = await handler(deps(db2))(await signed(k, "POST", target, grantBody(fresh.pub, index, null)), IP);
    assertEquals(r2.status, 204);
    assertEquals(db2.calls[2].args.slice(5, 7).map((x) => x.value), [role, null]);
  }

  // An off-curve key is malformed and never reaches SQL; so are put_kinds
  // with another role than write, and an unknown role.
  const offCurve = new Uint8Array(32);
  offCurve[0] = 2;
  for (const body of [grantBody(offCurve, 0, null), grantBody(fresh.pub, 2, kinds), grantBody(fresh.pub, 3, null)]) {
    const db3 = new FakeDb(withKey(k));
    await assertError(await handler(deps(db3))(await signed(k, "POST", target, body), IP), "malformed");
    assert(!db3.fns().includes("api_grant_credential"));
  }
});

Deno.test("PUT credentials/{c}/role is one api_set_credential_role call, 204", async () => {
  const k = await newKey();
  const c = new Uint8Array(16).fill(0x33);
  const kinds = new Uint8Array(32).fill(0xff);
  const target = `/v1/mailboxes/${MHEX}/credentials/${toHex(c)}/role`;
  const db = new FakeDb(withKey(k));
  const r = await handler(deps(db))(await signed(k, "PUT", target, roleBody(1, kinds)), IP);
  assertEquals(r.status, 204);
  assertEquals(db.fns(), ["ip_gate", "credential_key", "api_set_credential_role"]);
  assertEquals(db.calls[2].args.slice(3).map((x) => [x.type, x.value]), [
    ["bytea", M],
    ["bytea", c],
    ["smallint", 2],
    ["bytea", kinds],
  ]);
  const db2 = new FakeDb(withKey(k));
  await assertError(await handler(deps(db2))(await signed(k, "PUT", target, roleBody(0, kinds)), IP), "malformed");
  assert(!db2.fns().includes("api_set_credential_role"));
  // Only PUT: another method on the path is no_route.
  await assertError(
    await handler(deps(new FakeDb()))(await signed(k, "POST", target, roleBody(2, null)), IP),
    "no_route",
  );
});

Deno.test("forbidden_maps_to_403: in band and raised, with the Forbidden wire code", async () => {
  const k = await newKey();
  assertEquals(CODES.forbidden, { status: 403, wire: "Forbidden" });
  const target = `/v1/mailboxes/${MHEX}/commit`;
  const body = commitBody([{ kind: 5, id: 1, version: 1, put: { expected: null, data: [7] } }]);
  const inBand = new FakeDb(withKey(k, () => [{ status: "forbidden", retry_after: null }]));
  const r = await handler(deps(inBand))(await signed(k, "POST", target, body), IP);
  assertEquals(r.status, 403);
  assertEquals(await bytes(r), proto.encodeError({ code: "Forbidden", retry_after: null }));
  assertEquals(inBand.rollbacks, 0);
  assertEquals(inBand.commits, 2);
  const raised = new FakeDb(withKey(k, () => {
    throw { code: "OP403", message: "forbidden" };
  }));
  await assertError(await handler(deps(raised))(await signed(k, "POST", target, body), IP), "forbidden");
  // The wire bytes of the codes before it did not move: Forbidden is appended.
  assertEquals(proto.encodeError({ code: "NoRoute", retry_after: null }), new Uint8Array([1, 13, 0]));
  assertEquals(proto.encodeError({ code: "Forbidden", retry_after: null }), new Uint8Array([1, 14, 0]));
});

// --------------------------------------------------------------- locator

Deno.test("PUT locator is one api_set_locator call, 204; a short body is malformed before SQL", async () => {
  const k = await newKey();
  const loc = new Uint8Array(16).fill(0x5a);
  const target = `/v1/mailboxes/${MHEX}/locator`;
  const db = new FakeDb(withKey(k));
  const r = await handler(deps(db))(await signed(k, "PUT", target, new Uint8Array([1, ...loc])), IP);
  assertEquals(r.status, 204);
  assertEquals(await bytes(r), new Uint8Array());
  assertEquals(db.fns(), ["ip_gate", "credential_key", "api_set_locator"]);
  const args = db.calls[2].args;
  assertEquals(args.slice(0, 4).map((x) => x.value), [k.id, args[1].value, args[2].value, M]);
  assertEquals(args.slice(4).map((x) => [x.type, x.value]), [["bytea", loc]]);
  for (const body of [new Uint8Array([1, ...loc.slice(1)]), new Uint8Array([1, ...loc, 0])]) {
    const db2 = new FakeDb(withKey(k));
    await assertError(await handler(deps(db2))(await signed(k, "PUT", target, body), IP), "malformed");
    assert(!db2.fns().includes("api_set_locator"));
  }
  // Not a manager: in-band forbidden.
  const reader = new FakeDb(withKey(k, () => [{ status: "forbidden", retry_after: null }]));
  await assertError(
    await handler(deps(reader))(await signed(k, "PUT", target, new Uint8Array([1, ...loc])), IP),
    "forbidden",
  );
});

Deno.test("POST locate is unsigned: one locate call with the IP key, 200 Located or 404 not_found", async () => {
  const loc = new Uint8Array(16).fill(0x5b);
  const target = "/v1/locate";
  const post = (body: Uint8Array<ArrayBuffer>, path = target) => new Request(url(path), { method: "POST", body });
  const M2 = new Uint8Array(16).fill(0x6c);
  // Every 'ok' row, in the order SQL gave it (oldest first).
  const db = new FakeDb(() => [ok({ mailbox_id: M2 }), ok({ mailbox_id: M })]);
  const r = await handler(deps(db))(post(new Uint8Array([1, ...loc])), IP);
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("content-type"), proto.CONTENT_TYPE);
  assertEquals(await bytes(r), new Uint8Array([1, 2, ...M2, ...M]));
  assertEquals(db.fns(), ["locate"]);
  assertEquals(db.calls[0].args.map((x) => [x.type, x.value]), [
    ["bytea", loc],
    ["bytea", await expectedIpKey(IP, NOW)],
  ]);
  assert(!containsIp(db.calls[0].args));
  assertEquals(db.commits, 1);

  const none = new FakeDb(() => [{ status: "not_found", retry_after: null, mailbox_id: null }]);
  await assertError(await handler(deps(none))(post(new Uint8Array([1, ...loc])), IP), "not_found");
  assertEquals(none.commits, 1, "a miss still counts");
  const limited = new FakeDb(() => [{ status: "rate_limited", retry_after: 1200, mailbox_id: null }]);
  await assertError(await handler(deps(limited))(post(new Uint8Array([1, ...loc])), IP), "rate_limited", 1200);

  // A short, long or empty body, or a query: malformed, no SQL.
  for (const body of [new Uint8Array([1, ...loc.slice(1)]), new Uint8Array([1, ...loc, 0]), new Uint8Array()]) {
    const db2 = new FakeDb();
    await assertError(await handler(deps(db2))(post(body), IP), "malformed");
    assertEquals(db2.calls.length, 0);
  }
  const q = new FakeDb();
  await assertError(await handler(deps(q))(post(new Uint8Array([1, ...loc]), `${target}?x=1`), IP), "malformed");
  // The locator never travels in the URL: the old GET form is gone.
  const old = new FakeDb();
  await assertError(await handler(deps(old))(new Request(url(`/v1/locate/${toHex(loc)}`)), IP), "no_route");
  const get = new FakeDb();
  await assertError(await handler(deps(get))(new Request(url(target)), IP), "no_route");
  assertEquals(q.calls.length + old.calls.length + get.calls.length, 0);
});

Deno.test("DELETE mailbox is one api_delete_mailbox call, 204; refused is 403, deleted is 404", async () => {
  const k = await newKey();
  const target = `/v1/mailboxes/${MHEX}`;
  const db = new FakeDb(withKey(k));
  const r = await handler(deps(db))(await signed(k, "DELETE", target), IP);
  assertEquals(r.status, 204);
  assertEquals(db.fns(), ["ip_gate", "credential_key", "api_delete_mailbox"]);
  assertEquals(db.calls[2].args.map((x) => x.type), ["bytea", "bytea", "timestamptz", "bytea"]);
  assertEquals(db.calls[2].args[3].value, M);
  const refused = new FakeDb(withKey(k, () => [{ status: "forbidden", retry_after: null }]));
  await assertError(await handler(deps(refused))(await signed(k, "DELETE", target), IP), "forbidden");
  const gone = new FakeDb(withKey(k, () => {
    throw { code: "OP404", message: "not_found" };
  }));
  await assertError(await handler(deps(gone))(await signed(k, "DELETE", target), IP), "not_found");
});

/** CreateChild: version, kind index (0 Shared, 1 Contact), owner key, label. */
function childBody(kind: number, pub: Uint8Array, label = new Uint8Array()): Uint8Array {
  return new Uint8Array([1, kind, ...pub, label.length, ...label]);
}

Deno.test("POST children is one api_create_child call, 200 MailboxCreated; bad bodies never reach SQL", async () => {
  const k = await newKey();
  const owner = await newKey();
  const child = new Uint8Array(16).fill(0x22);
  const wake = new Uint8Array(16).fill(0x33);
  const target = `/v1/mailboxes/${MHEX}/children`;
  for (const [index, kind] of [[0, 2], [1, 3]]) {
    const db = new FakeDb(withKey(k, () => [ok({ mailbox_id: child, incarnation: 7n, wake_topic: wake })]));
    const r = await handler(deps(db))(
      await signed(k, "POST", target, childBody(index, owner.pub, new Uint8Array([5, 6]))),
      IP,
    );
    assertEquals(r.status, 200);
    assertEquals(await bytes(r), proto.encodeCreated({ mailbox_id: child, incarnation: 7n, wake_topic: wake }));
    assertEquals(db.fns(), ["ip_gate", "credential_key", "api_create_child"]);
    const args = db.calls[2].args;
    assertEquals(args.slice(0, 4).map((x) => x.value), [k.id, args[1].value, args[2].value, M]);
    assertEquals(args.slice(4).map((x) => [x.type, x.value]), [
      ["smallint", kind],
      ["bytea", owner.pub],
      ["bytea", new Uint8Array([5, 6])],
    ]);
  }

  // In-band refusals keep their codes.
  for (const code of ["forbidden", "quota", "malformed"] as Code[]) {
    const db = new FakeDb(withKey(k, () => [{ status: code, retry_after: null }]));
    await assertError(await handler(deps(db))(await signed(k, "POST", target, childBody(0, owner.pub)), IP), code);
  }
  const limited = new FakeDb(withKey(k, () => [{ status: "rate_limited", retry_after: 3600 }]));
  await assertError(
    await handler(deps(limited))(await signed(k, "POST", target, childBody(1, owner.pub)), IP),
    "rate_limited",
    3600,
  );

  // An off-curve owner key, an unknown kind, a long label, a short body.
  const offCurve = new Uint8Array(32);
  offCurve[0] = 2;
  for (
    const body of [
      childBody(0, offCurve),
      childBody(2, owner.pub),
      childBody(0, owner.pub, new Uint8Array(65)),
      childBody(0, owner.pub).slice(0, 20),
    ]
  ) {
    const db = new FakeDb(withKey(k));
    await assertError(await handler(deps(db))(await signed(k, "POST", target, body), IP), "malformed");
    assert(!db.fns().includes("api_create_child"));
  }
});

// ------------------------------------------------------------ client address

Deno.test("spoofed left X-Forwarded-For entries never change the key; IPv6 counts as its /64", async () => {
  const seen: Uint8Array[] = [];
  const db = new FakeDb((fn, args) => {
    if (fn === "rdv_close") seen.push(args[1].value as Uint8Array);
    return [ok()];
  });
  const h = makeHandler(deps(db));
  const close = (xff: string | null) => {
    const req = new Request(url(`/v1/rendezvous/${MHEX}`), { method: "DELETE" });
    if (xff !== null) req.headers.set("x-forwarded-for", xff);
    return h(req);
  };
  for (
    const xff of [
      IP,
      `1.2.3.4, ${IP}`,
      `10.0.0.1, 10.0.0.2,${IP}`,
      `::ffff:${IP}`,
      `garbage, ${IP}`,
    ]
  ) {
    assertEquals((await close(xff)).status, 204, xff);
  }
  for (const k of seen) assertEquals(k, await ipKey(SECRET, NOW, IP));

  seen.length = 0;
  for (const v6 of ["2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:0db8:0001:0002:0:0:0:9"]) {
    assertEquals((await close(`8.8.8.8, ${v6}`)).status, 204);
  }
  assertEquals(seen[0], await ipKey(SECRET, NOW, "2001:db8:1:2::/64"));
  assertEquals(seen[1], seen[0]);
  assertEquals(seen[2], seen[0]);
  assertEquals((await close("2001:db8:1:3::1")).status, 204);
  assert(toHex(seen[3]) !== toHex(seen[0]), "another /64, another key");

  // Missing or malformed: one shared fallback bucket, never a left entry.
  seen.length = 0;
  for (
    const xff of [null, "", "not an address", "1.2.3.4, 300.1.1.1", "01.2.3.4", "fe80::1%eth0", "1:2:3:4:5:6:7:8:9"]
  ) {
    assertEquals((await close(xff)).status, 204, String(xff));
  }
  const fallback = await ipKey(SECRET, NOW, FALLBACK_ADDRESS);
  for (const k of seen) assertEquals(k, fallback);
});

Deno.test("trusted hops count from the right; other headers are read whole", async () => {
  const { clientAddress, ipSourceFromEnv } = await import("./ip.ts");
  const h = (v: string) => ({
    get: (n: string) => (n === "x-forwarded-for" ? v : n === "cf-connecting-ip" ? v : null),
  });
  const two = ipSourceFromEnv("X-Forwarded-For", "2");
  assertEquals(clientAddress(h("6.6.6.6, 1.1.1.1, 10.0.0.9"), two), "1.1.1.1");
  assertEquals(clientAddress(h("10.0.0.9"), two), FALLBACK_ADDRESS);
  const cf = ipSourceFromEnv("CF-Connecting-IP", undefined);
  assertEquals(clientAddress(h("2001:db8::7"), cf), "2001:db8:0:0::/64");
  assertEquals(clientAddress(h("1.1.1.1, 2.2.2.2"), cf), FALLBACK_ADDRESS);
  for (const bad of ["0", "-1", "x", "17"]) {
    let threw = false;
    try {
      ipSourceFromEnv("x-forwarded-for", bad);
    } catch {
      threw = true;
    }
    assert(threw, bad);
  }
});

Deno.test("no client address header configured: the function refuses to boot", async () => {
  const { ipSourceFromEnv } = await import("./ip.ts");
  for (const header of [undefined, ""]) {
    let threw = false;
    try {
      ipSourceFromEnv(header, "1");
    } catch {
      threw = true;
    }
    assert(threw, String(header));
  }
  assertEquals(ipSourceFromEnv("sb-forwarded-for", undefined), { header: "sb-forwarded-for", trustedHops: 1 });
});

Deno.test("a row above the page head (a commit between the two reads) is left out, not a 503", async () => {
  const k = await newKey();
  const row = (seq: bigint) =>
    ok({
      incarnation: 3n,
      min_cursor: 0n,
      head: 5n,
      seq,
      kind: 5,
      id: new Uint8Array(16).fill(Number(seq)),
      version: 1n,
      deleted: false,
      data: new Uint8Array([1]),
      blob_sha256: null,
      size: 1,
    });
  const db = new FakeDb(withKey(k, () => [row(4n), row(5n), row(6n)]));
  const r = await handler(deps(db))(
    await signed(k, "GET", `/v1/mailboxes/${MHEX}/changes?after=3&limit=10&full=0`),
    IP,
  );
  assertEquals(r.status, 200);
  assertEquals(
    await bytes(r),
    proto.encodeChanges({
      incarnation: 3n,
      min_cursor: 0n,
      head: 5n,
      records: [4n, 5n].map((seq) => ({
        seq,
        kind: 5,
        id: new Uint8Array(16).fill(Number(seq)),
        version: 1n,
        body: { Inline: new Uint8Array([1]) },
      })),
      next_after: 5n,
      more: false,
    }),
  );
});

Deno.test("an after above i64 is malformed before SQL", async () => {
  const k = await newKey();
  const db = new FakeDb(withKey(k));
  const r = await handler(deps(db))(
    await signed(k, "GET", `/v1/mailboxes/${MHEX}/changes?after=9223372036854775808&limit=1&full=0`),
    IP,
  );
  await assertError(r, "malformed");
  assert(!db.fns().includes("api_changes"));
});
