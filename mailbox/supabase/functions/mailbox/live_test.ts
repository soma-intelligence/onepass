// Tests against a local stack (`supabase start`, then
// mailbox/scripts/local-env.sh). Ignored unless the stack's variables are
// set; run from this directory with:
//
//   deno test --allow-read --allow-env --allow-net --env-file=../../.env.local live_test.ts
//
// MAILBOX_TEST_FUNCTION_URL (for example
// http://127.0.0.1:57421/functions/v1/mailbox) adds the served function.
import { assert, assertEquals } from "@std/assert";
import * as proto from "./proto.ts";
import { a, client, over } from "./db.ts";
import { newKey, signedHeaders, type TestKey, toHex } from "./testutil.ts";

const DB_URL = Deno.env.get("MAILBOX_TEST_DB_URL");
const FN_URL = Deno.env.get("MAILBOX_TEST_FUNCTION_URL");

function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

Deno.test({
  name: "setting_does_not_leak_across_requests",
  ignore: !DB_URL,
  async fn() {
    // One connection, as a pooler in transaction mode may hand out.
    const sql = client(DB_URL!, { max: 1 });
    const db = over(sql);
    try {
      const now = () => new Date();
      const pid = async () => (await sql`select pg_backend_pid() as p`)[0].p;
      const firstPid = await pid();

      const mailboxWithRecord = async (key: TestKey, id: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
        const created = await db.transaction((tx) =>
          tx.call("api_create_mailbox", [
            a.bytea(key.pub),
            a.bytea(random(16)),
            a.timestamptz(now()),
            a.bytea(null),
            a.bytea(new Uint8Array([1])),
            a.bytea(random(32)),
            a.boolean(true),
          ])
        );
        assertEquals(created[0].status, "ok");
        const m = created[0].mailbox_id as Uint8Array;
        const done = await db.transaction((tx) =>
          tx.call("api_commit", [
            a.bytea(key.id),
            a.bytea(random(16)),
            a.timestamptz(now()),
            a.bytea(m),
            a.smallintArray([5, 5]),
            a.byteaArray([id, random(16)]),
            a.bigintArray([1n, 1n]),
            a.smallintArray([1, 2]),
            a.bigintArray([null, null]),
            a.byteaArray([data, null]),
            a.byteaArray([null, null]),
            a.integerArray([data.length, null]),
          ])
        );
        assertEquals(done.map((r) => r.status), ["ok", "ok"]);
        assertEquals(done[0].seq, 1n);
        // A delete of an absent key takes no seq.
        assertEquals(done[1].seq, null);
        return m;
      };

      const ka = await newKey();
      const kb = await newKey();
      const ida = random(16);
      const idb = random(16);
      const ma = await mailboxWithRecord(ka, ida, new Uint8Array([0xaa]));
      const mb = await mailboxWithRecord(kb, idb, new Uint8Array([0xbb, 0xbb]));

      const changes = (key: TestKey, m: Uint8Array) =>
        db.transaction((tx) =>
          tx.call("api_changes", [
            a.bytea(key.id),
            a.bytea(random(16)),
            a.timestamptz(now()),
            a.bytea(m),
            a.bigint(0n),
            a.integer(1000),
            a.boolean(false),
          ])
        );
      const pa = await changes(ka, ma);
      const pb = await changes(kb, mb);
      assertEquals(pa.map((r) => toHex(r.id as Uint8Array)), [toHex(ida)]);
      assertEquals(pb.map((r) => toHex(r.id as Uint8Array)), [toHex(idb)]);
      assertEquals(pb[0].data, new Uint8Array([0xbb, 0xbb]));

      // Between requests the connection carries no mailbox in scope.
      const setting = (await sql`select current_setting('onepass.mailbox', true) as v`)[0].v;
      assert(setting === null || setting === "", `onepass.mailbox leaked: ${setting}`);
      // A preset value never widens a call: credential B, mailbox A's id in the setting.
      await sql`select set_config('onepass.mailbox', ${toHex(ma)}, false)`;
      const crossed = await changes(kb, mb);
      assertEquals(crossed.map((r) => toHex(r.id as Uint8Array)), [toHex(idb)]);
      await sql`select set_config('onepass.mailbox', '', false)`;
      assertEquals(await pid(), firstPid, "all on one connection");
    } finally {
      await db.end();
    }
  },
});

Deno.test({
  name: "served function: config, create, commit, changes",
  ignore: !FN_URL,
  async fn() {
    const cfg = await fetch(`${FN_URL}/v1/config`);
    assertEquals(cfg.status, 200);
    assertEquals(cfg.headers.get("content-type"), proto.CONTENT_TYPE);
    await cfg.arrayBuffer();

    const k = await newKey();
    const created = Math.floor(Date.now() / 1000);
    const send = async (method: string, target: string, body?: Uint8Array) => {
      const headers = await signedHeaders(k, { method, target, body, created });
      headers.set("content-type", proto.CONTENT_TYPE);
      return await fetch(`${FN_URL}${target}`, {
        method,
        headers,
        body: body?.length ? (body as BodyInit) : undefined,
      });
    };
    // CreateMailbox { public_key, invite: None, label: [] } (open signup locally).
    const r1 = await send("POST", "/v1/mailboxes", new Uint8Array([1, ...k.pub, 0, 0]));
    assertEquals(r1.status, 200);
    const body1 = new Uint8Array(await r1.arrayBuffer());
    const m = body1.slice(1, 17);

    const id = random(16);
    const commit = new Uint8Array([1, 1, 5, ...id, 1, 0, 0, 0, 2, 7, 8]);
    const r2 = await send("POST", `/v1/mailboxes/${toHex(m)}/commit`, commit);
    assertEquals(r2.status, 200);
    assertEquals(new Uint8Array(await r2.arrayBuffer()), proto.encodeCommitResponse({ Applied: { seqs: [1n] } }));

    const r3 = await send("GET", `/v1/mailboxes/${toHex(m)}/changes?after=0&limit=10&full=0`);
    assertEquals(r3.status, 200);
    const page = new Uint8Array(await r3.arrayBuffer());
    // Ends with records [one], next_after 1, more false.
    assertEquals(Array.from(page.slice(-4)), [7, 8, 1, 0]);

    // A replay of the same signed request: 401 replay.
    const headers = await signedHeaders(k, { method: "GET", target: `/v1/mailboxes/${toHex(m)}`, created });
    const first = await fetch(`${FN_URL}/v1/mailboxes/${toHex(m)}`, { headers });
    assertEquals(first.status, 200);
    await first.arrayBuffer();
    const again = await fetch(`${FN_URL}/v1/mailboxes/${toHex(m)}`, { headers });
    assertEquals(again.status, 401);
    assertEquals(new Uint8Array(await again.arrayBuffer()), proto.encodeError({ code: "Replay", retry_after: null }));

    // Non-canonical S is refused by the edge runtime's WebCrypto too.
    const h2 = await signedHeaders(k, { method: "GET", target: `/v1/mailboxes/${toHex(m)}`, created });
    const sigText = h2.get("signature")!;
    const sig = Uint8Array.from(atob(sigText.slice(6, -1)), (c) => c.charCodeAt(0));
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;
    let s = 0n;
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]);
    let t = s + L;
    for (let i = 0; i < 32; i++) {
      sig[32 + i] = Number(t & 0xffn);
      t >>= 8n;
    }
    h2.set("signature", `sig1=:${btoa(String.fromCharCode(...sig))}:`);
    const forged = await fetch(`${FN_URL}/v1/mailboxes/${toHex(m)}`, { headers: h2 });
    assertEquals(forged.status, 401);
    assertEquals(
      new Uint8Array(await forged.arrayBuffer()),
      proto.encodeError({ code: "BadSignature", retry_after: null }),
    );

    // Blob announce: a signed upload URL on the public Storage address.
    const blob = new Uint8Array(20_000).fill(3);
    const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
    const ann = await send(
      "POST",
      `/v1/mailboxes/${toHex(m)}/blobs/uploads`,
      new Uint8Array([1, 1, ...sha, 0xa0, 0x9c, 0x01]),
    );
    assertEquals(ann.status, 200);
    const annBody = new TextDecoder().decode(new Uint8Array(await ann.arrayBuffer()));
    assert(annBody.includes(`/storage/v1/object/upload/sign/onepass-mailbox/${toHex(m)}/${toHex(sha)}.`), annBody);
  },
});
