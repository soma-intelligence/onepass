// Against a local stack (`supabase start`, then mailbox/scripts/local-env.sh):
// the real gc_take / gc_done as onepass_mailbox_janitor and the real Storage
// API with the service key. Ignored without the variables. Run from this
// directory:
//
//   deno test --allow-read --allow-env --allow-net --env-file=../../.env.local live_test.ts
import { assert, assertEquals } from "@std/assert";
import postgres from "postgres";
import { createClient } from "@supabase/supabase-js";
import { connectJanitor } from "../_shared/janitor.ts";
import { handler } from "./gc.ts";
import { BUCKET, graveStore, objectStore } from "./store.ts";

const JANITOR = Deno.env.get("MAILBOX_TEST_JANITOR_DB_URL");
const ADMIN = Deno.env.get("MAILBOX_TEST_ADMIN_DB_URL");
const STORAGE = Deno.env.get("MAILBOX_TEST_STORAGE_URL");
const SERVICE = Deno.env.get("MAILBOX_TEST_SERVICE_KEY");
const KEY = "live".repeat(10);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

Deno.test({
  name: "live: objects of the graveyard leave Storage, then the graves leave the table; a missing object is fine",
  ignore: !JANITOR || !ADMIN || !STORAGE || !SERVICE,
  async fn() {
    const admin = postgres(ADMIN!, { max: 1, onnotice: () => {} });
    const db = connectJanitor(JANITOR!, "onepass-live-test");
    const storage = createClient(STORAGE!, SERVICE!, { auth: { persistSession: false } }).storage;
    const bucket = storage.from(BUCKET);
    const mailbox = rand(16);
    const name = (gen: number) => `${hex(mailbox)}/${hex(rand(32))}.${gen}`;
    const present = name(1), absent = name(2);
    try {
      const up = await bucket.upload(present, new Uint8Array([1, 2, 3]), { contentType: "application/octet-stream" });
      assertEquals(up.error, null);
      await admin.begin(async (t) => {
        await t`select set_config('onepass.maintenance', 'on', true)`;
        await t`insert into onepass_mailbox.mailboxes (id, plan) values (${mailbox}, 'free')`;
        await t`insert into onepass_mailbox.blob_graves (mailbox_id, object_name) values (${mailbox}, ${present}), (${mailbox}, ${absent})`;
      });

      const h = handler({
        cronKey: KEY,
        graves: graveStore(db),
        objects: objectStore(storage),
        now: Date.now,
        log: () => {},
      });
      const res = await h(new Request("http://x/", { method: "POST", headers: { authorization: `Bearer ${KEY}` } }));
      assertEquals(res.status, 200);
      const body = await res.json();
      assert(body.deleted >= 2, JSON.stringify(body));
      assert(body.missing >= 1, JSON.stringify(body));
      assertEquals(body.failed, 0);

      const left =
        await admin`select count(*)::int as n from onepass_mailbox.blob_graves where mailbox_id = ${mailbox}`;
      assertEquals(left[0].n, 0);
      const dl = await bucket.download(present);
      assert(dl.error !== null, "the object is gone from Storage");
    } finally {
      await bucket.remove([present, absent]);
      await admin.begin(async (t) => {
        await t`select set_config('onepass.maintenance', 'on', true)`;
        await t`delete from onepass_mailbox.blob_graves where mailbox_id = ${mailbox}`;
        await t`delete from onepass_mailbox.mailboxes where id = ${mailbox}`;
      });
      await admin.end({ timeout: 5 });
      await db.end();
    }
  },
});
