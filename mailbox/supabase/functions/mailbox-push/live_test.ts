// Against a local stack (`supabase start`, then mailbox/scripts/local-env.sh):
// the real push_take / push_forget as onepass_mailbox_janitor, with fixture
// rows written by the stack's superuser. Ignored without the variables. Run
// from this directory:
//
//   deno test --allow-read --allow-env --allow-net --env-file=../../.env.local live_test.ts
import { assert, assertEquals } from "@std/assert";
import postgres from "postgres";
import { connectJanitor } from "../_shared/janitor.ts";
import { handler } from "./push.ts";
import { pushStore } from "./store.ts";
import type { PushProvider } from "./providers.ts";

const JANITOR = Deno.env.get("MAILBOX_TEST_JANITOR_DB_URL");
const ADMIN = Deno.env.get("MAILBOX_TEST_ADMIN_DB_URL");
const KEY = "live".repeat(10);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

/** A key and its credential id (SHA-256 of the domain string and the key, first 16 bytes). */
async function identity(): Promise<{ pub: Uint8Array; id: Uint8Array }> {
  const pub = rand(32);
  const msg = new Uint8Array([...new TextEncoder().encode("onepass/mailbox-credential-id/v1"), ...pub]);
  return { pub, id: new Uint8Array(await crypto.subtle.digest("SHA-256", msg)).slice(0, 16) };
}

Deno.test({
  name: "live: wake-ups reach every token but the author's, a gone token is forgotten, the queue is emptied",
  ignore: !JANITOR || !ADMIN,
  async fn() {
    const admin = postgres(ADMIN!, { max: 1, onnotice: () => {} });
    const db = connectJanitor(JANITOR!, "onepass-live-test");
    const mailbox = rand(16);
    const [idA, idO, idD] = [await identity(), await identity(), await identity()];
    const author = idA.id, other = idO.id, dead = idD.id;
    const tAuthor = rand(8), tOther = rand(8), tDead = rand(8);
    try {
      await admin.begin(async (t) => {
        await t`select set_config('onepass.maintenance', 'on', true)`;
        await t`insert into onepass_mailbox.mailboxes (id, plan) values (${mailbox}, 'free')`;
        for (const [who, kind, token] of [[idA, 1, tAuthor], [idO, 2, tOther], [idD, 1, tDead]] as const) {
          await t`insert into onepass_mailbox.credentials (id, mailbox_id, public_key, push_kind, push_token)
                  values (${who.id}, ${mailbox}, ${who.pub}, ${kind}, ${token})`;
        }
        await t`insert into onepass_mailbox.push_queue (mailbox_id, exclude_credential) values (${mailbox}, ${author})`;
      });

      const sent: string[] = [];
      const provider = (kind: number): PushProvider => ({
        kind,
        send(token) {
          sent.push(`${kind}:${hex(token)}`);
          return Promise.resolve(hex(token) === hex(tDead) ? "gone" : "sent");
        },
      });
      const h = handler({
        cronKey: KEY,
        store: pushStore(db),
        providers: [provider(1), provider(2)],
        now: Date.now,
        sleep: () => Promise.resolve(),
        log: () => {},
      });
      const res = await h(new Request("http://x/", { method: "POST", headers: { authorization: `Bearer ${KEY}` } }));
      assertEquals(res.status, 200);
      assertEquals(sent.sort(), [`1:${hex(tDead)}`, `2:${hex(tOther)}`].sort());
      assert(!sent.some((s) => s.endsWith(hex(tAuthor))));

      const cred = await admin`select id, push_token from onepass_mailbox.credentials where mailbox_id = ${mailbox}`;
      const tokenOf = (id: Uint8Array) => cred.find((r) => hex(new Uint8Array(r.id)) === hex(id))!.push_token;
      assertEquals(tokenOf(dead), null);
      assert(tokenOf(other) !== null && tokenOf(author) !== null);
      const left = await admin`select count(*)::int as n from onepass_mailbox.push_queue where mailbox_id = ${mailbox}`;
      assertEquals(left[0].n, 0);

      // Nothing queued: a second run sends nothing.
      sent.length = 0;
      await h(new Request("http://x/", { method: "POST", headers: { authorization: `Bearer ${KEY}` } }));
      assertEquals(sent.length, 0);
    } finally {
      await admin.begin(async (t) => {
        await t`select set_config('onepass.maintenance', 'on', true)`;
        await t`delete from onepass_mailbox.push_queue where mailbox_id = ${mailbox}`;
        await t`delete from onepass_mailbox.credentials where mailbox_id = ${mailbox}`;
        await t`delete from onepass_mailbox.mailboxes where id = ${mailbox}`;
      });
      await admin.end({ timeout: 5 });
      await db.end();
    }
  },
});
