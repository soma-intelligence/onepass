import { assert, assertEquals, assertFalse } from "@std/assert";
import { cronAuthorized } from "../_shared/cron.ts";
import { LogProvider, providersFromEnv, type PushProvider } from "./providers.ts";
import { handler, type PushStore, type PushTarget } from "./push.ts";

const KEY = "k".repeat(40);
const bytes = (...v: number[]) => new Uint8Array(v);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

interface QueueEntry {
  mailbox: Uint8Array;
  exclude: Uint8Array | null;
}
interface Cred {
  mailbox: Uint8Array;
  id: Uint8Array;
  kind: number;
  token: Uint8Array;
  /** A device target (tag set) is sent whatever the queue excludes. */
  tag?: Uint8Array;
}

/** push_take as the SQL does it: whole mailboxes, the author left out, queue emptied. */
function fakeStore(queue: QueueEntry[], creds: Cred[]) {
  const forgotten: { credential: Uint8Array; tag: Uint8Array | null; token: Uint8Array }[] = [];
  let takes = 0;
  const store: PushStore = {
    take(limit) {
      takes++;
      const entries = queue.splice(0, limit);
      const out: PushTarget[] = [];
      for (const e of entries) {
        for (const c of creds) {
          if (hex(c.mailbox) !== hex(e.mailbox)) continue;
          if (!c.tag && e.exclude && hex(e.exclude) === hex(c.id)) continue;
          out.push({ mailboxId: c.mailbox, credentialId: c.id, tag: c.tag ?? null, kind: c.kind, token: c.token });
        }
      }
      return Promise.resolve(out);
    },
    forget(credential, tag, token) {
      forgotten.push({ credential, tag, token });
      return Promise.resolve();
    },
  };
  return { store, forgotten, takes: () => takes };
}

class FakeProvider implements PushProvider {
  calls: Uint8Array[] = [];
  constructor(public kind: number, public answers: ("sent" | "gone" | "retry" | "throw")[] = []) {}
  send(token: Uint8Array) {
    this.calls.push(token);
    const a = this.answers.shift() ?? "sent";
    if (a === "throw") return Promise.reject(new Error("provider down"));
    return Promise.resolve(a);
  }
}

function setup(queue: QueueEntry[], creds: Cred[], providers: PushProvider[]) {
  const f = fakeStore(queue, creds);
  let clock = 1_000_000;
  const logs: string[] = [];
  const h = handler({
    cronKey: KEY,
    store: f.store,
    providers,
    now: () => clock,
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
    log: (m) => logs.push(m),
  });
  return { h, f, logs };
}

const post = (key: string | null = KEY) =>
  new Request("http://x/mailbox-push", {
    method: "POST",
    headers: key === null ? {} : { authorization: `Bearer ${key}` },
  });

const A = bytes(1), B = bytes(2);
const a1 = bytes(0xa1), a2 = bytes(0xa2), b1 = bytes(0xb1), b2 = bytes(0xb2);
const tok = (n: number) => bytes(n, n, n);

Deno.test("two mailboxes, three recipients: one call each to the provider of the right kind, none for the author", async () => {
  const fcm = new FakeProvider(1), apns = new FakeProvider(2), up = new FakeProvider(3);
  const { h } = setup(
    [{ mailbox: A, exclude: a1 }, { mailbox: B, exclude: null }],
    [
      { mailbox: A, id: a1, kind: 1, token: tok(1) }, // the author of A
      { mailbox: A, id: a2, kind: 2, token: tok(2) },
      { mailbox: B, id: b1, kind: 1, token: tok(3) },
      { mailbox: B, id: b2, kind: 3, token: tok(4) },
    ],
    [fcm, apns, up],
  );
  const res = await h(post());
  assertEquals(res.status, 200);
  assertEquals(fcm.calls.map(hex), ["030303"]);
  assertEquals(apns.calls.map(hex), ["020202"]);
  assertEquals(up.calls.map(hex), ["040404"]);
  const body = await res.json();
  assertEquals(body.sent, 3);
  assertEquals(body.gone, 0);
});

Deno.test("an excluded author is never notified, whatever the provider", async () => {
  const fcm = new FakeProvider(1);
  const { h } = setup(
    [{ mailbox: A, exclude: a1 }],
    [{ mailbox: A, id: a1, kind: 1, token: tok(1) }],
    [fcm],
  );
  const res = await h(post());
  assertEquals(res.status, 200);
  assertEquals(fcm.calls.length, 0);
});

Deno.test("a gone token is forgotten for that credential and that token", async () => {
  const fcm = new FakeProvider(1, ["gone", "sent"]);
  const { h, f } = setup(
    [{ mailbox: A, exclude: null }],
    [
      { mailbox: A, id: a1, kind: 1, token: tok(1) },
      { mailbox: A, id: a2, kind: 1, token: tok(2) },
    ],
    [fcm],
  );
  const body = await (await h(post())).json();
  assertEquals(body.gone, 1);
  assertEquals(body.sent, 1);
  assertEquals(f.forgotten.length, 1);
  assertEquals(hex(f.forgotten[0].credential), "a1");
  assertEquals(hex(f.forgotten[0].token), "010101");
});

Deno.test("retry is tried again a bounded number of times, then dropped without forgetting", async () => {
  const fcm = new FakeProvider(1, ["retry", "retry", "retry", "retry", "retry"]);
  const { h, f } = setup([{ mailbox: A, exclude: null }], [{ mailbox: A, id: a1, kind: 1, token: tok(1) }], [fcm]);
  const body = await (await h(post())).json();
  assertEquals(fcm.calls.length, 3);
  assertEquals(body.failed, 1);
  assertEquals(f.forgotten.length, 0);
});

Deno.test("retry then sent counts as sent", async () => {
  const fcm = new FakeProvider(1, ["retry", "sent"]);
  const { h } = setup([{ mailbox: A, exclude: null }], [{ mailbox: A, id: a1, kind: 1, token: tok(1) }], [fcm]);
  const body = await (await h(post())).json();
  assertEquals(fcm.calls.length, 2);
  assertEquals(body.sent, 1);
  assertEquals(body.failed, 0);
});

Deno.test("a provider that throws is a retry, never a crash and never a forget", async () => {
  const fcm = new FakeProvider(1, ["throw", "throw", "throw"]);
  const { h, f } = setup([{ mailbox: A, exclude: null }], [{ mailbox: A, id: a1, kind: 1, token: tok(1) }], [fcm]);
  const res = await h(post());
  assertEquals(res.status, 200);
  assertEquals((await res.json()).failed, 1);
  assertEquals(f.forgotten.length, 0);
});

Deno.test("a kind without a provider is skipped and its token kept", async () => {
  const fcm = new FakeProvider(1);
  const { h, f } = setup([{ mailbox: A, exclude: null }], [{ mailbox: A, id: a1, kind: 2, token: tok(1) }], [fcm]);
  const body = await (await h(post())).json();
  assertEquals(body.skipped, 1);
  assertEquals(fcm.calls.length, 0);
  assertEquals(f.forgotten.length, 0);
});

Deno.test("the queue is drained over several takes until it is empty", async () => {
  const fcm = new FakeProvider(1);
  const queue: QueueEntry[] = [];
  const creds: Cred[] = [];
  for (let i = 1; i <= 250; i++) {
    const m = bytes(i);
    queue.push({ mailbox: m, exclude: null });
    creds.push({ mailbox: m, id: bytes(0xc0, i), kind: 1, token: bytes(i) });
  }
  const { h, f } = setup(queue, creds, [fcm]);
  const body = await (await h(post())).json();
  assertEquals(body.sent, 250);
  assertEquals(fcm.calls.length, 250);
  assert(f.takes() >= 3);
});

Deno.test("no call without the cron key: 401 before any database call", async () => {
  const fcm = new FakeProvider(1);
  const { h, f } = setup([{ mailbox: A, exclude: null }], [{ mailbox: A, id: a1, kind: 1, token: tok(1) }], [fcm]);
  const bad: Request[] = [
    post(null),
    post("wrong".repeat(10)),
    post(" " + KEY),
    post("x" + KEY),
    post(KEY.slice(0, -1)),
    post(""),
    new Request("http://x/", { method: "POST", headers: { authorization: KEY } }),
    new Request("http://x/", { method: "POST", headers: { authorization: `bearer ${KEY}` } }),
    new Request("http://x/", { method: "POST", headers: { authorization: `Basic ${KEY}` } }),
    new Request("http://x/", { method: "GET" }),
    new Request("http://x/", { method: "DELETE", headers: { authorization: "Bearer x" } }),
  ];
  for (const r of bad) {
    const res = await h(r);
    assertEquals(res.status, 401);
    assertEquals(await res.text(), "");
  }
  assertEquals(f.takes(), 0);
  assertEquals(fcm.calls.length, 0);
});

Deno.test("the right key with another method is 405, still without a database call", async () => {
  const { h, f } = setup([], [], []);
  const res = await h(new Request("http://x/", { method: "GET", headers: { authorization: `Bearer ${KEY}` } }));
  assertEquals(res.status, 405);
  assertEquals(f.takes(), 0);
});

Deno.test("a database failure is 503 with no detail", async () => {
  const h = handler({
    cronKey: KEY,
    store: {
      take: () => Promise.reject(new Error("password=hunter2 connection refused")),
      forget: () => Promise.resolve(),
    },
    providers: [],
    now: Date.now,
    sleep: () => Promise.resolve(),
    log: () => {},
  });
  const res = await h(post());
  assertEquals(res.status, 503);
  assertFalse((await res.text()).includes("hunter2"));
});

Deno.test("cronAuthorized accepts only the exact bearer header", async () => {
  assert(await cronAuthorized(`Bearer ${KEY}`, KEY));
  assertFalse(await cronAuthorized(null, KEY));
  assertFalse(await cronAuthorized(`Bearer ${KEY}x`, KEY));
  assertFalse(await cronAuthorized(`Bearer  ${KEY}`, KEY));
  assertFalse(await cronAuthorized(KEY, KEY));
  // A short configured key never authorises, even when the header matches it.
  assertFalse(await cronAuthorized("Bearer abc", "abc"));
});

Deno.test("LogProvider says it sent and logs no token", async () => {
  const lines: string[] = [];
  const p = new LogProvider(2, (m) => lines.push(m));
  assertEquals(p.kind, 2);
  assertEquals(await p.send(bytes(0xde, 0xad, 0xbe, 0xef)), "sent");
  assertEquals(lines.length, 1);
  assertFalse(lines[0].toLowerCase().includes("deadbeef"));
});

Deno.test("MAILBOX_PUSH_PROVIDERS has no default: unset or unknown refuses to boot", () => {
  for (const mode of [undefined, "", "apns", "LOG"]) {
    let threw = false;
    try {
      providersFromEnv(mode);
    } catch {
      threw = true;
    }
    assertEquals(threw, true, String(mode));
  }
  assertEquals(providersFromEnv("none"), []);
  assertEquals(providersFromEnv("log").map((p) => p.kind), [1, 2, 3]);
});

Deno.test("sends_to_every_target: each device target of a shared credential, the author's included", async () => {
  const m = bytes(1);
  const shared = bytes(0xb1);
  const apns = new FakeProvider(2);
  const fcm = new FakeProvider(1);
  const { h, f } = setup(
    [{ mailbox: m, exclude: shared }],
    [
      { mailbox: m, id: shared, kind: 2, token: bytes(9) },
      { mailbox: m, id: shared, kind: 2, token: bytes(1, 1), tag: bytes(0x71) },
      { mailbox: m, id: shared, kind: 1, token: bytes(2, 2), tag: bytes(0x72) },
      { mailbox: m, id: shared, kind: 2, token: bytes(3, 3), tag: bytes(0x73) },
    ],
    [apns, fcm],
  );
  const r = await h(post());
  assertEquals(r.status, 200);
  // The historical token of the author (09) stays out; its targets do not.
  assertEquals(apns.calls.map(hex).sort(), ["0101", "0303"]);
  assertEquals(fcm.calls.map(hex), ["0202"]);
  assertEquals(f.forgotten.length, 0);
});

Deno.test("gone_target_forgotten: by credential, tag and token; the historical token by credential and token", async () => {
  const m = bytes(1);
  const c = bytes(0xc1);
  const provider = new FakeProvider(2, ["gone", "gone"]);
  const { h, f } = setup(
    [{ mailbox: m, exclude: null }],
    [
      { mailbox: m, id: c, kind: 2, token: bytes(5) },
      { mailbox: m, id: c, kind: 2, token: bytes(6), tag: bytes(0x7a) },
    ],
    [provider],
  );
  await h(post());
  assertEquals(f.forgotten.length, 2);
  const byTag = f.forgotten.find((x) => x.tag !== null)!;
  assertEquals([hex(byTag.credential), hex(byTag.tag!), hex(byTag.token)], ["c1", "7a", "06"]);
  const plain = f.forgotten.find((x) => x.tag === null)!;
  assertEquals([hex(plain.credential), hex(plain.token)], ["c1", "05"]);
});
