import { assertEquals, assertFalse } from "@std/assert";
import { type Grave, type GraveStore, handler, type ObjectStore, TAKE_TTL_MS } from "./gc.ts";

const KEY = "k".repeat(40);
const mbx = (n: number) => new Uint8Array(16).fill(n);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const grave = (m: number, h: number, gen = 1): Grave => ({
  mailboxId: mbx(m),
  objectName: `${hex(mbx(m))}/${h.toString(16).padStart(2, "0").repeat(32)}.${gen}`,
});

function setup(graves: Grave[], opts: {
  remove?: (name: string) => Promise<"deleted" | "missing">;
  done?: (g: Grave) => Promise<void>;
} = {}) {
  const events: string[] = [];
  let clock = 5_000_000;
  const queue = [...graves];
  const takes: number[] = [];
  const graveStore: GraveStore = {
    take(limit) {
      takes.push(limit);
      return Promise.resolve(queue.splice(0, limit));
    },
    done(g) {
      events.push(`done ${g.objectName}`);
      return opts.done ? opts.done(g) : Promise.resolve();
    },
  };
  const objects: ObjectStore = {
    remove(name) {
      events.push(`remove ${name}`);
      return opts.remove ? opts.remove(name) : Promise.resolve("deleted");
    },
  };
  const logs: string[] = [];
  const h = handler({
    cronKey: KEY,
    graves: graveStore,
    objects,
    now: () => clock,
    log: (m) => logs.push(m),
  });
  return { h, events, logs, takes, advance: (ms: number) => (clock += ms) };
}

const post = (key: string | null = KEY) =>
  new Request("http://x/mailbox-gc", {
    method: "POST",
    headers: key === null ? {} : { authorization: `Bearer ${key}` },
  });

Deno.test("a taken grave is removed from Storage, then gc_done is called, in that order", async () => {
  const g = [grave(1, 0xaa), grave(2, 0xbb, 3)];
  const { h, events } = setup(g);
  const res = await h(post());
  assertEquals(res.status, 200);
  assertEquals(events, [
    `remove ${g[0].objectName}`,
    `done ${g[0].objectName}`,
    `remove ${g[1].objectName}`,
    `done ${g[1].objectName}`,
  ]);
  const body = await res.json();
  assertEquals(body.taken, 2);
  assertEquals(body.deleted, 2);
});

Deno.test("a Storage failure skips gc_done for that grave and goes on with the next", async () => {
  const g = [grave(1, 0xaa), grave(1, 0xbb)];
  const { h, events } = setup(g, {
    remove: (name) => name === g[0].objectName ? Promise.reject(new Error("storage 500")) : Promise.resolve("deleted"),
  });
  const body = await (await h(post())).json();
  assertEquals(events, [`remove ${g[0].objectName}`, `remove ${g[1].objectName}`, `done ${g[1].objectName}`]);
  assertEquals(body.failed, 1);
  assertEquals(body.deleted, 1);
});

Deno.test("a missing object counts as deleted", async () => {
  const g = [grave(1, 0xaa)];
  const { h, events } = setup(g, { remove: () => Promise.resolve("missing") });
  const body = await (await h(post())).json();
  assertEquals(events, [`remove ${g[0].objectName}`, `done ${g[0].objectName}`]);
  assertEquals(body.missing, 1);
  assertEquals(body.failed, 0);
});

Deno.test("a gc_done failure is counted, logged without the name, and does not stop the run", async () => {
  const g = [grave(1, 0xaa), grave(1, 0xbb)];
  const { h, events, logs } = setup(g, {
    done: (x) => x === g[0] ? Promise.reject(new Error("db down")) : Promise.resolve(),
  });
  const res = await h(post());
  assertEquals(res.status, 200);
  assertEquals((await res.json()).failed, 1);
  assertEquals(events.length, 4);
  assertFalse(logs.some((l) => l.includes(g[0].objectName)));
});

Deno.test("a take older than 10 minutes is dropped without deleting anything", async () => {
  const g = [grave(1, 0xaa), grave(1, 0xbb), grave(1, 0xcc)];
  const ctx = setup(g, {
    remove: () => {
      // The first removal is slow: by the time it is over, the take is stale.
      ctx.advance(TAKE_TTL_MS + 1);
      return Promise.resolve("deleted");
    },
  });
  const body = await (await ctx.h(post())).json();
  assertEquals(ctx.events, [`remove ${g[0].objectName}`, `done ${g[0].objectName}`]);
  assertEquals(body.deleted, 1);
  assertEquals(body.dropped, 2);
});

Deno.test("a take exactly 10 minutes old is still used", async () => {
  const g = [grave(1, 0xaa), grave(1, 0xbb)];
  const ctx = setup(g, {
    remove: () => {
      ctx.advance(TAKE_TTL_MS);
      return Promise.resolve("deleted");
    },
  });
  const body = await (await ctx.h(post())).json();
  assertEquals(body.deleted, 2);
  assertEquals(body.dropped, 0);
});

Deno.test("the timer starts at each take: a second batch gets its own ten minutes", async () => {
  const g: Grave[] = [];
  for (let i = 1; i <= 150; i++) g.push(grave(1, i));
  const ctx = setup(g);
  const body = await (await ctx.h(post())).json();
  assertEquals(body.deleted, 150);
  assertEquals(ctx.takes.length, 3); // 100, 50, then empty
});

Deno.test("an object name that does not belong to the mailbox is never deleted", async () => {
  const good = grave(1, 0xaa);
  const bad: Grave[] = [
    { mailboxId: mbx(1), objectName: `${hex(mbx(2))}/${"aa".repeat(32)}.1` }, // another mailbox
    { mailboxId: mbx(1), objectName: `${hex(mbx(1))}/../${"aa".repeat(32)}.1` },
    { mailboxId: mbx(1), objectName: `${hex(mbx(1))}/${"aa".repeat(32)}.0` },
    { mailboxId: mbx(1), objectName: "other-bucket/file" },
    { mailboxId: mbx(1), objectName: "" },
  ];
  const { h, events } = setup([...bad, good]);
  const body = await (await h(post())).json();
  assertEquals(events, [`remove ${good.objectName}`, `done ${good.objectName}`]);
  assertEquals(body.failed, 5);
});

Deno.test("no call without the cron key: 401 before any database or Storage call", async () => {
  const g = [grave(1, 0xaa)];
  const { h, events, takes } = setup(g);
  const bad: Request[] = [
    post(null),
    post("wrong".repeat(10)),
    post(KEY.slice(0, -1)),
    post("x" + KEY),
    new Request("http://x/", { method: "POST", headers: { authorization: KEY } }),
    new Request("http://x/", { method: "POST", headers: { authorization: `bearer ${KEY}` } }),
    new Request("http://x/", { method: "GET" }),
  ];
  for (const r of bad) {
    const res = await h(r);
    assertEquals(res.status, 401);
    assertEquals(await res.text(), "");
  }
  assertEquals(takes.length, 0);
  assertEquals(events.length, 0);
});

Deno.test("the right key with another method is 405", async () => {
  const { h, takes } = setup([]);
  const res = await h(new Request("http://x/", { method: "GET", headers: { authorization: `Bearer ${KEY}` } }));
  assertEquals(res.status, 405);
  assertEquals(takes.length, 0);
});

Deno.test("a gc_take failure is 503 with no detail", async () => {
  const h = handler({
    cronKey: KEY,
    graves: { take: () => Promise.reject(new Error("password=hunter2")), done: () => Promise.resolve() },
    objects: { remove: () => Promise.resolve("deleted") },
    now: Date.now,
    log: () => {},
  });
  const res = await h(post());
  assertEquals(res.status, 503);
  assertFalse((await res.text()).includes("hunter2"));
});
