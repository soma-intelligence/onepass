// Open and sign in (spec docs/superpowers/specs/2026-11-04-open-and-sign-in-design.md), end to
// end: the app's step is played by `onepass-native-host sign-in <item> <url>`, which records the
// pending sign-in in the host's data directory exactly as the app records it in its App Group
// container. Then the test only opens the page, as Safari would: no click, no key.
import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Worker } from "@playwright/test";
import { type Ext, expect, paired } from "./fixtures";
import { FX } from "./server";

const ATLAS = "https://atlas-cloud.test";
const PENDING = "pending-sign-in.json";

paired.use({ build: "e2e" });

/** The id of a login, read over the worker's session (e2e build handle). */
async function itemId(w: Worker, origin: string, title: string): Promise<string> {
  return w.evaluate(
    async ({ origin, title }) => {
      const h = (globalThis as { __onepassE2E?: { session: { request(r: unknown): Promise<unknown> } } }).__onepassE2E;
      if (!h) throw new Error("not an e2e build");
      const r = (await h.session.request({ op: "list_for_origin", ctx: "menu", origin })) as { items: { item_id: string; title: string }[] };
      const it = r.items.find((x) => x.title === title);
      if (!it) throw new Error(`no item ${title}`);
      return it.item_id;
    },
    { origin, title },
  );
}

/** What the app does on "Ouvrir et se connecter", before it opens the URL. */
function recordSignIn(ext: Ext, item: string, url: string): void {
  execFileSync(ext.host.wrapper, ["sign-in", item, url], { stdio: "pipe" });
}

paired("open_and_sign_in_multistep_totp", async ({ ext }) => {
  const { page } = ext;
  const atlas = await itemId(await ext.worker(), ATLAS, "Atlas Cloud");
  recordSignIn(ext, atlas, `${ATLAS}/multistep`);
  expect(existsSync(join(ext.host.dataDir, PENDING))).toBe(true);
  await page.goto(`${ATLAS}/multistep`);
  // Identifier, password, then the one-time code, each on its own page, each submitted.
  await expect(page.locator("#status")).toHaveText("Connecté", { timeout: 30_000 });
  await expect(page.locator("#detail")).toHaveText(FX.atlas.email);
  await expect.poll(async () => (await ext.chainState())?.status, { timeout: 20_000 }).toBe("done");
  expect(ext.audit()).toContain('"op":"take_sign_in"');
  // Single use: gone, and the next visit fills nothing on its own.
  expect(existsSync(join(ext.host.dataDir, PENDING))).toBe(false);
  await page.goto(`${ATLAS}/logout`);
  await page.goto(`${ATLAS}/multistep`);
  await ext.settle(2500);
  await expect(page.locator("#email")).toHaveValue("");
  expect(ext.audit().match(/"op":"take_sign_in"/g)).toHaveLength(1);
});

paired("open_and_sign_in_wrong_host_gets_nothing", async ({ ext }) => {
  const { page } = ext;
  const atlas = await itemId(await ext.worker(), ATLAS, "Atlas Cloud");
  recordSignIn(ext, atlas, `${ATLAS}/multistep`);
  // Another site with a sign-in form, then a lookalike of the item's site.
  for (const url of ["https://sso.evil.test/login", "https://atlas-cloud.test.evil.test/login"]) {
    await page.goto(url);
    await ext.settle(2500);
    await expect(page.locator("#email")).toHaveValue("");
    await expect(page.locator("#password")).toHaveValue("");
  }
  expect(ext.server.captured).toEqual([]);
  expect(ext.audit()).not.toContain('"op":"take_sign_in"');
  expect(ext.audit()).not.toContain('"op":"fill_login"');
  // Still waiting for the item's own site.
  expect(existsSync(join(ext.host.dataDir, PENDING))).toBe(true);
});

paired("open_and_sign_in_expired_gets_nothing", async ({ ext }) => {
  const { page } = ext;
  const atlas = await itemId(await ext.worker(), ATLAS, "Atlas Cloud");
  // Recorded 90 s ago, for 60 s: what the app would have left behind.
  const now = Math.floor(Date.now() / 1000);
  writeFileSync(
    join(ext.host.dataDir, PENDING),
    JSON.stringify({ v: 1, item_id: atlas, site: "atlas-cloud.test", host: "atlas-cloud.test", created: now - 90, expires: now - 30 }),
    { mode: 0o600 },
  );
  await page.goto(`${ATLAS}/multistep`);
  await ext.settle(2500);
  await expect(page.locator("#email")).toHaveValue("");
  expect(ext.audit()).not.toContain('"op":"take_sign_in"');
  expect(ext.audit()).not.toContain('"op":"fill_login"');
  await expect.poll(() => existsSync(join(ext.host.dataDir, PENDING)), { timeout: 10_000 }).toBe(false);
});
