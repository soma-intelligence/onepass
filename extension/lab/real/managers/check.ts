// Visual check of the "other managers": OnePass (dist/chromium), Bitwarden
// and the three fakes loaded together in Playwright's Chromium, on a local
// login page. Writes lab/out/managers/check.png (fields at rest, every icon)
// and check-focus.png (username focused, menus open). Every hostname but the
// loopback page resolves to nowhere, so no extension reaches the network.
//
// Run: node --experimental-strip-types lab/real/managers/check.ts
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { MANAGERS_OUT } from "./fetch-bitwarden.ts";
import { managerExtensions } from "./index.ts";

const EXT_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ONEPASS = join(EXT_ROOT, "dist", "chromium");

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<style>body{font:15px/1.4 -apple-system,system-ui,sans-serif;background:#F5F7FA;margin:0;display:grid;place-items:center;min-height:100vh}
form{background:#fff;padding:32px;border-radius:14px;box-shadow:0 4px 18px rgba(0,0,0,.08);width:360px}
label{display:block;margin:14px 0 6px;color:#3E4C59}input{box-sizing:border-box;width:100%;height:42px;padding:0 12px;border:1px solid #CBD2D9;border-radius:8px;font-size:15px}
button{margin-top:22px;width:100%;height:42px;border:0;border-radius:8px;background:#1F2933;color:#fff;font-size:15px}</style></head>
<body><form action="/nowhere" method="post" onsubmit="return false"><h2 style="margin:0">Sign in</h2>
<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button></form></body></html>`;

/** Chromium's id of an unpacked extension: SHA-256 of its path, 32 hex digits mapped to a-p. */
function unpackedId(path: string): string {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function main(): Promise<void> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  const exts = [ONEPASS, ...managerExtensions({ bitwarden: true, fakes: ["1password", "lastpass", "dashlane"] })];
  const profile = mkdtempSync(join(tmpdir(), "onepass-managers-"));
  mkdirSync(MANAGERS_OUT, { recursive: true });
  const ctx = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    viewport: { width: 900, height: 620 },
    args: [
      `--disable-extensions-except=${exts.join(",")}`,
      `--load-extension=${exts.join(",")}`,
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-sync",
      "--disable-background-networking",
      "--disable-component-update",
    ],
  });
  try {
    // Extensions open welcome tabs on install (Bitwarden does); keep only ours.
    await new Promise((r) => setTimeout(r, 2500));
    const page = await ctx.newPage();
    for (const p of ctx.pages()) if (p !== page) await p.close();
    await page.goto(`http://127.0.0.1:${port}/login`);
    await page.waitForTimeout(2500);
    await page.screenshot({ path: join(MANAGERS_OUT, "check.png") });
    const planted = await page.evaluate(() => ({
      onepassword: document.querySelectorAll("com-1password-button").length,
      lastpass: document.querySelectorAll("[data-lastpass-icon-root]").length,
      dashlane: document.querySelectorAll("[data-dashlane-rid]").length,
      bitwarden: [...document.querySelectorAll("*")].filter((e) => e.tagName.includes("-") && !e.tagName.startsWith("COM-")).map((e) => e.tagName.toLowerCase()),
    }));
    console.log("loaded workers:", ctx.serviceWorkers().map((w) => w.url().split("/")[2]).length);
    console.log("planted:", JSON.stringify(planted));
    await page.click("#email");
    await page.waitForTimeout(1500);
    await page.screenshot({ path: join(MANAGERS_OUT, "check-focus.png") });
    const byId = new Map(exts.map((e) => [unpackedId(e), e.split("/").slice(-2).join("/")]));
    console.log("service workers:", JSON.stringify(ctx.serviceWorkers().map((w) => byId.get(new URL(w.url()).hostname) ?? w.url())));
  } finally {
    await ctx.close();
    rmSync(profile, { recursive: true, force: true });
  }
  try {
    await fillCheck(port);
  } finally {
    server.close();
  }
}

/** With the LastPass fake alone: focus opens its menu, a trusted row click fills the fictional pair. */
async function fillCheck(port: number): Promise<void> {
  const exts = managerExtensions({ bitwarden: false, fakes: ["lastpass"] });
  const profile = mkdtempSync(join(tmpdir(), "onepass-managers-"));
  const ctx = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${exts.join(",")}`, `--load-extension=${exts.join(",")}`, "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"],
  });
  try {
    const page = await ctx.newPage();
    await page.goto(`http://127.0.0.1:${port}/login`);
    page.setDefaultTimeout(10_000);
    await page.locator("[data-lastpass-icon-root]").first().waitFor();
    await page.click("#email");
    await page.locator("[data-lastpass-root] [data-row]").click();
    const values = await page.evaluate(() => ["email", "password"].map((id) => (document.getElementById(id) as HTMLInputElement).value));
    console.log("lastpass fake fill:", JSON.stringify(values));
  } finally {
    await ctx.close();
    rmSync(profile, { recursive: true, force: true });
  }
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
