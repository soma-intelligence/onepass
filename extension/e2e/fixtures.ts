// Playwright fixtures: a fresh headless Chromium profile per test with the
// unpacked extension, every hostname mapped to the local test server, every
// other request aborted, and the real native host installed for that
// profile. Helpers drive the extension the way a user does: pairing in the
// popup, the in-field menu (trusted keyboard), the overlay and save frames.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BrowserContext, type Frame, type Page, type Worker, test as base, chromium, expect } from "@playwright/test";
import { loadCert, type TestCert } from "./cert";
import type { E2EState } from "./global-setup";
import { type InstalledHost, installHost } from "./host";
import { startServer, type TestServer } from "./server";

export { expect };

const EXT_ROOT = fileURLToPath(new URL("../", import.meta.url));

/** Chromium's id of an unpacked extension: SHA-256 of its path, 32 hex digits mapped to a-p. */
export function unpackedExtensionId(path: string): string {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function state(): E2EState {
  const p = process.env.E2E_STATE;
  if (!p) throw new Error("e2e: E2E_STATE is not set (run through `npm run e2e`)");
  return JSON.parse(readFileSync(p, "utf8")) as E2EState;
}

/** Hosts a test page may reach; all resolve to 127.0.0.1 (`--host-resolver-rules`). */
const LOCAL_HOSTS = new Set([
  "atlas-cloud.test",
  "docs.atlas-cloud.test",
  "admin.atlas-cloud.test",
  "atlass-cloud.test",
  "atlas-cloud.test.evil.test",
  "evil.test",
  "sso.evil.test",
  "accounts.google.com",
  "accounts.google.com.evil.test",
]);

export type Build = "regular" | "e2e";

/** A whole-text matcher for a literal string. */
export function exact(s: string | RegExp): RegExp {
  return typeof s === "string" ? new RegExp(`^\\s*${s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`) : s;
}

export interface Ext {
  context: BrowserContext;
  /** Extension id (read from the service worker URL, checked against the path). */
  id: string;
  host: InstalledHost;
  server: TestServer;
  page: Page;
  /** The current service worker (a new one after a restart). */
  worker(): Promise<Worker>;
  /** Pairs through the popup; returns the code both sides showed. */
  pair(): Promise<string>;
  /** Stops every service worker (CDP), as the browser does when idle. */
  stopWorker(): Promise<void>;
  /** Opens the in-field menu of `selector` (focus + trusted ArrowDown). */
  openMenu(page: Page, selector: string, frame?: Frame): Promise<Frame>;
  /** Clicks a menu row by its exact title (and subtitle), once the click guard allows it. */
  pickRow(menu: Frame, title: string | RegExp, subtitle?: string): Promise<void>;
  /** Clicks "Se connecter" on an overlay account by its exact title. */
  overlayStart(page: Page, title: string): Promise<Frame>;
  /** The chain state of the page's tab (`storage.session`), if any. */
  chainState(): Promise<{ status: string; reason?: string; host?: string } | null>;
  extFrame(page: Page, kind: "menu" | "overlay" | "save"): Promise<Frame>;
  findExtFrame(page: Page, kind: "menu" | "overlay" | "save"): Frame | undefined;
  /** Waits until the click guard of a freshly shown extension frame is past. */
  settle(ms?: number): Promise<void>;
  /** `storage.session` of the extension, read in the service worker. */
  sessionStorage(): Promise<Record<string, unknown>>;
}

interface WorkerFixtures {
  env: { cert: TestCert; server: TestServer; cache: string };
}

interface TestFixtures {
  build: Build;
  ext: Ext;
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  env: [
    async ({}, use) => {
      const s = state();
      const cert = loadCert(s.certDir);
      const server = await startServer(cert);
      await use({ cert, server, cache: s.cache });
      await server.close();
    },
    { scope: "worker" },
  ],
  build: ["regular", { option: true }],
  ext: async ({ env, build }, use) => {
    const { server, cert, cache } = env;
    server.reset();
    const dir = mkdtempSync(join(tmpdir(), "onepass-e2e-test-"));
    const profile = join(dir, "profile");
    const extPath = join(EXT_ROOT, "dist", build === "e2e" ? "chromium-e2e" : "chromium");
    const context = await chromium.launchPersistentContext(profile, {
      channel: "chromium",
      headless: true,
      viewport: { width: 1280, height: 860 },
      locale: "fr-FR",
      args: [
        `--disable-extensions-except=${extPath}`,
        `--load-extension=${extPath}`,
        `--host-resolver-rules=MAP * 127.0.0.1:${server.port}, EXCLUDE localhost`,
        `--ignore-certificate-errors-spki-list=${cert.spki}`,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-component-update",
      ],
    });
    // Second safety net: nothing but the local test hosts and extension pages.
    await context.route("**/*", (route) => {
      const u = new URL(route.request().url());
      const ok =
        u.protocol === "chrome-extension:" ||
        u.protocol === "data:" ||
        ((u.protocol === "https:" || u.protocol === "http:") && LOCAL_HOSTS.has(u.hostname));
      return ok ? route.continue() : route.abort("blockedbyclient");
    });
    const worker = async (): Promise<Worker> => {
      const live = context.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
      return live ?? (await context.waitForEvent("serviceworker", { timeout: 15_000 }));
    };
    const id = new URL((await worker()).url()).host;
    if (id !== unpackedExtensionId(extPath)) {
      console.warn(`e2e: extension id ${id} differs from the path-derived id ${unpackedExtensionId(extPath)}`);
    }
    // The browser reads the host manifest at connectNative time: writing it
    // now, before the first connection, is enough.
    const host = installHost(dir, join(profile, "NativeMessagingHosts"), id, cache);
    const page = context.pages()[0] ?? (await context.newPage());

    const findExtFrame = (p: Page, kind: "menu" | "overlay" | "save") =>
      p.frames().find((f) => f.url().startsWith("chrome-extension://") && new URL(f.url()).pathname === `/${kind}.html`);
    const extFrame = async (p: Page, kind: "menu" | "overlay" | "save"): Promise<Frame> => {
      let f: Frame | undefined;
      await expect.poll(() => (f = findExtFrame(p, kind)) !== undefined, { timeout: 15_000, message: `${kind} frame` }).toBe(true);
      return f as Frame;
    };
    const settle = (ms = 450) => new Promise<void>((r) => setTimeout(r, ms));

    const ext: Ext = {
      context,
      id,
      host,
      server,
      page,
      worker,
      findExtFrame,
      extFrame,
      settle,
      async pair() {
        const popup = await context.newPage();
        await popup.goto(`chrome-extension://${id}/popup.html`);
        await popup.getByRole("button", { name: "Appairer avec OnePass" }).click();
        const sas = popup.locator(".sas");
        await expect(sas).toHaveText(/^\d{3} \d{3}$/, { timeout: 60_000 });
        const shown = (await sas.textContent())?.trim() ?? "";
        await expect.poll(() => host.codes().at(-1), { timeout: 10_000 }).toBe(shown);
        await popup.getByRole("button", { name: "Les codes sont identiques" }).click();
        await expect(popup.getByRole("button", { name: "Appairer avec OnePass" })).toHaveCount(0);
        await expect(popup.locator(".sas")).toHaveCount(0);
        await expect.poll(() => host.log().includes("pairing stored")).toBe(true);
        await popup.close();
        return shown;
      },
      async stopWorker() {
        const cdp = await context.newCDPSession(page);
        await cdp.send("ServiceWorker.enable");
        await cdp.send("ServiceWorker.stopAllWorkers");
        await cdp.detach();
      },
      async openMenu(p, selector, frame) {
        const scope = frame ?? p.mainFrame();
        for (let i = 0; i < 20; i++) {
          await scope.focus(selector);
          await p.keyboard.press("ArrowDown");
          for (let j = 0; j < 5; j++) {
            const f = findExtFrame(p, "menu");
            if (f) {
              await f.waitForLoadState("domcontentloaded");
              return f;
            }
            await settle(100);
          }
        }
        throw new Error(`no menu opened for ${selector}`);
      },
      async pickRow(menu, title, subtitle) {
        let row = menu.locator("button.row").filter({ has: menu.locator(".t1", { hasText: exact(title) }) });
        if (subtitle !== undefined) row = row.filter({ has: menu.locator(".t2", { hasText: exact(subtitle) }) });
        await expect(row).toHaveCount(1);
        await settle();
        await row.click();
      },
      async overlayStart(p, title) {
        const overlay = await extFrame(p, "overlay");
        const account = overlay.locator(".ov-account").filter({ has: overlay.locator(".t1", { hasText: exact(title) }) });
        await expect(account).toHaveCount(1);
        await settle();
        await account.getByRole("button", { name: "Se connecter" }).click();
        return overlay;
      },
      async chainState() {
        const all = await this.sessionStorage();
        const chains = Object.entries(all).filter(([k]) => k.startsWith("chain:"));
        return chains.length === 0 ? null : (chains[chains.length - 1]?.[1] as { status: string; reason?: string; host?: string });
      },
      async sessionStorage() {
        const w = await worker();
        return w.evaluate(() => chrome.storage.session.get(null));
      },
    };
    await use(ext);
    await context.close();
    rmSync(dir, { recursive: true, force: true });
  },
});

/** A test whose extension is paired before it starts. */
export const paired = test.extend<{ ext: Ext }>({
  ext: async ({ ext }, use) => {
    await ext.pair();
    await use(ext);
  },
});
