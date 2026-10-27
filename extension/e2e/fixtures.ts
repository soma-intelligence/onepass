// Playwright fixtures: a fresh headless Chromium profile per test with the
// unpacked extension, every hostname mapped to the local test server, every
// other request aborted, and the real native host installed for that
// profile. Helpers drive the extension the way a user does: pairing in the
// popup, the in-field menu (trusted keyboard), the overlay and save frames.
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BrowserContext, type Frame, type Page, type Worker, test as base, chromium, expect } from "@playwright/test";
import { loadCert, type TestCert } from "./cert";
import type { E2EState } from "./global-setup";
import { type InstalledHost, installHost, type StagedHost } from "./host";
import { CANARY_PATH, startServer, type TestServer } from "./server";
import { MOVE_GUARD_MS } from "../src/content/frames";
import { CLICK_GUARD_MS } from "../src/ui/components";

/**
 * Wait before clicking in a freshly shown or re-rendered extension frame:
 * the frames ignore clicks for CLICK_GUARD_MS after (re)display and the
 * content script for MOVE_GUARD_MS after a move (spec 8.3), plus a margin
 * for the IntersectionObserver v2 delay (100 ms) and rendering.
 */
export const GUARD_WAIT_MS = Math.max(CLICK_GUARD_MS, MOVE_GUARD_MS) + 150;

const LOOPBACK = new Set(["127.0.0.1", "::1"]);

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
  /** Waits `ms` (default GUARD_WAIT_MS: past the click guard of a freshly shown frame). */
  settle(ms?: number): Promise<void>;
  /** The host's audit journal (one JSON line per secret returned, no value). */
  audit(): string;
  /** `storage.session` of the extension, read in the service worker. */
  sessionStorage(): Promise<Record<string, unknown>>;
}

interface WorkerFixtures {
  env: { cert: TestCert; server: TestServer; cache: string; staged: StagedHost };
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
      await use({ cert, server, cache: s.cache, staged: s.host });
      await server.close();
    },
    { scope: "worker" },
  ],
  build: ["regular", { option: true }],
  ext: async ({ env, build }, use) => {
    const { server, cert, cache, staged } = env;
    server.reset();
    const dir = mkdtempSync(join(tmpdir(), "onepass-e2e-test-"));
    const profile = join(dir, "profile");
    const extPath = join(EXT_ROOT, "dist", build === "e2e" ? "chromium-e2e" : "chromium");
    // Whatever fails below (launch, canary, test, loopback check), the
    // browser closes and the temporary profile and host data go.
    let context: BrowserContext | undefined;
    const pendingChecks: Promise<void>[] = [];
    const remote: string[] = [];
    try {
      const ctx = await chromium.launchPersistentContext(profile, {
        channel: "chromium",
        headless: true,
        viewport: { width: 1280, height: 860 },
        locale: "fr-FR",
        ...(process.env.ONEPASS_E2E_VIDEO
          ? { recordVideo: { dir: process.env.ONEPASS_E2E_VIDEO, size: { width: 1280, height: 860 } } }
          : {}),
        args: [
          `--disable-extensions-except=${extPath}`,
          `--load-extension=${extPath}`,
          `--host-resolver-rules=MAP * 127.0.0.1:${server.port}, EXCLUDE localhost`,
          `--ignore-certificate-errors-spki-list=${cert.spki}`,
          // The extension follows the browser's UI language; the specs read French.
          "--lang=fr-FR",
          "--no-first-run",
          "--no-default-browser-check",
          "--disable-sync",
          "--disable-background-networking",
          "--disable-component-update",
        ],
      });
      context = ctx;
      // Second safety net: nothing but the local test hosts and extension pages.
      await ctx.route("**/*", (route) => {
        const u = new URL(route.request().url());
        const ok =
          u.protocol === "chrome-extension:" ||
          u.protocol === "data:" ||
          ((u.protocol === "https:" || u.protocol === "http:") && LOCAL_HOSTS.has(u.hostname));
        return ok ? route.continue() : route.abort("blockedbyclient");
      });
      // Third net: every network response must come from the loopback server,
      // so a real accounts.google.com (say) can never answer.
      ctx.on("response", (r) => {
        pendingChecks.push(
          r
            .serverAddr()
            .then((a) => {
              if (a && !LOOPBACK.has(a.ipAddress)) remote.push(`${r.url()} from ${a.ipAddress}`);
            })
            .catch(() => undefined),
        );
      });
      const worker = async (): Promise<Worker> => {
        const live = ctx.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
        return live ?? (await ctx.waitForEvent("serviceworker", { timeout: 15_000 }));
      };
      const id = new URL((await worker()).url()).host;
      if (id !== unpackedExtensionId(extPath)) {
        console.warn(`e2e: extension id ${id} differs from the path-derived id ${unpackedExtensionId(extPath)}`);
      }
      // The browser reads the host manifest at connectNative time: writing it
      // now, before the first connection, is enough.
      const host = installHost(dir, join(profile, "NativeMessagingHosts"), id, cache, staged);
      const page = ctx.pages()[0] ?? (await ctx.newPage());
      // Canary: the local server (this nonce) answers for a real provider name.
      const canary = await page.goto(`https://accounts.google.com${CANARY_PATH}`);
      expect(canary?.status()).toBe(200);
      expect(await canary?.text()).toBe(server.nonce);
      expect(LOOPBACK.has((await canary?.serverAddr())?.ipAddress ?? "")).toBe(true);

      const findExtFrame = (p: Page, kind: "menu" | "overlay" | "save") =>
        p.frames().find((f) => f.url().startsWith("chrome-extension://") && new URL(f.url()).pathname === `/${kind}.html`);
      const extFrame = async (p: Page, kind: "menu" | "overlay" | "save"): Promise<Frame> => {
        let f: Frame | undefined;
        await expect.poll(() => (f = findExtFrame(p, kind)) !== undefined, { timeout: 15_000, message: `${kind} frame` }).toBe(true);
        return f as Frame;
      };
      const settle = (ms = GUARD_WAIT_MS) => new Promise<void>((r) => setTimeout(r, ms));

      const ext: Ext = {
        context: ctx,
        id,
        host,
        server,
        page,
        worker,
        findExtFrame,
        extFrame,
        settle,
        async pair() {
          const popup = await ctx.newPage();
          await popup.goto(`chrome-extension://${id}/popup.html`);
          expect(popup.url(), "the popup tab must show the extension popup").toBe(`chrome-extension://${id}/popup.html`);
          await popup.getByRole("button", { name: "Appairer avec OnePass" }).click();
          // The host logs its banner first thing: if it never does, Chromium
          // could not start it (manifest, extension id, or an exec blocked by
          // the OS), and waiting for the code below would only time out.
          await expect
            .poll(() => host.log().includes("DEV MODE"), {
              timeout: 15_000,
              message: `native host never started (wrapper ${host.wrapper}, manifest ${host.manifest}, extension ${id})`,
            })
            .toBe(true);
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
          const cdp = await ctx.newCDPSession(page);
          await cdp.send("ServiceWorker.enable");
          await cdp.send("ServiceWorker.stopAllWorkers");
          await cdp.detach();
        },
        async openMenu(p, selector, frame) {
          const scope = frame ?? p.mainFrame();
          // The content script has started in that document (its host element).
          await expect(scope.locator("onepass-root")).toHaveCount(1);
          await scope.focus(selector, { timeout: 10_000 });
          // One trusted keystroke, as a user would press it.
          await p.keyboard.press("ArrowDown");
          const f = await extFrame(p, "menu");
          await f.waitForLoadState("domcontentloaded");
          return f;
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
        audit() {
          const path = join(host.dataDir, "audit.log");
          return existsSync(path) ? readFileSync(path, "utf8") : "";
        },
        async sessionStorage() {
          const w = await worker();
          return w.evaluate(() => chrome.storage.session.get(null));
        },
      };
      await use(ext);
    } finally {
      try {
        await context?.close();
        await Promise.all(pendingChecks);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    expect(remote, "responses from a non-loopback address").toEqual([]);
  },
});

/** A test whose extension is paired before it starts. */
export const paired = test.extend<{ ext: Ext }>({
  ext: async ({ ext }, use) => {
    await ext.pair();
    await use(ext);
  },
});
