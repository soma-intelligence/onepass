// Browser harness of the autofill lab, adapted from e2e/fixtures.ts with the
// world's hosts instead of fixed ones: a fresh headless Chromium profile with
// the unpacked extension and the real native host (the world's vault), every
// hostname mapped to the lab server, the same three network nets (resolver
// rule, route allowlist of the world's hosts, loopback check of every
// response, plus the canary), pairing through the popup, and the helpers the
// drivers use (in-field menu, overlay, chain state). launchPlain gives the
// passkey control a browser without the extension behind the same nets.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Browser, type BrowserContext, type Frame, type Page, type Worker, chromium, expect } from "@playwright/test";
import { loadCert } from "../../e2e/cert.ts";
import { installHost, type InstalledHost } from "../../e2e/host.ts";
import { CANARY_PATH } from "../../e2e/server.ts";
import { MOVE_GUARD_MS } from "../../src/content/frames.ts";
import { CLICK_GUARD_MS } from "../../src/ui/components.ts";
import type { World } from "../gen/model.ts";
import type { LabServer } from "../server/server.ts";
import { EXT_ROOT, type LabState } from "./global-setup.ts";

/** Past the click guard of a freshly shown extension frame (see e2e/fixtures.ts). */
export const GUARD_WAIT_MS = Math.max(CLICK_GUARD_MS, MOVE_GUARD_MS) + 150;
const LOOPBACK = new Set(["127.0.0.1", "::1"]);
export type ExtFrameKind = "menu" | "overlay" | "save";

export function readState(): LabState {
  const p = process.env.LAB_STATE;
  if (!p) throw new Error("lab: LAB_STATE is not set (run through `npm run lab:smoke`)");
  return JSON.parse(readFileSync(p, "utf8")) as LabState;
}

export function readWorld(state: LabState): World {
  return JSON.parse(readFileSync(state.world, "utf8")) as World;
}

/** A whole-text matcher for a literal string. */
export function exact(s: string): RegExp {
  return new RegExp(`^\\s*${s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`);
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** The part of a stored chain state (`chain:<tabId>`, no secret) the drivers read. */
export interface ChainView { status: string; reason?: string; host?: string; siteOrigin?: string; startedAt?: number }

export interface Lab {
  context: BrowserContext;
  id: string;
  host: InstalledHost;
  server: LabServer;
  world: World;
  newPage(): Promise<Page>;
  pair(): Promise<void>;
  findExtFrame(page: Page, kind: ExtFrameKind): Frame | undefined;
  /** Waits up to `timeout` ms for an extension frame; undefined if none showed. */
  waitExtFrame(page: Page, kind: ExtFrameKind, timeout: number): Promise<Frame | undefined>;
  /** Focus + one trusted ArrowDown in `selector` of `scope`; the menu frame, or undefined after `timeout`. */
  openMenu(page: Page, scope: Frame, selector: string, timeout?: number): Promise<Frame | undefined>;
  /** The menu row with this exact title, if offered within `timeout`. */
  menuRow(menu: Frame, title: string, timeout?: number): Promise<boolean>;
  /** Clicks a menu row by its exact title once the click guard allows it. */
  pickRow(menu: Frame, title: string): Promise<void>;
  /** Whether the overlay lists an account with this exact title within `timeout`. */
  overlayHas(overlay: Frame, title: string, timeout?: number): Promise<boolean>;
  /** Clicks "Se connecter" on the overlay account `title`. */
  overlayStart(overlay: Frame, title: string): Promise<void>;
  /** The latest chain started on `https://<site>`, if any. */
  chainState(site: string): Promise<ChainView | null>;
  close(): Promise<void>;
}

/**
 * Every non-loopback response seen by any browser of this process. A close
 * error can be swallowed on a bench-error path; this registry cannot, and
 * each batch test asserts it stays empty (like e2e/fixtures.ts).
 */
const violations: string[] = [];
// (Also every request to a host outside the world, as "<method> <host>".)
export function networkViolations(): readonly string[] {
  return violations;
}

/** Throws (lab:) when `remote` holds any non-loopback response. */
function assertLoopback(remote: string[]): void {
  if (remote.length > 0) throw new Error(`lab: responses from a non-loopback address: ${remote.join(", ")}`);
}

/** The bench error `e`, with the loopback failure of the close that followed it, if any. */
async function closeAfter(close: () => Promise<void>, e: unknown): Promise<Error> {
  const msg = (e as Error)?.message ?? String(e);
  const closed = await close().then(() => "", (c: unknown) => `; ${(c as Error)?.message ?? String(c)}`);
  return new Error(`${msg.startsWith("lab:") ? msg : `lab: ${msg}`}${closed}`);
}

/** Fields of a request body as the lab server would read them (form-urlencoded or JSON; anything else whole). */
export function requestFields(contentType: string, body: string | null): Record<string, string> {
  if (!body) return {};
  const type = contentType.toLowerCase();
  if (type.startsWith("application/x-www-form-urlencoded")) return Object.fromEntries(new URLSearchParams(body));
  if (type.startsWith("application/json")) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        const out: Record<string, string> = {};
        for (const [k, v] of Object.entries(parsed)) if (typeof v === "string") out[k] = v;
        return out;
      }
    } catch {
      // not JSON after all: checked whole below
    }
  }
  return { body };
}

/**
 * The three nets of e2e/fixtures.ts on a context; returns the pending
 * loopback checks. A request to a host outside the world is aborted, but
 * first recorded as a violation and shown to the leak ledger (query and
 * body), so a secret sent to an unplanned host is a leak, not a silence.
 */
async function guard(ctx: BrowserContext, world: World, server: LabServer): Promise<{ remote: string[]; pending: Promise<void>[] }> {
  const allowed = new Set(world.hosts);
  const remote: string[] = [];
  const pending: Promise<void>[] = [];
  await ctx.route("**/*", (route) => {
    const req = route.request();
    const u = new URL(req.url());
    const web = u.protocol === "https:" || u.protocol === "http:";
    if (u.protocol === "chrome-extension:" || u.protocol === "data:" || (web && allowed.has(u.hostname))) return route.continue();
    if (web) {
      violations.push(`${req.method()} ${u.hostname}`);
      const fields = { ...Object.fromEntries(u.searchParams), ...requestFields(req.headers()["content-type"] ?? "", req.postData()) };
      server.ledger.record(u.hostname, u.pathname, fields);
    }
    return route.abort("blockedbyclient");
  });
  ctx.on("response", (r) => {
    pending.push(r.serverAddr().then((a) => {
      if (a && !LOOPBACK.has(a.ipAddress)) {
        remote.push(`${r.url()} from ${a.ipAddress}`);
        violations.push(`${r.url()} from ${a.ipAddress}`);
      }
    }).catch(() => undefined));
  });
  return { remote, pending };
}

function args(state: LabState, server: LabServer): string[] {
  const cert = loadCert(state.certDir);
  return [
    `--host-resolver-rules=MAP * 127.0.0.1:${server.port}, EXCLUDE localhost`,
    `--ignore-certificate-errors-spki-list=${cert.spki}`,
    // The extension follows the browser's UI language; the drivers read French.
    "--lang=fr-FR",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-component-update",
  ];
}

async function canary(page: Page, server: LabServer): Promise<void> {
  const r = await page.goto(`https://accounts.google.com${CANARY_PATH}`);
  if (r?.status() !== 200 || (await r.text()) !== server.nonce || !LOOPBACK.has((await r.serverAddr())?.ipAddress ?? "")) {
    throw new Error("lab: canary failed (a provider host did not resolve to the lab server)");
  }
}

/** A field's box and fill state through the page hook of a shadow form (render-forms.ts), or null. */
export async function shadowField(scope: Frame, selector: string): Promise<{ x: number; y: number; width: number; height: number; filled: boolean } | null> {
  return scope.evaluate((sel) => {
    const hook = (window as unknown as { __labField?: (s: string) => { x: number; y: number; width: number; height: number; filled: boolean } | null }).__labField;
    return hook ? hook(sel) : null;
  }, selector).catch(() => null);
}

/**
 * Focuses `selector` in `scope` as a user would: by locator when it can reach
 * the field, else (closed shadow root) with a mouse click in the middle of
 * the box the page hook reports. Throws after `timeout` ms.
 */
export async function focusField(p: Page, scope: Frame, selector: string, timeout: number): Promise<void> {
  const end = Date.now() + timeout;
  const field = scope.locator(selector).first();
  for (;;) {
    if ((await field.count().catch(() => 0)) > 0) {
      await field.focus({ timeout: Math.max(1, end - Date.now()) });
      return;
    }
    const box = await shadowField(scope, selector);
    if (box && box.width > 0 && box.height > 0) {
      // The hook's box is relative to the frame's viewport: add the frame's own offset.
      const frameBox = scope === p.mainFrame() ? { x: 0, y: 0 } : await (await scope.frameElement()).boundingBox();
      await p.mouse.click((frameBox?.x ?? 0) + box.x + box.width / 2, (frameBox?.y ?? 0) + box.y + box.height / 2);
      return;
    }
    if (Date.now() >= end) throw new Error(`no field ${selector} within ${timeout} ms`);
    await sleep(200);
  }
}

export async function launchLab(state: LabState, world: World, server: LabServer): Promise<Lab> {
  const dir = mkdtempSync(join(tmpdir(), "onepass-lab-profile-"));
  const profile = join(dir, "profile");
  const extPath = join(EXT_ROOT, "dist", "chromium");
  let ctx: BrowserContext | undefined;
  try {
    ctx = await chromium.launchPersistentContext(profile, {
      channel: "chromium",
      headless: true,
      viewport: { width: 1280, height: 860 },
      locale: "fr-FR",
      args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`, ...args(state, server)],
    });
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`lab: browser launch failed: ${(e as Error).message}`);
  }
  const context = ctx;
  let nets: Awaited<ReturnType<typeof guard>> = { remote: [], pending: [] };
  const close = async () => {
    try {
      await context.close();
      await Promise.all(nets.pending);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    assertLoopback(nets.remote);
  };
  try {
    nets = await guard(context, world, server);
    const worker = async (): Promise<Worker> => {
      const live = context.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"));
      return live ?? (await context.waitForEvent("serviceworker", { timeout: 15_000 }));
    };
    const id = new URL((await worker()).url()).host;
    const host = installHost(dir, join(profile, "NativeMessagingHosts"), id, state.cache, state.host);
    const first = context.pages()[0] ?? (await context.newPage());
    await canary(first, server);

    const findExtFrame = (p: Page, kind: ExtFrameKind) =>
      p.frames().find((f) => f.url().startsWith("chrome-extension://") && new URL(f.url()).pathname === `/${kind}.html`);
    const waitExtFrame = async (p: Page, kind: ExtFrameKind, timeout: number) => {
      const end = Date.now() + timeout;
      for (;;) {
        const f = findExtFrame(p, kind);
        if (f) {
          await f.waitForLoadState("domcontentloaded").catch(() => undefined);
          return f;
        }
        if (Date.now() >= end || p.isClosed()) return undefined;
        await sleep(200);
      }
    };
    const sessionStorage = async () => (await worker()).evaluate(() => chrome.storage.session.get(null)) as Promise<Record<string, unknown>>;

    const lab: Lab = {
      context, id, host, server, world,
      async newPage() {
        return context.newPage();
      },
      async pair() {
        const popup = await context.newPage();
        try {
          await popup.goto(`chrome-extension://${id}/popup.html`);
          await popup.getByRole("button", { name: "Appairer avec OnePass" }).click();
          await expect.poll(() => host.log().includes("DEV MODE"), {
            timeout: 15_000, message: `lab: native host never started (wrapper ${host.wrapper})`,
          }).toBe(true);
          const sas = popup.locator(".sas");
          await expect(sas).toHaveText(/^\d{3} \d{3}$/, { timeout: 60_000 });
          const shown = (await sas.textContent())?.trim() ?? "";
          await expect.poll(() => host.codes().at(-1), { timeout: 10_000 }).toBe(shown);
          await popup.getByRole("button", { name: "Les codes sont identiques" }).click();
          await expect.poll(() => host.log().includes("pairing stored"), { timeout: 15_000 }).toBe(true);
        } catch (e) {
          throw new Error(`lab: pairing failed: ${(e as Error).message.split("\n")[0]}`);
        } finally {
          await popup.close();
        }
      },
      findExtFrame,
      waitExtFrame,
      async openMenu(p, scope, selector, timeout = 10_000) {
        await focusField(p, scope, selector, timeout);
        await p.keyboard.press("ArrowDown");
        return waitExtFrame(p, "menu", timeout);
      },
      async menuRow(menu, title, timeout = 5_000) {
        const row = menu.locator("button.row").filter({ has: menu.locator(".t1", { hasText: exact(title) }) });
        return row.first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async pickRow(menu, title) {
        const row = menu.locator("button.row").filter({ has: menu.locator(".t1", { hasText: exact(title) }) });
        await sleep(GUARD_WAIT_MS);
        await row.first().click();
      },
      async overlayHas(overlay, title, timeout = 5_000) {
        const account = overlay.locator(".ov-account").filter({ has: overlay.locator(".t1", { hasText: exact(title) }) });
        return account.first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async overlayStart(overlay, title) {
        const account = overlay.locator(".ov-account").filter({ has: overlay.locator(".t1", { hasText: exact(title) }) });
        await sleep(GUARD_WAIT_MS);
        await account.first().getByRole("button", { name: "Se connecter" }).click();
      },
      async chainState(site) {
        const chains = Object.entries(await sessionStorage()).filter(([k]) => k.startsWith("chain:")).map(([, v]) => v as ChainView)
          .filter((c) => c.siteOrigin === `https://${site}`).sort((a, b) => (a.startedAt ?? 0) - (b.startedAt ?? 0));
        return chains.at(-1) ?? null;
      },
      close,
    };
    return lab;
  } catch (e) {
    throw await closeAfter(close, e);
  }
}

export interface PlainBrowser {
  browser: Browser;
  context: BrowserContext;
  close(): Promise<void>;
}

/** A Chromium without the extension behind the same nets (passkey control). */
export async function launchPlain(state: LabState, world: World, server: LabServer): Promise<PlainBrowser> {
  const browser = await chromium.launch({ channel: "chromium", headless: true, args: args(state, server) });
  const context = await browser.newContext({ viewport: { width: 1280, height: 860 }, locale: "fr-FR" });
  let nets: Awaited<ReturnType<typeof guard>> = { remote: [], pending: [] };
  const close = async () => {
    await context.close();
    await browser.close();
    await Promise.all(nets.pending);
    assertLoopback(nets.remote);
  };
  try {
    nets = await guard(context, world, server);
    await canary(await context.newPage(), server);
  } catch (e) {
    throw await closeAfter(close, e);
  }
  return { browser, context, close };
}
