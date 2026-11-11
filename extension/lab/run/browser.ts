// Browser harness of the autofill lab, adapted from e2e/fixtures.ts with the
// world's hosts instead of fixed ones: a fresh headless Chromium profile with
// the unpacked extension and the real native host (the world's vault), every
// hostname mapped to the lab server, the same three network nets (resolver
// rule, route allowlist of the world's hosts, loopback check of every
// response, plus the canary), pairing through the popup, and the helpers the
// drivers use (in-field menu, overlay, chain state). launchPlain gives the
// passkey control a browser without the extension behind the same nets.
// Start states (host-control.ts): the vault as the popup sees it, the locked
// menu's unlock button, the overlay's other logins, and the fill-smart
// command dispatched in the service worker (the keyboard shortcut's handler).
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Browser, type BrowserContext, type Frame, type Locator, type Page, type Worker, chromium, expect } from "@playwright/test";
import { loadCert } from "../../e2e/cert.ts";
import { installHost, type InstalledHost } from "../../e2e/host.ts";
import { CANARY_PATH } from "../../e2e/server.ts";
import { MOVE_GUARD_MS } from "../../src/content/frames.ts";
import { CLICK_GUARD_MS } from "../../src/ui/components.ts";
import type { World } from "../gen/model.ts";
import { DEFAULT_PROFILE_ID } from "../gen/population.ts";
import { accountRow, overlayRowSelector } from "./account.ts";
import type { LabServer } from "../server/server.ts";
import { EXT_ROOT, type LabState } from "./global-setup.ts";
import { hostPids, patchHostConfig, stopHost, UNLOCK_APPROVED, UNLOCK_PENDING, unlockDelayMs, UnlockStandIn } from "./host-control.ts";
import type { StartHost } from "./start-state.ts";

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
  /** Whether the overlay lists an account with this exact title (sso: item title and provider, account.ts) within `timeout`. */
  overlayHas(overlay: Frame, title: string, timeout?: number): Promise<boolean>;
  /** Clicks "Se connecter" on the overlay account `title`; `before` runs right before the click. */
  overlayStart(overlay: Frame, title: string, before?: () => Promise<void>): Promise<void>;
  /** Whether the overlay is the generic card of a locked vault (no account named), within `timeout`. */
  overlayGeneric(overlay: Frame, timeout?: number): Promise<boolean>;
  /** Clicks "Se connecter" on the generic card; `before` runs right before the click. */
  overlayStartGeneric(overlay: Frame, before?: () => Promise<void>): Promise<void>;
  /**
   * Clicks the OnePass icon of `selector` in `scope` with the mouse, where
   * content/icon.ts draws it (a trusted click, as a user's), once the field
   * shows (within `timeout`) and the page analysis had time to attach it.
   * `before` runs right before the click (a cold start stops the host there).
   */
  clickIcon(page: Page, scope: Frame, selector: string, timeout: number, before?: () => Promise<void>): Promise<void>;
  /**
   * Runs `trigger` (the site's own passkey button) and returns the OnePass
   * passkey window it opened (popup passkey.html#<token>, a page of the
   * context), or undefined when none opened within `timeout`.
   */
  passkeyWindow(trigger: () => Promise<void>, timeout: number): Promise<Page | undefined>;
  /** The toolbar Fill on `page`: the popup's `popup_smart_fill` with `page` as the active tab; `before` runs right before it. */
  toolbarFill(page: Page, before?: () => Promise<void>): Promise<void>;
  /** The latest chain started on `https://<site>`, if any. */
  chainState(site: string): Promise<ChainView | null>;
  /**
   * The vault's lock state as the popup reads it (`popup_status`). Opens the
   * session when the host is not connected (so it warms a stopped host) and
   * never unlocks. Undefined when the host did not answer.
   */
  vaultStatus(): Promise<{ locked: boolean } | undefined>;
  /** LAB_DEBUG: what the worker keeps of unlocks and chains (`storage.session`, no secret there), the host's last log lines and its unlock files. */
  debugState(): Promise<string>;
  /** Whether the lab can run the fill-smart command (the service worker lets it dispatch the command event). */
  canShortcut(): Promise<boolean>;
  /** The fill-smart command with `page` as the active tab: what Ctrl+Shift+L (Command+Shift+L) runs. */
  shortcut(page: Page): Promise<void>;
  /**
   * What a menu that cannot fill yet shows: "waiting" (the gesture that opened it already asked the app to
   * unlock or to start; it goes on by itself), or "button" (the fallback: "Déverrouiller dans OnePass" on a
   * locked vault, "Ouvrir OnePass" when the app does not answer). Undefined: neither.
   */
  menuUnlockState(menu: Frame): Promise<"waiting" | "button" | undefined>;
  /** Presses the menu's unlock (or open) button once the click guard allows it. */
  menuUnlock(menu: Frame): Promise<void>;
  /** Whether `menu` lists any row now. */
  menuHasRows(menu: Frame): Promise<boolean>;
  /** Opens the overlay's "Autres identifiants" list; false when the overlay has none. */
  overlayOpenOthers(overlay: Frame): Promise<boolean>;
  /** Whether the opened list offers the account `title`. */
  overlayOtherHas(overlay: Frame, title: string, timeout?: number): Promise<boolean>;
  /** Clicks the row of the one other login `title` that hangs under the pill (exactly two logins); false when there is no such row. */
  overlayPickSecond(overlay: Frame, title: string, before?: () => Promise<void>): Promise<boolean>;
  /** Picks the account `title` in the opened list. */
  overlayPickOther(overlay: Frame, title: string): Promise<void>;
  /** Whether an extension frame of `page` says OnePass is locked. */
  lockedShown(page: Page): Promise<boolean>;
  /** What the start states ask of this profile's native host (start-state.ts). */
  startHost: StartHost;
  close(): Promise<void>;
}

/** UI strings the drivers read (the lab runs the extension in French). */
const UNLOCK_BUTTONS = /^\s*(Déverrouiller dans OnePass|Ouvrir OnePass)\s*$/;
const WAITING_TEXTS = ["Déverrouille OnePass pour continuer", "Ouverture de OnePass"];
const LOCKED_TEXT = "OnePass est verrouillé";
/** The extension's keyboard command (manifests/base.json `commands`, background/app.ts FILL_SMART_COMMAND). */
const FILL_SMART_COMMAND = "fill-smart";

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

/** URL of the extension's passkey choice window (background/passkey.ts opens it as a popup). */
const PASSKEY_WINDOW = /^chrome-extension:\/\/[^/]+\/passkey\.html#[A-Za-z0-9_-]+$/;

/** How long a click in a field gets to open the in-field menu before the driver asks with ArrowDown. */
const CLICK_MENU_MS = 1_500;

/** content/icon.ts: a 20 px icon, 6 px inside the field's right edge (see e2e/smart-fill.spec.ts). */
const ICON_CENTER_FROM_RIGHT = 6 + 10;
/** After the field shows: the content script analyses 150 ms after a mutation burst, then attaches its icon. */
const ICON_SETTLE_MS = 900;

/** The page-level box of `selector` in `scope` (closed shadow root: its page hook, offset by the frame), or null. */
async function fieldBox(p: Page, scope: Frame, selector: string): Promise<{ x: number; y: number; width: number; height: number } | null> {
  const field = scope.locator(selector).first();
  if ((await field.count().catch(() => 0)) > 0) {
    if (!(await field.isVisible().catch(() => false))) return null;
    return field.boundingBox().catch(() => null);
  }
  const box = await shadowField(scope, selector);
  if (!box || box.width <= 0 || box.height <= 0) return null;
  const frameBox = scope === p.mainFrame() ? { x: 0, y: 0 } : await (await scope.frameElement()).boundingBox();
  return { x: (frameBox?.x ?? 0) + box.x, y: (frameBox?.y ?? 0) + box.y, width: box.width, height: box.height };
}

/**
 * Focuses `selector` in `scope` as a user would: by locator when it can reach
 * the field, else (closed shadow root) with a mouse click in the middle of
 * the box the page hook reports. Throws after `timeout` ms. Says how: a click
 * in an empty field may already open the in-field menu, a focus never does.
 */
export async function focusField(p: Page, scope: Frame, selector: string, timeout: number): Promise<"focus" | "click"> {
  const end = Date.now() + timeout;
  const field = scope.locator(selector).first();
  for (;;) {
    if ((await field.count().catch(() => 0)) > 0) {
      await field.focus({ timeout: Math.max(1, end - Date.now()) });
      return "focus";
    }
    const box = await shadowField(scope, selector);
    if (box && box.width > 0 && box.height > 0) {
      // The hook's box is relative to the frame's viewport: add the frame's own offset.
      const frameBox = scope === p.mainFrame() ? { x: 0, y: 0 } : await (await scope.frameElement()).boundingBox();
      await p.mouse.click((frameBox?.x ?? 0) + box.x + box.width / 2, (frameBox?.y ?? 0) + box.y + box.height / 2);
      return "click";
    }
    if (Date.now() >= end) throw new Error(`no field ${selector} within ${timeout} ms`);
    await sleep(200);
  }
}

/** How many times the user taps a control the extension shows as held back before she gives up. */
const HELD_TAPS = 4;

/**
 * A click on a control of an extension frame, as a user makes it. The frames ignore a click that
 * comes within 300 ms of their content showing, and the guard starts again when the browser first
 * declares the frame visible (IntersectionObserver v2: measured 110 to 210 ms after a menu's rows
 * show, later on a busy machine), a time the bench cannot see: a click after a fixed wait lands
 * before or after it by chance. The frame then shows the control pressed (`held`) so the user taps
 * again (src/shared/click-guard.ts), and the bench does the same once the control is released.
 * It stays one gesture: the same intent, the same control. A control that stays held is left
 * alone (the scenario then fails on what it shows).
 */
async function userClick(target: Locator, timeout = 5_000): Promise<void> {
  // A user's click lands in the tab in front (the worker asks the app nothing for another tab).
  await target.page().bringToFront();
  for (let tap = 1; ; tap++) {
    await target.click({ timeout });
    // The held state is set in the click's own handler.
    const held = await target.evaluate((el) => el.classList.contains("held"), undefined, { timeout: 1_000 }).catch(() => false);
    if (!held || tap >= HELD_TAPS) return;
    if (process.env.LAB_DEBUG) console.log(`[lab debug] click held back by the frame's guard (tap ${tap}): tapping again`);
    await target.evaluate((el) => new Promise<void>((done) => {
      const end = Date.now() + 1_500;
      const look = () => (!el.classList.contains("held") || Date.now() >= end ? done() : void setTimeout(look, 30));
      look();
    }), undefined, { timeout: 3_000 }).catch(() => undefined);
    await sleep(60);
  }
}

/** The overlay rows of the account `title` (an sso "<brand> via <Provider>": the brand's row for that provider). */
function overlayAccount(overlay: Frame, title: string) {
  const row = accountRow(title);
  return overlay.locator(overlayRowSelector(row)).filter({ has: overlay.locator(".t1", { hasText: exact(row.title) }) });
}

/** The in-field menu rows of `title` (an sso "<brand> via <Provider>": the brand's row for that provider, never one of its other accounts). */
function menuRowOf(menu: Frame, title: string) {
  const row = accountRow(title);
  const rows = row.provider ? `button.row:not(.row-sub)[data-provider="${row.provider}"]` : "button.row";
  return menu.locator(rows).filter({ has: menu.locator(".t1", { hasText: exact(row.title) }) });
}

/** A fresh browser of the lab for simulated user `profileId` (default: the single default one) with that user's vault. */
export async function launchLab(state: LabState, world: World, server: LabServer, profileId: string = DEFAULT_PROFILE_ID): Promise<Lab> {
  const staged = state.profiles[profileId];
  if (!staged) throw new Error(`lab: no staged vault for profile ${profileId}`);
  const dir = mkdtempSync(join(tmpdir(), "onepass-lab-profile-"));
  const profile = join(dir, "profile");
  const extPath = state.extDir;
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
  let standIn: UnlockStandIn | undefined;
  const close = async () => {
    standIn?.stop();
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
    const host = installHost(dir, join(profile, "NativeMessagingHosts"), id, staged.cache, staged.host);
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
    const watcher = (standIn = new UnlockStandIn(host.dataDir, unlockDelayMs()));
    const deferredUnlock = state.caps?.deferredUnlock === true;
    const startHost: StartHost = {
      running() {
        const pids = hostPids(host.config);
        return pids === undefined ? undefined : pids.length > 0;
      },
      stop: () => stopHost(host.config),
      configure({ locked, deferred }) {
        // The host refuses unknown keys: `unlock` only when it has the control (undefined drops the key).
        patchHostConfig(host.config, { unlocked: !locked, unlock: deferred && deferredUnlock ? "file" : undefined });
      },
      status: () => lab.vaultStatus(),
      deferredUnlock,
      standIn: { start: () => watcher.start(), stop: () => watcher.stop() },
    };

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
        const how = await focusField(p, scope, selector, timeout);
        // A click in an empty field (closed shadow root) opens the menu itself: an
        // ArrowDown on top of it would open a second one and leave the driver
        // holding the first, already replaced frame (lab-2026-10-26 site 27).
        if (how === "click") {
          const opened = await waitExtFrame(p, "menu", CLICK_MENU_MS);
          if (opened) return opened;
        }
        await p.keyboard.press("ArrowDown");
        return waitExtFrame(p, "menu", timeout);
      },
      async menuRow(menu, title, timeout = 5_000) {
        const row = menuRowOf(menu, title);
        return row.first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async pickRow(menu, title) {
        const row = menuRowOf(menu, title);
        await sleep(GUARD_WAIT_MS);
        await userClick(row.first());
      },
      async overlayHas(overlay, title, timeout = 5_000) {
        const account = overlayAccount(overlay, title);
        return account.first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async overlayStart(overlay, title, before) {
        const account = overlayAccount(overlay, title);
        await sleep(GUARD_WAIT_MS);
        await before?.();
        await userClick(account.first().getByRole("button", { name: "Se connecter" }));
      },
      async overlayGeneric(overlay, timeout = 2_000) {
        return overlay.locator(".ov-pill[data-generic]").first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async overlayStartGeneric(overlay, before) {
        await sleep(GUARD_WAIT_MS);
        await before?.();
        await userClick(overlay.locator(".ov-pill[data-generic] button.ov-signin").first());
      },
      async clickIcon(p, scope, selector, timeout, before) {
        const end = Date.now() + timeout;
        let box = await fieldBox(p, scope, selector);
        while (!box) {
          if (Date.now() >= end) throw new Error(`no field ${selector} within ${timeout} ms`);
          await sleep(200);
          box = await fieldBox(p, scope, selector);
        }
        await sleep(ICON_SETTLE_MS);
        // The layout may have moved while the page settled.
        box = (await fieldBox(p, scope, selector)) ?? box;
        await before?.();
        // A user's click lands in the tab in front: the worker asks the app nothing for another tab.
        await p.bringToFront();
        await p.mouse.click(box.x + box.width - ICON_CENTER_FROM_RIGHT, box.y + box.height / 2);
      },
      async passkeyWindow(trigger, timeout) {
        const opened = context.waitForEvent("page", { predicate: (w) => PASSKEY_WINDOW.test(w.url()), timeout })
          .then((w) => w, () => undefined);
        await trigger();
        return opened;
      },
      async toolbarFill(p, before) {
        const popup = await context.newPage();
        try {
          await popup.goto(`chrome-extension://${id}/popup.html`);
          await p.bringToFront();
          await before?.();
          await popup.evaluate(() => chrome.runtime.sendMessage({ type: "popup_smart_fill" }).catch(() => undefined));
        } finally {
          await popup.close();
        }
      },
      async chainState(site) {
        const chains = Object.entries(await sessionStorage()).filter(([k]) => k.startsWith("chain:")).map(([, v]) => v as ChainView)
          .filter((c) => c.siteOrigin === `https://${site}`).sort((a, b) => (a.startedAt ?? 0) - (b.startedAt ?? 0));
        return chains.at(-1) ?? null;
      },
      async debugState() {
        const kept = Object.entries(await sessionStorage().catch(() => ({}) as Record<string, unknown>))
          .filter(([k]) => /^(overlay|unlock|unlock-chain|chain|menu):/.test(k))
          .map(([k, v]) => `${k.split(":")[0]} ${JSON.stringify(v).slice(0, 400)}`);
        const files = [UNLOCK_PENDING, UNLOCK_APPROVED].filter((f) => existsSync(join(host.dataDir, f)));
        return [`unlock files: ${files.join(", ") || "none"}`, `host pids: ${JSON.stringify(hostPids(host.config))}`, ...kept, ...host.log().trim().split("\n").slice(-14)].join("\n    ");
      },
      async vaultStatus() {
        const popup = await context.newPage();
        try {
          await popup.goto(`chrome-extension://${id}/popup.html`);
          const r = (await popup.evaluate(() => chrome.runtime.sendMessage({ type: "popup_status" }).catch(() => null))) as
            { ok?: { locked?: unknown } } | null;
          return typeof r?.ok?.locked === "boolean" ? { locked: r.ok.locked } : undefined;
        } catch {
          return undefined;
        } finally {
          await popup.close().catch(() => undefined);
        }
      },
      async canShortcut() {
        return (await worker()).evaluate(() => {
          const ev = chrome.commands?.onCommand as unknown as { dispatch?: unknown; hasListeners?: () => boolean } | undefined;
          return typeof ev?.dispatch === "function" && ev.hasListeners?.() === true;
        }).catch(() => false);
      },
      async shortcut(p) {
        await p.bringToFront();
        await (await worker()).evaluate((command) => {
          (chrome.commands.onCommand as unknown as { dispatch(c: string): void }).dispatch(command);
        }, FILL_SMART_COMMAND);
      },
      async menuUnlockState(menu) {
        if (await menu.getByRole("button", { name: UNLOCK_BUTTONS }).first().isVisible().catch(() => false)) return "button";
        const text = await menu.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
        return WAITING_TEXTS.some((t) => text.includes(t)) ? "waiting" : undefined;
      },
      async menuUnlock(menu) {
        await sleep(GUARD_WAIT_MS);
        await userClick(menu.getByRole("button", { name: UNLOCK_BUTTONS }).first());
      },
      async menuHasRows(menu) {
        return (await menu.locator("button.row").count().catch(() => 0)) > 0;
      },
      async overlayOpenOthers(overlay) {
        const others = overlay.locator("button.ov-others:not(.ov-other)").first();
        if (!(await others.isVisible().catch(() => false))) return false;
        await sleep(GUARD_WAIT_MS);
        await userClick(others);
        return true;
      },
      async overlayPickSecond(overlay, title, before) {
        const row = overlay.locator("button.ov-other").filter({ has: overlay.locator(".t1", { hasText: exact(accountRow(title).title) }) }).first();
        if (!(await row.isVisible().catch(() => false))) return false;
        await sleep(GUARD_WAIT_MS);
        await before?.();
        await userClick(row);
        return true;
      },
      async overlayOtherHas(overlay, title, timeout = 5_000) {
        const row = overlay.locator("li.ov-opt").filter({ has: overlay.locator(".t1", { hasText: exact(title) }) });
        return row.first().waitFor({ state: "visible", timeout }).then(() => true, () => false);
      },
      async overlayPickOther(overlay, title) {
        const row = overlay.locator("li.ov-opt").filter({ has: overlay.locator(".t1", { hasText: exact(title) }) });
        await sleep(GUARD_WAIT_MS);
        await userClick(row.first());
      },
      async lockedShown(p) {
        for (const f of p.frames()) {
          if (!f.url().startsWith("chrome-extension://")) continue;
          const text = await f.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
          if (text.includes(LOCKED_TEXT)) return true;
        }
        return false;
      },
      startHost,
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
