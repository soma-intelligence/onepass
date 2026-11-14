// Helpers of the two-factor setup specs (setup-qr.spec.ts, security.spec.ts): the popup's
// "Scan 2FA QR code" button, the setup card in the page, a stubbed tab capture and the
// worker's host requests (e2e build only).
import type { CDPSession, Frame, Page, Worker } from "@playwright/test";
import { type Ext, expect } from "./fixtures";
import { readPng } from "./png";
import { FX, type Hit, type TestServer, totp } from "./server";

export const ATLAS = "https://atlas-cloud.test";

/** The card's words (the specs run with the browser in English). */
export const L = {
  scan: "Scan 2FA QR code",
  none: "Nothing to scan on this page",
  add: "Add",
  cancel: "Cancel",
  replace: "Replace",
  newLogin: "New login",
  save: "Save",
  saved: "Saved. Press the site's button to confirm.",
  paste: "No QR code found. Paste the setup key.",
  title: (item: string) => `Add the 2FA code to ${item}?`,
  replaceTitle: (item: string) => `${item} already has a 2FA code. Replace it?`,
  mismatch: (account: string, username: string) => `The code is for ${account}. This login is ${username}.`,
  codesTitle: (count: number, item: string) => `Save ${count} recovery codes on ${item}?`,
} as const;

export function findSetupFrame(page: Page, not?: Frame): Frame | undefined {
  return page
    .frames()
    .find((f) => f !== not && !f.isDetached() && f.url().startsWith("chrome-extension://") && new URL(f.url()).pathname === "/setup.html");
}

/**
 * Requests to the test sites (Atlas, its subdomains and look-alikes). Chromium's own background
 * calls (account list, device check-in) also reach the local server through the host mapping;
 * they come from the browser, not from a page or the extension, and are left out.
 */
export function siteHits(server: TestServer): Hit[] {
  return server.hits.filter((h) => /(^|\.)atlas-cloud\.test$|^atlass-cloud\.test$|evil\.test$/.test(h.host));
}

/** The setup card shown in `page` (another one than `not`, if given), once its page loaded. */
export async function setupFrame(page: Page, not?: Frame): Promise<Frame> {
  let f: Frame | undefined;
  await expect.poll(() => (f = findSetupFrame(page, not)) !== undefined, { timeout: 20_000, message: "setup card" }).toBe(true);
  const frame = f as Frame;
  await frame.waitForLoadState("domcontentloaded");
  await expect(frame.locator(".save-card, .saved").first()).toBeVisible();
  return frame;
}

/** The card's token (its URL fragment). */
export const tokenOf = (card: Frame) => new URL(card.url()).hash.slice(1);

/**
 * Opens the popup the way the toolbar shows it for `page`: the popup page renders while `page`
 * is the active tab of the window (so its current site is `page`'s), then the button is clicked.
 * Returns the popup page (it may have closed itself once the card showed).
 */
export async function clickScan(ext: Ext, page: Page): Promise<Page> {
  const popup = await ext.context.newPage();
  await page.bringToFront();
  await popup.goto(`chrome-extension://${ext.id}/popup.html`);
  const button = popup.getByRole("button", { name: L.scan });
  await expect(button).toBeVisible();
  await button.click();
  return popup;
}

/** Waits past the click guard of a freshly shown or re-rendered card, then clicks `name`. */
export async function cardClick(ext: Ext, card: Frame, name: string): Promise<void> {
  const b = card.getByRole("button", { name, exact: true });
  await expect(b).toBeVisible();
  await ext.settle();
  await b.click();
}

/** The text of the card's focused element. */
export function focusedText(card: Frame): Promise<string> {
  return card.evaluate(() => (document.activeElement?.textContent ?? "").trim());
}

/** The current code of the setup seed (any of the three accepted windows). */
export function setupCodes(): string[] {
  const now = Date.now();
  return [-30_000, 0, 30_000].map((d) => totp(FX.setup.secret, now + d));
}

/**
 * Makes `chrome.tabs.captureVisibleTab` in the worker return a real screenshot of `page`.
 * Headless Chromium never grants `activeTab`, and no permission is added for the tests, so the
 * capture itself is stubbed: everything after it (decode in the page's scanner, card) is real.
 */
export async function stubCapture(ext: Ext, page: Page, cdp?: CDPSession): Promise<{ width: number; height: number }> {
  // With a CDP device-metrics override, Playwright's screenshot is taken at scale 1: the
  // override's own session takes it at the emulated device pixel ratio instead.
  const png = cdp
    ? Buffer.from((await cdp.send("Page.captureScreenshot", { format: "png" })).data, "base64")
    : await page.screenshot({ scale: "device" });
  const { width, height } = readPng(png);
  const dataUrl = `data:image/png;base64,${png.toString("base64")}`;
  const w = await ext.worker();
  await w.evaluate((u) => {
    (chrome.tabs as unknown as { captureVisibleTab: () => Promise<string> }).captureVisibleTab = async () => u;
  }, dataUrl);
  return { width, height };
}

/** `storage.local` and `storage.session` of the extension, as one JSON text. */
export async function storageDump(ext: Ext): Promise<string> {
  const w = await ext.worker();
  return w.evaluate(async () => JSON.stringify({ local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) }));
}

// ---- e2e build: the worker's host session ----

type E2EHandle = { session: { request(r: unknown): Promise<unknown> } };

/** A request straight to the host over the worker's session: `{ok}` or `{err: code}`. */
export async function hostRequest(w: Worker, req: Record<string, unknown>): Promise<{ ok?: unknown; err?: string }> {
  return w.evaluate(async (req) => {
    const h = (globalThis as { __onepassE2E?: E2EHandle }).__onepassE2E;
    if (!h) throw new Error("not an e2e build");
    try {
      return { ok: await h.session.request(req) };
    } catch (e) {
      return { err: (e as { code?: string }).code ?? String(e) };
    }
  }, req);
}

export async function itemId(w: Worker, title: string, origin = ATLAS): Promise<string> {
  const r = await hostRequest(w, { op: "list_for_origin", ctx: "menu", origin });
  const items = (r.ok as { items: { item_id: string; title: string }[] }).items;
  const it = items.find((x) => x.title === title);
  if (!it) throw new Error(`no item ${title} for ${origin}`);
  return it.item_id;
}

/** Whether the item has the field `field` (a field the extension may not read answers `not_allowed`). */
export async function hasField(w: Worker, item: string, field: string): Promise<boolean> {
  const r = await hostRequest(w, { op: "reveal", ctx: "popup", item_id: item, field });
  if (r.err === "not_found") return false;
  if (r.err === undefined || r.err === "not_allowed") return true;
  throw new Error(`reveal ${field}: ${r.err}`);
}

export interface SetupWrite {
  op: string;
  status?: string;
  err?: string;
  /** save_recovery_codes: how many codes were sent (never the codes). */
  count?: number;
}

/** Records every save_totp and save_recovery_codes the worker sends (op and answer, no value). */
export async function recordWrites(w: Worker): Promise<void> {
  await w.evaluate(() => {
    const g = globalThis as { __onepassE2E?: E2EHandle; __setupWrites?: unknown[] };
    const s = g.__onepassE2E?.session;
    if (!s) throw new Error("not an e2e build");
    const log: unknown[] = [];
    g.__setupWrites = log;
    const orig = s.request.bind(s);
    s.request = async (r: unknown) => {
      const op = (r as { op?: string }).op ?? "";
      const watched = op === "save_totp" || op === "save_recovery_codes";
      const count = op === "save_recovery_codes" ? String((r as { codes?: unknown }).codes ?? "").split("\n").length : undefined;
      try {
        const out = await orig(r);
        if (watched) log.push({ op, status: (out as { status?: string } | null)?.status ?? "ok", ...(count !== undefined ? { count } : {}) });
        return out;
      } catch (e) {
        if (watched) log.push({ op, err: (e as { code?: string }).code ?? "error" });
        throw e;
      }
    };
  });
}

export function writes(w: Worker): Promise<SetupWrite[]> {
  return w.evaluate(() => ((globalThis as { __setupWrites?: unknown[] }).__setupWrites ?? []) as never);
}
