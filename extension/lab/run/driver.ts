// Autofill driver interface of the lab (spec 7.4): what a scenario asks of
// the autofill under test, whatever it is. The `extension` implementation
// drives the real OnePass extension through its frames (overlay, in-field
// menu) and its chain state; a `system_autofill` implementation (macOS, iOS)
// can plug in later without touching the scenarios in drive.ts.
import type { Frame, Page } from "@playwright/test";
import { GUARD_WAIT_MS, type Lab, sleep } from "./browser.ts";

/** The one-click sign-in UI shown on a page (the extension's overlay). */
export interface OneClickUi {
  /** Whether the account `title` is offered, within `timeoutMs`. */
  offers(title: string, timeoutMs?: number): Promise<boolean>;
  /** Whether this is the generic card of a locked vault: it names no account, its one button unlocks then signs in. */
  generic(): Promise<boolean>;
}

/** What the in-field menu did: shown at all, and whether it offered `title`. */
export interface MenuOutcome {
  shown: boolean;
  offered: boolean;
}

/** What the passkey ceremony showed the user (Driver.passkey). */
export interface PasskeyOutcome { asked: boolean; offered: boolean; picked: boolean }

export interface Driver {
  readonly kind: "extension" | "system_autofill";
  /** The one-click UI of the page once it shows (within `timeoutMs`; 0: only if already there). */
  openOneClick(page: Page, timeoutMs: number): Promise<OneClickUi | undefined>;
  /** Starts the sign-in with the account `title` of the one-click UI; `before` runs right before the click. */
  pickAccount(ui: OneClickUi, title: string, before?: () => Promise<void>): Promise<void>;
  /** Presses the one button of a generic card (locked vault); `before` runs right before the click. */
  pickGeneric(ui: OneClickUi, before?: () => Promise<void>): Promise<void>;
  /**
   * Starts the sign-in with the one other account `title`, shown under the first one when the site
   * has exactly two (one gesture); false when the UI shows no such row. `before` runs right before the click.
   */
  pickSecond(ui: OneClickUi, title: string, before?: () => Promise<void>): Promise<boolean>;
  /** Opens the one-click UI's list of the site's other accounts (one gesture); false when it has none. */
  openOthers(ui: OneClickUi): Promise<boolean>;
  /** Whether the opened list offers the account `title`. */
  otherOffers(ui: OneClickUi, title: string): Promise<boolean>;
  /** Starts the sign-in with the account `title` of the opened list. */
  pickOther(ui: OneClickUi, title: string): Promise<void>;
  /** Opens the in-field menu in the first of `selectors` that offers one and leaves it open (no pick). */
  menuOpen(page: Page, scope: Frame, selectors: string[], timeouts?: { first: number; next: number }): Promise<Frame | undefined>;
  /**
   * What a menu that cannot fill yet shows (locked vault, app not running): "waiting" (the unlock was
   * asked by the gesture that opened it; it goes on by itself) or "button" (the user must ask). Undefined: neither.
   */
  menuUnlockState(menu: Frame): Promise<"waiting" | "button" | undefined>;
  /** Presses the unlock (or open) button of such a menu. */
  menuUnlock(menu: Frame): Promise<void>;
  /** Whether `menu` lists any row now. */
  menuHasRows(menu: Frame): Promise<boolean>;
  /** Whether the lab can start smart fill by the keyboard command. */
  canShortcut(): Promise<boolean>;
  /** Smart fill started by the keyboard command (fill-smart) on `page`. */
  shortcut(page: Page): Promise<void>;
  /** Whether the autofill tells the user, on `page`, that it is locked. */
  lockedShown(page: Page): Promise<boolean>;
  /**
   * Opens the in-field menu in the first of `selectors` (in `scope`) that
   * offers one, as a user would (focus + trusted ArrowDown), and picks `title`
   * when `pick` is set; otherwise only looks and closes the menu.
   */
  menuFill(page: Page, scope: Frame, selectors: string[], title: string | undefined, pick: boolean,
    timeouts?: { first: number; next: number }): Promise<MenuOutcome>;
  /**
   * Smart fill as the user starts it (spec 8.2): a click on the OnePass icon
   * of `selector` in `scope`, or the toolbar Fill when the page has no field
   * to click (`selector` undefined). The plan then runs on its own.
   * `before` runs right before the click (a cold start stops the host there).
   */
  smartFill(page: Page, scope: Frame, selector: string | undefined, timeoutMs: number, before?: () => Promise<void>): Promise<void>;
  /** Progress of a sign-in started on `https://<site>`: its status, stop reason and start time, if any. */
  progress(site: string): Promise<{ status: string; reason?: string; startedAt?: number } | null>;
  /** The in-field menu of the page, if one shows now. */
  menuFrame(page: Page): Frame | undefined;
  /** Whether a menu shows on the page now. */
  menuShown(page: Page): Promise<boolean>;
  /** Whether `menu` offers `title` (within 5 s). */
  menuOffers(menu: Frame, title: string): Promise<boolean>;
  /** Picks the row `title` of `menu`. */
  menuPick(menu: Frame, title: string): Promise<void>;
  /**
   * The site's passkey ceremony as the user plays it: `press` (the site's own
   * passkey button), then, when the autofill asks, the account `user` in its
   * passkey window (one trusted click). `asked`: a window opened; `offered`:
   * it listed `user`; `picked`: the user chose it. No window is no gesture:
   * during the user's one-click sign-in the autofill may sign on its own.
   */
  passkey(press: () => Promise<void>, user: string, timeoutMs: number): Promise<PasskeyOutcome>;
  /** Whether the autofill told the user it refused for rate limiting. */
  rateLimited(page: Page): Promise<boolean>;
  /** LAB_DEBUG: the autofill's own state behind a scenario that did not go on (no secret). */
  debugState?(): Promise<string>;
}

const RATE_LIMITED_TEXT = "Trop de demandes";

class Overlay implements OneClickUi {
  constructor(readonly lab: Lab, readonly frame: Frame) {}
  offers(title: string, timeoutMs = 5_000): Promise<boolean> {
    return this.lab.overlayHas(this.frame, title, timeoutMs);
  }
  generic(): Promise<boolean> {
    return this.lab.overlayGeneric(this.frame);
  }
}

/** The real OnePass extension of a paired lab profile. */
export function extensionDriver(lab: Lab): Driver {
  return {
    kind: "extension",
    async openOneClick(page, timeoutMs) {
      const frame = timeoutMs > 0 ? await lab.waitExtFrame(page, "overlay", timeoutMs) : lab.findExtFrame(page, "overlay");
      return frame ? new Overlay(lab, frame) : undefined;
    },
    async pickAccount(ui, title, before) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      await lab.overlayStart(ui.frame, title, before);
    },
    async pickGeneric(ui, before) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      await lab.overlayStartGeneric(ui.frame, before);
    },
    async pickSecond(ui, title, before) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      return lab.overlayPickSecond(ui.frame, title, before);
    },
    async openOthers(ui) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      return lab.overlayOpenOthers(ui.frame);
    },
    async otherOffers(ui, title) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      return lab.overlayOtherHas(ui.frame, title);
    },
    async pickOther(ui, title) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      await lab.overlayPickOther(ui.frame, title);
    },
    async menuOpen(page, scope, selectors, timeouts = { first: 10_000, next: 3_000 }) {
      for (const [k, sel] of selectors.entries()) {
        const menu = await lab.openMenu(page, scope, sel, k === 0 ? timeouts.first : timeouts.next).catch(() => undefined);
        if (menu) return menu;
      }
      return undefined;
    },
    menuUnlockState: (menu) => lab.menuUnlockState(menu),
    menuUnlock: (menu) => lab.menuUnlock(menu),
    menuHasRows: (menu) => lab.menuHasRows(menu),
    canShortcut: () => lab.canShortcut(),
    shortcut: (page) => lab.shortcut(page),
    lockedShown: (page) => lab.lockedShown(page),
    async menuFill(page, scope, selectors, title, pick, timeouts = { first: 10_000, next: 3_000 }) {
      let menu: Frame | undefined;
      for (const [k, sel] of selectors.entries()) {
        // The first field waits for delayed fields; the next ones are already there.
        menu = await lab.openMenu(page, scope, sel, k === 0 ? timeouts.first : timeouts.next).catch(() => undefined);
        if (menu) break;
      }
      if (!menu) return { shown: false, offered: false };
      const offered = title !== undefined && (await lab.menuRow(menu, title, pick ? 5_000 : 2_000));
      if (offered && pick) {
        await lab.pickRow(menu, title);
        await sleep(1_500);
      } else {
        await page.keyboard.press("Escape");
      }
      return { shown: true, offered };
    },
    async smartFill(page, scope, selector, timeoutMs, before) {
      if (selector === undefined) await lab.toolbarFill(page, before);
      else await lab.clickIcon(page, scope, selector, timeoutMs, before);
    },
    async progress(site) {
      const c = await lab.chainState(site).catch(() => null);
      return c
        ? { status: c.status, ...(c.reason !== undefined ? { reason: c.reason } : {}), ...(c.startedAt !== undefined ? { startedAt: c.startedAt } : {}) }
        : null;
    },
    menuFrame(page) {
      return lab.findExtFrame(page, "menu");
    },
    async menuShown(page) {
      return lab.findExtFrame(page, "menu") !== undefined;
    },
    menuOffers(menu, title) {
      return lab.menuRow(menu, title, 5_000);
    },
    menuPick(menu, title) {
      return lab.pickRow(menu, title);
    },
    async passkey(press, user, timeoutMs) {
      const win = await lab.passkeyWindow(press, timeoutMs);
      if (!win) return { asked: false, offered: false, picked: false };
      await win.waitForLoadState("domcontentloaded").catch(() => undefined);
      const row = win.getByRole("button", { name: `Se connecter en tant que ${user}`, exact: true });
      const offered = await row.first().waitFor({ state: "visible", timeout: 5_000 }).then(() => true, () => false);
      if (!offered) {
        await win.getByRole("button", { name: "Annuler", exact: true }).click({ timeout: 2_000 }).catch(() => undefined);
        return { asked: true, offered: false, picked: false };
      }
      // The window's click guard (ui/passkey.ts) ignores a click right after it shows.
      await sleep(GUARD_WAIT_MS);
      const picked = await row.first().click({ timeout: 5_000 }).then(() => true, () => false);
      return { asked: true, offered: true, picked };
    },
    debugState: () => lab.debugState(),
    async rateLimited(page) {
      for (const f of page.frames()) {
        if (!f.url().startsWith("chrome-extension://")) continue;
        const text = await f.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
        if (text.includes(RATE_LIMITED_TEXT)) return true;
      }
      return false;
    },
  };
}
