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
  /** Starts the sign-in with the account `title` of the one-click UI. */
  pickAccount(ui: OneClickUi, title: string): Promise<void>;
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
   */
  smartFill(page: Page, scope: Frame, selector: string | undefined, timeoutMs: number): Promise<void>;
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
}

const RATE_LIMITED_TEXT = "Trop de demandes";

class Overlay implements OneClickUi {
  constructor(readonly lab: Lab, readonly frame: Frame) {}
  offers(title: string, timeoutMs = 5_000): Promise<boolean> {
    return this.lab.overlayHas(this.frame, title, timeoutMs);
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
    async pickAccount(ui, title) {
      if (!(ui instanceof Overlay)) throw new Error("lab: not an extension overlay");
      await lab.overlayStart(ui.frame, title);
    },
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
    async smartFill(page, scope, selector, timeoutMs) {
      if (selector === undefined) await lab.toolbarFill(page);
      else await lab.clickIcon(page, scope, selector, timeoutMs);
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
