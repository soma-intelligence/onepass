// Autofill driver interface of the lab (spec 7.4): what a scenario asks of
// the autofill under test, whatever it is. The `extension` implementation
// drives the real OnePass extension through its frames (overlay, in-field
// menu) and its chain state; a `system_autofill` implementation (macOS, iOS)
// can plug in later without touching the scenarios in drive.ts.
import type { Frame, Page } from "@playwright/test";
import { type Lab, sleep } from "./browser.ts";

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
  /** Progress of a sign-in started on `https://<site>`: its status and stop reason, if any. */
  progress(site: string): Promise<{ status: string; reason?: string } | null>;
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
    async progress(site) {
      const c = await lab.chainState(site).catch(() => null);
      return c ? { status: c.status, ...(c.reason !== undefined ? { reason: c.reason } : {}) } : null;
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
