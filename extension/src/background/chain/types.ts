// The surface of the sign-in chain (spec 8.6) used by the menu and the
// overlay. `ChainRunner` (driver.ts) implements it; `idleChainDriver` starts
// nothing (tests of the pages that do not need a chain).
import type { ProviderId } from "../../shared/messages";
import type { ChainView } from "../../shared/ui";

export type { ChainView };

export interface StartOptions {
  /** The provider account picked by the user (one the page offered); else the default. */
  accountId?: string;
  /** Field of the top frame the user clicked from: the progress shows there. */
  anchorRef?: string;
}

export interface ChainDriver {
  /** Start a chain in the top frame of `tabId`, after a click in an extension page. */
  start(tabId: number, itemId: string, viaProvider?: ProviderId, opts?: StartOptions): Promise<void>;
  /** The user pressed "Arrêter" (reason `user`). */
  stop(tabId: number): Promise<void>;
  /**
   * What the overlay shows; null when no chain ran in this tab. `opening`:
   * for an overlay that just opened, where a chain that ended a while ago
   * gives way to the offer of the page.
   */
  state(tabId: number, opening?: boolean): Promise<ChainView | null>;
  /** The user closed the overlay of this top document: not offered again there. */
  closed?(tabId: number, origin: string, documentId?: string): Promise<void>;
}

/** No chain support: start and stop do nothing, no state. */
export const idleChainDriver: ChainDriver = {
  start: async () => undefined,
  stop: async () => undefined,
  state: async () => null,
};
