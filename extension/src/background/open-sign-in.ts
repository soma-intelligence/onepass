// Open and sign in (spec docs/superpowers/specs/2026-11-04-open-and-sign-in-design.md).
//
// The user tapped a login's website in the OnePass app ("Ouvrir et se connecter"): the app
// recorded a single-use pending sign-in (item id and site, 60 s, never a secret) where the bridge
// host reads it, then opened the page. Here, when a top frame loads an https page that shows a
// sign-in form, the service worker asks the host to take it (`take_sign_in`, origin and top origin
// from `sender`, both the same https origin), and on an item id starts the one-click sign-in chain
// (chain/driver.ts): the identifier, the password and the one-time code on the following pages,
// each value fetched just in time by `fill_login` (which redoes the item's own match rule), each
// step submitted, captcha and refused password stop it, all within the chain's 60 s.
//
// Nothing happens on a page the user did not open this way: without a pending entry the host
// answers `item_id: null`, and a normal page load never submits anything. One question per top
// document; a frame never asks.
import type { FormInfo, PageAnalysis } from "../shared/messages";
import { parseOrigin } from "../shared/domain";
import type { ChainDriver } from "./chain/types";
import type { CsContext, Frames } from "./frames";
import type { Session } from "./session";

const SIGN_IN_ROLES = new Set(["username", "email", "current_password"]);

/** A sign-in form (the chain's first step needs one). */
function isSignInForm(f: FormInfo): boolean {
  return f.kind === "login" && f.fields.some((x) => SIGN_IN_ROLES.has(x.role));
}

/** Most top documents remembered per tab as asked already. */
const MAX_ASKED = 16;

export interface OpenSignInDeps {
  session: Pick<Session, "request">;
  chain: Pick<ChainDriver, "start">;
  /** A sign-in chain runs in this tab: it is not interrupted. */
  chainRunning: (tabId: number) => Promise<boolean>;
  frames: Pick<Frames, "frameOrigin">;
  /**
   * Make the vault usable for the sign-in the user asked for: Face ID in the Safari extension on
   * iPhone, the app's unlock elsewhere. True once unlocked.
   */
  unlock: (tabId: number) => Promise<boolean>;
}

export class OpenSignIn {
  /** Per tab: the top documents (document id, else origin) already asked about. */
  private readonly asked = new Map<number, string[]>();

  constructor(private readonly deps: OpenSignInDeps) {}

  forgetTab(tabId: number): void {
    this.asked.delete(tabId);
  }

  /** An analysis of a frame; resolves with the item a chain started with, or null. */
  async onAnalysis(a: PageAnalysis, cs: CsContext): Promise<string | null> {
    if (cs.frameId !== 0) return null;
    const page = parseOrigin(cs.origin);
    if (page?.https !== true) return null;
    if (!a.forms.some(isSignInForm)) return null;
    const key = cs.documentId ?? `${cs.origin}|${a.url}`;
    const seen = this.asked.get(cs.tabId) ?? [];
    if (seen.includes(key)) return null;
    seen.push(key);
    if (seen.length > MAX_ASKED) seen.shift();
    this.asked.set(cs.tabId, seen);
    if (await this.deps.chainRunning(cs.tabId)) return null;
    // The origin from the browser, read again: the frame must still be the tab's top document.
    const top = await this.deps.frames.frameOrigin(cs.tabId, 0);
    if (top === null || top !== page.origin) return null;
    let itemId: string | null;
    try {
      ({ item_id: itemId } = await this.deps.session.request({ op: "take_sign_in", origin: page.origin, top_origin: top }));
    } catch {
      // Not paired, app unreachable, or a host that predates the operation: nothing to do.
      return null;
    }
    if (typeof itemId !== "string" || itemId === "") return null;
    try {
      const { locked } = await this.deps.session.request({ op: "status" });
      if (locked && !(await this.deps.unlock(cs.tabId))) return null;
      await this.deps.chain.start(cs.tabId, itemId);
    } catch {
      // Locked after all, the item no longer matches this page, the tab moved: stop, no retry.
      return null;
    }
    return itemId;
  }
}
