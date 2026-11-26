// The sign-in pill that appears by itself (2026-11-12): once the top page of a tab is ready and
// reads as a sign-in or a signup, the top-centre card of overlay.ts shows without a gesture.
// Appearing fills nothing, submits nothing and starts nothing: only a trusted click inside the
// card (an extension-origin frame behind the click guard) does, through the card's own paths.
//
// Faces, top frame only:
// - "signin": a login form, the vault open, at least one login for the site (the card's pill);
// - "generic": a login form, the vault locked (the card that unlocks, then resumes the page);
// - "signup": a signup form, the vault open ("Create with Cleon").
// Nothing on a login page with nothing saved, nor with no app.
//
// Never when: the page carries a sign-out control (a session is open there), a sign-in of ours
// succeeded on the site in this browser session and the form asks no password (a lone e-mail
// step, a newsletter box read as one), the setting is off, the site is in the never-list, the page is not https, the
// window is private, a chain runs in the tab or another of our surfaces is there, a field of the
// form already holds a value, or the pill already showed for this site in this tab (kept in
// `storage.session` across a worker restart: a reload does not bring it back, another site in
// the tab may show it; a tab that replaces another carries what that one showed).
import { parseOrigin } from "../shared/domain";
import { addNever, readAutoPill } from "../shared/auto-pill";
import type { StorageArea } from "./ext";
import type { CsContext } from "./frames";

/** `storage.session`: the `tab|site` pairs the pill showed for (a worker stopped by the browser keeps them). */
export const AUTO_PILL_SHOWN_KEY = "auto_pill_shown";
/** `storage.session`: the sites a chain signed in to (`done`), for the rest of the browser session. */
export const AUTO_PILL_SIGNED_IN_KEY = "auto_pill_signed_in";
/** Pairs kept at most (oldest dropped). */
const MAX_SHOWN = 500;

export type AutoFace = "signin" | "generic" | "signup";
/** What the vault answers without a gesture: open, locked, or no app to ask. */
export type AutoVault = "open" | "locked" | "missing";

/** What the top frame's last analysis recognised: refs of its login and signup forms. */
export interface AutoPage {
  origin: string;
  documentId?: string;
  login: string[];
  signup: string[];
  /** The page carries a sign-out control: someone is signed in there. */
  signedIn?: boolean;
  /** A login form of the page asks a password (not a lone identifier step). */
  password?: boolean;
}

export interface AutoPillDeps {
  local: StorageArea;
  /** `storage.session`, where the sites shown live across a worker restart; absent: memory only. */
  session?: StorageArea;
  topFrame(tabId: number): Promise<{ url: string; documentId?: string } | null>;
  incognito(tabId: number): Promise<boolean>;
  /**
   * The browser says the tab finished loading (`tabs.get(...).status === "complete"`). Asked when
   * an analysis comes for a tab this worker never saw load: the browser stops an idle worker
   * (Safari and Chrome, about 30 s), and a form shown later (a login modal, an SPA route) wakes a
   * new one whose `ready` is empty. Absent: such an analysis waits for the next load.
   */
  loaded?(tabId: number): Promise<boolean>;
  /** A chain runs in the tab, or the card, a menu or a save prompt is already there. */
  busy(tabId: number): Promise<boolean>;
  page(tabId: number): Promise<AutoPage | null>;
  /** A field of these forms of top document `cs` holds a value (typed, or filled). */
  prefilled(cs: CsContext, formRefs: string[]): Promise<boolean>;
  vault(): Promise<AutoVault>;
  /** The logins the card would offer in top document `cs`. */
  logins(cs: CsContext): Promise<number>;
  /** Shows the card; throws when it could not be shown. */
  open(cs: CsContext, face: AutoFace): Promise<void>;
}

export class AutoPill {
  /** Tabs whose top document finished loading (cleared when a new one commits). */
  private readonly ready = new Set<number>();
  /** `tab|site` where the pill already showed (mirrored in `storage.session`). */
  private readonly shown = new Set<string>();
  /** Writes of the mirror, one after the other. */
  private writes: Promise<void> = Promise.resolve();
  /** Sites a chain signed in to (mirrored in `storage.session`). */
  private readonly signedInSites = new Set<string>();
  /** Per tab: a look under way, and whether another trigger came meanwhile. */
  private readonly looking = new Map<number, { again: boolean; done: Promise<void> }>();

  constructor(private readonly deps: AutoPillDeps) {}

  /** `webNavigation.onCompleted` of the top frame. */
  onReady(tabId: number): Promise<void> {
    this.ready.add(tabId);
    return this.consider(tabId);
  }

  /** A page analysis: of the top frame of a ready page, a form may have shown up. */
  async onAnalysis(tabId: number, frameId: number): Promise<void> {
    if (frameId !== 0) return;
    if (!this.ready.has(tabId)) {
      // A worker started after the load: the browser knows whether the page is loaded.
      const loaded = await this.deps.loaded?.(tabId).catch(() => false);
      if (!loaded) return;
      this.ready.add(tabId);
    }
    return this.consider(tabId);
  }

  /** A new top document: not ready until it loads. The sites shown stay. */
  onCommitted(tabId: number): void {
    this.ready.delete(tabId);
  }

  onTabRemoved(tabId: number): Promise<void> {
    this.ready.delete(tabId);
    for (const k of this.shown) if (k.startsWith(`${tabId}|`)) this.shown.delete(k);
    return this.edit((list) => list.filter((k) => !k.startsWith(`${tabId}|`)));
  }

  /** `tabs.onReplaced`: the tab that took another's place (prerender) keeps what that one showed. */
  onReplaced(added: number, removed: number): Promise<void> {
    if (this.ready.delete(removed)) this.ready.add(added);
    const move = (k: string) => (k.startsWith(`${removed}|`) ? `${added}|${k.slice(`${removed}|`.length)}` : k);
    for (const k of [...this.shown]) {
      if (!k.startsWith(`${removed}|`)) continue;
      this.shown.delete(k);
      this.shown.add(move(k));
    }
    return this.edit((list) => [...new Set(list.map(move))]);
  }

  private async stored(): Promise<string[]> {
    if (!this.deps.session) return [];
    const raw = (await this.deps.session.get(AUTO_PILL_SHOWN_KEY))[AUTO_PILL_SHOWN_KEY];
    return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : [];
  }

  /** Changes the mirror in `storage.session` (nothing without one); serialized. */
  private edit(fn: (list: string[]) => string[]): Promise<void> {
    const session = this.deps.session;
    if (!session) return Promise.resolve();
    this.writes = this.writes.then(async () => {
      await session.set({ [AUTO_PILL_SHOWN_KEY]: fn(await this.stored()).slice(-MAX_SHOWN) });
    }).catch(() => undefined);
    return this.writes;
  }

  private async wasShown(key: string): Promise<boolean> {
    if (this.shown.has(key)) return true;
    await this.writes;
    try {
      return (await this.stored()).includes(key);
    } catch {
      return false;
    }
  }

  /** A chain ended `done` on `site`: signed in there, the card stops offering itself on a lone identifier step. */
  async signedIn(site: string): Promise<void> {
    this.signedInSites.add(site);
    const session = this.deps.session;
    if (!session) return;
    this.writes = this.writes.then(async () => {
      const raw = (await session.get(AUTO_PILL_SIGNED_IN_KEY))[AUTO_PILL_SIGNED_IN_KEY];
      const list = Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string" && x !== site) : [];
      await session.set({ [AUTO_PILL_SIGNED_IN_KEY]: [...list, site].slice(-MAX_SHOWN) });
    }).catch(() => undefined);
    return this.writes;
  }

  private async wasSignedIn(site: string): Promise<boolean> {
    if (this.signedInSites.has(site)) return true;
    if (!this.deps.session) return false;
    await this.writes;
    try {
      const raw = (await this.deps.session.get(AUTO_PILL_SIGNED_IN_KEY))[AUTO_PILL_SIGNED_IN_KEY];
      return Array.isArray(raw) && raw.includes(site);
    } catch {
      return false;
    }
  }

  /**
   * The chain's own offer of the card (driver.ts `offerOverlay`) goes through this gate: nothing on
   * a signed-in page, with the setting off, on a never-listed site, or where a card already showed
   * for this site in this tab (closed with x included, across a reload).
   */
  async mayOffer(tabId: number, origin: string, signedIn: boolean): Promise<boolean> {
    if (signedIn) return false;
    const site = parseOrigin(origin)?.site;
    if (!site) return true;
    if (await this.wasShown(`${tabId}|${site}`)) return false;
    const settings = await readAutoPill(this.deps.local);
    return settings.enabled && !settings.never.includes(site);
  }

  /** The chain's offer showed the card: the same as one shown by itself, for this site and tab. */
  async offered(tabId: number, origin: string): Promise<void> {
    const site = parseOrigin(origin)?.site;
    if (!site) return;
    const key = `${tabId}|${site}`;
    this.shown.add(key);
    await this.edit((list) => (list.includes(key) ? list : [...list, key]));
  }

  /** "Never on this site", for the registrable domain of `origin`. */
  async never(origin: string): Promise<void> {
    const site = parseOrigin(origin)?.site;
    if (site) await addNever(this.deps.local, site);
  }

  private consider(tabId: number): Promise<void> {
    const cur = this.looking.get(tabId);
    if (cur) {
      // One look at a time per tab; a trigger meanwhile looks once more after it.
      cur.again = true;
      return cur.done;
    }
    const entry = { again: false, done: Promise.resolve() };
    entry.done = (async () => {
      try {
        do {
          entry.again = false;
          await this.look(tabId).catch(() => undefined);
        } while (entry.again);
      } finally {
        this.looking.delete(tabId);
      }
    })();
    this.looking.set(tabId, entry);
    return entry.done;
  }

  private async look(tabId: number): Promise<void> {
    if (!this.ready.has(tabId)) return;
    const f = await this.deps.topFrame(tabId);
    const o = f ? parseOrigin(f.url) : null;
    if (!f || !o?.page || !o.https) return;
    const key = `${tabId}|${o.site}`;
    if (await this.wasShown(key)) return;
    const settings = await readAutoPill(this.deps.local);
    if (!settings.enabled || settings.never.includes(o.site)) return;
    if (await this.deps.incognito(tabId)) return;
    if (await this.deps.busy(tabId)) return;
    const p = await this.deps.page(tabId);
    if (!p || p.origin !== o.origin) return;
    if (p.documentId !== undefined && f.documentId !== undefined && p.documentId !== f.documentId) return;
    const kind = p.login.length > 0 ? "login" : p.signup.length > 0 ? "signup" : null;
    if (!kind) return;
    // A signed-in page (a sign-out control) offers nothing; nor, after our sign-in on the site, a
    // login form that asks no password (the session is open, the e-mail box is something else).
    if (p.signedIn === true) return;
    if (kind === "login" && p.password !== true && (await this.wasSignedIn(o.site))) return;
    const cs: CsContext = { tabId, frameId: 0, origin: o.origin, ...(f.documentId !== undefined ? { documentId: f.documentId } : {}) };
    if (await this.deps.prefilled(cs, kind === "login" ? p.login : p.signup)) return;
    const vault = await this.deps.vault();
    let face: AutoFace | null = null;
    if (kind === "login" && vault === "locked") face = "generic";
    else if (kind === "login" && vault === "open" && (await this.deps.logins(cs)) > 0) face = "signin";
    else if (kind === "signup" && vault === "open") face = "signup";
    if (!face) return;
    // The trigger may have gone stale while the vault answered: the same document, still idle.
    if (!this.ready.has(tabId) || (await this.wasShown(key)) || (await this.deps.busy(tabId))) return;
    // The tab may have moved meanwhile (another site, another document): the top frame again,
    // the same origin, and the same document where the browser names it.
    const now = await this.deps.topFrame(tabId);
    if (!now || parseOrigin(now.url)?.origin !== o.origin || now.documentId !== f.documentId) return;
    // The user may have typed in the form meanwhile: its values are looked at again.
    if (await this.deps.prefilled(cs, kind === "login" ? p.login : p.signup)) return;
    this.shown.add(key);
    try {
      await this.deps.open(cs, face);
    } catch {
      // Not shown (the page went away): it may show on this site later.
      this.shown.delete(key);
      return;
    }
    await this.edit((list) => (list.includes(key) ? list : [...list, key]));
  }
}
