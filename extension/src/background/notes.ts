// Site memory writes (`note_fill`, spec 7): what filled where, sent only
// after a fill that worked. The chain notes its own fill at `done`
// (chain/driver.ts); this module covers the two other signals:
//
// - a fill without a chain and without a submit (a plan's fill, or a pick
//   in the menu a plan opened), followed by a top-level navigation of the
//   same tab to another page of the same site within `NOTE_NAV_MS`: one note
//   per item of that fill, once. A commit of the filled page's own path (a
//   reload, a refused sign-in sent back with `?error=1`) is no success;
// - a save prompt confirmed (save or update) in a tab where such a fill
//   happened within `NOTE_SAVE_MS`: the saved login is noted with the roles
//   of that fill.
// One note per fill: a chain starting in the tab (it notes at `done`), a
// confirmed save, a closed tab or a new fill drop the tab's pending fill.
//
// Only roles, the intent, the steps and item ids are kept (memory only, per
// tab), never a value. A failing `note_fill` is swallowed: the memory is a
// hint, the fill itself already happened.
import type { FieldRole, FillIntent, FillStep, NoteFillRequest } from "../shared/messages";
import type { Session } from "./session";
import { siteOf } from "./penalty";

/** A navigation this soon after the fill counts as its success. */
export const NOTE_NAV_MS = 2 * 60 * 1000;
/** A save confirmed this soon after the fill notes the saved login. */
export const NOTE_SAVE_MS = 10 * 60 * 1000;

export interface FilledNote {
  /** Items written (login, card, identity), in plan order; no generated password. */
  items: string[];
  /** Roles of the planned form, in page order. */
  roles: FieldRole[];
  intent: FillIntent;
}

interface Pending extends FilledNote {
  origin: string;
  /** Path of the top document the fill happened in (query and hash ignored). */
  path: string;
  site: string;
  at: number;
  /** The navigation note went out (one per fill). */
  noted: boolean;
  timer: unknown;
}

export interface NoteTimers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
}

export interface FillNotesDeps {
  session: Pick<Session, "request">;
  now?: () => number;
  timers?: NoteTimers;
}

export class FillNotes {
  private readonly pending = new Map<number, Pending>();
  private readonly now: () => number;
  private readonly timers: NoteTimers;

  constructor(private readonly deps: FillNotesDeps) {
    this.now = deps.now ?? Date.now;
    this.timers = deps.timers ?? {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
    };
  }

  /**
   * A fill without a chain nor a submit in `tabId` at `origin`, whose top
   * document is at `topUrl` (null: unknown, no navigation note); replaces
   * the tab's previous one.
   */
  filled(tabId: number, origin: string, note: FilledNote, topUrl: string | null): void {
    const site = siteOf(origin);
    if (site === null) return;
    this.drop(tabId);
    const path = topUrl === null ? null : pathOf(topUrl);
    const p: Pending = {
      ...note,
      items: [...note.items],
      roles: [...note.roles],
      origin,
      path: path ?? "",
      site,
      at: this.now(),
      // Unknown page: never a navigation note (a save may still note).
      noted: path === null,
      timer: null,
    };
    p.timer = this.timers.setTimeout(() => {
      if (this.pending.get(tabId) === p) this.pending.delete(tabId);
    }, NOTE_SAVE_MS);
    this.pending.set(tabId, p);
  }

  /** The top frame of `tabId` committed `url`. */
  async onNavigation(tabId: number, url: string): Promise<void> {
    const p = this.pending.get(tabId);
    if (!p || p.noted) return;
    if (this.now() - p.at > NOTE_NAV_MS) return;
    if (siteOf(url) !== p.site || !url.startsWith("https://")) return;
    // The filled page again (reload, refused sign-in sent back): not a success, still waiting.
    if (pathOf(url) === p.path) return;
    p.noted = true;
    for (const item of p.items) await this.note("menu", item, p.origin, p.roles, p.intent, ["fill"]);
  }

  /** A save prompt of `tabId` saved or updated `itemId` for `origin`. */
  async onSaved(tabId: number, origin: string, itemId: string): Promise<void> {
    const p = this.pending.get(tabId);
    if (!p || this.now() - p.at > NOTE_SAVE_MS || siteOf(origin) !== p.site) return;
    // One note per fill: the save takes it.
    this.drop(tabId);
    await this.note("save_prompt", itemId, origin, p.roles, p.intent, ["fill"]);
  }

  onTabRemoved(tabId: number): void {
    this.drop(tabId);
  }

  /** A chain started (or ended) in `tabId`: it notes its own fill, the pending one goes. */
  forget(tabId: number): void {
    this.drop(tabId);
  }

  /** For tests: tabs with a fill waiting. */
  get size(): number {
    return this.pending.size;
  }

  private drop(tabId: number): void {
    const p = this.pending.get(tabId);
    if (!p) return;
    this.timers.clearTimeout(p.timer);
    this.pending.delete(tabId);
  }

  private async note(ctx: NoteFillRequest["ctx"], itemId: string, origin: string, roles: FieldRole[], intent: FillIntent, steps: FillStep[]): Promise<void> {
    await noteFill(this.deps.session, { ctx, item_id: itemId, origin, roles, intent, steps });
  }
}

function pathOf(url: string): string | null {
  try {
    return new URL(url).pathname;
  } catch {
    return null;
  }
}

/** `note_fill`, its failure swallowed (never breaks a fill, never logged: no value in it anyway). */
export async function noteFill(session: Pick<Session, "request">, req: NoteFillRequest): Promise<boolean> {
  try {
    await session.request({ op: "note_fill", ...req });
    return true;
  } catch {
    return false;
  }
}
