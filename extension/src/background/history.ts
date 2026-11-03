// Autofill history (2026-11-03): what the user chose in which browser
// profile, so the app ranks that profile's account first next time.
//
// The extension only reports; the app keeps the events in the vault
// database of this device, sealed, never synced, never sent anywhere
// (onepass_core::autofill_history), and the user turns it off there.
//
// - `client_info`, once per bridge session: the browser kind and an opaque
//   profile id drawn here once and kept in this profile's own extension
//   storage (`storage.local` is per browser profile). No profile name: no
//   browser gives it to an extension without an extra permission.
// - `note_autofill`: a list shown (ids, best first), a pick and its rank,
//   the first offer passed over, a list closed without a choice, a fill.
//
// Never a value: item ids, the frame's origin and a rank. Every failure is
// swallowed (an older app refuses both ops): a fill never waits on this.
import type { ClientInfoRequest, NoteAutofillRequest } from "../shared/messages";
import type { StorageArea } from "./ext";
import type { BridgeLike, Session } from "./session";

export type BrowserKind = ClientInfoRequest["browser"];

/** Contexts the app takes events from. */
export type HistoryCtx = NoteAutofillRequest["ctx"];

/** `storage.local` key of this profile's opaque id. */
export const PROFILE_KEY = "historyProfileId";
/** Most ids a `shown` event lists (the app's MAX_SHOWN). */
export const MAX_SHOWN = 8;

/** What the page's globals say about the browser (navigator, or a test double). */
export interface BrowserHints {
  userAgent: string;
  /** Brave's `navigator.brave`. */
  brave?: unknown;
  /** `navigator.userAgentData.brands`, where the browser has it. */
  brands?: readonly { brand: string }[];
}

/** The browser kind, from the most specific hint to the least. */
export function browserKind(h: BrowserHints): BrowserKind {
  const brands = (h.brands ?? []).map((b) => b.brand.toLowerCase());
  const ua = h.userAgent;
  if (h.brave !== undefined && h.brave !== null) return "brave";
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Edg\//.test(ua) || brands.includes("microsoft edge")) return "edge";
  if (/OPR\//.test(ua) || brands.includes("opera")) return "opera";
  if (/Vivaldi\//.test(ua)) return "vivaldi";
  if (brands.includes("arc")) return "arc";
  if (/Chrome\//.test(ua) || brands.includes("google chrome")) return "chrome";
  if (/Safari\//.test(ua)) return "safari";
  if (/Chromium\//.test(ua) || brands.includes("chromium")) return "chromium";
  return "unknown";
}

export interface HistoryDeps {
  session: Pick<Session, "getClient" | "request">;
  /** This browser profile's extension storage (`storage.local`). */
  area: StorageArea;
  browser: BrowserKind;
  /** Draws the profile id; `crypto.randomUUID` by default. */
  newId?: () => string;
}

interface Listed {
  origin: string;
  ctx: HistoryCtx;
  shown: string[];
}

export class AutofillHistory {
  /** Clients told `client_info` (a reconnect is told again). */
  private readonly told = new WeakSet<BridgeLike>();
  /** Lists shown and not yet closed, by surface key (a menu token, `popup`). */
  private readonly lists = new Map<string, Listed>();
  private profile: Promise<string> | undefined;

  constructor(private readonly deps: HistoryDeps) {}

  /** This profile's opaque id: drawn once, kept in its own storage. */
  profileId(): Promise<string> {
    this.profile ??= this.loadProfileId().catch((e: unknown) => {
      this.profile = undefined;
      throw e;
    });
    return this.profile;
  }

  private async loadProfileId(): Promise<string> {
    const raw = (await this.deps.area.get(PROFILE_KEY))[PROFILE_KEY];
    if (typeof raw === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(raw)) return raw;
    const id = (this.deps.newId ?? (() => crypto.randomUUID()))();
    await this.deps.area.set({ [PROFILE_KEY]: id });
    return id;
  }

  /** Tell the session's client the browser and profile, once. Never throws. */
  async ensureClient(): Promise<void> {
    try {
      const client = await this.deps.session.getClient();
      if (this.told.has(client)) return;
      // Marked first: an older app refuses the op, and is asked once only.
      this.told.add(client);
      await client.request({ op: "client_info", browser: this.deps.browser, profile_id: await this.profileId() });
    } catch {
      // No history for this session: the ranking works without it.
    }
  }

  /** A list of suggestions shown on a surface (`key`), best first. */
  async shown(key: string, ctx: HistoryCtx, origin: string, ids: readonly string[]): Promise<void> {
    const shown = ids.slice(0, MAX_SHOWN);
    this.lists.set(key, { origin, ctx, shown });
    if (shown.length > 0) await this.note({ ctx, origin, action: "shown", shown });
  }

  /** The user chose `itemId` on the surface `key` (the list closes with it). */
  async picked(key: string, itemId: string): Promise<void> {
    const l = this.lists.get(key);
    if (!l) return;
    this.lists.delete(key);
    const i = l.shown.indexOf(itemId);
    const rank = i >= 0 ? i : undefined;
    await this.note({ ctx: l.ctx, origin: l.origin, action: "picked", item_id: itemId, ...(rank !== undefined ? { rank } : {}) });
    const first = l.shown[0];
    if (first !== undefined && first !== itemId) {
      await this.note({ ctx: l.ctx, origin: l.origin, action: "picked_other", item_id: first, rank: 0 });
    }
  }

  /** `itemId` was written into a page of `origin`. */
  async filled(ctx: HistoryCtx, origin: string, itemId: string): Promise<void> {
    await this.note({ ctx, origin, action: "filled", item_id: itemId });
  }

  /** The surface `key` closed without a choice: its first entry was not wanted. */
  async dismissed(key: string): Promise<void> {
    const l = this.lists.get(key);
    if (!l) return;
    this.lists.delete(key);
    const first = l.shown[0];
    if (first !== undefined) await this.note({ ctx: l.ctx, origin: l.origin, action: "dismissed", item_id: first, rank: 0 });
  }

  /** The surface `key` went away (a tab closed, a lock): nothing to say. */
  drop(key: string): void {
    this.lists.delete(key);
  }

  private async note(req: NoteAutofillRequest): Promise<void> {
    if (!req.origin.startsWith("https://")) return;
    try {
      await this.ensureClient();
      await this.deps.session.request({ op: "note_autofill", ...req });
    } catch {
      // A hint: an older app, a locked vault, history off. Never in the way.
    }
  }
}
