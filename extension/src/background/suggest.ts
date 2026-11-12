// Suggested passwords held by the worker (spec 3.2, 3.5): a password
// generated for a new-password field waits here, under a fresh token, until
// the user accepts it (the ghost's Tab or pill, the menu's "Use"), dismisses
// it, or the page goes. Only the ghost page and the menu page of the same tab
// may read it (`peek`); the page itself never sees it before acceptance. It
// lives in this worker's memory only: never in a storage area, never logged.
// A worker restart loses it, and the field gets a new one on its next focus.
//
// Acceptance fills the new and confirm fields as the menu's generate does,
// remembers the password for the submission, and saves it at once: a signup
// as a pending Login (`savePending`), a change-password form as an update of
// the login being changed (`savePendingUpdate`, spec 5.2).
import type { GenerationReport } from "../bridge/client";
import type { FormKind, FrameKind, GhostMetrics, SuggestionPreview } from "../shared/messages";
import { newToken } from "../shared/tokens";
import { CUSTOM_MAX_LENGTH, CUSTOM_MIN_LENGTH, GENERATOR_PROFILE_KEY, type GeneratorProfile, parseGeneratorProfile } from "../shared/ui";
import type { SaveFlow } from "./chain/save-flow";
import type { StorageArea } from "./ext";
import type { FillTarget, Filler } from "./fill";
import type { UiContext } from "./frames";
import type { FormGenerator } from "./generate";

/** A held suggestion dies this long after its last draw. */
export const SUGGESTION_TTL_MS = 10 * 60 * 1000;
/** Held suggestions per tab (one per field); the oldest goes first. */
const MAX_PER_TAB = 8;

/** The frames that may read a held suggestion: the ghost over the field and the menu's preview row. */
const PEEK_FRAMES: readonly FrameKind[] = ["ghost", "menu"];
const PEEK_PAGES: ReadonlySet<string> = new Set(PEEK_FRAMES.map((k) => `${k}.html`));

export interface SuggestionDeps {
  generator: Pick<FormGenerator, "generateForForm">;
  filler: Pick<Filler, "fillGenerated">;
  saveFlow: Pick<SaveFlow, "rememberGenerated" | "savePending" | "savePendingUpdate">;
  /** `storage.local`: the generator profile the popup edits. */
  area: Pick<StorageArea, "get" | "set">;
  now?: () => number;
}

/** Where a suggestion is for: its frame, field and form kind (no secret). */
export interface SuggestionRecord {
  tabId: number;
  frameId: number;
  origin: string;
  formKind: FormKind;
  documentId?: string;
  /** The field the ghost or menu is anchored to; one suggestion per tab and field. */
  fieldRef?: string;
  /** The field's metrics for the ghost (absent for a menu). */
  metrics?: GhostMetrics;
}

interface Held {
  rec: SuggestionRecord;
  target: FillTarget;
  password: string;
  report: GenerationReport | null;
  at: number;
}

/** The four-segment strength of a generated password: the report's entropy, else an estimate. */
export function strengthOf(report: GenerationReport | null, password: string): SuggestionPreview["strength"] {
  let bits: number;
  if (report && typeof report.entropy_bits === "number" && Number.isFinite(report.entropy_bits)) bits = report.entropy_bits;
  else {
    if (password === "") return 0;
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    bits = [...password].length * Math.log2(Math.max(pool, 2));
  }
  // The popup's bands (popup.ts strengthText): weak, fair, strong, very strong.
  if (bits <= 0) return 0;
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

export class Suggestions {
  private readonly held = new Map<string, Held>();
  private readonly now: () => number;

  constructor(private readonly deps: SuggestionDeps) {
    this.now = deps.now ?? Date.now;
  }

  /**
   * Generate a password for the new-password fields of `t` and hold it under a new token. A
   * new open for the same tab and field replaces the one before. Null when the page refuses
   * every draw (its `pattern`).
   */
  async open(t: FillTarget, rec: SuggestionRecord): Promise<{ token: string } | null> {
    const g = await this.deps.generator.generateForForm(t, "menu");
    if (g === null) return null;
    for (const [k, h] of this.held) {
      const sameField = h.rec.tabId === rec.tabId && h.rec.frameId === rec.frameId && h.rec.fieldRef === rec.fieldRef;
      if (sameField || this.expired(h)) this.forget(k);
    }
    const mine = [...this.held].filter(([, h]) => h.rec.tabId === rec.tabId);
    for (const [k] of mine.slice(0, Math.max(0, mine.length - MAX_PER_TAB + 1))) this.forget(k);
    const token = newToken();
    this.held.set(token, { rec: { ...rec }, target: { ...t }, password: g.password, report: g.report, at: this.now() });
    return { token };
  }

  /** The held password of `token`, only to the ghost or menu page of its own tab; null otherwise. */
  peek(token: string, from: UiContext): { password: string; report: GenerationReport | null } | null {
    const h = this.live(token);
    if (!h || !PEEK_PAGES.has(from.page) || from.tabId === undefined || from.tabId !== h.rec.tabId) return null;
    return { password: h.password, report: h.report };
  }

  /** What the ghost or the menu shows of `token` (same sender rule as `peek`). */
  preview(token: string, from: UiContext): SuggestionPreview | null {
    const p = this.peek(token, from);
    if (!p) return null;
    return { password: p.password, strength: strengthOf(p.report, p.password), length: [...p.password].length };
  }

  /**
   * The custom profile the menu's length panel starts from: the stored one, else the popup's
   * defaults (20 characters, symbols on).
   */
  async storedProfile(): Promise<{ length: number; symbols: boolean }> {
    const p = parseGeneratorProfile((await this.deps.area.get(GENERATOR_PROFILE_KEY))[GENERATOR_PROFILE_KEY]);
    return typeof p === "object" ? { length: p.length, symbols: p.symbols } : { length: 20, symbols: true };
  }

  /** The field metrics the ghost of `token` was opened with. */
  metrics(token: string): GhostMetrics | null {
    return this.live(token)?.rec.metrics ?? null;
  }

  /** The record of a live suggestion and its form (no password). */
  recordOf(token: string): (SuggestionRecord & { formRef: string }) | null {
    const h = this.live(token);
    return h ? { ...h.rec, formRef: h.target.formRef } : null;
  }

  /** The latest live suggestion of a frame (and document), for the keys of its field. */
  forFrame(tabId: number, frameId: number, documentId?: string): string | null {
    let best: [string, number] | null = null;
    for (const [k, h] of this.held) {
      if (this.expired(h) || h.rec.tabId !== tabId || h.rec.frameId !== frameId) continue;
      if (documentId !== undefined && h.rec.documentId !== undefined && h.rec.documentId !== documentId) continue;
      if (!best || h.at >= best[1]) best = [k, h.at];
    }
    return best ? best[0] : null;
  }

  /** A new draw for `token` ("Other suggestion"); false when gone or when the page refused every draw. */
  async regenerate(token: string): Promise<boolean> {
    const h = this.live(token);
    if (!h) return false;
    const g = await this.deps.generator.generateForForm(h.target, "menu");
    // Forgotten meanwhile (navigation, lock): the draw is dropped.
    if (g === null || this.held.get(token) !== h) return false;
    h.password = g.password;
    h.report = g.report;
    h.at = this.now();
    return true;
  }

  /**
   * "Length and characters": the custom profile the popup edits, then a new draw with it. False
   * for a gone token or a length out of bounds.
   */
  async setProfile(token: string, length: number, symbols: boolean): Promise<boolean> {
    if (!this.live(token)) return false;
    if (!Number.isInteger(length) || length < CUSTOM_MIN_LENGTH || length > CUSTOM_MAX_LENGTH) return false;
    const profile: GeneratorProfile = { kind: "custom", length, symbols };
    await this.deps.area.set({ [GENERATOR_PROFILE_KEY]: profile });
    return this.regenerate(token);
  }

  /**
   * The user took the suggestion: fill, remember it for the submission, save it (pending Login
   * on a signup, pending update on a change-password form), then forget it. A gone token: nothing.
   */
  async accept(token: string, opts: { signup?: boolean } = {}): Promise<void> {
    const h = this.live(token);
    if (!h) return;
    // Spent before anything else: a second accept racing this one does nothing.
    this.held.delete(token);
    const { target: t, password, rec } = h;
    h.password = "";
    await this.deps.filler.fillGenerated(t, password);
    this.deps.saveFlow.rememberGenerated(rec.tabId, rec.origin, password);
    const weak = h.report?.weak_by_site === true;
    if (opts.signup === true || rec.formKind === "signup") await this.deps.saveFlow.savePending(rec.tabId, rec.origin, password, { weak });
    else if (rec.formKind === "change_password") await this.deps.saveFlow.savePendingUpdate(rec.tabId, rec.origin, password, { weak });
  }

  /** Forget `token` (the ghost dismissed). */
  dismiss(token: string): void {
    this.forget(token);
  }

  /** Forget every suggestion of `tabId`: navigation, tab closed. */
  drop(tabId: number): void {
    for (const [k, h] of this.held) if (h.rec.tabId === tabId) this.forget(k);
  }

  /** Forget the suggestions of one frame (a child frame navigated). */
  dropFrame(tabId: number, frameId: number): void {
    for (const [k, h] of this.held) if (h.rec.tabId === tabId && h.rec.frameId === frameId) this.forget(k);
  }

  /** Forget everything: the vault locked. */
  clear(): void {
    for (const k of [...this.held.keys()]) this.forget(k);
  }

  private expired(h: Held): boolean {
    const age = this.now() - h.at;
    return age < 0 || age > SUGGESTION_TTL_MS;
  }

  private live(token: string): Held | null {
    const h = this.held.get(token);
    if (!h) return null;
    if (this.expired(h)) {
      this.forget(token);
      return null;
    }
    return h;
  }

  private forget(token: string): void {
    const h = this.held.get(token);
    if (h) h.password = "";
    this.held.delete(token);
  }
}
