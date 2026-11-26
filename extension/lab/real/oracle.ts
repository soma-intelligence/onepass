// Oracle of the real-site bench: the product rules R1 to R5 of README.md,
// judged on one snapshot of a page after one step of the journey. Pure: the
// visit (visit.ts) gathers the snapshot in the browser, this file only
// decides. A finding never carries a field value, only roles, tags and boxes.
import { summarizeEvents, type GuardEvent } from "./guard.ts";

export type Rule = "R1" | "R2" | "R3" | "R4" | "R5";
export type Verdict = "pass" | "violation" | "warn" | "info" | "skip";

export interface Rect { x: number; y: number; width: number; height: number }

export type FieldRole = "username" | "password" | "search" | "newsletter" | "other";

export interface FieldView {
  /** Index among the page's visible inputs (journey order). */
  index: number;
  role: FieldRole;
  box: Rect;
}

export type CardFace = "signin" | "generic" | "signup" | "other";

/** A control of the page sampled for clickability, and what `elementFromPoint` found at its centre. */
export interface ControlProbe {
  tag: string;
  x: number;
  y: number;
  /** "self": the control (or its own content); "onepass": the OnePass shell; "other": anything else of the page; "none": nothing. */
  hit: "self" | "onepass" | "other" | "none";
  /** When `hit` is "onepass": what of the shell took the pointer (an iframe's class and size, or the host element). */
  by?: string;
}

/** A point of a OnePass frame's box, and whether the OnePass shell takes the pointer there. */
export interface FrameProbe { x: number; y: number; onepass: boolean }

export interface Snapshot {
  step: string;
  host: string;
  /** Overlay frames in the page (the card); more than one is a redundancy. */
  overlayFrames: number;
  /** The card's face, when a card is shown. */
  card: CardFace | null;
  /** Visible parts of the card (page coordinates), for R2. */
  cardBoxes: Rect[];
  /** The overlay frame's whole box. */
  cardFrame: Rect | null;
  menuOpen: boolean;
  menuBox: Rect | null;
  /** OnePass field icons shown (page coordinates). */
  icons: Rect[];
  fields: FieldView[];
  /** The page has a sign-in form (password field, or identifier step of a sign-in). */
  loginForm: boolean;
  signupForm: boolean;
  /** Signed-in marks the page shows (sign-out control, account menu, avatar); empty: none. */
  signedInMarks: string[];
  /** Icons of other managers (page coordinates). */
  foreignIcons: Rect[];
  /** Dropdowns of other managers open now. */
  foreignMenus: number;
  controls: ControlProbe[];
  /** Points over OnePass frames outside their visible parts (transparent areas). */
  frameProbes: FrameProbe[];
  /** After the bench focused a field: where the focus is. */
  focus?: { expected: "field"; on: "field" | "onepass" | "foreign" | "page" | "none" };
  /** Fields whose value changed while the bench typed nothing (indices; values never leave the page). */
  valuesChanged: number[];
  /** Time from the click on × to the card gone (ms); undefined when not measured, null when it never went. */
  closeMs?: number | null;
}

export interface JudgeContext {
  /** Logins the vault holds for the page's site. */
  vaultLogins: number;
  /** The site is known signed in (profile target listed as signed in). */
  knownSignedIn: boolean;
  /** The user closed the card with × on this site in this tab. */
  closedByX: boolean;
  /** Steps that just arrived on a page (where a missing card on a sign-in page is worth a note). */
  arrival: boolean;
}

export interface Finding {
  rule: Rule;
  verdict: Verdict;
  detail: string;
  /** Area to capture for a violation (page coordinates). */
  box?: Rect;
}

/** Most a close by × may take, click guard and fade included. */
export const CLOSE_MAX_MS = 700;
/** Margin around the card's visible parts that still counts as the card (shadow, rounding). */
const CARD_MARGIN = 6;

export function inside(r: Rect, x: number, y: number, margin = 0): boolean {
  return x >= r.x - margin && x <= r.x + r.width + margin && y >= r.y - margin && y <= r.y + r.height + margin;
}

export function overlap(a: Rect, b: Rect): boolean {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}

export function union(rects: readonly Rect[]): Rect | undefined {
  if (rects.length === 0) return undefined;
  const x1 = Math.min(...rects.map((r) => r.x));
  const y1 = Math.min(...rects.map((r) => r.y));
  const x2 = Math.max(...rects.map((r) => r.x + r.width));
  const y2 = Math.max(...rects.map((r) => r.y + r.height));
  return { x: x1, y: y1, width: x2 - x1, height: y2 - y1 };
}

const point = (x: number, y: number): Rect => ({ x: x - 1, y: y - 1, width: 2, height: 2 });

/** R1: the card only where the user has to sign in with an account of the vault, never on a signed-in page, never after ×. */
export function judgeR1(s: Snapshot, c: JudgeContext): Finding[] {
  const signedIn = c.knownSignedIn || s.signedInMarks.length > 0;
  const why = c.knownSignedIn ? "profile signed in" : s.signedInMarks.join(", ");
  if (s.card === null) {
    if (c.arrival && s.loginForm && c.vaultLogins > 0 && !signedIn && !c.closedByX) {
      return [{ rule: "R1", verdict: "info", detail: "no card on a sign-in page with an account in the vault" }];
    }
    return [{ rule: "R1", verdict: "pass", detail: "no card" }];
  }
  const box = s.cardFrame ?? undefined;
  const out: Finding[] = [];
  if (c.closedByX) out.push({ rule: "R1", verdict: "violation", detail: "card came back after × on this site", ...(box ? { box } : {}) });
  if (signedIn) out.push({ rule: "R1", verdict: "violation", detail: `card on a signed-in page (${why})`, ...(box ? { box } : {}) });
  if (s.card === "signin" || s.card === "generic") {
    if (!s.loginForm) out.push({ rule: "R1", verdict: "violation", detail: `${s.card} card on a page with no sign-in form`, ...(box ? { box } : {}) });
    if (s.card === "signin" && c.vaultLogins === 0) out.push({ rule: "R1", verdict: "violation", detail: "sign-in card with no account of the site in the vault", ...(box ? { box } : {}) });
  } else if (s.card === "signup") {
    if (!s.signupForm) out.push({ rule: "R1", verdict: "violation", detail: "signup card on a page with no signup form", ...(box ? { box } : {}) });
  }
  const searchOnly = s.fields.length > 0 && s.fields.every((f) => f.role === "search" || f.role === "newsletter");
  if (searchOnly && !s.loginForm) out.push({ rule: "R1", verdict: "violation", detail: "card for a search or newsletter field", ...(box ? { box } : {}) });
  if (out.length === 0) out.push({ rule: "R1", verdict: "pass", detail: `${s.card} card where needed` });
  return dedupe(out);
}

/** R2: page controls stay clickable; no transparent OnePass area takes the pointer; × closes at once. */
export function judgeR2(s: Snapshot): Finding[] {
  const out: Finding[] = [];
  const own = [...s.cardBoxes, ...(s.menuBox ? [s.menuBox] : [])];
  for (const ctl of s.controls) {
    if (ctl.hit !== "onepass") continue;
    if (own.some((r) => inside(r, ctl.x, ctl.y, CARD_MARGIN))) continue;
    if (s.icons.some((r) => inside(r, ctl.x, ctl.y, 1))) {
      out.push({ rule: "R2", verdict: "violation", detail: `OnePass icon covers a page <${ctl.tag}>`, box: point(ctl.x, ctl.y) });
      continue;
    }
    out.push({ rule: "R2", verdict: "violation", detail: `invisible OnePass area covers a page <${ctl.tag}>${ctl.by ? ` (${ctl.by})` : ""}`, box: point(ctl.x, ctl.y) });
  }
  const leaks = s.frameProbes.filter((p) => p.onepass && !own.some((r) => inside(r, p.x, p.y, CARD_MARGIN)) && !s.icons.some((r) => inside(r, p.x, p.y, 1)));
  if (leaks.length > 0) {
    out.push({
      rule: "R2", verdict: "violation", detail: `transparent OnePass frame area takes the pointer (${leaks.length} of ${s.frameProbes.length} points)`,
      ...(union(leaks.map((p) => point(p.x, p.y))) ? { box: union(leaks.map((p) => point(p.x, p.y)))! } : {}),
    });
  }
  if (s.closeMs !== undefined) {
    if (s.closeMs === null) out.push({ rule: "R2", verdict: "violation", detail: "× did not remove the card", ...(s.cardFrame ? { box: s.cardFrame } : {}) });
    else if (s.closeMs > CLOSE_MAX_MS) out.push({ rule: "R2", verdict: "violation", detail: `× took ${Math.round(s.closeMs)} ms to remove the card`, ...(s.cardFrame ? { box: s.cardFrame } : {}) });
  }
  if (out.length === 0) {
    const probed = s.controls.length + s.frameProbes.length;
    out.push({ rule: "R2", verdict: probed > 0 || s.closeMs !== undefined ? "pass" : "skip", detail: probed > 0 ? `${s.controls.length} controls and ${s.frameProbes.length} frame points clear` : s.closeMs !== undefined ? "× closed at once" : "nothing to probe" });
  }
  return dedupe(out);
}

/** The field an icon belongs to: the one whose box holds the icon's centre. */
function fieldOf(icon: Rect, fields: readonly FieldView[]): FieldView | undefined {
  const cx = icon.x + icon.width / 2;
  const cy = icon.y + icon.height / 2;
  return fields.find((f) => inside(f.box, cx, cy, 2));
}

/** R3: one OnePass prompt at a time; one icon per field; no icon where none is needed. */
export function judgeR3(s: Snapshot): Finding[] {
  const out: Finding[] = [];
  if (s.overlayFrames > 1) out.push({ rule: "R3", verdict: "violation", detail: `${s.overlayFrames} cards at once`, ...(s.cardFrame ? { box: s.cardFrame } : {}) });
  if (s.card !== null && s.menuOpen) {
    const box = union([...(s.cardFrame ? [s.cardFrame] : []), ...(s.menuBox ? [s.menuBox] : [])]);
    out.push({ rule: "R3", verdict: "violation", detail: "card and field menu open together", ...(box ? { box } : {}) });
  }
  const perField = new Map<number, Rect[]>();
  for (const icon of s.icons) {
    const f = fieldOf(icon, s.fields);
    if (!f) continue;
    perField.set(f.index, [...(perField.get(f.index) ?? []), icon]);
  }
  for (const [index, icons] of perField) {
    const f = s.fields.find((x) => x.index === index)!;
    if (icons.length > 1) out.push({ rule: "R3", verdict: "violation", detail: `${icons.length} OnePass icons in one ${f.role} field`, box: f.box });
    if (f.role === "search" || f.role === "newsletter") out.push({ rule: "R3", verdict: "violation", detail: `OnePass icon in a ${f.role} field`, box: f.box });
  }
  if (out.length === 0) out.push({ rule: "R3", verdict: "pass", detail: `${s.icons.length} icon(s), ${s.card ? "card" : "no card"}, ${s.menuOpen ? "menu" : "no menu"}` });
  return dedupe(out);
}

/** R4: no clash with another manager: icons apart, one dropdown at a time, focus kept, values kept. */
export function judgeR4(s: Snapshot, managersLoaded: boolean): Finding[] {
  const out: Finding[] = [];
  for (const icon of s.icons) {
    const clash = s.foreignIcons.find((f) => overlap(icon, f));
    if (clash) out.push({ rule: "R4", verdict: "violation", detail: "OnePass icon overlaps another manager's icon", box: union([icon, clash])! });
  }
  if (s.menuOpen && s.foreignMenus > 0) out.push({ rule: "R4", verdict: "violation", detail: "OnePass menu and another manager's dropdown open together", ...(s.menuBox ? { box: s.menuBox } : {}) });
  if (s.card !== null && s.foreignMenus > 0) out.push({ rule: "R4", verdict: "warn", detail: "card shown while another manager's dropdown is open", ...(s.cardFrame ? { box: s.cardFrame } : {}) });
  if (s.focus) {
    if (s.focus.on === "onepass") out.push({ rule: "R4", verdict: "violation", detail: "OnePass took the focus from the field" });
    else if (s.focus.on === "foreign") out.push({ rule: "R4", verdict: "warn", detail: "another manager took the focus from the field" });
  }
  for (const i of s.valuesChanged) {
    const f = s.fields.find((x) => x.index === i);
    out.push({ rule: "R4", verdict: "violation", detail: `value of a ${f?.role ?? "page"} field changed while nobody typed`, ...(f ? { box: f.box } : {}) });
  }
  if (out.length === 0) out.push({ rule: "R4", verdict: managersLoaded ? "pass" : "skip", detail: managersLoaded ? `${s.foreignIcons.length} foreign icon(s), no clash` : "no other manager loaded" });
  return dedupe(out);
}

/** R5: every request or submit the guard had to cut in this step; OnePass as the cause is a violation. */
export function judgeR5(events: readonly GuardEvent[]): Finding[] {
  if (events.length === 0) return [{ rule: "R5", verdict: "pass", detail: "nothing cut" }];
  return summarizeEvents(events).map((e) => {
    const verdict: Verdict = e.cause === "onepass" ? "violation" : e.kind === "submit" || e.kind === "form-submit" || e.kind === "request-submit" ? "warn" : "info";
    return { rule: "R5" as const, verdict, detail: `${e.count} ${e.key} cut` };
  });
}

/** Every rule on one snapshot. */
export function judge(s: Snapshot, c: JudgeContext, events: readonly GuardEvent[], managersLoaded: boolean): Finding[] {
  return [...judgeR1(s, c), ...judgeR2(s), ...judgeR3(s), ...judgeR4(s, managersLoaded), ...judgeR5(events)];
}

function dedupe(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  return fs.filter((f) => {
    const k = `${f.rule}|${f.verdict}|${f.detail}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
