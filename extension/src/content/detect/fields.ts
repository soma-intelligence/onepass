// Field classification (spec 8.2): `autocomplete` decides directly, otherwise a
// weighted score over the field's texts and attributes (weights in lexicon.ts).

import type { FieldRole } from "../../shared/messages";
import {
  ATTRIBUTE_WEIGHTS,
  AUTOCOMPLETE_QUALIFIERS,
  AUTOCOMPLETE_ROLES,
  AUTOCOMPLETE_SCORE,
  MAX_SOURCE_CHARS,
  NON_PASSWORD_TYPE_PENALTY,
  normalizeText,
  PASSWORD_TYPE_ROLES,
  SCORE_THRESHOLD,
  SCORED_ROLES,
  type ScoredRole,
  type Source,
  SOURCE_WEIGHTS,
  TERMS,
  TYPE_WEIGHTS,
  type Weights,
} from "./lexicon";
import { ownText } from "./text";

export type FieldElement = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

/** Input types that never hold a value OnePass fills. */
const NON_FIELD_INPUT_TYPES: ReadonlySet<string> = new Set([
  "hidden",
  "submit",
  "button",
  "reset",
  "image",
  "file",
  "radio",
  "range",
  "color",
  "search",
]);

const PASSWORD_ROLES: readonly ScoredRole[] = ["current_password", "new_password", "confirm_password"];

/**
 * Query for controls that may hold a value. Filters in the selector so that
 * caps apply to real candidates, not to hidden inputs or buttons.
 */
export const FIELD_SELECTOR =
  "input:not([type=hidden i]):not([type=submit i]):not([type=button i]):not([type=image i]):not([type=reset i]), select, textarea";

/** True for `<input>`, `<select>` and `<textarea>` controls that may hold a fillable value. */
export function isFieldCandidate(el: Element): el is FieldElement {
  if (el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) return true;
  return el instanceof HTMLInputElement && !NON_FIELD_INPUT_TYPES.has(el.type);
}

export function controlType(el: FieldElement): string {
  if (el instanceof HTMLSelectElement) return "select";
  if (el instanceof HTMLTextAreaElement) return "textarea";
  return el.type;
}

/** Role named by the `autocomplete` attribute, if any. */
export function autocompleteRole(el: FieldElement): ScoredRole | null {
  const raw = (el.getAttribute("autocomplete") ?? "").slice(0, MAX_SOURCE_CHARS).toLowerCase();
  const tokens = raw
    .split(/\s+/)
    .filter((t) => t !== "" && !t.startsWith("section-") && !AUTOCOMPLETE_QUALIFIERS.has(t));
  const last = tokens[tokens.length - 1];
  if (last === undefined) return null;
  return AUTOCOMPLETE_ROLES[last] ?? null;
}

function containsControl(el: Element): boolean {
  return el.matches("input, select, textarea") || el.querySelector("input, select, textarea") !== null;
}

/** Short text right before the field: up to two previous siblings, else the parent's previous sibling. */
function nearbyText(el: Element): string {
  let out = "";
  let sib = el.previousElementSibling;
  for (let i = 0; i < 2 && sib && !containsControl(sib); i++, sib = sib.previousElementSibling) {
    out = `${ownText(sib, 100)} ${out}`;
  }
  if (out.trim() === "" && el.parentElement) {
    const before = el.parentElement.previousElementSibling;
    if (before && !containsControl(before)) out = ownText(before, 100);
  }
  return out.slice(0, MAX_SOURCE_CHARS);
}

function labelText(el: FieldElement): string {
  let out = "";
  for (const label of Array.from(el.labels ?? []).slice(0, 3)) out += ` ${ownText(label)}`;
  return out.slice(0, MAX_SOURCE_CHARS);
}

function labelledByText(el: Element): string {
  const ids = (el.getAttribute("aria-labelledby") ?? "").slice(0, MAX_SOURCE_CHARS).split(/\s+/);
  let out = "";
  for (const id of ids.slice(0, 3)) {
    if (id === "") continue;
    const ref = el.ownerDocument.getElementById(id);
    if (ref) out += ` ${ownText(ref)}`;
  }
  return out;
}

function sources(el: FieldElement): [Source, string][] {
  const attr = (n: string) => (el.getAttribute(n) ?? "").slice(0, MAX_SOURCE_CHARS);
  return [
    ["name", attr("name")],
    ["id", attr("id")],
    ["placeholder", attr("placeholder")],
    ["ariaLabel", `${attr("aria-label")} ${labelledByText(el)}`],
    ["label", labelText(el)],
    ["title", attr("title")],
    ["nearby", nearbyText(el)],
  ];
}

function zeroScores(): Record<FieldRole, number> {
  const out = { unknown: 0 } as Record<FieldRole, number>;
  for (const r of SCORED_ROLES) out[r] = 0;
  return out;
}

function add(scores: Record<FieldRole, number>, w: Weights, factor = 1): void {
  for (const [role, v] of Object.entries(w) as [ScoredRole, number][]) scores[role] += v * factor;
}

/**
 * The single scoring function of the detector (ruling R-09): one score per
 * role. A recognized `autocomplete` token gives its role AUTOCOMPLETE_SCORE.
 * `cardForm` false means the field's form holds no other card field: terms
 * with `alone` weights (an ambiguous "security code") use them instead.
 */
export function scoreField(el: FieldElement, cardForm = true): Record<FieldRole, number> {
  const scores = zeroScores();
  const type = controlType(el);

  if (type === "checkbox") {
    // A checkbox can only be "remember me".
    for (const [src, text] of sources(el)) {
      const t = normalizeText(text);
      for (const term of TERMS) {
        if (term.w.remember_me !== undefined && term.re.test(t)) {
          scores.remember_me += term.w.remember_me * SOURCE_WEIGHTS[src];
        }
      }
    }
    return scores;
  }

  const direct = autocompleteRole(el);
  if (direct !== null) {
    scores[direct] = AUTOCOMPLETE_SCORE;
    return scores;
  }

  for (const [src, text] of sources(el)) {
    const t = normalizeText(text);
    if (t === "") continue;
    for (const term of TERMS) {
      if (term.re.test(t)) add(scores, cardForm ? term.w : (term.alone ?? term.w), SOURCE_WEIGHTS[src]);
    }
  }

  const typeWeights = TYPE_WEIGHTS[type];
  if (typeWeights) add(scores, typeWeights);
  if (type !== "password") {
    for (const r of PASSWORD_ROLES) scores[r] += NON_PASSWORD_TYPE_PENALTY;
  }

  if (el instanceof HTMLInputElement) {
    const numeric = el.inputMode === "numeric" || el.inputMode === "decimal";
    if (el.maxLength === 1) add(scores, ATTRIBUTE_WEIGHTS.maxLengthOne);
    if (numeric) add(scores, ATTRIBUTE_WEIGHTS.numericInputMode);
    if (numeric && el.maxLength >= 4 && el.maxLength <= 8) add(scores, ATTRIBUTE_WEIGHTS.shortNumeric);
    const pattern = el.pattern.slice(0, MAX_SOURCE_CHARS);
    if (/^(\\d|\[0-9\])/.test(pattern)) add(scores, ATTRIBUTE_WEIGHTS.digitPattern);
  }

  scores.remember_me = 0;
  if (type === "password") {
    for (const r of SCORED_ROLES) if (!PASSWORD_TYPE_ROLES.has(r)) scores[r] = 0;
  }
  return scores;
}

/** Highest-scoring role above SCORE_THRESHOLD, else `unknown` with score 0 (`cardForm`: see scoreField). */
export function classifyField(el: FieldElement, cardForm = true): { role: FieldRole; score: number } {
  const scores = scoreField(el, cardForm);
  let best: FieldRole = "unknown";
  let bestScore = 0;
  for (const r of SCORED_ROLES) {
    if (scores[r] > bestScore) {
      best = r;
      bestScore = scores[r];
    }
  }
  if (bestScore < SCORE_THRESHOLD) return { role: "unknown", score: 0 };
  return { role: best, score: bestScore };
}
