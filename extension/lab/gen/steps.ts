// Step sequences of the multi_step flow (generator version 2): which roles
// each page of a multi-step sign-in asks for, drawn by weight from the
// sequences distilled from the corpus (patterns.json `steps`).
import type { Patterns, StepSeq } from "../corpus/types.ts";
import type { Lang, Role } from "./model.ts";
import { STEP_ROLES } from "./render-forms.ts";
import type { Rng } from "./rng.ts";

const IDENTIFIER: Role[] = ["username", "email"];

/** Keeps the roles a step form renders (render-forms.ts STEP_ROLES), each once, and drops empty steps. */
function renderable(seq: StepSeq): Role[][] {
  const seen = new Set<Role>();
  const out: Role[][] = [];
  for (const step of seq) {
    const roles = step.filter((r) => STEP_ROLES.includes(r) && !seen.has(r) && (seen.add(r), true));
    if (roles.length > 0) out.push(roles);
  }
  return out;
}

/**
 * The roles of each page of a multi-step sign-in: a weighted draw from
 * `p.steps`, cut to the roles a step form renders, then completed so that
 * the account can sign in: a missing identifier step goes first ("email"
 * when the corpus has email labels in `lang` or in English, else
 * "username"), a missing password goes right after the identifier, and a
 * sequence of one page holding both is split in two (at least 2 steps).
 */
export function pickSteps(r: Rng, p: Patterns, lang: Lang): Role[][] {
  const usable = (p.steps ?? []).map(([seq, w]) => [renderable(seq), w] as const).filter(([seq, w]) => seq.length > 0 && w > 0);
  const seq = usable.length > 0 ? r.weighted(usable).map((s) => [...s]) : [["email"], ["password"]] as Role[][];
  const has = (role: Role) => seq.some((s) => s.includes(role));
  if (!IDENTIFIER.some(has)) {
    const emailLabels = p.roles?.email?.labels ?? {};
    seq.unshift([(emailLabels[lang]?.length ?? 0) > 0 || (emailLabels.en?.length ?? 0) > 0 ? "email" : "username"]);
  }
  const at = seq.findIndex((s) => s.some((x) => IDENTIFIER.includes(x)));
  if (!has("password")) seq.splice(at + 1, 0, ["password"]);
  // A single page asking for the identifier and more is split: the identifier alone first.
  const idStep = seq[at]!;
  if (seq.length < 2 && idStep.length > 1) {
    const ids = idStep.filter((x) => IDENTIFIER.includes(x));
    seq.splice(at, 1, ids, idStep.filter((x) => !IDENTIFIER.includes(x)));
  }
  return seq;
}
