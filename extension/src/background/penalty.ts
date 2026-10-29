// Smart fill penalty (spec 5.3): after a refused password (the chain ended
// in `repeat`), the next plans for that site lose one level of confidence,
// so a click fills without sending and the user sees what happens. Cleared
// when a chain on the site reaches `done`.
//
// `storage.session` key `smartfill.penalty.<site>`, no secret. The site is
// the registrable domain as `parseOrigin` computes it (tldts, private
// domains included), the mirror of `onepass_bridge::origin::Origin::site`
// (psl): the same key the bridge files the site memory under. Computed here
// rather than asked of the bridge: the chain needs it while the host may be
// gone (locked, disconnected), and a penalty must still apply then.
import { parseOrigin } from "../shared/domain";
import type { PlanOut } from "../shared/messages";
import type { StorageArea } from "./ext";

const PREFIX = "smartfill.penalty.";

export function penaltyKey(site: string): string {
  return PREFIX + site;
}

/** The site key of `origin` (null when it does not parse). */
export function siteOf(origin: string): string | null {
  return parseOrigin(origin)?.site ?? null;
}

export async function setPenalty(area: StorageArea, site: string, now: number): Promise<void> {
  await area.set({ [penaltyKey(site)]: { at: now } });
}

export async function clearPenalty(area: StorageArea, site: string): Promise<void> {
  await area.remove(penaltyKey(site));
}

export async function hasPenalty(area: StorageArea, origin: string): Promise<boolean> {
  const site = siteOf(origin);
  if (site === null) return false;
  const k = penaltyKey(site);
  return (await area.get(k))[k] !== undefined;
}

/** `plan` with `High` lowered to `Medium` (no auto-submit, no chain); other levels as they are. */
export function penalized(plan: PlanOut): PlanOut {
  return plan.confidence === "high" ? { ...plan, confidence: "medium" } : plan;
}
