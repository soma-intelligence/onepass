// Oracle of the autofill lab (spec 7.5): turns what a scenario driver observed
// (server events, chain state, which fields ended up non-empty) into one
// verdict. Order: a leak beats everything; a bench error (`lab:` prefix,
// native host rate limit) is lab_error; "nofill" scenarios pass only when
// nothing was filled or signed in; expected failures become xpass when the
// goal is met; a missed goal fails with its first explaining cause.
// Results carry field names, hosts and verdicts, never a value.
import type { DriverId, Expect, FlowId, Lang, Scenario, Site, TraitId } from "../gen/model.ts";
import type { LabEvent } from "../server/ledger.ts";

export type Verdict = "pass" | "fail" | "leak" | "xfail" | "xpass" | "flaky" | "lab_error";

export interface Observation {
  driver: DriverId;
  /** An extension frame (overlay for one_click and lookalike, menu for menu_fill) was shown. */
  overlayShown: boolean;
  /** The site's item was offered (overlay account or menu row). */
  itemOffered: boolean;
  chain?: { status: string; reason?: string };
  events: LabEvent[];
  /** Field name -> non-empty after the fill (before submit). */
  filled: Record<string, boolean>;
  error?: string;
  durationMs: number;
}

export interface Judgement { verdict: Verdict; cause?: string }

export interface Result {
  worldSeed: string; site: number; siteSeed: string; flow: FlowId; traits: TraitId[]; lang: Lang; labelLang: Lang;
  driver: DriverId; expect: Expect; verdict: Verdict; cause?: string; retried: boolean; durationMs: number; repro: string;
}

const FORM_FLOWS = new Set<FlowId>(["checkout_card", "address", "identity"]);

/** The account a successful sign-in on `site` must be for (undefined when the flow has none). */
function expectedUser(site: Site): string | undefined {
  return site.flow === "sso" ? site.sso?.email : site.account?.username;
}

/** Whether the scenario reached its goal: the right sign-in, or the form accepted. */
function goalMet(site: Site, events: LabEvent[]): boolean {
  if (FORM_FLOWS.has(site.flow)) {
    return events.some((e) => e.kind === "submit" && e.host === site.host && e.form === site.flow && e.ok);
  }
  return events.some((e) => e.kind === "signin" && e.host === site.host && rightSignin(site, e));
}

function rightSignin(site: Site, e: Extract<LabEvent, { kind: "signin" }>): boolean {
  const want = expectedUser(site);
  if (want !== undefined && e.user.trim().toLowerCase() !== want.trim().toLowerCase()) return false;
  if (site.flow === "sso") return e.via === site.sso?.provider;
  return e.via === undefined;
}

const WRONG_FILL = new Set(["wrong_fields"]);

function failCause(site: Site, o: Observation): string {
  if (!o.overlayShown) return "no_overlay";
  if (!o.itemOffered) return "no_menu_item";
  if (o.chain?.status === "handoff") return `handoff:${o.chain.reason ?? "unknown"}`;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  if (o.events.some((e) => e.kind === "signin" && hosts.has(e.host))) return "wrong_fill";
  const refused = o.events.filter((e): e is Extract<LabEvent, { kind: "submit" }> => e.kind === "submit" && !e.ok && hosts.has(e.host));
  const last = refused.at(-1);
  if (last) return WRONG_FILL.has(last.reason ?? "") ? "wrong_fill" : `rp_refused:${last.reason ?? "unknown"}`;
  // The chain ended (done, stopped) short of the site's sign-in: a step it did not see.
  if (o.chain !== undefined && o.chain.status !== "running") return `chain_ended:${o.chain.status}`;
  return "timeout";
}

export function judge(s: Scenario, site: Site, o: Observation): Judgement {
  const leak = o.events.find((e): e is Extract<LabEvent, { kind: "leak" }> => e.kind === "leak");
  if (leak) return { verdict: "leak", cause: `leak:${leak.secret}:${leak.field}@${leak.host}` };
  if (o.error !== undefined && (o.error.startsWith("lab:") || o.error.includes("rate_limited"))) {
    return { verdict: "lab_error", cause: o.error };
  }
  if (s.expect === "nofill") {
    const filled = Object.values(o.filled).some(Boolean) || o.events.some((e) => e.kind === "signin");
    if (filled) return { verdict: "fail", cause: "filled_where_forbidden" };
    // Spec 7.3: no overlay or menu may offer the real site's item on its lookalike.
    if (s.driver === "lookalike" && o.itemOffered) return { verdict: "fail", cause: "offered_where_forbidden" };
    return { verdict: "pass" };
  }
  const met = goalMet(site, o.events);
  if (s.expect === "xfail") return met ? { verdict: "xpass" } : { verdict: "xfail", cause: failCause(site, o) };
  return met ? { verdict: "pass" } : { verdict: "fail", cause: failCause(site, o) };
}
