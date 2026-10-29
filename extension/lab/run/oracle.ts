// Oracle of the autofill lab (spec 7.5): turns what a scenario driver observed
// (server events, chain state, which fields ended up non-empty) into one
// verdict. Order: a leak beats everything; a bench error (`lab:` prefix,
// native host rate limit) is lab_error; any other driver exception fails
// (driver_error, so a crash never reads as "nothing was filled"); "nofill"
// scenarios pass only when
// nothing was filled or signed in; expected failures become xpass when the
// goal is met; a missed goal fails with its first explaining cause.
// Two safety causes come right after a leak and fail any scenario, whatever
// its expectation (smart fill, spec 1 and 10): `wrong_item` (a field holds a
// value of another vault item, or the site signed in another account) and
// `auto_submit_outside_login` (a post of the site that the user did not send,
// on a flow whose true intent is not a sign-in; the code step of a sign-in is
// part of the login family, spec 8.1).
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
  /** Fields the driver typed itself as the user would (signup email): never counted as filled by the extension. */
  typed?: string[];
  /** Gestures toward OnePass the driver made (overlay pick, menu opened, menu row, field icon, toolbar Fill). */
  clicks?: number;
  /** When the driver, as the user, sent the site's form (ms, server clock); unset when it never did. */
  userSubmitAt?: number;
  /** Fields that held a value of another vault item than the scenario's (names only, from items.ts). */
  foreign?: string[];
  error?: string;
  durationMs: number;
}

export interface Judgement { verdict: Verdict; cause?: string }

export interface Result {
  worldSeed: string; site: number; siteSeed: string; flow: FlowId; traits: TraitId[]; lang: Lang; labelLang: Lang;
  driver: DriverId; expect: Expect;
  /** The documented reason of the expectation (capabilities.ts: "R-16 passkeys", "R-10", "lookalike host"...). */
  reason?: string;
  verdict: Verdict; cause?: string; retried: boolean; durationMs: number; repro: string;
  /** Goal met with one gesture toward OnePass (undefined where the scenario has no goal to reach). */
  oneClick?: boolean;
}

const FORM_FLOWS = new Set<FlowId>(["checkout_card", "address", "identity"]);
/** Flows whose true intent is a sign-in (code step included): the only ones OnePass may send. */
export const LOGIN_FAMILY = new Set<FlowId>(["login_single", "login_username_first", "login_email_then_password", "login_totp",
  "login_passkey", "sso"]);
/** Drivers whose one-click success the report compares. */
export const ONE_CLICK_DRIVERS = new Set<DriverId>(["one_click", "menu_fill", "smart_fill"]);

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

/** The site's last refusal of a post, as a cause (wrong_fill or rp_refused:<reason>). */
function refusalCause(site: Site, o: Observation): string | undefined {
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  const last = o.events.filter((e): e is Extract<LabEvent, { kind: "submit" }> => e.kind === "submit" && !e.ok && hosts.has(e.host)).at(-1);
  if (!last) return undefined;
  return WRONG_FILL.has(last.reason ?? "") ? "wrong_fill" : `rp_refused:${last.reason ?? "unknown"}`;
}

function failCause(site: Site, o: Observation): string {
  // menu_fill has no overlay: its in-field menu never opened.
  if (!o.overlayShown) return o.driver === "menu_fill" ? "no_menu" : "no_overlay";
  if (!o.itemOffered) return "no_menu_item";
  const refused = refusalCause(site, o);
  if (o.chain?.status === "handoff") return `handoff:${o.chain.reason ?? "unknown"}${refused ? ` (${refused})` : ""}`;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  if (o.events.some((e) => e.kind === "signin" && hosts.has(e.host))) return "wrong_fill";
  if (refused) return refused;
  // The chain ended (done, stopped) short of the site's sign-in: a step it did not see.
  if (o.chain !== undefined && o.chain.status !== "running") return `chain_ended:${o.chain.status}`;
  return "timeout";
}

/** First line of a driver exception, cut short (Playwright messages carry call logs). */
function shortError(msg: string): string {
  const line = (msg.split("\n")[0] ?? "").trim();
  return line.length > 80 ? `${line.slice(0, 77)}...` : line || "unknown";
}

/** A sign-in of the site as another account than the scenario's. */
function wrongAccount(site: Site, events: LabEvent[]): boolean {
  const want = expectedUser(site);
  if (want === undefined) return false;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  return events.some((e) => e.kind === "signin" && hosts.has(e.host) && e.user.trim().toLowerCase() !== want.trim().toLowerCase());
}

/** A post of the site (or its frame) before the user sent the form, on a flow that is not a sign-in. */
function autoSubmitOutsideLogin(site: Site, o: Observation): boolean {
  if (LOGIN_FAMILY.has(site.flow)) return false;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  const userAt = o.userSubmitAt ?? Number.POSITIVE_INFINITY;
  return o.events.some((e) => (e.kind === "submit" || e.kind === "signin") && hosts.has(e.host) && e.at < userAt);
}

export function judge(s: Scenario, site: Site, o: Observation): Judgement {
  const leak = o.events.find((e): e is Extract<LabEvent, { kind: "leak" }> => e.kind === "leak");
  if (leak) return { verdict: "leak", cause: `leak:${leak.secret}:${leak.field}@${leak.host}` };
  if (autoSubmitOutsideLogin(site, o)) return { verdict: "fail", cause: "auto_submit_outside_login" };
  if ((o.foreign?.length ?? 0) > 0 || wrongAccount(site, o.events)) return { verdict: "fail", cause: "wrong_item" };
  if (o.error !== undefined && (o.error.startsWith("lab:") || o.error.includes("rate_limited"))) {
    return { verdict: "lab_error", cause: o.error };
  }
  if (o.error !== undefined) return { verdict: "fail", cause: `driver_error:${shortError(o.error)}` };
  if (s.expect === "nofill") {
    const typed = new Set(o.typed ?? []);
    const filled = Object.entries(o.filled).some(([name, v]) => v && !typed.has(name)) || o.events.some((e) => e.kind === "signin");
    if (filled) return { verdict: "fail", cause: "filled_where_forbidden" };
    // Spec 7.3: no overlay or menu may offer the real site's item on its lookalike.
    if (s.driver === "lookalike" && o.itemOffered) return { verdict: "fail", cause: "offered_where_forbidden" };
    return { verdict: "pass" };
  }
  const met = goalMet(site, o.events);
  if (s.expect === "xfail") return met ? { verdict: "xpass" } : { verdict: "xfail", cause: failCause(site, o) };
  return met ? { verdict: "pass" } : { verdict: "fail", cause: failCause(site, o) };
}

/**
 * Whether the scenario met its goal with one gesture toward OnePass: the
 * overlay's account, or the field icon whose plan did the rest. Opening the
 * in-field menu and picking its row are two gestures. The user's own typing
 * and own press on the form's button are not counted. Undefined for the
 * scenarios without a goal (nofill, lookalike, bench control).
 */
export function oneClickOf(s: Scenario, verdict: Verdict, o: Observation): boolean | undefined {
  if (!ONE_CLICK_DRIVERS.has(s.driver) || s.expect === "nofill" || verdict === "lab_error") return undefined;
  const met = verdict === "pass" || verdict === "flaky" || verdict === "xpass";
  return met && o.clicks === 1;
}

/** Causes that are safety failures: never replayed, never hidden by a replay. */
export const SAFETY_CAUSES = new Set(["wrong_item", "auto_submit_outside_login"]);

/**
 * Whether a first attempt gets one replay in a fresh profile: a plain
 * failure only. A forbidden fill (expect nofill) or a safety failure is
 * final, never turned into a flaky pass.
 */
export function replayable(s: Scenario, j: Judgement): boolean {
  return j.verdict === "fail" && s.expect !== "nofill" && !SAFETY_CAUSES.has(j.cause ?? "");
}

/**
 * The verdict after a replay of `first`: a pass makes it flaky; a leak or a
 * safety failure on the replay replaces it (a violation is never dropped);
 * anything else keeps the first failure. `replay` says whether the replay's
 * observation is the one the verdict stands on.
 */
export function afterReplay(first: Judgement, again: Judgement): { judgement: Judgement; replay: boolean } {
  if (again.verdict === "pass") return { judgement: { verdict: "flaky", ...(first.cause ? { cause: first.cause } : {}) }, replay: true };
  if (again.verdict === "leak" || SAFETY_CAUSES.has(again.cause ?? "")) return { judgement: again, replay: true };
  return { judgement: first, replay: false };
}
