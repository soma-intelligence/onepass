// Oracle of the autofill lab (spec 7.5): turns what a scenario driver observed
// (server events, chain state, which fields ended up non-empty) into one
// verdict. Order: a leak beats everything; a bench error (`lab:` prefix,
// native host rate limit) is lab_error; any other driver exception fails
// (driver_error, so a crash never reads as "nothing was filled"); "nofill"
// scenarios pass only when
// nothing was filled or signed in; expected failures become xpass when the
// goal is met; a missed goal fails with its first explaining cause.
// Results carry field names, hosts and verdicts, never a value.
import type { DriverId, Expect, FixtureFile, FlowId, Lang, Scenario, Site, TraitId, World } from "../gen/model.ts";
import type { LabEvent } from "../server/ledger.ts";
import { wrongFields } from "../server/rp.ts";

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
  /** Field name -> value after the fill, for the fields whose value the page lets the driver read (never stored in a Result). */
  values?: Record<string, string>;
  /** Fields the driver typed itself as the user would (signup email): never counted as filled by the extension. */
  typed?: string[];
  error?: string;
  durationMs: number;
}

export interface Judgement { verdict: Verdict; cause?: string }

export interface Result {
  worldSeed: string; site: number; siteSeed: string; flow: FlowId; traits: TraitId[]; lang: Lang; labelLang: Lang;
  driver: DriverId; expect: Expect;
  /** Simulated user (population.ts); "p0" is the default one. */
  profile?: string;
  /** The documented reason of the expectation (capabilities.ts: "R-16 passkeys", "R-10", "lookalike host"...). */
  reason?: string;
  verdict: Verdict; cause?: string; retried: boolean; durationMs: number; repro: string;
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

/** Names of the filled fields whose value is not the one the profile's vault should give (empty: all right or unreadable). */
export type FillCheck = (values: Record<string, string>) => string[];

/**
 * The check of a scenario under a behaviour: the values the extension put in
 * the form against what `vault` (the active profile's) holds for the site. Form
 * flows go through the relying party's own comparison; password flows compare
 * the identifier and the password of the site's account (the primary item, not
 * a second account or a duplicate). Fields with no value to compare (generated
 * password, one-time code, closed shadow root) are not checked.
 */
export function fillCheck(world: World, site: Site, vault: FixtureFile): FillCheck {
  if (FORM_FLOWS.has(site.flow)) {
    return (values) => wrongFields({ ...world, fixture: vault }, site, values).filter((n) => n in values);
  }
  const account = site.account;
  if (!account || account.password === "" || site.flow === "signup") return () => [];
  return (values) => site.fields.filter((f) => {
    const got = values[f.name];
    if (got === undefined) return false;
    if (f.role === "username" || f.role === "email") return got.trim().toLowerCase() !== account.username.trim().toLowerCase();
    return f.role === "password" ? got !== account.password : false;
  }).map((f) => f.name);
}

/** Whether every field the scenario's page(s) asked for held a value after the fill (abandons_step: step 1 only). */
function fillMet(s: Scenario, site: Site, o: Observation): boolean {
  const fields = s.behaviour === "abandons_step" && site.steps ? site.steps[0]! : site.fields;
  const typed = new Set(o.typed ?? []);
  return fields.length > 0 && fields.every((f) => o.filled[f.name] === true || typed.has(f.name));
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

export function judge(s: Scenario, site: Site, o: Observation, check?: FillCheck): Judgement {
  const leak = o.events.find((e): e is Extract<LabEvent, { kind: "leak" }> => e.kind === "leak");
  if (leak) return { verdict: "leak", cause: `leak:${leak.secret}:${leak.field}@${leak.host}` };
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
  // Under a behaviour the user acts after the fill (edits a field, leaves the form): the extension is
  // judged on what it filled, never on how the site answered the user's later post.
  // The values count too: a second account or a wrong country format filled in is a wrong fill, as a refused post is without a behaviour.
  const behaving = s.behaviour !== undefined;
  const wrong = behaving ? (check?.(o.values ?? {}) ?? []) : [];
  const met = behaving ? fillMet(s, site, o) && wrong.length === 0 : goalMet(site, o.events);
  const cause = (): string => (behaving && wrong.length > 0 && fillMet(s, site, o) ? "wrong_fill" : failCause(site, o));
  if (s.expect === "xfail") return met ? { verdict: "xpass" } : { verdict: "xfail", cause: cause() };
  return met ? { verdict: "pass" } : { verdict: "fail", cause: cause() };
}
