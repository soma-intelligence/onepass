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
// part of the login family, spec 8.1). A third, `other_person_filled` (spec
// 11.4), fails a forms page whose passenger 2 or later the extension filled. A fourth, `auto_saved_on_failure`
// (save spec 4), fails a login saved by itself after a refused sign-in; `ghost_in_page_dom` fails a password
// found in the page's DOM before the user accepted it.
// Results carry field names, hosts and verdicts, never a value.
// Gestures (gestures.ts): every result also says how many human-equivalent
// gestures the attempt took, their kinds, and whether the oracle saw the
// scenario's session; "one gesture, signed in" is both at once. A scenario
// whose start state the host cannot be put in is `skipped` (out of every
// rate), with the missing control as its cause.
import type { DriverId, Expect, FixtureFile, FlowId, Lang, Scenario, Site, StartState, TraitId, Trigger, World } from "../gen/model.ts";
import type { LabEvent } from "../server/ledger.ts";
import { wrongFields } from "../server/rp.ts";
import { flowFamily, type Gesture, type GestureFields, gestureFields, type GestureKind, triggerOf } from "./gestures.ts";

export type Verdict = "pass" | "fail" | "leak" | "xfail" | "xpass" | "flaky" | "lab_error" | "skipped";

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
  /** Gestures toward OnePass the driver made (overlay pick, menu opened, menu row, field icon, toolbar Fill). */
  clicks?: number;
  /** When the driver, as the user, sent the site's form (ms, server clock); unset when it never did. */
  userSubmitAt?: number;
  /** Fields that held a value of another vault item than the scenario's (names only, from items.ts). */
  foreign?: string[];
  /** Every human-equivalent gesture of the attempt, in order (gestures.ts); absent on a bench error before any driver ran. */
  gestures?: Gesture[];
  /** How the driver started OnePass (the toolbar Fill where the page has no field with an icon). */
  trigger?: Trigger;
  /** Account profiles: the identifier field held the site's other account, not the one the user means. */
  otherAccount?: boolean;
  /** Locked start: OnePass said it is locked and offered the user's item nowhere. */
  lockedShown?: boolean;
  /** The start state could not be set up: the missing control ("host lacks control ..."). Nothing was played. */
  skipped?: string;
  /** How the unlock of a locked start was approved: at once by the host, or by the stand-in's approval file. */
  unlock?: "instant" | "deferred";
  /**
   * Save and ghost drivers (task 12b fills these; never a value, only counts and flags, the lab rule):
   * - ghostShown: the ghost suggestion frame (extension, shadow of the field) appeared on the new-password field.
   * - ghostInPageDom: the generated password text, read from the ghost frame, was found in `page.content()` or
   *   in any input value of any frame before the accepting gesture (the leak probe; true is a failure).
   * - ghostAccepted: after the scenario's gesture the password field held a value the extension put there.
   * - menuOpened: the in-field menu opened (menu_arrow, and the fallbacks when the ghost cannot be placed).
   * - savedLogins: logins the vault gained for the site's origin (vaultLogins after minus before, pending
   *   ones not counted).
   * - autoSaved: a login was saved with no gesture on a card (the toast "saved" appeared by itself).
   * - cardShown: the save card (or its folded pill) appeared.
   * - failedSignIn: the site refused the sign-in the driver typed (failed_login, or a refusal seen by the ledger).
   */
  ghostShown?: boolean;
  ghostInPageDom?: boolean;
  ghostAccepted?: boolean;
  menuOpened?: boolean;
  savedLogins?: number;
  autoSaved?: boolean;
  cardShown?: boolean;
  failedSignIn?: boolean;
  error?: string;
  durationMs: number;
}

export interface Judgement { verdict: Verdict; cause?: string }

export interface Result {
  worldSeed: string; site: number; siteSeed: string; flow: FlowId; traits: TraitId[]; lang: Lang; labelLang: Lang;
  driver: DriverId; expect: Expect;
  /** ghost and save_typed: the variant of the scenario. */
  variant?: string;
  /** Simulated user (population.ts); "p0" is the default one. */
  profile?: string;
  /** The documented reason of the expectation (capabilities.ts: "R-16 passkeys", "R-10", "lookalike host"...). */
  reason?: string;
  verdict: Verdict; cause?: string; retried: boolean; durationMs: number; repro: string;
  /** Goal met with one gesture toward OnePass (undefined where the scenario has no goal to reach). */
  oneClick?: boolean;
  /** Deliberate gestures of the attempt the verdict stands on, the user's own submit included (absent in runs before the gesture accounting). */
  gestures?: number;
  /** Their kinds in order, biometric approvals included. */
  gestureList?: GestureKind[];
  /** Unlock approvals by the Touch ID stand-in ("+1 biometric"). */
  biometric?: number;
  /** The oracle saw the scenario's session (flows whose goal is a session, scenarios with a goal). */
  signedIn?: boolean;
  /** The headline metric: signedIn with exactly one deliberate gesture. */
  oneGesture?: boolean;
  /** Absent in older runs: unlocked_warm. */
  startState?: StartState;
  trigger?: Trigger;
  unlock?: "instant" | "deferred";
  /** Account profiles: the outcome the scenario states. */
  outcome?: string;
}

/** Flows whose goal is a form the relying party accepts (the forms flows of spec 11 included). */
export const FORM_FLOWS = new Set<FlowId>(["checkout_card", "address", "identity", "travel_booking", "company_b2b", "car_rental", "admin_identity"]);
/**
 * Flows whose true intent is a sign-in (code step included): the only ones OnePass may send.
 * multi_step is a sign-in split over pages (identifier, then password or code), which the menu
 * pick and the one-click chain run to its end (ruling R31).
 */
export const LOGIN_FAMILY = new Set<FlowId>(["login_single", "login_username_first", "login_email_then_password", "login_totp",
  "login_passkey", "sso", "multi_step"]);
/** Drivers whose one-click success the report compares. */
export const ONE_CLICK_DRIVERS = new Set<DriverId>(["one_click", "menu_fill", "smart_fill"]);

/** The account a successful sign-in on `site` must be for: the scenario's own (account profiles), else the site's (undefined when the flow has none). */
function expectedUser(site: Site, s?: Scenario): string | undefined {
  if (s?.account) return s.account.username;
  return site.flow === "sso" ? site.sso?.email : site.account?.username;
}

/** Whether the scenario reached its goal: the right sign-in, or the form accepted. */
function goalMet(site: Site, events: LabEvent[], s?: Scenario): boolean {
  if (FORM_FLOWS.has(site.flow)) {
    return events.some((e) => e.kind === "submit" && e.host === site.host && e.form === site.flow && e.ok);
  }
  return events.some((e) => e.kind === "signin" && e.host === site.host && rightSignin(site, e, s));
}

function rightSignin(site: Site, e: Extract<LabEvent, { kind: "signin" }>, s?: Scenario): boolean {
  const want = expectedUser(site, s);
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

/** `all` without the fields the vault must leave empty: a shipping block hidden behind "same as billing", the birth country, a loyalty program it lacks. */
function owed(site: Site, all: readonly Site["fields"][number][]): Site["fields"] {
  return all.filter((f) => !(f.block === "shipping" && site.forms?.shippingSame) && f.role !== "birth_country"
    && !(f.role === "loyalty_number" && site.forms?.loyaltyTitle === undefined));
}

/**
 * The fields a first fill left empty because they were off screen (`offScreen`, by name: too little of them in the
 * viewport): personal data goes only into fields the user can see (security review M4), so the user scrolls to
 * them and fills again. An empty field that was on screen is a miss, never a target; passengers 2 and later are
 * the user's own.
 */
export function foldTargets(site: Site, filled: Readonly<Record<string, boolean>>, offScreen: ReadonlySet<string>): Site["fields"] {
  return owed(site, site.fields).filter((f) => (f.person ?? 0) === 0 && filled[f.name] !== true && offScreen.has(f.name));
}

/** Whether every field the scenario's page(s) asked for held a value after the fill (abandons_step: step 1 only). */
function fillMet(s: Scenario, site: Site, o: Observation): boolean {
  const all = s.behaviour === "abandons_step" && site.steps ? site.steps[0]! : site.fields;
  const fields = owed(site, all);
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
  // Account profiles: the site's other account went in (the relying party takes the meant one only).
  if (o.otherAccount) return "wrong_account";
  // A locked start that ended on "OnePass is locked": nothing the user could pick.
  if (o.lockedShown && !o.itemOffered) return "locked";
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
function wrongAccount(site: Site, events: LabEvent[], s?: Scenario): boolean {
  const want = expectedUser(site, s);
  if (want === undefined) return false;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  return events.some((e) => e.kind === "signin" && hosts.has(e.host) && e.user.trim().toLowerCase() !== want.trim().toLowerCase());
}

/**
 * A field of passenger 2 or later (another person than the vault's) held a value in the snapshot of
 * the fill (spec 11.4). The drivers take that snapshot before the user types those passengers.
 */
function otherPersonFilled(site: Site, o: Observation): boolean {
  return site.fields.some((f) => (f.person ?? 0) > 0 && o.filled[f.name] === true);
}

/** A post of the site (or its frame) before the user sent the form, on a flow that is not a sign-in. */
function autoSubmitOutsideLogin(site: Site, o: Observation): boolean {
  if (LOGIN_FAMILY.has(site.flow)) return false;
  const hosts = new Set([site.host, site.frameHost].filter((h): h is string => h !== undefined));
  const userAt = o.userSubmitAt ?? Number.POSITIVE_INFINITY;
  return o.events.some((e) => (e.kind === "submit" || e.kind === "signin") && hosts.has(e.host) && e.at < userAt);
}

/** Variants that expect the save card, never an automatic save (spec 4.3, 5.1, 5.3). */
const CARD_VARIANTS = new Set(["update_card", "no_username", "spa_stays", "private_window"]);

/**
 * Cause a save_typed scenario missed its goal for, undefined when met. A locked vault turns the automatic
 * variants into the card (spec 4.3). A card variant that saved anything saved without a gesture.
 */
function saveCause(s: Scenario, o: Observation): string | undefined {
  const saved = (o.savedLogins ?? 0) > 0;
  const v = s.variant;
  if (v === "failed_login") return saved ? "save_unexpected" : undefined;
  if (CARD_VARIANTS.has(v ?? "") || s.start === "locked") {
    if (saved || o.autoSaved === true) return "save_unexpected";
    return o.cardShown === true ? undefined : "card_expected";
  }
  return saved && o.autoSaved === true ? undefined : "save_missing";
}

/** Cause a ghost scenario missed its goal for, undefined when met. */
function ghostCause(s: Scenario, o: Observation): string | undefined {
  switch (s.variant) {
    case "accept_tab": case "accept_click":
      if (o.ghostShown !== true) return "no_ghost";
      return o.ghostAccepted === true ? undefined : "ghost_not_accepted";
    case "ignore_typing":
      if (o.ghostShown !== true) return "no_ghost";
      return o.ghostAccepted === true ? "ghost_accepted_unasked" : undefined;
    default: // menu_arrow and the fallbacks: the menu opened.
      return o.menuOpened === true ? undefined : "no_menu";
  }
}

export function judge(s: Scenario, site: Site, o: Observation, check?: FillCheck): Judgement {
  const leak = o.events.find((e): e is Extract<LabEvent, { kind: "leak" }> => e.kind === "leak");
  if (leak) return { verdict: "leak", cause: `leak:${leak.secret}:${leak.field}@${leak.host}` };
  if (o.skipped !== undefined) return { verdict: "skipped", cause: o.skipped };
  // A save on a failed sign-in, and a password in the page's DOM, fail whatever the expectation says.
  if (o.failedSignIn === true && o.autoSaved === true) return { verdict: "fail", cause: "auto_saved_on_failure" };
  if (o.ghostInPageDom === true) return { verdict: "fail", cause: "ghost_in_page_dom" };
  if (autoSubmitOutsideLogin(site, o)) return { verdict: "fail", cause: "auto_submit_outside_login" };
  if ((o.foreign?.length ?? 0) > 0 || wrongAccount(site, o.events, s)) return { verdict: "fail", cause: "wrong_item" };
  if (otherPersonFilled(site, o)) return { verdict: "fail", cause: "other_person_filled" };
  if (o.error !== undefined && (o.error.startsWith("lab:") || o.error.includes("rate_limited"))) {
    return { verdict: "lab_error", cause: o.error };
  }
  if (o.error !== undefined) return { verdict: "fail", cause: `driver_error:${shortError(o.error)}` };
  if (s.driver === "ghost" || s.driver === "save_typed") {
    const cause = s.driver === "ghost" ? ghostCause(s, o) : saveCause(s, o);
    if (s.expect === "xfail") return cause === undefined ? { verdict: "xpass" } : { verdict: "xfail", cause };
    return cause === undefined ? { verdict: "pass" } : { verdict: "fail", cause };
  }
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
  const met = behaving ? fillMet(s, site, o) && wrong.length === 0 : goalMet(site, o.events, s);
  const cause = (): string => (behaving && wrong.length > 0 && fillMet(s, site, o) ? "wrong_fill" : failCause(site, o));
  if (s.expect === "xfail") return met ? { verdict: "xpass" } : { verdict: "xfail", cause: cause() };
  return met ? { verdict: "pass" } : { verdict: "fail", cause: cause() };
}

/**
 * Whether the scenario met its goal with one gesture toward OnePass: the
 * overlay's account, or the field icon whose plan did the rest. Opening the
 * in-field menu and picking its row are two gestures. The user's own typing
 * and own press on the form's button are not counted. Undefined for the
 * scenarios without a goal (nofill, lookalike, bench control).
 */
export function oneClickOf(s: Scenario, verdict: Verdict, o: Observation): boolean | undefined {
  if (!ONE_CLICK_DRIVERS.has(s.driver) || s.expect === "nofill" || verdict === "lab_error" || verdict === "skipped") return undefined;
  const met = verdict === "pass" || verdict === "flaky" || verdict === "xpass";
  return met && o.clicks === 1;
}

/**
 * Whether the oracle saw the scenario's session: the right account signed in
 * on the site, on a verdict that met the goal (a leak or a safety failure with
 * a session is no success). Undefined where there is none to see: the form
 * flows, the scenarios without a goal, a bench error, a skipped start state.
 */
export function signedInOf(s: Scenario, site: Site, verdict: Verdict, o: Observation): boolean | undefined {
  if (!ONE_CLICK_DRIVERS.has(s.driver) || s.expect === "nofill" || verdict === "lab_error" || verdict === "skipped") return undefined;
  if (flowFamily(site.flow) === undefined) return undefined;
  const met = verdict === "pass" || verdict === "flaky" || verdict === "xpass";
  return met && o.events.some((e) => e.kind === "signin" && e.host === site.host && rightSignin(site, e, s));
}

/** The gesture fields of a result (gestures.ts), from the attempt the verdict stands on. */
export function resultGestures(s: Scenario, site: Site, verdict: Verdict, o: Observation): GestureFields {
  const trigger = o.trigger ?? triggerOf(s.driver, { shortcut: s.shortcut === true, hasField: site.fields.length > 0 });
  return gestureFields(o.gestures ?? [], signedInOf(s, site, verdict, o), s.start ?? "unlocked_warm", trigger);
}

/** Causes that are safety failures: never replayed, never hidden by a replay. */
export const SAFETY_CAUSES = new Set(["wrong_item", "auto_submit_outside_login", "other_person_filled", "auto_saved_on_failure"]);

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
