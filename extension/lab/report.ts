// Report of an autofill lab run (spec 8): folds the per-scenario Results into
// rates and renders a French Markdown report. Results carry field names, hosts
// and verdicts, never a value, so neither does the report. Type-only import:
// this module runs under `node --experimental-strip-types` through cli.ts.
// Since the gesture accounting, the report also has "one gesture, signed in"
// by start state, trigger and flow family (results that store their gestures),
// the account profiles' stated outcomes, and the scenarios skipped for a
// missing host control. Skipped results are out of every older number.
import { START_STATES, type StartState, type Trigger } from "./gen/model.ts";
import { ACCOUNT_OUTCOME, type Profile } from "./gen/population.ts";
import { type FlowFamily, flowFamily } from "./run/gestures.ts";
import type { Result } from "./run/oracle.ts";

export interface Rate {
  total: number; pass: number; fail: number; leak: number; xfail: number; xpass: number; flaky: number; labError: number;
  /** (pass + flaky) over total minus xfail, xpass and lab_error; 1 when nothing counts. */
  rate: number;
}

/** One-click success of a driver group: goal met with one gesture, over the scenarios with a goal. */
export interface OneClickRate { total: number; ok: number; rate: number }
/** The current drivers (overlay for sign-ins, in-field menu for forms) against smart_fill. */
export interface OneClickPair { current: OneClickRate; smart_fill: OneClickRate }

/** One cell of "one gesture, signed in": the measured scenarios of a start state, a trigger and a flow family. */
export interface OneGestureCell {
  start: StartState; trigger: Trigger; family: FlowFamily;
  /** Scenarios whose goal is a session, measured (no bench error, not skipped). */
  total: number;
  /** The oracle saw the session, whatever the gestures. */
  signedIn: number;
  /** Signed in with exactly one deliberate gesture. */
  ok: number;
  /** Of `ok`, those that also took an unlock approval (+1 biometric). */
  biometric: number;
}

/** What an account profile's scenarios did from one start state with one trigger (measured ones only). */
export interface AccountRow { profile: string; start: StartState; trigger: Trigger; total: number; signedIn: number; oneGesture: number; wrongAccount: number }

export interface Summary {
  /** "One gesture, signed in" cells, account profiles apart in `accounts` (empty for a run from before the gesture accounting). */
  oneGesture: OneGestureCell[];
  /** Whether any result stores its gestures. */
  hasGestures: boolean;
  /** Scenarios whose start state could not be set up: out of every rate. */
  skipped: Result[];
  /** Account profiles (results that state an outcome), by profile. */
  accounts: AccountRow[];
  overall: Rate;
  byFlow: Record<string, Rate>;
  byTrait: Record<string, Rate>;
  byLang: Record<string, Rate>;
  byDriver: Record<string, Rate>;
  /** Simulated user (population.ts); results without a profile belong to the default one, "p0". */
  byProfile: Record<string, Rate>;
  /** The bench self-check (driver passkey_control, no extension): out of every rate above but byDriver. */
  control: Rate;
  /** fail, leak and lab_error verdicts of the bench self-check. */
  controlFailures: Result[];
  /** fail and leak verdicts (bench self-check excluded). */
  failures: Result[];
  /** leak verdicts of every driver. */
  leaks: Result[];
  /** xfail and xpass verdicts. */
  expected: Result[];
  flaky: Result[];
  /** wrong_item failures (a value of another item, or another account signed in). */
  wrongItem: Result[];
  /** auto_submit_outside_login failures (OnePass sent a form whose true intent is not a sign-in). */
  autoSubmitOutsideLogin: Result[];
  /** other_person_filled failures (a passenger 2 or later filled by the extension). */
  otherPersonFilled: Result[];
  /** One-click success per flow, current drivers against smart_fill. */
  oneClick: Record<string, OneClickPair>;
  oneClickTotal: OneClickPair;
  /** Goal met per flow, any number of gestures, over the same scenarios as the one-click rates. */
  goalMet: Record<string, OneClickPair>;
  goalMetTotal: OneClickPair;
}

function emptyRate(): Rate {
  return { total: 0, pass: 0, fail: 0, leak: 0, xfail: 0, xpass: 0, flaky: 0, labError: 0, rate: 1 };
}

function add(r: Rate, v: Result["verdict"]): void {
  r.total++;
  switch (v) {
    case "pass": r.pass++; break;
    case "fail": r.fail++; break;
    case "leak": r.leak++; break;
    case "xfail": r.xfail++; break;
    case "xpass": r.xpass++; break;
    case "flaky": r.flaky++; break;
    case "lab_error": r.labError++; break;
  }
}

function finish(r: Rate): Rate {
  const counted = r.total - r.xfail - r.xpass - r.labError;
  r.rate = counted > 0 ? (r.pass + r.flaky) / counted : 1;
  return r;
}

function group(results: Result[], keys: (r: Result) => string[]): Record<string, Rate> {
  const out: Record<string, Rate> = {};
  for (const r of results) {
    for (const k of new Set(keys(r))) add((out[k] ??= emptyRate()), r.verdict);
  }
  for (const k of Object.keys(out)) finish(out[k]!);
  return out;
}

/** Results in (site, driver) order: batches finish in any order, the report must not. */
function bySiteDriver(results: Result[]): Result[] {
  return [...results].sort((a, b) => a.site - b.site || a.driver.localeCompare(b.driver));
}

/** The bench self-check driver: proves the lab's relying party, measures nothing of the extension. */
export const CONTROL_DRIVER = "passkey_control";

const emptyOneClick = (): OneClickPair => ({ current: { total: 0, ok: 0, rate: 0 }, smart_fill: { total: 0, ok: 0, rate: 0 } });

const MET = new Set<Result["verdict"]>(["pass", "flaky", "xpass"]);

/** Per flow and in total, current against smart_fill: `ok` counts the results `hit` accepts. */
function pairRates(results: Result[], hit: (r: Result) => boolean): { byFlow: Record<string, OneClickPair>; total: OneClickPair } {
  const byFlow: Record<string, OneClickPair> = {};
  const total = emptyOneClick();
  for (const r of results) {
    if (r.oneClick === undefined) continue;
    const side = r.driver === "smart_fill" ? "smart_fill" : "current";
    for (const pair of [(byFlow[r.flow] ??= emptyOneClick()), total]) {
      pair[side].total++;
      if (hit(r)) pair[side].ok++;
    }
  }
  for (const pair of [...Object.values(byFlow), total]) {
    for (const x of [pair.current, pair.smart_fill]) x.rate = x.total > 0 ? x.ok / x.total : 0;
  }
  return { byFlow, total };
}

/**
 * The run is red on any leak, any wrong item, any auto-submit outside a sign-in (spec 10) and any other person filled (spec 11.4),
 * and when every scenario is a lab error, since such a run measured nothing.
 */
export function isRed(s: Summary): boolean {
  const benchFailed = s.overall.total > 0 && s.overall.labError === s.overall.total;
  return s.leaks.length > 0 || s.wrongItem.length > 0 || s.autoSubmitOutsideLogin.length > 0 || s.otherPersonFilled.length > 0 || benchFailed;
}

/** The "one gesture, signed in" cells of the results that store their gestures and have a session to see. */
function oneGestureCells(results: Result[]): OneGestureCell[] {
  const cells = new Map<string, OneGestureCell>();
  for (const r of results) {
    const family = flowFamily(r.flow);
    if (family === undefined || r.signedIn === undefined || r.gestures === undefined || r.trigger === undefined) continue;
    const start = r.startState ?? "unlocked_warm";
    const key = `${start}|${r.trigger}|${family}`;
    let c = cells.get(key);
    if (!c) cells.set(key, (c = { start, trigger: r.trigger, family, total: 0, signedIn: 0, ok: 0, biometric: 0 }));
    c.total++;
    if (r.signedIn) c.signedIn++;
    if (r.oneGesture === true) {
      c.ok++;
      if ((r.biometric ?? 0) > 0) c.biometric++;
    }
  }
  return [...cells.values()];
}

function accountRows(results: Result[]): AccountRow[] {
  const rows = new Map<string, AccountRow>();
  for (const r of results) {
    if (r.outcome === undefined || r.signedIn === undefined || r.trigger === undefined) continue;
    const id = r.profile ?? "p0";
    const start = r.startState ?? "unlocked_warm";
    const key = `${id}|${start}|${r.trigger}`;
    let row = rows.get(key);
    if (!row) rows.set(key, (row = { profile: id, start, trigger: r.trigger, total: 0, signedIn: 0, oneGesture: 0, wrongAccount: 0 }));
    row.total++;
    if (r.signedIn) row.signedIn++;
    if (r.oneGesture) row.oneGesture++;
    if (r.cause === "wrong_account" || r.cause === "wrong_item") row.wrongAccount++;
  }
  const order = (a: AccountRow) => `${a.profile}|${START_STATES.indexOf(a.start)}|${a.trigger}`;
  return [...rows.values()].sort((a, b) => order(a).localeCompare(order(b)));
}

export function summarize(every: Result[]): Summary {
  // A skipped scenario was not played: it is in no rate and no table but its own list.
  const all = every.filter((r) => r.verdict !== "skipped");
  const results = all.filter((r) => r.driver !== CONTROL_DRIVER);
  const checks = all.filter((r) => r.driver === CONTROL_DRIVER);
  const overall = emptyRate();
  for (const r of results) add(overall, r.verdict);
  finish(overall);
  const control = emptyRate();
  for (const r of checks) add(control, r.verdict);
  finish(control);
  const oneClick = pairRates(results, (r) => r.oneClick === true);
  const goalMet = pairRates(results, (r) => MET.has(r.verdict));
  return {
    // A site with several accounts is another question: those results have their own table.
    oneGesture: oneGestureCells(results.filter((r) => r.outcome === undefined)),
    hasGestures: results.some((r) => r.gestures !== undefined),
    skipped: bySiteDriver(every.filter((r) => r.verdict === "skipped")),
    accounts: accountRows(results),
    overall,
    byFlow: group(results, (r) => [r.flow]),
    // A site with several traits counts once under each of them.
    byTrait: group(results, (r) => (r.traits.length > 0 ? r.traits : ["(aucun)"])),
    byLang: group(results, (r) => [r.lang]),
    byDriver: group(all, (r) => [r.driver]),
    byProfile: group(results, (r) => [r.profile ?? "p0"]),
    control,
    controlFailures: bySiteDriver(checks.filter((r) => r.verdict === "fail" || r.verdict === "leak" || r.verdict === "lab_error")),
    failures: bySiteDriver(results.filter((r) => r.verdict === "fail" || r.verdict === "leak")),
    // Every leak, the bench self-check's included: a leak is never out of the count.
    leaks: bySiteDriver(all.filter((r) => r.verdict === "leak")),
    expected: bySiteDriver(results.filter((r) => r.verdict === "xfail" || r.verdict === "xpass")),
    flaky: bySiteDriver(results.filter((r) => r.verdict === "flaky")),
    wrongItem: bySiteDriver(all.filter((r) => r.cause === "wrong_item")),
    autoSubmitOutsideLogin: bySiteDriver(all.filter((r) => r.cause === "auto_submit_outside_login")),
    otherPersonFilled: bySiteDriver(all.filter((r) => r.cause === "other_person_filled")),
    oneClick: oneClick.byFlow,
    oneClickTotal: oneClick.total,
    goalMet: goalMet.byFlow,
    goalMetTotal: goalMet.total,
  };
}

const pct = (x: number): string => `${(x * 100).toFixed(1)} %`;

function table(title: string, by: Record<string, Rate>): string[] {
  const rows = Object.entries(by).sort(([a], [b]) => a.localeCompare(b));
  const out = [`### ${title}`, "", "| Clé | Total | Réussis | Échecs | Fuites | Attendus | Inattendus | Instables | Erreurs labo | Taux |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"];
  for (const [k, r] of rows) {
    out.push(`| ${k} | ${r.total} | ${r.pass} | ${r.fail} | ${r.leak} | ${r.xfail} | ${r.xpass} | ${r.flaky} | ${r.labError} | ${pct(r.rate)} |`);
  }
  return [...out, ""];
}

const ratio = (x: OneClickRate): string => (x.total > 0 ? `${x.ok}/${x.total} (${pct(x.rate)})` : "sans scénario");

function oneClickTable(s: Summary): string[] {
  const rows = Object.entries(s.oneClick).sort(([a], [b]) => a.localeCompare(b));
  if (rows.length === 0) return ["Aucun scénario avec un but dans ce passage.", ""];
  const out = [
    "But atteint avec un seul geste vers OnePass : le compte de l'overlay, ou l'icône du champ dont le plan fait le reste. Ouvrir le menu du champ puis choisir sa ligne fait deux gestes. La frappe de l'utilisateur et son propre appui sur le bouton du formulaire ne comptent pas. Hors scénarios sans but (rien à remplir, sosies, contrôle du banc) et erreurs du labo.",
    "",
    "| Flux | Actuel (overlay, menu) | smart_fill |",
    "| --- | --- | --- |",
  ];
  for (const [flow, p] of rows) out.push(`| ${flow} | ${ratio(p.current)} | ${ratio(p.smart_fill)} |`);
  out.push(`| Total | ${ratio(s.oneClickTotal.current)} | ${ratio(s.oneClickTotal.smart_fill)} |`, "");
  out.push(
    "### But atteint, quel que soit le nombre de gestes",
    "",
    "Mêmes scénarios, but atteint (réussis, instables, réussites inattendues) : le menu des formulaires compte ici comme le plan.",
    "",
    "| Flux | Actuel (overlay, menu) | smart_fill |",
    "| --- | --- | --- |",
  );
  for (const [flow, p] of Object.entries(s.goalMet).sort(([a], [b]) => a.localeCompare(b))) {
    out.push(`| ${flow} | ${ratio(p.current)} | ${ratio(p.smart_fill)} |`);
  }
  out.push(`| Total | ${ratio(s.goalMetTotal.current)} | ${ratio(s.goalMetTotal.smart_fill)} |`, "");
  return out;
}

const START_FR: Record<StartState, string> = { unlocked_warm: "déverrouillé, hôte en marche", locked: "verrouillé", cold: "hôte arrêté" };
const TRIGGER_FR: Record<Trigger, string> = {
  field_icon: "icône du champ", overlay_row: "compte de l'overlay", shortcut: "raccourci clavier",
  toolbar: "bouton de la barre d'outils", menu_key: "menu du champ (flèche bas)",
};
/** The triggers every table shows, measured or not; the two others only when a scenario used them. */
const MAIN_TRIGGERS: readonly Trigger[] = ["field_icon", "overlay_row", "shortcut"];
const OTHER_TRIGGERS: readonly Trigger[] = ["toolbar", "menu_key"];
const FAMILIES: readonly FlowFamily[] = ["password", "totp", "passkey", "sso", "multi_step", "signup"];

/** "ok/total (rate)", with the unlock approvals of the successes apart. */
function gestureCell(cells: OneGestureCell[]): string {
  const total = cells.reduce((n, c) => n + c.total, 0);
  if (total === 0) return "sans scénario";
  const ok = cells.reduce((n, c) => n + c.ok, 0);
  const bio = cells.reduce((n, c) => n + c.biometric, 0);
  return `${ok}/${total} (${pct(ok / total)})${bio > 0 ? `, +1 biométrie : ${bio}` : ""}`;
}

/** "One gesture, signed in" by start state, trigger and flow family. */
function oneGestureTable(s: Summary): string[] {
  if (!s.hasGestures) return ["Ce passage date d'avant le comptage des gestes : ses résultats ne disent pas combien de gestes chaque scénario a demandés.", ""];
  const out = [
    "Connecté (l'oracle a vu la session du bon compte sur le site) avec exactement un geste délibéré. Chaque geste compte : l'icône, une ligne ou le raccourci de OnePass, le bouton de déverrouillage, un choix dans une liste, et aussi l'appui de l'utilisateur sur le bouton du site et chaque champ qu'il tape. L'approbation du déverrouillage (Touch ID, jouée par le banc) est comptée à part : « +1 biométrie » dit combien de réussites en ont eu besoin. Seuls les flux dont le but est une session, hors scénarios sans but, erreurs du labo et scénarios sautés ; les profils à plusieurs comptes par site ont leur tableau plus bas. « Réussite en un clic » ci-dessus garde son ancien calcul, où l'appui sur le bouton du site ne comptait pas.",
    "",
    `| État de départ | Déclencheur | ${FAMILIES.join(" | ")} | Total |`,
    `| --- | --- | ${FAMILIES.map(() => "---").join(" | ")} | --- |`,
  ];
  const pick = (start: StartState, trigger: Trigger, family?: FlowFamily) =>
    s.oneGesture.filter((c) => c.start === start && c.trigger === trigger && (family === undefined || c.family === family));
  const rows: [StartState, Trigger][] = [];
  for (const start of START_STATES) {
    for (const trigger of [...MAIN_TRIGGERS, ...OTHER_TRIGGERS]) {
      if (MAIN_TRIGGERS.includes(trigger) || pick(start, trigger).length > 0) rows.push([start, trigger]);
    }
  }
  for (const [start, trigger] of rows) {
    out.push(`| ${START_FR[start]} | ${TRIGGER_FR[trigger]} | ${FAMILIES.map((f) => gestureCell(pick(start, trigger, f))).join(" | ")} | ${gestureCell(pick(start, trigger))} |`);
  }
  out.push("", "### Connecté, quel que soit le nombre de gestes", "", "| État de départ | Déclencheur | Connectés | En un geste |", "| --- | --- | --- | --- |");
  for (const [start, trigger] of rows) {
    const cells = pick(start, trigger);
    const total = cells.reduce((n, c) => n + c.total, 0);
    if (total === 0) continue;
    const signedIn = cells.reduce((n, c) => n + c.signedIn, 0);
    const ok = cells.reduce((n, c) => n + c.ok, 0);
    out.push(`| ${START_FR[start]} | ${TRIGGER_FR[trigger]} | ${signedIn}/${total} (${pct(signedIn / total)}) | ${ok}/${total} (${pct(ok / total)}) |`);
  }
  out.push("");
  if (s.accounts.length > 0) {
    out.push("### Plusieurs comptes sur un site", "", "Le résultat attendu de chaque profil est écrit sous « Par profil ».", "",
      "| Profil | État de départ | Déclencheur | Scénarios mesurés | Connectés | En un geste | Mauvais compte |", "| --- | --- | --- | --- | --- | --- | --- |");
    for (const a of s.accounts) out.push(`| ${a.profile} | ${START_FR[a.start]} | ${TRIGGER_FR[a.trigger]} | ${a.total} | ${a.signedIn} | ${a.oneGesture} | ${a.wrongAccount} |`);
    out.push("");
  }
  return out;
}

const BEHAVIOUR_FR: Record<Profile["behaviour"], string> = {
  complete: "va au bout", partial: "vide un champ rempli avant d'envoyer", corrects_field: "corrige un champ rempli avant d'envoyer",
  abandons_step: "abandonne après la première étape",
};

/** What each profile is, in one line (nothing when the world has the single default profile). */
function profileLines(profiles: Profile[] | undefined): string[] {
  if (!profiles || profiles.length === 0) return [];
  const out = ["Profils simulés (l'oracle juge le remplissage de l'extension, jamais la correction de l'utilisateur) :", ""];
  for (const p of profiles) {
    // An account profile is its stated outcome (population.ts), not a drawn vault.
    if (p.accounts) {
      out.push(`- ${p.id} : ${ACCOUNT_OUTCOME[p.accounts]}`);
      continue;
    }
    const vault = p.vaultSize === 0 ? "coffre vide" : p.vaultSize === 1 ? "coffre du monde seul" : `coffre de ${p.vaultSize} éléments`;
    const extras = [p.duplicates > 0 ? `${p.duplicates} doublon(s)` : "", p.multiAccount ? "plusieurs comptes par site" : ""].filter(Boolean);
    out.push(`- ${p.id} : ${[vault, ...extras, `pays ${p.country}, langue ${p.lang}`, BEHAVIOUR_FR[p.behaviour]].join(", ")}`);
  }
  return [...out, ""];
}

function scenarioLine(r: Result): string {
  const traits = r.traits.length > 0 ? r.traits.join(", ") : "aucun";
  return `- site ${r.site} (${r.flow}, ${r.driver}, traits : ${traits}, langue ${r.lang}) : ${r.cause ?? "sans cause"}. Rejeu : \`${r.repro}\``;
}

function countBy<T>(items: T[], key: (t: T) => string): [string, T[]][] {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    m.set(k, [...(m.get(k) ?? []), it]);
  }
  return [...m.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}

export function renderReport(world: { seed: string; sites: number; profiles?: Profile[] }, s: Summary, meta: { date?: string; commit?: string; durationMin?: number }): string {
  const o = s.overall;
  const l: string[] = [];
  l.push(`# Rapport du laboratoire d'autofill`, "");
  l.push(`- Graine du monde : \`${world.seed}\``, `- Date : ${meta.date ?? "inconnue"}`, `- Commit : ${meta.commit !== undefined ? `\`${meta.commit}\`` : "inconnu"}`, `- Durée : ${meta.durationMin !== undefined ? `${meta.durationMin} min` : "inconnue"}`, "");
  l.push("## Résumé", "");
  l.push(`- Sites : ${world.sites}`, `- Scénarios : ${o.total} (plus ${s.control.total} de contrôle du banc, comptés à part)`);
  l.push(`- Taux de réussite global (hors attendus, inattendus et erreurs du labo) : ${pct(o.rate)}`);
  l.push(`- Réussis : ${o.pass}, échecs : ${o.fail}, instables : ${o.flaky}, échecs attendus : ${o.xfail}, réussites inattendues : ${o.xpass}, erreurs du labo : ${o.labError}`);
  const leaks = s.leaks.length;
  l.push(`- Fuites : ${leaks}${leaks > 0 ? " (le passage est rouge)" : ""}`);
  const wrong = s.wrongItem.length;
  l.push(`- Mauvais élément (\`wrong_item\`) : ${wrong}${wrong > 0 ? " (le passage est rouge)" : ""}`);
  const auto = s.autoSubmitOutsideLogin.length;
  l.push(`- Envois automatiques hors connexion (\`auto_submit_outside_login\`) : ${auto}${auto > 0 ? " (le passage est rouge)" : ""}`);
  const other = s.otherPersonFilled.length;
  l.push(`- Autre personne remplie (\`other_person_filled\`) : ${other}${other > 0 ? " (le passage est rouge)" : ""}`, "");
  l.push("## Réussite en un clic", "", ...oneClickTable(s));
  l.push("## Un geste, connecté", "", ...oneGestureTable(s));
  l.push("## Taux de réussite", "");
  l.push(...table("Par flux", s.byFlow), ...table("Par trait", s.byTrait), ...table("Par langue", s.byLang), ...table("Par pilote", s.byDriver), ...table("Par profil", s.byProfile), ...profileLines(world.profiles));

  l.push("## Contrôle du banc", "");
  const c = s.control;
  if (c.total === 0) l.push("Aucun scénario de contrôle dans ce passage.", "");
  else {
    l.push("Scénarios `passkey_control` : sans l'extension, l'authentificateur virtuel de Chromium tient la clé du site et la RP du labo doit accepter l'assertion. Hors des taux ci-dessus (sauf par pilote).", "");
    l.push(`- Scénarios : ${c.total}, réussis : ${c.pass}, échecs : ${c.fail}, instables : ${c.flaky}, erreurs du labo : ${c.labError}`, "");
    if (s.controlFailures.length === 0) l.push("Aucun échec : la RP du labo vérifie les passkeys comme prévu.", "");
    else l.push("Échecs du contrôle (défaut du banc à corriger avant de lire les échecs passkey) :", "", ...s.controlFailures.map(scenarioLine), "");
  }

  l.push("## Échecs", "");
  const fails = s.failures.filter((r) => r.verdict === "fail");
  if (fails.length === 0) l.push("Aucun.", "");
  else l.push(...fails.map(scenarioLine), "");

  l.push("## Réussites inattendues", "");
  const xpass = s.expected.filter((r) => r.verdict === "xpass");
  if (xpass.length === 0) l.push("Aucune.", "");
  else l.push("Une capacité attendue manquante est arrivée : retirer l'attente d'échec correspondante.", "", ...xpass.map(scenarioLine), "");

  l.push("## Ce que l'extension ne fait pas encore", "");
  const xfail = s.expected.filter((r) => r.verdict === "xfail");
  if (xfail.length === 0) l.push("Aucun échec attendu dans ce passage.", "");
  else {
    l.push("Échecs attendus, regroupés par raison documentée (à défaut, par cause) :", "");
    for (const [cause, rs] of countBy(xfail, (r) => r.reason ?? r.cause ?? "sans cause")) {
      const flows = [...new Set(rs.map((r) => r.flow))].sort().join(", ");
      const traits = [...new Set(rs.flatMap((r) => r.traits))].sort().join(", ") || "aucun";
      l.push(`- ${cause} : ${rs.length} scénario(s), flux : ${flows}, traits : ${traits}`);
    }
    l.push("");
  }
  if (fails.length > 0) {
    l.push("Causes d'échec récurrentes (hors attendus) :", "");
    for (const [cause, rs] of countBy(fails, (r) => r.cause ?? "sans cause")) l.push(`- ${cause} : ${rs.length} scénario(s)`);
    l.push("");
  }

  l.push("## Fuites", "");
  if (s.leaks.length === 0) l.push("Aucune.", "");
  else l.push(...s.leaks.map(scenarioLine), "");

  l.push("## Mauvais élément rempli", "");
  if (s.wrongItem.length === 0) l.push("Aucun.", "");
  else l.push(...s.wrongItem.map(scenarioLine), "");

  l.push("## Envois automatiques hors connexion", "");
  if (s.autoSubmitOutsideLogin.length === 0) l.push("Aucun.", "");
  else l.push(...s.autoSubmitOutsideLogin.map(scenarioLine), "");

  l.push("## Autre personne remplie", "");
  if (s.otherPersonFilled.length === 0) l.push("Aucune.", "");
  else l.push(...s.otherPersonFilled.map(scenarioLine), "");

  l.push("## Instables", "");
  if (s.flaky.length === 0) l.push("Aucun.", "");
  else l.push("Réussis au second essai, en profil neuf :", "", ...s.flaky.map(scenarioLine), "");
  if (s.skipped.length > 0) {
    l.push("## Scénarios sautés", "", "L'état de départ n'a pas pu être mis en place : rien n'a été joué, et ces scénarios ne sont dans aucun taux.", "");
    for (const [cause, rs] of countBy(s.skipped, (r) => r.cause ?? "sans cause")) {
      const starts = [...new Set(rs.map((r) => r.startState ?? "unlocked_warm"))].sort().join(", ");
      l.push(`- ${cause} : ${rs.length} scénario(s), état de départ : ${starts}`);
    }
    l.push("");
  }
  return l.join("\n");
}
