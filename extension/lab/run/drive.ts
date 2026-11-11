// Scenario drivers of the autofill lab (spec 7.3, 7.4): each one plays a
// scenario the way a user would and returns an Observation for the oracle,
// never a verdict. one_click goes through the real overlay and the sign-in
// chain, menu_fill through the in-field menu (trusted ArrowDown) and the
// site's submit button, smart_fill through a trusted click on the field's
// OnePass icon (the toolbar Fill when the page has no field) and whatever the
// plan does next (chain, fill, menu), lookalike opens the trap copy and looks
// for the real site's item, passkey_control proves the bench's WebAuthn
// relying party with Chromium's virtual authenticator and no extension.
// Every driver counts its gestures toward OnePass (`clicks`), stamps the
// moment it sent the form itself (`userSubmitAt`), and reports which fields
// held another vault item's value (`foreign`, names only: values read in the
// page stay in the driver's memory). The autofill itself is
// reached only through the Driver interface (driver.ts). Driver steps that
// the page cannot satisfy are recorded as observations; only bench failures
// (navigation to a lab host, browser launch, host rate limit) carry `lab:`.
// Gestures (gestures.ts): every driver also records each human-equivalent
// gesture it makes, the user's own press on the site's button and the fields
// she types included, so that a result can say how many it took. `clicks`
// keeps its older meaning (gestures toward OnePass only).
// Start states (start-state.ts): from a locked vault or a stopped host the
// state is set up when the user arrives and checked again right before her
// gesture. The gesture itself asks the app to unlock (or to start): the menu
// or the card then waits and goes on by itself, one gesture plus the
// stand-in's approval, added to the gestures as a biometric. Only the menu's
// fallback button ("Déverrouiller dans OnePass", "Ouvrir OnePass") is one
// more gesture.
// Account profiles (population.ts): the driver looks for the account the
// user means (the overlay's other logins when it is not on the pill) and,
// when that account was used last on the site, first makes that site memory
// by one earlier OnePass sign-in, outside the measured gestures.
import type { Frame, Page } from "@playwright/test";
import { CASE_PATH, caseMismatches, type CountryCase } from "../gen/cases.ts";
import { passkeyPkcs8 } from "../gen/data.ts";
import type { Expect, FieldSpec, Scenario, Site, StartState, World } from "../gen/model.ts";
import type { Behaviour } from "../gen/population.ts";
import { PAGE_PATH, stepPath } from "../gen/render.ts";
import type { LabEvent } from "../server/ledger.ts";
import type { LabServer } from "../server/server.ts";
import { focusField, type PlainBrowser, shadowField, sleep } from "./browser.ts";
import type { Driver, MenuOutcome } from "./driver.ts";
import { Gestures, insertApprovals, triggerOf } from "./gestures.ts";
import { lacks } from "./host-control.ts";
import { foreignFields } from "./items.ts";
import type { StartControl } from "./start-state.ts";
import { smartTarget } from "./target.ts";
import { foldTargets, type Observation } from "./oracle.ts";

/** What a scenario runs against: the autofill under test, the lab server, a fresh tab. */
export interface ScenarioEnv {
  driver: Driver;
  server: LabServer;
  world: World;
  newPage(): Promise<Page>;
  /** Start-state control of the profile (absent: only the historical start can be played). */
  start?: StartControl;
  /** Account profiles: the identifier of the site's other account, the one the user does not mean. */
  otherUser?: string;
}

const OVERLAY_WAIT_MS = 15_000;
/** After a scroll: the content script's layout pass and its icons follow. */
const ICON_MOVE_SETTLE_MS = 600;
const CHAIN_WAIT_MS = 60_000;
const LOOKALIKE_WAIT_MS = 5_000;
/** The menu row of the password generator (signup). */
export const GENERATE_ROW = "Générer un mot de passe";

/** CSS selector of an element id (generated ids may start with a digit). */
const byId = (id: string) => `[id="${id.replace(/["\\]/g, "\\$&")}"]`;

function blank(driver: Observation["driver"]): Observation {
  return { driver, overlayShown: false, itemOffered: false, events: [], filled: {}, values: {}, clicks: 0, gestures: [], durationMs: 0 };
}

/** The gesture recorder of an observation (its list is the observation's). */
function recorder(o: Observation): Gestures {
  const g = new Gestures();
  o.gestures = g.list;
  return g;
}

const startOf = (s: Scenario | undefined): StartState => s?.start ?? "unlocked_warm";

/** The attempts whose start state was set up (only those have unlock approvals to read at the end). */
const arrived = new WeakSet<Observation>();

/** Sets the scenario's start state up as the user arrives; false (and `o.skipped`) when the host cannot be put in it. */
async function arrive(env: ScenarioEnv, s: Scenario | undefined, o: Observation): Promise<boolean> {
  const start = startOf(s);
  if (start === "unlocked_warm") return true;
  const why = env.start ? await env.start.arrive(start) : lacks("stop", "this run has no start-state control");
  if (why !== undefined) o.skipped = why;
  else arrived.add(o);
  return why === undefined;
}

/** beforeGesture as the step a driver runs right before its click: throws when the start state cannot be held (`o.skipped` says why). */
const gateOf = (env: ScenarioEnv, s: Scenario | undefined, o: Observation) => async (): Promise<void> => {
  if (!(await beforeGesture(env, s, o))) throw new Error("lab: the start state did not hold");
};

/** Right before the user's gesture: a cold start stops the host again if the page load started it. */
async function beforeGesture(env: ScenarioEnv, s: Scenario | undefined, o: Observation): Promise<boolean> {
  const start = startOf(s);
  if (start === "unlocked_warm" || !env.start) return true;
  const why = await env.start.beforeGesture(start);
  if (why !== undefined) o.skipped = why;
  return why === undefined;
}

function message(e: unknown): string {
  return ((e as Error)?.message ?? String(e)).split("\n")[0] ?? "error";
}

async function goto(page: Page, url: string): Promise<void> {
  try {
    await page.goto(url);
  } catch (e) {
    throw new Error(`lab: navigation to ${url} failed: ${message(e)}`);
  }
}

/**
 * Which of the site's fields hold a value, in every frame of the page (open
 * shadow roots directly, a closed one through its page hook `__labField`).
 * Split OTP cells count for their field. ORed into `acc`, so a value seen
 * once stays seen. `values` (driver memory only, never in an Observation)
 * keeps the last non-empty value of each field it can read.
 */
async function snapshotFilled(page: Page, site: Site, acc: Record<string, boolean>, values?: Record<string, string>): Promise<void> {
  const fields = site.fields.map((f) => ({ id: f.id, name: f.name }));
  for (const f of fields) acc[f.name] ??= false;
  for (const frame of page.frames()) {
    if (frame.url().startsWith("chrome-extension://")) continue;
    const seen = await frame.evaluate((list) => {
      const roots: (Document | ShadowRoot)[] = [document];
      for (let k = 0; k < roots.length; k++) {
        for (const el of roots[k]!.querySelectorAll("*")) if (el.shadowRoot) roots.push(el.shadowRoot);
      }
      const hook = (window as unknown as { __labField?: (sel: string) => { filled: boolean } | null }).__labField;
      const read = (id: string): string | undefined => {
        const sel = `[id="${id.replace(/["\\]/g, "\\$&")}"]`;
        for (const r of roots) {
          const el = r.querySelector(sel) as HTMLInputElement | null;
          // A radio or a checkbox holds a value only once checked.
          if (el && (el.type === "radio" || el.type === "checkbox") && !el.checked) continue;
          if (el && "value" in el && el.value !== "") return el.value;
        }
        return undefined;
      };
      // A radio group (forms flows): its fieldset carries the field id, its radios "<id>-<k>".
      const radio = (id: string): string | undefined => {
        for (let k = 1; k <= 8; k++) {
          const v = read(`${id}-${k}`);
          if (v !== undefined) return v;
        }
        return undefined;
      };
      const value = (id: string) => read(id) !== undefined || hook?.(`[id="${id.replace(/["\\]/g, "\\$&")}"]`)?.filled === true;
      return list.filter((f) => value(f.id) || [1, 2, 3, 4, 5, 6].some((k) => value(`${f.id}-${k}`)))
        .map((f) => [f.name, read(f.id) ?? radio(f.id) ?? ""] as [string, string]);
    }, fields).catch(() => [] as [string, string][]);
    for (const [name, v] of seen) {
      acc[name] = true;
      if (values && v !== "") values[name] = v;
    }
  }
}

/** The frame holding the site's form: its /frame document for framed sites, else the top document. */
async function formScope(page: Page, site: Site): Promise<Frame> {
  if (!site.traits.includes("iframe_same_origin") && !site.traits.includes("iframe_cross_site")) return page.mainFrame();
  const end = Date.now() + 10_000;
  for (;;) {
    const f = page.frames().find((x) => x !== page.mainFrame() && !x.url().startsWith("chrome-extension://")
      && x.url().includes(PAGE_PATH.frame));
    if (f) return f;
    if (Date.now() >= end) return page.mainFrame();
    await sleep(200);
  }
}

/** Waits until `pred` holds over the server events, or `ms` elapse. */
async function waitEvents(server: LabServer, pred: (e: LabEvent[]) => boolean, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end && !pred(server.events())) await sleep(200);
}

const signedIn = (site: Site) => (es: LabEvent[]) => es.some((e) => e.kind === "signin" && e.host === site.host);
const submitted = (site: Site) => (es: LabEvent[]) =>
  es.some((e) => (e.kind === "submit" || e.kind === "signin") && (e.host === site.host || e.host === site.frameHost));

/** Whether the site of the running scenario signed anyone in (any site: the server holds one scenario's events). */
const signedInAny = (env: ScenarioEnv): boolean => env.server.events().some((e) => e.kind === "signin");

/** LAB_DEBUG: the page as the driver left it (screenshot, URL, extension frame text) under <LAB_DEBUG>/. */
async function debugDump(page: Page, o: Observation): Promise<void> {
  const dir = process.env.LAB_DEBUG;
  if (!dir) return;
  const name = `${o.driver}-${Date.now()}`;
  await page.screenshot({ path: `${dir}/${name}.png`, fullPage: true }).catch(() => undefined);
  const frames: string[] = [];
  for (const f of page.frames()) {
    const text = f.url().startsWith("chrome-extension://") ? await f.locator("body").innerText({ timeout: 1_000 }).catch(() => "") : "";
    frames.push(`${f.url()} ${text.replace(/\s+/g, " ").slice(0, 300)}`);
  }
  console.log(`[lab debug] ${name} url=${page.url()}\n  ${frames.join("\n  ")}`);
}

/** After the page closes, how long requests still in flight get to reach the server before its events are read. */
const LATE_GRACE_MS = 500;

/** The fields of `site` holding another item's value (names), from the values the driver read. */
function foreign(env: ScenarioEnv, site: Site, o: Observation, values: Record<string, string>): void {
  o.foreign = foreignFields(env.world, site, values, o.typed ?? []);
  // Account profiles: the identifier that went in is the site's other account.
  const id = site.fields.find((f) => f.role === "username" || f.role === "email");
  const got = id ? values[id.name] : undefined;
  if (env.otherUser !== undefined && got !== undefined && got.trim().toLowerCase() === env.otherUser.trim().toLowerCase()) o.otherAccount = true;
}

/** The unlock approvals of a locked start, added to the gestures where they happened (gestures.ts insertApprovals). */
async function recordUnlock(env: ScenarioEnv, s: Scenario | undefined, o: Observation): Promise<void> {
  const start = startOf(s);
  if (start === "unlocked_warm" || !env.start || !arrived.has(o)) return;
  const done = await env.start.finish(start).catch(() => ({ approvals: 0 } as { approvals: number; unlock?: "instant" | "deferred" }));
  if (o.skipped !== undefined) return;
  if (done.unlock) o.unlock = done.unlock;
  insertApprovals((o.gestures ??= []), done.approvals, Date.now());
}

async function finish(env: ScenarioEnv, page: Page | undefined, o: Observation, started: number, s?: Scenario): Promise<Observation> {
  if (page && o.error === undefined && (await env.driver.rateLimited(page).catch(() => false))) o.error = "lab: rate_limited";
  if (page && startOf(s) === "locked" && !o.itemOffered) o.lockedShown = await env.driver.lockedShown(page).catch(() => false);
  if (process.env.LAB_DEBUG && startOf(s) !== "unlocked_warm" && !signedInAny(env) && env.driver.debugState) {
    console.log(`[lab debug] state ${o.driver}@${startOf(s)}:\n    ${await env.driver.debugState().catch((e: unknown) => `unreadable: ${message(e)}`)}`);
  }
  await recordUnlock(env, s, o);
  if (page) await debugDump(page, o);
  o.durationMs = Date.now() - started;
  // Read the events last: a late post (a leak) must not be lost to the next scenario's reset.
  await page?.close().catch(() => undefined);
  await sleep(LATE_GRACE_MS);
  o.events = env.server.events();
  return o;
}

/** one_click: the one-click UI's sign-in with the site's item, then the sign-in progress to its end. */
export async function oneClick(env: ScenarioEnv, site: Site, s?: Scenario): Promise<Observation> {
  let started = Date.now();
  const o = blank("one_click");
  const g = recorder(o);
  o.trigger = "overlay_row";
  const values: Record<string, string> = {};
  const title = s?.account?.title ?? site.itemTitle;
  let page: Page | undefined;
  try {
    if (!(await prime(env, site, s, o))) return finish(env, undefined, o, started, s);
    started = Date.now();
    if (!(await arrive(env, s, o))) return finish(env, undefined, o, started, s);
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    if (site.passkeyOnly && startOf(s) === "locked") {
      // A locked arrival on a passkey-only page: the generic card (the page reads as a sign-in), its
      // one button unlocks, then OnePass presses the site's passkey button and signs. No card: as below.
      const card = await env.driver.openOneClick(page, OVERLAY_WAIT_MS);
      if (card && (await card.generic())) {
        o.overlayShown = true;
        await env.driver.pickGeneric(card, gateOf(env, s, o));
        g.add("overlay_row");
        o.clicks = 1;
        await waitEvents(env.server, signedIn(site), GENERIC_WAIT_MS);
        o.itemOffered = signedIn(site)(env.server.events());
        foreign(env, site, o, values);
        return finish(env, page, o, started, s);
      }
    }
    if (site.passkeyOnly) {
      if (!(await beforeGesture(env, s, o))) return finish(env, page, o, started, s);
      // Nothing to fill: the user presses the site's passkey button and picks her account in OnePass's window.
      const r = await passkeyStep(env, page, site, o, g);
      o.overlayShown = r.asked;
      o.itemOffered = r.offered;
      foreign(env, site, o, values);
      return finish(env, page, o, started, s);
    }
    const ui = await env.driver.openOneClick(page, OVERLAY_WAIT_MS);
    o.overlayShown = ui !== undefined;
    // A locked arrival: the card names nobody (the vault cannot say who matches).
    const generic = ui !== undefined && startOf(s) === "locked" && (await ui.generic());
    if (ui && title && !generic) o.itemOffered = await ui.offers(title);
    const since = Date.now();
    const waits = startOf(s) !== "unlocked_warm";
    if (ui && generic) {
      // Its one button is the gesture: OnePass unlocks, then signs in by itself, or asks who in the menu.
      await env.driver.pickGeneric(ui, gateOf(env, s, o));
      g.add("overlay_row");
      o.clicks = 1;
      const next = await afterGeneric(env, page, site, since);
      o.itemOffered = next === "chain";
      if (next === "menu" && title) {
        const menu = env.driver.menuFrame(page);
        o.itemOffered = menu !== undefined && (await env.driver.menuOffers(menu, title));
        if (menu && o.itemOffered) {
          await env.driver.menuPick(menu, title);
          g.add("menu_row");
          o.clicks = 2;
        }
      }
      if (o.itemOffered) await followChain(env, page, site, o, values, g, since, waits);
      else await snapshotFilled(page, site, o.filled, values);
    } else if (ui && title && o.itemOffered) {
      await env.driver.pickAccount(ui, title, gateOf(env, s, o));
      g.add("overlay_row");
      o.clicks = 1;
      await followChain(env, page, site, o, values, g, since, waits);
    } else if (ui && title && s?.account) {
      // Her account is not the one on the pill. With exactly two logins it hangs under it: one gesture.
      // With more she opens the other logins and picks it there (two gestures).
      if (!(await beforeGesture(env, s, o))) return finish(env, page, o, started, s);
      if (await env.driver.pickSecond(ui, title)) {
        g.add("picker");
        o.itemOffered = true;
        o.clicks = 1;
        await followChain(env, page, site, o, values, g, since, waits);
      } else if (await env.driver.openOthers(ui)) {
        g.add("picker_open");
        if (await env.driver.otherOffers(ui, title)) {
          await env.driver.pickOther(ui, title);
          g.add("picker");
          o.itemOffered = true;
          o.clicks = 2;
          await followChain(env, page, site, o, values, g, since, waits);
        }
      }
      if (!o.itemOffered) await snapshotFilled(page, site, o.filled, values);
    } else {
      await snapshotFilled(page, site, o.filled, values);
    }
  } catch (e) {
    o.error = message(e);
  }
  foreign(env, site, o, values);
  return finish(env, page, o, started, s);
}

/** How long the generic card's click gets to lead somewhere: the unlock (approved by the stand-in), then the plan. */
const GENERIC_WAIT_MS = 30_000;

/** What the generic card's click led to, first seen: a chain of this site started after `since`, or the menu with rows. */
async function afterGeneric(env: ScenarioEnv, page: Page, site: Site, since: number): Promise<"chain" | "menu" | "nothing"> {
  const end = Date.now() + GENERIC_WAIT_MS;
  while (Date.now() < end) {
    const c = await env.driver.progress(site.host).catch(() => null);
    if (c && (c.startedAt ?? 0) >= since) return "chain";
    const menu = env.driver.menuFrame(page);
    if (menu && (await env.driver.menuHasRows(menu).catch(() => false))) return "menu";
    await sleep(300);
  }
  return "nothing";
}

/** After the priming sign-in reports done: time for its site memory note to reach the host. */
const PRIME_NOTE_MS = 1_500;

/**
 * Account profile "used last on this site": the site memory is made the way
 * a user makes it, by one earlier OnePass sign-in with the account she means
 * (the overlay; the other logins when it is not on the pill), then a
 * sign-out. Outside the measured gestures. False (and a `lab:` error: the
 * scenario's premise does not hold) when that sign-in did not happen.
 */
async function prime(env: ScenarioEnv, site: Site, s: Scenario | undefined, o: Observation): Promise<boolean> {
  const account = s?.account;
  if (!account?.lastUsed || s?.expect === "nofill") return true;
  let page: Page | undefined;
  let why: string | undefined;
  try {
    // The user made that memory on an ordinary day: an open vault and a running host, whatever this scenario starts from.
    if (startOf(s) !== "unlocked_warm" && !(await env.start?.reset())) throw new Error("the host did not come back unlocked");
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    const ui = await env.driver.openOneClick(page, OVERLAY_WAIT_MS);
    if (!ui) why = "no overlay";
    else if (await ui.offers(account.title, 3_000)) await env.driver.pickAccount(ui, account.title);
    else if (await env.driver.pickSecond(ui, account.title)) why = undefined;
    else if ((await env.driver.openOthers(ui)) && (await env.driver.otherOffers(ui, account.title))) await env.driver.pickOther(ui, account.title);
    else why = "account not offered";
    if (why === undefined) {
      const seen = blank("one_click");
      await followChain(env, page, site, seen, {}, recorder(seen));
      const user = account.username.trim().toLowerCase();
      const ok = env.server.events().some((e) => e.kind === "signin" && e.host === site.host && e.user.trim().toLowerCase() === user);
      if (!ok) why = `no sign-in (chain ${seen.chain?.status ?? "none"}${seen.chain?.reason ? `:${seen.chain.reason}` : ""})`;
    }
    if (why === undefined) {
      await sleep(PRIME_NOTE_MS);
      await page.goto(`https://${site.host}/logout`).catch(() => undefined);
    }
  } catch (e) {
    why = message(e);
  } finally {
    await page?.close().catch(() => undefined);
    // The measured attempt starts from a clean log and no session; the vault and the meant account stay.
    env.server.rewind();
  }
  if (why !== undefined) o.error = `lab: priming sign-in failed (${why.replace(/^lab: /, "")})`;
  return why === undefined;
}

/** Follows a sign-in chain of `site` to its end (or CHAIN_WAIT_MS), reading the fields on the way. */
/**
 * `since`: only a chain started from then on is this attempt's (an earlier one of the same site, the priming
 * sign-in, is not). `waits`: from a locked or cold start a chain stopped as `locked` is waiting for the unlock
 * the gesture asked and goes on by itself; it is followed until it does.
 */
async function followChain(env: ScenarioEnv, page: Page, site: Site, o: Observation, values: Record<string, string>, g: Gestures,
  since = 0, waits = false): Promise<void> {
      const end = Date.now() + CHAIN_WAIT_MS;
      for (;;) {
        await snapshotFilled(page, site, o.filled, values);
        const latest = await env.driver.progress(site.host);
        const c = latest && (latest.startedAt === undefined || latest.startedAt >= since) ? latest : null;
        if (c) o.chain = c;
        // Password then passkey: the site now asks for the passkey, the user presses its button (below).
        const passkeyAsked = site.flow === "login_passkey" && (await passkeyButton(page, 0)) !== undefined;
        const waiting = waits && c !== null && c.status !== "running" && c.reason === "locked";
        if ((c && c.status !== "running" && !waiting) || passkeyAsked || Date.now() >= end) {
          if (process.env.LAB_DEBUG) console.log(`[lab debug] progress ${JSON.stringify(c)} at ${page.url()}`);
          break;
        }
        await sleep(500);
      }
      if (site.flow === "login_passkey" && !signedIn(site)(env.server.events())) {
        await passkeyStep(env, page, site, o, g);
        const c = await env.driver.progress(site.host);
        if (c) o.chain = c;
      }
      // The last post can still be in flight when the chain reports done.
      await waitEvents(env.server, signedIn(site), 3_000);
}

/** How long the site's passkey button gets to open OnePass's window (none opens while the chain signs itself). */
const PASSKEY_WINDOW_MS = 8_000;

/**
 * The passkey step of a login_passkey site, as the user plays it: she
 * presses the site's passkey button, then picks her account if OnePass's
 * window asks (one more gesture). During her one-click sign-in the
 * extension signs for the chain's item without a window. Waits for the
 * site's sign-in or its refusal of the assertion.
 */
async function passkeyStep(env: ScenarioEnv, page: Page, site: Site, o: Observation, g: Gestures): Promise<{ asked: boolean; offered: boolean }> {
  const button = await passkeyButton(page, fieldWait(site));
  if (!button || !site.account) return { asked: false, offered: false };
  const press = () => {
    g.add("site_button", "passkey");
    return button.click({ timeout: 10_000 });
  };
  const r = await env.driver.passkey(press, site.account.username, PASSKEY_WINDOW_MS);
  if (r.picked) {
    o.clicks = (o.clicks ?? 0) + 1;
    g.add("picker", "passkey");
  }
  const end = Date.now() + 15_000;
  while (Date.now() < end && !signedIn(site)(env.server.events())) {
    if (env.server.events().some((e) => e.kind === "submit" && e.form === "passkey" && !e.ok)) break;
    await sleep(200);
  }
  return { asked: r.asked, offered: r.offered };
}

/**
 * The fields the menu is tried in, in order, and the menu row picked there.
 * The extension offers its menu on some roles only (a card form opens it from
 * the number, not the cardholder name): like a user, the driver moves on to
 * the next field of the form when the first one offers no menu.
 */
function menuTarget(site: Site): { fields: FieldSpec[]; title: string | undefined } {
  if (site.flow === "signup") return { fields: site.fields.filter((f) => f.role === "new_password").slice(0, 1), title: GENERATE_ROW };
  const title = site.cardTitle ?? site.identityTitle ?? site.itemTitle;
  // A forms page: the first passenger's (driver's, contact's) given name first, then the others in page order.
  const first = site.forms ? site.fields.find((f) => f.role === "given_name" && (f.person ?? 0) === 0) : undefined;
  return { fields: first ? [first, ...site.fields.filter((f) => f !== first)] : site.fields, title };
}

/**
 * The user fills passengers 2 and later herself (forms flows, spec 11.4):
 * after the snapshot of the fill, a made-up value in each of their fields
 * (the first radio, the first real option of a list), listed in `typed`.
 */
async function userTypesPersons(page: Page, scope: Frame, site: Site, o: Observation, g: Gestures): Promise<void> {
  const others = site.fields.filter((f) => (f.person ?? 0) > 0);
  for (const f of others) {
    o.typed = [...(o.typed ?? []), f.name];
    g.add("site_type", f.name);
    if (f.render?.choice?.kind === "radio") {
      await scope.locator(byId(`${f.id}-1`)).first().check({ timeout: 5_000 }).catch(() => undefined);
    } else if (f.type === "select" || f.render?.date?.kind === "part" && f.render.date.select) {
      await scope.locator(byId(f.id)).first().selectOption({ index: 1 }, { timeout: 5_000 }).catch(() => undefined);
    } else {
      // A date input takes ISO only (a browser drops anything else), a part a number, a text date its written form.
      const d = f.render?.date;
      const v = f.type === "email" ? "voyageur@lab.test" : d?.kind === "input" || f.type === "date" ? "1990-01-01" : d?.kind === "part" ? (d.part === "year" ? "1990" : "1") : d ? "01/01/1990" : "Lab";
      await typeField(page, scope, f.id, v, 5_000).catch(() => undefined);
    }
  }
}

/** How long a field of `site` may take to show: its delayed_fields delay plus a margin. */
const fieldWait = (site: Site): number => (site.delayMs ?? 0) + 10_000;

/**
 * Types `value` into the field `id` of `scope` (the form's frame) as a user
 * would: through its locator, or (closed shadow root) by clicking the box its
 * page hook reports (offset by the frame) and typing. Waits up to `timeoutMs`
 * for a delayed field.
 */
async function typeField(page: Page, scope: Frame, id: string, value: string, timeoutMs = 10_000): Promise<void> {
  const sel = byId(id);
  const field = scope.locator(sel).first();
  const end = Date.now() + timeoutMs;
  for (;;) {
    if ((await field.count().catch(() => 0)) > 0) {
      await field.fill(value, { timeout: Math.max(1, end - Date.now()) });
      return;
    }
    const box = await shadowField(scope, sel);
    if (box && box.width > 0 && box.height > 0) {
      await focusField(page, scope, sel, 1_000);
      await page.keyboard.type(value);
      return;
    }
    if (Date.now() >= end) throw new Error(`no field ${id}`);
    await sleep(200);
  }
}

/**
 * Submits the form as a user would: its submit button; else (closed shadow
 * root) the page hook that submits the shadow form through its own handler
 * (which copies the values to the light-DOM relay); else (button hidden, as
 * before the password step is revealed) the form itself.
 */
async function submitForm(scope: Frame): Promise<void> {
  const button = scope.locator(byId("lab-submit")).first();
  if (await button.isVisible().catch(() => false)) {
    await button.click({ timeout: 5_000 });
    return;
  }
  await scope.evaluate(() => {
    const hook = (window as unknown as { __labSubmit?: () => void }).__labSubmit;
    if (hook) hook();
    else (document.getElementById("lab-form") as HTMLFormElement | null)?.submit();
  });
}

/**
 * What the simulated user does to the form after the extension filled it
 * (profile behaviour): "partial" empties the last text field, "corrects_field"
 * retypes the first one. The snapshot of the fill is taken before, and the
 * oracle judges that snapshot: this edit is the user's, not the extension's.
 * A failed edit is not a scenario error (the field may be a select or hidden).
 */
async function userEdits(page: Page, scope: Frame, fields: FieldSpec[], behaviour: Behaviour, g: Gestures): Promise<void> {
  const text = fields.filter((f) => f.type !== "select");
  const target = behaviour === "partial" ? text.at(-1) : behaviour === "corrects_field" ? text[0] : undefined;
  if (!target) return;
  g.add("site_type", target.name);
  await typeField(page, scope, target.id, behaviour === "partial" ? "" : "corrected-by-user", 2_000).catch(() => undefined);
}

/**
 * multi_step: on each page in turn, the menu on that step's fields, the item
 * picked, then its button ("next" before the last step). Stops at the first
 * step whose menu does not offer the item (the oracle reads no_menu or
 * no_menu_item), or when the next page does not come (a refusal the oracle
 * reads from the server events). The flags hold only if every step reached
 * showed the menu and offered the item. Under a behaviour, the user edits
 * the last step after the fill; abandons_step stops after step 1 (nothing is
 * submitted, the oracle judges step 1 only).
 */
async function menuFillSteps(env: ScenarioEnv, page: Page, scope: Frame, site: Site, o: Observation, behaviour: Behaviour, g: Gestures,
  s?: Scenario): Promise<void> {
  const steps = site.steps!;
  const since = Date.now();
  for (const [k, step] of steps.entries()) {
    if (k > 0 && !(await waitPath(scope, stepPath(k), 10_000))) return;
    if (k === 0 && startOf(s) !== "unlocked_warm") {
      await fieldShown(page, scope, step[0]?.id, fieldWait(site));
      if (!(await beforeGesture(env, s, o))) return;
    }
    const menu = await menuStep(env, page, scope, step.map((f) => byId(f.id)), site.itemTitle, g, k === 0 ? s : undefined);
    o.overlayShown = menu.shown && (k === 0 || o.overlayShown);
    o.itemOffered = menu.offered && (k === 0 || o.itemOffered);
    await snapshotFilled(page, site, o.filled, o.values);
    if (!menu.offered) return;
    if (behaviour === "abandons_step") return;
    if (k === steps.length - 1) await userEdits(page, scope, step, behaviour, g);
    // The user sends the step: stamped at the first one (anything the site
    // got before is OnePass's). Later steps follow the user's own post, so
    // one stamp cannot tell an extension post of a later step from hers.
    o.userSubmitAt ??= Date.now();
    if (await userMustSubmit(env, site, since)) g.add("site_submit");
    await submitForm(scope).catch(() => undefined);
  }
  await waitEvents(env.server, signedIn(site), 10_000);
}

/** Rows of a field the extension's rule calls perceivable (content/detect/visibility.ts PERCEIVABLE_MIN_PX). */
const SEEN_MIN_PX = 10;

/** Where the fields of `site` sit in the form's frame: the names with fewer than SEEN_MIN_PX rows on screen, and the names wholly on screen. */
async function onScreen(scope: Frame, site: Site): Promise<{ hidden: Set<string>; whole: Set<string> }> {
  const look = () => scope.evaluate(({ list, min }) => {
    const hidden: string[] = [];
    const whole: string[] = [];
    let missing = 0;
    // A closed shadow root hides its fields from the document: the page hook gives their box (render-forms.ts).
    const hook = (window as unknown as { __labField?: (sel: string) => { x: number; y: number; width: number; height: number } | null }).__labField;
    const boxOf = (id: string): { top: number; bottom: number; height: number } | undefined => {
      const r = document.getElementById(id)?.getBoundingClientRect();
      if (r) return r;
      const h = hook?.(`[id="${id.replace(/["\\]/g, "\\$&")}"]`);
      return h ? { top: h.y, bottom: h.y + h.height, height: h.height } : undefined;
    };
    for (const f of list) {
      const b = boxOf(f.id);
      if (!b || b.height === 0) {
        missing++;
        continue;
      }
      const seen = Math.min(b.bottom, window.innerHeight) - Math.max(b.top, 0);
      if (seen < min) hidden.push(f.name);
      else if (b.top >= 0 && b.bottom <= window.innerHeight) whole.push(f.name);
    }
    return { hidden, whole, missing };
  }, { list: site.fields.map((f) => ({ id: f.id, name: f.name })), min: SEEN_MIN_PX }).catch(() => ({ hidden: [] as string[], whole: [] as string[], missing: 1 }));
  // A page that redraws its form (spa_rerender) has no field for a moment: looked at again, a few times.
  let r = await look();
  for (let k = 0; k < RERENDER_LOOKS && r.missing > 0; k++) {
    await sleep(300);
    r = await look();
  }
  return { hidden: new Set(r.hidden), whole: new Set(r.whole) };
}

/** Looks given to a form being redrawn before its fields are read as they are. */
const RERENDER_LOOKS = 5;
/** How many times the user scrolls on and fills again before she gives up on a long form. */
const FOLD_ROUNDS = 3;
/** Fields tried for the menu after a scroll (the menu opens from the fields carrying the OnePass icon only). */
const FOLD_MENU_TRIES = 4;

/**
 * A forms page longer than the screen: the extension writes personal data only into the fields on
 * screen (security review M4). Like a user, scroll down just enough to see the last field the fold
 * hid, and ask the menu again from a field still on screen: two more gestures a round. The menu
 * fields are tried in page order among those wholly on screen (focusing another would scroll back).
 * A field left empty while on screen is never asked again (the oracle reads it as a wrong fill),
 * and a form whose icon fields leave the screen before its last fields show stays unfilled.
 */
async function fillBelowFold(env: ScenarioEnv, page: Page, scope: Frame, site: Site, o: Observation, g: Gestures,
  title: string | undefined, values: Record<string, string>): Promise<void> {
  for (let round = 0; round < FOLD_ROUNDS; round++) {
    const targets = foldTargets(site, o.filled, (await onScreen(scope, site)).hidden);
    const last = targets.at(-1);
    if (process.env.LAB_DEBUG) console.log(`[lab debug] fold round ${round} site ${site.index}: ${targets.length} field(s) off screen and empty`);
    if (!last) return;
    await scope.evaluate((id) => {
      const hook = (window as unknown as { __labField?: (sel: string) => { y: number; height: number } | null }).__labField;
      const r = document.getElementById(id)?.getBoundingClientRect();
      const h = r ? undefined : hook?.(`[id="${id.replace(/["\\]/g, "\\$&")}"]`);
      const bottom = r ? r.bottom : h ? h.y + h.height : undefined;
      if (bottom !== undefined) window.scrollBy(0, bottom + 24 - window.innerHeight);
    }, last.id).catch(() => undefined);
    await sleep(ICON_MOVE_SETTLE_MS);
    const { whole } = await onScreen(scope, site);
    const from = site.fields.filter((f) => (f.person ?? 0) === 0 && whole.has(f.name) && o.filled[f.name] === true).slice(0, FOLD_MENU_TRIES);
    if (process.env.LAB_DEBUG) console.log(`[lab debug] fold round ${round} site ${site.index}: menu asked from ${from.length} field(s) on screen`);
    if (from.length === 0) return;
    const menu = await menuStep(env, page, scope, from.map((f) => byId(f.id)), title, g);
    if (!menu.offered) return;
    o.clicks = (o.clicks ?? 0) + 2;
    await snapshotFilled(page, site, o.filled, values);
  }
}

/** menu_fill: focus the first field offering the menu, ArrowDown, pick the item, then (as the profile's behaviour says) submit. */
export async function menuFill(env: ScenarioEnv, site: Site, behaviour: Behaviour = "complete", s?: Scenario): Promise<Observation> {
  const started = Date.now();
  const o = blank("menu_fill");
  const g = recorder(o);
  o.trigger = "menu_key";
  const values: Record<string, string> = {};
  let page: Page | undefined;
  try {
    if (!(await arrive(env, s, o))) return finish(env, undefined, o, started, s);
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    const scope = await formScope(page, site);
    if (site.steps) {
      await menuFillSteps(env, page, scope, site, o, behaviour, g, s);
      return finish(env, page, o, started, s);
    }
    const { fields, title } = menuTarget(site);
    if (site.flow === "signup") {
      // Typed by the user before asking for a generated password: never counted as an extension fill.
      const email = site.fields.find((f) => f.role === "email" || f.role === "username");
      if (email && site.account) {
        o.typed = [email.name];
        g.add("site_type", email.name);
        await typeField(page, scope, email.id, site.account.username, fieldWait(site)).catch(() => undefined);
      }
    }
    if (startOf(s) !== "unlocked_warm") {
      await fieldShown(page, scope, fields[0]?.id, fieldWait(site));
      if (!(await beforeGesture(env, s, o))) return finish(env, page, o, started, s);
    }
    const since = Date.now();
    const menu = await menuStep(env, page, scope, fields.map((f) => byId(f.id)), s?.account?.title ?? title, g, s);
    o.overlayShown = menu.shown;
    o.itemOffered = menu.offered;
    // Two gestures: the menu opened from the field, then its row.
    o.clicks = (menu.shown ? 1 : 0) + (menu.offered ? 1 : 0);
    if (menu.offered) await debugDump(page, o);
    await snapshotFilled(page, site, o.filled, values);
    if (menu.offered && site.forms) await fillBelowFold(env, page, scope, site, o, g, s?.account?.title ?? title, values);
    await userTypesPersons(page, scope, site, o, g);
    // abandons_step has no step to abandon on a one-page form: the user goes on.
    if (behaviour === "partial" || behaviour === "corrects_field") await userEdits(page, scope, site.fields, behaviour, g);
    await userSubmit(env, page, scope, site, o, g, since);
  } catch (e) {
    o.error = message(e);
  }
  foreign(env, site, o, values);
  return finish(env, page, o, started, s);
}

/** Waits up to `ms` for the field `id` of `scope` to show (a delayed field, a closed shadow root through its hook). */
async function fieldShown(page: Page, scope: Frame, id: string | undefined, ms: number): Promise<boolean> {
  if (id === undefined) return false;
  const sel = byId(id);
  const end = Date.now() + ms;
  for (;;) {
    if (await scope.locator(sel).first().isVisible().catch(() => false)) return true;
    const box = await shadowField(scope, sel);
    if (box && box.width > 0 && box.height > 0) return true;
    if (Date.now() >= end || page.isClosed()) return false;
    await sleep(200);
  }
}

/** How long a menu gets to say it waits for the app, and an unlock (or a start of the app) to show its effect. */
const LOCKED_MENU_MS = 4_000;
const UNLOCK_WAIT_MS = 20_000;

/**
 * A menu opened from a locked or cold start. The gesture that opened it
 * already asked the app to unlock (or to start): the menu waits, the
 * stand-in approves, and OnePass goes on with the fill by itself, the menu
 * leaving ("resumed", no further gesture), or its rows come ("rows": the
 * user picks). Only when the menu falls back to its button (the app could
 * not be asked) does the user press it: one more gesture, once. "locked":
 * nothing opened in time. "open": the menu was an ordinary one.
 */
async function unlockFromMenu(env: ScenarioEnv, page: Page, menu: Frame, g: Gestures): Promise<"open" | "rows" | "resumed" | "locked"> {
  const says = Date.now() + LOCKED_MENU_MS;
  for (;;) {
    if (env.driver.menuFrame(page) === undefined) return "resumed";
    if ((await env.driver.menuUnlockState(menu)) !== undefined) break;
    if ((await env.driver.menuHasRows(menu)) || Date.now() >= says) return "open";
    await sleep(200);
  }
  const end = Date.now() + UNLOCK_WAIT_MS;
  let pressed = false;
  for (;;) {
    const now = env.driver.menuFrame(page);
    if (!now) return "resumed";
    if (await env.driver.menuHasRows(now)) return "rows";
    if (!pressed && (await env.driver.menuUnlockState(now)) === "button") {
      await env.driver.menuUnlock(now);
      g.add("unlock_button");
      pressed = true;
    }
    if (Date.now() >= end) return "locked";
    await sleep(200);
  }
}

/**
 * The in-field menu asked from the keyboard in the first of `selectors` that
 * offers one, and its row `title` picked. From a locked or cold start (`s`)
 * the menu first waits for the app (unlockFromMenu); when OnePass then goes
 * on by itself there is no row to pick and the item counts as offered.
 */
async function menuStep(env: ScenarioEnv, page: Page, scope: Frame, selectors: string[], title: string | undefined, g: Gestures,
  s?: Scenario): Promise<MenuOutcome> {
  g.add("menu_key");
  if (startOf(s) === "unlocked_warm") {
    const m = await env.driver.menuFill(page, scope, selectors, title, true);
    if (m.offered) g.add("menu_row");
    return m;
  }
  const menu = await env.driver.menuOpen(page, scope, selectors);
  if (!menu) return { shown: false, offered: false };
  if ((await unlockFromMenu(env, page, menu, g)) === "resumed") return { shown: true, offered: true };
  const now = env.driver.menuFrame(page);
  const offered = now !== undefined && title !== undefined && (await env.driver.menuOffers(now, title));
  if (now && title !== undefined && offered) {
    await env.driver.menuPick(now, title);
    g.add("menu_row");
    await sleep(1_500);
  } else {
    await page.keyboard.press("Escape");
  }
  return { shown: true, offered };
}

/**
 * Whether the user still has to send the form herself: not when the site
 * already signed her in, nor when a sign-in chain started since `since` is
 * doing it. Only the gesture count reads this; the drivers press as before.
 */
async function userMustSubmit(env: ScenarioEnv, site: Site, since: number): Promise<boolean> {
  if (signedIn(site)(env.server.events())) return false;
  const c = await env.driver.progress(site.host).catch(() => null);
  return !(c && (c.startedAt ?? 0) >= since);
}

/** The user sends the form: stamped first (anything the site got before is OnePass's), then its button. */
async function userSubmit(env: ScenarioEnv, page: Page, scope: Frame, site: Site, o: Observation, g: Gestures, since: number): Promise<void> {
  o.userSubmitAt = Date.now();
  if (await userMustSubmit(env, site, since)) g.add("site_submit");
  await submitForm(scope).catch(() => undefined);
  await waitEvents(env.server, submitted(site), 10_000);
  await waitEvents(env.server, signedIn(site), site.flow === "signup" ? 3_000 : 0);
}

/** How long smart_fill waits for the plan's first visible effect (chain, menu, a filled field). */
const SMART_WAIT_MS = 10_000;
/** After a first field fills: time for the plan's other groups. */
const SMART_SETTLE_MS = 1_500;
/** Before the keyboard command: the content script analyses 150 ms after a mutation burst (as ICON_SETTLE_MS in browser.ts). */
const SHORTCUT_SETTLE_MS = 900;
/** The menu row the user would pick for this site. */
const menuTitle = (site: Site): string | undefined =>
  site.flow === "signup" ? GENERATE_ROW : site.cardTitle ?? site.identityTitle ?? site.itemTitle;

type SmartOutcome = "chain" | "menu" | "filled" | "nothing";

/** What the click led to, first seen: a chain of this site started after `since`, the menu, or a filled field. */
async function smartOutcome(env: ScenarioEnv, page: Page, site: Site, o: Observation, values: Record<string, string>,
  since: number): Promise<SmartOutcome> {
  const end = Date.now() + SMART_WAIT_MS + (site.delayMs ?? 0);
  for (;;) {
    const c = await env.driver.progress(site.host);
    if (c && (c.startedAt ?? 0) >= since) return "chain";
    if (await env.driver.menuShown(page)) return "menu";
    await snapshotFilled(page, site, o.filled, values);
    const typed = new Set(o.typed ?? []);
    if (Object.entries(o.filled).some(([n, v]) => v && !typed.has(n))) {
      await sleep(SMART_SETTLE_MS);
      // A chain can start after its first fill shows (open_chain fills, then sends).
      const late = await env.driver.progress(site.host);
      if (late && (late.startedAt ?? 0) >= since) return "chain";
      await snapshotFilled(page, site, o.filled, values);
      return "filled";
    }
    if (Date.now() >= end) return "nothing";
    await sleep(300);
  }
}

/**
 * smart_fill (spec 8.2): one trusted click on the OnePass icon of the form's
 * field (the toolbar Fill when the page has none), then what the plan does.
 * Chain: followed to its end, OnePass sends. Fill: the user presses the
 * form's own button, as D2 wants for anything but a sign-in. Menu: a second
 * gesture, the site's row (never on a "nofill" scenario), then the user's
 * button. The signup email is typed by the user first, as in menu_fill.
 */
export async function smartFill(env: ScenarioEnv, site: Site, expectation: Expect, s?: Scenario): Promise<Observation> {
  let started = Date.now();
  const o = blank("smart_fill");
  const g = recorder(o);
  const target = smartTarget(site);
  const shortcut = s?.shortcut === true;
  o.trigger = triggerOf("smart_fill", { shortcut, hasField: target !== undefined });
  const values: Record<string, string> = {};
  let page: Page | undefined;
  try {
    if (shortcut && !(await env.driver.canShortcut())) {
      o.skipped = lacks("fill_smart_command", "the lab cannot run the extension's keyboard command in this browser");
      return finish(env, undefined, o, started, s);
    }
    if (!(await prime(env, site, s, o))) return finish(env, undefined, o, started, s);
    started = Date.now();
    if (!(await arrive(env, s, o))) return finish(env, undefined, o, started, s);
    page = await env.newPage();
    await goto(page, `https://${site.host}/`);
    const scope = await formScope(page, site);
    if (site.flow === "signup") {
      const email = site.fields.find((f) => f.role === "email" || f.role === "username");
      if (email && site.account) {
        o.typed = [email.name];
        g.add("site_type", email.name);
        await typeField(page, scope, email.id, site.account.username, fieldWait(site)).catch(() => undefined);
      }
    }
    if (shortcut || startOf(s) !== "unlocked_warm") {
      // The page as the user sees it before her gesture: its field shown and analysed (the icon path waits the same inside its click).
      await fieldShown(page, scope, target?.id, fieldWait(site));
      if (shortcut) await sleep(SHORTCUT_SETTLE_MS);
    }
    const since = Date.now();
    const waits = startOf(s) !== "unlocked_warm";
    // The start state is checked right before the gesture goes out (a cold start stops the host there).
    const gate = gateOf(env, s, o);
    if (shortcut) {
      await gate();
      await env.driver.shortcut(page);
    } else {
      await env.driver.smartFill(page, scope, target ? byId(target.id) : undefined, fieldWait(site), gate);
    }
    g.add(shortcut ? "shortcut" : target ? "field_icon" : "toolbar");
    o.clicks = 1;
    let outcome = await smartOutcome(env, page, site, o, values, since);
    if (outcome === "menu" && waits) {
      // The menu waits for the app (unlock asked by the gesture, or the app starting), then the plan goes on.
      const waiting = env.driver.menuFrame(page);
      const after = waiting ? await unlockFromMenu(env, page, waiting, g) : "open";
      if (after === "resumed") outcome = await smartOutcome(env, page, site, o, values, since);
    }
    if (process.env.LAB_DEBUG) console.log(`[lab debug] smart_fill outcome ${outcome}`);
    o.overlayShown = outcome !== "nothing";
    o.itemOffered = outcome === "chain" || outcome === "filled";
    if (outcome === "chain") {
      await followChain(env, page, site, o, values, g, since, waits);
    } else if (outcome === "menu") {
      const title = s?.account?.title ?? menuTitle(site);
      const menu = env.driver.menuFrame(page);
      const offered = menu !== undefined && title !== undefined && (await env.driver.menuOffers(menu, title));
      o.itemOffered = offered;
      if (offered && expectation !== "nofill") {
        await env.driver.menuPick(menu, title);
        g.add("menu_row");
        o.clicks = 2;
        await sleep(1_500);
        await snapshotFilled(page, site, o.filled, values);
        await userTypesPersons(page, scope, site, o, g);
        await userSubmit(env, page, scope, site, o, g, since);
      } else {
        await page.keyboard.press("Escape");
        await snapshotFilled(page, site, o.filled, values);
      }
    } else if (outcome === "filled") {
      if (expectation !== "nofill") {
        await userTypesPersons(page, scope, site, o, g);
        await userSubmit(env, page, scope, site, o, g, since);
      }
    }
    // A passkey-only page has nothing to fill: the user goes on with the site's passkey button.
    if (site.passkeyOnly && expectation !== "nofill" && !signedIn(site)(env.server.events())) {
      const r = await passkeyStep(env, page, site, o, g);
      o.overlayShown ||= r.asked;
      o.itemOffered ||= r.offered;
    }
  } catch (e) {
    o.error = message(e);
  }
  foreign(env, site, o, values);
  return finish(env, page, o, started, s);
}

/** lookalike: the trap copy must not get the real site's item; its form is then sent as it is. */
export async function lookalike(env: ScenarioEnv, site: Site): Promise<Observation> {
  const started = Date.now();
  const o = blank("lookalike");
  let page: Page | undefined;
  try {
    if (!site.lookalike) throw new Error("lab: the site has no lookalike host");
    page = await env.newPage();
    await goto(page, `https://${site.lookalike.host}/`);
    await sleep(LOOKALIKE_WAIT_MS);
    const ui = await env.driver.openOneClick(page, 0);
    o.overlayShown = ui !== undefined;
    if (ui && site.itemTitle) o.itemOffered = await ui.offers(site.itemTitle, 1_000);
    const first = site.fields.find((f) => f.role !== "otp");
    if (first) {
      const menu = await env.driver.menuFill(page, page.mainFrame(), [byId(first.id)], site.itemTitle, false, { first: 5_000, next: 0 });
      if (menu.shown) o.overlayShown = true;
      if (menu.offered) o.itemOffered = true;
    }
    await snapshotFilled(page, site, o.filled);
    o.userSubmitAt = Date.now();
    recorder(o).add("site_submit");
    await submitForm(page.mainFrame()).catch(() => undefined);
    await sleep(1_500);
  } catch (e) {
    o.error = message(e);
  }
  return finish(env, page, o, started);
}

const pathOf = (f: Frame): string => {
  try {
    return new URL(f.url()).pathname;
  } catch {
    return "";
  }
};

/** Waits until `scope` (top document or the form's frame) shows the page at `path`. */
async function waitPath(scope: Frame, path: string, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (pathOf(scope) !== path) {
    if (Date.now() >= end) return false;
    await sleep(200);
  }
  return true;
}

/** A refused post of the site (its host or its frame host) since the scenario began. */
const refused = (server: LabServer, site: Site) =>
  server.events().some((e) => e.kind === "submit" && !e.ok && (e.host === site.host || e.host === site.frameHost));

/**
 * Types the password step by hand (passkey control: no extension), in the
 * site's login style, where the other drivers reach the form: inside its
 * frame for framed sites, after its delay for delayed fields, through the
 * page hooks in a closed shadow root. Returns false when the RP refused a
 * step (the oracle then reads its refusal); throws `lab:` when the RP served
 * no next step.
 */
async function typePassword(page: Page, server: LabServer, site: Site): Promise<boolean> {
  const account = site.account!;
  const id = site.fields.find((f) => f.role === "username" || f.role === "email");
  const pw = site.fields.find((f) => f.role === "password");
  if (!id || !pw) throw new Error("lab: password-then-passkey site without identifier or password field");
  const scope = await formScope(page, site);
  await typeField(page, scope, id.id, account.username, fieldWait(site));
  if (site.loginStyle === "username_first") {
    await submitForm(scope);
    if (!(await waitPath(scope, PAGE_PATH.password, 10_000))) {
      if (refused(server, site)) return false;
      throw new Error(`lab: no password step after the identifier (at ${scope.url()})`);
    }
  } else if (site.loginStyle === "email_then_password") {
    const next = scope.locator(byId("lab-next")).first();
    // Out of reach in a closed shadow root: Enter in the identifier reveals the password step too.
    if ((await next.count()) > 0) await next.click();
    else await page.keyboard.press("Enter");
  }
  await typeField(page, scope, pw.id, account.password, fieldWait(site));
  await submitForm(scope);
  return true;
}

/** The passkey button of the page, in whichever frame the site shows it (framed sites: the frame). */
async function passkeyButton(page: Page, ms: number): Promise<ReturnType<Page["locator"]> | undefined> {
  const end = Date.now() + ms;
  for (;;) {
    for (const f of page.frames()) {
      if (f.url().startsWith("chrome-extension://")) continue;
      const b = f.locator(byId("lab-passkey")).first();
      if ((await b.count().catch(() => 0)) > 0) return b;
    }
    if (Date.now() >= end) return undefined;
    await sleep(200);
  }
}

/** passkey_control: Chromium's virtual authenticator holds the site's key; the lab RP must accept it. */
export async function passkeyControl(server: LabServer, plain: PlainBrowser, site: Site): Promise<Observation> {
  const started = Date.now();
  // Not an extension scenario: the UI flags hold so that a failure is explained by the RP's refusal.
  const o: Observation = { ...blank("passkey_control"), overlayShown: true, itemOffered: true };
  let page: Page | undefined;
  try {
    const key = site.account?.passkey;
    if (!key) throw new Error("lab: the site has no passkey");
    page = await plain.context.newPage();
    const cdp = await plain.context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
      },
    });
    await cdp.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: {
        credentialId: Buffer.from(key.credentialId, "base64url").toString("base64"),
        isResidentCredential: false, rpId: site.host, privateKey: passkeyPkcs8(key).toString("base64"), signCount: 0,
      },
    });
    await goto(page, `https://${site.host}/`);
    const typed = site.passkeyOnly ? true : await typePassword(page, server, site);
    const button = typed ? await passkeyButton(page, 10_000) : undefined;
    // No passkey step: the RP refused the password (the oracle reads why) or served none (a bench defect).
    if (typed && !button && !refused(server, site)) {
      throw new Error(`lab: no passkey step served (at ${page.frames().map((f) => f.url()).join(", ")})`);
    }
    if (button) await button.click({ timeout: 10_000 });
    const end = button ? Date.now() + 15_000 : 0;
    while (Date.now() < end && !server.events().some((e) => e.kind === "signin" && e.host === site.host)) {
      if (server.events().some((e) => e.kind === "submit" && e.form === "passkey" && !e.ok)) break;
      await sleep(200);
    }
  } catch (e) {
    o.error = message(e);
  }
  o.durationMs = Date.now() - started;
  await page?.close().catch(() => undefined);
  await sleep(LATE_GRACE_MS);
  o.events = server.events();
  return o;
}

/** A country case's verdict: pass, fail (with its cause) or lab_error (the bench, not OnePass). */
export interface CaseOutcome { verdict: "pass" | "fail" | "lab_error"; cause?: string; durationMs: number }

/** The fill reply can come 2.5 s after the pick: the controls are read until they match, up to this long. */
const CASE_SETTLE_MS = 4_000;

/** What each selector of `selectors` holds: a field's value, else the element's trimmed text (as the jsdom replay reads it). */
function readControls(page: Page, selectors: string[]): Promise<Record<string, string>> {
  return page.evaluate((sels) => Object.fromEntries(sels.map((s) => {
    const el = document.querySelector(s);
    if (!el) return [s, "\u0000missing"];
    if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) return [s, el.value];
    return [s, (el.textContent ?? "").trim()];
  })), selectors);
}

/**
 * One country case (lab/gen/cases.ts): the in-field menu of the case's name
 * field, its identity item picked, then each control read once the fill
 * settled. Nothing is submitted.
 */
export async function countryCase(env: ScenarioEnv, c: CountryCase): Promise<CaseOutcome> {
  const started = Date.now();
  let page: Page | undefined;
  const done = (verdict: CaseOutcome["verdict"], cause?: string): CaseOutcome =>
    ({ verdict, ...(cause ? { cause } : {}), durationMs: Date.now() - started });
  try {
    page = await env.newPage();
    await goto(page, `https://${c.host}${CASE_PATH}`);
    const menu = await env.driver.menuFill(page, page.mainFrame(), [c.field], c.title, true);
    if (!menu.shown) return done("fail", "no_menu");
    if (!menu.offered) return done("fail", "no_menu_item");
    const selectors = Object.keys(c.expect);
    const until = Date.now() + CASE_SETTLE_MS;
    let wrong = caseMismatches(c, await readControls(page, selectors));
    while (wrong.length > 0 && Date.now() < until) {
      await sleep(250);
      wrong = caseMismatches(c, await readControls(page, selectors));
    }
    return wrong.length === 0 ? done("pass") : done("fail", `wrong_controls:${wrong.join(",")}`);
  } catch (e) {
    return done("lab_error", message(e));
  } finally {
    await page?.close().catch(() => undefined);
  }
}
