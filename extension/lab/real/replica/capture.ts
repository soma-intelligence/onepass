// Captures replicas of the Tranco top sites: for each host, the rendered home
// page and, when one is found, the sign-in page, cleaned into static HTML
// (transform.ts), plus the signed-in variant of the home page (signed-in.ts).
// Playwright Chromium without any extension. GET only (every other method is
// aborted in the browser), robots.txt under the `OnePassLabReal` agent, at
// least 5 s between two pages of the same site, several sites in parallel.
// Resumable: a host with a meta.json is skipped.
// Usage: node --experimental-strip-types lab/real/replica/capture.ts [--sites 1000] [--workers 6] [--out lab/out/replicas] [--retry-errors]
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { getDomain } from "tldts";
import { discoverFormPages, type SeedLexicon } from "../../corpus/discover.ts";
import { HostPacer, writeAtomic } from "../../corpus/schedule.ts";
import { sanitizeText } from "../../corpus/sanitize.ts";
import { defaultReplicaDir, RealRobots, UA_SUFFIX, bareUrl, readMeta, readTranco, type ReplicaMeta } from "./common.ts";
import { makeSignedIn } from "./signed-in.ts";
import { cleanPage, MAX_SHEET } from "./transform.ts";

const USAGE = `Usage: node --experimental-strip-types lab/real/replica/capture.ts [options]
  --sites <n>      first n Tranco hosts (default 1000)
  --workers <n>    hosts in parallel (default 6)
  --out <dir>      output folder (default lab/out/replicas)
  --hosts <a,b>    capture these Tranco hosts instead (rank kept when listed)
  --retry-errors   capture again the hosts whose meta.json says error
  --help           print this text`;

const GOTO_MS = 30_000;
const IDLE_MS = 8_000;
const PAGE_DEADLINE_MS = GOTO_MS + IDLE_MS + 15_000;
const HOST_GAP_MS = 5_000;
/** Sign-in pages tried per site after the home page. */
const MAX_LOGIN_TRIES = 3;
/** Resource types never fetched: a replica keeps none of them. */
const SKIPPED_TYPES = new Set(["image", "media", "font", "manifest", "texttrack", "eventsource", "websocket", "ping", "other"]);

export const stats = { abortedNonGet: 0, abortedRobots: 0, skippedResources: 0, pages: 0 };

/** What the router does with one request. Pure, for tests. */
export function requestVerdict(r: { method: string; resourceType: string; isMainNavigation: boolean; robotsAllowed: boolean }): "continue" | "abort-method" | "abort-robots" | "abort-skip" {
  if (r.method.toUpperCase() !== "GET") return "abort-method";
  if (r.isMainNavigation && !r.robotsAllowed) return "abort-robots";
  if (!r.isMainNavigation && SKIPPED_TYPES.has(r.resourceType)) return "abort-skip";
  return "continue";
}

/** Sign-in candidates for a home page: discovered sign-in links first, then common paths. Sign-up and checkout pages excluded. */
export function loginCandidates(homeUrl: string, html: string, lexicon: SeedLexicon, max = MAX_LOGIN_TRIES): string[] {
  // Sign-in words only: the sign-up and payment intents would lead to other forms.
  const signinOnly: SeedLexicon = { buttons: { signin: lexicon.buttons.signin ?? {} } };
  const urls = discoverFormPages({ url: homeUrl, html }, undefined, signinOnly);
  return urls
    .filter((u) => !/regist|signup|sign-up|inscription|registr|join|checkout|kasse|paiement|pago|cart/i.test(new URL(u).pathname))
    .filter((u) => bareUrl(u) !== bareUrl(homeUrl))
    .slice(0, max);
}

const SIGN_IN_PATH = /log-?in|log-?on|sign-?in|signon|auth|identifier|account|session|connexion|connecter|anmelden|einloggen|acceder|iniciar|accedi|entrar|inloggen|aanmelden|passport|sso/i;
const SIGN_IN_HOST = /^(login|signin|accounts?|auth|id|sso|passport|secure)\./i;

/**
 * Whether a probed page counts as a sign-in page: a visible password field, or an
 * identifier-first field (autocomplete "username"/"webauthn", or a sign-in URL).
 * A bare email field elsewhere (newsletter, payment page) does not count.
 */
export function signInKind(probe: { password: boolean; identifier: boolean; usernameAutocomplete?: boolean }, url: string): "password" | "identifier" | undefined {
  if (probe.password) return "password";
  if (!probe.identifier) return undefined;
  const u = new URL(url);
  return probe.usernameAutocomplete || SIGN_IN_PATH.test(u.pathname) || SIGN_IN_HOST.test(u.hostname) ? "identifier" : undefined;
}

/** The site key pages are paced by (registrable domain, so accounts.x.com and www.x.com share it). */
export const siteKey = (host: string): string => getDomain(host) ?? host;

/** Runs in the page: does it show a sign-in form? */
function signInProbe(): Probe {
  const visible = (el: Element): boolean => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  const inputs = Array.from(document.querySelectorAll("input")).filter(visible);
  const password = inputs.some((i) => i.type === "password");
  const identifier = inputs.some((i) => i.type === "email" || /username|email|webauthn/.test(i.autocomplete) || /user|email|login|identifier|account|phone/i.test(`${i.name} ${i.id}`));
  const usernameAutocomplete = inputs.some((i) => /\b(username|webauthn)\b/.test(i.autocomplete));
  const body = document.body;
  return { password, identifier, usernameAutocomplete, textLength: (body?.innerText ?? "").trim().length, links: document.querySelectorAll("a[href]").length };
}

/** Runs in the page: marks the controls shown at the top of the page (where a header's "Sign in" sits). */
function markVisibleTopControls(): void {
  for (const el of Array.from(document.querySelectorAll("a, button, [role=button], [role=link]"))) {
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0 || r.top < 0 || r.top > 200) continue;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || st.display === "none" || Number(st.opacity) === 0) continue;
    el.setAttribute("data-onepass-lab-vis", "");
  }
}

export interface Probe { password: boolean; identifier: boolean; usernameAutocomplete: boolean; textLength: number; links: number; }

/** A bot wall or an empty shell rather than the site's page (nothing a replica can use). */
export function looksBlocked(probe: Pick<Probe, "textLength" | "links" | "password" | "identifier">, html: string): boolean {
  if (/id="challenge-(container|form|running)"|cf-challenge|cf-turnstile|g-recaptcha|h-captcha|px-captcha|_Incapsula_Resource|perimeterx|datadome|validateCaptcha/i.test(html) && probe.textLength < 600) return true;
  return probe.textLength < 80 && probe.links < 3 && !probe.password && !probe.identifier;
}

const errText = (e: unknown): string => sanitizeText(e instanceof Error ? e.message.split("\n")[0] : String(e)) ?? "unknown";

export class BrowserGone extends Error {}

interface PageShot { finalUrl: string; html: string; css: Map<string, string>; probe: Probe; lang?: string; }

async function renderPage(browser: any, url: string, robots: RealRobots, userAgent: string): Promise<PageShot | { error: string; robots?: boolean }> {
  if (!(await robots.allowed(new URL(url)))) return { error: "robots", robots: true };
  const ctx = await browser.newContext({ userAgent, serviceWorkers: "block", acceptDownloads: false, locale: "en-US", viewport: { width: 1280, height: 900 } });
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; ctx.close().catch(() => {}); }, PAGE_DEADLINE_MS);
  const css = new Map<string, string>();
  const pendingCss: Promise<void>[] = [];
  let first = true;
  try {
    // No popups; a popup's paused POST could otherwise slip out while it closes.
    await ctx.addInitScript("window.open = () => null;");
    await ctx.route("**/*", async (route: any) => {
      const req = route.request();
      let nav = false;
      try { nav = req.isNavigationRequest() && req.frame().parentFrame() === null; } catch { /* no frame: not a navigation */ }
      const v = requestVerdict({ method: req.method(), resourceType: req.resourceType(), isMainNavigation: nav, robotsAllowed: nav ? await robots.allowed(new URL(req.url())) : true });
      if (v === "abort-method") { stats.abortedNonGet++; await route.abort().catch(() => {}); }
      else if (v === "abort-robots") { stats.abortedRobots++; await route.abort().catch(() => {}); }
      else if (v === "abort-skip") { stats.skippedResources++; await route.abort().catch(() => {}); }
      else await route.continue().catch(() => {});
    });
    await ctx.routeWebSocket(/.*/, (ws: any) => { ws.close().catch(() => {}); });
    ctx.on("page", (p: any) => {
      p.on("download", (d: any) => { d.cancel().catch(() => {}); });
      if (first) { first = false; return; }
      p.close().catch(() => {});
    });
    const page = await ctx.newPage();
    page.on("response", (res: any) => {
      try {
        if (res.request().resourceType() !== "stylesheet" || !res.ok()) return;
        pendingCss.push(res.text().then((t: string) => { if (t.length <= MAX_SHEET) css.set(res.url(), t); }).catch(() => {}));
      } catch { /* closed */ }
    });
    const response = await page.goto(url, { timeout: GOTO_MS, waitUntil: "domcontentloaded" });
    if (response && !response.ok()) return { error: `http ${response.status()}` };
    await page.waitForLoadState("networkidle", { timeout: IDLE_MS }).catch(() => {});
    const finalUrl: string = page.url();
    if (!(await robots.allowed(new URL(finalUrl)))) return { error: "robots", robots: true };
    const probe = await page.evaluate(signInProbe);
    const lang: string = await page.evaluate(() => document.documentElement.lang || "");
    await page.evaluate(markVisibleTopControls);
    const html: string = await page.content();
    await Promise.all(pendingCss);
    stats.pages++;
    return { finalUrl, html, css, probe, lang: lang ? lang.toLowerCase().slice(0, 16) : undefined };
  } catch (e) {
    if (!browser.isConnected()) throw new BrowserGone(errText(e));
    return { error: timedOut ? "timeout" : errText(e) };
  } finally {
    clearTimeout(deadline);
    await ctx.close().catch(() => {});
  }
}

const isShot = (r: PageShot | { error: string }): r is PageShot => "html" in r;

/** Captures one host into `<out>/<host>/`. Never throws except BrowserGone. */
export async function captureHost(browser: any, host: string, rank: number, out: string, pacer: HostPacer, lexicon: SeedLexicon, userAgent: string): Promise<ReplicaMeta> {
  const key = siteKey(host);
  const gate = (): Promise<void> => pacer.wait(key);
  const robots = new RealRobots(userAgent, gate);
  const folder = join(out, host);
  rmSync(folder, { recursive: true, force: true }); // leftovers of an interrupted run
  mkdirSync(folder, { recursive: true });
  const meta: ReplicaMeta = { host, rank, status: "ok", capturedAt: new Date().toISOString(), signInForm: false, files: [], tried: [], inlinedCss: 0 };
  const write = (name: string, html: string): void => { writeAtomic(join(folder, name), html); meta.files.push(name); };

  await gate();
  const home = await renderPage(browser, `https://${host}/`, robots, userAgent);
  if (!isShot(home)) {
    meta.status = home.robots ? "skipped: robots" : `error: ${home.error}`;
    return meta;
  }
  if (looksBlocked(home.probe, home.html)) {
    meta.status = "error: blocked or empty page";
    return meta;
  }
  meta.homeUrl = bareUrl(home.finalUrl);
  meta.lang = home.lang;
  const cleanHome = cleanPage(home.html, { url: home.finalUrl, css: home.css, kind: "home" });
  meta.inlinedCss += cleanHome.inlinedCss;
  write("home.html", cleanHome.html);
  write("signed-in.html", makeSignedIn(cleanHome.html, { url: home.finalUrl, lang: home.lang }).html);

  for (const url of loginCandidates(home.finalUrl, home.html, lexicon)) {
    meta.tried.push(bareUrl(url));
    await gate();
    const r = await renderPage(browser, url, robots, userAgent);
    if (!isShot(r) || looksBlocked(r.probe, r.html)) continue;
    const kind = signInKind(r.probe, r.finalUrl);
    if (!kind) continue;
    const clean = cleanPage(r.html, { url: r.finalUrl, css: r.css, kind: "login" });
    meta.inlinedCss += clean.inlinedCss;
    write("login.html", clean.html);
    meta.loginUrl = bareUrl(r.finalUrl);
    meta.signInForm = true;
    meta.signInKind = kind;
    break;
  }
  // No separate sign-in page, but the home page itself carries a password form (a common pattern).
  if (!meta.signInForm && home.probe.password) {
    write("login.html", cleanPage(home.html, { url: home.finalUrl, css: home.css, kind: "login" }).html);
    meta.loginUrl = meta.homeUrl;
    meta.signInForm = true;
    meta.signInKind = "password";
  }
  return meta;
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--retry-errors") out["retry-errors"] = true;
    else if (a.startsWith("--")) out[a.slice(2)] = argv[++i] ?? "";
  }
  return out;
}

/** Hosts of the first `sites` Tranco entries still to capture. */
export function pendingReplicaHosts(hosts: string[], sites: number, out: string, retryErrors: boolean): { host: string; rank: number }[] {
  return hosts.slice(0, sites).map((host, i) => ({ host, rank: i + 1 })).filter(({ host }) => {
    const m = readMeta(out, host);
    if (!m) return true;
    return retryErrors && m.status.startsWith("error");
  });
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(USAGE); return; }
  const out = typeof args.out === "string" && args.out ? args.out : defaultReplicaDir();
  const sites = Math.max(1, Number(args.sites ?? 1000) || 1000);
  const workers = Math.min(16, Math.max(1, Number(args.workers ?? 6) || 6));
  const lexicon = JSON.parse((await import("node:fs")).readFileSync(new URL("../../corpus/seed-lexicon.json", import.meta.url), "utf8")) as SeedLexicon;
  mkdirSync(out, { recursive: true });
  const tranco = readTranco();
  const picked = typeof args.hosts === "string" && args.hosts ? args.hosts.split(",").map((h) => h.trim().toLowerCase()).filter(Boolean) : undefined;
  const todo = picked
    ? picked.map((host) => ({ host, rank: tranco.indexOf(host) + 1 || 100_000 })).filter(({ host }) => !readMeta(out, host) || args["retry-errors"] === true)
    : pendingReplicaHosts(tranco, sites, out, args["retry-errors"] === true);
  console.log(`${todo.length} hosts to capture${picked ? "" : ` out of the first ${sites}`}, ${workers} workers, into ${out}`);

  const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
  const chromium = pw.chromium ?? pw.default!.chromium;
  const browser = await chromium.launch({ channel: "chromium" });
  const userAgent = `${(await browser.newContext().then(async (c: any) => { const p = await c.newPage(); const ua = await p.evaluate(() => navigator.userAgent); await c.close(); return ua; })) as string} ${UA_SUFFIX}`;
  const pacer = new HostPacer(HOST_GAP_MS);
  const counts = { ok: 0, signIn: 0, robots: 0, errors: 0 };
  let next = 0;
  let dead = false;
  const worker = async (): Promise<void> => {
    while (next < todo.length && !dead) {
      const { host, rank } = todo[next++]!;
      let meta: ReplicaMeta;
      try {
        meta = await captureHost(browser, host, rank, out, pacer, lexicon, userAgent);
      } catch (e) {
        dead = true;
        console.error(`${host}: browser gone (${errText(e)}), stopping`);
        return;
      }
      if (!browser.isConnected()) { dead = true; return; }
      writeAtomic(join(out, host, "meta.json"), JSON.stringify(meta, null, 2) + "\n");
      if (meta.status === "ok") counts.ok++;
      else if (meta.status === "skipped: robots") counts.robots++;
      else counts.errors++;
      if (meta.signInForm) counts.signIn++;
      console.log(`${String(rank).padStart(4)} ${host}: ${meta.status}${meta.signInForm ? `, sign-in ${meta.signInKind} at ${meta.loginUrl}` : ""}`);
    }
  };
  try {
    await Promise.all(Array.from({ length: workers }, worker));
    if (dead) process.exitCode = 1;
  } finally {
    await browser.close().catch(() => {});
    console.log(`captured ${counts.ok} (with sign-in form ${counts.signIn}), robots ${counts.robots}, errors ${counts.errors}; pages ${stats.pages}; aborted non-GET ${stats.abortedNonGet}; robots-blocked navigations ${stats.abortedRobots}; skipped resources ${stats.skippedResources}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
