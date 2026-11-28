// Network guard of the real-site bench (README "Garde-fous réseau"): only GET
// and HEAD leave the browser for a real host, every other method is aborted
// before it leaves; form submits, form.submit(), requestSubmit() and
// navigator.sendBeacon are cut in every frame by an init script; top-level
// navigations obey robots.txt for the agent token `OnePassLabReal`; popups,
// downloads and WebSockets are closed. Every cut is logged with its cause
// (OnePass, the page, another extension) so the oracle can count them (R5).
// Page pacing (5 s between two page loads of one host) is the visit's job,
// through the HostPacer of lab/corpus/schedule.ts.
import type { BrowserContext, Page, Request, Route } from "@playwright/test";
import { isAllowed, robotsEntry, type RobotsEntry } from "../corpus/robots.ts";

/** robots.txt agent token of this bench. */
export const REAL_AGENT = "OnePassLabReal";
/** Appended to the browser's own user agent: sites see who visits. */
export const UA_TOKEN = "OnePassLabReal/1 (+https://github.com/soma-intelligence/onepass)";
/** Minimum gap between two page loads of one host. */
export const HOST_GAP_MS = 5_000;
/** Methods that may leave for a real host. */
const SAFE_METHODS = new Set(["GET", "HEAD"]);

export type RequestVerdict = "continue" | "abort-method" | "abort-robots" | "abort-offlist";

export interface RequestFacts {
  method: string;
  url: string;
  /** A navigation of the top frame. */
  isMainNavigation: boolean;
}

/**
 * What the guard does with one request. Extension and data URLs are local and always continue.
 * `allowedHosts`: when set (replica runs), any web host outside it is aborted (nothing real may answer).
 * `robotsAllowed`: robots.txt verdict of a top-level navigation (ignored for other requests).
 */
export function requestVerdict(req: RequestFacts, robotsAllowed: boolean, allowedHosts?: ReadonlySet<string>): RequestVerdict {
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return "abort-offlist";
  }
  if (u.protocol === "chrome-extension:" || u.protocol === "data:" || u.protocol === "blob:" || u.protocol === "about:") return "continue";
  const web = u.protocol === "https:" || u.protocol === "http:" || u.protocol === "wss:" || u.protocol === "ws:";
  if (!web) return "abort-offlist";
  if (allowedHosts && !allowedHosts.has(u.hostname)) return "abort-offlist";
  if (!SAFE_METHODS.has(req.method.toUpperCase())) return "abort-method";
  if (req.isMainNavigation && !robotsAllowed) return "abort-robots";
  return "continue";
}

export type Cause = "onepass" | "page" | "other-extension" | "unknown";

/** Who sent a request, from the URL of the frame (or worker) it came from. */
export function causeOf(originUrl: string | undefined, onePassId: string | undefined): Cause {
  if (!originUrl) return "unknown";
  if (originUrl.startsWith("chrome-extension://")) {
    const id = originUrl.slice("chrome-extension://".length).split("/")[0];
    return onePassId && id === onePassId ? "onepass" : "other-extension";
  }
  return "page";
}

export type GuardEventKind = "method" | "robots" | "offlist" | "submit" | "form-submit" | "request-submit" | "beacon" | "websocket" | "popup" | "download";

/** One cut of the guard. No URL query, no body, no value: the host, the method and who caused it. */
export interface GuardEvent {
  at: number;
  kind: GuardEventKind;
  /** Host the request went to (or of the page that tried the submit). */
  host: string;
  method?: string;
  cause: Cause;
}

/** Every cut of a run, in order; the visit reads the ones of its step. */
export class GuardLog {
  readonly events: GuardEvent[] = [];
  record(e: Omit<GuardEvent, "at">, at = Date.now()): void {
    this.events.push({ ...e, at });
  }
  /** Events since `since` (ms) whose page or target host is in `hosts` (any when omitted). */
  since(since: number, hosts?: (h: string) => boolean): GuardEvent[] {
    return this.events.filter((e) => e.at >= since && (!hosts || hosts(e.host)));
  }
}

/** Counts per kind and cause, for the report line of one step. */
export function summarizeEvents(events: readonly GuardEvent[]): { key: string; count: number; cause: Cause; kind: GuardEventKind }[] {
  const m = new Map<string, { key: string; count: number; cause: Cause; kind: GuardEventKind }>();
  for (const e of events) {
    const key = `${e.kind}${e.method ? ` ${e.method}` : ""} by ${e.cause}`;
    const cur = m.get(key) ?? { key, count: 0, cause: e.cause, kind: e.kind };
    cur.count++;
    m.set(key, cur);
  }
  return [...m.values()];
}

/** Fetches robots.txt text for an origin (injectable for the tests). */
export type RobotsFetch = (origin: string) => Promise<{ status: number; ok: boolean; redirected: boolean; contentType: string; text: string }>;

export const defaultRobotsFetch = (userAgent: string): RobotsFetch => async (origin) => {
  const res = await fetch(`${origin}/robots.txt`, { headers: { "user-agent": userAgent }, signal: AbortSignal.timeout(10_000) });
  const text = res.ok ? await res.text() : "";
  return { status: res.status, ok: res.ok, redirected: res.redirected, contentType: res.headers.get("content-type") ?? "", text };
};

/** robots.txt of each origin, fetched once (lab/corpus/robots.ts rules), for the `OnePassLabReal` agent. */
export class RobotsGate {
  private readonly cache = new Map<string, Promise<RobotsEntry>>();
  private readonly fetchRobots: RobotsFetch;
  private readonly agent: string;
  constructor(fetchRobots: RobotsFetch, agent: string = REAL_AGENT) {
    this.fetchRobots = fetchRobots;
    this.agent = agent;
  }
  private entry(origin: string): Promise<RobotsEntry> {
    let hit = this.cache.get(origin);
    if (!hit) {
      hit = this.fetchRobots(origin).then(
        (r) => robotsEntry(r, () => r.text),
        () => "deny" as const,
      );
      this.cache.set(origin, hit);
    }
    return hit;
  }
  async allowed(url: URL | string): Promise<boolean> {
    const u = typeof url === "string" ? new URL(url) : url;
    if (u.protocol !== "https:" && u.protocol !== "http:") return true;
    const e = await this.entry(u.origin);
    if (e === "deny") return false;
    return e === null || isAllowed(e, this.agent, u.pathname + u.search);
  }
}

/** Name of the binding the init script reports its cuts through. */
export const GUARD_BINDING = "__onepassLabGuard";

/**
 * Runs first in every frame of every page: cuts submit events (capture, before the page's own
 * handlers), form.submit(), requestSubmit(), navigator.sendBeacon and window.open, and reports
 * each cut. Main world only: a content script's own form.submit() runs in its isolated world;
 * its request is then cut by the route (non-GET) instead.
 */
export const GUARD_INIT_SCRIPT = `(() => {
  const report = (kind) => { try { const b = window[${JSON.stringify(GUARD_BINDING)}]; if (typeof b === "function") b(kind); } catch (e) {} };
  window.addEventListener("submit", (e) => { e.preventDefault(); e.stopImmediatePropagation(); report("submit"); }, true);
  try { HTMLFormElement.prototype.submit = function () { report("form-submit"); }; } catch (e) {}
  try { HTMLFormElement.prototype.requestSubmit = function () { report("request-submit"); }; } catch (e) {}
  try {
    Object.defineProperty(Navigator.prototype, "sendBeacon", { configurable: true, writable: true, value: function () { report("beacon"); return false; } });
  } catch (e) {}
  try { window.open = function () { report("popup"); return null; }; } catch (e) {}
  // A site's service worker could send what the page's route never sees: none gets registered.
  try { if (window.ServiceWorkerContainer) ServiceWorkerContainer.prototype.register = function () { return Promise.reject(new DOMException("blocked by the bench", "SecurityError")); }; } catch (e) {}
})();`;

export interface GuardOptions {
  log: GuardLog;
  /** robots.txt for top-level navigations; null: no robots check (replica: nothing real is reached). */
  robots: RobotsGate | null;
  /** Replica runs: the only web hosts that may be reached. */
  allowedHosts?: ReadonlySet<string>;
  /** OnePass's extension id, once known. */
  onePassId: () => string | undefined;
  /** Pages the bench opened itself (never closed as popups). */
  ownPages: WeakSet<Page>;
}

function originOf(req: Request): string | undefined {
  try {
    return req.frame().url();
  } catch {
    // A worker's request has no frame: its URL is the worker's.
    try {
      return req.serviceWorker()?.url();
    } catch {
      return undefined;
    }
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Installs the route, the WebSocket cut, the init script, its binding and the popup closer on `ctx`. */
export async function installGuard(ctx: BrowserContext, opts: GuardOptions): Promise<void> {
  const { log } = opts;
  await ctx.exposeBinding(GUARD_BINDING, (source, kind: unknown) => {
    const k = typeof kind === "string" && ["submit", "form-submit", "request-submit", "beacon", "popup"].includes(kind) ? (kind as GuardEventKind) : "submit";
    let url = "";
    try {
      url = source.frame.url();
    } catch {
      // detached frame
    }
    // A submit is cut in the page's main world: who asked for it cannot be told from there.
    log.record({ kind: k, host: hostOf(url), cause: "unknown" });
  });
  await ctx.addInitScript(GUARD_INIT_SCRIPT);
  await ctx.route("**/*", async (route: Route) => {
    const req = route.request();
    let nav = false;
    try {
      nav = req.isNavigationRequest() && req.frame().parentFrame() === null;
    } catch {
      nav = false;
    }
    const facts: RequestFacts = { method: req.method(), url: req.url(), isMainNavigation: nav };
    let robotsOk = true;
    if (nav && opts.robots && requestVerdict(facts, true, opts.allowedHosts) === "continue") {
      robotsOk = await opts.robots.allowed(req.url()).catch(() => false);
    }
    const verdict = requestVerdict(facts, robotsOk, opts.allowedHosts);
    if (verdict === "continue") {
      await route.continue().catch(() => undefined);
      return;
    }
    const kind: GuardEventKind = verdict === "abort-method" ? "method" : verdict === "abort-robots" ? "robots" : "offlist";
    log.record({ kind, host: hostOf(req.url()), method: req.method().toUpperCase(), cause: causeOf(originOf(req), opts.onePassId()) });
    await route.abort("blockedbyclient").catch(() => undefined);
  });
  await ctx.routeWebSocket(/.*/, (ws) => {
    log.record({ kind: "websocket", host: hostOf(ws.url()), cause: "page" });
    ws.close().catch(() => undefined);
  });
  const watch = (p: Page) => {
    p.on("download", (d) => {
      log.record({ kind: "download", host: hostOf(p.url()), cause: "page" });
      d.cancel().catch(() => undefined);
    });
  };
  for (const p of ctx.pages()) watch(p);
  ctx.on("page", (p) => {
    watch(p);
    // Give the bench a tick to claim the page it just opened.
    setTimeout(() => {
      if (opts.ownPages.has(p)) return;
      const url = p.url();
      // The extensions' own windows (popup, passkey) are theirs to manage.
      if (url.startsWith("chrome-extension://")) return;
      log.record({ kind: "popup", host: hostOf(url), cause: "unknown" });
      p.close().catch(() => undefined);
    }, 250);
  });
}
