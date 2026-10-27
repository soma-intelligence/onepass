// Network side of robots.txt for the corpus tools: one fetch per origin, cached,
// and the allow check shared by extract.ts and crawl-top.ts.
import { isAllowed, robotsEntry } from "./robots.ts";
import type { RobotsEntry } from "./robots.ts";

export const USER_AGENT = "OnePassLabCorpus/2 (+https://github.com/soma-intelligence/onepass)";
export const ROBOTS_AGENT = "OnePassLabCorpus";

const robotsCache = new Map<string, RobotsEntry>();

/** `gate` runs before a network fetch of robots.txt (cache misses only), so callers can pace it. */
export async function getRobots(origin: string, gate?: (host: string) => Promise<void>): Promise<RobotsEntry> {
  const hit = robotsCache.get(origin);
  if (hit !== undefined) return hit;
  let entry: RobotsEntry;
  try {
    if (gate) await gate(new URL(origin).hostname);
    const res = await fetch(origin + "/robots.txt", { headers: { "user-agent": USER_AGENT }, signal: AbortSignal.timeout(10_000) });
    const text = res.ok ? await res.text() : "";
    entry = robotsEntry({ status: res.status, ok: res.ok, redirected: res.redirected, contentType: res.headers.get("content-type") ?? "" }, () => text);
  } catch {
    entry = "deny";
  }
  robotsCache.set(origin, entry);
  return entry;
}

export async function urlAllowed(u: URL, gate?: (host: string) => Promise<void>): Promise<boolean> {
  const e = await getRobots(u.origin, gate);
  if (e === "deny") return false;
  return e === null || isAllowed(e, ROBOTS_AGENT, u.pathname + u.search);
}
