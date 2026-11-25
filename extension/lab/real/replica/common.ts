// Shared pieces of the replica tools (capture, signed-in variants, server,
// profile): output layout, the per-site meta file, the crawler identity and
// robots.txt under the `OnePassLabReal` agent.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isAllowed, robotsEntry, type RobotsEntry } from "../../corpus/robots.ts";

// Resolved on use: under the test runner's DOM environment import.meta.url is no file URL.
const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
/** `extension/lab/out/replicas/` (git-ignored with the rest of `lab/out/`). */
export const defaultReplicaDir = (): string => here("../../out/replicas/");
/** `extension/lab/out/real-profile/`, the persistent Chrome profile of the signed-in bench. */
export const defaultProfileDir = (): string => here("../../out/real-profile/");
export const trancoPath = (): string => here("../../corpus/tranco.json");

/** robots.txt agent token. */
export const ROBOTS_AGENT = "OnePassLabReal";
/** Suffix appended to the browser's own user agent so sites see who visits. */
export const UA_SUFFIX = "OnePassLabReal/1 (+https://github.com/soma-intelligence/onepass)";

export type CaptureStatus = "ok" | "skipped: robots" | `error: ${string}`;

/** `<host>/meta.json`: written last, so its presence marks a finished host. */
export interface ReplicaMeta {
  /** The Tranco host (folder name). */
  host: string;
  rank: number;
  status: CaptureStatus;
  capturedAt: string;
  /** Final URL of the home page, origin and path only. */
  homeUrl?: string;
  /** Final URL of the sign-in page, origin and path only. */
  loginUrl?: string;
  /** Whether a sign-in form was found (on a sign-in page or on the home page itself). */
  signInForm: boolean;
  /** "password": a visible password field; "identifier": identifier-first form (no password yet). */
  signInKind?: "password" | "identifier";
  /** `<html lang>` of the home page, lower case, when present. */
  lang?: string;
  /** Files written next to the meta file. */
  files: string[];
  /** Sign-in URLs tried, origin and path only. */
  tried: string[];
  /** Stylesheets inlined into home.html / login.html. */
  inlinedCss: number;
}

export function readTranco(path = trancoPath()): string[] {
  return (JSON.parse(readFileSync(path, "utf8")) as { hosts: string[] }).hosts;
}

export function readMeta(dir: string, host: string): ReplicaMeta | undefined {
  try {
    return JSON.parse(readFileSync(join(dir, host, "meta.json"), "utf8")) as ReplicaMeta;
  } catch {
    return undefined;
  }
}

/** Every finished host of a replica folder, in Tranco order when the rank is known. */
export function listReplicas(dir: string): ReplicaMeta[] {
  if (!existsSync(dir)) return [];
  const out: ReplicaMeta[] = [];
  for (const name of readdirSync(dir)) {
    if (name.startsWith(".")) continue;
    const m = readMeta(dir, name);
    if (m) out.push(m);
  }
  return out.sort((a, b) => a.rank - b.rank);
}

/** Origin and path only: a query or fragment can carry values a site issued to this session. */
export function bareUrl(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/** robots.txt under the `OnePassLabReal` agent, one fetch per origin, cached. */
export class RealRobots {
  private cache = new Map<string, Promise<RobotsEntry>>();
  private userAgent: string;
  private gate: (host: string) => Promise<void>;
  private fetcher: typeof fetch;
  constructor(userAgent: string, gate: (host: string) => Promise<void>, fetcher: typeof fetch = fetch) {
    this.userAgent = userAgent;
    this.gate = gate;
    this.fetcher = fetcher;
  }

  private entry(origin: string): Promise<RobotsEntry> {
    let hit = this.cache.get(origin);
    if (!hit) {
      hit = (async (): Promise<RobotsEntry> => {
        try {
          await this.gate(new URL(origin).hostname);
          const res = await this.fetcher(origin + "/robots.txt", { method: "GET", headers: { "user-agent": this.userAgent }, signal: AbortSignal.timeout(10_000) });
          const text = res.ok ? await res.text() : "";
          return robotsEntry({ status: res.status, ok: res.ok, redirected: res.redirected, contentType: res.headers.get("content-type") ?? "" }, () => text);
        } catch {
          return "deny";
        }
      })();
      this.cache.set(origin, hit);
    }
    return hit;
  }

  async allowed(u: URL): Promise<boolean> {
    if (u.protocol !== "https:" && u.protocol !== "http:") return false;
    const e = await this.entry(u.origin);
    if (e === "deny") return false;
    return e === null || isAllowed(e, ROBOTS_AGENT, u.pathname + u.search);
  }
}
