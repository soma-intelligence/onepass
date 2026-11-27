// Targets and options of the real-site bench (README "Trois sortes de cibles"):
// `live` (the real URL, signed out, a fresh profile), `profile` (the real URL in
// the persistent signed-in profile lab/out/real-profile/), `replica` (pages
// captured by GET, served locally under their real hostname).
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

export type TargetKind = "live" | "profile" | "replica";
export const TARGET_KINDS: readonly TargetKind[] = ["live", "profile", "replica"];
export type ManagerName = "bitwarden" | "1password" | "lastpass" | "dashlane";
export const MANAGER_NAMES: readonly ManagerName[] = ["bitwarden", "1password", "lastpass", "dashlane"];

export const EXT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const TRANCO_PATH = join(EXT_ROOT, "lab/corpus/tranco.json");
export const DEFAULT_PROFILE_DIR = join(EXT_ROOT, "lab/out/real-profile");
export const DEFAULT_REPLICA_DIR = join(EXT_ROOT, "lab/out/replicas");
/** Time box of one site. */
export const SITE_TIME_BOX_MS = 90_000;
/** Most live sites one run may visit without --allow-many (the bench's own rule of restraint). */
export const MAX_SITES = 1000;

export interface Target {
  kind: TargetKind;
  host: string;
  /** Tranco rank, 1-based (0: not in the list). */
  rank: number;
  url: string;
  /** The page is known signed in (profile targets listed as signed in). */
  knownSignedIn: boolean;
}

export interface RealOptions {
  sites: number;
  kinds: TargetKind[];
  workers: number;
  out: string;
  managers: ManagerName[];
  headed: boolean;
  timeBoxMs: number;
  profileDir: string;
  replicaDir: string;
  /** Only these hosts (comma list), when set. */
  only?: string[];
}

export const USAGE = `Usage: npm run lab:real-site -- [options]

  --sites N        first N hosts of the Tranco list (default 1000)
  --kinds LIST     live,profile,replica (default live)
  --workers N      browsers in parallel (default 2; profile always runs with 1)
  --out DIR        output directory (default lab/out/real-<date>)
  --managers LIST  bitwarden,1password,lastpass,dashlane loaded next to OnePass (default none)
  --only LIST      only these hosts (comma list), still in Tranco order
  --headed         show the browsers
  --time-box S     seconds per site (default 90)
  --profile-dir D  persistent profile of the profile targets (default lab/out/real-profile)
  --replica-dir D  captured replicas (default lab/out/replicas)
  --help           this text`;

function list<T extends string>(raw: string, allowed: readonly T[], what: string): T[] {
  const out = raw.split(",").map((x) => x.trim()).filter(Boolean);
  for (const x of out) if (!allowed.includes(x as T)) throw new Error(`lab:real: unknown ${what} "${x}" (allowed: ${allowed.join(", ")})`);
  return [...new Set(out)] as T[];
}

function positive(raw: string | undefined, name: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new Error(`lab:real: --${name} must be a positive integer (${raw})`);
  return n;
}

/** The date part of the default output folder (local time, YYYY-MM-DD-HHMM). */
export function stamp(d = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

/** Parses the CLI; throws on anything unknown. `help: true` when asked for the usage. */
export function parseArgs(argv: readonly string[], now = new Date()): RealOptions & { help: boolean } {
  const o: RealOptions & { help: boolean } = {
    sites: MAX_SITES, kinds: ["live"], workers: 2, out: join(EXT_ROOT, "lab/out", `real-${stamp(now)}`), managers: [], headed: false,
    timeBoxMs: SITE_TIME_BOX_MS, profileDir: DEFAULT_PROFILE_DIR, replicaDir: DEFAULT_REPLICA_DIR, help: false,
  };
  const abs = (p: string) => (isAbsolute(p) ? p : join(process.cwd(), p));
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const val = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`lab:real: ${a} needs a value`);
      return v;
    };
    switch (a) {
      case "--help": case "-h": o.help = true; break;
      case "--sites": o.sites = Math.min(MAX_SITES, positive(val(), "sites")); break;
      case "--kinds": o.kinds = list(val(), TARGET_KINDS, "kind"); break;
      case "--workers": o.workers = Math.min(8, positive(val(), "workers")); break;
      case "--out": o.out = abs(val()); break;
      case "--managers": o.managers = list(val(), MANAGER_NAMES, "manager"); break;
      case "--only": o.only = val().split(",").map((x) => x.trim().toLowerCase()).filter(Boolean); break;
      case "--headed": o.headed = true; break;
      case "--time-box": o.timeBoxMs = positive(val(), "time-box") * 1000; break;
      case "--profile-dir": o.profileDir = abs(val()); break;
      case "--replica-dir": o.replicaDir = abs(val()); break;
      default: throw new Error(`lab:real: unknown option ${a}\n${USAGE}`);
    }
  }
  if (o.kinds.length === 0) throw new Error("lab:real: --kinds is empty");
  return o;
}

export function readTranco(path = TRANCO_PATH): string[] {
  return (JSON.parse(readFileSync(path, "utf8")) as { hosts: string[] }).hosts;
}

/** The first `n` Tranco hosts, narrowed to `only` when given. */
export function pickHosts(tranco: readonly string[], n: number, only?: readonly string[]): { host: string; rank: number }[] {
  const out = tranco.slice(0, n).map((host, i) => ({ host, rank: i + 1 }));
  return only ? out.filter((x) => only.includes(x.host)) : out;
}

export function liveTargets(hosts: readonly { host: string; rank: number }[]): Target[] {
  return hosts.map(({ host, rank }) => ({ kind: "live", host, rank, url: `https://${host}/`, knownSignedIn: false }));
}

/**
 * Hosts the tester signed in to in the persistent profile, when the profile tool recorded them
 * (`<profileDir>/signed-in.json`: an array of hosts, or `{ "hosts": [...] }`). Undefined: no list.
 */
export function readSignedIn(profileDir: string): string[] | undefined {
  const file = join(profileDir, "signed-in.json");
  if (!existsSync(file)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(file, "utf8")) as unknown;
    const arr = Array.isArray(raw) ? raw : (raw as { hosts?: unknown }).hosts;
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string").map((x) => x.toLowerCase()) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Profile targets: with a signed-in list, its hosts among the picked ones (known signed in); without
 * one, every picked host, signed-in state read from the page only.
 */
export function profileTargets(hosts: readonly { host: string; rank: number }[], signedIn: readonly string[] | undefined): Target[] {
  if (!signedIn) return hosts.map(({ host, rank }) => ({ kind: "profile", host, rank, url: `https://${host}/`, knownSignedIn: false }));
  const set = new Set(signedIn);
  return hosts.filter((h) => set.has(h.host)).map(({ host, rank }) => ({ kind: "profile", host, rank, url: `https://${host}/`, knownSignedIn: true }));
}

/** Replica targets: the served hosts, in Tranco order, limited to the picked ones when they are Tranco hosts. */
export function replicaTargets(served: readonly string[], picked: readonly { host: string; rank: number }[], tranco: readonly string[]): Target[] {
  const rankOf = new Map(tranco.map((h, i) => [h, i + 1]));
  const pickedSet = new Set(picked.map((p) => p.host));
  const tops = served.filter((h) => pickedSet.has(h) || pickedSet.has(h.replace(/^www\./, "")));
  return tops
    .map((host) => ({ kind: "replica" as const, host, rank: rankOf.get(host) ?? rankOf.get(host.replace(/^www\./, "")) ?? 0, url: `https://${host}/`, knownSignedIn: false }))
    .sort((a, b) => (a.rank || 1e9) - (b.rank || 1e9));
}
