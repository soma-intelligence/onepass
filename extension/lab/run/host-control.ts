// Start-state control of the lab's native host (the development host the
// browser spawns for one profile): find its process, stop it (a cold start),
// make its next start locked (config key `unlocked`), and play Touch ID for
// an unlock. Lab side only: nothing here changes the host.
//
// What the host gives: `unlocked: false` starts it locked, and by default its
// `unlock` request approves at once ("instant"). The real app answers
// `unlock` while still locked and opens later, once Touch ID passed; the host
// plays that with one more control:
//   config `"unlock": "file"`: an `unlock` request writes
//   `<data_dir>/unlock-pending` and answers the current (locked) status; the
//   vault opens when `<data_dir>/unlock-approved` exists (both files are then
//   removed), checked before each later request.
// `hostSupports` probes the host binary for that key (an older binary lacks
// it); the stand-in below approves through those files ("deferred"), after a
// human delay, and keeps the approval for every host process of the profile.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const UNLOCK_PENDING = "unlock-pending";
export const UNLOCK_APPROVED = "unlock-approved";

/** Controls a start state needs and the host or the platform may lack. */
export type HostControlName = "stop" | "deferred_unlock" | "fill_smart_command";

/** The skip cause of a scenario whose start state needs a missing control. */
export const lacks = (control: HostControlName, why: string): string => `host lacks control ${control} (${why})`;

/** Pids of the processes whose command line holds `needle` (the host's own config path), from `ps` output. */
export function pidsIn(psOutput: string, needle: string): number[] {
  const out: number[] = [];
  for (const line of psOutput.split("\n")) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (m && m[2]!.includes(needle)) out.push(Number(m[1]));
  }
  return out;
}

/** Pids of the native host started with `config` (its wrapper execs the binary with `--config <config>`); undefined when `ps` cannot be read. */
export function hostPids(config: string): number[] | undefined {
  const r = spawnSync("ps", ["-axww", "-o", "pid=,command="], { encoding: "utf8" });
  if (r.status !== 0 || typeof r.stdout !== "string") return undefined;
  return pidsIn(r.stdout, `--config ${config}`).filter((pid) => pid !== process.pid);
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Stops the host of `config` (SIGTERM, then SIGKILL after 2 s). True once none is left; false when it cannot be seen or will not die. */
export async function stopHost(config: string): Promise<boolean> {
  const pids = hostPids(config);
  if (pids === undefined) return false;
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // Gone since the listing.
    }
  }
  const end = Date.now() + 4_000;
  let killed = false;
  while (pids.some(alive)) {
    if (Date.now() >= end) return false;
    if (!killed && Date.now() >= end - 2_000) {
      killed = true;
      for (const pid of pids.filter(alive)) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Gone.
        }
      }
    }
    await sleep(50);
  }
  return true;
}

/** Rewrites keys of the host's config file (an undefined value removes its key); the next host process reads them. */
export function patchHostConfig(config: string, patch: Record<string, unknown>): void {
  const now = JSON.parse(readFileSync(config, "utf8")) as Record<string, unknown>;
  writeFileSync(config, JSON.stringify({ ...now, ...patch }));
}

/**
 * Whether the host binary accepts the config key `key` (its config refuses
 * unknown keys). Probed with `approve`, which only parses the config and
 * writes one file in a throwaway data directory.
 */
export function hostSupports(bin: string, key: string, value: unknown): boolean {
  const dir = mkdtempSync(join(tmpdir(), "onepass-lab-probe-"));
  try {
    const config = join(dir, "probe.json");
    writeFileSync(config, JSON.stringify({
      data_dir: join(dir, "data"), allowed_extensions: [], source: { kind: "fixture", path: join(dir, "none.json") }, approval: "auto", [key]: value,
    }));
    return spawnSync(bin, ["approve", "000 000", "--config", config], { stdio: "ignore", timeout: 10_000 }).status === 0;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * One look of the Touch ID stand-in at a deferred host: approves a pending
 * unlock (writes `unlock-approved`) and says whether it did. Never approves
 * twice for one request, never without one.
 */
export function approvePendingUnlock(dataDir: string): boolean {
  const pending = join(dataDir, UNLOCK_PENDING);
  const approved = join(dataDir, UNLOCK_APPROVED);
  if (!existsSync(pending) || existsSync(approved)) return false;
  writeFileSync(approved, "", { mode: 0o600 });
  return true;
}

/** How long the stand-in leaves an unlock pending before it approves: a finger reaching Touch ID. */
export const UNLOCK_DELAY_MS = 800;

/** The stand-in's delay for this run: `LAB_UNLOCK_DELAY_MS` (0: at once), else `UNLOCK_DELAY_MS`. */
export function unlockDelayMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LAB_UNLOCK_DELAY_MS;
  if (raw === undefined || raw === "") return UNLOCK_DELAY_MS;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 60_000) throw new Error(`lab: LAB_UNLOCK_DELAY_MS must be an integer from 0 to 60000 (${raw})`);
  return n;
}

/**
 * The stand-in watching one host data directory: every pending unlock approved, and counted.
 * `delayMs`: how long a request stays pending first. The real unlock arrives later than the
 * request (the user looks at the app, then touches the sensor): the extension must wait and
 * resume, not find the vault open at its next look by luck.
 *
 * Once approved, the unlock holds until `stop()`: a profile has more than one host process (the
 * main session, and the agent channel's own native port, reopened every few seconds), each with
 * its own lock, and the one that asks first takes the approval files away. The app has one vault
 * for all its connections; here the stand-in puts both files back while the scenario lasts, so
 * every process of the profile opens at its next request. Never before a host asked (a request
 * is what writes `unlock-pending`), and nothing is left for the next scenario.
 */
export class UnlockStandIn {
  private timer: ReturnType<typeof setInterval> | undefined;
  private count = 0;
  private seenAt: number | undefined;
  private approved = false;
  private readonly dataDir: string;
  private readonly delayMs: number;
  constructor(dataDir: string, delayMs = 0) {
    this.dataDir = dataDir;
    this.delayMs = delayMs;
  }
  private clear(): void {
    for (const f of [UNLOCK_PENDING, UNLOCK_APPROVED]) rmSync(join(this.dataDir, f), { force: true });
  }
  start(everyMs = 100): void {
    this.stop();
    this.count = 0;
    this.seenAt = undefined;
    this.approved = false;
    // A file of an earlier scenario is no request of this one.
    this.clear();
    this.timer = setInterval(() => {
      const pending = join(this.dataDir, UNLOCK_PENDING);
      const approved = join(this.dataDir, UNLOCK_APPROVED);
      if (this.approved) {
        // Taken by one host process: back for the others.
        if (!existsSync(pending)) writeFileSync(pending, "", { mode: 0o600 });
        if (!existsSync(approved)) writeFileSync(approved, "", { mode: 0o600 });
        return;
      }
      const waiting = existsSync(pending) && !existsSync(approved);
      if (!waiting) {
        this.seenAt = undefined;
        return;
      }
      this.seenAt ??= Date.now();
      if (Date.now() - this.seenAt < this.delayMs) return;
      this.seenAt = undefined;
      if (approvePendingUnlock(this.dataDir)) {
        this.count++;
        this.approved = true;
      }
    }, everyMs);
  }
  /** Stops watching and removes what it left; the approvals given since start(). */
  stop(): number {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      if (this.approved) this.clear();
    }
    this.timer = undefined;
    this.approved = false;
    return this.count;
  }
}
