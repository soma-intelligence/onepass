// Scheduling helpers of the top 1000 crawl: done markers, atomic writes,
// per-host pacing and the per-site page and error budget.
import { readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** A host is done when `<host>.done.json` exists and parses; page files alone prove nothing. */
export function pendingHosts(hosts: string[], outDir: string): string[] {
  return hosts.filter((h) => {
    try { JSON.parse(readFileSync(join(outDir, `${h}.done.json`), "utf8")); return false; } catch { return true; }
  });
}

/** Writes `<path>.tmp` then renames; a failed rename leaves neither target nor tmp file. */
export function writeAtomicWith(path: string, data: string, rename: (from: string, to: string) => void): void {
  const tmp = path + ".tmp";
  writeFileSync(tmp, data);
  try { rename(tmp, path); } catch (e) { try { unlinkSync(tmp); } catch { /* already gone */ } throw e; }
}

export function writeAtomic(path: string, data: string): void {
  writeAtomicWith(path, data, renameSync);
}

/** Spaces the requests of one host at least `minGapMs` apart; other hosts are independent. */
export class HostPacer {
  private next = new Map<string, number>();
  private minGapMs: number;
  private now: () => number;
  private sleep: (ms: number) => Promise<void>;
  constructor(
    minGapMs: number,
    now: () => number = Date.now,
    sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) { this.minGapMs = minGapMs; this.now = now; this.sleep = sleep; }

  async wait(host: string): Promise<void> {
    // Reserve the slot synchronously so concurrent callers queue up behind each other.
    const t = this.now();
    const slot = Math.max(t, this.next.get(host) ?? t);
    this.next.set(host, slot + this.minGapMs);
    if (slot > t) await this.sleep(slot - t);
  }
}

/** At most `maxPages` pages per site; the site is abandoned after `maxErrors` errors. */
export class SiteBudget {
  private pages = 0;
  private errors = 0;
  private maxPages: number;
  private maxErrors: number;
  constructor(maxPages = 6, maxErrors = 2) { this.maxPages = maxPages; this.maxErrors = maxErrors; }
  allowPage(): boolean {
    if (this.abandoned || this.pages >= this.maxPages) return false;
    this.pages++;
    return true;
  }
  recordError(): void { this.errors++; }
  get abandoned(): boolean { return this.errors >= this.maxErrors; }
}

/** What the crawler does with one browser request: only GET leaves the browser, robots guards navigations. */
export function routeVerdict(req: { method: string; isMainNavigation: boolean }, allowed: boolean): "continue" | "abort-method" | "abort-robots" {
  if (req.method.toUpperCase() !== "GET") return "abort-method";
  if (req.isMainNavigation && !allowed) return "abort-robots";
  return "continue";
}
