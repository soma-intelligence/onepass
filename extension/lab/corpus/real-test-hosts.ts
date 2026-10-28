// Isolation of the real test set (Ruling R13). The generator pools labels from
// patterns.json, so a real-test page must never feed the distiller: the host
// list is committed (real-test-hosts.json: { seed, hosts }) and distill drops
// every sample of those sites, from every source, before counting anything.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Sample } from "./types.ts";

export const REAL_TEST_HOSTS_FILE = join(dirname(fileURLToPath(import.meta.url)), "real-test-hosts.json");

export interface RealTestHosts { seed: string; hosts: string[]; pages: number }

const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne"]);

/** Registrable site of a host, by a short rule (last two labels, three under co.uk style suffixes): sub-domains and www share it. */
export function siteOf(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const n = labels[labels.length - 1]!.length === 2 && SECOND_LEVEL.has(labels[labels.length - 2]!) ? 3 : 2;
  return labels.slice(-n).join(".");
}

export function readRealTestHosts(file: string = REAL_TEST_HOSTS_FILE): RealTestHosts {
  const v = JSON.parse(readFileSync(file, "utf8")) as Partial<RealTestHosts>;
  if (typeof v.seed !== "string" || !Array.isArray(v.hosts) || !v.hosts.every((h) => typeof h === "string")) {
    throw new Error(`${file}: expected { seed, hosts: string[] }`);
  }
  if (typeof v.pages !== "number") throw new Error(`${file}: expected a numeric "pages"`);
  return { seed: v.seed, hosts: v.hosts, pages: v.pages };
}

/** Samples whose site is not one of `hosts`. */
export function withoutHosts(samples: Sample[], hosts: string[]): Sample[] {
  const banned = new Set(hosts.map(siteOf));
  return samples.filter((s) => !banned.has(siteOf(s.host)));
}
