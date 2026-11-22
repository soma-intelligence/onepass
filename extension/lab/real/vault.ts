// Fictional vault of the real-site bench (README "Coffre fictif"): one login
// per Tranco domain (`lab-<n>@example.test`, a random password, never a real
// one), a second account on about 15 % of the sites, an exact duplicate on a
// few, served by the development native host as lab/run/global-setup.ts does
// (stageHost, then the encrypted fixture cache built once). Which sites get
// two accounts or a duplicate is a hash of the host: the same on every run.
// The passwords are drawn anew on every run and only ever written to the
// staged fixture outside the checkout.
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getDomain } from "tldts";
import type { StagedHost } from "../../e2e/host.ts";

/** Share of the sites with a second account. */
export const TWO_ACCOUNTS_PERCENT = 15;
/** Share of the sites whose first login also exists as an exact duplicate (same identifier and password). */
export const DUPLICATE_PERCENT = 4;

export interface FixtureLogin {
  type: "login";
  title: string;
  vault: string;
  urls: { url: string; rule: "domain" }[];
  fields: { username: string; password: string };
}

export interface RealFixture {
  _comment: string;
  account: string;
  vaults: { name: string; color?: string }[];
  items: FixtureLogin[];
}

/** How many logins the vault holds per registrable domain (never an identifier, never a password). */
export interface VaultIndex {
  /** Logins of the registrable domain of `host` (0 when none). */
  loginsFor(host: string): number;
  readonly domains: number;
  readonly items: number;
}

/** A stable bucket 0..99 of `host` for `salt`. */
export function bucket(host: string, salt: string): number {
  return createHash("sha256").update(`${salt}:${host}`).digest().readUInt32BE(0) % 100;
}

/** A fictional password: never a real one, never reused across sites. */
export function fictionalPassword(random: (n: number) => Buffer = randomBytes): string {
  return `Lab-${random(15).toString("base64url")}`;
}

/** The registrable domain of `host` (itself when tldts knows none). */
export function siteOf(host: string): string {
  return getDomain(host) ?? host;
}

/** The vault for `hosts` (Tranco order: the login of rank n is `lab-<n>@example.test`). */
export function buildVault(hosts: readonly string[], random: (n: number) => Buffer = randomBytes): RealFixture {
  const items: FixtureLogin[] = [];
  hosts.forEach((host, i) => {
    const n = i + 1;
    const urls = [{ url: `https://${host}`, rule: "domain" as const }];
    const first: FixtureLogin = {
      type: "login", title: host, vault: "Personnel", urls, fields: { username: `lab-${n}@example.test`, password: fictionalPassword(random) },
    };
    items.push(first);
    if (bucket(host, "two-accounts") < TWO_ACCOUNTS_PERCENT) {
      items.push({
        type: "login", title: `${host} (pro)`, vault: "Travail", urls, fields: { username: `lab-${n}-b@example.test`, password: fictionalPassword(random) },
      });
    }
    if (bucket(host, "duplicate") < DUPLICATE_PERCENT) {
      items.push({ ...first, title: `${host} (copie)`, fields: { ...first.fields } });
    }
  });
  return {
    _comment: "Fictional data of the real-site bench (lab/real/vault.ts): identifiers lab-<n>@example.test, random passwords, never real.",
    account: "lab@example.test",
    vaults: [{ name: "Personnel", color: "#5856D6" }, { name: "Travail", color: "#34C759" }],
    items,
  };
}

/** Logins per registrable domain of a vault. */
export function indexVault(fixture: RealFixture): VaultIndex {
  const per = new Map<string, number>();
  for (const it of fixture.items) {
    for (const u of it.urls) {
      const site = siteOf(new URL(u.url).hostname);
      per.set(site, (per.get(site) ?? 0) + 1);
    }
  }
  return {
    loginsFor: (host) => per.get(siteOf(host)) ?? 0,
    domains: per.size,
    items: fixture.items.length,
  };
}

/** What the report may say of the vault: counts only. */
export function vaultSummary(fixture: RealFixture): { items: number; sites: number; twoAccounts: number; duplicates: number } {
  const titles = fixture.items.map((i) => i.title);
  return {
    items: fixture.items.length,
    sites: titles.filter((t) => !t.endsWith(" (pro)") && !t.endsWith(" (copie)")).length,
    twoAccounts: titles.filter((t) => t.endsWith(" (pro)")).length,
    duplicates: titles.filter((t) => t.endsWith(" (copie)")).length,
  };
}

export interface StagedVault {
  host: StagedHost;
  cache: string;
  index: VaultIndex;
  summary: ReturnType<typeof vaultSummary>;
}

/**
 * Builds the host (cargo), writes the fixture under `root` (a temporary directory outside the
 * checkout: the browser must not exec the host from a privacy-protected folder, see e2e/host.ts),
 * stages the host with it and builds the encrypted fixture cache once.
 */
export async function stageVault(root: string, hosts: readonly string[]): Promise<StagedVault> {
  // Loaded here only: the host module resolves the core folder at import time.
  const { buildHost, prebuildFixtureCache, stageHost } = await import("../../e2e/host.ts");
  buildHost();
  mkdirSync(root, { recursive: true });
  const fixture = buildVault(hosts);
  const file = join(root, "real-fixture.json");
  writeFileSync(file, JSON.stringify(fixture), { mode: 0o600 });
  const host = stageHost(join(root, "host"), file);
  const cache = await prebuildFixtureCache(join(root, "prebuild"), host);
  return { host, cache, index: indexVault(fixture), summary: vaultSummary(fixture) };
}
