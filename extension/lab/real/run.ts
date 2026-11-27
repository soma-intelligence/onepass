// CLI of the real-site bench (README.md in this folder):
//   npm run lab:real-site -- [--sites N] [--kinds live,profile,replica] [--workers N] [--out DIR] [--managers bitwarden,1password,lastpass,dashlane]
// Run by `node --experimental-strip-types`, this file only checks the options
// and starts the Playwright runner (lab/real/playwright.config.ts), whose
// TypeScript loader takes the product modules the bench imports; under the
// runner it is one test that builds the extension and the native host with
// the fictional vault, launches the browsers (OnePass plus the other managers
// asked for), plays the journey of visit.ts on every target and writes
// results.jsonl, report.md and shots/ in the output folder.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { createHash } from "node:crypto";
import { test, type BrowserContext, type Page } from "@playwright/test";
import { countByRule, ResultsWriter, type ResultRow, type RunMeta, writeReport } from "./report.ts";
import {
  EXT_ROOT, liveTargets, type ManagerName, parseArgs, pickHosts, profileTargets, readSignedIn, readTranco, replicaTargets, type RealOptions, type Target, type TargetKind, USAGE,
} from "./targets.ts";

const UNDER_RUNNER = process.env.LAB_REAL_UNDER_RUNNER === "1";
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Chromium's id of an unpacked extension: SHA-256 of its path, 32 hex digits mapped to a-p (e2e/fixtures.ts). */
export function unpackedExtensionId(path: string): string {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function until(fn: () => boolean | Promise<boolean>, timeout: number, what: string): Promise<void> {
  const end = Date.now() + timeout;
  for (;;) {
    if (await fn()) return;
    if (Date.now() >= end) throw new Error(`lab:real: ${what} (after ${timeout} ms)`);
    await sleep(200);
  }
}

/** Replica server of replica/server.ts (written by another tool); `spki` when it exposes its certificate key. */
interface ReplicaServer { port: number; hosts: string[]; close(): Promise<void>; spki?: string }

interface Bench {
  context: BrowserContext;
  onePassId: string;
  ownPages: WeakSet<Page>;
  close(): Promise<void>;
}

async function main(argv: string[]): Promise<void> {
  const opts: RealOptions = parseArgs(argv);
  const started = new Date();
  const { chromium } = await import("@playwright/test");
  const { buildLabExtension, LAB_DIST_ROOT } = await import("../build-marker.ts");
  const { installHost } = await import("../../e2e/host.ts");
  const { GuardLog, HOST_GAP_MS, installGuard, RobotsGate, defaultRobotsFetch, UA_TOKEN } = await import("./guard.ts");
  const { HostPacer } = await import("../corpus/schedule.ts");
  const { stageVault } = await import("./vault.ts");
  const { visitSite } = await import("./visit.ts");

  mkdirSync(opts.out, { recursive: true });
  const writer = new ResultsWriter(opts.out);
  const notes: string[] = [];
  const tranco = readTranco();
  const picked = pickHosts(tranco, opts.sites, opts.only);
  console.log(`lab:real: ${picked.length} site(s), kinds ${opts.kinds.join(",")}, out ${opts.out}`);

  // The extension (own build folder per run) and the native host with the fictional vault of the whole top 1000.
  const built = buildLabExtension(LAB_DIST_ROOT, basename(opts.out), { ONEPASS_CLASSIFIER: process.env.ONEPASS_CLASSIFIER, ONEPASS_MODEL_DIR: process.env.ONEPASS_MODEL_DIR });
  const root = mkdtempSync(join(tmpdir(), "onepass-real-"));
  const vault = await stageVault(root, tranco);
  writeFileSync(join(opts.out, "vault-summary.json"), JSON.stringify(vault.summary, null, 2));
  console.log(`lab:real: vault of ${vault.summary.items} fictional logins staged`);

  // Other managers.
  let managers: string[] = [];
  if (opts.managers.length > 0) {
    const fakes = opts.managers.filter((m): m is Exclude<ManagerName, "bitwarden"> => m !== "bitwarden");
    try {
      const mod = (await import(new URL("./managers/index.ts", import.meta.url).href)) as {
        managerExtensions(o: { bitwarden: boolean; fakes: ("1password" | "lastpass" | "dashlane")[] }): string[];
      };
      try {
        managers = mod.managerExtensions({ bitwarden: opts.managers.includes("bitwarden"), fakes });
      } catch (e) {
        notes.push(`managers: ${String((e as Error).message).split("\n")[0]}; ran without Bitwarden`);
        managers = mod.managerExtensions({ bitwarden: false, fakes });
      }
    } catch (e) {
      notes.push(`managers/index.ts could not be loaded (${String((e as Error).message).split("\n")[0]}); ran without other managers`);
    }
  }

  // The browser's own user agent, plus the bench's token.
  const probe = await chromium.launch({ channel: "chromium", headless: true });
  const ua = `${(await (await probe.newPage()).evaluate(() => navigator.userAgent)).replace("HeadlessChrome", "Chrome")} ${UA_TOKEN}`;
  await probe.close();

  const guard = new GuardLog();
  const pacer = new HostPacer(HOST_GAP_MS);
  const robots = new RobotsGate(defaultRobotsFetch(ua));
  const words = JSON.parse(readFileSync(join(EXT_ROOT, "src/shared/l10n/fr.json"), "utf8")) as Record<string, string>;
  const pairLabel = words["popup.pairWithOnepass"] ?? "Appairer avec OnePass";
  const matchLabel = words["popup.codesMatch"] ?? "Les codes sont identiques";

  /** One browser: OnePass (+ managers), the guard, the native host installed for its profile, paired. */
  async function openBench(kind: TargetKind, replica?: ReplicaServer): Promise<Bench> {
    const tmp = mkdtempSync(join(tmpdir(), "onepass-real-bench-"));
    const persistent = kind === "profile";
    const userDataDir = persistent ? opts.profileDir : join(tmp, "profile");
    const exts = [built.dir, ...managers];
    const args = [
      `--disable-extensions-except=${exts.join(",")}`,
      `--load-extension=${exts.join(",")}`,
      "--lang=fr-FR",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-sync",
      "--disable-component-update",
    ];
    if (replica) {
      args.push(`--host-resolver-rules=${replica.hosts.map((h) => `MAP ${h} 127.0.0.1:${replica.port}`).join(", ")}, EXCLUDE localhost`);
      // Pinned to the replica's key when the server gives it; else every certificate (nothing but the replica answers: the guard aborts every other host).
      args.push(replica.spki ? `--ignore-certificate-errors-spki-list=${replica.spki}` : "--ignore-certificate-errors");
    }
    const ownPages = new WeakSet<Page>();
    let onePassId: string | undefined;
    let context: BrowserContext;
    try {
      context = await chromium.launchPersistentContext(userDataDir, {
        channel: "chromium", headless: !opts.headed, viewport: { width: 1280, height: 860 }, locale: "fr-FR", userAgent: ua, acceptDownloads: false, args,
      });
    } catch (e) {
      rmSync(tmp, { recursive: true, force: true });
      throw new Error(`lab:real: browser launch failed (${kind}): ${String((e as Error).message).split("\n")[0]}`);
    }
    const manifestDir = join(userDataDir, "NativeMessagingHosts");
    const close = async () => {
      await context.close().catch(() => undefined);
      // The persistent profile keeps nothing of this run's host.
      if (persistent) rmSync(join(manifestDir, "me.somalabs.onepass.dev.json"), { force: true });
      rmSync(tmp, { recursive: true, force: true });
    };
    try {
      await installGuard(context, { log: guard, robots: replica ? null : robots, ...(replica ? { allowedHosts: new Set(replica.hosts) } : {}), onePassId: () => onePassId, ownPages });
      const expected = unpackedExtensionId(built.dir);
      const findWorker = () => context.serviceWorkers().find((w) => w.url().startsWith(`chrome-extension://${expected}/`));
      let worker = findWorker();
      if (!worker) {
        worker = await context.waitForEvent("serviceworker", { predicate: (w) => w.url().startsWith(`chrome-extension://${expected}/`), timeout: 20_000 }).catch(() => undefined);
      }
      if (!worker) throw new Error("lab:real: the OnePass service worker never started");
      onePassId = new URL(worker.url()).host;
      const host = installHost(tmp, manifestDir, onePassId, vault.cache, vault.host);
      // Pairing through the popup, as a user does.
      const popup = await context.newPage();
      ownPages.add(popup);
      try {
        await popup.goto(`chrome-extension://${onePassId}/popup.html`);
        const pair = popup.getByRole("button", { name: pairLabel });
        if (await pair.waitFor({ state: "visible", timeout: 10_000 }).then(() => true, () => false)) {
          await pair.click();
          await until(() => host.log().includes("DEV MODE"), 15_000, `native host never started (wrapper ${host.wrapper})`);
          const sas = popup.locator(".sas");
          await until(async () => /^\d{3} \d{3}$/.test(((await sas.textContent().catch(() => "")) ?? "").trim()), 60_000, "no pairing code shown");
          const shown = ((await sas.textContent()) ?? "").trim();
          await until(() => host.codes().at(-1) === shown, 10_000, "the host logged another pairing code");
          await popup.getByRole("button", { name: matchLabel }).click();
          await until(() => host.log().includes("pairing stored"), 15_000, "pairing not stored");
        }
        const status = (await popup.evaluate(() => chrome.runtime.sendMessage({ type: "popup_status" }).catch(() => null))) as { ok?: { locked?: unknown } } | null;
        if (status?.ok?.locked !== false) throw new Error(`lab:real: the vault is not open after pairing (${JSON.stringify(status)?.slice(0, 120)})`);
      } finally {
        await popup.close().catch(() => undefined);
      }
      return { context, onePassId, ownPages, close };
    } catch (e) {
      await close();
      throw e;
    }
  }

  const emit = (row: ResultRow) => writer.add(row);

  async function runKind(kind: TargetKind, targets: Target[], workers: number, replica?: ReplicaServer): Promise<void> {
    if (targets.length === 0) {
      notes.push(`${kind}: no target`);
      return;
    }
    let next = 0;
    const visited = new Set<number>();
    const failures: string[] = [];
    const worker = async (w: number) => {
      let bench: Bench;
      try {
        bench = await openBench(kind, replica);
      } catch (e) {
        failures.push(String((e as Error).message).split("\n")[0]!);
        return;
      }
      try {
        while (next < targets.length) {
          const i = next++;
          const t = targets[i]!;
          visited.add(i);
          // A signed-out visitor: no cookie of an earlier site (the persistent profile keeps its own).
          if (kind !== "profile") await bench.context.clearCookies().catch(() => undefined);
          const before = writer.rows.length;
          await visitSite({
            context: bench.context, onePassId: bench.onePassId, pacer, robots: replica ? null : robots, guard, vault: vault.index, out: opts.out,
            managersLoaded: managers.length > 0, timeBoxMs: opts.timeBoxMs, ownPages: bench.ownPages, emit,
          }, t);
          const rows = writer.rows.slice(before);
          const bad = rows.filter((r) => r.verdict === "violation").length;
          console.log(`  [${kind} w${w}] ${t.rank} ${t.host}: ${rows.length} rows, ${bad} violation(s)${rows.some((r) => r.verdict === "timeout") ? ", time box" : ""}`);
        }
      } finally {
        await bench.close();
      }
    };
    await Promise.all(Array.from({ length: Math.min(workers, targets.length) }, (_, w) => worker(w)));
    for (const f of [...new Set(failures)]) notes.push(`${kind}: ${f}`);
    targets.forEach((t, i) => {
      if (!visited.has(i)) emit({ host: t.host, kind, step: "journey", rule: "-", verdict: "error", detail: `not visited: ${failures[0] ?? "no browser"}` });
    });
  }

  try {
    for (const kind of opts.kinds) {
      if (kind === "live") {
        await runKind("live", liveTargets(picked), opts.workers);
      } else if (kind === "profile") {
        if (!existsSync(opts.profileDir)) {
          notes.push(`profile: no profile in ${opts.profileDir} (prepare it with npm run lab:real-site:profile); skipped`);
          continue;
        }
        const signedIn = readSignedIn(opts.profileDir);
        if (!signedIn) notes.push("profile: no signed-in.json in the profile; every picked site visited, signed-in state read from the page");
        // One browser only: a persistent profile cannot be opened twice.
        await runKind("profile", profileTargets(picked, signedIn), 1);
      } else {
        let server: ReplicaServer | undefined;
        try {
          const mod = (await import(new URL("./replica/server.ts", import.meta.url).href)) as { startReplicaServer(o: { dir: string }): Promise<ReplicaServer> };
          server = await mod.startReplicaServer({ dir: opts.replicaDir });
        } catch (e) {
          notes.push(`replica: replica/server.ts unavailable or failed (${String((e as Error).message).split("\n")[0]}); replica targets skipped`);
          continue;
        }
        try {
          await runKind("replica", replicaTargets(server.hosts, picked, tranco), opts.workers, server);
        } finally {
          await server.close().catch(() => undefined);
        }
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
    const meta: RunMeta = {
      startedAt: started.toISOString(), finishedAt: new Date().toISOString(), kinds: opts.kinds, sites: picked.length,
      managers: opts.managers.filter((m) => managers.some((p) => p.includes(m))), notes, vault: vault.summary,
    };
    const report = writeReport(opts.out, writer.rows, meta);
    writeFileSync(join(opts.out, "run.json"), JSON.stringify(meta, null, 2));
    const counts = countByRule(writer.rows);
    console.log(`lab:real: report ${report}`);
    for (const [rule, c] of Object.entries(counts)) console.log(`  ${rule}: ${Object.entries(c).map(([v, n]) => `${v} ${n}`).join(", ") || "none"}`);
    for (const n of notes) console.log(`  note: ${n}`);
  }
}

/** Direct run: check the options, then hand over to the Playwright runner. */
function cli(): void {
  const argv = process.argv.slice(2);
  let opts: ReturnType<typeof parseArgs>;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    console.error((e as Error).message);
    process.exitCode = 2;
    return;
  }
  if (opts.help) {
    console.log(USAGE);
    return;
  }
  const cliJs = join(EXT_ROOT, "node_modules/@playwright/test/cli.js");
  const r = spawnSync(process.execPath, [cliJs, "test", "-c", join(EXT_ROOT, "lab/real/playwright.config.ts")], {
    cwd: EXT_ROOT,
    stdio: "inherit",
    env: { ...process.env, LAB_REAL_UNDER_RUNNER: "1", LAB_REAL_ARGS: JSON.stringify(argv) },
  });
  process.exitCode = r.status ?? 1;
}

if (UNDER_RUNNER) {
  test("real-site bench", async () => {
    test.setTimeout(0);
    await main(JSON.parse(process.env.LAB_REAL_ARGS ?? "[]") as string[]);
  });
} else if (process.argv[1] && basename(process.argv[1]) === "run.ts") {
  cli();
}
