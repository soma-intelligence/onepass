// The real development native host (core/onepass-native-host) for the
// end-to-end tests: fixture vault (fictional items), automatic pairing
// approval (the code still goes to its log, where tests read it), installed
// as the native messaging host `me.somalabs.onepass.dev` of a Chromium
// profile.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BridgeClient } from "../src/bridge/client";
import { DEV_HOST as NATIVE_HOST } from "../src/background/native";
import { NodeTransport } from "../test/bridge/node-transport";

export const CORE = fileURLToPath(new URL("../../core/", import.meta.url));
export const HOST_BIN = join(CORE, "target/debug/onepass-native-host");
export const FIXTURE = join(CORE, "onepass-native-host/fixtures/e2e.json");
export const FIXTURE_CACHE = "fixture-cache.bin";
const CARGO_PATH = `${join(homedir(), ".cargo/bin")}:${process.env.PATH ?? ""}`;

/** `cargo build --locked -p onepass-native-host` (debug: the fixture source is debug only). */
export function buildHost(): void {
  try {
    execFileSync("cargo", ["build", "--locked", "-p", "onepass-native-host"], {
      cwd: CORE,
      env: { ...process.env, PATH: CARGO_PATH },
      stdio: "pipe",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (e) {
    const out = e as { stdout?: Buffer; stderr?: Buffer };
    throw new Error(`e2e: cargo build failed\n${out.stdout?.toString() ?? ""}${out.stderr?.toString() ?? ""}`);
  }
}

export interface HostConfig {
  data_dir: string;
  allowed_extensions: string[];
  source: { kind: "fixture"; path: string };
  approval: "auto";
  unlocked: boolean;
  reprompt: "deny";
}

/** The host binary and fixture vault the browser runs, copied out of the repository. */
export interface StagedHost {
  bin: string;
  fixture: string;
}

/**
 * Copies the host binary and the fixture vault (default: the e2e one) into `dir` (a temporary
 * directory). The browser must never exec the binary from the checkout:
 * when the repository lives in a privacy-protected folder (~/Desktop,
 * ~/Documents, ~/Downloads on macOS), the native host process inherits the
 * browser as its responsible app, and dyld's open() of its own executable
 * blocks on a folder-access consent that headless Chromium never answers.
 * The host then never starts and pairing hangs with no host log at all.
 */
export function stageHost(dir: string, fixture: string = FIXTURE): StagedHost {
  mkdirSync(dir, { recursive: true });
  const bin = join(dir, "onepass-native-host");
  copyFileSync(HOST_BIN, bin);
  chmodSync(bin, 0o755);
  const staged = join(dir, "e2e.json");
  copyFileSync(fixture, staged);
  return { bin, fixture: staged };
}

export function hostConfig(dataDir: string, extensionId: string, fixture: string): HostConfig {
  return {
    data_dir: dataDir,
    allowed_extensions: [extensionId],
    source: { kind: "fixture", path: fixture },
    approval: "auto",
    unlocked: true,
    reprompt: "deny",
  };
}

/**
 * Builds the encrypted fixture store once (about 10 s in a debug build) by
 * pairing and opening one session with the TypeScript client; each test then
 * starts from a copy of `<dir>/data/fixture-cache.bin`.
 */
export async function prebuildFixtureCache(dir: string, staged: StagedHost): Promise<string> {
  mkdirSync(dir, { recursive: true });
  const dataDir = join(dir, "data");
  const config = join(dir, "native-host.json");
  writeFileSync(config, JSON.stringify(hostConfig(dataDir, "e2e-prebuild", staged.fixture)));
  const t = new NodeTransport(staged.bin, ["chrome-extension://e2e-prebuild/"], {
    ...process.env,
    ONEPASS_NATIVE_HOST_CONFIG: config,
  });
  try {
    const client = new BridgeClient(t);
    const record = await client.pair("OnePass", "Chromium", async () => true);
    await client.open(record);
    await client.request({ op: "status" });
    client.close();
  } finally {
    t.close();
    await t.exited;
  }
  const cache = join(dataDir, FIXTURE_CACHE);
  if (!existsSync(cache)) throw new Error("e2e: the native host wrote no fixture cache");
  return cache;
}

export interface InstalledHost {
  dataDir: string;
  config: string;
  wrapper: string;
  manifest: string;
  log(): string;
  /** Every pairing code the host logged, in order. */
  codes(): string[];
}

/**
 * Installs the host for one test: data dir (seeded with the prebuilt
 * cache), config, wrapper script (Chrome passes no custom arguments) and the
 * host manifest in `<manifestDir>/me.somalabs.onepass.dev.json`.
 */
export function installHost(
  dir: string,
  manifestDir: string,
  extensionId: string,
  cache: string,
  staged: StagedHost,
): InstalledHost {
  const dataDir = join(dir, "host-data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  copyFileSync(cache, join(dataDir, FIXTURE_CACHE));
  const config = join(dir, "native-host.json");
  writeFileSync(config, JSON.stringify(hostConfig(dataDir, extensionId, staged.fixture)));
  const wrapper = join(dir, "onepass-native-host.sh");
  writeFileSync(wrapper, `#!/bin/sh\nexec "${staged.bin}" --config "${config}" "$@"\n`, { mode: 0o755 });
  mkdirSync(manifestDir, { recursive: true });
  const manifest = join(manifestDir, `${NATIVE_HOST}.json`);
  writeFileSync(
    manifest,
    JSON.stringify(
      {
        name: NATIVE_HOST,
        description: "OnePass development native host (e2e tests)",
        path: wrapper,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extensionId}/`],
      },
      null,
      2,
    ),
  );
  const logPath = join(dataDir, "native-host.log");
  const log = () => (existsSync(logPath) ? readFileSync(logPath, "utf8") : "");
  return {
    dataDir,
    config,
    wrapper,
    manifest,
    log,
    codes: () => [...log().matchAll(/pairing code: (\d{3} \d{3})/g)].map((m) => m[1] ?? ""),
  };
}
