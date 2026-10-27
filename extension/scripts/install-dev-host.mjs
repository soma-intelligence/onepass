#!/usr/bin/env node
// Installs the development native messaging host (spec 9) for the user's
// browsers, or into one Chromium profile directory (tests).
//
// Usage:
//   node scripts/install-dev-host.mjs --browser chrome|chromium|firefox|all
//        [--profile <user-data-dir>] [--extension-id <id>]
//        [--host <binary>] [--config <native-host.json>]
//
// - The browser launches the host without custom arguments, so a wrapper
//   script `onepass-native-host.sh` (next to the config) execs the binary
//   with `--config`.
// - Chrome and Chromium need the extension id (`--extension-id`, else the
//   first `allowed_extensions` entry of the config that is not the Firefox
//   id). Firefox uses `onepass@somalabs.me`.
// - `--profile` writes `<dir>/NativeMessagingHosts/` (Chromium family only),
//   which Chromium reads for that user data directory.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOST_NAME = "me.somalabs.onepass.dev";
const FIREFOX_ID = "onepass@somalabs.me";
const here = dirname(fileURLToPath(import.meta.url));

function parse(argv) {
  const out = { browser: "all" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === "--browser") out.browser = next();
    else if (a === "--profile") out.profile = resolve(next());
    else if (a === "--extension-id") out.extensionId = next();
    else if (a === "--host") out.host = resolve(next());
    else if (a === "--config") out.config = resolve(next());
    else if (a === "--help" || a === "-h") out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

/** Per-user manifest directories. */
function userDir(browser) {
  const home = homedir();
  if (platform() === "darwin") {
    const base = join(home, "Library/Application Support");
    return {
      chrome: join(base, "Google/Chrome/NativeMessagingHosts"),
      chromium: join(base, "Chromium/NativeMessagingHosts"),
      firefox: join(base, "Mozilla/NativeMessagingHosts"),
    }[browser];
  }
  if (platform() === "linux") {
    return {
      chrome: join(home, ".config/google-chrome/NativeMessagingHosts"),
      chromium: join(home, ".config/chromium/NativeMessagingHosts"),
      firefox: join(home, ".mozilla/native-messaging-hosts"),
    }[browser];
  }
  throw new Error(`unsupported platform: ${platform()}`);
}

function main() {
  const o = parse(process.argv.slice(2));
  if (o.help) {
    console.log("node scripts/install-dev-host.mjs --browser chrome|chromium|firefox|all [--profile <dir>] [--extension-id <id>] [--host <binary>] [--config <file>]");
    return;
  }
  const browsers = o.browser === "all" ? ["chrome", "chromium", "firefox"] : [o.browser];
  for (const b of browsers) if (!["chrome", "chromium", "firefox"].includes(b)) throw new Error(`unknown browser: ${b}`);
  if (o.profile && browsers.includes("firefox")) throw new Error("--profile applies to chrome or chromium only");

  const host = o.host ?? resolve(here, "../../core/target/debug/onepass-native-host");
  const config = o.config ?? join(homedir(), ".onepass-dev/native-host.json");
  if (!existsSync(host)) throw new Error(`host binary not found: ${host} (cargo build -p onepass-native-host)`);
  if (!existsSync(config)) throw new Error(`host config not found: ${config}`);
  let extensionId = o.extensionId;
  if (!extensionId) {
    const allowed = JSON.parse(readFileSync(config, "utf8")).allowed_extensions ?? [];
    extensionId = allowed.find((x) => x !== FIREFOX_ID);
  }

  const wrapper = join(dirname(config), "onepass-native-host.sh");
  writeFileSync(wrapper, `#!/bin/sh\nexec "${host}" --config "${config}" "$@"\n`, { mode: 0o755 });

  for (const b of browsers) {
    const dir = o.profile ? join(o.profile, "NativeMessagingHosts") : userDir(b);
    const manifest = { name: HOST_NAME, description: "OnePass development native host", path: wrapper, type: "stdio" };
    if (b === "firefox") {
      manifest.allowed_extensions = [FIREFOX_ID];
    } else {
      if (!extensionId) throw new Error(`${b}: pass --extension-id (or list it in allowed_extensions)`);
      manifest.allowed_origins = [`chrome-extension://${extensionId}/`];
    }
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${HOST_NAME}.json`);
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`${b}: ${file}`);
  }
}

try {
  main();
} catch (e) {
  console.error(`install-dev-host: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
