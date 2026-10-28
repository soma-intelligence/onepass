#!/usr/bin/env node
// Installs the native messaging manifest of the OnePass app's relay
// (`me.somalabs.onepass`, spec docs/specs/2026-10-27-release-bridge-design.md):
// Chrome and Firefox then launch `<OnePass.app>/Contents/Helpers/onepass-relay`,
// which reaches the vault unlocked in the app. macOS only.
//
// Usage:
//   node scripts/install-app-host.mjs --app /Applications/OnePass.app
//        --browser chrome|chromium|firefox|all [--extension-id <id>] [--profile <user-data-dir>]
//
// - Chrome and Chromium need the extension id (`--extension-id`); the app
//   must list it too (build setting ONEPASS_BROWSER_EXTENSIONS). Firefox uses
//   `onepass@somalabs.me`.
// - `--profile` writes `<dir>/NativeMessagingHosts/` (Chromium family only).
// - Writes only the manifest files; never touches the app.
import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";

const HOST_NAME = "me.somalabs.onepass";
const FIREFOX_ID = "onepass@somalabs.me";
const CHROME_ID = /^[a-p]{32}$/;

function parse(argv) {
  const out = { browser: "all" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === "--app") out.app = resolve(next());
    else if (a === "--browser") out.browser = next();
    else if (a === "--extension-id") out.extensionId = next();
    else if (a === "--profile") out.profile = resolve(next());
    else if (a === "--help" || a === "-h") out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

const dirs = {
  chrome: "Google/Chrome/NativeMessagingHosts",
  chromium: "Chromium/NativeMessagingHosts",
  firefox: "Mozilla/NativeMessagingHosts",
};

/** The manifest for `browser`, pointing at `relay`. */
export function manifestFor(browser, relay, extensionId) {
  const m = { name: HOST_NAME, description: "OnePass", path: relay, type: "stdio" };
  if (browser === "firefox") return { ...m, allowed_extensions: [FIREFOX_ID] };
  if (!extensionId || !CHROME_ID.test(extensionId)) throw new Error(`${browser}: pass --extension-id <32 letters a-p>`);
  return { ...m, allowed_origins: [`chrome-extension://${extensionId}/`] };
}

function main() {
  const o = parse(process.argv.slice(2));
  if (o.help) {
    console.log("node scripts/install-app-host.mjs --app <OnePass.app> --browser chrome|chromium|firefox|all [--extension-id <id>] [--profile <dir>]");
    return;
  }
  if (platform() !== "darwin") throw new Error("the OnePass app relay is macOS only");
  if (!o.app) throw new Error("pass --app <path to OnePass.app>");
  const relay = join(o.app, "Contents/Helpers/onepass-relay");
  if (!existsSync(relay) || !statSync(relay).isFile()) {
    throw new Error(`no relay in this app: ${relay} (only builds signed by a team carry it)`);
  }
  const browsers = o.browser === "all" ? ["chrome", "chromium", "firefox"] : [o.browser];
  for (const b of browsers) if (!(b in dirs)) throw new Error(`unknown browser: ${b}`);
  if (o.profile && browsers.includes("firefox")) throw new Error("--profile applies to chrome or chromium only");
  for (const b of browsers) {
    if (b !== "firefox" && !o.extensionId && o.browser === "all") continue;
    const dir = o.profile ? join(o.profile, "NativeMessagingHosts") : join(homedir(), "Library/Application Support", dirs[b]);
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${HOST_NAME}.json`);
    writeFileSync(file, `${JSON.stringify(manifestFor(b, relay, o.extensionId), null, 2)}\n`);
    console.log(`${b}: ${file}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (e) {
    console.error(`install-app-host: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}
