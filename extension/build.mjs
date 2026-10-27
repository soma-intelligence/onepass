// Build script: bundles the extension for each browser into dist/<browser>/.
// Usage: node build.mjs [chromium|firefox|safari ...] [--dev] [--e2e]
// Source maps are off by default (this is a password manager); --dev enables
// inline maps. --e2e writes dist/<browser>-e2e/ instead, whose service worker
// entry is src/background/e2e-entry.ts (the regular one plus a handle for the
// end-to-end security suite); the regular build never bundles that file.
import { build as esbuild } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const BROWSERS = ["chromium", "firefox", "safari"];
const UI_PAGES = ["popup", "menu", "overlay", "save"];

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Deep merge: objects merge by key, arrays merge by index, else override. */
export function merge(base, over) {
  if (Array.isArray(base) && Array.isArray(over)) {
    const len = Math.max(base.length, over.length);
    return Array.from({ length: len }, (_, i) =>
      i < base.length && i < over.length ? merge(base[i], over[i]) : (over[i] ?? base[i]),
    );
  }
  if (isObject(base) && isObject(over)) {
    const out = { ...base };
    for (const [k, v] of Object.entries(over)) out[k] = k in base ? merge(base[k], v) : v;
    return out;
  }
  return over;
}

export function mergeManifest(browser, dir = join(root, "manifests")) {
  const read = (f) => JSON.parse(readFileSync(join(dir, f), "utf8"));
  const merged = merge(read("base.json"), read(`${browser}.json`));
  return merged;
}

async function buildBrowser(browser, dev, e2e = false) {
  const out = join(root, "dist", e2e ? `${browser}-e2e` : browser);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const common = {
    bundle: true,
    target: "es2022",
    sourcemap: dev ? "inline" : false,
    minify: false,
    logLevel: "warning",
  };
  await esbuild({
    ...common,
    entryPoints: [join(root, e2e ? "src/background/e2e-entry.ts" : "src/background/index.ts")],
    outfile: join(out, "background.js"),
    format: browser === "firefox" ? "iife" : "esm",
  });
  await esbuild({
    ...common,
    entryPoints: [join(root, "src/content/index.ts")],
    outfile: join(out, "content.js"),
    format: "iife",
  });
  for (const page of UI_PAGES) {
    await esbuild({
      ...common,
      entryPoints: [join(root, `src/ui/${page}.ts`)],
      outfile: join(out, `${page}.js`),
      format: "iife",
    });
    cpSync(join(root, `src/ui/${page}.html`), join(out, `${page}.html`));
  }
  cpSync(join(root, "src/ui/theme.css"), join(out, "theme.css"));
  cpSync(join(root, "src/_locales"), join(out, "_locales"), { recursive: true });
  writeFileSync(
    join(out, "manifest.json"),
    JSON.stringify(mergeManifest(browser), null, 2) + "\n",
  );
}

export async function buildAll(browsers = BROWSERS, dev = false, e2e = false) {
  for (const b of browsers) await buildBrowser(b, dev, e2e);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const dev = args.includes("--dev");
  const e2e = args.includes("--e2e");
  const picked = args.filter((a) => !a.startsWith("--"));
  for (const b of picked) {
    if (!BROWSERS.includes(b)) throw new Error(`unknown browser: ${b}`);
  }
  await buildAll(picked.length ? picked : BROWSERS, dev, e2e);
}
