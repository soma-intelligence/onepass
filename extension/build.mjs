// Build script: bundles the extension for each browser into dist/<browser>/.
// Usage: node build.mjs [chromium|firefox|safari ...] [--dev] [--e2e] [--dev-host]
// Source maps are off by default (this is a password manager); --dev enables
// inline maps. --e2e writes dist/<browser>-e2e/ instead, whose service worker
// entry is src/background/e2e-entry.ts (the regular one plus a handle for the
// end-to-end security suite); the regular build never bundles that file.
// The native messaging host is the OnePass app's (`me.somalabs.onepass`);
// --dev-host builds for the development host (`me.somalabs.onepass.dev`),
// as the end-to-end tests and the lab do. Safari ignores it.
//
// Field classifier (Task 15, ruling R20): ONEPASS_CLASSIFIER = heuristic (default) | gbm | encoder.
// A model build takes the model from ONEPASS_MODEL_DIR (gbm.onnx, or encoder.onnx +
// tokenizer.json), copies it to model/ and the onnxruntime-web WASM file to ort/, and adds
// 'wasm-unsafe-eval' to the extension pages CSP. The default build holds none of it: no model, no
// onnxruntime code, today's CSP.
import { build as esbuild } from "esbuild";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generate as generateDesignTokens } from "./scripts/gen-design-tokens.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const BROWSERS = ["chromium", "firefox", "safari"];
const UI_PAGES = ["popup", "menu", "overlay", "save", "passkey"];

const CLASSIFIERS = ["heuristic", "gbm", "encoder"];
const DEFAULT_CSP = "script-src 'self'; object-src 'none'";
const MODEL_CSP = "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'";
/** Files of a model build, by classifier kind (in ONEPASS_MODEL_DIR, copied to model/). */
const MODEL_FILES = { gbm: ["gbm.onnx"], encoder: ["encoder.onnx", "tokenizer.json"] };
/** The onnxruntime-web WASM binary of the "onnxruntime-web/wasm" entry (single build, SIMD). */
const ORT_WASM = "ort-wasm-simd-threaded.wasm";

/** Classifier of the build from the environment; throws on an unknown kind or missing model files. */
export function classifierConfig(env = process.env) {
  const kind = env.ONEPASS_CLASSIFIER || "heuristic";
  if (!CLASSIFIERS.includes(kind)) throw new Error(`ONEPASS_CLASSIFIER must be one of ${CLASSIFIERS.join(", ")}, got ${JSON.stringify(kind)}`);
  if (kind === "heuristic") return { kind };
  if (!env.ONEPASS_MODEL_DIR) throw new Error(`ONEPASS_CLASSIFIER=${kind} needs ONEPASS_MODEL_DIR`);
  const dir = resolve(env.ONEPASS_MODEL_DIR);
  for (const f of MODEL_FILES[kind]) {
    if (!existsSync(join(dir, f))) throw new Error(`ONEPASS_MODEL_DIR ${dir} has no ${f}`);
  }
  return { kind, dir };
}

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

export const APP_HOST = "me.somalabs.onepass";
export const DEV_HOST = "me.somalabs.onepass.dev";

async function buildBrowser(browser, dev, e2e = false, devHost = false, dist = join(root, "dist")) {
  const classifier = classifierConfig();
  const out = join(dist, e2e ? `${browser}-e2e` : browser);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const common = {
    bundle: true,
    target: "es2022",
    sourcemap: dev ? "inline" : false,
    minify: false,
    logLevel: "warning",
    // The dev-only form flow recorder (src/dev) exists only in a build made
    // with ONEPASS_LAB_RECORDER=1; otherwise esbuild drops every branch and
    // import behind the flag.
    // __CLASSIFIER__ drops the model code (and onnxruntime-web) from heuristic builds the same way.
    define: {
      __LAB_RECORDER__: String(process.env.ONEPASS_LAB_RECORDER === "1"),
      __CLASSIFIER__: JSON.stringify(classifier.kind),
      __DEV__: String(dev),
      __ONEPASS_NATIVE_HOST__: JSON.stringify(devHost ? DEV_HOST : APP_HOST),
    },
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
  // Passkeys (spec 3.2): the MAIN-world shim and its isolated relay, each a
  // bundle of its own (the shim shares nothing with the extension's code).
  await esbuild({
    ...common,
    define: { ...common.define, __PASSKEY_SHIM__: "true" },
    entryPoints: [join(root, "src/content/passkey-shim.ts")],
    outfile: join(out, "passkey-shim.js"),
    format: "iife",
  });
  await esbuild({
    ...common,
    define: { ...common.define, __PASSKEY_RELAY__: "true" },
    entryPoints: [join(root, "src/content/passkey.ts")],
    outfile: join(out, "passkey-relay.js"),
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
  cpSync(join(root, "src/icons"), join(out, "icons"), { recursive: true });
  const manifest = mergeManifest(browser);
  if (manifest.content_security_policy?.extension_pages !== DEFAULT_CSP) throw new Error("manifest CSP changed: update build.mjs");
  if (classifier.kind !== "heuristic") {
    mkdirSync(join(out, "model"));
    for (const f of MODEL_FILES[classifier.kind]) cpSync(join(classifier.dir, f), join(out, "model", f));
    mkdirSync(join(out, "ort"));
    const wasm = createRequire(import.meta.url).resolve(`onnxruntime-web/${ORT_WASM}`);
    cpSync(wasm, join(out, "ort", ORT_WASM));
    // WebAssembly compilation in the service worker; nothing else changes.
    manifest.content_security_policy = { ...manifest.content_security_policy, extension_pages: MODEL_CSP };
  }
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
}

export async function buildAll(browsers = BROWSERS, dev = false, e2e = false, devHost = false, dist = join(root, "dist")) {
  // The content script reads its colours from a generated mirror of src/ui/theme.css.
  const tokens = join(root, "src/shared/design-tokens.ts");
  const next = generateDesignTokens();
  if (!existsSync(tokens) || readFileSync(tokens, "utf8") !== next) writeFileSync(tokens, next);
  for (const b of browsers) await buildBrowser(b, dev, e2e, devHost, dist);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const dev = args.includes("--dev");
  const e2e = args.includes("--e2e");
  const devHost = args.includes("--dev-host");
  const picked = args.filter((a) => !a.startsWith("--"));
  for (const b of picked) {
    if (!BROWSERS.includes(b)) throw new Error(`unknown browser: ${b}`);
  }
  await buildAll(picked.length ? picked : BROWSERS, dev, e2e, devHost);
}
