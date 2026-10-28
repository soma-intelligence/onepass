// @vitest-environment node
// Classifier builds (Task 15, ruling R20). The default build (ONEPASS_CLASSIFIER unset or
// "heuristic") must hold no model, no onnxruntime-web code or WASM, and today's CSP exactly. A
// model build copies the model from ONEPASS_MODEL_DIR plus the onnxruntime WASM file, and only it
// gains 'wasm-unsafe-eval'. The bench models (git-ignored) are needed for the model build tests.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error build.mjs has no type declarations
import { buildAll, classifierConfig } from "../../build.mjs";

const root = join(__dirname, "..", "..");
const GBM = join(root, "..", "ml", "out", "bench-model");
const ENC = join(root, "..", "ml", "out", "bench-encoder");
const hasGbm = existsSync(join(GBM, "gbm.onnx"));
const hasEnc = existsSync(join(ENC, "encoder.onnx")) && existsSync(join(ENC, "tokenizer.json"));
if (!hasGbm || !hasEnc) console.warn("build-classifier.test: bench models absent (ml/out/bench-model, ml/out/bench-encoder), model build tests skipped");

const DEFAULT_CSP = "script-src 'self'; object-src 'none'";
const MODEL_CSP = "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'";
// Strings only onnxruntime-web and the model loader contain.
const ORT_MARKERS = ["onnxruntime", "InferenceSession", "wasmBinary", "ort-wasm-simd-threaded", "vectorizer_version", "MatMulInteger"];

const dirs: string[] = [];
const saved = { c: process.env.ONEPASS_CLASSIFIER, d: process.env.ONEPASS_MODEL_DIR };
afterEach(() => {
  for (const [k, v] of [["ONEPASS_CLASSIFIER", saved.c], ["ONEPASS_MODEL_DIR", saved.d]] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function build(env: { c?: string; d?: string }, browsers = ["chromium", "firefox", "safari"]): Promise<string> {
  const dist = mkdtempSync(join(tmpdir(), "onepass-classifier-build-"));
  dirs.push(dist);
  if (env.c === undefined) delete process.env.ONEPASS_CLASSIFIER;
  else process.env.ONEPASS_CLASSIFIER = env.c;
  if (env.d === undefined) delete process.env.ONEPASS_MODEL_DIR;
  else process.env.ONEPASS_MODEL_DIR = env.d;
  await buildAll(browsers, false, false, dist);
  return dist;
}

const files = (dir: string): string[] =>
  readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)).map((x) => `${f}/${x}`) : [f]));
const manifest = (dist: string, b: string) => JSON.parse(readFileSync(join(dist, b, "manifest.json"), "utf8"));

describe("classifier config", () => {
  it("defaults to heuristic, refuses unknown kinds and a model build without its files", () => {
    expect(classifierConfig({})).toEqual({ kind: "heuristic" });
    expect(classifierConfig({ ONEPASS_CLASSIFIER: "" })).toEqual({ kind: "heuristic" });
    expect(classifierConfig({ ONEPASS_CLASSIFIER: "heuristic", ONEPASS_MODEL_DIR: GBM })).toEqual({ kind: "heuristic" });
    expect(() => classifierConfig({ ONEPASS_CLASSIFIER: "GBM" })).toThrow(/ONEPASS_CLASSIFIER/);
    expect(() => classifierConfig({ ONEPASS_CLASSIFIER: "1" })).toThrow(/ONEPASS_CLASSIFIER/);
    expect(() => classifierConfig({ ONEPASS_CLASSIFIER: "gbm" })).toThrow(/ONEPASS_MODEL_DIR/);
    expect(() => classifierConfig({ ONEPASS_CLASSIFIER: "gbm", ONEPASS_MODEL_DIR: join(root, "test") })).toThrow(/gbm\.onnx/);
    expect(() => classifierConfig({ ONEPASS_CLASSIFIER: "encoder", ONEPASS_MODEL_DIR: GBM })).toThrow(/encoder\.onnx/);
  });
});

describe("default build", () => {
  it("contains nothing of the classifier models, and keeps today's CSP", async () => {
    const dist = await build({});
    for (const b of ["chromium", "firefox", "safari"]) {
      const all = files(join(dist, b));
      expect(all.filter((f) => /\.(onnx|wasm)$|^model\/|^ort\/|tokenizer\.json$/.test(f)), b).toEqual([]);
      for (const f of all.filter((x) => x.endsWith(".js"))) {
        const code = readFileSync(join(dist, b, f), "utf8");
        for (const m of ORT_MARKERS) expect(code, `${b}/${f} has ${m}`).not.toContain(m);
      }
      expect(manifest(dist, b).content_security_policy).toEqual({ extension_pages: DEFAULT_CSP });
    }
  }, 120_000);

  it("ONEPASS_CLASSIFIER=heuristic is the same build as unset", async () => {
    const a = await build({});
    const b = await build({ c: "heuristic", d: GBM });
    for (const br of ["chromium", "firefox", "safari"]) {
      expect(files(join(b, br))).toEqual(files(join(a, br)));
      for (const f of files(join(a, br))) expect(readFileSync(join(b, br, f)).equals(readFileSync(join(a, br, f))), `${br}/${f}`).toBe(true);
    }
  }, 120_000);
});

describe("model builds", () => {
  it.skipIf(!hasGbm)("gbm: model, WASM and wasm-unsafe-eval, nothing of the encoder", async () => {
    const dist = await build({ c: "gbm", d: GBM }, ["chromium", "firefox"]);
    for (const b of ["chromium", "firefox"]) {
      expect(readFileSync(join(dist, b, "model/gbm.onnx")).equals(readFileSync(join(GBM, "gbm.onnx")))).toBe(true);
      expect(existsSync(join(dist, b, "model/encoder.onnx"))).toBe(false);
      expect(existsSync(join(dist, b, "model/tokenizer.json"))).toBe(false);
      expect(existsSync(join(dist, b, "ort/ort-wasm-simd-threaded.wasm"))).toBe(true);
      expect(manifest(dist, b).content_security_policy).toEqual({ extension_pages: MODEL_CSP });
      const bg = readFileSync(join(dist, b, "background.js"), "utf8");
      expect(bg).toContain("InferenceSession");
      // onnxruntime stays in the service worker: the content script never holds it.
      const cs = readFileSync(join(dist, b, "content.js"), "utf8");
      for (const m of ["InferenceSession", "wasmBinary"]) expect(cs).not.toContain(m);
      expect(cs).toContain('type: "classify"');
    }
  }, 120_000);

  it.skipIf(!hasEnc)("encoder: model and tokenizer", async () => {
    const dist = await build({ c: "encoder", d: ENC }, ["chromium"]);
    expect(readFileSync(join(dist, "chromium/model/encoder.onnx")).equals(readFileSync(join(ENC, "encoder.onnx")))).toBe(true);
    expect(readFileSync(join(dist, "chromium/model/tokenizer.json")).equals(readFileSync(join(ENC, "tokenizer.json")))).toBe(true);
    expect(existsSync(join(dist, "chromium/model/gbm.onnx"))).toBe(false);
    expect(manifest(dist, "chromium").content_security_policy).toEqual({ extension_pages: MODEL_CSP });
  }, 120_000);
});
