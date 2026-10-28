// @vitest-environment node
// Service worker model loader (Task 15): a model whose metadata does not match this build's feature
// extractor, vectorizer or label set is refused (the content script then keeps its heuristics), and
// a compatible model answers one label per field. The bench models (git-ignored, ml/out) are used
// when present; those tests skip with a message otherwise.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { checkMetadata, loadModel, type InferenceRuntime, type ModelAssets, onnxMetadata } from "../../src/background/model";
import { ortRuntime } from "../../src/background/ort";
import { FEATURE_VERSION, type FieldFeatures } from "../../src/content/detect/features";
import { VECTOR_DIM, VECTORIZER_VERSION } from "../../src/content/detect/vectorize";
import { MODEL_LABELS } from "../../src/shared/model-labels";

const root = join(__dirname, "..", "..");
const GBM = join(root, "..", "ml", "out", "bench-model");
const ENC = join(root, "..", "ml", "out", "bench-encoder");
const hasGbm = existsSync(join(GBM, "gbm.onnx"));
const hasEnc = existsSync(join(ENC, "encoder.onnx")) && existsSync(join(ENC, "tokenizer.json"));
if (!hasGbm) console.warn("model.test: ml/out/bench-model/gbm.onnx absent, gbm inference tests skipped");
if (!hasEnc) console.warn("model.test: ml/out/bench-encoder/{encoder.onnx,tokenizer.json} absent, encoder inference tests skipped");

const CASES = (JSON.parse(readFileSync(join(root, "test/vectors/vectorize.json"), "utf8")) as { cases: { name: string; features: FieldFeatures }[] }).cases;
const caseOf = (n: string) => CASES.find((c) => c.name === n)!.features;

// ---- a minimal protobuf writer for ModelProto fixtures ----
function varint(n: number): number[] {
  const out: number[] = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return out;
}
const bytes = (s: string) => Array.from(new TextEncoder().encode(s));
const len = (field: number, body: number[]) => [...varint((field << 3) | 2), ...varint(body.length), ...body];
const entry = (k: string, v: string) => len(14, [...len(1, bytes(k)), ...len(2, bytes(v))]);
function modelProto(meta: Record<string, string>): Uint8Array {
  const graph = len(7, [...len(1, bytes("node")), ...len(2, bytes("graph"))]);
  const ir = [...varint((1 << 3) | 0), ...varint(9)];
  const fixed64 = [...varint((99 << 3) | 1), 1, 2, 3, 4, 5, 6, 7, 8];
  const fixed32 = [...varint((98 << 3) | 5), 1, 2, 3, 4];
  return Uint8Array.from([...ir, ...len(2, bytes("onepass")), ...graph, ...fixed64, ...fixed32, ...Object.entries(meta).flatMap(([k, v]) => entry(k, v))]);
}

const GOOD_GBM = {
  feature_version: String(FEATURE_VERSION),
  vectorizer_version: String(VECTORIZER_VERSION),
  vector_dim: String(VECTOR_DIM),
  labels: JSON.stringify(MODEL_LABELS),
  model: "gbm",
};
const GOOD_ENC = { ...GOOD_GBM, vector_dim: "128", model: "encoder" };

describe("onnxMetadata", () => {
  it("reads metadata_props and skips every other field", () => {
    expect(onnxMetadata(modelProto(GOOD_GBM))).toEqual(GOOD_GBM);
  });

  it("throws on truncated or malformed bytes", () => {
    const b = modelProto(GOOD_GBM);
    expect(() => onnxMetadata(b.slice(0, b.length - 3))).toThrow();
    expect(() => onnxMetadata(Uint8Array.from([0x0f]))).toThrow(); // wire type 7
    expect(() => onnxMetadata(Uint8Array.from([0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f]))).toThrow(); // length past the end
  });

  it.skipIf(!hasGbm)("reads the bench gbm metadata", () => {
    const m = onnxMetadata(readFileSync(join(GBM, "gbm.onnx")));
    expect(m.model).toBe("gbm");
    expect(m.vector_dim).toBe("4096");
  });
});

describe("checkMetadata", () => {
  it("accepts this build's gbm and encoder (encoder vector_dim is the token length, not VECTOR_DIM)", () => {
    expect(checkMetadata("gbm", GOOD_GBM)).toBeNull();
    expect(checkMetadata("encoder", GOOD_ENC)).toBeNull();
  });

  it.each([
    ["feature_version differs", "gbm", { ...GOOD_GBM, feature_version: String(FEATURE_VERSION + 1) }],
    ["feature_version missing", "gbm", { ...GOOD_GBM, feature_version: undefined }],
    ["vectorizer_version differs", "gbm", { ...GOOD_GBM, vectorizer_version: String(VECTORIZER_VERSION + 1) }],
    ["vectorizer_version missing (pre-R18 export)", "gbm", { ...GOOD_GBM, vectorizer_version: undefined }],
    ["vectorizer_version differs (encoder)", "encoder", { ...GOOD_ENC, vectorizer_version: "0" }],
    ["labels reordered", "gbm", { ...GOOD_GBM, labels: JSON.stringify([...MODEL_LABELS].reverse()) }],
    ["labels without none", "gbm", { ...GOOD_GBM, labels: JSON.stringify(MODEL_LABELS.slice(0, -1)) }],
    ["labels with an extra role", "gbm", { ...GOOD_GBM, labels: JSON.stringify([...MODEL_LABELS, "confirm_password"]) }],
    ["labels not JSON", "gbm", { ...GOOD_GBM, labels: "username,email" }],
    ["gbm vector_dim differs", "gbm", { ...GOOD_GBM, vector_dim: "2048" }],
    ["gbm vector_dim missing", "gbm", { ...GOOD_GBM, vector_dim: undefined }],
    ["encoder vector_dim not a length", "encoder", { ...GOOD_ENC, vector_dim: "-3" }],
    ["encoder vector_dim not an integer", "encoder", { ...GOOD_ENC, vector_dim: "12.5" }],
    ["model kind differs", "encoder", { ...GOOD_ENC, model: "gbm" }],
    ["version with spaces", "gbm", { ...GOOD_GBM, feature_version: ` ${FEATURE_VERSION}` }],
  ] as const)("refuses: %s", (_name, kind, meta) => {
    const clean = Object.fromEntries(Object.entries(meta).filter(([, v]) => v !== undefined)) as Record<string, string>;
    expect(checkMetadata(kind, clean)).not.toBeNull();
  });
});

function memAssets(files: Record<string, Uint8Array>): ModelAssets {
  return { read: async (p) => files[p] ?? null };
}

const fakeRuntime = (probs: (n: number) => Float32Array): InferenceRuntime => ({
  open: async () => ({
    run: async (feeds) => {
      const n = (Object.values(feeds)[0] as { dims: number[] }).dims[0]!;
      return { probabilities: { data: probs(n), dims: [n, MODEL_LABELS.length] } };
    },
  }),
});

describe("loadModel", () => {
  const oneHot = (k: number) => (n: number) => {
    const out = new Float32Array(n * MODEL_LABELS.length);
    for (let i = 0; i < n; i++) out[i * MODEL_LABELS.length + k] = 0.8;
    return out;
  };

  it("absent model: null, and the runtime is never started", async () => {
    const runtime = vi.fn(async () => fakeRuntime(oneHot(0)));
    expect(await loadModel("gbm", { assets: memAssets({}), runtime })).toBeNull();
    expect(runtime).not.toHaveBeenCalled();
  });

  it("incompatible metadata: null, and the runtime is never started", async () => {
    const runtime = vi.fn(async () => fakeRuntime(oneHot(0)));
    const bad = modelProto({ ...GOOD_GBM, feature_version: "99" });
    expect(await loadModel("gbm", { assets: memAssets({ "model/gbm.onnx": bad }), runtime })).toBeNull();
    expect(await loadModel("gbm", { assets: memAssets({ "model/gbm.onnx": Uint8Array.from([0xff]) }), runtime })).toBeNull();
    expect(runtime).not.toHaveBeenCalled();
  });

  it("a runtime that cannot open the model: null", async () => {
    const runtime = async (): Promise<InferenceRuntime> => ({ open: async () => { throw new Error("bad op"); } });
    expect(await loadModel("gbm", { assets: memAssets({ "model/gbm.onnx": modelProto(GOOD_GBM) }), runtime })).toBeNull();
  });

  it("encoder: missing, malformed or mismatched tokenizer gives null", async () => {
    const tok = JSON.parse(readFileSync(join(root, "test/vectors/tokenizer.json"), "utf8")).tokenizer as { truncation: { max_length: number } };
    const enc = modelProto(GOOD_ENC);
    const runtime = async () => fakeRuntime(oneHot(1));
    expect(await loadModel("encoder", { assets: memAssets({ "model/encoder.onnx": enc }), runtime })).toBeNull();
    expect(await loadModel("encoder", { assets: memAssets({ "model/encoder.onnx": enc, "model/tokenizer.json": bytes("{") as unknown as Uint8Array }), runtime })).toBeNull();
    const other = { ...tok, truncation: { ...tok.truncation, max_length: 64 } };
    const files = { "model/encoder.onnx": enc, "model/tokenizer.json": Uint8Array.from(bytes(JSON.stringify(other))) };
    expect(await loadModel("encoder", { assets: memAssets(files), runtime })).toBeNull();
    const ok = { "model/encoder.onnx": enc, "model/tokenizer.json": Uint8Array.from(bytes(JSON.stringify(tok))) };
    const s = await loadModel("encoder", { assets: memAssets(ok), runtime });
    expect(s?.kind).toBe("encoder");
    expect(await s!.predict([caseOf("english_email")])).toEqual([{ label: MODEL_LABELS[1], score: expect.closeTo(0.8, 5) }]);
  });

  it("gbm: one label per field, argmax of the probabilities; a wrong output shape throws", async () => {
    const s = await loadModel("gbm", { assets: memAssets({ "model/gbm.onnx": modelProto(GOOD_GBM) }), runtime: async () => fakeRuntime(oneHot(2)) });
    expect(await s!.predict([caseOf("english_email"), caseOf("password_login")])).toEqual([
      { label: "password", score: expect.closeTo(0.8, 5) },
      { label: "password", score: expect.closeTo(0.8, 5) },
    ]);
    expect(await s!.predict([])).toEqual([]);
    const wrong: InferenceRuntime = { open: async () => ({ run: async () => ({ probabilities: { data: new Float32Array(3), dims: [1, 3] } }) }) };
    const w = await loadModel("gbm", { assets: memAssets({ "model/gbm.onnx": modelProto(GOOD_GBM) }), runtime: async () => wrong });
    await expect(w!.predict([caseOf("english_email")])).rejects.toThrow();
  });
});

const fileAssets = (dir: string): ModelAssets => ({
  read: async (p) => {
    const f = join(dir, p.replace(/^model\//, ""));
    return existsSync(f) ? new Uint8Array(readFileSync(f)) : null;
  },
});

describe("bench models on onnxruntime-web (wasm)", () => {
  const wasm = () => new Uint8Array(readFileSync(join(root, "node_modules/onnxruntime-web/dist/ort-wasm-simd-threaded.wasm")));

  it.skipIf(!hasGbm)("gbm reads email and password fields", async () => {
    const s = await loadModel("gbm", { assets: fileAssets(GBM), runtime: () => ortRuntime(wasm()) });
    expect(s?.kind).toBe("gbm");
    const out = await s!.predict([caseOf("english_email"), caseOf("password_login")]);
    expect(out.map((o) => o.label)).toEqual(["email", "password"]);
    for (const o of out) expect(o.score).toBeGreaterThan(0.5);
  }, 30_000);

  it.skipIf(!hasEnc)("encoder (MatMulInteger, DynamicQuantizeLinear) reads email and password fields", async () => {
    const s = await loadModel("encoder", { assets: fileAssets(ENC), runtime: () => ortRuntime(wasm()) });
    expect(s?.kind).toBe("encoder");
    const out = await s!.predict([caseOf("english_email"), caseOf("password_login"), caseOf("japanese")]);
    expect(out.slice(0, 2).map((o) => o.label)).toEqual(["email", "password"]);
    expect(MODEL_LABELS).toContain(out[2]!.label);
  }, 60_000);
});
