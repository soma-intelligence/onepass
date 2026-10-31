// Field classifier models in the service worker (Task 15). A model build (ONEPASS_CLASSIFIER gbm or
// encoder) ships model/<kind>.onnx (+ model/tokenizer.json for the encoder) and the onnxruntime-web
// WASM file; build.mjs copies them from ONEPASS_MODEL_DIR. The default build has none of this.
//
// Runtime contract (rulings R18, R20): the ONNX metadata must carry this build's feature_version
// (features.ts), vectorizer_version (vectorize.ts), the label list of shared/model-labels.ts and,
// for gbm, vector_dim == VECTOR_DIM (for the encoder vector_dim is its max token length, checked
// against the tokenizer). Anything else is refused: loadModel gives null and the content scripts
// keep their heuristics. The refusal is logged once, in dev builds only.
//
// Nothing here imports onnxruntime: the runtime is injected (ort.ts in builds, fakes in tests).

import type { ModelSessionLike } from "../content/detect/classifier";
import { FEATURE_VERSION, type FieldFeatures } from "../content/detect/features";
import { serialize, VECTOR_DIM, VECTORIZER_VERSION, vectorize } from "../content/detect/vectorize";
import { MODEL_LABELS, type ModelLabel } from "../shared/model-labels";
import { encode, loadTokenizer, type Tokenizer } from "./tokenizer";

export type ModelKind = "gbm" | "encoder";

export interface ModelAssets {
  /** Bytes of a file packaged with the extension, or null when absent. */
  read(path: string): Promise<Uint8Array | null>;
}

export interface Tensor {
  type: "float32" | "int64";
  data: Float32Array | BigInt64Array;
  dims: number[];
}

export interface RuntimeSession {
  run(feeds: Record<string, Tensor>): Promise<Record<string, { data: unknown; dims: readonly number[] }>>;
}

export interface InferenceRuntime {
  open(model: Uint8Array): Promise<RuntimeSession>;
}

export interface ModelSession extends ModelSessionLike {
  /** Encoder: total tokens the request would run (the worker's token budget). Absent for gbm (cost = fields). */
  tokens?(features: FieldFeatures[]): number;
}

// ---- ONNX metadata (ModelProto.metadata_props, field 14) ----

const METADATA_FIELD = 14;

/** Reads `metadata_props` of an ONNX ModelProto; skips every other field; throws on malformed bytes. */
export function onnxMetadata(b: Uint8Array): Record<string, string> {
  const utf8 = new TextDecoder("utf-8", { fatal: true });
  const varint = (r: { at: number; end: number }): number => {
    let v = 0;
    let mul = 1;
    for (let i = 0; i < 10; i++) {
      if (r.at >= r.end) throw new Error("onnx: truncated varint");
      const x = b[r.at++]!;
      v += (x & 0x7f) * mul;
      if ((x & 0x80) === 0) return v;
      mul *= 128;
    }
    throw new Error("onnx: varint too long");
  };
  /** Fields of one message as (field number, wire type, start, end of a length-delimited body). */
  const fields = (start: number, end: number, each: (field: number, body: [number, number] | null) => void): void => {
    const r = { at: start, end };
    while (r.at < end) {
      const tag = varint(r);
      const field = Math.floor(tag / 8);
      switch (tag % 8) {
        case 0:
          varint(r);
          each(field, null);
          break;
        case 1:
          r.at += 8;
          each(field, null);
          break;
        case 2: {
          const n = varint(r);
          if (n > end - r.at) throw new Error("onnx: length past the end");
          each(field, [r.at, r.at + n]);
          r.at += n;
          break;
        }
        case 5:
          r.at += 4;
          each(field, null);
          break;
        default:
          throw new Error("onnx: unsupported wire type");
      }
      if (r.at > end) throw new Error("onnx: truncated field");
    }
  };
  const out: Record<string, string> = {};
  fields(0, b.length, (field, body) => {
    if (field !== METADATA_FIELD || body === null) return;
    let key: string | undefined;
    let value = "";
    fields(body[0], body[1], (f, v) => {
      if (v === null) return;
      if (f === 1) key = utf8.decode(b.subarray(v[0], v[1]));
      else if (f === 2) value = utf8.decode(b.subarray(v[0], v[1]));
    });
    if (key !== undefined) out[key] = value;
  });
  return out;
}

const isCount = (s: string | undefined): boolean => s !== undefined && /^[1-9][0-9]{0,8}$/.test(s);

/** Why this build must refuse a model with this metadata, or null when it is compatible. */
export function checkMetadata(kind: ModelKind, meta: Record<string, string>): string | null {
  if (meta.model !== kind) return `model is ${JSON.stringify(meta.model)}, expected ${kind}`;
  if (meta.feature_version !== String(FEATURE_VERSION)) return `feature_version ${JSON.stringify(meta.feature_version)} != ${FEATURE_VERSION}`;
  if (meta.vectorizer_version !== String(VECTORIZER_VERSION)) {
    return `vectorizer_version ${JSON.stringify(meta.vectorizer_version)} != ${VECTORIZER_VERSION}`;
  }
  let labels: unknown;
  try {
    labels = JSON.parse(meta.labels ?? "");
  } catch {
    return "labels are not JSON";
  }
  if (!Array.isArray(labels) || labels.length !== MODEL_LABELS.length || labels.some((l, i) => l !== MODEL_LABELS[i])) {
    return "labels differ from the lab Role list + none";
  }
  if (kind === "gbm" && meta.vector_dim !== String(VECTOR_DIM)) return `vector_dim ${JSON.stringify(meta.vector_dim)} != ${VECTOR_DIM}`;
  if (kind === "encoder" && !isCount(meta.vector_dim)) return `vector_dim ${JSON.stringify(meta.vector_dim)} is not a token length`;
  return null;
}

// ---- sessions ----

function argmax(probs: Float32Array, n: number): { label: ModelLabel; score: number }[] {
  const c = MODEL_LABELS.length;
  const out: { label: ModelLabel; score: number }[] = [];
  for (let i = 0; i < n; i++) {
    let best = 0;
    for (let k = 1; k < c; k++) if (probs[i * c + k]! > probs[i * c + best]!) best = k;
    out.push({ label: MODEL_LABELS[best]!, score: probs[i * c + best]! });
  }
  return out;
}

function probabilities(out: Record<string, { data: unknown; dims: readonly number[] }>, n: number): Float32Array {
  const p = out.probabilities;
  const c = MODEL_LABELS.length;
  if (!p || !(p.data instanceof Float32Array) || p.dims.length !== 2 || p.dims[0] !== n || p.dims[1] !== c || p.data.length !== n * c) {
    throw new Error("model: unexpected output");
  }
  return p.data;
}

function gbmSession(rt: RuntimeSession): ModelSession {
  return {
    kind: "gbm",
    async predict(features) {
      if (features.length === 0) return [];
      const n = features.length;
      const data = new Float32Array(n * VECTOR_DIM);
      features.forEach((f, i) => data.set(vectorize(f), i * VECTOR_DIM));
      const out = await rt.run({ features: { type: "float32", data, dims: [n, VECTOR_DIM] } });
      return argmax(probabilities(out, n), n);
    },
  };
}

function encoderSession(rt: RuntimeSession, tok: Tokenizer): ModelSession {
  return {
    kind: "encoder",
    tokens: (features) => features.reduce((n, f) => n + encode(tok, serialize(f)).length, 0),
    async predict(features: FieldFeatures[]) {
      if (features.length === 0) return [];
      const n = features.length;
      const seqs = features.map((f) => encode(tok, serialize(f)));
      // Pad to the longest sequence (ml/onepass_ml/train_encoder.py batch_inputs).
      const l = Math.max(...seqs.map((s) => s.length));
      const ids = new BigInt64Array(n * l).fill(BigInt(tok.padId));
      const mask = new BigInt64Array(n * l);
      seqs.forEach((s, i) => s.forEach((id, j) => {
        ids[i * l + j] = BigInt(id);
        mask[i * l + j] = 1n;
      }));
      const out = await rt.run({
        input_ids: { type: "int64", data: ids, dims: [n, l] },
        attention_mask: { type: "int64", data: mask, dims: [n, l] },
      });
      return argmax(probabilities(out, n), n);
    },
  };
}

let refusalLogged = false;
function refuse(kind: ModelKind, why: string, log?: (msg: string) => void): null {
  if (__DEV__ && !refusalLogged) {
    refusalLogged = true;
    (log ?? console.warn)(`onepass: ${kind} model refused (${why}); heuristics stay in use`);
  }
  return null;
}

export interface LoadDeps {
  assets: ModelAssets;
  /** Started only for a model that passed the metadata checks. */
  runtime: () => Promise<InferenceRuntime>;
  log?: (msg: string) => void;
}

/** The packaged model of `kind`, or null when absent, refused (see the header) or not loadable. */
export async function loadModel(kind: ModelKind, deps: LoadDeps): Promise<ModelSession | null> {
  try {
    const bytes = await deps.assets.read(`model/${kind}.onnx`);
    if (bytes === null) return refuse(kind, "absent", deps.log);
    const why = checkMetadata(kind, onnxMetadata(bytes));
    if (why !== null) return refuse(kind, why, deps.log);
    let tok: Tokenizer | null = null;
    if (kind === "encoder") {
      const raw = await deps.assets.read("model/tokenizer.json");
      if (raw === null) return refuse(kind, "tokenizer.json absent", deps.log);
      tok = loadTokenizer(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)));
      const dim = Number(onnxMetadata(bytes).vector_dim);
      if (tok.maxLength !== dim) return refuse(kind, `tokenizer max_length ${tok.maxLength} != vector_dim ${dim}`, deps.log);
    }
    const rt = await (await deps.runtime()).open(bytes);
    return tok === null ? gbmSession(rt) : encoderSession(rt, tok);
  } catch (e) {
    return refuse(kind, e instanceof Error ? e.message : "load failed", deps.log);
  }
}

/** Files of the installed extension, read with fetch (the service worker's own origin). */
export function extensionAssets(getURL: (path: string) => string, fetcher: typeof fetch = fetch): ModelAssets {
  return {
    async read(path) {
      try {
        const r = await fetcher(getURL(path));
        return r.ok ? new Uint8Array(await r.arrayBuffer()) : null;
      } catch {
        return null;
      }
    },
  };
}
