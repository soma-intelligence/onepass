// The `classify` handler of model builds (Task 15). app.ts imports this module only behind
// `__CLASSIFIER__ !== "heuristic"` (a dynamic import esbuild drops from the default build), so
// neither the model code nor onnxruntime-web reaches a default build.
import { sameSite } from "../shared/domain";
import { MAX_CLASSIFY_FIELDS, type ModelLabel } from "../shared/model-labels";
import type { BgExt } from "./ext";
import type { CsContext, Frames } from "./frames";
import { extensionAssets, loadModel, type ModelKind, type ModelSession } from "./model";
import { ORT_WASM, ortRuntime } from "./ort";

export type ClassifyReply =
  | null
  | { kind: ModelKind; crossSite: true }
  | { kind: ModelKind; crossSite: false; labels?: { label: ModelLabel; score: number }[] }
  /** Over budget, the tab's inference still running, or the tab over its rate: the form keeps its heuristics. */
  | { kind: ModelKind; crossSite: false; refused: "budget" | "busy" | "rate" };

/**
 * Worker budget. Inference runs on the worker thread (WASM, no proxy), so one page must not be able
 * to hold it: one inference per tab at a time, at most `maxFields` fields (and, for the encoder,
 * `maxTokens` tokens) per request, and a token bucket of `rateBurst` requests per tab refilled at
 * `ratePerSecond`.
 */
export interface ClassifyLimits {
  maxFields: number;
  maxTokens: number;
  rateBurst: number;
  ratePerSecond: number;
}

export const DEFAULT_LIMITS: ClassifyLimits = { maxFields: MAX_CLASSIFY_FIELDS, maxTokens: 2048, rateBurst: 8, ratePerSecond: 2 };
/** Tabs whose rate state is kept (oldest dropped first). */
const MAX_TABS = 512;

/** Loads the packaged model of `kind` with onnxruntime-web; null when absent or refused (model.ts). */
export function loadClassifierModel(ext: Pick<BgExt, "runtime">, kind: ModelKind): Promise<ModelSession | null> {
  const assets = extensionAssets((p) => ext.runtime.getURL(p));
  return loadModel(kind, {
    assets,
    runtime: async () => {
      const wasm = await assets.read(ORT_WASM);
      if (wasm === null) throw new Error("onnxruntime wasm absent");
      return ortRuntime(wasm);
    },
  });
}

/**
 * `classify` from a content script. A child frame that is not of the top frame's site (or under a
 * non-HTTPS top frame) is told it is cross-site and gets no label: its fields stay on today's
 * roles and every fill there is refused anyway (R-10, frames.ts checkFillTarget). An empty list is
 * the handshake. null: no usable model in this worker.
 */
export function createClassifyHandler(deps: {
  kind: ModelKind;
  frames: Pick<Frames, "details">;
  session: () => Promise<ModelSession | null>;
  limits?: Partial<ClassifyLimits>;
  now?: () => number;
}): (m: { fields: Parameters<ModelSession["predict"]>[0] }, from: CsContext) => Promise<ClassifyReply> {
  const limits = { ...DEFAULT_LIMITS, ...deps.limits };
  const now = deps.now ?? Date.now;
  const tabs = new Map<number, { busy: boolean; tokens: number; at: number }>();
  const stateOf = (tabId: number) => {
    let st = tabs.get(tabId);
    if (st === undefined) {
      if (tabs.size >= MAX_TABS) tabs.delete(tabs.keys().next().value as number);
      st = { busy: false, tokens: limits.rateBurst, at: now() };
      tabs.set(tabId, st);
    }
    const t = now();
    st.tokens = Math.min(limits.rateBurst, st.tokens + ((t - st.at) / 1000) * limits.ratePerSecond);
    st.at = t;
    return st;
  };
  return async (m, from) => {
    if (from.frameId !== 0) {
      const top = await deps.frames.details(from.tabId, 0);
      if (!top || !sameSite(top.url, from.origin) || !top.url.startsWith("https://")) return { kind: deps.kind, crossSite: true };
    }
    const s = await deps.session();
    if (s === null || s.kind !== deps.kind) return null;
    if (m.fields.length === 0) return { kind: s.kind, crossSite: false };
    if (m.fields.length > limits.maxFields) return { kind: s.kind, crossSite: false, refused: "budget" };
    const st = stateOf(from.tabId);
    if (st.busy) return { kind: s.kind, crossSite: false, refused: "busy" };
    if (st.tokens < 1) return { kind: s.kind, crossSite: false, refused: "rate" };
    st.tokens -= 1;
    st.busy = true;
    try {
      if (s.tokens && s.tokens(m.fields) > limits.maxTokens) return { kind: s.kind, crossSite: false, refused: "budget" };
      return { kind: s.kind, crossSite: false, labels: await s.predict(m.fields) };
    } finally {
      st.busy = false;
    }
  };
}
