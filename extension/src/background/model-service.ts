// The `classify` handler of model builds (Task 15). app.ts imports this module only behind
// `__CLASSIFIER__ !== "heuristic"` (a dynamic import esbuild drops from the default build), so
// neither the model code nor onnxruntime-web reaches a default build.
import { sameSite } from "../shared/domain";
import type { ModelLabel } from "../shared/model-labels";
import type { BgExt } from "./ext";
import type { CsContext, Frames } from "./frames";
import { extensionAssets, loadModel, type ModelKind, type ModelSession } from "./model";
import { ORT_WASM, ortRuntime } from "./ort";

export type ClassifyReply =
  | null
  | { kind: ModelKind; crossSite: true }
  | { kind: ModelKind; crossSite: false; labels?: { label: ModelLabel; score: number }[] };

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
}): (m: { fields: Parameters<ModelSession["predict"]>[0] }, from: CsContext) => Promise<ClassifyReply> {
  return async (m, from) => {
    if (from.frameId !== 0) {
      const top = await deps.frames.details(from.tabId, 0);
      if (!top || !sameSite(top.url, from.origin) || !top.url.startsWith("https://")) return { kind: deps.kind, crossSite: true };
    }
    const s = await deps.session();
    if (s === null || s.kind !== deps.kind) return null;
    if (m.fields.length === 0) return { kind: s.kind, crossSite: false };
    return { kind: s.kind, crossSite: false, labels: await s.predict(m.fields) };
  };
}
