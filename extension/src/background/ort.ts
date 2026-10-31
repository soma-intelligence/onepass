// onnxruntime-web behind the InferenceRuntime of model.ts. Bundled only in model builds: the
// service worker imports this module behind `__CLASSIFIER__ !== "heuristic"`, which esbuild drops
// from the default build. WASM backend, one thread, no proxy worker (a service worker can start
// neither threads nor workers); the .wasm bytes are passed in (build.mjs packages them under ort/),
// so nothing is fetched or imported from a computed URL.
import * as ort from "onnxruntime-web/wasm";
import type { InferenceRuntime } from "./model";

export const ORT_WASM = "ort/ort-wasm-simd-threaded.wasm";

export async function ortRuntime(wasm: Uint8Array): Promise<InferenceRuntime> {
  ort.env.wasm.numThreads = 1;
  ort.env.wasm.proxy = false;
  ort.env.wasm.wasmBinary = wasm;
  return {
    async open(model) {
      const s = await ort.InferenceSession.create(model, { executionProviders: ["wasm"], graphOptimizationLevel: "all" });
      return {
        async run(feeds) {
          const tensors: Record<string, ort.Tensor> = {};
          for (const [k, t] of Object.entries(feeds)) tensors[k] = new ort.Tensor(t.type, t.data, t.dims);
          const out = await s.run(tensors);
          const res: Record<string, { data: unknown; dims: readonly number[] }> = {};
          for (const [k, t] of Object.entries(out)) res[k] = { data: t.data, dims: t.dims };
          return res;
        },
      };
    },
  };
}
