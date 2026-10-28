// Per-run lab build (Task 16, C1). The lab used to build every classifier into the shared dist/chromium,
// where a concurrent e2e or smoke rebuild (or a parallel classifier pass) silently changed the build
// under test. Each run now builds into `dist-lab/<run name>/chromium` and checks the result against the
// requested classifier before using it; the marker (kind, sha256 of the model files) goes in classifier.json.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ClassifierKind } from "./compare.ts";

const EXT_ROOT = fileURLToPath(new URL("../", import.meta.url));
/** Root of the per-run builds (git-ignored). */
export const LAB_DIST_ROOT = join(EXT_ROOT, "dist-lab");
const MODEL_FILES: Record<Exclude<ClassifierKind, "heuristic">, string[]> = { gbm: ["gbm.onnx"], encoder: ["encoder.onnx", "tokenizer.json"] };

export interface BuildMarker { classifier: ClassifierKind; modelSha256?: string }

const sha = (file: string): string => createHash("sha256").update(readFileSync(file)).digest("hex");

/** Kind of the build the environment asks for (as build.mjs reads it). */
export function kindOf(env: Record<string, string | undefined>): ClassifierKind {
  const k = env.ONEPASS_CLASSIFIER || "heuristic";
  if (k !== "heuristic" && k !== "gbm" && k !== "encoder") throw new Error(`ONEPASS_CLASSIFIER must be heuristic|gbm|encoder, got ${k}`);
  return k;
}

/**
 * Builds the chromium extension of `env`'s classifier into `<root>/<name>/chromium` (own process, own
 * variables, nothing shared) and verifies it. Returns the extension folder and its marker.
 */
export function buildLabExtension(root: string, name: string, env: Record<string, string | undefined>): { dir: string; marker: BuildMarker } {
  const kind = kindOf(env);
  const dist = join(root, name);
  execFileSync(process.execPath, ["-e", "import('./build.mjs').then((m) => m.buildAll(['chromium'], false, false, process.argv[1]))", dist], {
    cwd: EXT_ROOT, stdio: "inherit", env: { ...process.env, ...env } as NodeJS.ProcessEnv,
  });
  const dir = join(dist, "chromium");
  return { dir, marker: verifyBuild(dir, kind, env.ONEPASS_MODEL_DIR) };
}

/** Throws unless the extension in `dir` is the `kind` build (manifest CSP, model files byte-identical to `modelDir`'s). */
export function verifyBuild(dir: string, kind: ClassifierKind, modelDir?: string): BuildMarker {
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as { content_security_policy?: { extension_pages?: string } };
  const wasm = (manifest.content_security_policy?.extension_pages ?? "").includes("'wasm-unsafe-eval'");
  if (kind === "heuristic") {
    if (wasm || existsSync(join(dir, "model"))) throw new Error(`the build in ${dir} is not a heuristic build (model files or wasm CSP present)`);
    return { classifier: "heuristic" };
  }
  if (!wasm) throw new Error(`the build in ${dir} is not a ${kind} build (manifest CSP has no wasm-unsafe-eval)`);
  if (!modelDir) throw new Error(`verifying a ${kind} build needs its model folder`);
  const parts: string[] = [];
  for (const f of MODEL_FILES[kind]) {
    const built = join(dir, "model", f);
    if (!existsSync(built)) throw new Error(`the build in ${dir} has no model/${f}`);
    const h = sha(built);
    if (h !== sha(join(modelDir, f))) throw new Error(`model/${f} in ${dir} differs (sha256) from ${modelDir}/${f}`);
    parts.push(h);
  }
  return { classifier: kind, modelSha256: createHash("sha256").update(parts.join("")).digest("hex") };
}
