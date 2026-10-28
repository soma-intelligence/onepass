// @vitest-environment node
// Per-run lab builds (Task 16, C1): each classifier builds into its own folder, never into the shared
// dist/chromium, and the build is checked against the requested kind before a run uses it.
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildLabExtension, verifyBuild } from "../../lab/build-marker.ts";

const EXT = join(import.meta.dirname, "..", "..");
const tmp: string[] = [];
afterEach(() => { while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); });
const mk = () => { const d = mkdtempSync(join(tmpdir(), "bm-")); tmp.push(d); return d; };

describe("lab build per run", () => {
  it("two_classifier_builds_use_their_own_folders_and_leave_dist_chromium_alone", { timeout: 120_000 }, () => {
    const root = mk();
    const model = mk();
    writeFileSync(join(model, "gbm.onnx"), "fake-model-bytes");
    const shared = join(EXT, "dist", "chromium", "manifest.json");
    const before = existsSync(shared) ? statSync(shared).mtimeMs : null;

    const h = buildLabExtension(root, "s-heuristic", { ONEPASS_CLASSIFIER: "heuristic" });
    const g = buildLabExtension(root, "s-gbm", { ONEPASS_CLASSIFIER: "gbm", ONEPASS_MODEL_DIR: model });

    expect(h.dir).toBe(join(root, "s-heuristic", "chromium"));
    expect(g.dir).toBe(join(root, "s-gbm", "chromium"));
    expect(existsSync(join(h.dir, "model"))).toBe(false);
    expect(readFileSync(join(g.dir, "model", "gbm.onnx"), "utf8")).toBe("fake-model-bytes");
    expect(h.marker).toEqual({ classifier: "heuristic" });
    expect(g.marker.classifier).toBe("gbm");
    expect(g.marker.modelSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(existsSync(shared) ? statSync(shared).mtimeMs : null).toBe(before);
  });

  it("verifyBuild_refuses_a_build_that_is_not_the_requested_kind", { timeout: 120_000 }, () => {
    const root = mk();
    const model = mk();
    writeFileSync(join(model, "gbm.onnx"), "m");
    const g = buildLabExtension(root, "g", { ONEPASS_CLASSIFIER: "gbm", ONEPASS_MODEL_DIR: model });
    const h = buildLabExtension(root, "h", { ONEPASS_CLASSIFIER: "heuristic" });
    expect(() => verifyBuild(h.dir, "gbm", model)).toThrow(/CSP|model/);
    expect(() => verifyBuild(g.dir, "heuristic")).toThrow(/heuristic/);
    // the model file was swapped after the build
    writeFileSync(join(g.dir, "model", "gbm.onnx"), "tampered");
    expect(() => verifyBuild(g.dir, "gbm", model)).toThrow(/sha256|model/);
  });
});
