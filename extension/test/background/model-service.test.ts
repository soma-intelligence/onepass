// @vitest-environment node
// classify handler (Task 15): cross-site child frames get no label, the handshake reports the
// model kind, and a worker without a usable model answers null.
import { describe, expect, it, vi } from "vitest";
import { createBackground } from "../../src/background/app";
import { createClassifyHandler } from "../../src/background/model-service";
import type { ModelSession } from "../../src/background/model";
import type { FieldFeatures } from "../../src/content/detect/features";
import { FakeExt } from "./fake-ext";

const session: ModelSession = { kind: "gbm", predict: async (fs) => fs.map(() => ({ label: "email", score: 0.7 })) };
const f = { index: 0, tag: "input" } as FieldFeatures;
const cs = (frameId: number, origin = "https://atlas-cloud.test") => ({ tabId: 1, frameId, origin });
const frames = (top: string | null) => ({ details: vi.fn(async () => (top === null ? null : { url: top, frameId: 0, parentFrameId: -1 })) });

describe("classify handler", () => {
  it("top frame: handshake, then one label per field", async () => {
    const h = createClassifyHandler({ kind: "gbm", frames: frames(null), session: async () => session });
    expect(await h({ fields: [] }, cs(0))).toEqual({ kind: "gbm", crossSite: false });
    expect(await h({ fields: [f, f] }, cs(0))).toEqual({ kind: "gbm", crossSite: false, labels: [{ label: "email", score: 0.7 }, { label: "email", score: 0.7 }] });
  });

  it("a child frame of the same site is classified; of another site, or under an http or unknown top, it is cross-site", async () => {
    const predict = vi.fn(session.predict);
    const s = { ...session, predict };
    const same = createClassifyHandler({ kind: "gbm", frames: frames("https://www.atlas-cloud.test/app"), session: async () => s });
    expect(await same({ fields: [f] }, cs(3, "https://login.atlas-cloud.test"))).toMatchObject({ crossSite: false });
    for (const top of ["https://evil.test/frame", "http://atlas-cloud.test/", null]) {
      const h = createClassifyHandler({ kind: "gbm", frames: frames(top), session: async () => s });
      expect(await h({ fields: [f] }, cs(3)), String(top)).toEqual({ kind: "gbm", crossSite: true });
    }
    expect(predict).toHaveBeenCalledTimes(1);
  });

  it("no model, or a model of another kind: null", async () => {
    expect(await createClassifyHandler({ kind: "gbm", frames: frames(null), session: async () => null })({ fields: [f] }, cs(0))).toBeNull();
    expect(await createClassifyHandler({ kind: "encoder", frames: frames(null), session: async () => session })({ fields: [] }, cs(0))).toBeNull();
  });

  it("the default (heuristic) build registers no classify handler and has no model", () => {
    const bg = createBackground(new FakeExt() as never, { pairings: { load: async () => null, save: async () => {}, clear: async () => {} } as never });
    expect(bg.handlers.cs.classify).toBeUndefined();
    expect(bg.modelSession).toBeNull();
  });
});
