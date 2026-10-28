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

  it("I2: a burst of 50 concurrent requests from one tab runs one inference; the others keep heuristics", async () => {
    let inferences = 0;
    const slow: ModelSession = { kind: "gbm", predict: async (fs) => { inferences++; await new Promise((r) => setTimeout(r, 20)); return fs.map(() => ({ label: "email", score: 0.7 })); } };
    const h = createClassifyHandler({ kind: "gbm", frames: frames(null), session: async () => slow });
    const replies = await Promise.all(Array.from({ length: 50 }, () => h({ fields: [f] }, cs(0))));
    expect(inferences).toBe(1);
    expect(replies.filter((r) => r && "labels" in r)).toHaveLength(1);
    expect(replies.filter((r) => r && "refused" in r && r.refused === "busy")).toHaveLength(49);
  });

  it("I2: 50 sequential requests from one tab are capped by its rate; another tab keeps its own budget", async () => {
    let inferences = 0;
    const counted: ModelSession = { kind: "gbm", predict: async (fs) => (inferences++, fs.map(() => ({ label: "email" as const, score: 0.7 }))) };
    let t = 1_000_000;
    const h = createClassifyHandler({ kind: "gbm", frames: frames(null), session: async () => counted, now: () => t });
    for (let i = 0; i < 50; i++) await h({ fields: [f] }, cs(0));
    expect(inferences).toBe(8);
    expect(await h({ fields: [f] }, cs(0))).toEqual({ kind: "gbm", crossSite: false, refused: "rate" });
    expect(await h({ fields: [f] }, { tabId: 2, frameId: 0, origin: "https://other.test" })).toMatchObject({ labels: [{ label: "email" }] });
    t += 1000; // two more per second
    for (let i = 0; i < 10; i++) await h({ fields: [f] }, cs(0));
    expect(inferences).toBe(8 + 1 + 2);
  });

  it("I2: over the field or token budget, nothing runs", async () => {
    const predict = vi.fn(session.predict);
    const enc: ModelSession = { kind: "encoder", predict, tokens: (fs) => fs.length * 128 };
    const h = createClassifyHandler({ kind: "encoder", frames: frames(null), session: async () => enc });
    expect(await h({ fields: Array(65).fill(f) }, cs(0))).toEqual({ kind: "encoder", crossSite: false, refused: "budget" });
    expect(await h({ fields: Array(17).fill(f) }, cs(0))).toEqual({ kind: "encoder", crossSite: false, refused: "budget" });
    expect(await h({ fields: Array(16).fill(f) }, cs(0))).toMatchObject({ labels: expect.any(Array) });
    expect(predict).toHaveBeenCalledTimes(1);
  });

  it("I2: while one tab bursts, another tab's fill is delayed by at most one inference", async () => {
    // Inference blocks the worker thread (WASM, no proxy): the fake spins for 25 ms.
    const spin = (ms: number) => { const end = performance.now() + ms; while (performance.now() < end) { /* busy */ } };
    const blocking: ModelSession = { kind: "gbm", predict: async (fs) => { spin(25); return fs.map(() => ({ label: "email", score: 0.7 })); } };
    const h = createClassifyHandler({ kind: "gbm", frames: frames(null), session: async () => blocking });
    const start = performance.now();
    const burst = Array.from({ length: 50 }, () => h({ fields: [f] }, cs(0)));
    // Tab 2's fill: any other handler work, queued behind the burst on the same thread.
    const fillDone = new Promise<number>((r) => setTimeout(() => r(performance.now() - start), 0));
    const [delay] = await Promise.all([fillDone, Promise.all(burst)]);
    // Unbounded, 50 inferences would hold the thread for about 1250 ms.
    expect(delay).toBeLessThan(150);
  });

  it("the default (heuristic) build registers no classify handler and has no model", () => {
    const bg = createBackground(new FakeExt() as never, { pairings: { load: async () => null, save: async () => {}, clear: async () => {} } as never });
    expect(bg.handlers.cs.classify).toBeUndefined();
    expect(bg.modelSession).toBeNull();
  });
});
