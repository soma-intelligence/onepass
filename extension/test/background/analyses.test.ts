// Per frame analyses kept for the chain (spec C1): bounded, other origins
// left out, changes of a tab serialized.
import { describe, expect, it } from "vitest";
import { PageAnalyses } from "../../src/background/analyses";
import type { StorageArea } from "../../src/background/ext";
import type { CsContext } from "../../src/background/frames";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { FakeArea } from "./fake-ext";

const SITE = "https://atlas-cloud.test";
const form: FormInfo = { ref: "f1", kind: "login", fields: [{ ref: "u1", role: "email" }] };
const page = (url: string, forms: FormInfo[] = [form]): PageAnalysis => ({
  url,
  forms,
  captcha: false,
  push: false,
  providerButtons: [],
  accountChooser: [],
});
const from = (frameId: number, origin: string): CsContext => ({ tabId: 7, frameId, origin, documentId: `d${frameId}` });
const ids = async (a: PageAnalyses) => (await a.children(7)).map((x) => x.frameId);

describe("PageAnalyses child frames", () => {
  it("other-origin frames cannot crowd a same-origin frame out of the cap", async () => {
    const a = new PageAnalyses(new FakeArea());
    await a.record(page(`${SITE}/`, []), from(0, SITE));
    for (let i = 1; i <= 20; i++) await a.record(page(`https://ads${i}.test/`), from(i, `https://ads${i}.test`));
    await a.record(page(`${SITE}/frame`), from(30, SITE));
    expect(await ids(a)).toEqual([30]);
  });

  it("frames of another origin recorded before the top frame's analysis are dropped with it", async () => {
    const a = new PageAnalyses(new FakeArea());
    await a.record(page("https://ads.test/"), from(2, "https://ads.test"));
    await a.record(page(`${SITE}/frame`), from(3, SITE));
    await a.record(page(`${SITE}/`, []), from(0, SITE));
    expect(await ids(a)).toEqual([3]);
  });

  it("two concurrent analyses after a worker restart both stay stored", async () => {
    const area = new FakeArea();
    const first = new PageAnalyses(area);
    await first.record(page(`${SITE}/`, []), from(0, SITE));
    await first.record(page(`${SITE}/a`), from(3, SITE));
    // A restarted worker whose first storage write lands late.
    let delayed = false;
    const slow: StorageArea = {
      get: (k) => area.get(k),
      remove: (k) => area.remove(k),
      set: async (items) => {
        if (!delayed && Object.keys(items).some((k) => k.startsWith("frames:"))) {
          delayed = true;
          await new Promise((r) => setTimeout(r, 20));
        }
        await area.set(items);
      },
    };
    const restarted = new PageAnalyses(slow);
    await Promise.all([restarted.record(page(`${SITE}/b`), from(4, SITE)), restarted.record(page(`${SITE}/c`), from(5, SITE))]);
    expect(await ids(restarted)).toEqual([3, 4, 5]);
    // What another restart reads back from storage.
    expect(await ids(new PageAnalyses(area))).toEqual([3, 4, 5]);
  });
});
