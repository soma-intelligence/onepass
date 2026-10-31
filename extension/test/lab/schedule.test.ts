// Crawl scheduling: done markers, atomic writes, per-host pacing and site budget.
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HostPacer, SiteBudget, clearHost, pendingHosts, routeVerdict, writeAtomic, writeAtomicWith } from "../../lab/corpus/schedule.ts";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "sched-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const done = (host: string) => JSON.stringify({ host, pages: 0, status: "skipped: robots", finishedAt: "2026-10-27T00:00:00.000Z" });

describe("pendingHosts", () => {
  it("a host with a parsing done marker is skipped", () => {
    writeFileSync(join(dir, "a.example.done.json"), done("a.example"));
    expect(pendingHosts(["a.example", "b.example"], dir)).toEqual(["b.example"]);
  });
  it("a truncated done marker is not counted as done", () => {
    writeFileSync(join(dir, "a.example.done.json"), '{"host":"a.ex');
    expect(pendingHosts(["a.example", "b.example"], dir)).toEqual(["a.example", "b.example"]);
  });
  it("page files without a marker do not make a host done", () => {
    writeFileSync(join(dir, "a.example.0.json"), "{}");
    expect(pendingHosts(["a.example"], dir)).toEqual(["a.example"]);
  });
  it("a missing output directory means everything is pending", () => {
    expect(pendingHosts(["a.example"], join(dir, "nope"))).toEqual(["a.example"]);
  });
});

describe("writeAtomic", () => {
  it("writes the file and leaves no tmp file", () => {
    writeAtomic(join(dir, "x.json"), "{}");
    expect(readFileSync(join(dir, "x.json"), "utf8")).toBe("{}");
    expect(readdirSync(dir)).toEqual(["x.json"]);
  });
  it("leaves no target when the rename never happens", () => {
    expect(() => writeAtomicWith(join(dir, "x.json"), "{}", () => { throw new Error("boom"); })).toThrow("boom");
    expect(existsSync(join(dir, "x.json"))).toBe(false);
  });
});

describe("HostPacer", () => {
  const clock = () => {
    const c = { t: 1000, slept: [] as number[] };
    return { c, now: () => c.t, sleep: async (ms: number) => { c.slept.push(ms); c.t += ms; } };
  };
  it("keeps 5 s between pages of one host", async () => {
    const { c, now, sleep } = clock();
    const p = new HostPacer(5000, now, sleep);
    await p.wait("a.example");
    expect(c.slept).toEqual([]);
    c.t += 1000;
    await p.wait("a.example");
    expect(c.slept).toEqual([4000]);
    expect(c.t).toBe(1000 + 1000 + 4000);
  });
  it("does not delay a different host", async () => {
    const { c, now, sleep } = clock();
    const p = new HostPacer(5000, now, sleep);
    await p.wait("a.example");
    await p.wait("b.example");
    expect(c.slept).toEqual([]);
  });
  it("never sleeps when the gap has already passed", async () => {
    const { c, now, sleep } = clock();
    const p = new HostPacer(5000, now, sleep);
    await p.wait("a.example");
    c.t += 6000;
    await p.wait("a.example");
    expect(c.slept).toEqual([]);
  });
  it("concurrent waits on one host are serialised 5 s apart", async () => {
    const { c, now, sleep } = clock();
    const p = new HostPacer(5000, now, sleep);
    await Promise.all([p.wait("a.example"), p.wait("a.example"), p.wait("a.example")]);
    expect(c.t - 1000).toBe(10000);
  });
});

describe("SiteBudget", () => {
  it("abandons after 2 errors", () => {
    const b = new SiteBudget();
    b.recordError();
    expect(b.abandoned).toBe(false);
    b.recordError();
    expect(b.abandoned).toBe(true);
    expect(b.allowPage()).toBe(false);
  });
  it("caps at 6 pages", () => {
    const b = new SiteBudget();
    for (let i = 0; i < 6; i++) expect(b.allowPage()).toBe(true);
    expect(b.allowPage()).toBe(false);
  });
});

describe("routeVerdict", () => {
  it("aborts every method but GET", () => {
    for (const method of ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "post"]) {
      expect(routeVerdict({ method, isMainNavigation: false }, true)).toBe("abort-method");
    }
  });
  it("lets GET through, and stops main navigations robots disallows", () => {
    expect(routeVerdict({ method: "GET", isMainNavigation: false }, false)).toBe("continue");
    expect(routeVerdict({ method: "GET", isMainNavigation: true }, true)).toBe("continue");
    expect(routeVerdict({ method: "GET", isMainNavigation: true }, false)).toBe("abort-robots");
  });
});

describe("clearHost", () => {
  it("removes page files, marker and tmp of one host only", () => {
    for (const f of ["a.example.0.json", "a.example.3.json", "a.example.done.json", "a.example.1.json.tmp", "b.a.example.0.json", "ab.example.0.json", "a.example.txt"]) writeFileSync(join(dir, f), "{}");
    clearHost("a.example", dir);
    expect(readdirSync(dir).sort()).toEqual(["a.example.txt", "ab.example.0.json", "b.a.example.0.json"]);
  });
});
