// Report of the real-site bench: rows on disk, Markdown grouped by rule then site.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { countByRule, renderReport, ResultsWriter, type RunMeta, shotName } from "../../../lab/real/report.ts";

const meta: RunMeta = {
  startedAt: "2026-11-21T10:00:00Z", finishedAt: "2026-11-21T10:05:00Z", kinds: ["live"], sites: 2, managers: [], notes: ["replica skipped"],
  vault: { items: 3, sites: 2, twoAccounts: 1, duplicates: 0 },
};

describe("report", () => {
  it("writes one JSON line per row", () => {
    const out = mkdtempSync(join(tmpdir(), "real-report-"));
    const w = new ResultsWriter(out);
    w.add({ host: "a.example", kind: "live", step: "home", rule: "R1", verdict: "pass", detail: "no card" });
    w.add({ host: "a.example", kind: "live", step: "home", rule: "R2", verdict: "violation", detail: "x", shot: "shots/a.png" });
    const lines = readFileSync(join(out, "results.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toHaveLength(2);
    expect(Object.keys(lines[1]!)).toEqual(["host", "kind", "step", "rule", "verdict", "detail", "shot"]);
  });

  it("groups violations by rule then by site, with the shot", () => {
    const rows = [
      { host: "b.example", kind: "live" as const, step: "signin-page", rule: "R1" as const, verdict: "violation" as const, detail: "card on a signed-in page (avatar)", shot: "shots/b.png" },
      { host: "a.example", kind: "live" as const, step: "home", rule: "R1" as const, verdict: "violation" as const, detail: "signin card on a page with no sign-in form" },
      { host: "a.example", kind: "live" as const, step: "home", rule: "R3" as const, verdict: "pass" as const, detail: "ok" },
      { host: "c.example", kind: "live" as const, step: "journey", rule: "-" as const, verdict: "timeout" as const, detail: "time box" },
    ];
    const md = renderReport(rows, meta);
    expect(md).toContain("| R1 card only where needed | 0 | 2 | 0 | 0 | 0 |");
    expect(md.indexOf("### a.example (live)")).toBeLessThan(md.indexOf("### b.example (live)"));
    expect(md).toContain("![b.example signin-page](shots/b.png)");
    expect(md).toContain("## R3 no redundancy\n\nNo violation.");
    expect(md).toContain("| c.example | live | journey | timeout | time box |");
    expect(md).toContain("- Note: replica skipped");
    expect(md).not.toContain(String.fromCharCode(0x2014));
    expect(countByRule(rows).R1).toEqual({ violation: 2 });
  });

  it("names shots by host, kind, step and rule only", () => {
    expect(shotName("www.example.com", "profile", 3, "R2")).toBe("www.example.com-profile-03-R2.png");
  });
});
