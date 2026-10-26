// @vitest-environment node
// Report of the autofill lab (spec 8): rates exclude expected failures and
// bench errors, traits count each trait, the Markdown is French, free of the
// em dash and of any vault value, and leaks get their own section.
import { describe, expect, it } from "vitest";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";
import { renderReport, summarize } from "../../lab/report.ts";
import type { Result, Verdict } from "../../lab/run/oracle.ts";

function res(n: number, verdict: Verdict, over: Partial<Result> = {}): Result {
  return {
    worldSeed: "w", site: n, siteSeed: `s${n}`, flow: "login_single", traits: [], lang: "en", labelLang: "en",
    driver: "one_click", expect: "pass", verdict, retried: false, durationMs: 10,
    repro: `npm run lab:repro -- --seed w --site ${n}`, ...over,
  };
}

const meta = { date: "2026-10-26", commit: "abc1234", durationMin: 7 };
const world = { seed: "w", sites: 10 };

describe("lab report", () => {
  it("rate_excludes_xfail_and_lab_error", () => {
    const s = summarize([
      res(0, "pass"), res(1, "pass"), res(2, "fail", { cause: "timeout" }), res(3, "flaky"),
      res(4, "xfail"), res(5, "xpass"), res(6, "lab_error"),
    ]);
    expect(s.overall.total).toBe(7);
    expect(s.overall.rate).toBeCloseTo(3 / 4);
    expect(s.overall.xfail).toBe(1);
    expect(s.overall.xpass).toBe(1);
    expect(s.overall.labError).toBe(1);
    expect(summarize([res(0, "xfail")]).overall.rate).toBe(1);
  });

  it("groups_by_trait_count_each_trait", () => {
    const s = summarize([
      res(0, "pass", { traits: ["honeypot", "spa_rerender"] }),
      res(1, "fail", { traits: ["honeypot"], cause: "timeout" }),
      res(2, "pass"),
    ]);
    expect(s.byTrait.honeypot!.total).toBe(2);
    expect(s.byTrait.spa_rerender!.total).toBe(1);
    expect(s.byTrait["(aucun)"]!.total).toBe(1);
    expect(s.byFlow.login_single!.total).toBe(3);
    expect(s.byLang.en!.total).toBe(3);
    expect(s.byDriver.one_click!.total).toBe(3);
  });

  it("markdown_has_no_em_dash", () => {
    const s = summarize([res(0, "pass"), res(1, "fail", { cause: "timeout" }), res(2, "xfail", { cause: "no_overlay" }), res(3, "xpass"), res(4, "flaky")]);
    const md = renderReport(world, s, meta);
    expect(md).not.toContain("\u2014");
    expect(md).toContain("## Ce que l'extension ne fait pas encore");
    expect(md).toContain("npm run lab:repro -- --seed w --site 1");
    expect(md).toContain("## Instables");
  });

  it("markdown_has_no_secret", () => {
    const w = generate("report-secret-seed", { sites: 12, patterns: loadPatterns() });
    const results = w.scenarios.map((sc) => {
      const site = w.sites[sc.site]!;
      return res(site.index, "fail", { flow: site.flow, traits: site.traits, lang: site.lang, driver: sc.driver, cause: "timeout" });
    });
    const md = renderReport({ seed: w.seed, sites: w.sites.length }, summarize(results), meta);
    const secrets: string[] = [];
    for (const site of w.sites) {
      if (site.account) secrets.push(site.account.password, site.account.totpSecret ?? "");
    }
    for (const accounts of Object.values(w.idp)) for (const a of accounts) secrets.push(a.password);
    secrets.push(...JSON.stringify(w.fixture).match(/"(?:number|password|cvv|csc|secret|totp)[^"]*":\s*"([^"]{4,})"/g)?.map((m) => m.split('"')[3]!) ?? []);
    const real = secrets.filter((x) => x.length >= 4);
    expect(real.length).toBeGreaterThan(0);
    for (const x of real) expect(md).not.toContain(x);
  });

  it("xfail_grouped_by_reason_with_cause_fallback", () => {
    const s = summarize([
      res(0, "xfail", { reason: "R-16 passkeys", cause: "no_overlay" }),
      res(1, "xfail", { reason: "R-16 passkeys", cause: "timeout" }),
      res(2, "xfail", { cause: "chain_ended:done" }),
      res(3, "fail", { cause: "timeout" }),
    ]);
    const md = renderReport(world, s, meta);
    expect(md).toContain("- R-16 passkeys : 2 scénario(s)");
    expect(md).toContain("- chain_ended:done : 1 scénario(s)");
    expect(md).toContain("Causes d'échec récurrentes");
  });

  it("missing_meta_prints_unknown", () => {
    const md = renderReport(world, summarize([res(0, "pass")]), {});
    expect(md).toContain("Date : inconnue");
    expect(md).toContain("Commit : inconnu");
    expect(md).toContain("Durée : inconnue");
  });

  it("leaks_section", () => {
    const clean = renderReport(world, summarize([res(0, "pass")]), meta);
    expect(clean).toMatch(/## Fuites\n\nAucune\./);
    const leaky = summarize([res(0, "pass"), res(1, "leak", { cause: "leak:password:pw@evil.test" })]);
    expect(leaky.leaks).toHaveLength(1);
    const md = renderReport(world, leaky, meta);
    expect(md).toMatch(/## Fuites\n\n- site 1/);
    expect(md).toContain("leak:password:pw@evil.test");
    expect(md).not.toMatch(/## Fuites\n\nAucune\./);
  });
});
