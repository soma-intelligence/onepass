// @vitest-environment node
// Lab relying party checks: TOTP (RFC 6238 appendix B, SHA-1 vectors, one
// period of tolerance) and the comparison of posted card / identity fields
// with the fictional values of the vault fixture; signup passwords must look
// generated.
import { describe, expect, it } from "vitest";
import { totp } from "../../e2e/server.ts";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import type { Site } from "../../lab/gen/model.ts";
import { expectedValues, looksGenerated, totpOk, wrongFields } from "../../lab/server/rp.ts";

// base32("12345678901234567890"), the SHA-1 secret of RFC 6238 appendix B.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const world = generate("rp-test", { sites: 10, patterns: patternsJson as unknown as Patterns });
const flow = (f: Site["flow"]) => world.sites.find((s) => s.flow === f)!;

describe("totpOk", () => {
  it("rfc6238_sha1_vectors", () => {
    expect(totpOk(RFC_SECRET, "287082", 59_000)).toBe(true);
    expect(totpOk(RFC_SECRET, "081804", 1_111_111_109_000)).toBe(true);
    expect(totpOk(RFC_SECRET, "081805", 1_111_111_109_000)).toBe(false);
    expect(totpOk(RFC_SECRET, " 287 082 ", 59_000)).toBe(true);
  });
  it("accepts_previous_period", () => {
    const now = 1_700_000_015_000;
    const previous = totp(RFC_SECRET, now - 30_000);
    expect(previous).not.toBe(totp(RFC_SECRET, now));
    expect(totpOk(RFC_SECRET, previous, now)).toBe(true);
    expect(totpOk(RFC_SECRET, totp(RFC_SECRET, now + 30_000), now)).toBe(true);
  });
  it("rejects_two_periods_ago", () => {
    const now = 1_700_000_015_000;
    const old = totp(RFC_SECRET, now - 60_000);
    expect([-30_000, 0, 30_000].map((d) => totp(RFC_SECRET, now + d))).not.toContain(old);
    expect(totpOk(RFC_SECRET, old, now)).toBe(false);
  });
});

describe("wrongFields", () => {
  it("card_values_normalized", () => {
    const site = flow("checkout_card");
    const exp = expectedValues(world, site);
    const body: Record<string, string> = {};
    for (const f of site.fields) {
      if (f.role === "cc_number") body[f.name] = exp.cc_number!.replace(/\s/g, "");
      else if (f.role === "cc_exp") body[f.name] = exp.cc_exp!.replace(/^(\d\d)\/\d\d(\d\d)$/, "$1 / $2");
      else if (f.role === "cc_exp_month") body[f.name] = exp.cc_exp!.slice(0, 2);
      else if (f.role === "cc_exp_year") body[f.name] = exp.cc_exp!.slice(3);
      else body[f.name] = ` ${exp[f.role]} `;
    }
    expect(wrongFields(world, site, body)).toEqual([]);
    const csc = site.fields.find((f) => f.role === "cc_csc")!;
    expect(wrongFields(world, site, { ...body, [csc.name]: "000" })).toEqual([csc.name]);
  });
  it("identity_values_and_missing_field", () => {
    const site = flow("identity");
    const exp = expectedValues(world, site);
    const body: Record<string, string> = {};
    for (const f of site.fields) body[f.name] = f.role === "tel" ? exp.tel!.replace(/\s/g, "") : exp[f.role]!;
    expect(wrongFields(world, site, body)).toEqual([]);
    const email = site.fields.find((f) => f.role === "email")!;
    const { [email.name]: _drop, ...rest } = body;
    expect(wrongFields(world, site, rest)).toEqual([email.name]);
  });
});

describe("looksGenerated", () => {
  it("length_and_classes", () => {
    expect(looksGenerated("Kp4-vX9m!tQz")).toBe(true);
    expect(looksGenerated("abcdefgh1234")).toBe(false); // two classes
    expect(looksGenerated("Ab1-xyz")).toBe(false); // too short
    expect(looksGenerated("ABCDEFGH123!")).toBe(true); // upper, digit, symbol
    expect(looksGenerated("")).toBe(false);
  });
});
