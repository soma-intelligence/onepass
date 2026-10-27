import { describe, expect, it } from "vitest";
import vectors from "./vectors/psl.json";
import { isSecure, parseOrigin, sameSite } from "../src/shared/domain";

describe("shared PSL vectors", () => {
  for (const c of vectors.cases) {
    it(`${c.a} vs ${c.b}`, () => {
      expect(parseOrigin(c.a)?.site).toBe(c.site_a);
      expect(sameSite(c.a, c.b)).toBe(c.same_site);
    });
  }
});

describe("parseOrigin", () => {
  it("extracts origin, host, site and https", () => {
    expect(parseOrigin("https://Login.Atlas-Cloud.test:8443/a?b#c")).toEqual({
      origin: "https://login.atlas-cloud.test:8443",
      host: "login.atlas-cloud.test",
      site: "atlas-cloud.test",
      https: true,
    });
  });
  it("flags http", () => {
    expect(parseOrigin("http://atlas-cloud.test")?.https).toBe(false);
  });
  it("rejects garbage and hostless schemes", () => {
    expect(parseOrigin("not a url")).toBeNull();
    expect(parseOrigin("about:blank")).toBeNull();
    expect(parseOrigin("data:text/html,hi")).toBeNull();
    expect(parseOrigin("")).toBeNull();
  });
});

describe("sameSite / isSecure", () => {
  it("is false when either side is unparsable", () => {
    expect(sameSite("nope", "https://atlas-cloud.test")).toBe(false);
    expect(sameSite("nope", "nope")).toBe(false);
  });
  it("isSecure only for https", () => {
    expect(isSecure("https://atlas-cloud.test")).toBe(true);
    expect(isSecure("http://atlas-cloud.test")).toBe(false);
    expect(isSecure("javascript:alert(1)")).toBe(false);
    expect(isSecure("nope")).toBe(false);
  });
});
