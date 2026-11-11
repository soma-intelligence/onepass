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
      page: true,
    });
  });
  it("flags http", () => {
    expect(parseOrigin("http://atlas-cloud.test")?.https).toBe(false);
  });
  it("http is a page to list, plan or fill on the three loopback hosts only (the bridge's parse_page)", () => {
    for (const [url, origin] of [
      ["http://localhost:3000/login?x", "http://localhost:3000"],
      ["http://LOCALHOST./", "http://localhost"],
      ["http://127.0.0.1:8080", "http://127.0.0.1:8080"],
      ["http://127.1", "http://127.0.0.1"],
      ["http://[::1]:5173/app", "http://[::1]:5173"],
      ["http://[0:0:0:0:0:0:0:1]", "http://[::1]"],
    ] as const) {
      expect(parseOrigin(url)).toMatchObject({ origin, https: false, page: true });
    }
    for (const url of [
      "http://atlas-cloud.test",
      "http://app.localhost:3000",
      "http://localhost.evil.test",
      "http://nas.local",
      "http://127.0.0.2",
      "http://192.168.1.10",
      "http://10.0.0.1",
      "http://[::2]",
      "http://0.0.0.0",
    ]) {
      expect(parseOrigin(url)).toMatchObject({ https: false, page: false });
    }
    expect(parseOrigin("ws://localhost:3000")).toBeNull();
    expect(parseOrigin("https://localhost:3000")).toMatchObject({ https: true, page: true });
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
