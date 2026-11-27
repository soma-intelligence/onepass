// Capture policy: GET only, robots on navigations, no heavy resources,
// sign-in candidates, resumable host list, site pacing key.
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loginCandidates, pendingReplicaHosts, requestVerdict, siteKey } from "../../../../lab/real/replica/capture.ts";
import { RealRobots } from "../../../../lab/real/replica/common.ts";

const LEX = { buttons: { signin: { en: ["Sign in", "Log in"] }, signup: { en: ["Sign up"] } } };

describe("replica capture", () => {
  it("lets only GET leave the browser", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      expect(requestVerdict({ method, resourceType: "fetch", isMainNavigation: false, robotsAllowed: true })).toBe("abort-method");
    }
    expect(requestVerdict({ method: "GET", resourceType: "document", isMainNavigation: true, robotsAllowed: false })).toBe("abort-robots");
    expect(requestVerdict({ method: "GET", resourceType: "image", isMainNavigation: false, robotsAllowed: true })).toBe("abort-skip");
    expect(requestVerdict({ method: "GET", resourceType: "stylesheet", isMainNavigation: false, robotsAllowed: true })).toBe("continue");
    expect(requestVerdict({ method: "get", resourceType: "document", isMainNavigation: true, robotsAllowed: true })).toBe("continue");
  });

  it("picks sign-in candidates, never sign-up or checkout", () => {
    const html = `<a href="/account/login?next=/x">Sign in</a><a href="/signup">Sign up</a><a href="/cart">Cart</a>`;
    const c = loginCandidates("https://www.shop.com/", html, LEX);
    expect(c[0]).toBe("https://www.shop.com/account/login");
    expect(c.some((u) => /signup|cart|register|checkout/.test(u))).toBe(false);
    expect(c.length).toBeLessThanOrEqual(3);
  });

  it("paces by registrable domain", () => {
    expect(siteKey("accounts.google.com")).toBe("google.com");
    expect(siteKey("www.bbc.co.uk")).toBe("bbc.co.uk");
  });

  it("resumes: skips finished hosts, retries errors on demand", () => {
    const dir = mkdtempSync(join(tmpdir(), "replica-"));
    for (const [h, status] of [["a.com", "ok"], ["b.com", "error: timeout"]] as const) {
      mkdirSync(join(dir, h));
      writeFileSync(join(dir, h, "meta.json"), JSON.stringify({ host: h, rank: 1, status, files: [], tried: [], signInForm: false, inlinedCss: 0, capturedAt: "" }));
    }
    const hosts = ["a.com", "b.com", "c.com", "d.com"];
    expect(pendingReplicaHosts(hosts, 3, dir, false).map((x) => x.host)).toEqual(["c.com"]);
    expect(pendingReplicaHosts(hosts, 3, dir, true).map((x) => x.host)).toEqual(["b.com", "c.com"]);
    expect(pendingReplicaHosts(hosts, 4, dir, false).map((x) => x.rank)).toEqual([3, 4]);
  });

  it("reads robots.txt under the OnePassLabReal agent", async () => {
    const calls: string[] = [];
    const fake = (async (url: string) => {
      calls.push(url);
      return new Response("User-agent: *\nAllow: /\n\nUser-agent: OnePassLabReal\nDisallow: /login\n", { status: 200, headers: { "content-type": "text/plain" } });
    }) as unknown as typeof fetch;
    const r = new RealRobots("ua", async () => {}, fake);
    expect(await r.allowed(new URL("https://x.com/"))).toBe(true);
    expect(await r.allowed(new URL("https://x.com/login"))).toBe(false);
    expect(calls).toEqual(["https://x.com/robots.txt"]);
  });

  it("denies when robots.txt is unreachable", async () => {
    const r = new RealRobots("ua", async () => {}, (async () => { throw new Error("net"); }) as unknown as typeof fetch);
    expect(await r.allowed(new URL("https://y.com/"))).toBe(false);
  });
});

describe("sign-in page test", () => {
  it("needs a password field or a sign-in identifier field", async () => {
    const { signInKind } = await import("../../../../lab/real/replica/capture.ts");
    expect(signInKind({ password: true, identifier: false }, "https://x.com/anything")).toBe("password");
    expect(signInKind({ password: false, identifier: true }, "https://accounts.google.com/v3/signin/identifier")).toBe("identifier");
    expect(signInKind({ password: false, identifier: true }, "https://www.microsoft.com/en-us/store/b/payment-financing-options")).toBeUndefined();
    expect(signInKind({ password: false, identifier: true, usernameAutocomplete: true }, "https://x.com/start")).toBe("identifier");
    expect(signInKind({ password: false, identifier: false }, "https://x.com/login")).toBeUndefined();
  });
});

describe("blocked pages", () => {
  it("spots bot walls and empty shells", async () => {
    const { looksBlocked } = await import("../../../../lab/real/replica/capture.ts");
    const none = { password: false, identifier: false };
    expect(looksBlocked({ ...none, textLength: 0, links: 0 }, '<div id="challenge-container"></div>')).toBe(true);
    expect(looksBlocked({ ...none, textLength: 40, links: 1 }, "<p>Loading</p>")).toBe(true);
    expect(looksBlocked({ ...none, textLength: 4000, links: 120 }, "<p>news</p>")).toBe(false);
    expect(looksBlocked({ password: true, identifier: true, textLength: 30, links: 0 }, "<form></form>")).toBe(false);
  });
});
