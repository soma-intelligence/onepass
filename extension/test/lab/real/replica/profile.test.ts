// Profile tool helpers: suggested sites and the cookie host list (names only).
import { describe, expect, it } from "vitest";
import { cookieHosts, sitesFile, startPage, suggestSites } from "../../../../lab/real/replica/profile.ts";
import type { ReplicaMeta } from "../../../../lab/real/replica/common.ts";

const meta = (host: string, signIn: boolean): ReplicaMeta => ({ host, rank: 1, status: "ok", capturedAt: "", signInForm: signIn, loginUrl: signIn ? `https://${host}/login` : undefined, files: [], tried: [], inlinedCss: 0 });

describe("profile tool", () => {
  it("suggests captured sign-in sites first, then plausible Tranco hosts", () => {
    const s = suggestSites([meta("a.com", true), meta("b.com", false)], ["gstatic.com", "a.com", "b.com", "c.com", "akamai.net", "d.com"], 3);
    expect(s.map((x) => x.host)).toEqual(["a.com", "c.com", "d.com"]);
    expect(s[0]).toEqual({ host: "a.com", url: "https://a.com/login", captured: true });
  });

  it("keeps host names only, never values", () => {
    const hosts = cookieHosts([{ domain: ".google.com", value: "secret" } as { domain: string }, { domain: "accounts.google.com" }, { domain: ".google.com" }]);
    expect(hosts).toEqual(["accounts.google.com", "google.com"]);
    const file = sitesFile(hosts, new Date(0));
    expect(file).not.toContain("secret");
    expect(JSON.parse(file).sites).toEqual(["google.com"]);
  });

  it("escapes the start page", () => {
    expect(startPage([{ host: "<x>", url: "https://x/", captured: false }])).toContain("&#60;x&#62;");
  });
});
