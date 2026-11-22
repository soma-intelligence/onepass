// Fictional vault of the real-site bench.
import { describe, expect, it } from "vitest";
import { bucket, buildVault, indexVault, TWO_ACCOUNTS_PERCENT, vaultSummary } from "../../../lab/real/vault.ts";

const hosts = Array.from({ length: 1000 }, (_, i) => `site${i}.example.com`);

describe("buildVault", () => {
  const v = buildVault(hosts);

  it("gives every site a fictional login lab-<n>@example.test", () => {
    const first = v.items.filter((i) => !i.title.includes(" ("));
    expect(first).toHaveLength(1000);
    expect(first[0]).toMatchObject({ title: "site0.example.com", fields: { username: "lab-1@example.test" }, urls: [{ url: "https://site0.example.com", rule: "domain" }] });
    expect(v.items.every((i) => /^lab-\d+(-b)?@example\.test$/.test(i.fields.username))).toBe(true);
  });

  it("draws random passwords, never twice the same except for duplicates", () => {
    const pw = v.items.filter((i) => !i.title.endsWith(" (copie)")).map((i) => i.fields.password);
    expect(new Set(pw).size).toBe(pw.length);
    expect(pw.every((p) => p.startsWith("Lab-") && p.length >= 20)).toBe(true);
  });

  it("puts two accounts on about 15 % of the sites and a few exact duplicates", () => {
    const s = vaultSummary(v);
    expect(s.sites).toBe(1000);
    expect(s.twoAccounts).toBeGreaterThan(100);
    expect(s.twoAccounts).toBeLessThan(200);
    expect(s.duplicates).toBeGreaterThan(10);
    const dup = v.items.find((i) => i.title.endsWith(" (copie)"))!;
    const orig = v.items.find((i) => i.title === dup.title.replace(" (copie)", ""))!;
    expect(dup.fields).toEqual(orig.fields);
  });

  it("chooses the two-account sites by host, the same on every run", () => {
    const again = buildVault(hosts);
    const pro = (x: typeof v) => x.items.filter((i) => i.title.endsWith(" (pro)")).map((i) => i.title);
    expect(pro(again)).toEqual(pro(v));
    expect(bucket("site1.example.com", "two-accounts") < TWO_ACCOUNTS_PERCENT).toBe(pro(v).includes("site1.example.com (pro)"));
  });

  it("indexes logins by registrable domain", () => {
    const idx = indexVault(buildVault(["google.com", "bbc.co.uk"]));
    expect(idx.loginsFor("accounts.google.com")).toBeGreaterThanOrEqual(1);
    expect(idx.loginsFor("www.bbc.co.uk")).toBeGreaterThanOrEqual(1);
    expect(idx.loginsFor("example.org")).toBe(0);
  });
});
