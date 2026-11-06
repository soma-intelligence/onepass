// @vitest-environment node
// The account a lab driver looks for: an sso site's "<brand> via <Provider>"
// is the overlay row of the item "<brand>" for that provider.
import { describe, expect, it } from "vitest";
import { accountRow, overlayRowSelector } from "../../lab/run/account.ts";
import { generate, loadPatterns } from "../../lab/gen/generate.ts";

describe("lab account rows", () => {
  it("an sso title names the item and its provider", () => {
    expect(accountRow("Plush Orchard via Microsoft")).toEqual({ title: "Plush Orchard", provider: "microsoft" });
    expect(accountRow("Quiet Fjord via Google")).toEqual({ title: "Quiet Fjord", provider: "google" });
    expect(accountRow("Amber Falcon via Apple")).toEqual({ title: "Amber Falcon", provider: "apple" });
  });

  it("any other title is the row's own title", () => {
    expect(accountRow("Plush Orchard")).toEqual({ title: "Plush Orchard" });
    expect(accountRow("Carte Plush Orchard")).toEqual({ title: "Carte Plush Orchard" });
    expect(accountRow("Via Google Pebble")).toEqual({ title: "Via Google Pebble" });
  });

  it("sso rows are picked by provider, never a provider's other account", () => {
    expect(overlayRowSelector({ title: "Plush Orchard", provider: "microsoft" })).toBe('.ov-pill[data-provider="microsoft"]');
    expect(overlayRowSelector({ title: "Plush Orchard" })).toBe(".ov-pill");
  });

  it("every sso site of a world maps to its vault item's title and provider", () => {
    const w = generate("account-rows", { sites: 120, patterns: loadPatterns() });
    const items = w.fixture.items as { type: string; title: string; urls?: { url: string }[]; login_methods?: { provider: string }[] }[];
    const sso = w.sites.filter((s) => s.flow === "sso");
    expect(sso.length).toBeGreaterThan(5);
    for (const s of sso) {
      const item = items.find((i) => i.type === "login" && i.urls?.[0]?.url === `https://${s.host}`)!;
      expect(accountRow(s.itemTitle!)).toEqual({ title: item.title, provider: item.login_methods![0]!.provider });
    }
  });
});
