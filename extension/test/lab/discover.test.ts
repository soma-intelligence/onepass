// Form page discovery: lexicon links of the home page, then sitemap, then common paths.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { COMMON_PATHS, discoverFormPages } from "../../lab/corpus/discover.ts";
import lexicon from "../../lab/corpus/seed-lexicon.json";

const load = (name: string) => readFileSync(resolve(__dirname, "../fixtures/lab", name), "utf8");

describe("discoverFormPages", () => {
  it("lexicon links first, then sitemap, then common paths, max 6", () => {
    const urls = discoverFormPages({ url: "https://shop.example/", html: load("home-with-links.html") }, load("sitemap.xml"), lexicon);
    expect(urls[0]).toBe("https://shop.example/connexion");
    expect(urls).toHaveLength(6);
    expect(urls).toContain("https://shop.example/inscription");
    expect(new Set(urls).size).toBe(6);
    expect(urls.some((u) => /logout|deconnexion|other\.example|elsewhere/.test(u))).toBe(false);
  });
  it("off-site and logout links are dropped", () => {
    const urls = discoverFormPages({ url: "https://a.example/", html: '<a href="https://evil.test/login">Log in</a><a href="/logout">Log out</a>' }, undefined, lexicon);
    expect(urls).toEqual(COMMON_PATHS.map((p) => "https://a.example" + p));
  });
  it("non http schemes, fragments and duplicates are dropped", () => {
    const html = '<a href="mailto:a@b.c">Sign in</a><a href="#login">Sign in</a><a href="/login">Sign in</a><a href="/login#x">Log in</a>';
    const urls = discoverFormPages({ url: "https://a.example/", html }, undefined, lexicon);
    expect(urls[0]).toBe("https://a.example/login");
    expect(urls.filter((u) => u === "https://a.example/login")).toHaveLength(1);
  });
  it("same registrable domain subdomains are kept", () => {
    const html = '<a href="https://accounts.a.example/start">Sign in</a>';
    const urls = discoverFormPages({ url: "https://www.a.example/", html }, undefined, lexicon);
    expect(urls[0]).toBe("https://accounts.a.example/start");
  });
  it("malformed percent sequences do not throw", () => {
    const sitemap = "<urlset><url><loc>https://a.example/%zz/login</loc></url></urlset>";
    let urls: string[] = [];
    expect(() => { urls = discoverFormPages({ url: "https://a.example/", html: '<a href="/%zz">Sign in</a>' }, sitemap, lexicon); }).not.toThrow();
    expect(urls.length).toBeLessThanOrEqual(6);
    expect(urls).toContain("https://a.example/%zz");
  });
});
