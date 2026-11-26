// @vitest-environment node
// Other password managers of the real-site bench: Bitwarden release picking
// and archive checks (no network here), the managerExtensions() contract, and
// the fake extensions (manifests, one shared script, DOM they plant, no fill
// or menu on untrusted events, no network API).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";
import { afterEach, describe, expect, it } from "vitest";
import {
  browserVersion,
  isOfficialAssetUrl,
  parseDigest,
  pickAsset,
  pickRelease,
  type Release,
  unsafeEntries,
} from "../../../../lab/real/managers/fetch-bitwarden.ts";
import { BITWARDEN_DIR, FAKE_MANAGERS, fakeExtensionDir, managerExtensions } from "../../../../lab/real/managers/index.ts";

const asset = (name: string, digest?: string | null) => ({
  name,
  size: 1,
  browser_download_url: `https://github.com/bitwarden/clients/releases/download/browser-v1.0.0/${name}`,
  digest,
});
const release = (tag: string, over: Partial<Release> = {}): Release => ({
  tag_name: tag,
  draft: false,
  prerelease: false,
  published_at: null,
  assets: [asset(`bit-dist-chrome-${tag.slice(9)}.zip`)],
  ...over,
});

describe("fetch-bitwarden helpers", () => {
  it("reads only browser-vX.Y.Z tags", () => {
    expect(browserVersion("browser-v2026.11.0")).toEqual([2026, 11, 0]);
    expect(browserVersion("desktop-v2026.11.0")).toBeNull();
    expect(browserVersion("browser-v2026.11.0-rc")).toBeNull();
  });

  it("picks the newest published browser release by version, not by list order", () => {
    const r = pickRelease([
      release("cli-v2027.1.0"),
      release("browser-v2026.9.10"),
      release("browser-v2026.12.0", { draft: true }),
      release("browser-v2026.11.1", { prerelease: true }),
      release("browser-v2026.11.0"),
      release("browser-v2026.10.2"),
    ]);
    expect(r.tag_name).toBe("browser-v2026.11.0");
  });

  it("throws without any browser release", () => {
    expect(() => pickRelease([release("web-v1.0.0")])).toThrow(/no published browser-v/);
  });

  it("prefers the store Chrome build, then the plain name, then OSS", () => {
    const names = ["oss-dist-chrome-1.zip", "dist-firefox-1.zip", "dist-chrome-1.zip", "bit-dist-chrome-1.zip"];
    expect(pickAsset(release("browser-v1.0.0", { assets: names.map((n) => asset(n)) })).name).toBe("bit-dist-chrome-1.zip");
    expect(pickAsset(release("browser-v1.0.0", { assets: names.slice(0, 3).map((n) => asset(n)) })).name).toBe("dist-chrome-1.zip");
    expect(pickAsset(release("browser-v1.0.0", { assets: [asset("oss-dist-chrome-1.zip")] })).name).toBe("oss-dist-chrome-1.zip");
    expect(() => pickAsset(release("browser-v1.0.0", { assets: [asset("dist-firefox-1.zip")] }))).toThrow(/no dist-chrome/);
  });

  it("parses sha256 digests only", () => {
    const hex = "07cf19b8f79e649005fdeee67c85d3cf31c735449a01a37a5b9f0287732605a5";
    expect(parseDigest(`sha256:${hex.toUpperCase()}`)).toBe(hex);
    expect(parseDigest(null)).toBeNull();
    expect(parseDigest(undefined)).toBeNull();
    expect(parseDigest("sha512:abc")).toBeNull();
    expect(parseDigest("sha256:1234")).toBeNull();
  });

  it("accepts only official release download URLs", () => {
    expect(isOfficialAssetUrl("https://github.com/bitwarden/clients/releases/download/browser-v2026.11.0/bit-dist-chrome-2026.11.0.zip")).toBe(true);
    expect(isOfficialAssetUrl("http://github.com/bitwarden/clients/releases/download/browser-v1/x.zip")).toBe(false);
    expect(isOfficialAssetUrl("https://github.com/evil/clients/releases/download/browser-v1/x.zip")).toBe(false);
    expect(isOfficialAssetUrl("https://example.com/bitwarden/clients/releases/download/browser-v1/x.zip")).toBe(false);
    expect(isOfficialAssetUrl("not a url")).toBe(false);
  });

  it("flags zip entries that would escape the extraction folder", () => {
    expect(unsafeEntries(["manifest.json", "content/a.js", "_locales/en/messages.json"])).toEqual([]);
    expect(unsafeEntries(["../x", "a/../../b", "/etc/x", "C:/x", "a\\b", ""])).toHaveLength(6);
    expect(unsafeEntries(["a..b/c"])).toEqual([]);
  });
});

describe("managerExtensions", () => {
  it("returns the requested fakes, once each, as absolute folders with a manifest", () => {
    const dirs = managerExtensions({ bitwarden: false, fakes: ["lastpass", "1password", "lastpass"] });
    expect(dirs).toEqual([fakeExtensionDir("lastpass"), fakeExtensionDir("1password")]);
    for (const d of dirs) {
      expect(d.startsWith("/")).toBe(true);
      expect(existsSync(join(d, "manifest.json"))).toBe(true);
    }
  });

  it("returns nothing for nothing", () => {
    expect(managerExtensions({ bitwarden: false, fakes: [] })).toEqual([]);
  });

  it("rejects an unknown fake", () => {
    expect(() => managerExtensions({ bitwarden: false, fakes: ["keeper" as "lastpass"] })).toThrow(/unknown fake/);
  });

  it("puts Bitwarden first when extracted, and explains how to fetch it otherwise", () => {
    if (existsSync(join(BITWARDEN_DIR, "manifest.json"))) {
      expect(managerExtensions({ bitwarden: true, fakes: ["dashlane"] })).toEqual([BITWARDEN_DIR, fakeExtensionDir("dashlane")]);
    } else {
      expect(() => managerExtensions({ bitwarden: true, fakes: [] })).toThrow(/fetch-bitwarden\.ts/);
    }
  });
});

const read = (p: string) => readFileSync(p, "utf8");

describe("fake extensions", () => {
  it("are MV3 extensions with no permission, one content script, short_name naming the fake", () => {
    for (const fake of FAKE_MANAGERS) {
      const m = JSON.parse(read(join(fakeExtensionDir(fake), "manifest.json")));
      expect(m.manifest_version).toBe(3);
      expect(m.short_name).toBe(`fake-${fake}`);
      expect(m.permissions).toEqual([]);
      expect(m.host_permissions).toBeUndefined();
      expect(m.background).toBeUndefined();
      expect(m.content_scripts).toEqual([{ matches: ["<all_urls>"], js: ["fake.js"], run_at: "document_idle", all_frames: false }]);
    }
  });

  it("share one identical script", () => {
    const [first, ...rest] = FAKE_MANAGERS.map((f) => read(join(fakeExtensionDir(f), "fake.js")));
    for (const s of rest) expect(s).toBe(first);
  });

  it("use no network or storage API", () => {
    const src = read(join(fakeExtensionDir("1password"), "fake.js"));
    for (const api of ["fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "localStorage", "sessionStorage", "indexedDB", "chrome.storage", "sendMessage", ".submit(", "\u2014"]) {
      expect(src.includes(api), api).toBe(false);
    }
  });
});

describe("fake script in a page", () => {
  const src = read(join(fakeExtensionDir("1password"), "fake.js"));
  const HTML =
    '<!doctype html><title>Sign in</title><form><input id="u" type="email" name="email"><input id="p" type="password" name="password"></form><input id="q" type="search" name="q">';

  /** A fresh page with every element laid out at one visible box, the fake loaded as `fake`. */
  const run = (fake: string) => {
    const dom = new JSDOM(HTML, { runScripts: "outside-only" });
    const w = dom.window as unknown as { chrome: unknown; eval(s: string): unknown; requestAnimationFrame(cb: () => void): number; document: Document };
    // Rescans are scheduled on animation frames; the initial scan is what these cases check.
    w.requestAnimationFrame = () => 0;
    const rect = { x: 100, y: 100, left: 100, top: 100, right: 400, bottom: 136, width: 300, height: 36, toJSON() {} };
    (w as unknown as { Element: typeof Element }).Element.prototype.getBoundingClientRect = () => rect as DOMRect;
    w.chrome = { runtime: { getManifest: () => ({ short_name: `fake-${fake}` }) } } as unknown;
    w.eval(src);
    pages.push(dom);
    return w.document;
  };
  const pages: JSDOM[] = [];
  afterEach(() => { while (pages.length) pages.pop()!.window.close(); });

  it("1password: com-1password-button on username and password, none on search", () => {
    const d = run("1password");
    expect(d.querySelectorAll("com-1password-button")).toHaveLength(2);
    expect(d.getElementById("u")!.getAttribute("data-fake-1password")).toBe("username");
    expect(d.getElementById("p")!.getAttribute("data-fake-1password")).toBe("password");
    expect(d.getElementById("q")!.hasAttribute("data-fake-1password")).toBe(false);
  });

  it("lastpass: data-lastpass-icon-root icons", () => {
    expect(run("lastpass").querySelectorAll("[data-lastpass-icon-root]")).toHaveLength(2);
  });

  it("dashlane: data-dashlane-rid on the fields and an icon each", () => {
    const d = run("dashlane");
    expect(d.getElementById("u")!.getAttribute("data-dashlane-rid")).toMatch(/^[0-9a-f]{16}$/);
    expect(d.getElementById("p")!.getAttribute("data-dashlane-rid")).toMatch(/^[0-9a-f]{16}$/);
    expect(d.querySelectorAll("[data-dashlane-icon]")).toHaveLength(2);
  });

  it("an unknown short_name plants nothing", () => {
    expect(run("keeper").querySelectorAll("[data-fake-manager]")).toHaveLength(0);
  });

  it("untrusted focus and clicks open no menu and fill nothing", () => {
    const d = run("lastpass");
    const u = d.getElementById("u") as HTMLInputElement;
    u.dispatchEvent(new d.defaultView!.FocusEvent("focus"));
    (d.querySelector("[data-lastpass-icon-root]") as HTMLElement).click();
    expect(d.querySelector("[data-lastpass-root]")).toBeNull();
    expect(u.value).toBe("");
    expect((d.getElementById("p") as HTMLInputElement).value).toBe("");
  });
});
