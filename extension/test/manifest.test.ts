import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BROWSERS = ["chromium", "firefox", "safari"] as const;

type Manifest = {
  manifest_version: number;
  name: string;
  version: string;
  permissions: string[];
  host_permissions: string[];
  content_scripts: { matches: string[]; all_frames: boolean; run_at: string }[];
  action: { default_popup: string };
  background: { service_worker?: string; scripts?: string[]; type?: string };
  web_accessible_resources: { resources: string[]; matches: string[]; use_dynamic_url?: boolean }[];
  content_security_policy: { extension_pages: string };
  browser_specific_settings?: { gecko?: { id?: string } };
  key?: string;
};

const load = (b: string): Manifest =>
  JSON.parse(readFileSync(join(root, "dist", b, "manifest.json"), "utf8")) as Manifest;

beforeAll(() => {
  execFileSync("node", ["build.mjs"], { cwd: root, stdio: "pipe" });
}, 60_000);

describe.each(BROWSERS)("manifest %s", (b) => {
  it("has the exact permissions and no http entry", () => {
    const m = load(b);
    expect(m.manifest_version).toBe(3);
    expect(m.name).toBe("OnePass");
    expect(m.version).toBe("0.2.0");
    expect([...m.permissions].sort()).toEqual(
      ["activeTab", "nativeMessaging", "scripting", "storage", "webNavigation"].sort(),
    );
    expect(m.host_permissions).toEqual(["https://*/*"]);
    const all = [
      ...m.host_permissions,
      ...m.content_scripts.flatMap((c) => c.matches),
      ...m.web_accessible_resources.flatMap((w) => w.matches),
    ];
    expect(all.every((u) => u.startsWith("https://"))).toBe(true);
    expect(JSON.stringify(m)).not.toMatch(/http:\/\/|<all_urls>/);
  });

  it("injects the content script in all HTTPS frames at idle", () => {
    const [cs] = load(b).content_scripts;
    expect(cs?.matches).toEqual(["https://*/*"]);
    expect(cs?.all_frames).toBe(true);
    expect(cs?.run_at).toBe("document_idle");
  });

  it("exposes only the three pages and their scripts", () => {
    const m = load(b);
    expect(m.web_accessible_resources).toHaveLength(1);
    expect([...(m.web_accessible_resources[0]?.resources ?? [])].sort()).toEqual(
      ["menu.html", "menu.js", "overlay.html", "overlay.js", "save.html", "save.js"].sort(),
    );
  });

  it("sets popup and CSP", () => {
    const m = load(b);
    expect(m.action.default_popup).toBe("popup.html");
    expect(m.content_security_policy.extension_pages).toBe("script-src 'self'; object-src 'none'");
    expect(m.key).toBeUndefined();
  });
});

describe("per-browser differences", () => {
  it("chromium: service worker and dynamic url", () => {
    const m = load("chromium");
    expect(m.background.service_worker).toBe("background.js");
    expect(m.background.type).toBe("module");
    expect(m.web_accessible_resources[0]?.use_dynamic_url).toBe(true);
  });
  it("firefox: background scripts and gecko id", () => {
    const m = load("firefox");
    expect(m.background.scripts).toEqual(["background.js"]);
    expect(m.background.service_worker).toBeUndefined();
    expect(m.browser_specific_settings?.gecko?.id).toBe("onepass@somalabs.me");
    expect(m.web_accessible_resources[0]?.use_dynamic_url).toBeUndefined();
  });
  it("safari: service worker", () => {
    const m = load("safari");
    expect(m.background.service_worker).toBe("background.js");
    expect(m.web_accessible_resources[0]?.use_dynamic_url).toBeUndefined();
  });
});

describe("native messaging host of the build", () => {
  it("is the app's relay in a regular build", () => {
    const bg = readFileSync(join(root, "dist", "chromium", "background.js"), "utf8");
    expect(bg).toMatch(/NATIVE_HOST = true \? "me\.somalabs\.onepass" :/);
  });
});
