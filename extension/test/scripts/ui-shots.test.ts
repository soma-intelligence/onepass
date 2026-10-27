// @vitest-environment node
// Path guards of the dev-only visual harness (scripts/ui-shots.mjs).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { MARKER, checkOutDir, isInside, prepareSite, servedPath } from "../../scripts/shots-paths.mjs";

const EXT = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const dirs: string[] = [];
const temp = () => {
  const d = mkdtempSync(join(tmpdir(), "onepass-shots-test-"));
  dirs.push(d);
  return d;
};

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("ui-shots path guards", () => {
  it("isInside compares whole path segments", () => {
    expect(isInside("/a/site", "/a/site/x.js")).toBe(true);
    expect(isInside("/a/site", "/a/site")).toBe(false);
    expect(isInside("/a/site", "/a/site-evil/x.js")).toBe(false);
    expect(isInside("/a/site", "/a/site/../other")).toBe(false);
    expect(isInside("/a/site", "/a/site/..foo")).toBe(true);
  });

  it("accepts an output directory under extension/ or the temp dir only", () => {
    expect(checkOutDir(join(EXT, "test-results", "ui-shots"), EXT)).toBe(join(EXT, "test-results", "ui-shots"));
    expect(checkOutDir(join(tmpdir(), "shots"), EXT)).not.toBeNull();
    expect(checkOutDir(EXT, EXT)).toBeNull();
    expect(checkOutDir(resolve(EXT, ".."), EXT)).toBeNull();
    expect(checkOutDir("/", EXT)).toBeNull();
    expect(checkOutDir(tmpdir(), EXT)).toBeNull();
    expect(checkOutDir(join(EXT, "..", "docs"), EXT)).toBeNull();
  });

  it("replaces only a site folder it created", () => {
    const out = temp();
    writeFileSync(join(out, "keep.txt"), "x");
    const site = prepareSite(out);
    expect(existsSync(join(site, MARKER))).toBe(true);
    writeFileSync(join(site, "old.js"), "x");
    prepareSite(out);
    expect(existsSync(join(site, "old.js"))).toBe(false);
    expect(readFileSync(join(out, "keep.txt"), "utf8")).toBe("x");

    const other = temp();
    mkdirSync(join(other, "site"));
    writeFileSync(join(other, "site", "mine.txt"), "x");
    expect(() => prepareSite(other)).toThrow(/refusing/);
    expect(existsSync(join(other, "site", "mine.txt"))).toBe(true);
  });

  it("serves only files inside the site folder", () => {
    const site = join(temp(), "site");
    expect(servedPath(site, "/popup.html")).toBe(join(site, "popup.html"));
    expect(servedPath(site, "/../keep.txt")).toBeNull();
    expect(servedPath(site, "/%2e%2e/keep.txt")).toBeNull();
    expect(servedPath(site, "/..%2fsite-evil/x.js")).toBeNull();
    expect(servedPath(site, "/%E0%A4%A")).toBeNull();
  });

  it("the script refuses an output directory outside the allowed roots, deleting nothing", () => {
    const outside = resolve(EXT, "..", "docs");
    const r = spawnSync(process.execPath, [join(EXT, "scripts", "ui-shots.mjs"), outside], { encoding: "utf8" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("must be under extension/");
    expect(existsSync(outside)).toBe(true);
  });
});
