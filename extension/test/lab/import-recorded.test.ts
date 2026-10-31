// @vitest-environment node
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { importRecorded } from "../../lab/corpus/import-recorded";
import type { Sample } from "../../lab/corpus/types";
import type { FieldFeatures } from "../../src/content/detect/features";

const field = (over: Partial<FieldFeatures> = {}): FieldFeatures => ({
  index: 0, tag: "input", type: "text", hasPattern: false, required: false, depth: 3, siblings: 0,
  visibility: "visible", width: 200, height: 30, formButtons: [], neighbourLabels: [], ...over,
});
const step = (host: string, at: number, fields: FieldFeatures[], buttons: string[] = []) => ({
  host, at, form: { fields, buttons }, filled: {},
});

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "onepass-import-"));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const read = (dir: string, f: string) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Sample;

describe("import-recorded", () => {
  it("groups the steps of one host, in order, into a recorded Sample", () => {
    const out = tmp();
    const r = importRecorded(
      [
        step("b.test", 20, [field({ type: "password", name: "pw", autocomplete: "current-password" })], ["sign in"]),
        step("a.test", 5, [field({ name: "x" })]),
        step("b.test", 10, [field({ type: "email", name: "email", autocomplete: "email" })], ["next"]),
      ],
      out,
    );
    expect(r.hosts).toBe(2);
    expect(readdirSync(out).sort()).toEqual(["a.test.json", "b.test.json"]);
    const b = read(out, "b.test.json");
    expect(b).toMatchObject({ source: "recorded", extractor: 2, host: "b.test", status: "ok" });
    expect(b.steps).toHaveLength(2);
    expect(b.steps![0]![0]!.step).toBe("identifier");
    expect(b.steps![1]![0]!.step).toBe("password");
    expect(b.steps![0]![0]!.fields[0]!.role).toBe("email");
  });

  it("runs every string through the sanitizer", () => {
    const out = tmp();
    importRecorded([step("a.test", 1, [field({ label: "mail bob@example.com", before: "call 0612345678 now", name: "x".repeat(60), placeholder: "tok " + "A".repeat(30) })], ["pay 1234567890123456"])], out);
    const json = readFileSync(join(out, "a.test.json"), "utf8");
    expect(json).not.toContain("bob@example.com");
    expect(json).not.toContain("0612345678");
    expect(json).not.toContain("1234567890123456");
    expect(json).not.toContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  });

  it("never writes a page-supplied lab label, filled map or unexpected key", () => {
    const out = tmp();
    const s = step("a.test", 1, [{ ...field(), lab: "email" } as FieldFeatures]);
    importRecorded([{ ...s, secret: "hunter2", filled: { 0: "user" } } as never], out);
    const json = readFileSync(join(out, "a.test.json"), "utf8");
    expect(json).not.toContain("hunter2");
    expect(json).not.toContain('"lab"');
  });

  it("skips a host that is not a plain hostname", () => {
    const out = tmp();
    const r = importRecorded([step("evil/../x", 1, [field()]), step("ok.test", 1, [field()])], out);
    expect(readdirSync(out)).toEqual(["ok.test.json"]);
    expect(r.skipped).toBe(1);
  });

  it("accepts the popup export file and a bare array through the CLI parser", async () => {
    const { parseExport } = await import("../../lab/corpus/import-recorded");
    const s = step("a.test", 1, [field()]);
    expect(parseExport(JSON.stringify({ version: 1, steps: [s] }))).toHaveLength(1);
    expect(parseExport(JSON.stringify([s]))).toHaveLength(1);
    expect(() => parseExport('{"nope":1}')).toThrow();
    const f = join(tmp(), "x.json");
    writeFileSync(f, "[]");
  });
});
