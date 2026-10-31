// @vitest-environment node
// The dev-only recorder must not exist in a release build: neither its message
// types nor its module code may reach any bundle unless ONEPASS_LAB_RECORDER=1.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error build.mjs has no type declarations
import { buildAll } from "../../build.mjs";

const BUNDLES = ["background.js", "content.js", "popup.js"];
// Strings only the recorder modules contain.
const MARKERS = ["lab-recorder-export", "lab-recorder-step", "onepass-lab-recorder", "recordSubmit", "createRecorderContent", "installRecorder"];

const dirs: string[] = [];
const saved = process.env.ONEPASS_LAB_RECORDER;
afterEach(() => {
  if (saved === undefined) delete process.env.ONEPASS_LAB_RECORDER;
  else process.env.ONEPASS_LAB_RECORDER = saved;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function bundles(flag: string | undefined): Promise<Record<string, string>> {
  const dist = mkdtempSync(join(tmpdir(), "onepass-recorder-build-"));
  dirs.push(dist);
  if (flag === undefined) delete process.env.ONEPASS_LAB_RECORDER;
  else process.env.ONEPASS_LAB_RECORDER = flag;
  await buildAll(["chromium", "firefox"], false, false, false, dist);
  const out: Record<string, string> = {};
  for (const b of ["chromium", "firefox"]) for (const f of BUNDLES) out[`${b}/${f}`] = readFileSync(join(dist, b, f), "utf8");
  return out;
}

describe("recorder in builds", () => {
  it("a release build contains nothing of the recorder", async () => {
    const out = await bundles(undefined);
    for (const [name, code] of Object.entries(out)) for (const m of MARKERS) expect(code, `${name} has ${m}`).not.toContain(m);
  }, 60_000);

  it("any other flag value is still a release build", async () => {
    const out = await bundles("true");
    for (const [name, code] of Object.entries(out)) for (const m of MARKERS) expect(code, `${name} has ${m}`).not.toContain(m);
  }, 60_000);

  it("the dev build has it in the three bundles (the check above is not vacuous)", async () => {
    const out = await bundles("1");
    expect(out["chromium/content.js"]).toContain("lab-recorder-step");
    expect(out["chromium/background.js"]).toContain("lab-recorder-export");
    expect(out["chromium/popup.js"]).toContain("lab-recorder-export");
    expect(out["firefox/background.js"]).toContain("lab-recorder-export");
  }, 60_000);
});
