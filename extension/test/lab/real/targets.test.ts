// @vitest-environment node
// Options and targets of the real-site bench.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { liveTargets, parseArgs, pickHosts, profileTargets, readSignedIn, replicaTargets } from "../../../lab/real/targets.ts";

describe("parseArgs", () => {
  it("has the defaults of the README", () => {
    const o = parseArgs([], new Date(2026, 10, 21, 9, 5));
    expect(o).toMatchObject({ sites: 1000, kinds: ["live"], workers: 2, managers: [], timeBoxMs: 90_000 });
    expect(o.out).toMatch(/lab\/out\/real-2026-11-21-0905$/);
  });

  it("reads every option and refuses unknown ones", () => {
    const o = parseArgs(["--sites", "5", "--kinds", "live,replica", "--workers", "3", "--managers", "bitwarden,1password", "--out", "/tmp/x", "--time-box", "30"]);
    expect(o).toMatchObject({ sites: 5, kinds: ["live", "replica"], workers: 3, managers: ["bitwarden", "1password"], out: "/tmp/x", timeBoxMs: 30_000 });
    expect(() => parseArgs(["--kinds", "live,nope"])).toThrow(/unknown kind/);
    expect(() => parseArgs(["--managers", "keepass"])).toThrow(/unknown manager/);
    expect(() => parseArgs(["--sites", "0"])).toThrow(/positive/);
    expect(() => parseArgs(["--bogus"])).toThrow(/unknown option/);
  });
});

describe("targets", () => {
  const tranco = ["google.com", "facebook.com", "bbc.co.uk", "example.org"];
  const picked = pickHosts(tranco, 3);

  it("picks the first N in Tranco order, narrowed by --only", () => {
    expect(picked).toEqual([{ host: "google.com", rank: 1 }, { host: "facebook.com", rank: 2 }, { host: "bbc.co.uk", rank: 3 }]);
    expect(pickHosts(tranco, 4, ["example.org"])).toEqual([{ host: "example.org", rank: 4 }]);
  });

  it("builds live, profile and replica targets", () => {
    expect(liveTargets(picked)[0]).toEqual({ kind: "live", host: "google.com", rank: 1, url: "https://google.com/", knownSignedIn: false });
    expect(profileTargets(picked, undefined)).toHaveLength(3);
    expect(profileTargets(picked, ["facebook.com"])).toEqual([{ kind: "profile", host: "facebook.com", rank: 2, url: "https://facebook.com/", knownSignedIn: true }]);
    const rep = replicaTargets(["bbc.co.uk", "www.google.com", "example.org"], picked, tranco);
    expect(rep.map((t) => [t.host, t.rank])).toEqual([["www.google.com", 1], ["bbc.co.uk", 3]]);
  });

  it("reads the profile's signed-in list in either shape", () => {
    const dir = mkdtempSync(join(tmpdir(), "real-targets-"));
    expect(readSignedIn(dir)).toBeUndefined();
    writeFileSync(join(dir, "signed-in.json"), JSON.stringify({ hosts: ["GitHub.com"] }));
    expect(readSignedIn(dir)).toEqual(["github.com"]);
    writeFileSync(join(dir, "signed-in.json"), JSON.stringify(["a.com"]));
    expect(readSignedIn(dir)).toEqual(["a.com"]);
  });
});
