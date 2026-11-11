// An app from before `origin` on `unlock` and `vaults` refuses the unknown field (`invalid`):
// the request goes again without it, once, and the field is not sent again this session.
import { describe, expect, it } from "vitest";
import { HostCompat } from "../../src/background/host-compat";
import { BgError } from "../../src/background/session";

const SITE = "https://atlas-cloud.test";

function fake(old: boolean, fail?: (r: Record<string, unknown>) => BgError | undefined) {
  const requests: Record<string, unknown>[] = [];
  const session = {
    request: async (r: Record<string, unknown>) => {
      requests.push({ ...r });
      const f = fail?.(r);
      if (f) throw f;
      if (old && "origin" in r && (r.op === "unlock" || r.op === "vaults")) throw new BgError("invalid");
      return r.op === "unlock" ? { locked: false } : { vaults: [{ id: "v1", name: "Personnel", color: null }] };
    },
  };
  return { requests, compat: new HostCompat(session as never) };
}

describe("unlock and vaults with an origin, against an app that does not know the field", () => {
  it("a current app: the origin goes, nothing is retried", async () => {
    const t = fake(false);
    expect(await t.compat.unlock(SITE)).toEqual({ locked: false });
    expect((await t.compat.vaults(SITE)).vaults).toHaveLength(1);
    expect(t.requests).toEqual([{ op: "unlock", origin: SITE }, { op: "vaults", origin: SITE }]);
  });

  it("an older app answers `invalid`: once more without the origin, then never with it again (either request)", async () => {
    const t = fake(true);
    expect(await t.compat.unlock(SITE)).toEqual({ locked: false });
    expect(t.requests).toEqual([{ op: "unlock", origin: SITE }, { op: "unlock" }]);
    expect((await t.compat.vaults(SITE)).vaults).toHaveLength(1);
    expect(await t.compat.unlock(SITE)).toEqual({ locked: false });
    expect(t.requests.slice(2)).toEqual([{ op: "vaults" }, { op: "unlock" }]);
  });

  it("the same from `vaults` first", async () => {
    const t = fake(true);
    await t.compat.vaults(SITE);
    await t.compat.unlock(SITE);
    expect(t.requests).toEqual([{ op: "vaults", origin: SITE }, { op: "vaults" }, { op: "unlock" }]);
  });

  it("no origin to send: one plain request", async () => {
    const t = fake(true);
    await t.compat.unlock(undefined);
    await t.compat.vaults();
    expect(t.requests).toEqual([{ op: "unlock" }, { op: "vaults" }]);
  });

  it("any other refusal is the answer: no retry, and the app is not taken for an old one", async () => {
    let locked = true;
    const t = fake(false, (r) => (r.op === "vaults" && locked ? new BgError("locked") : undefined));
    await expect(t.compat.vaults(SITE)).rejects.toMatchObject({ code: "locked" });
    expect(t.requests).toEqual([{ op: "vaults", origin: SITE }]);
    locked = false;
    await t.compat.vaults(SITE);
    expect(t.requests.at(-1)).toEqual({ op: "vaults", origin: SITE });
  });

  it("`invalid` again without the origin: the refusal stands and the origin is still sent next time", async () => {
    const t = fake(false, (r) => (r.op === "unlock" ? new BgError("invalid") : undefined));
    await expect(t.compat.unlock(SITE)).rejects.toMatchObject({ code: "invalid" });
    expect(t.requests).toEqual([{ op: "unlock", origin: SITE }, { op: "unlock" }]);
    await t.compat.vaults(SITE);
    expect(t.requests.at(-1)).toEqual({ op: "vaults", origin: SITE });
  });
});
