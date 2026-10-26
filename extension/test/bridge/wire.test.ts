// @vitest-environment node
import { describe, expect, it } from "vitest";
import { BridgeError } from "../../src/bridge/bytes";
import { MAX_FRAME, parseEnvelope } from "../../src/bridge/wire";
import { type PairingVector, type SessionVector, loadVector } from "./vectors";

const pv = loadVector<PairingVector>("pairing");
const sv = loadVector<SessionVector>("session");

function code(f: () => unknown): string {
  try {
    f();
  } catch (e) {
    return e instanceof BridgeError ? e.code : "other";
  }
  return "none";
}

describe("wire envelopes", () => {
  it("every vector envelope parses and keeps its shape", () => {
    const all = [
      pv.pair_hello,
      pv.pair_offer,
      pv.pair_reveal,
      pv.pair_sas,
      pv.pair_done,
      pv.pair_confirm,
      pv.pair_ok,
      sv.hello,
      sv.welcome,
      sv.finish,
      ...sv.frames_e2h.map((f) => f.msg),
      ...sv.frames_h2e.map((f) => f.msg),
    ];
    for (const env of all) {
      expect(parseEnvelope(env)).toEqual(env);
    }
  });

  it("parses JSON text too, error frames included", () => {
    expect(parseEnvelope('{"v":1,"t":"error","code":"unknown_pairing"}')).toEqual({
      v: 1,
      t: "error",
      code: "unknown_pairing",
    });
  });

  it("version other than 1, or missing, is refused as version", () => {
    expect(code(() => parseEnvelope({ ...pv.pair_ok, v: 2 }))).toBe("version");
    expect(code(() => parseEnvelope({ t: "pair_ok" }))).toBe("version");
    expect(code(() => parseEnvelope({ ...pv.pair_ok, v: "1" }))).toBe("version");
  });

  it("malformed envelopes are bad_frame", () => {
    const offer = pv.pair_offer;
    const cases: unknown[] = [
      null,
      [],
      "not json",
      { v: 1, t: "nope" },
      { ...offer, pk: "AAAA" },
      { ...offer, pairing_id: 5 },
      { ...offer, n: undefined },
      { v: 1, t: "msg", c: -1, d: "AA==" },
      { v: 1, t: "msg", c: 2 ** 53, d: "AA==" },
      { v: 1, t: "msg", c: 1.5, d: "AA==" },
      { v: 1, t: "msg", c: 0, d: "%%" },
      { v: 1, t: "error" },
    ];
    for (const c of cases) {
      expect(code(() => parseEnvelope(c)), JSON.stringify(c)).toBe("bad_frame");
    }
  });

  it("refuses frames over 1 MiB", () => {
    const big = `{"v":1,"t":"msg","c":0,"d":"${"A".repeat(MAX_FRAME)}"}`;
    expect(code(() => parseEnvelope(big))).toBe("bad_frame");
  });
});
