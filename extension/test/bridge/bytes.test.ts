// @vitest-environment node
import { describe, expect, it } from "vitest";
import { concat, ctEqual, fromB64, toB64, u32be, u64be, utf8 } from "../../src/bridge/bytes";

describe("bytes", () => {
  it("base64 round trip, standard alphabet with padding", () => {
    const all = new Uint8Array(256).map((_, i) => i);
    const s = toB64(all);
    expect(s).toBe(Buffer.from(all).toString("base64"));
    expect(fromB64(s)).toEqual(all);
    expect(toB64(new Uint8Array([1, 2, 3]))).toBe("AQID");
    expect(toB64(new Uint8Array([0xfb, 0xff]))).toBe("+/8=");
  });

  it("base64 rejects non canonical or foreign input", () => {
    for (const bad of ["AQI", "AQ=D", "AQID\n", " AQID", "-_8=", "+/9=", "AR==", "A===", "AQID=="]) {
      expect(() => fromB64(bad), bad).toThrow();
    }
    expect(fromB64("")).toEqual(new Uint8Array(0));
  });

  it("big-endian integers", () => {
    expect(u32be(0x01020304)).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(u64be(0x0102030405)).toEqual(new Uint8Array([0, 0, 0, 1, 2, 3, 4, 5]));
    expect(u64be(2 ** 32)).toEqual(new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0]));
  });

  it("concat, utf8, constant-time equality", () => {
    expect(concat(new Uint8Array([1]), new Uint8Array([]), new Uint8Array([2, 3]))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    expect(utf8("é")).toEqual(new Uint8Array([0xc3, 0xa9]));
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1]))).toBe(false);
  });
});
