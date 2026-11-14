import QRCode from "qrcode";
import { describe, expect, it } from "vitest";
import { decodeQr } from "../../src/setup/qr-decode";

const URI = "otpauth://totp/Atlas:ada?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Atlas";

/** Draws a QR matrix into a raw RGBA buffer: `px` per module, a 4-module quiet zone. */
function draw(text: string, px: number, invert: boolean) {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const n = qr.modules.size;
  const side = (n + 8) * px;
  const data = new Uint8ClampedArray(side * side * 4);
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const mx = Math.floor(x / px) - 4;
      const my = Math.floor(y / px) - 4;
      const dark = mx >= 0 && my >= 0 && mx < n && my < n && qr.modules.get(my, mx) === 1;
      const v = dark !== invert ? 0 : 255;
      const i = (y * side + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
  }
  return { data, width: side, height: side };
}

describe("decodeQr", () => {
  it("decodes a black-on-white code at 3 px per module", () => {
    expect(decodeQr(draw(URI, 3, false))).toBe(URI);
  });

  it("decodes an inverted code", () => {
    expect(decodeQr(draw(URI, 3, true))).toBe(URI);
  });

  it("returns null on noise", () => {
    const w = 120;
    const data = new Uint8ClampedArray(w * w * 4);
    let seed = 12345;
    for (let i = 0; i < data.length; i += 4) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      const v = (seed >> 16) & 1 ? 255 : 0;
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
    expect(decodeQr({ data, width: w, height: w })).toBeNull();
  });
});
