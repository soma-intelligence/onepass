import { describe, expect, it } from "vitest";
import { findCandidates } from "../../../src/content/setup/candidates";

function sized(el: Element, w: number, h: number): Element {
  el.getBoundingClientRect = () =>
    ({ x: 0, y: 0, left: 0, top: 0, right: w, bottom: h, width: w, height: h, toJSON: () => ({}) }) as DOMRect;
  return el;
}

function page(html: string): Document {
  document.body.innerHTML = html;
  return document;
}

describe("findCandidates", () => {
  it("returns the otpauth link first", () => {
    const doc = page(`<img id="i"><a id="l" href="otpauth://totp/x?secret=ABCDEFGHIJKLMNOP">key</a>`);
    sized(doc.getElementById("i")!, 200, 200);
    const out = findCandidates(doc);
    expect(out[0]?.kind).toBe("link");
    expect(out[1]?.kind).toBe("img");
  });

  it("keeps a 200x200 img and drops a 60x60 one, a 300x100 banner and a hidden one", () => {
    const doc = page(`<img id="ok"><img id="small"><img id="banner"><img id="hidden" style="display:none">`);
    sized(doc.getElementById("ok")!, 200, 200);
    sized(doc.getElementById("small")!, 60, 60);
    sized(doc.getElementById("banner")!, 300, 100);
    sized(doc.getElementById("hidden")!, 200, 200);
    const out = findCandidates(doc);
    expect(out.map((c) => (c.el as HTMLElement).id)).toEqual(["ok"]);
  });

  it("finds a canvas, an inline svg and a div with a background-image", () => {
    const doc = page(
      `<canvas id="c"></canvas><svg id="s" xmlns="http://www.w3.org/2000/svg"></svg>` +
        `<div id="d" style="background-image:url(data:image/png;base64,AAAA)"></div>`,
    );
    sized(doc.getElementById("c")!, 150, 150);
    sized(doc.getElementById("s") as unknown as Element, 160, 160);
    sized(doc.getElementById("d")!, 170, 170);
    const kinds = findCandidates(doc).map((c) => c.kind).sort();
    expect(kinds).toEqual(["background", "canvas", "svg"]);
  });

  it("caps at 12 and keeps the largest on an avatar grid of 30 squares plus one QR", () => {
    let html = "";
    for (let i = 0; i < 30; i++) html += `<img class="av">`;
    html += `<img id="qr">`;
    const doc = page(html);
    doc.querySelectorAll(".av").forEach((e) => sized(e, 90, 90));
    sized(doc.getElementById("qr")!, 220, 220);
    const out = findCandidates(doc);
    expect(out).toHaveLength(12);
    expect((out[0]!.el as HTMLElement).id).toBe("qr");
  });
});
