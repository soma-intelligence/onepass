import { describe, expect, it } from "vitest";
import { findRecoveryCodes } from "../../../src/content/setup/recovery";

const codes = (n: number, shape: (i: number) => string) => Array.from({ length: n }, (_, i) => shape(i));
const hex = (i: number) => `a1b${i % 10}c-d2e${(i * 7) % 10}f`;

function root(html: string, title = ""): ParentNode {
  document.title = title;
  document.body.innerHTML = html;
  return document;
}

describe("findRecoveryCodes", () => {
  it("finds 10 codes in a list under 'Recovery codes'", () => {
    const list = codes(10, hex);
    const r = root(`<h2>Recovery codes</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toEqual(list);
  });

  it("finds 8 codes 'xxxx-xxxx' in a pre under 'Codes de secours'", () => {
    const list = codes(8, (i) => `abc${i}-wxy${i}`);
    const r = root(`<section><h3>Codes de secours</h3><pre>${list.join("\n")}</pre></section>`);
    expect(findRecoveryCodes(r)).toEqual(list);
  });

  it("returns null for a list of 10 product SKUs with no recovery wording", () => {
    const list = codes(10, (i) => `SKU${i}0-ABCD${i}`);
    const r = root(`<h2>Products</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toBeNull();
  });

  it("returns null for 5 codes and for 33 codes", () => {
    const five = codes(5, hex);
    const many = codes(33, (i) => `ab${String(i).padStart(2, "0")}c-de${String(i).padStart(2, "0")}f`);
    expect(findRecoveryCodes(root(`<h2>Recovery codes</h2><ul>${five.map((c) => `<li>${c}</li>`).join("")}</ul>`))).toBeNull();
    expect(findRecoveryCodes(root(`<h2>Recovery codes</h2><ul>${many.map((c) => `<li>${c}</li>`).join("")}</ul>`))).toBeNull();
  });

  it("returns null when the tokens have different shapes", () => {
    const list = [...codes(5, hex), ...codes(5, (i) => `abcdefgh${i}`)];
    const r = root(`<h2>Recovery codes</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toBeNull();
  });

  it("ignores wording that is only in the page title", () => {
    const list = codes(6, (i) => `SKU${i}0-ABCD${i}`);
    const r = root(`<h2>Products</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`, "Backup generators");
    expect(findRecoveryCodes(r)).toBeNull();
  });

  it("keeps a Discord-style list where one random code has no digit", () => {
    const list = ["k3xq9vbn", "p7mzt2wa", "qwertyui", "h4jd8sle", "9cn2ruxo", "fz6tb1wq", "y8gk3mvd", "e2lr5npa", "u9xw4hcz", "b6vt7qjm"];
    const r = root(`<h2>Backup codes</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toEqual(list);
  });

  it("returns null when fewer than half the tokens have a digit", () => {
    const list = ["k3xq9vbn", "p7mzt2wa", "qwertyui", "asdfghjk", "zxcvbnml", "poiuytre"];
    const r = root(`<h2>Backup codes</h2><ul>${list.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toBeNull();
  });

  it("returns null for four-letter navigation words", () => {
    const words = ["Home", "Shop", "Blog", "Help", "Docs", "News"];
    const r = root(`<h2>Recovery codes</h2><ul>${words.map((c) => `<li>${c}</li>`).join("")}</ul>`);
    expect(findRecoveryCodes(r)).toBeNull();
  });
});
