import { describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import {
  collectShadowRoots,
  composedOrder,
  MAX_SHADOW_DEPTH,
  MAX_SHADOW_ELEMENTS,
} from "../../src/content/detect/shadow";
import { isRendered } from "../../src/content/detect/visibility";
import { testGeometry } from "./helpers";

const SITE = "https://atlas-cloud.test/login";

const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>`;

function page(html: string): void {
  document.documentElement.innerHTML = `<head></head><body>${html}</body>`;
}

function host(sel: string, mode: ShadowRootMode, inner: string): ShadowRoot {
  const el = document.querySelector(sel);
  if (!el) throw new Error(`missing ${sel}`);
  const root = el.attachShadow({ mode });
  root.innerHTML = inner;
  return root;
}

/** A stand-in for `chrome.dom.openOrClosedShadowRoot`: closed roots made by the test. */
function fakeDomApi(closed: Map<Element, ShadowRoot>) {
  return (el: Element) => el.shadowRoot ?? closed.get(el) ?? null;
}

describe("shadow roots (D1, D2)", () => {
  it("open_shadow_fields_detected", () => {
    page(`<lab-shell></lab-shell>`);
    const root = host("lab-shell", "open", LOGIN);
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
    const f = a.forms[0]!;
    expect(refs.get(f.ref)).toBe(root.getElementById("login"));
    expect(f.fields.map((x) => [refs.get(x.ref), x.role])).toEqual([
      [root.getElementById("u"), "username"],
      [root.getElementById("p"), "current_password"],
    ]);
    expect(refs.get(f.submitRef!)).toBe(root.getElementById("go"));
  });

  it("closed_shadow_fields_detected_with_dom_api", () => {
    page(`<lab-shell></lab-shell>`);
    const root = host("lab-shell", "closed", LOGIN);
    const refs = new RefRegistry();
    // Without the extension API, a closed root stays out of reach.
    expect(analyzeDocument(document, refs, { url: SITE, geometry: testGeometry }).forms).toEqual([]);
    const shadowRoots = collectShadowRoots(document, { shadowRootOf: fakeDomApi(new Map([[root.host, root]])) });
    expect(shadowRoots).toEqual([root]);
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry, shadowRoots });
    expect(a.forms.map((f) => f.kind)).toEqual(["login"]);
    expect(refs.get(a.forms[0]!.fields[1]!.ref)).toBe(root.getElementById("p"));
  });

  it("the hidden light-DOM relay of a shadow form is never a form", () => {
    page(`<lab-shell></lab-shell><form id="relay" hidden><input type="hidden" name="username"><input type="hidden" name="password"></form>`);
    const root = host("lab-shell", "open", LOGIN);
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    expect(a.forms.map((f) => refs.get(f.ref))).toEqual([root.getElementById("login")]);
  });

  it("skips the hosts it is told to (our own UI)", () => {
    page(`<onepass-root></onepass-root>`);
    const root = host("onepass-root", "open", LOGIN);
    expect(collectShadowRoots(document, { skip: (el) => el === root.host })).toEqual([]);
  });

  it("shadow_walk_bounded", () => {
    // Elements: a host past the first 3000 elements is not inspected.
    const filler = "<i></i>".repeat(MAX_SHADOW_ELEMENTS);
    page(`${filler}<x-late></x-late>`);
    host("x-late", "open", LOGIN);
    expect(collectShadowRoots(document)).toEqual([]);
    page(`<x-early></x-early>${filler}`);
    const early = host("x-early", "open", LOGIN);
    expect(collectShadowRoots(document)).toEqual([early]);

    // Depth: roots nested 10 deep, only the first 8 are entered.
    page(`<x-n></x-n>`);
    let el: Element = document.querySelector("x-n")!;
    const chain: ShadowRoot[] = [];
    for (let i = 0; i < 10; i++) {
      const r = el.attachShadow({ mode: "open" });
      r.innerHTML = "<x-n></x-n>";
      chain.push(r);
      el = r.querySelector("x-n")!;
    }
    expect(collectShadowRoots(document)).toEqual(chain.slice(0, MAX_SHADOW_DEPTH));
    expect(collectShadowRoots(document, { maxDepth: 2 })).toEqual(chain.slice(0, 2));
  });

  it("orders forms across trees by their hosts", () => {
    page(`<form id="a"><input id="ae" type="email" autocomplete="email"><input type="password" autocomplete="current-password"></form><x-b></x-b>`);
    const root = host("x-b", "open", LOGIN);
    const a = analyzeDocument(document, new RefRegistry(), { url: SITE, geometry: testGeometry });
    expect(a.forms).toHaveLength(2);
    const inner = root.getElementById("u")!;
    const outer = document.getElementById("ae")!;
    expect(composedOrder(outer, inner)).toBe(-1);
    expect(composedOrder(inner, outer)).toBe(1);
    expect(composedOrder(root.host, inner)).toBe(-1);
  });

  it("an aria-hidden ancestor outside the root hides the fields inside", () => {
    page(`<div aria-hidden="true"><x-c></x-c></div>`);
    const root = host("x-c", "open", LOGIN);
    expect(isRendered(root.getElementById("p")!, testGeometry)).toBe(false);
    expect(analyzeDocument(document, new RefRegistry(), { url: SITE, geometry: testGeometry }).forms).toEqual([]);
  });

  it("aria-labelledby resolves inside the field's own root", () => {
    page(`<x-d></x-d>`);
    const root = host(
      "x-d",
      "open",
      `<div><span id="lbl">Email address</span><input id="e" aria-labelledby="lbl"><span id="lp">Password</span><input id="pw" type="password" aria-labelledby="lp"></div>`,
    );
    const refs = new RefRegistry();
    const a = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const f = a.forms[0]!;
    expect(f.fields.map((x) => [refs.get(x.ref), x.role])).toEqual([
      [root.getElementById("e"), "email"],
      [root.getElementById("pw"), "current_password"],
    ]);
  });
});
