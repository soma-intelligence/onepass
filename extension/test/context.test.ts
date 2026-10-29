import { beforeEach, describe, expect, it } from "vitest";
import {
  buildPageContext,
  buttonClass,
  confidenceOf,
  findTypedUsername,
  hashTypedUsername,
  withTypedUsernameHash,
} from "../src/content/context";
import { analyzeDocument } from "../src/content/detect/forms";
import { RefRegistry } from "../src/content/detect/refs";
import { createFiller } from "../src/content/filler";
import type { PageContext } from "../src/shared/messages";
import { byId, testGeometry } from "./detect/helpers";

const ORIGIN = "https://atlas-cloud.test";
const ORIGINS = { origin: ORIGIN, topOrigin: ORIGIN, frame: "top" } as const;
const SITE = `${ORIGIN}/login`;

function page(html: string): { ctx: PageContext; refs: RefRegistry } {
  document.body.innerHTML = html;
  const refs = new RefRegistry();
  const analysis = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  return { ctx: buildPageContext(document, refs, analysis, ORIGINS, testGeometry), refs };
}

function button(label: string): HTMLButtonElement {
  const b = document.createElement("button");
  b.textContent = label;
  return b;
}

const LOGIN = `
  <form id="login">
    <input id="u" type="text" name="username" autocomplete="username">
    <input id="p" type="password" name="password" autocomplete="current-password">
    <button id="go" type="submit">Sign in</button>
  </form>`;

beforeEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
});

describe("buildPageContext", () => {
  it("login_page_context", () => {
    const { ctx, refs } = page(LOGIN);
    expect(ctx.origin).toBe(ORIGIN);
    expect(ctx.top_origin).toBe(ORIGIN);
    expect(ctx.frame_kind).toBe("top");
    expect(ctx.typed_username_hash).toBeNull();
    expect(ctx.forms).toHaveLength(1);
    const f = ctx.forms[0]!;
    expect(refs.get(f.form_ref)).toBe(byId("login"));
    expect(f.intent_hints).toEqual({
      kind: "login",
      signup_words: false,
      reset_words: false,
      checkout_words: false,
      ignore: false,
    });
    expect(f.step_index).toBeNull();
    expect(f.fields.map((x) => x.role)).toEqual(["username", "current_password"]);
    for (const x of f.fields) {
      expect(x.visible).toBe(true);
      expect(x.prefilled).toBe("empty");
    }
    expect(f.buttons).toHaveLength(1);
    expect(refs.get(f.buttons[0]!.button_ref)).toBe(byId("go"));
    expect(f.buttons[0]!.class).toBe("submit");
  });

  it("child frame keeps its own origin; a top frame is its own top", () => {
    document.body.innerHTML = LOGIN;
    const refs = new RefRegistry();
    const analysis = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const top = buildPageContext(
      document,
      refs,
      analysis,
      { origin: ORIGIN, topOrigin: "https://other.test", frame: "top" },
      testGeometry,
    );
    expect(top.top_origin).toBe(ORIGIN);
    const child = buildPageContext(
      document,
      refs,
      analysis,
      { origin: ORIGIN, topOrigin: ORIGIN, frame: "same_origin_child" },
      testGeometry,
    );
    expect(child.frame_kind).toBe("same_origin_child");
    expect(child.origin).toBe(child.top_origin);
  });

  it("search_form_has_ignore_hint", () => {
    const { ctx } = page(`
      <form id="s" role="search" action="/search">
        <input type="text" name="q" autocomplete="username">
        <button type="submit">Continue</button>
      </form>`);
    expect(ctx.forms).toHaveLength(1);
    expect(ctx.forms[0]!.intent_hints.ignore).toBe(true);
  });

  it("newsletter_only_form_has_ignore_hint", () => {
    const { ctx } = page(`
      <form id="nl" action="/subscribe">
        <h2>Join our newsletter</h2>
        <input type="text" name="first" autocomplete="given-name">
        <input type="email" name="email" autocomplete="email">
        <button type="submit">Subscribe</button>
      </form>`);
    expect(ctx.forms).toHaveLength(1);
    expect(ctx.forms[0]!.intent_hints.ignore).toBe(true);
    const login = page(LOGIN).ctx;
    expect(login.forms[0]!.intent_hints.ignore).toBe(false);
  });

  it("signup and checkout words come from the form and its headings", () => {
    const signup = page(`
      <form id="f"><h2>Create your account</h2>
        <input type="email" autocomplete="email" name="email">
        <input type="password" autocomplete="new-password" name="pw">
        <input type="password" autocomplete="new-password" name="pw2">
        <button type="submit">Create account</button></form>`).ctx;
    expect(signup.forms[0]!.intent_hints.signup_words).toBe(true);
    expect(signup.forms[0]!.buttons[0]!.class).toBe("create");
    const pay = page(`
      <form id="f"><h2>Payment</h2>
        <input name="n" autocomplete="cc-number"><input name="c" autocomplete="cc-csc">
        <button type="submit">Pay</button></form>`).ctx;
    expect(pay.forms[0]!.intent_hints.checkout_words).toBe(true);
    expect(pay.forms[0]!.buttons[0]!.class).toBe("pay");
  });

  it("typed_username_marked_typed", () => {
    const { ctx, refs } = page(LOGIN);
    expect(ctx.forms[0]!.fields[0]!.prefilled).toBe("empty");
    (byId("u") as HTMLInputElement).value = "tom@example.com";
    (byId("p") as HTMLInputElement).value = "hunter2hunter2";
    const analysis = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const again = buildPageContext(document, refs, analysis, ORIGINS, testGeometry);
    expect(again.forms[0]!.fields.map((x) => x.prefilled)).toEqual(["typed", "typed"]);
    expect(findTypedUsername(analysis, refs)).toBe("tom@example.com");
    // No value ever travels in the context.
    const json = JSON.stringify(again);
    expect(json).not.toContain("tom@example.com");
    expect(json).not.toContain("hunter2");
  });

  it("onepass_filled_field_marked_ours", () => {
    document.body.innerHTML = LOGIN;
    const refs = new RefRegistry();
    const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const filler = createFiller({
      refs,
      geometry: testGeometry,
      analyze,
      resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null,
    });
    const form = analyze().forms[0]!;
    expect(filler.fillForm(form.ref, { username: "tom@example.com" })).toBe(1);
    const analysis = analyze();
    const ctx = buildPageContext(document, refs, analysis, ORIGINS, testGeometry);
    expect(ctx.forms[0]!.fields.map((x) => x.prefilled)).toEqual(["ours", "empty"]);
    // What we wrote is not "typed": nothing to hash.
    expect(findTypedUsername(analysis, refs)).toBeUndefined();
    // Edited afterwards, it is the user's.
    (byId("u") as HTMLInputElement).value = "someone@else.test";
    const edited = buildPageContext(document, refs, analyze(), ORIGINS, testGeometry);
    expect(edited.forms[0]!.fields[0]!.prefilled).toBe("typed");
  });

  it("context_respects_bounds", () => {
    const forms = Array.from({ length: 33 }, (_, i) => LOGIN.replace('id="login"', `id="f${i}"`).replace(/ id="(u|p|go)"/g, "")).join("");
    const { ctx, refs } = page(forms);
    expect(ctx.forms).toHaveLength(32);
    expect(ctx.forms.map((f) => (refs.get(f.form_ref) as HTMLElement).id)).toEqual(
      Array.from({ length: 32 }, (_, i) => `f${i}`),
    );
  });

  it("caps fields and buttons of one form", () => {
    const fields = Array.from({ length: 70 }, (_, i) => `<input type="email" autocomplete="email" name="e${i}">`).join("");
    const buttons = Array.from({ length: 40 }, () => `<button type="submit">Pay</button>`).join("");
    const { ctx, refs } = page(`<form>${fields}<input type="password" autocomplete="current-password">${buttons}</form>`);
    const f0 = ctx.forms[0]!;
    expect(f0.fields).toHaveLength(64);
    const firstIds = Array.from(document.querySelectorAll("form input")).slice(0, 64);
    expect(f0.fields.map((x) => refs.get(x.field_ref))).toEqual(firstIds);
    expect(ctx.forms[0]!.buttons).toHaveLength(32);
    const all = ctx.forms.flatMap((f) => f.fields.map((x) => x.field_ref));
    expect(new Set(all).size).toBe(all.length);
  });

  it("the cap keeps the submit and every pay or create button, whatever their place", () => {
    const others = Array.from({ length: 40 }, (_, i) => `<button type="button">Option ${i}</button>`).join("");
    const { ctx, refs } = page(`<form id="login">
      <input type="text" name="username" autocomplete="username">
      <input type="password" autocomplete="current-password">
      ${others}<button id="pay" type="button">Pay now</button><button id="new" type="button">Create account</button>
      <button id="go" type="submit">Sign in</button></form>`);
    const buttons = ctx.forms[0]!.buttons;
    expect(buttons).toHaveLength(32);
    expect(refs.get(buttons[0]!.button_ref)).toBe(byId("go"));
    expect(buttons[0]!.class).toBe("submit");
    expect(buttons.slice(1, 3).map((b) => refs.get(b.button_ref))).toEqual([byId("pay"), byId("new")]);
    expect(buttons.slice(1, 3).map((b) => b.class)).toEqual(["pay", "create"]);
  });
});

describe("buttonClass", () => {
  it("pay_button_class", () => {
    for (const label of ["Pay", "Payer", "Place order"]) expect(buttonClass(button(label))).toBe("pay");
  });

  it("create_button_class", () => {
    for (const label of ["Create account", "Créer un compte"]) expect(buttonClass(button(label))).toBe("create");
  });

  it("next, submit and other", () => {
    expect(buttonClass(button("Continue"))).toBe("next");
    expect(buttonClass(button("Sign in"))).toBe("submit");
    const s = document.createElement("input");
    s.type = "submit";
    s.value = "Go";
    expect(buttonClass(s)).toBe("submit");
    const cancel = button("Cancel");
    cancel.type = "button";
    expect(buttonClass(cancel)).toBe("other");
  });
});

describe("confidenceOf", () => {
  it("confidence_in_unit_range", () => {
    for (const s of [-5, 0, 0.1, 2.5, 6, 100, 1e9, Number.NaN, Number.POSITIVE_INFINITY]) {
      const c = confidenceOf(s);
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThanOrEqual(1);
    }
    expect(confidenceOf(0)).toBe(0);
    expect(confidenceOf(100)).toBe(1);
    expect(confidenceOf(3)).toBeLessThan(confidenceOf(6));
    const { ctx } = page(LOGIN);
    for (const x of ctx.forms[0]!.fields) {
      expect(x.confidence).toBeGreaterThan(0);
      expect(x.confidence).toBeLessThanOrEqual(1);
    }
  });
});

describe("hashTypedUsername", () => {
  const ZERO_SALT = "00".repeat(32);

  it("hash_matches_rust_vector", async () => {
    // Same vector as `username_hash` in onepass-bridge tests/service.rs:
    // SHA-256(salt || lowercase(trim(username))).
    expect(await hashTypedUsername(ZERO_SALT, "Tom@Example.com ")).toBe(
      "a2d55ed8b5a8ec8839231c0db36ebe5fd98d0bc6e8268b889a44f408e72c0d35",
    );
  });

  it("is undefined for an empty value", async () => {
    expect(await hashTypedUsername(ZERO_SALT, "")).toBeUndefined();
    expect(await hashTypedUsername(ZERO_SALT, "   ")).toBeUndefined();
  });

  it("goes on the wire as 32 numbers, like serde's [u8; 32]", async () => {
    const { ctx } = page(LOGIN);
    const out = await withTypedUsernameHash(ctx, ZERO_SALT, "Tom@Example.com ");
    expect(out.typed_username_hash).toHaveLength(32);
    expect(out.typed_username_hash?.slice(0, 4)).toEqual([0xa2, 0xd5, 0x5e, 0xd8]);
    // The exact JSON that `typed_username_hash_json_matches_the_extension_shape`
    // (onepass-core tests/fill_plan.rs) reads back as a `[u8; 32]`.
    expect(JSON.stringify(out.typed_username_hash)).toBe("[162,213,94,216,181,168,236,136,57,35,28,13,179,110,190,95,217,141,11,198,232,38,139,136,154,68,244,8,231,44,13,53]");
    expect(ctx.typed_username_hash).toBeNull();
    expect((await withTypedUsernameHash(ctx, ZERO_SALT, "")).typed_username_hash).toBeNull();
  });
});

describe("round 1 fixes", () => {
  it("confidence by signal: name-only logins clear 0.6, type-only do not", () => {
    const { ctx } = page(`<form>
      <input id="a" type="text" name="username">
      <input id="b" type="password" name="password">
      <button type="submit">Sign in</button></form>`);
    for (const x of ctx.forms[0]!.fields) expect(x.confidence).toBeGreaterThanOrEqual(0.6);
    const bare = page(`<form><input type="password"><input type="text" autocomplete="username"><button type="submit">Sign in</button></form>`).ctx;
    const pw = bare.forms[0]!.fields.find((x) => x.role === "current_password")!;
    expect(pw.confidence).toBeLessThan(0.6);
    expect(confidenceOf(Number.NaN)).toBe(0);
    expect(confidenceOf(3, 3)).toBeLessThanOrEqual(0.5);
  });

  it("an untouched select is empty, a changed one is typed", () => {
    const html = `<form id="f">
      <input autocomplete="cc-number" name="n">
      <select id="m" autocomplete="cc-exp-month"><option value="">Month</option><option value="01">01</option><option value="02">02</option></select>
      <select id="y" autocomplete="cc-exp-year"><option value="2030">2030</option><option value="2031" selected>2031</option></select>
      <button type="submit">Pay</button></form>`;
    const { ctx, refs } = page(html);
    const state = (id: string) => ctx.forms[0]!.fields.find((x) => (refs.get(x.field_ref) as HTMLElement).id === id)!.prefilled;
    expect(state("m")).toBe("empty");
    expect(state("y")).toBe("empty");
    (byId("m") as HTMLSelectElement).value = "02";
    const analysis = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const again = buildPageContext(document, refs, analysis, ORIGINS, testGeometry);
    const m = again.forms[0]!.fields.find((x) => (refs.get(x.field_ref) as HTMLElement).id === "m")!;
    expect(m.prefilled).toBe("typed");
  });

  it("buttons outside the form (form attribute, submitRef) are included, page words read in a multi-form page", () => {
    const { ctx, refs } = page(`
      <h1>Create your account</h1>
      <form id="su"><input type="email" autocomplete="email"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form>
      <button id="out" type="submit" form="su">Continue</button>
      <form id="other"><input type="text" autocomplete="username"><input type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>`);
    const su = ctx.forms.find((f) => (refs.get(f.form_ref) as HTMLElement).id === "su")!;
    expect(su.buttons.map((b) => (refs.get(b.button_ref) as HTMLElement).id)).toContain("out");
    expect(su.intent_hints.signup_words).toBe(true);
    const refsAll = su.buttons.map((b) => b.button_ref);
    expect(new Set(refsAll).size).toBe(refsAll.length);
  });

  it("orphan group includes its submitRef", () => {
    const { ctx, refs } = page(`<div id="g"><input type="email" autocomplete="email"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></div>
      <button id="go" type="button">Create account</button>`);
    expect(ctx.forms).toHaveLength(1);
    // Whatever the detector picked as submit is listed.
    const analysis = analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
    const sub = analysis.forms[0]!.submitRef;
    if (sub !== undefined) expect(ctx.forms[0]!.buttons.map((b) => b.button_ref)).toContain(sub);
  });

  it("wider create words", () => {
    for (const l of ["Get started", "Start free trial", "Create", "Créer"]) expect(buttonClass(button(l))).toBe("create");
  });

  it("hash trim is Rust char::is_whitespace", async () => {
    const z = "00".repeat(32);
    const plain = await hashTypedUsername(z, "tom@x.com");
    expect(await hashTypedUsername(z, "tom@x.com\u0085")).toBe(plain);
    expect(await hashTypedUsername(z, "\uFEFFtom@x.com")).not.toBe(plain);
  });

  it("malformed salt gives undefined", async () => {
    expect(await hashTypedUsername("zz", "tom")).toBeUndefined();
    expect(await hashTypedUsername("00".repeat(31), "tom")).toBeUndefined();
    expect(await hashTypedUsername("00".repeat(33), "tom")).toBeUndefined();
  });

  it("a security code read as a one-time code keeps a real confidence", () => {
    const { ctx } = page(`<form><input type="text" name="security code" id="c" autocomplete="off"><button type="submit">Continue</button></form>`);
    const f = ctx.forms[0]?.fields.find((x) => x.role === "otp");
    if (f) expect(f.confidence).toBeGreaterThanOrEqual(0.6);
    expect(f).toBeDefined();
  });
});
