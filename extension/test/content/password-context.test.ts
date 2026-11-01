import { afterEach, describe, expect, it } from "vitest";
import { collectPasswordContext, patternMatches } from "../../src/content/password-context";
import type { PageAnalysis } from "../../src/shared/messages";
import { EXT_ID, setPage, start, type Started } from "./harness";

function page(html: string): HTMLFormElement {
  document.body.innerHTML = html;
  return document.querySelector("form") as HTMLFormElement;
}

const field = (id: string) => document.getElementById(id) as HTMLInputElement;

describe("collectPasswordContext", () => {
  it("reads_min_max_rules", () => {
    const form = page(`
      <form>
        <input id="pw" type="password" passwordrules="minlength: 10; required: upper;" minlength="10" maxlength="40">
        <input id="cf" type="password" passwordrules="max-consecutive: 2;" minlength="12" maxlength="30">
        <input id="other" type="password" passwordrules="ignored: yes;" maxlength="5">
      </form>`);
    const { context, pattern } = collectPasswordContext(form, [field("pw"), field("cf")]);
    // Both rule strings, the largest min, the smallest max; never a field outside the list.
    expect(context.rules).toEqual(["minlength: 10; required: upper;", "max-consecutive: 2;"]);
    expect(context.min_length).toBe(12);
    expect(context.max_length).toBe(30);
    expect(pattern).toBeNull();
  });

  it("ignores absent lengths and page rules the bridge would refuse", () => {
    const long = "a".repeat(1025);
    // 342 three-byte chars: 1026 UTF-8 bytes, under 1024 UTF-16 units.
    const wide = "€".repeat(342);
    const attrs = Array.from({ length: 10 }, (_, i) => `<input id="p${i}" type="password" passwordrules="r${i};">`).join("");
    const form = page(`<form><input id="a" type="password" passwordrules="${long}"><input id="b" type="password" passwordrules="${wide}">${attrs}</form>`);
    const fields = [field("a"), field("b"), ...Array.from({ length: 10 }, (_, i) => field(`p${i}`))];
    const { context } = collectPasswordContext(form, fields);
    expect(context.rules).toEqual(["r0;", "r1;", "r2;", "r3;", "r4;", "r5;", "r6;", "r7;"]);
    expect(context.min_length).toBeUndefined();
    expect(context.max_length).toBeUndefined();
    expect(context.hint_text).toBeUndefined();
  });

  it("aria_describedby_first", () => {
    const form = page(`
      <p id="far">Unrelated text far away.</p>
      <form>
        <label>New password <input id="pw" type="password" aria-describedby="help help2"></label>
        <span>Wrapper sibling hint.</span>
        <div id="help">  At least 12   characters. </div>
        <div id="help2">One digit.</div>
      </form>`);
    const { context } = collectPasswordContext(form, [field("pw")]);
    // aria-describedby text first (each once), then the siblings after the label wrapper.
    expect(context.hint_text).toBe("At least 12 characters. One digit. Wrapper sibling hint.");
  });

  it("reads following siblings within three, inside the form only", () => {
    const form = page(`
      <form>
        <div>
          <input id="pw" type="password">
          <small>8 to 20 characters.</small>
          <input type="text" value="typed-secret">
          <em>No spaces.</em>
          <b>Too far.</b>
        </div>
      </form>
      <p>Outside the form.</p>`);
    const { context } = collectPasswordContext(form, [field("pw")]);
    expect(context.hint_text).toBe("8 to 20 characters. No spaces.");
    expect(JSON.stringify(context)).not.toContain("typed-secret");
  });

  it("never reads a value typed in the page", () => {
    const form = page(`<form><input id="pw" type="password" aria-describedby="h"><p id="h">Hint</p></form>`);
    field("pw").value = "Typed-Secret-1!";
    expect(JSON.stringify(collectPasswordContext(form, [field("pw")]))).not.toContain("Typed-Secret-1!");
  });

  it("hint_capped_600", () => {
    const pieces = Array.from({ length: 6 }, (_, i) => `<div id="h${i}">${String(i).repeat(300)}</div>`).join("");
    const ids = Array.from({ length: 6 }, (_, i) => `h${i}`).join(" ");
    const form = page(`<form><input id="pw" type="password" aria-describedby="${ids}">${pieces}</form>`);
    const { context } = collectPasswordContext(form, [field("pw")]);
    const hint = context.hint_text ?? "";
    expect(hint.length).toBe(600);
    // Each piece cut to 200 chars.
    expect(hint.startsWith(`${"0".repeat(200)} ${"1".repeat(200)} `)).toBe(true);
  });

  it("pattern_over_512_null", () => {
    const form = page(`<form><input id="a" type="password"><input id="b" type="password" pattern="[a-z0-9]+"></form>`);
    // The first field with a pattern.
    expect(collectPasswordContext(form, [field("a"), field("b")]).pattern).toBe("[a-z0-9]+");
    field("b").setAttribute("pattern", "a".repeat(513));
    expect(collectPasswordContext(form, [field("a"), field("b")]).pattern).toBeNull();
    field("b").setAttribute("pattern", "a".repeat(512));
    expect(collectPasswordContext(form, [field("a"), field("b")]).pattern).toBe("a".repeat(512));
  });

  it("never reads editable text", () => {
    const form = page(`<form><input id="pw" type="password" aria-describedby="h"><div id="h" contenteditable="true">typed-note</div>
      <p>Real hint.</p><div><span contenteditable>typed-two</span></div></form>`);
    const { context } = collectPasswordContext(form, [field("pw")]);
    expect(context.hint_text).toBe("Real hint.");
  });

  it("without a field list, reads the form's password inputs", () => {
    const form = page(`<form><input type="text" maxlength="3"><input type="password" maxlength="24"></form>`);
    expect(collectPasswordContext(form).context).toEqual({ rules: [], max_length: 24 });
  });
});

describe("patternMatches (in the page's tab)", () => {
  it("tests the whole value with the v flag", () => {
    expect(patternMatches("[a-z]+", "abc")).toBe(true);
    expect(patternMatches("[a-z]+", "abc1")).toBe(false);
    // Alternation is anchored as a whole.
    expect(patternMatches("a|b", "ab")).toBe(false);
  });

  it("accepts when there is nothing to apply", () => {
    expect(patternMatches(null, "x")).toBe(true);
    // Compile errors: a lone `-` in a class under the v flag, an open group.
    expect(patternMatches("[a-z-]", "!")).toBe(true);
    expect(patternMatches("(", "!")).toBe(true);
    // Over 512 chars.
    expect(patternMatches("a".repeat(513), "b")).toBe(true);
    expect(patternMatches("a".repeat(512), "b")).toBe(false);
  });
});

describe("password_context message", () => {
  const ORIGIN = "https://atlas-cloud.test";
  let s: Started | null = null;
  afterEach(() => s?.cs.stop());

  const SIGNUP = `<form id="f">
      <label for="e">Email</label><input id="e" type="email" autocomplete="email">
      <label for="n">New password</label><input id="n" type="password" autocomplete="new-password" maxlength="20" pattern="[A-Za-z0-9]+" aria-describedby="h">
      <p id="h">8 to 20 letters or digits.</p>
      <label for="c">Confirm</label><input id="c" type="password" autocomplete="new-password" minlength="8">
      <button type="submit">Create account</button></form>`;

  function ask(st: Started, message: unknown, sender: unknown = { id: EXT_ID }): unknown {
    let out: unknown;
    for (const l of st.ext.listeners) l(message as never, sender as never, (x) => (out = x));
    return out;
  }

  function formRef(st: Started): string {
    const all = st.ext.ofType("page_analysis");
    const f = (all[all.length - 1]!.analysis as PageAnalysis).forms[0];
    if (!f) throw new Error("no form");
    return f.ref;
  }

  it("replies the rules of the form's new password fields", () => {
    setPage(SIGNUP);
    s = start();
    (document.getElementById("n") as HTMLInputElement).value = "Typed-Secret-1";
    const out = ask(s, { type: "password_context", origin: ORIGIN, formRef: formRef(s) });
    expect(out).toEqual({
      ok: true,
      context: { rules: [], min_length: 8, max_length: 20, hint_text: "8 to 20 letters or digits." },
      has_pattern: true,
    });
    expect(JSON.stringify(out)).not.toContain("Typed-Secret-1");
  });

  it("pattern_check answers for the field's own pattern", () => {
    setPage(SIGNUP);
    s = start();
    const ref = formRef(s);
    expect(ask(s, { type: "pattern_check", origin: ORIGIN, formRef: ref, candidate: "Abcdef12" })).toEqual({ ok: true, matches: true });
    expect(ask(s, { type: "pattern_check", origin: ORIGIN, formRef: ref, candidate: "Abc-def!12" })).toEqual({ ok: true, matches: false });
    // Same gates as the context: pinned origin, our extension, a known form.
    expect(ask(s, { type: "pattern_check", origin: "https://evil.test", formRef: ref, candidate: "x" })).toEqual({ ok: false });
    expect(ask(s, { type: "pattern_check", origin: ORIGIN, formRef: ref, candidate: "x" }, { id: "other-extension" })).toBeUndefined();
    expect(ask(s, { type: "pattern_check", origin: ORIGIN, formRef: "nope", candidate: "x" })).toEqual({ ok: false });
  });

  it("only for our extension and the pinned origin", () => {
    setPage(SIGNUP);
    s = start();
    const ref = formRef(s);
    expect(ask(s, { type: "password_context", origin: "https://evil.test", formRef: ref })).toEqual({ ok: false });
    expect(ask(s, { type: "password_context", origin: ORIGIN, formRef: ref }, { id: "other-extension" })).toBeUndefined();
    expect(ask(s, { type: "password_context", origin: ORIGIN, formRef: "nope" })).toEqual({ ok: false });
  });
});
