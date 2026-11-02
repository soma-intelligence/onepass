import { beforeEach, describe, expect, it } from "vitest";
import { createProbe, installGuard, prune, type TruthObservation } from "../../bench/probe";
import { testGeometry } from "../detect/helpers";

const ORIGIN = "https://shop.example";

const LOGIN = `
  <h1>Sign in</h1>
  <form id="f" action="/session" method="post">
    <label for="u">Email or username</label><input id="u" name="login" autocomplete="username">
    <label for="p">Password</label><input id="p" type="password" name="password" autocomplete="current-password">
    <input id="trap" name="website" tabindex="-1" style="display:none">
    <button type="submit">Sign in</button>
  </form>
  <form id="s" role="search"><input id="q" type="search" name="q" placeholder="Search"></form>`;

describe("bench probe", () => {
  beforeEach(() => {
    document.body.innerHTML = LOGIN;
  });

  it("analyze returns the context, the detected role and the features of each truth selector", () => {
    const probe = createProbe({ geometry: testGeometry, origin: ORIGIN });
    const a = probe.analyze(["#u", "#p", "#missing", "##bad"]);
    expect(a.context.origin).toBe(ORIGIN);
    expect(a.context.forms.length).toBeGreaterThan(0);
    const [u, p, missing, bad] = a.truth as [TruthObservation, TruthObservation, TruthObservation, TruthObservation];
    expect(u).toMatchObject({ selector: "#u", found: true, detected: "username" });
    expect(u.features?.name).toBe("login");
    expect(p.detected).toBe("current_password");
    expect(missing).toMatchObject({ found: false, detected: null, features: null });
    expect(bad.found).toBe(false);
  });

  it("fill writes the plan's groups through the extension filler, readback gives booleans only", async () => {
    const probe = createProbe({ geometry: testGeometry, origin: ORIGIN });
    const a = probe.analyze(["#u", "#p"]);
    const form = a.context.forms.find((f) => f.fields.some((x) => x.role === "current_password"))!;
    const groups = [{ form_ref: form.form_ref, fields: form.fields.filter((f) => f.role !== null).map((f) => [f.field_ref, f.role!] as [string, string]) }];
    const written = await probe.fill(groups, { username: "bench.user", email: "bench.user@example.invalid", current_password: "Fake-Bench-Pass-1" });
    expect(written).toBeGreaterThanOrEqual(2);
    const r = probe.readback([
      { selector: "#u", expect: ["bench.user", "bench.user@example.invalid"] },
      { selector: "#p", expect: ["Fake-Bench-Pass-1"] },
      { selector: "#q", expect: [] },
    ]);
    expect(r).toEqual([
      { selector: "#u", found: true, filled: true, expected_value: true },
      { selector: "#p", found: true, filled: true, expected_value: true },
      { selector: "#q", found: true, filled: false, expected_value: false },
    ]);
    expect(JSON.stringify(r)).not.toContain("Fake-Bench");
  });

  it("fill ignores a group whose fields are not in the plan's form", async () => {
    const probe = createProbe({ geometry: testGeometry, origin: ORIGIN });
    probe.analyze(["#u"]);
    expect(await probe.fill([{ form_ref: "nope", fields: [] }], { username: "x" })).toBe(0);
  });

  it("survey lists every field with a selector that finds it alone", () => {
    const probe = createProbe({ geometry: testGeometry, origin: ORIGIN });
    const fields = probe.survey();
    const sels = fields.map((f) => f.selector);
    expect(sels).toContain("#u");
    expect(sels).toContain("#p");
    for (const f of fields) expect(document.querySelectorAll(f.selector)).toHaveLength(1);
    expect(fields.find((f) => f.selector === "#p")?.detected).toBe("current_password");
    document.body.innerHTML = `<div><form><input name="a"><input name="a"></form></div>`;
    const two = createProbe({ geometry: testGeometry, origin: ORIGIN }).survey().map((f) => f.selector);
    expect(new Set(two).size).toBe(2);
    for (const s of two) expect(document.querySelectorAll(s)).toHaveLength(1);
  });

  it("the guard cancels submit events and form.submit()", () => {
    installGuard(window);
    const f = document.getElementById("f") as HTMLFormElement;
    let reached = false;
    document.addEventListener("submit", (e) => { reached = !e.defaultPrevented; });
    const ev = new Event("submit", { bubbles: true, cancelable: true });
    f.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(true);
    expect(reached).toBe(false);
    expect(() => f.submit()).not.toThrow();
    expect(() => f.requestSubmit()).not.toThrow();
  });
});

describe("prune", () => {
  it("drops scripts, styles, media, comments, prose, numbers and addresses; keeps the form", () => {
    document.head.innerHTML = `<title>Sign in to Shop</title><style>.x{}</style><script>evil()</script>`;
    document.body.innerHTML = `
      <!-- secret comment -->
      <script>track()</script><img src="a.png"><iframe src="https://ads.example"></iframe>
      <p>${"Long editorial paragraph that should never be committed to a public repository. ".repeat(3)}</p>
      <p>Call 415 555 0123</p><p>help@shop.example</p>
      <div hidden><input id="gone" name="hidden-section"></div>
      <form action="/session" onsubmit="x()" data-track="1">
        <label for="u" class="lbl">Email</label><input id="u" name="email" type="email" autocomplete="email" value="prefill@x.example" onfocus="y()" style="color:red">
        <input type="hidden" name="csrf" value="abcdef0123456789abcdef0123456789">
        <button type="submit">Continue</button>
      </form>`;
    const html = prune(document, { geometry: testGeometry, visible: (el) => !el.closest("[hidden]") });
    expect(html).toContain('<form action="/session">');
    expect(html).toContain('id="u"');
    expect(html).toContain('autocomplete="email"');
    expect(html).toContain("Continue");
    expect(html).toContain("<title>Sign in to Shop</title>");
    for (const bad of ["<script", "<style", "<img", "<iframe", "secret comment", "editorial", "415", "help@", "onsubmit", "onfocus", "data-track", "style=", "prefill@", "abcdef0123", "gone"]) {
      expect(html, bad).not.toContain(bad);
    }
    expect(html).toMatch(/^<!doctype html>/);
  });
});
