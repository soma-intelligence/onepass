// Security review M3: OnePass never submits a form the browser would send to another site.
import { afterEach, describe, expect, it } from "vitest";
import { submitTargetAllowed } from "../../src/content/submit";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { setPage, start, type Started } from "./harness";

// The origin the harness pins (relative actions resolve against the jsdom document URL).
const ORIGIN = "https://atlas-cloud.test";

let s: Started | null = null;
afterEach(() => {
  s?.cs.stop();
  s = null;
});

function loginForm(st: Started): FormInfo {
  const all = st.ext.ofType("page_analysis");
  const a = all[all.length - 1]!.analysis as PageAnalysis;
  return a.forms.find((f) => f.kind === "login")!;
}

/** Starts on `html`, fills the login form, asks for its submit; the clicks and submissions the page saw. */
function submitOf(html: string): { reply: unknown; clicks: number; submits: number; filled: unknown } {
  setPage(html);
  s = start();
  const f = loginForm(s);
  let clicks = 0;
  let submits = 0;
  document.addEventListener("click", (e) => {
    if ((e.target as Element).matches("button, input[type=submit]")) clicks++;
    e.preventDefault();
  }, true);
  document.addEventListener("submit", (e) => {
    submits++;
    e.preventDefault();
  }, true);
  const filled = s.ext.deliver({ type: "fill", origin: ORIGIN, formRef: f.ref, values: { username: "ada", current_password: "pw" } });
  const reply = s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref, planned: true });
  return { reply, clicks, submits, filled };
}

const FIELDS = `<input name="u" autocomplete="username"><input type="password" name="p" autocomplete="current-password">`;

describe("submit target (M3)", () => {
  it("submits a form whose action stays on the page's site", () => {
    const r = submitOf(`<form id="f" action="/login">${FIELDS}<button id="go" type="submit">Sign in</button></form>`);
    expect(r.reply).toEqual({ ok: true });
    expect(r.clicks).toBe(1);
  });

  it("fills but does not submit a form posting to another site", () => {
    const r = submitOf(`<form id="f" action="https://evil.test/c">${FIELDS}<button id="go" type="submit">Sign in</button></form>`);
    expect((r.filled as { ok: boolean }).ok).toBe(true);
    expect(r.reply).toEqual({ ok: false });
    expect(r.clicks).toBe(0);
    expect(r.submits).toBe(0);
  });

  it("does not submit when the button's formaction points to another site", () => {
    const r = submitOf(`<form id="f" action="/login">${FIELDS}<button id="go" type="submit" formaction="https://evil.test/c">Sign in</button></form>`);
    expect(r.reply).toEqual({ ok: false });
    expect(r.clicks).toBe(0);
  });

  it("does not submit when another submit control of the form (Enter's default button) leaves the site", () => {
    const r = submitOf(
      `<form id="f" action="/login">${FIELDS}<input type="submit" value="x" formaction="//evil.test/c" style="display:none"><button id="go" type="submit">Sign in</button></form>`,
    );
    expect(r.reply).toEqual({ ok: false });
  });

  it("is not fooled by a control named action (DOM clobbering)", () => {
    const r = submitOf(
      `<form id="f" action="https://evil.test/c"><input type="hidden" name="action" value="/login">${FIELDS}<button id="go" type="submit">Sign in</button></form>`,
    );
    expect(r.reply).toEqual({ ok: false });
  });

  it("resolves a whitespace action against an injected <base href>, as the browser does (review E1)", () => {
    const r = submitOf(
      `<base href="https://evil.test/steal"><form id="f" action=" ">${FIELDS}<button id="go" type="submit">Sign in</button></form>`,
    );
    expect(r.reply).toEqual({ ok: false });
    expect(r.clicks).toBe(0);
    document.querySelector("base")?.remove();
  });

  it("resolves a whitespace formaction against an injected <base href> too", () => {
    const r = submitOf(
      `<base href="https://evil.test/steal"><form id="f">${FIELDS}<button id="go" type="submit" formaction="  ">Sign in</button></form>`,
    );
    expect(r.reply).toEqual({ ok: false });
    document.querySelector("base")?.remove();
  });

  it("a loopback http page: only its exact origin (another port is another server)", () => {
    const local = "http://localhost:3000/login";
    expect(submitTargetAllowed(null, local, local)).toBe(true);
    expect(submitTargetAllowed("/session", local, local)).toBe(true);
    expect(submitTargetAllowed("http://localhost:3000/session", local, local)).toBe(true);
    // Another port, another loopback name, https there, a public host.
    expect(submitTargetAllowed("http://localhost:4000/steal", local, local)).toBe(false);
    expect(submitTargetAllowed("//localhost:4000/steal", local, local)).toBe(false);
    expect(submitTargetAllowed("http://127.0.0.1:3000/steal", local, local)).toBe(false);
    expect(submitTargetAllowed("https://localhost:3000/session", local, local)).toBe(false);
    expect(submitTargetAllowed("https://evil.test/steal", local, local)).toBe(false);
    // A `<base href>` on another port moves relative targets there.
    expect(submitTargetAllowed("session", "http://localhost:4000/", local)).toBe(false);
    const ip = "http://127.0.0.1:8080/";
    expect(submitTargetAllowed("http://127.0.0.1:8081/", ip, ip)).toBe(false);
    expect(submitTargetAllowed("http://127.0.0.1:8080/x", ip, ip)).toBe(true);
  });

  it("resolves targets: same site, subdomain, downgrade, schemes", () => {
    const page = "https://www.atlas-cloud.test/login";
    expect(submitTargetAllowed(null, page, page)).toBe(true);
    expect(submitTargetAllowed("", "https://evil.test/", page)).toBe(true);
    expect(submitTargetAllowed("  ", page, page)).toBe(true);
    expect(submitTargetAllowed("  ", "https://evil.test/steal", page)).toBe(false);
    expect(submitTargetAllowed("/session", page, page)).toBe(true);
    expect(submitTargetAllowed("https://auth.atlas-cloud.test/s", page, page)).toBe(true);
    expect(submitTargetAllowed("javascript:void 0", page, page)).toBe(true);
    expect(submitTargetAllowed("https://evil.test/c", page, page)).toBe(false);
    expect(submitTargetAllowed("//evil.test/c", page, page)).toBe(false);
    expect(submitTargetAllowed("http://www.atlas-cloud.test/s", page, page)).toBe(false);
    expect(submitTargetAllowed("mailto:x@evil.test", page, page)).toBe(false);
    expect(submitTargetAllowed("data:text/html,x", page, page)).toBe(false);
    // A page base elsewhere (<base href>): the browser posts there, so it is judged there.
    expect(submitTargetAllowed("/c", "https://evil.test/", page)).toBe(false);
  });
});
