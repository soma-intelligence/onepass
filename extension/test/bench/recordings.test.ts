// Regressions from the real-site bench (docs/lab/2026-11-02-real-site-bench-and-retrain.md): the
// recorded pages of bench/recordings, read by the content script's own detection in jsdom, against
// the hand-written truth of bench/sites.json. The Rust planner side of the same pages runs in the
// offline bench (`onepass-bench offline --check bench/expected-offline.json`).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createProbe } from "../../bench/probe";
import { buttonClass } from "../../src/content/context";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import type { FieldRole, PageContext } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const BENCH = join(__dirname, "..", "..", "..", "bench");

interface TruthField {
  selector: string;
  role: string;
  accept?: string[];
}
interface Site {
  id: string;
  url: string;
  kind: string;
  fields: TruthField[];
}

const SITES: Site[] = JSON.parse(readFileSync(join(BENCH, "sites.json"), "utf8")).sites;

/** Bench truth roles read as extension roles: `password` is the current password, `none` no role (a search box, a select). */
function accepted(f: TruthField): (string | null)[] {
  return [f.role, ...(f.accept ?? [])].flatMap((r) => (r === "password" ? ["current_password"] : r === "none" ? [null, "unknown"] : [r]));
}

function load(id: string): { site: Site; context: PageContext; detected: (FieldRole | null)[] } {
  const site = SITES.find((s) => s.id === id);
  if (!site) throw new Error(`no bench site ${id}`);
  const html = readFileSync(join(BENCH, "recordings", `${id}.html`), "utf8");
  document.documentElement.innerHTML = html.replace(/<!doctype[^>]*>/i, "");
  Object.defineProperty(document, "URL", { value: site.url, configurable: true });
  const a = createProbe({ geometry: testGeometry, origin: new URL(site.url).origin }).analyze(site.fields.map((f) => f.selector));
  return { site, context: a.context, detected: a.truth.map((t) => t.detected) };
}

describe("real-site bench recordings", () => {
  const ids = SITES.map((s) => s.id);

  it.each(ids)("%s: every truth field is detected with its role", (id) => {
    const { site, detected } = load(id);
    site.fields.forEach((f, i) => {
      expect(accepted(f), `${id} ${f.selector}`).toContain(detected[i]);
    });
  });

  it.each(ids)("%s: the detector reads the page's kind", (id) => {
    const { site, context } = load(id);
    const kinds = context.forms.map((f) => f.intent_hints.kind);
    expect(kinds).toContain(site.kind);
  });

  it("wordpress-login: a disabled Continue still marks the identifier step, and is not the submit", () => {
    const { context } = load("wordpress-login");
    const form = context.forms.find((f) => f.intent_hints.kind === "login");
    expect(form?.fields.map((f) => f.role)).toEqual(["username"]);
    // The disabled button is never offered as the button to press.
    const refs = new RefRegistry();
    const analysis = analyzeDocument(document, refs, { url: "https://wordpress.com/log-in", geometry: testGeometry });
    const login = analysis.forms.find((f) => f.kind === "login");
    expect(login?.submitRef).toBeUndefined();
  });

  it("zoom-login: the Next button after the form is the identifier step's submit", () => {
    const refs = new RefRegistry();
    load("zoom-login");
    const analysis = analyzeDocument(document, refs, { url: "https://zoom.us/signin", geometry: testGeometry });
    const login = analysis.forms.find((f) => f.kind === "login");
    expect(login).toBeDefined();
    expect(refs.get(login!.submitRef!)?.id).toBe("signin_btn_next");
  });

  it("spiegel-login: a 'sign in or create account' button is a sign-in, not a create button", () => {
    const { context } = load("spiegel-login");
    expect(context.forms[0]?.buttons.map((b) => b.class)).toEqual(["submit"]);
  });

  it("qiita-signup: a lone guessed password under a register button is a new password", () => {
    const { context } = load("qiita-signup");
    const form = context.forms[0];
    expect(form?.intent_hints.kind).toBe("signup");
    expect(form?.fields.map((f) => f.role)).toEqual(["username", "email", "new_password"]);
  });

  it("the sign-in pages keep their current password", () => {
    for (const id of ids.filter((x) => SITES.find((s) => s.id === x)?.kind === "login")) {
      const { context } = load(id);
      const roles = context.forms.flatMap((f) => f.fields.map((x) => x.role));
      expect(roles, id).not.toContain("new_password");
    }
  });
});

describe("lone password under a create-worded submit", () => {
  const roles = (html: string): string[] => {
    document.body.innerHTML = html;
    const analysis = analyzeDocument(document, new RefRegistry(), { url: "https://site.test/account", geometry: testGeometry });
    return analysis.forms.flatMap((f) => f.fields.map((x) => x.role));
  };
  it("a sign-in with a noisy 'create imagelog in' label keeps its current password (lab g5 sites 63, 72)", () => {
    expect(
      roles(`<form><label for="u">username *</label><input id="u" name="identifier">
        <label for="p">Your password</label><input id="p" type="password" name="password-field">
        <button type="submit">create imagelog in</button></form>`),
    ).toEqual(["username", "current_password"]);
    expect(
      roles(`<form><label for="p">password input</label><input id="p" type="password" name="ul-password">
        <button type="submit">create imagelog in</button></form>`),
    ).toEqual(["current_password"]);
  });
  it("a user name, an e-mail and one password under Register is a signup", () => {
    expect(
      roles(`<form><label for="u">Username</label><input id="u" name="user[url_name]">
        <label for="e">Email</label><input id="e" type="email" name="user[email]">
        <label for="p">Password</label><input id="p" type="password" name="user[password]">
        <input type="submit" value="register"></form>`),
    ).toEqual(["username", "email", "new_password"]);
  });
});

describe("buttonClass on combined labels", () => {
  const button = (label: string): HTMLButtonElement => {
    document.body.innerHTML = `<button type="button">${label}</button>`;
    return document.querySelector("button") as HTMLButtonElement;
  };
  it("a label with both sign-in and create wording is a sign-in", () => {
    expect(buttonClass(button("Anmelden oder Konto erstellen"))).toBe("submit");
    expect(buttonClass(button("Sign in or create an account"))).toBe("submit");
    expect(buttonClass(button("Se connecter ou créer un compte"))).toBe("submit");
  });
  it("create wording alone stays a create button", () => {
    expect(buttonClass(button("Create account"))).toBe("create");
    expect(buttonClass(button("Konto erstellen"))).toBe("create");
    expect(buttonClass(button("Sign up"))).toBe("create");
  });
});
