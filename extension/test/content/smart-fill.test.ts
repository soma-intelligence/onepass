// Task 10 (smart fill) in the content script: which gestures send
// `fill_salt` and `plan_context`, the menu as the fallback, the worker's
// `smart_fill` and `plan_request`, and the re-check of a plan's submit.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { EXT_BASE, flush, input, setPage, start, type Started, TOKEN, userClick, userClickIcon } from "./harness";

const ORIGIN = "https://atlas-cloud.test";
const SALT = "ab".repeat(32);
const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>
<form id="news"><input id="ne" type="email" autocomplete="email"><button type="submit">Subscribe</button></form>`;

let s: Started | null = null;
beforeEach(() => {
  s = null;
});
afterEach(() => {
  s?.cs.stop();
});

const SMART = ["fill_salt", "plan_context"];
const smartSent = (st: Started) => st.ext.sent.filter((m) => SMART.includes((m as { type: string }).type));

function analysis(st: Started): PageAnalysis {
  const all = st.ext.ofType("page_analysis");
  return all[all.length - 1]?.analysis as PageAnalysis;
}

function formById(st: Started, id: string): FormInfo {
  const f = analysis(st).forms.find((x) => (st.cs.internals.refs.get(x.ref) as HTMLElement | null)?.id === id);
  if (!f) throw new Error(`no form #${id}`);
  return f;
}

const icons = (st: Started) => Array.from(st.cs.internals.root.querySelectorAll<HTMLElement>(".icon"));

/** The worker: a salt, then `outcome` for the plan (or an error envelope), a menu URL. */
function worker(st: Started, outcome: unknown) {
  st.ext.reply = (m) => {
    switch ((m as { type: string }).type) {
      case "fill_salt":
        return { ok: { salt: SALT } };
      case "plan_context":
        return outcome;
      case "open_menu":
        return { ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } };
      default:
        return { ok: null };
    }
  };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) {
    await flush();
    await new Promise((r) => setTimeout(r, 0));
  }
}

describe("triggers", () => {
  it("auto_focus_never_fills: a click into a field, a load or a mutation sends no plan nor salt", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, { ok: { outcome: "filled" } });
    input("u").focus();
    userClick(input("u"));
    await settle();
    // The click into the empty field asks for the menu (auto), as before.
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
    // The page adds a field: analysed again, never planned.
    document.getElementById("login")!.insertAdjacentHTML("beforeend", '<input id="otp" autocomplete="one-time-code">');
    await settle();
    expect(smartSent(s)).toEqual([]);
    // A page script clicking the icon is not a gesture either.
    icons(s)[0]!.click();
    await settle();
    expect(smartSent(s)).toEqual([]);
    expect(s.ext.sent.some((m) => JSON.stringify(m).includes("plan"))).toBe(false);
  });

  it("an icon click sends the salt request, then the context with its form and field, the username only hashed", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, { ok: { outcome: "filled" } });
    input("u").value = "alex@atlas.dev";
    userClickIcon(icons(s)[1]!);
    await settle();
    const f = formById(s, "login");
    expect(smartSent(s).map((m) => (m as { type: string }).type)).toEqual(["fill_salt", "plan_context"]);
    const pc = s.ext.ofType("plan_context")[0]!;
    expect(pc.formRef).toBe(f.ref);
    expect(pc.fieldRef).toBe(f.fields.find((x) => x.role === "current_password")!.ref);
    const ctx = pc.context as { forms: { form_ref: string }[]; typed_username_hash: number[] | null; origin?: unknown };
    expect(ctx.typed_username_hash).toHaveLength(32);
    expect(ctx.origin).toBeUndefined();
    expect(ctx.forms.map((x) => x.form_ref)).toContain(f.ref);
    expect(JSON.stringify(s.ext.sent)).not.toContain("alex@atlas.dev");
    // Filled: no menu.
    expect(s.ext.ofType("open_menu")).toEqual([]);
  });

  it("menu outcome: the menu under the clicked field", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, { ok: { outcome: "menu" } });
    userClickIcon(icons(s)[0]!);
    await settle();
    const f = formById(s, "login");
    expect(s.ext.ofType("open_menu")).toEqual([{ type: "open_menu", fieldRef: f.fields[0]!.ref, formRef: f.ref, formKind: "login" }]);
    expect(s.cs.internals.root.querySelector("iframe")?.getAttribute("src")).toBe(`${EXT_BASE}menu.html#${TOKEN}`);
  });

  it("plan_context error (bridge down, invalid context, origin mismatch): the menu, never a second plan", async () => {
    for (const reply of [{ err: "host_missing" }, { err: "invalid" }, { err: "origin_mismatch" }, null]) {
      setPage(LOGIN);
      s = start();
      worker(s, reply);
      userClickIcon(icons(s)[0]!);
      await settle();
      expect(s.ext.ofType("plan_context")).toHaveLength(1);
      expect(s.ext.ofType("open_menu")).toHaveLength(1);
      s.cs.stop();
    }
    s = null;
  });

  it("no salt (bridge down): the plan is asked without a hash", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, { ok: { outcome: "filled" } });
    const base = s.ext.reply;
    s.ext.reply = (m) => ((m as { type: string }).type === "fill_salt" ? { err: "host_missing" } : base(m));
    input("u").value = "alex@atlas.dev";
    userClickIcon(icons(s)[0]!);
    await settle();
    expect((s.ext.ofType("plan_context")[0]!.context as { typed_username_hash: unknown }).typed_username_hash).toBeNull();
  });

  it("smart_fill from our worker runs without a form (whole plan); from anyone else, nothing", async () => {
    setPage(LOGIN);
    s = start();
    worker(s, { ok: { outcome: "menu" } });
    s.ext.deliver({ type: "smart_fill" }, { id: "someone-else" });
    await settle();
    expect(smartSent(s)).toEqual([]);
    input("u").focus();
    // A resume names the origin its card waited on: another page in this frame by now gets nothing.
    expect(s.ext.deliver({ type: "smart_fill", origin: "https://evil.test" })).toEqual({ ok: false });
    await settle();
    expect(smartSent(s)).toEqual([]);
    expect(s.ext.deliver({ type: "smart_fill" })).toEqual({ ok: true });
    await settle();
    const pc = s.ext.ofType("plan_context")[0]!;
    expect(pc.formRef).toBeUndefined();
    expect(pc.fieldRef).toBeUndefined();
    // "menu" without a clicked field: under the focused one.
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ fieldRef: formById(s, "login").fields[0]!.ref })]);
  });

  it("a gesture without a field on a page with no field to open the menu under says so (bare); with one, it does not", async () => {
    setPage('<main><button id="g" type="button">Continue with Google</button></main>');
    s = start();
    worker(s, { err: "locked" });
    expect(s.ext.deliver({ type: "smart_fill" })).toEqual({ ok: true });
    await settle();
    expect(s.ext.ofType("plan_context")[0]).toMatchObject({ bare: true });
    expect(s.ext.ofType("plan_context")[0]!.fieldRef).toBeUndefined();
    expect(s.ext.ofType("open_menu")).toEqual([]);
    s.cs.stop();

    setPage(LOGIN);
    s = start();
    worker(s, { err: "locked" });
    s.ext.deliver({ type: "smart_fill" });
    await settle();
    expect(s.ext.ofType("plan_context")[0]!.bare).toBeUndefined();
    expect(s.ext.ofType("open_menu")).toHaveLength(1);
  });

  describe("the resume of a menu's field after an unlock, on a page that redrew its form meanwhile", () => {
    const redraw = () => {
      const form = document.getElementById("login")!;
      const copy = form.cloneNode(true) as HTMLElement;
      form.replaceWith(copy);
    };

    it("the field is gone with its form: the copy of that very form takes the fill (its first field)", async () => {
      setPage(LOGIN);
      s = start();
      worker(s, { ok: { outcome: "filled" } });
      const before = formById(s, "login");
      redraw();
      await settle();
      expect(s.ext.deliver({ type: "smart_fill", fieldRef: before.fields[0]!.ref, formRef: before.ref, origin: ORIGIN })).toEqual({ ok: true });
      await settle();
      const after = formById(s, "login");
      expect(after.ref).not.toBe(before.ref);
      expect(s.ext.ofType("plan_context")).toEqual([expect.objectContaining({ formRef: after.ref, fieldRef: after.fields[0]!.ref })]);
    });

    it("no copy of that form, two of them, another origin, or no form named: nothing runs", async () => {
      setPage(LOGIN);
      s = start();
      worker(s, { ok: { outcome: "filled" } });
      const before = formById(s, "login");
      const dead = before.fields[0]!.ref;
      // Without the form's ref the dead field resumes nothing (as before).
      redraw();
      await settle();
      expect(s.ext.deliver({ type: "smart_fill", fieldRef: dead, origin: ORIGIN })).toEqual({ ok: false });
      expect(s.ext.deliver({ type: "smart_fill", fieldRef: dead, formRef: before.ref, origin: "https://evil.test" })).toEqual({ ok: false });
      // Two forms with the same identity: which one is not ours to guess.
      document.getElementById("login")!.insertAdjacentHTML("afterend", document.getElementById("login")!.outerHTML);
      await settle();
      expect(s.ext.deliver({ type: "smart_fill", fieldRef: dead, formRef: before.ref, origin: ORIGIN })).toEqual({ ok: false });
      // The form went away altogether.
      for (const f of [...document.querySelectorAll("#login")]) f.remove();
      await settle();
      expect(s.ext.deliver({ type: "smart_fill", fieldRef: dead, formRef: before.ref, origin: ORIGIN })).toEqual({ ok: false });
      await settle();
      expect(smartSent(s)).toEqual([]);
    });
  });

  it("plan_request: the page context, no value and no hash", () => {
    setPage(LOGIN);
    s = start();
    input("u").value = "alex@atlas.dev";
    input("p").value = "pw-Secret-1";
    const r = s.ext.deliver({ type: "plan_request" }) as { ok: boolean; context: { forms: unknown[]; typed_username_hash: unknown } };
    expect(r.ok).toBe(true);
    expect(r.context.forms.length).toBeGreaterThan(0);
    expect(r.context.typed_username_hash).toBeNull();
    expect(JSON.stringify(r)).not.toMatch(/alex@atlas\.dev|pw-Secret-1/);
    expect(smartSent(s)).toEqual([]);
  });
});

describe("a plan's submit (planned)", () => {
  const clicks = () => {
    let n = 0;
    document.getElementById("go")!.addEventListener("click", (e) => {
      n++;
      e.preventDefault();
    });
    return () => n;
  };

  it("submits the planned form as it is", () => {
    setPage(LOGIN);
    s = start();
    const n = clicks();
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: formById(s, "login").ref, planned: true })).toEqual({ ok: true });
    expect(n()).toBe(1);
  });

  it("refuses a button the page relabelled pay or create since the plan", () => {
    for (const label of ["Pay now", "Create account", "Sign up with a passkey"]) {
      setPage(LOGIN);
      s = start();
      const f = formById(s, "login");
      const n = clicks();
      document.getElementById("go")!.textContent = label;
      expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref, planned: true })).toEqual({ ok: false });
      expect(n()).toBe(0);
      // The chain's own submit (not a plan) keeps its behavior.
      s.cs.stop();
    }
    s = null;
  });

  it("keeps a sign-in whose form also shows a passkey button", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    document.getElementById("login")!.insertAdjacentHTML("beforeend", '<button type="button">Use a passkey</button>');
    const n = clicks();
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref, planned: true })).toEqual({ ok: true });
    expect(n()).toBe(1);
  });

  it("refuses another pay button added to the form", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    document.getElementById("login")!.insertAdjacentHTML("beforeend", '<button type="button">Buy now</button>');
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref, planned: true })).toEqual({ ok: false });
  });

  it("refuses a re-rendered copy of the form (no lineage substitution), which an unplanned submit accepts", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    const old = document.getElementById("login")!;
    old.replaceWith(old.cloneNode(true));
    const n = clicks();
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref, planned: true })).toEqual({ ok: false });
    expect(n()).toBe(0);
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref })).toEqual({ ok: true });
    expect(n()).toBe(1);
  });
});

describe("the signup menu's passkey choice (click_passkey)", () => {
  const SIGNUP = `
    <form id="signup"><input type="email" id="e" autocomplete="email">
      <input type="password" id="np" autocomplete="new-password">
      <button type="button" id="pk">Sign up with a passkey</button>
      <button type="submit" id="go">Create account</button></form>`;

  const buttonRef = (label: RegExp): string => {
    const r = s!.ext.deliver({ type: "plan_request" }) as { context: { forms: { buttons: { button_ref: string; class: string }[] }[] } };
    const b = r.context.forms[0]!.buttons.find((x) => x.class === "passkey");
    expect(b).toBeDefined();
    expect(label.test(document.getElementById("pk")!.textContent ?? "")).toBe(true);
    return b!.button_ref;
  };

  it("clicks the passkey button", () => {
    setPage(SIGNUP);
    s = start();
    let n = 0;
    document.getElementById("pk")!.addEventListener("click", () => void n++);
    const ref = buttonRef(/passkey/);
    expect(s.ext.deliver({ type: "click_passkey", origin: ORIGIN, ref })).toEqual({ ok: true });
    expect(n).toBe(1);
  });

  it("refuses a button relabelled since the plan, and another origin", () => {
    setPage(SIGNUP);
    s = start();
    let n = 0;
    document.getElementById("pk")!.addEventListener("click", () => void n++);
    const ref = buttonRef(/passkey/);
    expect(s.ext.deliver({ type: "click_passkey", origin: "https://evil.test", ref })).toEqual({ ok: false });
    document.getElementById("pk")!.textContent = "Delete my data";
    expect(s.ext.deliver({ type: "click_passkey", origin: ORIGIN, ref })).toEqual({ ok: false });
    expect(n).toBe(0);
  });
});

describe("a passkey-only sign-in page: the worker asks to press its one passkey button (click_passkey_signin)", () => {
  const page = (buttons: string) => `<main><h1>Sign in</h1>${buttons}</main>`;
  const clicks = (id: string) => {
    const seen = { n: 0 };
    document.getElementById(id)!.addEventListener("click", () => void seen.n++);
    return seen;
  };

  it("presses the one button that reads as a passkey sign-in", () => {
    setPage(page('<button type="button" id="pk">Use passkey</button><a href="/help">Help</a>'));
    s = start();
    const seen = clicks("pk");
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: ORIGIN })).toEqual({ ok: true });
    expect(seen.n).toBe(1);
  });

  it("presses nothing when no button, several, a hidden one, or one that makes a passkey; nor for another origin", () => {
    setPage(page('<button type="button" id="a">Sign in</button>'));
    s = start();
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: ORIGIN })).toEqual({ ok: false });
    s.cs.stop();

    setPage(page('<button type="button" id="a">Use passkey</button><button type="button" id="b">Sign in with a passkey</button>'));
    s = start();
    const a = clicks("a");
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: ORIGIN })).toEqual({ ok: false });
    expect(a.n).toBe(0);
    s.cs.stop();

    setPage(page('<button type="button" id="a" style="display:none">Use passkey</button>'));
    s = start();
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: ORIGIN })).toEqual({ ok: false });
    s.cs.stop();

    setPage(page('<button type="button" id="a">Create a passkey</button>'));
    s = start();
    const made = clicks("a");
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: ORIGIN })).toEqual({ ok: false });
    expect(made.n).toBe(0);
    s.cs.stop();

    setPage(page('<button type="button" id="a">Use passkey</button>'));
    s = start();
    const other = clicks("a");
    expect(s.ext.deliver({ type: "click_passkey_signin", origin: "https://evil.test" })).toEqual({ ok: false });
    expect(other.n).toBe(0);
  });
});
