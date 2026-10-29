// Task 10 (smart fill) in the content script: which gestures send
// `fill_salt` and `plan_context`, the menu as the fallback, the worker's
// `smart_fill` and `plan_request`, and the re-check of a plan's submit.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { EXT_BASE, flush, input, setPage, start, type Started, TOKEN, userClick } from "./harness";

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
    userClick(icons(s)[1]!);
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
    userClick(icons(s)[0]!);
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
      userClick(icons(s)[0]!);
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
    userClick(icons(s)[0]!);
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
    expect(s.ext.deliver({ type: "smart_fill" })).toEqual({ ok: true });
    await settle();
    const pc = s.ext.ofType("plan_context")[0]!;
    expect(pc.formRef).toBeUndefined();
    expect(pc.fieldRef).toBeUndefined();
    // "menu" without a clicked field: under the focused one.
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ fieldRef: formById(s, "login").fields[0]!.ref })]);
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
    for (const label of ["Pay now", "Create account"]) {
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
