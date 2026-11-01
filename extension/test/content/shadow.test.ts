import { afterEach, describe, expect, it, vi } from "vitest";
import { GESTURE_MS } from "../../src/content/submit";
import type { PageAnalysis } from "../../src/shared/messages";
import { asUser, EXT_BASE, flush, setPage, start, type Started, TOKEN, userClick, userKey, useTimers } from "./harness";

const ORIGIN = "https://atlas-cloud.test";

const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>`;

type Run = Started;

let run: Run | null = null;

afterEach(() => {
  run?.cs.stop();
  run = null;
  vi.useRealTimers();
});

/** Closed roots made through `attachShadow` while recording, for the fake DOM API. */
const closedRoots = new WeakMap<Element, ShadowRoot>();
const fakeOpenOrClosed = (el: Element): ShadowRoot | null => el.shadowRoot ?? closedRoots.get(el) ?? null;

function attach(el: Element, mode: ShadowRootMode, html: string): ShadowRoot {
  const root = el.attachShadow({ mode });
  if (mode === "closed") closedRoots.set(el, root);
  root.innerHTML = html;
  return root;
}

function begin(withDomApi = true): Run {
  run = start(undefined, withDomApi ? { shadowRootOf: fakeOpenOrClosed } : {});
  return run;
}

function last(r: Run): PageAnalysis {
  const all = r.ext.ofType("page_analysis");
  return all[all.length - 1]!.analysis as PageAnalysis;
}

function field(root: ShadowRoot, id: string): HTMLInputElement {
  return root.getElementById(id) as HTMLInputElement;
}

describe("content script in shadow roots (D1, D2)", () => {
  it("fill_inside_shadow_root", () => {
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "open", LOGIN);
    const r = begin();
    const f = last(r).forms[0]!;
    expect(f.kind).toBe("login");
    const reply = r.ext.deliver({ type: "fill", origin: ORIGIN, formRef: f.ref, values: { username: "alex@atlas.dev", current_password: "pw" } });
    expect(reply).toMatchObject({ ok: true });
    expect(field(root, "u").value).toBe("alex@atlas.dev");
    expect(field(root, "p").value).toBe("pw");
    // The chain's submit clicks the button inside the root.
    let submitted = 0;
    root.addEventListener("submit", (e) => {
      e.preventDefault();
      submitted++;
    });
    expect(r.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref })).toEqual({ ok: true });
    expect(submitted).toBe(1);
  });

  it("closed roots are read through the DOM API, our own host never", () => {
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "closed", LOGIN);
    const r = begin();
    const f = last(r).forms[0]!;
    expect(r.cs.internals.refs.get(f.fields[1]!.ref)).toBe(field(root, "p"));
    expect(last(r).forms).toHaveLength(1);
  });

  it("the DOM API is never asked for our own host's root", () => {
    setPage(`<lab-shell></lab-shell>`);
    attach(document.querySelector("lab-shell")!, "closed", LOGIN);
    const asked: Element[] = [];
    const spy = (el: Element) => (asked.push(el), fakeOpenOrClosed(el));
    run = start(undefined, { shadowRootOf: spy });
    const ours = run.cs.internals.root.host;
    // Analyse again with our host attached to the page.
    expect(run.ext.deliver({ type: "plan_request" })).toMatchObject({ ok: true });
    expect(asked.length).toBeGreaterThan(0);
    expect(document.contains(ours)).toBe(true);
    expect(asked).not.toContain(ours);
  });

  it("the planner's context holds the forms of the roots", () => {
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "closed", LOGIN);
    const r = begin();
    const reply = r.ext.deliver({ type: "plan_request" }) as { context: { forms: { form_ref: string; fields: { field_ref: string; role: string }[]; buttons: { button_ref: string }[] }[] } };
    const [f] = reply.context.forms;
    expect(r.cs.internals.refs.get(f!.form_ref)).toBe(root.getElementById("login"));
    expect(f!.fields.map((x) => [r.cs.internals.refs.get(x.field_ref), x.role])).toEqual([
      [field(root, "u"), "username"],
      [field(root, "p"), "current_password"],
    ]);
    expect(f!.buttons.map((b) => r.cs.internals.refs.get(b.button_ref))).toEqual([root.getElementById("go")]);
  });

  it("a fill gives the focus back to the field of the root that had it", () => {
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "open", LOGIN);
    const r = begin();
    field(root, "u").focus();
    const f = last(r).forms[0]!;
    expect(r.ext.deliver({ type: "fill", origin: ORIGIN, formRef: f.ref, values: { username: "alex@atlas.dev", current_password: "pw" } })).toMatchObject({ ok: true });
    expect(root.activeElement).toBe(field(root, "u"));
  });

  it("a click inside a button's own shadow root still submits the light form", () => {
    useTimers();
    setPage(`<form id="login"><input id="u" name="username" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><x-btn id="go" role="button">Sign in</x-btn></form>`);
    const inner = attach(document.getElementById("go")!, "open", `<span id="label"><slot></slot></span>`);
    const r = begin();
    (document.getElementById("u") as HTMLInputElement).value = "alex@atlas.dev";
    (document.getElementById("p") as HTMLInputElement).value = "s3cret";
    userClick(inner.getElementById("label")!);
    vi.advanceTimersByTime(300);
    (document.getElementById("p") as HTMLElement).remove();
    vi.advanceTimersByTime(300);
    expect(r.ext.ofType("submitted_credentials").map((m) => [m.username, m.password])).toEqual([["alex@atlas.dev", "s3cret"]]);
  });

  it("without the DOM API (Firefox, Safari) a closed root stays out of reach", () => {
    setPage(`<lab-shell></lab-shell>`);
    attach(document.querySelector("lab-shell")!, "closed", LOGIN);
    const r = begin(false);
    expect(last(r).forms).toEqual([]);
  });

  it("observer_sees_shadow_mutations", async () => {
    useTimers();
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "closed", `<div id="app"></div>`);
    const r = begin();
    expect(last(r).forms).toEqual([]);
    root.getElementById("app")!.innerHTML = LOGIN;
    await flush();
    vi.advanceTimersByTime(200);
    expect(r.ext.ofType("page_analysis")).toHaveLength(2);
    expect(last(r).forms.map((f) => f.kind)).toEqual(["login"]);
    // An attribute change inside the root is seen too: as in the document,
    // the form is left with its identifier. (A `type` change: jsdom ignores
    // inline style inside shadow roots, browsers do not.)
    field(root, "p").setAttribute("type", "hidden");
    await flush();
    vi.advanceTimersByTime(200);
    expect(r.ext.ofType("page_analysis")).toHaveLength(3);
    expect(last(r).forms.map((f) => f.fields.map((x) => x.role))).toEqual([["username"]]);
  });

  it("a focus into a root attached after the last analysis analyses now", async () => {
    setPage(`<lab-shell></lab-shell>`);
    const r = begin();
    // attachShadow makes no mutation record: nothing tells the observer.
    const root = attach(document.querySelector("lab-shell")!, "open", LOGIN);
    await flush();
    expect(last(r).forms).toEqual([]);
    asUser(field(root, "u"), new FocusEvent("focusin", { bubbles: true, composed: true }));
    expect(last(r).forms.map((f) => f.kind)).toEqual(["login"]);
  });

  it("opens the menu on a trusted ArrowDown in a field of a closed root", async () => {
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "closed", LOGIN);
    const r = begin();
    r.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    field(root, "u").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true, composed: true }));
    await flush();
    expect(r.ext.ofType("open_menu")).toHaveLength(0);
    userKey(field(root, "u"), "ArrowDown");
    await flush();
    const open = r.ext.ofType("open_menu");
    expect(open).toHaveLength(1);
    expect(r.cs.internals.refs.get(open[0]!.fieldRef as string)).toBe(field(root, "u"));
  });

  it("captures a submission inside a root once, from the real target", () => {
    useTimers();
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "open", LOGIN);
    const r = begin();
    root.addEventListener("submit", (e) => e.preventDefault());
    field(root, "u").value = "alex@atlas.dev";
    field(root, "p").value = "s3cret";
    userClick(root.getElementById("go")!);
    expect(r.ext.ofType("submitted_credentials").map((m) => [m.username, m.password])).toEqual([["alex@atlas.dev", "s3cret"]]);
    // A forged click is ignored. (Within GESTURE_MS of the user's click, the
    // browser's own submit would count, as in the document.)
    vi.advanceTimersByTime(GESTURE_MS + 1000);
    root.getElementById("go")!.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
    expect(r.ext.ofType("submitted_credentials")).toHaveLength(1);
  });

  it("Enter on a focused button host reaches the submit watcher (its gesture counts)", async () => {
    setPage(`<form id="login"><input id="u" name="username" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><x-btn id="go" role="button" tabindex="0">Sign in</x-btn></form>`);
    const host = document.getElementById("go")!;
    attach(host, "closed", `<span><slot></slot></span>`);
    const r = begin();
    (document.getElementById("u") as HTMLInputElement).value = "alex@atlas.dev";
    (document.getElementById("p") as HTMLInputElement).value = "s3cret";
    host.focus();
    userKey(host, "Enter");
    await new Promise((res) => setTimeout(res, 0));
    asUser(document.getElementById("login")!, new Event("submit", { bubbles: true, cancelable: true }));
    expect(r.ext.ofType("submitted_credentials").map((m) => [m.username, m.password])).toEqual([["alex@atlas.dev", "s3cret"]]);
  });

  it("a click on a provider button host itself (its padding) is reported", async () => {
    setPage(`${LOGIN}<x-btn id="g" role="button" tabindex="0">Continuer avec Google</x-btn>`);
    const host = document.getElementById("g")!;
    const inner = attach(host, "open", `<span id="label"><slot></slot></span>`);
    const r = begin();
    const btn = last(r).providerButtons[0]!;
    expect(btn.provider).toBe("google");
    userClick(host);
    await new Promise((res) => setTimeout(res, 0));
    expect(r.ext.ofType("provider_click")).toEqual([{ type: "provider_click", provider: "google", ref: btn.ref }]);
    // From inside its root: once, not twice.
    userClick(inner.getElementById("label")!);
    await new Promise((res) => setTimeout(res, 0));
    expect(r.ext.ofType("provider_click")).toHaveLength(2);
  });

  it("stop removes the listeners and observation of the roots", async () => {
    useTimers();
    setPage(`<lab-shell></lab-shell>`);
    const root = attach(document.querySelector("lab-shell")!, "open", `<div id="app"></div>`);
    const r = begin();
    r.cs.stop();
    root.getElementById("app")!.innerHTML = LOGIN;
    await flush();
    vi.advanceTimersByTime(200);
    userKey(field(root, "u"), "ArrowDown");
    expect(r.ext.ofType("page_analysis")).toHaveLength(1);
    expect(r.ext.ofType("open_menu")).toHaveLength(0);
  });
});
