import { afterEach, describe, expect, it, vi } from "vitest";
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
    expect(reply).toEqual({ ok: true });
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
    // An attribute change inside the root (a step revealed) is seen too.
    field(root, "p").setAttribute("hidden", "");
    (field(root, "p") as HTMLElement).style.display = "none";
    await flush();
    vi.advanceTimersByTime(200);
    expect(last(r).forms).toEqual([]);
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
    // A forged click is ignored.
    vi.advanceTimersByTime(3000);
    root.getElementById("go")!.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
    expect(r.ext.ofType("submitted_credentials")).toHaveLength(1);
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
