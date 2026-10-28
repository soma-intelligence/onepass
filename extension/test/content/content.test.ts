import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FormInfo, PageAnalysis } from "../../src/shared/messages";
import { GESTURE_MS } from "../../src/content/submit";
import {
  asUser,
  EXT_BASE,
  flush,
  input,
  PAGE,
  setPage,
  start,
  type Started,
  TOKEN,
  userClick,
  userKey,
  useTimers,
} from "./harness";

const ORIGIN = "https://atlas-cloud.test";

const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>`;

let s: Started | null = null;

beforeEach(() => {
  s = null;
});

afterEach(() => {
  s?.cs.stop();
  vi.useRealTimers();
});

function analysis(st: Started): PageAnalysis {
  const all = st.ext.ofType("page_analysis");
  const last = all[all.length - 1];
  if (!last) throw new Error("no page_analysis sent");
  return last.analysis as PageAnalysis;
}

function formById(st: Started, id: string): FormInfo {
  const f = analysis(st).forms.find((x) => (st.cs.internals.refs.get(x.ref) as HTMLElement | null)?.id === id);
  if (!f) throw new Error(`no form #${id}`);
  return f;
}

function fill(st: Started, formRef: string, values: Record<string, string>, origin = ORIGIN): unknown {
  return st.ext.deliver({ type: "fill", origin, formRef, values });
}

function icons(st: Started): HTMLElement[] {
  return Array.from(st.cs.internals.root.querySelectorAll<HTMLElement>(".icon"));
}

describe("shell and icon", () => {
  it("hosts icons in a closed shadow root the page cannot reach", () => {
    setPage(LOGIN);
    s = start();
    const host = document.documentElement.querySelector("onepass-root") as HTMLElement;
    expect(host).not.toBeNull();
    expect(host.parentElement).toBe(document.documentElement);
    expect(host.shadowRoot).toBeNull();
    expect(document.querySelectorAll(".icon")).toHaveLength(0);
    // Username and password fields each get an icon.
    expect(icons(s)).toHaveLength(2);
  });

  it("icon_ignores_untrusted_click", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    const icon = icons(s)[0]!;
    icon.click();
    icon.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);

    userClick(icon);
    await flush();
    const open = s.ext.ofType("open_menu");
    expect(open).toHaveLength(1);
    const f = formById(s, "login");
    expect(open[0]).toEqual({ type: "open_menu", fieldRef: f.fields[0]!.ref, formRef: f.ref, formKind: "login" });
    const frame = s.cs.internals.root.querySelector("iframe")!;
    expect(frame.getAttribute("src")).toBe(`${EXT_BASE}menu.html#${TOKEN}`);
    expect(frame.getAttribute("allow")).toBe("");
    expect(frame.hasAttribute("sandbox")).toBe(false);
    // S1: the page sees no iframe and no menu URL.
    expect(document.querySelectorAll("iframe")).toHaveLength(0);
    expect(document.documentElement.outerHTML).not.toContain(TOKEN);
  });

  it("opens the menu on a trusted ArrowDown in the field only", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    input("u").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    userKey(input("u"), "ArrowDown");
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(1);
  });

  it("closes the menu on Escape and tells the worker", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    userClick(icons(s)[0]!);
    await flush();
    expect(s.cs.internals.root.querySelector("iframe")).not.toBeNull();
    userKey(input("u"), "Escape");
    await flush();
    expect(s.cs.internals.root.querySelector("iframe")).toBeNull();
    expect(s.ext.ofType("close_menu")).toHaveLength(1);
  });

  it("a trusted click into an empty field asks for the menu (auto), never a page click", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    input("u").click(); // page script: untrusted
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    userClick(input("u"));
    await flush();
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ type: "open_menu", formKind: "login", auto: true })]);
    // A filled field: the user is editing, nothing pops up.
    s.ext.deliver({ type: "remove_frame", kind: "menu" });
    input("p").value = "typed";
    userClick(input("p"));
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(1);
  });

  it("menu open: arrows and Return go to the menu, the focus and the page's form stay", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    input("u").focus();
    userKey(input("u"), "ArrowDown");
    await flush();
    expect(s.cs.internals.root.querySelector("iframe")).not.toBeNull();
    let submitted = 0;
    document.getElementById("login")!.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter" && !e.defaultPrevented) submitted++;
    });
    // Return before any arrow: the page's own (the menu has no highlight yet).
    userKey(input("u"), "Enter");
    userKey(input("u"), "ArrowDown");
    userKey(input("u"), "ArrowUp");
    const enter = userKey(input("u"), "Enter");
    // A page's synthetic key is never relayed.
    input("u").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
    await flush();
    expect(s.ext.ofType("menu_key").map((m) => m.key)).toEqual(["down", "up", "enter"]);
    expect(enter.defaultPrevented).toBe(true);
    expect(submitted).toBe(1);
    expect(document.activeElement).toBe(input("u"));
  });

  it("typing in the field closes the menu; a click in the field keeps it", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    userKey(input("u"), "ArrowDown");
    await flush();
    asUser(input("u"), new MouseEvent("pointerdown", { bubbles: true, composed: true }));
    expect(s.cs.internals.root.querySelector("iframe")).not.toBeNull();
    input("u").dispatchEvent(new InputEvent("input", { bubbles: true })); // page script
    expect(s.cs.internals.root.querySelector("iframe")).not.toBeNull();
    asUser(input("u"), new InputEvent("input", { bubbles: true, composed: true }));
    expect(s.cs.internals.root.querySelector("iframe")).toBeNull();
    expect(s.ext.ofType("close_menu")).toHaveLength(1);
  });

  it("resize_frame from the worker sizes the frame (clamped), never from another sender", async () => {
    setPage(LOGIN);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    userKey(input("u"), "ArrowDown");
    await flush();
    const f = s.cs.internals.root.querySelector("iframe")!;
    s.ext.deliver({ type: "resize_frame", kind: "menu", height: 166 }, { id: "other" });
    expect(f.style.height).toBe("420px");
    s.ext.deliver({ type: "resize_frame", kind: "menu", height: 166 });
    expect(f.style.height).toBe("166px");
    s.ext.deliver({ type: "resize_frame", kind: "menu", height: "9999" });
    expect(f.style.height).toBe("166px");
  });

  it("refuses a menu URL that is not an extension page", async () => {
    setPage(LOGIN);
    s = start();
    for (const url of [
      `https://evil.test/menu.html#${TOKEN}`,
      `javascript:alert(1)//${TOKEN}`,
      `${EXT_BASE}save.html#${TOKEN}`,
      `${EXT_BASE}menu.html`,
    ]) {
      s.ext.reply = () => ({ ok: { url } });
      userClick(icons(s)[0]!);
      await flush();
      expect(s.cs.internals.root.querySelector("iframe")).toBeNull();
    }
    // Chromium use_dynamic_url: another extension id, but the very URL the worker returned.
    const dynamic = `chrome-extension://0123456789abcdef/menu.html#${TOKEN}`;
    s.ext.reply = () => ({ ok: { url: dynamic } });
    userClick(icons(s)[0]!);
    await flush();
    expect(s.cs.internals.root.querySelector("iframe")?.getAttribute("src")).toBe(dynamic);
  });

  it("does nothing on a plain HTTP page", () => {
    setPage(LOGIN);
    s = start("http://atlas-cloud.test/login");
    expect(document.documentElement.querySelector("onepass-root")).toBeNull();
    expect(s.ext.sent).toHaveLength(0);
  });
});

describe("show_frame / remove_frame", () => {
  it("shows an extension frame and refuses foreign URLs or senders", () => {
    setPage(LOGIN);
    s = start();
    const root = s.cs.internals.root;
    s.ext.deliver({ type: "show_frame", kind: "save", url: `https://evil.test/save.html#${TOKEN}` });
    expect(root.querySelector("iframe")).toBeNull();
    s.ext.deliver({ type: "show_frame", kind: "save", url: `${EXT_BASE}save.html#${TOKEN}` }, { id: "other" });
    expect(root.querySelector("iframe")).toBeNull();
    s.ext.deliver({ type: "show_frame", kind: "save", url: `${EXT_BASE}overlay.html#${TOKEN}` });
    expect(root.querySelector("iframe")).toBeNull();
    s.ext.deliver({ type: "show_frame", kind: "save", url: `${EXT_BASE}save.html#${TOKEN}` });
    const f = root.querySelector("iframe")!;
    expect(f.getAttribute("src")).toBe(`${EXT_BASE}save.html#${TOKEN}`);
    expect(f.getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(f.style.width).toBe("360px");
    s.ext.deliver({ type: "remove_frame", kind: "save" });
    expect(root.querySelector("iframe")).toBeNull();
  });

  it("an origin pin must match this document's origin", () => {
    setPage(LOGIN);
    s = start();
    const root = s.cs.internals.root;
    s.ext.deliver({ type: "show_frame", kind: "save", url: `${EXT_BASE}save.html#${TOKEN}`, origin: "https://evil.test" });
    expect(root.querySelector("iframe")).toBeNull();
    s.ext.deliver({ type: "show_frame", kind: "save", url: `${EXT_BASE}save.html#${TOKEN}`, origin: "https://atlas-cloud.test" });
    expect(root.querySelector("iframe")).not.toBeNull();
  });
});

describe("filler", () => {
  const THREE = `
<form id="a"><input id="au" autocomplete="username"><input id="ap" type="password" autocomplete="current-password"></form>
<form id="b"><input id="bu" autocomplete="username"><input id="bp" type="password" autocomplete="current-password"></form>
<form id="c"><input id="cu" autocomplete="email" type="email"><input id="cp" type="password" autocomplete="new-password"></form>`;

  it("fill_only_target_form", () => {
    setPage(THREE);
    s = start();
    const b = formById(s, "b");
    fill(s, b.ref, { username: "alex@atlas.dev", email: "alex@atlas.dev", current_password: "pw-b", new_password: "x" });
    expect(input("bu").value).toBe("alex@atlas.dev");
    expect(input("bp").value).toBe("pw-b");
    for (const id of ["au", "ap", "cu", "cp"]) expect(input(id).value).toBe("");
  });

  it("refuses a fill whose origin pin differs from the page", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    fill(s, f.ref, { username: "alex", current_password: "pw" }, "https://evil.test");
    fill(s, f.ref, { username: "alex", current_password: "pw" }, "http://atlas-cloud.test");
    expect(input("u").value).toBe("");
    expect(input("p").value).toBe("");
    // A message that does not come from our extension.
    s.ext.deliver({ type: "fill", origin: ORIGIN, formRef: f.ref, values: { username: "x" } }, { id: "other" });
    expect(input("u").value).toBe("");
    fill(s, f.ref, { username: "alex", current_password: "pw" });
    expect(input("u").value).toBe("alex");
    expect(input("p").value).toBe("pw");
  });

  it("a fill gives the focus back to the field that had it", () => {
    setPage(LOGIN);
    s = start();
    input("u").focus();
    expect(fill(s, formById(s, "login").ref, { username: "alex@atlas.dev", current_password: "pw" })).toEqual({ ok: true });
    expect(input("p").value).toBe("pw");
    expect(document.activeElement).toBe(input("u"));
  });

  it("dispatches input and change events that bubble", () => {
    setPage(LOGIN);
    s = start();
    const seen: string[] = [];
    for (const t of ["focus", "input", "change", "blur"]) document.addEventListener(t, (e) => seen.push(`${t}:${(e.target as HTMLElement).id}`), true);
    fill(s, formById(s, "login").ref, { username: "alex" });
    expect(seen).toEqual(["focus:u", "input:u", "change:u", "blur:u"]);
  });

  it("react_controlled_input_keeps_value", () => {
    setPage(LOGIN);
    s = start();
    // A React-like controlled input: an instance-level `value` tracker records
    // writes through `el.value = ...`; on `input` the component reads the DOM
    // value, compares it with the tracker and, only if it differs, updates its
    // state. It then re-renders `value` from its state.
    const el = input("u");
    const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!;
    let tracked = "";
    let state = "";
    Object.defineProperty(el, "value", {
      configurable: true,
      get: () => proto.get!.call(el) as string,
      set: (v: string) => {
        tracked = v;
        proto.set!.call(el, v);
      },
    });
    el.addEventListener("input", () => {
      const dom = proto.get!.call(el) as string;
      if (dom !== tracked) {
        tracked = dom;
        state = dom;
      }
      el.value = state;
    });
    fill(s, formById(s, "login").ref, { username: "alex@atlas.dev" });
    expect(state).toBe("alex@atlas.dev");
    expect(el.value).toBe("alex@atlas.dev");
  });

  it("split_otp_filled", () => {
    setPage(`<form id="otp">${[1, 2, 3, 4, 5, 6].map((i) => `<input id="c${i}" maxlength="1" inputmode="numeric">`).join("")}</form>`);
    s = start();
    const f = formById(s, "otp");
    expect(f.kind).toBe("otp");
    expect(f.fields[0]!.parts).toHaveLength(6);
    const order: string[] = [];
    document.addEventListener("input", (e) => order.push((e.target as HTMLElement).id), true);
    fill(s, f.ref, { otp: "123456" });
    expect([1, 2, 3, 4, 5, 6].map((i) => input(`c${i}`).value).join(",")).toBe("1,2,3,4,5,6");
    expect(order).toEqual(["c1", "c2", "c3", "c4", "c5", "c6"]);
  });

  it("invisible_field_not_filled", () => {
    setPage(`
<form id="login">
  <input id="u" autocomplete="username">
  <input id="decoy" name="password" type="password" style="opacity:0">
  <input id="p" type="password" autocomplete="current-password">
</form>`);
    s = start();
    const f = formById(s, "login");
    // Hidden after the analysis was sent: still never written.
    input("u").style.display = "none";
    fill(s, f.ref, { username: "alex", current_password: "pw" });
    expect(input("u").value).toBe("");
    expect(input("decoy").value).toBe("");
    expect(input("p").value).toBe("pw");
  });

  it("fills expiry selects by value or text", () => {
    setPage(`
<form id="card">
  <input id="num" autocomplete="cc-number">
  <select id="m" autocomplete="cc-exp-month"><option value="">Mois</option><option value="m1">janvier</option><option value="m4">avril</option></select>
  <select id="y" autocomplete="cc-exp-year"><option value="">Year</option><option value="26">26</option><option value="27">27</option></select>
  <select id="m2" autocomplete="cc-exp-month" form="card2"><option>01</option><option>04</option></select>
</form>
<form id="card2"><input id="num2" autocomplete="cc-number"><input id="name2" autocomplete="cc-name">
  <select id="mm" autocomplete="cc-exp-month"><option value="1">1</option><option value="4">4</option></select>
  <select id="mon" autocomplete="cc-exp-month"><option value="x">--</option><option value="y">April</option></select>
</form>`);
    s = start();
    fill(s, formById(s, "card").ref, { cc_number: "4111111111111111", cc_exp_month: "04", cc_exp_year: "2027" });
    expect(input("num").value).toBe("4111111111111111");
    expect((document.getElementById("m") as HTMLSelectElement).value).toBe("m4");
    expect((document.getElementById("y") as HTMLSelectElement).value).toBe("27");
    fill(s, formById(s, "card2").ref, { cc_number: "4111111111111111", cc_exp_month: "04" });
    expect((document.getElementById("mm") as HTMLSelectElement).value).toBe("4");
    expect((document.getElementById("mon") as HTMLSelectElement).value).toBe("y");
    expect((document.getElementById("m2") as HTMLSelectElement).value).toBe("04");
  });
});

describe("re-rendered forms (B2)", () => {
  /**
   * A single-page app that replaces the form with a fresh clone on `input`
   * (same attributes): `copy` carries the values over, `times` is how many
   * input events re-render (Infinity: every one).
   */
  let stopRerender: (() => void) | null = null;
  afterEach(() => {
    stopRerender?.();
    stopRerender = null;
  });

  function rerenderOnInput(opts: { copy: boolean; times: number }): void {
    let left = opts.times;
    const onInput = () => {
      if (left <= 0) return;
      left--;
      const old = document.getElementById("login") as HTMLFormElement;
      const fresh = old.cloneNode(true) as HTMLFormElement;
      const from = old.querySelectorAll("input");
      const to = fresh.querySelectorAll("input");
      from.forEach((el, i) => (to[i]!.value = opts.copy ? el.value : ""));
      old.replaceWith(fresh);
    };
    document.addEventListener("input", onInput);
    const before = stopRerender;
    stopRerender = () => {
      document.removeEventListener("input", onInput);
      before?.();
    };
  }

  it("fill_resolves_detached_ref_again", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    rerenderOnInput({ copy: true, times: 1 });
    const first = input("u");
    expect(fill(s, f.ref, { username: "alex@atlas.dev", current_password: "pw-1" })).toEqual({ ok: true });
    expect(input("u")).not.toBe(first);
    expect(input("u").value).toBe("alex@atlas.dev");
    expect(input("p").value).toBe("pw-1");
  });

  it("refill_once_after_rerender_clears_value", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    rerenderOnInput({ copy: false, times: 1 });
    fill(s, f.ref, { username: "alex@atlas.dev", current_password: "pw-1" });
    expect(input("u").value).toBe("alex@atlas.dev");
    expect(input("p").value).toBe("pw-1");
  });

  it("endless_rerender_refills_once", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    rerenderOnInput({ copy: false, times: Number.POSITIVE_INFINITY });
    const writes: string[] = [];
    document.addEventListener("input", (e) => writes.push((e.target as HTMLElement).id), true);
    fill(s, f.ref, { username: "alex@atlas.dev", current_password: "pw-1" });
    // One fill, then a single second fill of the replaced fields; never more.
    expect(writes).toEqual(["u", "p", "u", "p"]);
  });

  it("a stale form ref is not resolved to a different form", () => {
    setPage(`${LOGIN}<form id="other"><input id="ou" autocomplete="username"><input id="op" type="password" autocomplete="current-password"></form>`);
    s = start();
    const f = formById(s, "login");
    document.getElementById("login")!.remove();
    expect(fill(s, f.ref, { username: "alex", current_password: "pw" })).toEqual({ ok: false });
    expect(input("ou").value).toBe("");
  });

  it("submits the re-rendered form for a stale form ref", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    rerenderOnInput({ copy: true, times: 1 });
    fill(s, f.ref, { username: "alex@atlas.dev" });
    let clicks = 0;
    document.getElementById("go")!.addEventListener("click", (e) => {
      clicks++;
      e.preventDefault();
    });
    expect(s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref })).toEqual({ ok: true });
    expect(clicks).toBe(1);
  });

  it("form identity reads attributes: fields named id or tagName do not blur two forms together", () => {
    const form = (id: string, p: string) =>
      `<form id="${id}"><input name="id" autocomplete="username"><input name="tagName" type="hidden"><input id="${p}" type="password" autocomplete="current-password"></form>`;
    setPage(form("login", "p") + form("other", "op"));
    // Browsers expose a form's controls as named properties of the form,
    // shadowing `form.id` and `form.tagName`; jsdom does not, so mimic it.
    const proto = HTMLFormElement.prototype;
    const saved = ["id", "tagName"].map((k) => [k, Object.getOwnPropertyDescriptor(Element.prototype, k)!] as const);
    for (const [k] of saved) {
      Object.defineProperty(proto, k, {
        configurable: true,
        get(this: HTMLFormElement) {
          return this.elements.namedItem(k);
        },
      });
    }
    stopRerender = () => {
      for (const [k] of saved) delete (proto as unknown as Record<string, unknown>)[k];
    };
    s = start();
    const f = analysis(s).forms.find((x) => s!.cs.internals.refs.get(x.ref)?.getAttribute("id") === "login")!;
    rerenderOnInput({ copy: true, times: 1 });
    fill(s, f.ref, { username: "alex@atlas.dev", current_password: "pw-1" });
    expect(input("p").value).toBe("pw-1");
    expect(input("op").value).toBe("");
  });
});

describe("late fields (B1)", () => {
  it("ArrowDown in a field added before the next analysis opens the menu", async () => {
    useTimers();
    setPage(`<div id="app"></div>`);
    s = start();
    s.ext.reply = () => ({ ok: { url: `${EXT_BASE}menu.html#${TOKEN}` } });
    document.getElementById("app")!.innerHTML = LOGIN;
    await flush();
    userKey(input("u"), "ArrowDown");
    await flush();
    expect(s.ext.ofType("open_menu")).toHaveLength(1);
  });

  it("analyses on such a key at most once per 150 ms", async () => {
    useTimers();
    setPage(`<div id="app"></div><div id="more"></div>`);
    s = start();
    s.ext.reply = () => ({ ok: null });
    document.getElementById("app")!.innerHTML = LOGIN;
    await flush();
    userKey(input("u"), "ArrowDown");
    expect(s.ext.ofType("page_analysis")).toHaveLength(2);
    document.getElementById("more")!.innerHTML = `<form id="b"><input id="bu" autocomplete="username"><input id="bp" type="password" autocomplete="current-password"></form>`;
    await flush();
    vi.advanceTimersByTime(100);
    userKey(input("bu"), "ArrowDown");
    // Within 150 ms of the last one: no analysis on the key, the observer's comes on time.
    expect(s.ext.ofType("page_analysis")).toHaveLength(2);
    vi.advanceTimersByTime(60);
    expect(s.ext.ofType("page_analysis")).toHaveLength(3);
  });
});

describe("submission watcher", () => {
  function creds(st: Started) {
    return st.ext.ofType("submitted_credentials").map((m) => [m.username, m.password, m.isNew]);
  }

  it("submission_captured_on_submit_click_enter_and_spa", async () => {
    useTimers();
    // 1. submit event (trusted, as dispatched by the browser) right after a
    // user gesture in the form.
    setPage(LOGIN);
    s = start();
    input("u").value = "alex@atlas.dev";
    input("p").value = "s3cret";
    const form = document.getElementById("login") as HTMLFormElement;
    form.addEventListener("submit", (e) => e.preventDefault());
    userClick(input("p"));
    form.requestSubmit();
    expect(creds(s)).toEqual([["alex@atlas.dev", "s3cret", false]]);
    // A forged (untrusted) submit event is ignored, and a second report within 2 s is deduplicated.
    form.dispatchEvent(new Event("submit", { bubbles: true }));
    expect(creds(s)).toHaveLength(1);
    s.cs.stop();

    // 2. click on the submit button (the browser's submit is deduplicated).
    setPage(LOGIN);
    s = start();
    vi.advanceTimersByTime(3000);
    input("u").value = "alex@atlas.dev";
    input("p").value = "click-pw";
    document.getElementById("login")!.addEventListener("submit", (e) => e.preventDefault());
    userClick(document.getElementById("go")!);
    expect(creds(s)).toEqual([["alex@atlas.dev", "click-pw", false]]);
    s.cs.stop();

    // 3. Enter in a field, outside any <form>.
    setPage(`<div id="box"><input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><div role="button" id="go">Sign in</div></div>`);
    s = start();
    vi.advanceTimersByTime(3000);
    input("u").value = "alex@atlas.dev";
    input("p").value = "enter-pw";
    input("p").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(creds(s)).toHaveLength(0);
    userKey(input("p"), "Enter");
    expect(creds(s)).toEqual([["alex@atlas.dev", "enter-pw", false]]);
    s.cs.stop();

    // 4. SPA: a plain button click, then the form disappears within 2 s.
    setPage(`<div id="app"><div id="box"><input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><button type="button" id="other">Go</button></div></div>`);
    s = start();
    vi.advanceTimersByTime(3000);
    input("u").value = "alex@atlas.dev";
    input("p").value = "spa-pw";
    userClick(document.getElementById("other")!);
    input("p").value = "";
    document.getElementById("box")!.remove();
    vi.advanceTimersByTime(1000);
    expect(creds(s)).toEqual([["alex@atlas.dev", "spa-pw", false]]);
    s.cs.stop();

    // 5. SPA: a click after which the form stays: nothing.
    setPage(`<div id="box"><input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><button type="button" id="other">Show password</button></div>`);
    s = start();
    vi.advanceTimersByTime(3000);
    input("u").value = "alex@atlas.dev";
    input("p").value = "stay-pw";
    userClick(document.getElementById("other")!);
    vi.advanceTimersByTime(2500);
    expect(creds(s)).toHaveLength(0);
  });

  it("does not report a submission triggered by page script alone", () => {
    useTimers();
    setPage(LOGIN);
    s = start();
    input("u").value = "alex@atlas.dev";
    input("p").value = "chosen-by-page";
    const form = document.getElementById("login") as HTMLFormElement;
    form.addEventListener("submit", (e) => e.preventDefault());
    form.requestSubmit();
    document.getElementById("go")!.click();
    expect(creds(s)).toHaveLength(0);
    // A user gesture that is too old does not count either.
    userClick(input("p"));
    vi.advanceTimersByTime(GESTURE_MS + 1);
    form.requestSubmit();
    expect(creds(s)).toHaveLength(0);
    // A gesture in the form within the window does.
    userClick(input("p"));
    vi.advanceTimersByTime(GESTURE_MS - 1000);
    form.requestSubmit();
    expect(creds(s)).toEqual([["alex@atlas.dev", "chosen-by-page", false]]);
    // A gesture in another form does not count.
    s.cs.stop();
    setPage(`${LOGIN}<form id="other"><input id="q" autocomplete="username"><input id="r" type="password" autocomplete="current-password"></form>`);
    s = start();
    input("u").value = "alex@atlas.dev";
    input("p").value = "chosen-by-page";
    (document.getElementById("login") as HTMLFormElement).addEventListener("submit", (e) => e.preventDefault());
    userClick(input("q"));
    (document.getElementById("login") as HTMLFormElement).requestSubmit();
    expect(creds(s)).toHaveLength(0);
  });

  it("uses navigator.userActivation when the browser has it", () => {
    setPage(LOGIN);
    const nav = window.navigator as Navigator & { userActivation?: { isActive: boolean } };
    const ua = { isActive: false };
    Object.defineProperty(nav, "userActivation", { configurable: true, value: ua });
    try {
      s = start();
      input("u").value = "alex@atlas.dev";
      input("p").value = "s3cret";
      const form = document.getElementById("login") as HTMLFormElement;
      form.addEventListener("submit", (e) => e.preventDefault());
      // Active page-wide after a click elsewhere: a script-only submit is not reported.
      document.body.insertAdjacentHTML("beforeend", `<button id="elsewhere" type="button">Menu</button>`);
      userClick(document.getElementById("elsewhere")!);
      ua.isActive = true;
      form.requestSubmit();
      expect(creds(s)).toHaveLength(0);
      // A gesture in the form, but no activation: nothing either.
      ua.isActive = false;
      userClick(input("p"));
      form.requestSubmit();
      expect(creds(s)).toHaveLength(0);
      ua.isActive = true;
      form.requestSubmit();
      expect(creds(s)).toEqual([["alex@atlas.dev", "s3cret", false]]);
    } finally {
      delete (nav as { userActivation?: unknown }).userActivation;
    }
  });

  it("forgets the dedupe key after 2 s and on stop", () => {
    useTimers();
    setPage(LOGIN);
    s = start();
    input("u").value = "alex@atlas.dev";
    input("p").value = "s3cret";
    document.getElementById("login")!.addEventListener("submit", (e) => e.preventDefault());
    userClick(document.getElementById("go")!);
    userClick(document.getElementById("go")!);
    expect(creds(s)).toHaveLength(1);
    vi.advanceTimersByTime(2000);
    userClick(document.getElementById("go")!);
    expect(creds(s)).toHaveLength(2);
    s.cs.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reports the new password of a signup form", () => {
    setPage(`<form id="s"><input id="e" type="email" autocomplete="email"><input id="n" type="password" autocomplete="new-password"><button id="go">Create</button></form>`);
    s = start();
    input("e").value = "alex@atlas.dev";
    input("n").value = "fresh-pw";
    document.getElementById("s")!.addEventListener("submit", (e) => e.preventDefault());
    userClick(document.getElementById("go")!);
    expect(creds(s)).toEqual([["alex@atlas.dev", "fresh-pw", true]]);
  });

  it("clicks and submits only for the pinned origin", () => {
    setPage(LOGIN);
    s = start();
    const f = formById(s, "login");
    let clicks = 0;
    document.getElementById("go")!.addEventListener("click", (e) => {
      clicks++;
      e.preventDefault();
    });
    s.ext.deliver({ type: "click", origin: "https://evil.test", ref: f.submitRef });
    s.ext.deliver({ type: "submit", origin: "https://evil.test", ref: f.ref });
    expect(clicks).toBe(0);
    s.ext.deliver({ type: "click", origin: ORIGIN, ref: f.submitRef });
    expect(clicks).toBe(1);
    s.ext.deliver({ type: "submit", origin: ORIGIN, ref: f.ref });
    expect(clicks).toBe(2);
  });
});

describe("observer", () => {
  it("sends page_analysis on start, then only when the analysis changes (150 ms)", async () => {
    useTimers();
    setPage(`<div id="app"></div>`);
    s = start();
    expect(s.ext.ofType("page_analysis")).toHaveLength(1);
    expect(analysis(s).forms).toHaveLength(0);
    expect(analysis(s).url).toBe(PAGE);

    document.getElementById("app")!.innerHTML = LOGIN;
    await flush();
    vi.advanceTimersByTime(100);
    expect(s.ext.ofType("page_analysis")).toHaveLength(1);
    vi.advanceTimersByTime(60);
    expect(s.ext.ofType("page_analysis")).toHaveLength(2);
    expect(analysis(s).forms.map((f) => f.kind)).toEqual(["login"]);
    // Icons follow the new analysis.
    expect(icons(s)).toHaveLength(2);

    // A mutation that changes nothing in the analysis sends nothing.
    document.getElementById("app")!.appendChild(document.createElement("span"));
    await flush();
    vi.advanceTimersByTime(200);
    expect(s.ext.ofType("page_analysis")).toHaveLength(2);

    // Removing the form is a change.
    document.getElementById("app")!.innerHTML = "";
    await flush();
    vi.advanceTimersByTime(200);
    expect(s.ext.ofType("page_analysis")).toHaveLength(3);
    expect(icons(s)).toHaveLength(0);
  });

  it("re-attaches the host when the page removes it", async () => {
    useTimers();
    setPage(LOGIN);
    s = start();
    document.documentElement.querySelector("onepass-root")!.remove();
    await flush();
    vi.advanceTimersByTime(200);
    expect(document.documentElement.querySelector("onepass-root")).not.toBeNull();
  });
});

describe("provider and account clicks (spec 8.7)", () => {
  it("reports a trusted click on a provider button, inner element included; ignores page clicks", () => {
    setPage(`${LOGIN}<button id="g" type="button"><span id="gs">Continuer avec Google</span></button>`);
    s = start();
    const btn = analysis(s).providerButtons[0]!;
    expect(btn.provider).toBe("google");
    document.getElementById("g")!.click();
    expect(s.ext.ofType("provider_click")).toEqual([]);
    userClick(document.getElementById("gs")!);
    expect(s.ext.ofType("provider_click")).toEqual([{ type: "provider_click", provider: "google", ref: btn.ref }]);
    // Elsewhere: nothing.
    userClick(document.getElementById("u")!);
    expect(s.ext.ofType("provider_click")).toHaveLength(1);
  });

  it("reports the account clicked on a provider's chooser", () => {
    setPage(`<ul><li><div id="a1" role="link" tabindex="0" data-identifier="alex.perso@example.com">Alex Martin</div></li>
      <li><div id="a2" role="link" tabindex="0"><span>Alex Martin</span><span id="a2e">alex.pro@example.com</span></div></li></ul>`);
    s = start("https://accounts.google.com/v3/signin/accountchooser");
    expect(analysis(s).accountChooser).toHaveLength(2);
    userClick(document.getElementById("a2e")!);
    const sent = s.ext.ofType("account_click");
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ type: "account_click", email: "alex.pro@example.com" });
  });
});
