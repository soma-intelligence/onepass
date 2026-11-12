// Task 7: the ghost's triggers and keys in the content script (spec 3.1, 3.3, 3.4, 3.5). A trusted
// focus with a recent gesture into an empty new-password field of a signup or change-password form
// asks the worker for the ghost; Tab or Enter accept, a printable key or Escape dismiss, Arrow Down
// opens the menu on its suggestion. The password itself never reaches this script.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Layout } from "../../src/content/frames";
import type { PageAnalysis } from "../../src/shared/messages";
import { asUser, EXT_BASE, flush, input, PAGE, setPage, start, type Started, TOKEN, userClick, userKey } from "./harness";

const SIGNUP = `
<form id="s">
  <input id="e" type="email" autocomplete="email">
  <input id="n" type="password" autocomplete="new-password">
  <input id="c" type="password" autocomplete="new-password">
  <button id="go" type="submit">Create account</button>
</form>`;

const LOGIN = `
<form id="login">
  <input id="u" name="username" autocomplete="username">
  <input id="p" type="password" autocomplete="current-password">
  <button id="go" type="submit">Sign in</button>
</form>`;

/** The password the worker holds for the ghost; it must never show up on this side. */
const SECRET = "Zq8!vRt2#mKw9@pLx4";
const GHOST_URL = `${EXT_BASE}ghost.html#${TOKEN}`;
const MENU_URL = `${EXT_BASE}menu.html#${TOKEN}`;

let s: Started | null = null;
beforeEach(() => {
  s = null;
});
afterEach(() => {
  s?.cs.stop();
  vi.restoreAllMocks();
});

/** The worker: a ghost URL for ghost_open, a menu URL for ghost_menu and open_menu. */
function worker(st: Started): void {
  st.ext.reply = (m) => {
    switch ((m as { type: string }).type) {
      case "ghost_open":
        return { ok: { url: GHOST_URL } };
      case "ghost_menu":
      case "open_menu":
        return { ok: { url: MENU_URL } };
      default:
        return { ok: {} };
    }
  };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 4; i++) {
    await flush();
    await new Promise((r) => setTimeout(r, 0));
  }
}

/** Gives `el` a laid out box wide enough for the ghost (jsdom has no layout). */
function wide(el: HTMLElement, width = 240): void {
  const r = { x: 10, y: 20, width, height: 36 };
  el.getBoundingClientRect = () =>
    ({ ...r, left: r.x, top: r.y, right: r.x + r.width, bottom: r.y + r.height, toJSON: () => r }) as DOMRect;
}

/** A user's press into `el`: the pointer goes down, the field takes the focus, the click lands. */
function userFocus(el: HTMLElement): void {
  asUser(el, new MouseEvent("pointerdown", { bubbles: true, composed: true, cancelable: true }));
  el.focus();
  asUser(el, new MouseEvent("mousedown", { bubbles: true, composed: true, cancelable: true }));
  userClick(el);
}

const ghostFrame = (st: Started) => st.cs.internals.root.querySelector<HTMLIFrameElement>("iframe.ghost");
const menuFrame = (st: Started) =>
  Array.from(st.cs.internals.root.querySelectorAll("iframe")).find((f) => f.getAttribute("src")?.includes("menu.html")) ?? null;

function analysis(st: Started): PageAnalysis {
  const all = st.ext.ofType("page_analysis");
  return all[all.length - 1]?.analysis as PageAnalysis;
}

function refOf(st: Started, id: string): { formRef: string; fieldRef: string } {
  for (const f of analysis(st).forms) {
    for (const x of f.fields) if ((st.cs.internals.refs.get(x.ref) as HTMLElement | null)?.id === id) return { formRef: f.ref, fieldRef: x.ref };
  }
  throw new Error(`no field #${id}`);
}

/** A signup page with the ghost shown over #n. */
async function ghostShown(extra: Parameters<typeof start>[1] = {}, href = PAGE): Promise<Started> {
  setPage(SIGNUP);
  wide(input("n"));
  const st = start(href, extra);
  worker(st);
  await settle();
  userFocus(input("n"));
  await settle();
  expect(ghostFrame(st)).not.toBeNull();
  return st;
}

describe("ghost triggers (spec 3.1)", () => {
  it("opens on trusted focus into a signup new-password field", async () => {
    s = await ghostShown();
    const { formRef, fieldRef } = refOf(s, "n");
    expect(s.ext.ofType("ghost_open")).toEqual([
      {
        type: "ghost_open",
        fieldRef,
        formRef,
        formKind: "signup",
        metrics: expect.objectContaining({ box: { x: 10, y: 20, width: 240, height: 36 } }),
      },
    ]);
    expect(ghostFrame(s)!.getAttribute("src")).toBe(GHOST_URL);
    // The ghost instead of the menu: the click that came with the focus asks for no menu.
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    expect(menuFrame(s)).toBeNull();
  });

  it("ghost needs a trusted focus", async () => {
    setPage(SIGNUP);
    wide(input("n"));
    s = start();
    worker(s);
    await settle();
    // Page script moves the focus, no gesture of the user: nothing.
    input("n").focus();
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    input("n").blur();
    // A gesture, then a forged focus event: nothing either.
    asUser(input("e"), new MouseEvent("pointerdown", { bubbles: true, composed: true }));
    input("n").dispatchEvent(new FocusEvent("focusin", { bubbles: true, composed: true }));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    // A gesture older than a second does not vouch for a later focus.
    const t0 = Date.now();
    asUser(input("e"), new MouseEvent("pointerdown", { bubbles: true, composed: true }));
    vi.spyOn(Date, "now").mockReturnValue(t0 + 1001);
    input("n").focus();
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    expect(ghostFrame(s)).toBeNull();
  });

  it("not on a sign-in form", async () => {
    setPage(LOGIN);
    wide(input("p"));
    s = start();
    worker(s);
    await settle();
    userFocus(input("p"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    expect(ghostFrame(s)).toBeNull();
    // The menu, as before, on a click into an empty field of a sign-in form.
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
  });

  it("not into a filled field", async () => {
    setPage(SIGNUP);
    wide(input("n"));
    s = start();
    worker(s);
    await settle();
    input("n").value = "typed";
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
  });

  it("a keyboard Tab into the field is a gesture too", async () => {
    setPage(SIGNUP);
    wide(input("n"));
    s = start();
    worker(s);
    await settle();
    input("e").focus();
    userKey(input("e"), "Tab");
    input("n").focus();
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(1);
    expect(ghostFrame(s)).not.toBeNull();
  });
});

describe("ghost keys (spec 3.3)", () => {
  it("Tab accepts and is not passed to the page", async () => {
    s = await ghostShown();
    const seen: string[] = [];
    input("n").addEventListener("keydown", (e) => seen.push(e.key));
    const e = userKey(input("n"), "Tab");
    await settle();
    expect(e.defaultPrevented).toBe(true);
    expect(seen).toEqual([]);
    expect(s.ext.ofType("ghost_accept")).toEqual([{ type: "ghost_accept" }]);
    // Accepted: the ghost frame is gone at once.
    expect(ghostFrame(s)).toBeNull();
    // The worker's fill lands in the field.
    const { formRef } = refOf(s, "n");
    s.ext.deliver({ type: "fill", origin: "https://atlas-cloud.test", formRef, values: { new_password: "filled-by-worker" } });
    expect(input("n").value).toBe("filled-by-worker");
  });

  it("Enter accepts", async () => {
    s = await ghostShown();
    let submitted = 0;
    document.getElementById("s")!.addEventListener("submit", (ev) => {
      ev.preventDefault();
      submitted++;
    });
    const e = userKey(input("n"), "Enter");
    await settle();
    expect(e.defaultPrevented).toBe(true);
    expect(submitted).toBe(0);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(1);
    expect(ghostFrame(s)).toBeNull();
  });

  it("typing dismisses and the key reaches the field", async () => {
    s = await ghostShown();
    const seen: string[] = [];
    input("n").addEventListener("keydown", (e) => seen.push(e.key));
    const e = userKey(input("n"), "a");
    await settle();
    expect(e.defaultPrevented).toBe(false);
    expect(seen).toEqual(["a"]);
    expect(s.ext.ofType("ghost_dismiss")).toEqual([{ type: "ghost_dismiss" }]);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(0);
    expect(ghostFrame(s)).toBeNull();
  });

  it("Escape dismisses and the ghost does not come back on refocus", async () => {
    let href = PAGE;
    s = await ghostShown({ href: () => href });
    userKey(input("n"), "Escape");
    await settle();
    expect(s.ext.ofType("ghost_dismiss")).toHaveLength(1);
    expect(ghostFrame(s)).toBeNull();
    input("e").focus();
    await settle();
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(1);
    expect(ghostFrame(s)).toBeNull();
    // A dismissed field is a plain empty field again: the click into it offers the menu (auto).
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
    s.ext.deliver({ type: "remove_frame", kind: "menu" });
    // The page navigates (same document, a new URL): the field gets its ghost again.
    href = `${PAGE}/next`;
    input("e").focus();
    await settle();
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(2);
    expect(ghostFrame(s)).not.toBeNull();
  });

  it("a field replaced by the page is not dismissed", async () => {
    s = await ghostShown();
    userKey(input("n"), "Escape");
    await settle();
    // The page swaps the field for a new one.
    const fresh = input("n").cloneNode(true) as HTMLInputElement;
    input("n").replaceWith(fresh);
    wide(fresh);
    await new Promise((r) => setTimeout(r, 200));
    await settle();
    userFocus(fresh);
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(2);
  });

  it("ArrowDown opens the menu", async () => {
    s = await ghostShown();
    const e = userKey(input("n"), "ArrowDown");
    await settle();
    expect(e.defaultPrevented).toBe(true);
    expect(s.ext.ofType("ghost_menu")).toEqual([{ type: "ghost_menu" }]);
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    expect(ghostFrame(s)).toBeNull();
    expect(menuFrame(s)?.getAttribute("src")).toBe(MENU_URL);
  });

  it("fallback opens the menu when fitGhost says narrow", async () => {
    setPage(SIGNUP);
    // No box from jsdom: zero wide, under MIN_GHOST_WIDTH.
    s = start();
    worker(s);
    await settle();
    userFocus(input("n"));
    await settle();
    const { fieldRef } = refOf(s, "n");
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    // Once, from the focus (the click that came with it asks nothing more).
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ fieldRef, formKind: "signup", auto: true })]);
    expect(menuFrame(s)).not.toBeNull();
    expect(ghostFrame(s)).toBeNull();
  });

  it("blur removes without dismissing", async () => {
    s = await ghostShown();
    input("e").focus();
    await settle();
    expect(ghostFrame(s)).toBeNull();
    expect(s.ext.ofType("ghost_dismiss")).toHaveLength(0);
    // Not dismissed: the next focus of the user brings it back.
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(2);
    expect(ghostFrame(s)).not.toBeNull();
  });

  it("a click on the ghost's pill (focus into the ghost frame) keeps the ghost", async () => {
    s = await ghostShown();
    const frame = ghostFrame(s)!;
    frame.focus();
    await settle();
    expect(s.cs.internals.root.activeElement).toBe(frame);
    expect(ghostFrame(s)).toBe(frame);
    expect(s.ext.ofType("ghost_dismiss")).toHaveLength(0);
    // The worker removes it once the pill accepted.
    s.ext.deliver({ type: "remove_frame", kind: "ghost" });
    expect(ghostFrame(s)).toBeNull();
  });

  it("Tab without a ghost moves focus as usual", async () => {
    setPage(LOGIN);
    s = start();
    worker(s);
    await settle();
    input("p").focus();
    const e = userKey(input("p"), "Tab");
    await settle();
    expect(e.defaultPrevented).toBe(false);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(0);
    // Nor after the ghost went (dismissed by Escape).
    s.cs.stop();
    s = await ghostShown();
    userKey(input("n"), "Escape");
    const t = userKey(input("n"), "Tab");
    await settle();
    expect(t.defaultPrevented).toBe(false);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(0);
  });

  it("keys from page script do nothing to the ghost", async () => {
    s = await ghostShown();
    const e = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    input("n").dispatchEvent(e);
    await settle();
    expect(e.defaultPrevented).toBe(false);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(0);
    expect(ghostFrame(s)).not.toBeNull();
  });
});

describe("ghost fix round 1", () => {
  it("a field inside an open shadow root, hit by the field's own root, gets a ghost", async () => {
    document.documentElement.innerHTML = `<head></head><body><div id="host"></div></body>`;
    const host = document.getElementById("host")!;
    const root = host.attachShadow({ mode: "open" });
    root.innerHTML = SIGNUP;
    const field = root.getElementById("n") as HTMLInputElement;
    wide(field);
    // As a browser does: the document's hit test sees the host, the shadow root's the field.
    s = start(undefined, { hitTest: () => host, fieldHitTest: (el) => el });
    worker(s);
    await settle();
    userFocus(field);
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(1);
    expect(ghostFrame(s)).not.toBeNull();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
  });

  it("a field really covered by another element gets the menu", async () => {
    setPage(`${SIGNUP}<div id="cover"></div>`);
    wide(input("n"));
    const cover = document.getElementById("cover")!;
    s = start(undefined, { fieldHitTest: (el, x) => (x > 200 ? cover : el) });
    worker(s);
    await settle();
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
    expect(ghostFrame(s)).toBeNull();
  });

  it("the keyup of an accepted Enter never reaches the page", async () => {
    s = await ghostShown();
    const ups: string[] = [];
    input("n").addEventListener("keyup", (e) => ups.push(e.key));
    document.addEventListener("keyup", (e) => ups.push(`doc:${e.key}`));
    userKey(input("n"), "Enter");
    const up = asUser(input("n"), new KeyboardEvent("keyup", { key: "Enter", bubbles: true, composed: true, cancelable: true }));
    await settle();
    expect(up.defaultPrevented).toBe(true);
    expect(ups).toEqual([]);
    expect(s.ext.ofType("ghost_accept")).toHaveLength(1);
    // Only that one keyup: the next is the page's again.
    asUser(input("n"), new KeyboardEvent("keyup", { key: "Enter", bubbles: true, composed: true, cancelable: true }));
    expect(ups).toEqual(["Enter", "doc:Enter"]);
  });

  it("focus leaving the ghost frame for the body drops the ghost, not dismissed", async () => {
    s = await ghostShown();
    const frame = ghostFrame(s)!;
    frame.focus();
    await settle();
    expect(ghostFrame(s)).toBe(frame);
    frame.blur();
    await settle();
    expect(document.activeElement).toBe(document.body);
    expect(ghostFrame(s)).toBeNull();
    expect(s.ext.ofType("ghost_dismiss")).toHaveLength(0);
    // Not dismissed: the user's next focus brings it back.
    userFocus(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(2);
  });

  it("a ghost the frames drop (field scrolled out) comes back on a click into the still focused field", async () => {
    s = await ghostShown();
    input("n").setAttribute("data-test-rect", "0,5000,240,36");
    window.dispatchEvent(new Event("scroll"));
    await settle();
    expect(ghostFrame(s)).toBeNull();
    expect(document.activeElement).toBe(input("n"));
    input("n").removeAttribute("data-test-rect");
    userClick(input("n"));
    await settle();
    expect(s.ext.ofType("ghost_open")).toHaveLength(2);
    expect(ghostFrame(s)).not.toBeNull();
  });
});

describe("ghost on touch layouts (ruling: the menu instead)", () => {
  it("a trusted tap on touch opens the menu on its suggestion row, never a ghost", async () => {
    setPage(SIGNUP);
    wide(input("n"));
    s = start(undefined, { layout: () => ({ touch: true, sheet: false }) });
    worker(s);
    await settle();
    userFocus(input("n"));
    await settle();
    const { fieldRef } = refOf(s, "n");
    expect(s.ext.ofType("ghost_open")).toHaveLength(0);
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ fieldRef, formKind: "signup", auto: true })]);
    expect(ghostFrame(s)).toBeNull();
  });

  it("a tap into the already focused field on touch opens the menu too", async () => {
    setPage(SIGNUP);
    wide(input("n"));
    s = start(undefined, { layout: () => ({ touch: true, sheet: false }) });
    worker(s);
    await settle();
    input("n").focus(); // page script: nothing
    await settle();
    expect(s.ext.ofType("open_menu")).toHaveLength(0);
    asUser(input("n"), new MouseEvent("pointerdown", { bubbles: true, composed: true }));
    await settle();
    expect(s.ext.ofType("open_menu")).toEqual([expect.objectContaining({ auto: true })]);
  });

  it("the layout flipping to touch while the ghost shows drops it", async () => {
    let layout: Layout = { touch: false, sheet: false };
    s = await ghostShown({ layout: () => layout });
    layout = { touch: true, sheet: false };
    window.dispatchEvent(new Event("resize"));
    await settle();
    expect(ghostFrame(s)).toBeNull();
    expect(s.ext.ofType("ghost_dismiss")).toHaveLength(0);
  });
});

describe("ghost secret (spec 3.5, S1)", () => {
  it("the suggested password never reaches the page DOM nor the content script", async () => {
    // A worker that holds SECRET: it answers it to the ghost page's own call (`ghost_init`) only,
    // as the real one does; this side gets the ghost's URL. Every reply the script got is kept.
    setPage(SIGNUP);
    wide(input("n"));
    s = start();
    const replies: unknown[] = [];
    s.ext.reply = (m) => {
      const type = (m as { type: string }).type;
      const r =
        type === "ghost_init"
          ? { ok: { password: SECRET, strength: 4, length: SECRET.length } }
          : type === "ghost_open"
            ? { ok: { url: GHOST_URL } }
            : { ok: {} };
      replies.push(structuredClone(r));
      return r;
    };
    const received: unknown[] = [];
    s.ext.listeners.unshift((m) => void received.push(structuredClone(m)));
    await settle();
    userFocus(input("n"));
    await settle();
    expect(ghostFrame(s)).not.toBeNull();
    // The ghost page reports its pill (through the worker): a box, never the text.
    s.ext.deliver({ type: "ghost_pill", rect: { x: 150, y: 4, width: 60, height: 24 }, over: false });
    await settle();
    expect(s.ext.ofType("ghost_init")).toHaveLength(0);
    const shadow = s.cs.internals.root.innerHTML;
    for (const seen of [document.documentElement.outerHTML, shadow, JSON.stringify(s.ext.sent), JSON.stringify(received), JSON.stringify(replies)]) {
      expect(seen).not.toContain(SECRET);
    }
    // Nor once accepted: the fill message is the worker's, the content script sent no value.
    userKey(input("n"), "Tab");
    await settle();
    expect(JSON.stringify(s.ext.sent)).not.toContain(SECRET);
    expect(ghostFrame(s)).toBeNull();
  });
});
