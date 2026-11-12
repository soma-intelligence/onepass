// The ghost (spec 3.2, 3.5): an extension frame laid over an empty new-password field, showing the
// password the worker holds for it in grey, in the field's own type metrics, and at the field's
// right edge a pill: "Use" with a "Tab" keycap, and a chevron that opens the menu on the same
// suggestion. The password lives here and in the worker only until the user accepts it; the page
// sees neither. The keys (Tab, Enter, Escape, Arrow Down) are read by the content script on the
// field itself; this page only takes the pill's clicks, behind the frames' click guard.
//
// The frame lets the pointer through to the field except over the pill: the page reports the
// pill's box (`ghost_pill`), and again when the pointer leaves it, which the content script
// cannot see while the frame has the pointer.
import { ext } from "../shared/browser";
import { t } from "../shared/i18n";
import type { GhostMetrics, SuggestionPreview } from "../shared/messages";
import { ClickGuard, type FrameDeps, call, h, icon, mount, observeVisibility, tokenFromHash } from "./components";
import { parseEmpty, parseGhostInit } from "./parse";

export interface GhostHandle {
  ready: Promise<void>;
}

/** The field's type metrics on the ghost's box (the grey preview may use another face). */
function applyMetrics(box: HTMLElement, m: GhostMetrics): void {
  const s = box.style;
  s.fontSize = `${m.fontSize}px`;
  s.lineHeight = `${m.lineHeight}px`;
  s.paddingLeft = `${m.paddingLeft}px`;
  s.paddingRight = `${m.paddingRight}px`;
  s.textAlign = m.textAlign;
  // A local face of the field; none (a web font of the page): the mono face of `.mono`.
  if (m.fontFamily !== null) s.fontFamily = m.fontFamily;
}

export function mountGhost(root: HTMLElement, deps: FrameDeps): GhostHandle {
  const now = deps.now ?? (() => performance.now());
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  mount(root);

  const render = (p: SuggestionPreview & { metrics: GhostMetrics }) => {
    if (!token) return;
    let done = false;
    const send = (type: "ghost_accept" | "ghost_menu") => {
      if (done) return;
      done = true;
      void call(deps.send, { type, token }, parseEmpty);
    };
    const use = h(
      "button",
      { class: "ghost-use", attrs: { type: "button" }, on: { click: guard.wrap(() => send("ghost_accept")) } },
      t("ghost.use"),
      " ",
      h("kbd", null, t("ghost.tab")),
    );
    const more = h(
      "button",
      { class: "ghost-more", attrs: { type: "button", "aria-label": t("ghost.more") }, on: { click: guard.wrap(() => send("ghost_menu")) } },
      icon("chevron", 12),
    );
    const pill = h("span", { class: "ghost-pill" }, use, more);
    const text = h("span", { class: p.metrics.fontFamily === null ? "ghost-text mono" : "ghost-text" }, p.password);
    const box = h("div", { class: "ghost" }, text, pill);
    applyMetrics(box, p.metrics);
    mount(root, box);
    (deps.observe ?? observeVisibility)(pill, (v) => guard.setVisibility(v));

    // The pill's box in this frame, for the content script's pointer pass-through.
    const report = () => {
      const r = pill.getBoundingClientRect();
      const rect = { x: Math.max(0, r.left), y: Math.max(0, r.top), width: Math.max(0, r.width), height: Math.max(0, r.height) };
      void call(deps.send, { type: "ghost_pill", token, rect, over: false }, parseEmpty);
    };
    report();
    pill.addEventListener("pointerleave", report);
    root.ownerDocument.defaultView?.addEventListener("resize", report);
  };

  const load = async () => {
    if (!token) return;
    const r = await call(deps.send, { type: "ghost_init", token }, parseGhostInit);
    // Gone or refused: nothing shows (the content script removes the frame).
    if (r.ok) render(r.value);
  };

  return { ready: load() };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountGhost(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
