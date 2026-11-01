// ARIA comboboxes (React-select, Downshift, MUI Autocomplete...) for the
// country and region roles (spec 2026-10-31, section 3.5): the name is
// typed as a keystroke would write it, the matching `role=option` of the
// combobox's list is pressed (pointer and mouse events, then click: the
// event path the filler and submit.ts already use), and a hidden native
// select that backs the widget gets the same choice (section 4).
import type { OptionLike } from "./geo/options";

/** A text input that drives a list of options. */
export function isCombobox(el: Element): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement)) return false;
  const role = (el.getAttribute("role") ?? "").toLowerCase();
  const auto = (el.getAttribute("aria-autocomplete") ?? "").toLowerCase();
  const popup = (el.getAttribute("aria-haspopup") ?? "").toLowerCase();
  return role === "combobox" || auto === "list" || auto === "both" || popup === "listbox";
}

type Root = Document | ShadowRoot;

const rootOf = (el: Element): Root => {
  const r = el.getRootNode();
  return r instanceof ShadowRoot ? r : el.ownerDocument;
};

const byIds = (root: Root, ids: string | null): Element[] =>
  (ids ?? "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => root.getElementById(id) ?? (root !== root.ownerDocument ? root.ownerDocument?.getElementById(id) : null) ?? null)
    .filter((x): x is HTMLElement => x !== null);

/** The list the combobox shows: named by ARIA, else the one next to it. */
export function listOf(input: HTMLInputElement): Element | null {
  const root = rootOf(input);
  for (const attr of ["aria-controls", "aria-owns"]) {
    for (const el of byIds(root, input.getAttribute(attr))) {
      if (el.matches('[role="listbox"]')) return el;
      const inner = el.querySelector('[role="listbox"]');
      if (inner) return inner;
    }
  }
  const active = byIds(root, input.getAttribute("aria-activedescendant"))[0];
  const fromActive = active?.closest('[role="listbox"]');
  if (fromActive) return fromActive;
  // A list rendered next to the input, within the widget.
  let n: Element | null = input.parentElement;
  for (let i = 0; n && i < 4; n = n.parentElement, i++) {
    const l = n.querySelector('[role="listbox"]');
    if (l) return l;
  }
  return null;
}

/** What a press could activate besides choosing: never pressed, nor anything holding or inside one. */
const ACTIVE = 'a[href], area[href], button, input, select, textarea, form, [contenteditable=""], [contenteditable="true"]';

/** The enabled options of the combobox's list, in order (none that is, holds or sits in a control or a link). */
export function optionsOf(input: HTMLInputElement): HTMLElement[] {
  const list = listOf(input);
  if (!list) return [];
  return Array.from(list.querySelectorAll<HTMLElement>('[role="option"]')).filter((o) => {
    if (o.getAttribute("aria-disabled") === "true" || o.hasAttribute("disabled")) return false;
    const up = o.parentElement?.closest(ACTIVE);
    // An inline list inside the form is fine; a control or a link around the option is not.
    if (up && !(up instanceof HTMLFormElement)) return false;
    return !o.matches(ACTIVE) && o.querySelector(ACTIVE) === null;
  });
}

/** An option as a list entry: its value attribute when it has one, else its text (never a placeholder). */
export const optionLike = (o: HTMLElement): OptionLike => {
  const text = (o.textContent ?? "").replace(/\s+/g, " ").trim();
  return { value: o.getAttribute("data-value") ?? o.getAttribute("value") ?? text, text };
};

/** Presses `el` as a pointer would: down, up, click. */
export function press(el: Element): void {
  const init = { bubbles: true, composed: true, cancelable: true, button: 0, buttons: 1 };
  const view = el.ownerDocument.defaultView;
  const Pointer = view && "PointerEvent" in view ? (view.PointerEvent as typeof PointerEvent) : null;
  if (Pointer) el.dispatchEvent(new Pointer("pointerdown", { ...init, pointerType: "mouse", isPrimary: true }));
  el.dispatchEvent(new MouseEvent("mousedown", init));
  if (Pointer) el.dispatchEvent(new Pointer("pointerup", { ...init, buttons: 0, pointerType: "mouse", isPrimary: true }));
  el.dispatchEvent(new MouseEvent("mouseup", { ...init, buttons: 0 }));
  el.dispatchEvent(new MouseEvent("click", { ...init, buttons: 0 }));
}

/**
 * The hidden native select behind the widget: in the closest container of
 * the input (4 levels at most) that holds no other visible field, not
 * visible itself. Null when there is none, or more than one.
 */
export function backingSelect(input: HTMLInputElement, visible: (el: Element) => boolean): HTMLSelectElement | null {
  let n: Element | null = input.parentElement;
  for (let i = 0; n && i < 4; n = n.parentElement, i++) {
    const fields = Array.from(n.querySelectorAll("input, select, textarea")).filter(
      (f) => f !== input && !(f instanceof HTMLInputElement && f.type === "hidden"),
    );
    if (fields.some((f) => visible(f))) return null;
    const selects = fields.filter((f): f is HTMLSelectElement => f instanceof HTMLSelectElement);
    if (selects.length > 1) return null;
    if (selects.length === 1) return selects[0]!;
  }
  return null;
}
