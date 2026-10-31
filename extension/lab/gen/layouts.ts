// Field layouts of the autofill lab forms (generator version 2): where a
// field's label sits, or whether there is one at all. Real pages put it
// above the field ("stacked", the version 1 look), inside it (floating label),
// only as a placeholder, on the left, in a two-column grid, as plain text
// before the field, or inside a card. Every layout keeps a name the field
// extractor can read (label, preceding text or placeholder). Pure string
// builders: no DOM, no clock, no randomness.
import type { LayoutId } from "./model.ts";

export const LAYOUTS: LayoutId[] = ["stacked", "floating", "placeholder_only", "side_label", "grid", "inline", "card"];

const LAYOUT_CSS: Record<LayoutId, string> = {
  stacked: "",
  floating: ".lab-float{position:relative}.lab-float input{padding-top:18px}"
    + ".lab-float label{position:absolute;left:11px;top:4px;font-size:11px;font-weight:500;color:#6e6e73}",
  placeholder_only: "",
  side_label: ".lab-side{display:grid;grid-template-columns:40% 1fr;align-items:center;gap:10px}.lab-side label{margin:0}",
  grid: ".lab-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}",
  inline: ".lab-inline{display:flex;align-items:center;gap:8px}.lab-inline .lab-text{flex:0 0 35%;font-size:13px}",
  card: ".lab-card{padding:16px;margin:0 0 14px;border:1px solid #e3e3e8;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08)}",
};

/** Escaping is the caller's (render-forms.ts): `label` and `id` arrive escaped. */
export interface LaidField { id: string; label: string; select: boolean; control: (extraAttrs: string) => string }

/** One field in `layout`: its label (or the text standing for it) and its control. */
export function layoutField(layout: LayoutId, f: LaidField): string {
  const label = `<label for="${f.id}">${f.label}</label>`;
  switch (layout) {
    case "floating":
      // The empty placeholder lets CSS tell an empty field from a filled one, as floating labels do.
      return `<div class="field lab-float">${f.control(f.select ? "" : ' placeholder=" "')}${label}</div>`;
    case "placeholder_only":
      return `<div class="field">${f.control(f.select ? ` aria-label="${f.label}"` : ` placeholder="${f.label}"`)}</div>`;
    case "side_label":
      return `<div class="field lab-side">${label}${f.control("")}</div>`;
    case "inline":
      return `<div class="field lab-inline"><span class="lab-text">${f.label}</span>${f.control("")}</div>`;
    default:
      return `<div class="field">${label}${f.control("")}</div>`;
  }
}

/** The fields of a form grouped as `layout` groups them (grid, card), unchanged otherwise. */
export function layoutGroup(layout: LayoutId, fields: string): string {
  if (layout === "grid") return `<div class="lab-grid">${fields}</div>`;
  if (layout === "card") return `<div class="lab-card">${fields}</div>`;
  return fields;
}

/** The stylesheet a layout adds to the shared one ("" for layouts the shared one covers). */
export function layoutCss(layout: LayoutId): string {
  return LAYOUT_CSS[layout];
}
