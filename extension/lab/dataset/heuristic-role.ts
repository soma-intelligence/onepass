// The existing heuristic classifier (`classifyField`) on a dataset row (Task 16). A row keeps the
// field's features, not its element, so the field is rebuilt as the extractor read it: a control
// with its attributes, a <label> with the label text, and the text before it as a sibling. This
// is an approximation (no form context, `cardForm` true, no signup read over the form) and says so
// in the report. Bundled by esbuild and run in jsdom by heuristic-eval.ts (src imports carry no
// extension, which node's type stripping cannot resolve).
import { classifyField, type FieldElement } from "../../src/content/detect/fields.ts";
import type { FieldFeatures } from "../../src/content/detect/features.ts";
import type { FieldRole } from "../../src/shared/messages.ts";
import { macroF1, mergedMacroF1 } from "./f1.ts";

const LABEL_OF: Partial<Record<FieldRole, string>> = {
  current_password: "password", new_password: "new_password", confirm_password: "new_password", bday: "birth_date",
  username: "username", email: "email", otp: "otp", cc_name: "cc_name", cc_number: "cc_number", cc_exp: "cc_exp",
  cc_exp_month: "cc_exp_month", cc_exp_year: "cc_exp_year", cc_csc: "cc_csc", given_name: "given_name",
  family_name: "family_name", tel: "tel", organization: "organization", address_line1: "address_line1",
  address_line2: "address_line2", postal_code: "postal_code", city: "city", country: "country",
};

function build(doc: Document, f: FieldFeatures): FieldElement {
  const box = doc.createElement("div");
  if (f.before) {
    const s = doc.createElement("span");
    s.textContent = f.before;
    box.append(s);
  }
  const el = doc.createElement(f.tag === "select" ? "select" : f.tag === "textarea" ? "textarea" : "input") as FieldElement;
  if (el instanceof HTMLInputElement && f.type) el.type = f.type;
  const set = (k: string, v: string | undefined) => { if (v !== undefined && v !== "") el.setAttribute(k, v); };
  set("name", f.name); set("id", f.id); set("autocomplete", f.autocomplete); set("placeholder", f.placeholder);
  set("aria-label", f.ariaLabel); set("inputmode", f.inputmode);
  if (f.maxlength !== undefined) el.setAttribute("maxlength", String(f.maxlength));
  if (f.label) {
    const l = doc.createElement("label");
    l.textContent = f.label;
    if (f.id) {
      l.setAttribute("for", f.id);
      box.append(l, el);
    } else {
      l.append(el);
      box.append(l);
    }
  } else box.append(el);
  doc.body.append(box);
  return el;
}

/** Dataset label (Role or "none") the heuristic gives a field. */
export function heuristicLabel(f: FieldFeatures, doc: Document = document): string {
  const el = build(doc, f);
  try {
    return LABEL_OF[classifyField(el).role] ?? "none";
  } finally {
    el.closest("div")?.remove();
  }
}

/** Rows scored and the heuristic's macro F1 against their `target`, plain and with password classes merged (R23); null without rows. */
export function heuristicRows(rows: (FieldFeatures & { target: string })[], doc: Document = document): { rows: number; macroF1: number | null; mergedF1: number | null } {
  if (rows.length === 0) return { rows: 0, macroF1: null, mergedF1: null };
  const truth = rows.map((r) => r.target);
  const pred = rows.map((r) => heuristicLabel(r, doc));
  return { rows: rows.length, macroF1: macroF1(truth, pred), mergedF1: mergedMacroF1(truth, pred) };
}
