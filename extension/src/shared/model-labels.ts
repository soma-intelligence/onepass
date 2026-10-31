// Class labels of the field classifiers (models A and B): the lab Role list plus "none", in the
// order of `Role` in lab/gen/model.ts and of ml/onepass_ml/labels.py (the index of a label is the
// class index of every model). Kept here because src never imports lab/; a test compares the three.

export const MODEL_ROLES = [
  "username", "email", "password", "new_password", "otp", "cc_name", "cc_number", "cc_exp",
  "cc_exp_month", "cc_exp_year", "cc_csc", "given_name", "family_name", "tel", "birth_date",
  "organization", "address_line1", "address_line2", "postal_code", "city", "country",
] as const;

export type ModelRole = (typeof MODEL_ROLES)[number];
export type ModelLabel = ModelRole | "none";

/**
 * Most fields of one form sent to the model: the content script never asks for more (bigger forms
 * keep their heuristic roles), the router drops a bigger `classify` message and the worker's
 * budget refuses one.
 */
export const MAX_CLASSIFY_FIELDS = 64;

export const MODEL_LABELS: readonly ModelLabel[] = [...MODEL_ROLES, "none"];

const LABEL_SET: ReadonlySet<string> = new Set(MODEL_LABELS);

export function isModelLabel(v: unknown): v is ModelLabel {
  return typeof v === "string" && LABEL_SET.has(v);
}
