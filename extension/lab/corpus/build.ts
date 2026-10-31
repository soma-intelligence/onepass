// Turns the shared extractor's page features into a corpus Sample: sanitizes
// every string, drops redacted neighbour text, guesses roles and form steps.
import type { ProviderId } from "../gen/model.ts";
import type { FieldFeatures, PageFeatures } from "../../src/content/detect/features.ts";
import { classifyRole } from "./roles.ts";
import { sanitizeNeighbour, sanitizeOrigin, sanitizeText, sanitizeToken } from "./sanitize.ts";
import type { FormStep, Sample, SampleField, SampleForm, SampleSource } from "./types.ts";

export interface PageExtra { lang?: string; providerTexts: string[]; }

function stepOf(fields: SampleField[]): FormStep {
  const vis = fields.filter((f) => f.visibility === "visible");
  const has = (r: SampleField["role"][]) => vis.some((f) => r.includes(f.role));
  const pw = has(["password", "new_password"]);
  const id = has(["username", "email"]);
  if (pw && id) return "both";
  if (pw) return "password";
  if (has(["otp"])) return "code";
  if (id) return "identifier";
  return "other";
}

function hostSite(a: string, b: string): boolean {
  const base = (h: string) => h.split(".").slice(-2).join(".");
  return base(a) === base(b);
}

/** Text a sanitized neighbour or attribute may carry: a redacted one is dropped, never a feature. */
function keep(s: string | undefined, clean: (x: string | undefined) => string | undefined = sanitizeNeighbour): string | undefined {
  const t = clean(s);
  return t === "<redacted>" ? undefined : t;
}

export function fieldOf(x: FieldFeatures): SampleField {
  const out: SampleField = {
    tag: x.tag, type: x.type, name: sanitizeToken(x.name), id: sanitizeToken(x.id), autocomplete: sanitizeToken(x.autocomplete),
    inputmode: sanitizeToken(x.inputmode), maxlength: x.maxlength, hasPattern: x.hasPattern, required: x.required,
    label: sanitizeText(x.label ?? x.ariaLabel ?? x.placeholder),
    placeholder: keep(x.placeholder, sanitizeText), ariaLabel: keep(x.ariaLabel, sanitizeText),
    before: keep(x.before), after: keep(x.after),
    index: x.index, depth: x.depth, siblings: x.siblings,
    visibility: x.visibility, role: "unknown",
  };
  out.role = classifyRole(out);
  return out;
}

export function build(base: Sample, page: PageFeatures, extra: PageExtra, calls: ("get" | "create")[], source?: SampleSource): Sample {
  const forms: SampleForm[] = page.forms.map((f) => {
    const fields = f.fields.map(fieldOf);
    return { step: stepOf(fields), fields, buttons: f.buttons.map((b) => sanitizeText(b)).filter((b): b is string => !!b) };
  });
  const iframes: { origin: string; sameSite: boolean }[] = [];
  for (const fr of page.iframes) {
    try {
      const u = new URL(fr.origin);
      iframes.push({ origin: sanitizeOrigin(u.origin), sameSite: hostSite(u.hostname, base.host) });
    } catch { /* ignore malformed origin */ }
  }
  const providers = new Set<ProviderId>();
  for (const t of extra.providerTexts) for (const p of ["google", "apple", "microsoft"] as ProviderId[]) if (t.toLowerCase().includes(p)) providers.add(p);
  const lang = extra.lang?.toLowerCase().split("-")[0];
  return {
    ...base, ...(source ? { source } : {}), lang: lang || "und", forms, framework: page.framework, iframes, shadowFields: page.shadowFields,
    webauthnCalls: [...new Set(calls)], providerButtons: [...providers].sort(),
  };
}

