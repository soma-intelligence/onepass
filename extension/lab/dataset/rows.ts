// Labelled dataset rows (Task 9). A row is the features of one rendered field
// plus the true role the generator drew for it. The label never comes from the
// extractor or the page text: the renderer marks each control of a page with
// `data-lab-field="<index among the fields of that page>"` (dataset mode only)
// and the index is looked up in the Site's FieldSpec list of that page. A control
// without a mark (honeypot, decoy form, hidden relay) is "none". Rows hold no
// field value: FieldFeatures has none, and the labels / placeholders are the
// generator's lexicon strings, not account data.
import { FEATURE_VERSION } from "../../src/content/detect/features.ts";
import type { FieldFeatures, PageFeatures } from "../../src/content/detect/features.ts";
import { MODEL_ROLES } from "../../src/shared/model-labels.ts";
import { GENERATOR_VERSION } from "../gen/model.ts";
import type { FieldSpec, LabRole, Lang, Role, Site, TraitId } from "../gen/model.ts";
import { pageFields, styleOf } from "../gen/render.ts";
import type { PageContext, PageId } from "../gen/render.ts";
import { splitOf } from "./split.ts";
import type { Split } from "./split.ts";

export interface DatasetRow extends Omit<FieldFeatures, "lab"> {
  seed: string;
  generator: number;
  featureVersion: number;
  site: number;
  step: number;
  source: "synthetic" | "rendered" | "commoncrawl" | "recorded";
  /** Registrable site of the real sample the site derives from, or "synthetic:<site seed>". */
  origin: string;
  split: Split | "real_test";
  lang: Lang;
  framework: string;
  traits: TraitId[];
  /** The target: the role the generator drew for the field, or "none". `label` (inherited) stays the label text of the page. */
  target: Role | "none";
}

const MODEL_ROLE_SET: ReadonlySet<string> = new Set(MODEL_ROLES);
/** Whether a generated role is one of the 21 model classes. */
export const isModelRole = (r: LabRole): r is Role => MODEL_ROLE_SET.has(r);

export interface DatasetPage { page: PageId; ctx: PageContext; fields: FieldSpec[] }

/**
 * Origin of a generated site. The generator draws labels from the distilled
 * lexicon (patterns.json), which pools every corpus sample, so no single real
 * host is known: each site is its own origin, "synthetic:" plus its site seed
 * (unique across chunks, unlike the bare index).
 */
export const originOf = (site: Site): string => `synthetic:${site.seed}`;

/**
 * Pages of a site that hold fields, in flow order, as the lab serves them: the entry-like page (the
 * frame page when the form lives in an iframe), the password page of a
 * username-first login only, the OTP page, or every step of a multi_step form.
 * The index in this list is the row's `step`.
 */
export function datasetPages(site: Site): DatasetPage[] {
  const framed = site.traits.includes("iframe_same_origin") || site.traits.includes("iframe_cross_site");
  const first: PageId = framed ? "frame" : "entry";
  const out: DatasetPage[] = [];
  const add = (page: PageId, ctx: PageContext) => {
    const fields = pageFields(site, page, ctx.step ?? 0);
    if (fields.length > 0) out.push({ page, ctx, fields });
  };
  if (site.steps) {
    site.steps.forEach((_, k) => (k === 0 ? add(first, {}) : add("step", { step: k })));
    return out;
  }
  add(first, {});
  // The lab serves /password only after a username-first identifier (rp.ts redirects there), /otp only to a TOTP account.
  if (styleOf(site) === "username_first") add("password", {});
  add("otp", {});
  return out;
}

/** One row per extracted field of the page `step` of `site`. Throws when a mark does not match a spec (a generator or renderer bug). */
export function rowsFor(site: Site, step: number, page: PageFeatures, seed: string): DatasetRow[] {
  const spec = datasetPages(site)[step];
  if (!spec) throw new Error(`site ${site.index} has no dataset page ${step}`);
  const origin = originOf(site);
  const split = splitOf(origin, seed);
  const rows: DatasetRow[] = [];
  for (const form of page.forms) {
    for (const f of form.fields) {
      let target: Role | "none" = "none";
      if (f.lab !== undefined) {
        const at = Number(f.lab);
        const field = Number.isInteger(at) ? spec.fields[at] : undefined;
        if (!field) throw new Error(`site ${site.index} page ${step}: mark ${f.lab} has no field`);
        // Roles of the forms flows are not model classes (ruling R13): "none" for training.
        target = isModelRole(field.role) ? field.role : "none";
      }
      const { lab: _lab, ...features } = f;
      rows.push({
        ...features, seed, generator: GENERATOR_VERSION, featureVersion: FEATURE_VERSION, site: site.index, step,
        source: "synthetic", origin, split, lang: site.lang, framework: site.framework ?? "static", traits: site.traits, target,
      });
    }
  }
  return rows;
}
