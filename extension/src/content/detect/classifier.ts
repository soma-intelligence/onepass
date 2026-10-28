// Pluggable field classifier (Task 15). The build picks one (ONEPASS_CLASSIFIER, `__CLASSIFIER__`):
// "heuristic" (default, today's scoring in fields.ts), "gbm" (model A) or "encoder" (model B).
// A model runs in the service worker (src/background/model.ts); the content script sends it the
// fields' features, never a field value, and gets one label per field back.
//
// Safety: the model only proposes. applySafetyRules runs after it and before the existing logic
// (formKind, look-alikes, origin checks, all unchanged): invisible fields and fields of a
// cross-site frame are forced to `unknown`, and an `unknown` is final. In a cross-site frame the
// model is not consulted at all (the frame keeps today's roles, and the service worker refuses
// every fill there, R-10).
//
// The page analysis is synchronous (the filler and the submit watcher re-analyse on the spot), so
// model answers go through a cache (createModelHook): a form the model has not answered yet keeps
// its heuristic roles, and the page is analysed again when the answer arrives.

import type { FieldRole } from "../../shared/messages";
import { isModelLabel, type ModelLabel } from "../../shared/model-labels";
import type { FieldFeatures, Visibility } from "./features";
import { classifyField, type FieldElement } from "./fields";
import { domGeometry, type Geometry, isVisible } from "./visibility";

export type ClassifierKind = "heuristic" | "gbm" | "encoder";
export type ModelKind = Exclude<ClassifierKind, "heuristic">;

export interface RoleScore {
  role: FieldRole;
  score: number;
}

export interface FieldClassifier {
  kind: ClassifierKind;
  /** One role per field of ONE form (the signup context is read over the form). */
  classify(fields: FieldElement[], features: FieldFeatures[]): Promise<RoleScore[]>;
}

/** A loaded model as the content script sees it (remoteSession), or a fake in tests. */
export interface ModelSessionLike {
  kind: ModelKind;
  predict(features: FieldFeatures[]): Promise<{ label: ModelLabel; score: number }[]>;
}

/** Most fields of one form sent to the model; bigger forms keep their heuristic roles. */
export const MAX_CLASSIFY_FIELDS = 256;
/** Longest text value sent, in code points (vectorize reads at most 256 after normalization). */
export const MAX_FEATURE_CHARS = 1024;

const LABEL_ROLE: Readonly<Record<Exclude<ModelLabel, "password">, FieldRole>> = {
  username: "username",
  email: "email",
  new_password: "new_password",
  otp: "otp",
  cc_name: "cc_name",
  cc_number: "cc_number",
  cc_exp: "cc_exp",
  cc_exp_month: "cc_exp_month",
  cc_exp_year: "cc_exp_year",
  cc_csc: "cc_csc",
  given_name: "given_name",
  family_name: "family_name",
  tel: "tel",
  birth_date: "bday",
  organization: "organization",
  address_line1: "address_line1",
  address_line2: "address_line2",
  postal_code: "postal_code",
  city: "city",
  country: "country",
  none: "unknown",
};

/** FieldRole of a model label: `password` is a new password in a signup form, else the current one; `none` is unknown. */
export function toFieldRole(r: ModelLabel, context: { signup: boolean }): FieldRole {
  if (r === "password") return context.signup ? "new_password" : "current_password";
  return Object.prototype.hasOwnProperty.call(LABEL_ROLE, r) ? LABEL_ROLE[r as keyof typeof LABEL_ROLE] : "unknown";
}

/**
 * Signup context of one form from its model labels: an identifier and exactly two password fields
 * (password or new_password), at least one of them a new password. Three password fields are a
 * change form (current, new, confirm) and one is a login: there `password` stays the current one,
 * so a current password is never taken for a new one.
 */
export function signupContext(labels: readonly ModelLabel[]): boolean {
  const passwords = labels.filter((l) => l === "password" || l === "new_password").length;
  return passwords === 2 && labels.includes("new_password") && labels.some((l) => l === "username" || l === "email");
}

const HIDDEN: ReadonlySet<Visibility> = new Set<Visibility>(["display_none", "offscreen", "opacity", "zero_size"]);

/**
 * Runs after the classifier, before the existing logic: `unknown` on every invisible field (the
 * fill-time visibility check of visibility.ts, and any non-visible `visibility` of the features),
 * on every field of a cross-site frame, and on any field the classifier gave no role. Never turns
 * an `unknown` into anything else.
 */
export function applySafetyRules(
  fields: FieldElement[],
  roles: RoleScore[],
  frame: { crossSite: boolean },
  ctx: { geometry?: Geometry; features?: readonly (FieldFeatures | undefined)[] } = {},
): RoleScore[] {
  const geometry = ctx.geometry ?? domGeometry;
  return fields.map((el, i) => {
    const r = roles[i];
    const v = ctx.features?.[i]?.visibility;
    const refused =
      r === undefined ||
      r.role === "unknown" ||
      frame.crossSite ||
      (v !== undefined && HIDDEN.has(v)) ||
      !isVisible(el, geometry);
    return refused ? { role: "unknown", score: 0 } : { role: r.role, score: r.score };
  });
}

/** Today's scoring, field by field. */
export const heuristicClassifier: FieldClassifier = {
  kind: "heuristic",
  classify: async (fields) => fields.map((el) => classifyField(el)),
};

function modelClassifier(session: ModelSessionLike): FieldClassifier {
  return {
    kind: session.kind,
    async classify(_fields, features) {
      const preds = await session.predict(features);
      if (preds.length !== features.length) throw new Error("classifier: wrong number of predictions");
      const signup = signupContext(preds.map((p) => p.label));
      return preds.map((p) => ({ role: toFieldRole(p.label, { signup }), score: p.score }));
    },
  };
}

/** The classifier of a build: the model when it loads and is of the expected kind, else the heuristics. */
export async function classifierFor(
  kind: ClassifierKind,
  deps: { load: () => Promise<ModelSessionLike | null> },
): Promise<FieldClassifier> {
  if (kind === "heuristic") return heuristicClassifier;
  let session: ModelSessionLike | null = null;
  try {
    session = await deps.load();
  } catch {
    session = null;
  }
  return session !== null && session.kind === kind ? modelClassifier(session) : heuristicClassifier;
}

const capText = (s: string | undefined): string | undefined => {
  if (s === undefined) return undefined;
  const cps = Array.from(s);
  return cps.length > MAX_FEATURE_CHARS ? cps.slice(0, MAX_FEATURE_CHARS).join("") : s;
};

/** What the service worker gets: the features the vectorizer reads, texts capped; never `lab`, geometry or the page title. */
export function wireFeatures(f: FieldFeatures): FieldFeatures {
  const out: FieldFeatures = {
    index: f.index,
    tag: capText(f.tag) ?? "",
    hasPattern: f.hasPattern === true,
    required: f.required === true,
    depth: f.depth,
    siblings: f.siblings,
    visibility: f.visibility,
    width: 0,
    height: 0,
    formButtons: (f.formButtons ?? []).slice(0, 12).map((s) => capText(s) ?? ""),
    neighbourLabels: (f.neighbourLabels ?? []).slice(0, 4).map((s) => capText(s) ?? ""),
  };
  for (const k of ["type", "name", "id", "autocomplete", "inputmode", "label", "placeholder", "ariaLabel", "before", "after"] as const) {
    const v = capText(f[k]);
    if (v !== undefined) out[k] = v;
  }
  if (f.maxlength !== undefined) out.maxlength = f.maxlength;
  return out;
}

/** The worker said the asking frame is cross-site. */
export class CrossSiteFrame extends Error {}

type Send = (m: { type: "classify"; fields: FieldFeatures[] }) => Promise<unknown>;

/** The `ok` value of a reply envelope, or undefined. */
function okOf(r: unknown): Record<string, unknown> | null | undefined {
  if (typeof r !== "object" || r === null || !("ok" in r)) return undefined;
  const ok = (r as { ok: unknown }).ok;
  if (ok === null) return null;
  return typeof ok === "object" && !Array.isArray(ok) ? (ok as Record<string, unknown>) : undefined;
}

/**
 * The service worker's model as a session, after a handshake (an empty `classify`): null when the
 * worker has no model (absent, refused, incompatible), answers for another kind, or says this
 * frame is cross-site.
 */
export async function remoteSession(send: Send, kind: ModelKind): Promise<ModelSessionLike | null> {
  const hello = okOf(await send({ type: "classify", fields: [] }));
  if (!hello || hello.kind !== kind || hello.crossSite !== false) return null;
  return {
    kind,
    async predict(features) {
      const ok = okOf(await send({ type: "classify", fields: features.map(wireFeatures) }));
      if (ok?.crossSite === true) throw new CrossSiteFrame("classifier: cross-site frame");
      if (!ok || ok.crossSite !== false || !Array.isArray(ok.labels) || ok.labels.length !== features.length) {
        throw new Error("classifier: no model answer");
      }
      return ok.labels.map((x: unknown) => {
        const o = x as { label?: unknown; score?: unknown } | null;
        if (!o || !isModelLabel(o.label) || typeof o.score !== "number" || !Number.isFinite(o.score)) {
          throw new Error("classifier: bad model answer");
        }
        return { label: o.label, score: o.score };
      });
    },
  };
}

/** Synchronous view of a model for detectForms. */
export interface ModelHook {
  /** True once the worker said this frame is cross-site: the model is then never consulted. */
  readonly crossSite: boolean;
  /** The model's roles for one form if already known; otherwise null (and the form is asked for). */
  lookup(features: FieldFeatures[]): RoleScore[] | null;
}

/** Most forms remembered (the oldest answers are dropped first). */
const MAX_CACHED_FORMS = 512;

const cacheKey = (features: FieldFeatures[]): string =>
  JSON.stringify(features.map((f) => {
    const { lab: _lab, width: _w, height: _h, pageTitle: _t, ...rest } = f;
    return rest;
  }));

/** A ModelHook over a model classifier: answers from a cache, asks each new form once, calls onUpdate when an answer lands. */
export function createModelHook(opts: { classifier: FieldClassifier; onUpdate: () => void }): ModelHook {
  const cache = new Map<string, RoleScore[] | null>();
  const pending = new Set<string>();
  let crossSite = false;
  const remember = (key: string, v: RoleScore[] | null) => {
    if (cache.size >= MAX_CACHED_FORMS) cache.delete(cache.keys().next().value as string);
    cache.set(key, v);
  };
  return {
    get crossSite() {
      return crossSite;
    },
    lookup(features) {
      if (crossSite || features.length === 0 || features.length > MAX_CLASSIFY_FIELDS) return null;
      const key = cacheKey(features);
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      if (!pending.has(key)) {
        pending.add(key);
        opts.classifier.classify([], features).then(
          (roles) => {
            pending.delete(key);
            remember(key, roles.length === features.length ? roles : null);
            opts.onUpdate();
          },
          (e: unknown) => {
            // Failed or refused: this form stays on the heuristics.
            pending.delete(key);
            remember(key, null);
            if (e instanceof CrossSiteFrame) {
              crossSite = true;
              opts.onUpdate();
            }
          },
        );
      }
      return null;
    },
  };
}
