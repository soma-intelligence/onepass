// Shapes of the pattern corpus: raw page samples, distilled patterns, and a
// stable JSON writer shared by the CLIs.
import type { Lang, ProviderId, Role, TraitId } from "../gen/model.ts";
import type { Framework, Visibility } from "../../src/content/detect/features.ts";

// Single-sourced in the shared extractor, which must stay free of lab imports.
export type { Framework, Visibility };

export type Category = "login" | "signup" | "checkout" | "address" | "identity";
export type FormStep = "identifier" | "password" | "both" | "code" | "other";

export type SampleSource = "rendered" | "commoncrawl" | "recorded";

export interface SampleField {
  tag: string; type?: string; name?: string; id?: string; autocomplete?: string; inputmode?: string;
  maxlength?: number; hasPattern: boolean; required: boolean; label?: string;
  placeholder?: string; ariaLabel?: string;
  before?: string; after?: string;                          // neighbour text, 40 characters at most each
  index?: number; depth?: number; siblings?: number;        // optional: extractor 1 samples stay valid
  visibility: Visibility; role: Role | "unknown";
}
export interface SampleForm { step: FormStep; fields: SampleField[]; buttons: string[]; }

export interface Sample {
  source_url: string; host: string; category: Category; captured_at: string; extractor: 1 | 2;
  source?: SampleSource;                                     // absent = "rendered"
  status: "ok" | "skipped: robots" | "skipped: duplicate host" | `error: ${string}`;
  lang?: Lang; forms?: SampleForm[]; steps?: SampleForm[][]; framework?: Framework; iframes?: { origin: string; sameSite: boolean }[];
  shadowFields?: number; webauthnCalls?: ("get" | "create")[]; providerButtons?: ProviderId[];
}

export type ButtonKind = "signin" | "next" | "pay" | "save" | "signup" | "passkey";

/** Roles of each page of a multi-step form, in order. */
export type StepSeq = Role[][];

/** What the hand-written seed lexicon holds (version 1 shape): the baseline distill blends the samples into. */
export interface Lexicon {
  version: number; samples: number;
  langs: [Lang, number][];                                   // weight = share of samples
  roles: Record<Role, { labels: Record<Lang, string[]>; tokens: string[]; autocompleteRate: number }>;
  buttons: Record<ButtonKind, Record<Lang, string[]>>;
  structure: { identifierFirst: number; sso: Record<ProviderId, number>; iframe: number; shadow: number; splitOtp: number; webauthn: number };
}

export interface Patterns extends Lexicon {
  version: 2;
  steps: [StepSeq, number][];                                // weight = share of step sequences
  frameworks: [string, number][];                            // "static", "react", "vue", "angular": share of samples with forms
  traits: Record<TraitId, number>;                           // relative weight of each lab trait (baseline nudged by the corpus)
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) o[k] = sortKeys((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

/** JSON with sorted keys and two-space indent: byte-stable output. */
export function stableJson(v: unknown): string {
  return JSON.stringify(sortKeys(v), null, 2) + "\n";
}
