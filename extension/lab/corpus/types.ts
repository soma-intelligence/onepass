// Shapes of the pattern corpus: raw page samples, distilled patterns, and a
// stable JSON writer shared by the CLIs.
import type { Lang, ProviderId, Role } from "../gen/model.ts";

export type Category = "login" | "signup" | "checkout" | "address" | "identity";
export type Visibility = "visible" | "display_none" | "offscreen" | "opacity" | "zero_size";
export type FormStep = "identifier" | "password" | "both" | "code" | "other";

export interface SampleField {
  tag: string; type?: string; name?: string; id?: string; autocomplete?: string; inputmode?: string;
  maxlength?: number; hasPattern: boolean; required: boolean; label?: string;
  visibility: Visibility; role: Role | "unknown";
}
export interface SampleForm { step: FormStep; fields: SampleField[]; buttons: string[]; }

export interface Sample {
  source_url: string; host: string; category: Category; captured_at: string; extractor: 1;
  status: "ok" | "skipped: robots" | "skipped: duplicate host" | `error: ${string}`;
  lang?: Lang; forms?: SampleForm[]; iframes?: { origin: string; sameSite: boolean }[];
  shadowFields?: number; webauthnCalls?: ("get" | "create")[]; providerButtons?: ProviderId[];
}

export type ButtonKind = "signin" | "next" | "pay" | "save" | "signup" | "passkey";

export interface Patterns {
  version: 1; samples: number;
  langs: [Lang, number][];                                   // weight = share of samples
  roles: Record<Role, { labels: Record<Lang, string[]>; tokens: string[]; autocompleteRate: number }>;
  buttons: Record<ButtonKind, Record<Lang, string[]>>;
  structure: { identifierFirst: number; sso: Record<ProviderId, number>; iframe: number; shadow: number; splitOtp: number; webauthn: number };
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
