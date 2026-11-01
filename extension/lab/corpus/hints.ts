// Extracts the written hints found near password fields of the passive corpus,
// as a draft for the Rust hint-reader check (core/onepass-core/tests/fixtures/
// password_hints.jsonl). Usage:
//   node --experimental-strip-types lab/corpus/hints.ts [--samples dir] [--out file] [--max 200]
//
// Limitation: samples keep only the neighbour text of each field (`before`,
// `after`, `label`, `placeholder`, `ariaLabel`, 40 characters each at most),
// not the aria-describedby text nor the full sibling text of spec 4.1. Every
// non-empty piece of those slots for a password field is one candidate hint.
// The output carries empty expectations: labels are written by hand.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Sample, SampleField } from "./types.ts";

const arg = (name: string, dflt: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return (i >= 0 ? process.argv[i + 1] : undefined) ?? dflt;
};

const SLOTS = ["after", "before", "label", "placeholder", "ariaLabel"] as const;
const PIECE_MAX = 200;
const TOTAL_MAX = 600;

const isPassword = (f: SampleField): boolean =>
  f.type === "password" || f.role === "password" || f.role === "new_password";

const clean = (s: string): string =>
  s.replace(/[​-‍﻿]/g, "").replace(/\s+/g, " ").trim().slice(0, PIECE_MAX);

/** Distinct hint pieces of one corpus, in a stable order. */
export function extractHints(samples: Sample[], max: number): string[] {
  const seen = new Set<string>();
  for (const s of samples) {
    if (s.status !== "ok") continue;
    const forms = [...(s.forms ?? []), ...(s.steps ?? []).flat()];
    for (const form of forms) {
      for (const f of form.fields) {
        if (!isPassword(f)) continue;
        for (const slot of SLOTS) {
          const t = clean(f[slot] ?? "");
          if (t.length >= 3) seen.add(t.slice(0, TOTAL_MAX));
        }
      }
    }
  }
  return [...seen].sort().slice(0, max);
}

if (import.meta.url === `file://${process.argv[1] ?? ""}`) {
  const dir = arg("samples", "lab/corpus/samples/top1000");
  const out = arg("out", "");
  const max = Number(arg("max", "200"));
  const samples = readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()
    .map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")) as Sample);
  const lines = extractHints(samples, max).map((text) => JSON.stringify({ text }));
  if (out) writeFileSync(out, lines.join("\n") + "\n");
  else console.log(lines.join("\n"));
  console.error(`${lines.length} hints`);
}
