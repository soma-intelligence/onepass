// Distiller of the pattern corpus: merges the hand-written baseline lexicon
// with the "ok" samples and writes a stable patterns.json. As a CLI it reads
// samples/*.json and seed-lexicon.json next to this file.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Lang, ProviderId, Role } from "../gen/model.ts";
import { classifyRole } from "./roles.ts";
import { stableJson } from "./types.ts";
import type { ButtonKind, Patterns, Sample } from "./types.ts";

const BASELINE_WEIGHT = 10; // pseudo-samples given to the baseline when blending rates
const PROVIDERS: ProviderId[] = ["google", "apple", "microsoft"];

const BUTTON_WORDS: [ButtonKind, RegExp][] = [
  ["passkey", /passkey|cle d acces|llave de acceso|chiave di accesso/],
  ["signup", /sign ?up|create (an )?account|register|creer un compte|inscri|registrier|konto erstellen|registrarse|crear cuenta|registrati|criar conta|registreer/],
  ["pay", /\bpay|payer|bezahl|zahlungspflichtig|pagar|pagare|paga\b|place order|commander|bestellen|realizar pedido|betaal/],
  ["signin", /sign ?in|log ?in|se connecter|connexion|identifier|anmeld|einlogg|iniciar sesion|acceder|entrar|accedi|inloggen/],
  ["save", /\bsave|enregistrer|sauvegarder|speichern|guardar|salva|salvar|opslaan|update/],
  ["next", /\bnext|continue|suivant|continuer|weiter|fortfahren|siguiente|continuar|avanti|proximo|volgende/],
];

export function normLabel(s: string): string {
  return s.replace(/\s+/g, " ").trim().toLowerCase();
}

function plain(s: string): string {
  return normLabel(s).normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/['’\-_]/g, " ");
}

// Buttons naming an identity or payment provider say nothing about generic labels.
const PROVIDER_NAME = /google|apple|microsoft|github|facebook|twitter|linkedin|paypal|amazon|\bx\b/;

export function classifyButton(text: string): ButtonKind | undefined {
  const t = plain(text);
  if (PROVIDER_NAME.test(t)) return undefined;
  for (const [kind, re] of BUTTON_WORDS) if (re.test(t)) return kind;
  return undefined;
}

function blend(base: number, baseWeight: number, hits: number, n: number): number {
  return (base * baseWeight + hits) / (baseWeight + n);
}

function addTo(map: Record<string, string[]>, lang: string, value: string): void {
  (map[lang] ??= []).push(value);
}

function clean(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/** Dedupes on the normalized key, keeps the smallest original casing, sorts by key. */
function dedupe(values: string[]): string[] {
  const best = new Map<string, string>();
  for (const v of values) {
    const c = clean(v);
    if (!c) continue;
    const k = normLabel(c);
    const cur = best.get(k);
    if (cur === undefined || c < cur) best.set(k, c);
  }
  return [...best.keys()].sort().map((k) => best.get(k)!);
}

function finish(map: Record<string, string[]>): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const k of Object.keys(map).sort()) out[k] = dedupe(map[k]!);
  return out;
}

const SKIP = new Set(["<redacted>", "<long>"]);

export function distill(samples: Sample[], baseline: Patterns): Patterns {
  const ok = samples.filter((s) => s.status === "ok");
  const n = ok.length;
  const roles = Object.keys(baseline.roles) as Role[];

  const labels = {} as Record<Role, Record<string, string[]>>;
  const tokens = {} as Record<Role, string[]>;
  const acHit = {} as Record<Role, number>;
  const acSeen = {} as Record<Role, number>;
  for (const r of roles) {
    labels[r] = Object.fromEntries(Object.entries(baseline.roles[r].labels).map(([l, a]) => [l, [...a]]));
    tokens[r] = [...baseline.roles[r].tokens];
    acHit[r] = 0; acSeen[r] = 0;
  }
  const buttons = {} as Record<ButtonKind, Record<string, string[]>>;
  for (const k of Object.keys(baseline.buttons) as ButtonKind[]) {
    buttons[k] = Object.fromEntries(Object.entries(baseline.buttons[k]).map(([l, a]) => [l, [...a]]));
  }

  const langCount: Record<string, number> = {};
  let identifierFirst = 0, iframe = 0, shadow = 0, splitOtp = 0, webauthn = 0;
  const sso: Record<ProviderId, number> = { google: 0, apple: 0, microsoft: 0 };

  for (const s of ok) {
    const lang: Lang = s.lang || "und";
    langCount[lang] = (langCount[lang] ?? 0) + 1;
    if (s.forms?.some((f) => f.step === "identifier")) identifierFirst++;
    if (s.iframes && s.iframes.length > 0) iframe++;
    if ((s.shadowFields ?? 0) > 0) shadow++;
    if (s.webauthnCalls && s.webauthnCalls.length > 0) webauthn++;
    for (const p of PROVIDERS) if (s.providerButtons?.includes(p)) sso[p]++;
    let sawSplit = false, sawWebauthn = false;
    for (const f of s.forms ?? []) {
      if (f.fields.filter((x) => x.role === "otp" && x.maxlength === 1).length >= 4) sawSplit = true;
      for (const b of f.buttons) {
        const kind = classifyButton(b);
        if (kind && !SKIP.has(b)) addTo(buttons[kind], lang, b);
      }
      for (const fld of f.fields) {
        if (fld.autocomplete?.toLowerCase().includes("webauthn")) sawWebauthn = true;
        if (fld.role === "unknown" || fld.visibility !== "visible") continue;
        const r = fld.role;
        acSeen[r]++;
        if (fld.autocomplete && classifyRole({ autocomplete: fld.autocomplete }) === r) acHit[r]++;
        if (fld.label && !SKIP.has(fld.label)) addTo(labels[r], lang, fld.label);
        for (const t of [fld.name, fld.id]) if (t && !SKIP.has(t)) tokens[r].push(t);
      }
    }
    if (sawSplit) splitOtp++;
    if (sawWebauthn && !(s.webauthnCalls && s.webauthnCalls.length > 0)) webauthn++;
  }

  const outRoles = {} as Patterns["roles"];
  for (const r of roles) {
    outRoles[r] = {
      labels: finish(labels[r]),
      tokens: [...new Set(tokens[r].map(normLabel))].filter(Boolean).sort(),
      autocompleteRate: blend(baseline.roles[r].autocompleteRate, BASELINE_WEIGHT, acHit[r], acSeen[r]),
    };
  }
  const outButtons = {} as Patterns["buttons"];
  for (const k of Object.keys(buttons) as ButtonKind[]) outButtons[k] = finish(buttons[k]);

  const b = baseline.structure;
  const freq = (base: number, hits: number) => blend(base, BASELINE_WEIGHT, hits, n);
  const langs: [Lang, number][] = n === 0
    ? [...baseline.langs].sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))
    : Object.entries(langCount).map(([l, c]): [Lang, number] => [l, c / n]).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1));

  return {
    version: 1, samples: n, langs, roles: outRoles, buttons: outButtons,
    structure: {
      identifierFirst: freq(b.identifierFirst, identifierFirst),
      sso: { google: freq(b.sso.google, sso.google), apple: freq(b.sso.apple, sso.apple), microsoft: freq(b.sso.microsoft, sso.microsoft) },
      iframe: freq(b.iframe, iframe), shadow: freq(b.shadow, shadow),
      splitOtp: freq(b.splitOtp, splitOtp), webauthn: freq(b.webauthn, webauthn),
    },
  };
}

function main(): void {
  const dir = fileURLToPath(new URL(".", import.meta.url));
  const baseline = JSON.parse(readFileSync(dir + "seed-lexicon.json", "utf8")) as Patterns;
  let files: string[] = [];
  try { files = readdirSync(dir + "samples").filter((f) => f.endsWith(".json")).sort(); } catch { /* no samples yet */ }
  const samples = files.map((f) => JSON.parse(readFileSync(dir + "samples/" + f, "utf8")) as Sample);
  const out = distill(samples, baseline);
  writeFileSync(dir + "patterns.json", stableJson(out));
  console.log(`patterns.json written (${out.samples} samples)`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
