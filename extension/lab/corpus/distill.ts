// Distiller of the pattern corpus: merges the hand-written baseline lexicon
// with the "ok" samples and writes a stable patterns.json (version 2: also
// step sequences, frameworks and trait weights). As a CLI it reads
// seed-lexicon.json and the samples of the three sources: samples/*.json (hand
// picked), samples/top1000/*.json (rendered crawl), samples/commoncrawl/*.json
// (Common Crawl pages, copied from the job output), and private/*.json (recorded flows) only with --with-private,
// so that the committed patterns.json never depends on private files.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TRAIT_WEIGHTS } from "../gen/generate.ts";
import type { Lang, ProviderId, Role, TraitId } from "../gen/model.ts";
import { classifyRole } from "./roles.ts";
import { readRealTestHosts, withoutHosts } from "./real-test-hosts.ts";
import { stableJson } from "./types.ts";
import type { ButtonKind, Lexicon, Patterns, Sample, SampleForm, StepSeq } from "./types.ts";

const BASELINE_WEIGHT = 10; // pseudo-samples given to the baseline when blending rates
// Lab traits are tests of the extension, not a census: a trait the corpus
// shows passively weighs half its baseline and half its corpus rate; the
// others (delays, closed shadow roots, decoys, lookalikes, mixed languages:
// nothing a single GET can tell) keep their baseline.
const OBSERVED_TRAITS: TraitId[] = ["iframe_same_origin", "iframe_cross_site", "shadow_open", "spa_rerender", "no_autocomplete",
  "obfuscated_names", "honeypot"];
const PROVIDERS: ProviderId[] = ["google", "apple", "microsoft"];
// Step sequences assumed before any sample, as pseudo-counts (BASELINE_WEIGHT in total).
const BASELINE_STEPS: [StepSeq, number][] = [
  [[["username"], ["password"]], 4], [[["email"], ["password"]], 4],
  [[["email"], ["password"], ["otp"]], 1], [[["username", "password"], ["otp"]], 1],
];
const IDENTIFIER: Role[] = ["username", "email"];

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

// Buttons naming an identity or payment provider say nothing about generic labels,
// nor does any "continue with <someone>" button, whatever the provider is called.
const PROVIDER_NAME = /google|apple|microsoft|github|facebook|twitter|linkedin|paypal|amazon|\bx\b/;
const PROVIDER_PHRASE = /^(continue|continuer|weiter|continuar|continua|sign ?in|log ?in|se connecter|anmelden) (with|avec|mit|con)\b/;
// Wording of a password being chosen (signup, reset): never a label of the sign-in password.
const NEW_PASSWORD = /\b(create|new|choose|confirm|retype|repeat|again|nouveau|nouvel|creer|choisi|confirme|neues|erstell|wiederhol|bestatig|crea|nueva|nuevo|repet|nuova|conferma)\b/;

// Consent banners, skip links and pagination are not form buttons.
const NOT_A_BUTTON = /\b(skip|without|accept|accepter|akzeptieren|aceptar|accetta|agree|ohne|sans|sin|senza)\b|\bnext (page|items?)\b/;

export function classifyButton(text: string): ButtonKind | undefined {
  const t = plain(text);
  if (PROVIDER_NAME.test(t) || PROVIDER_PHRASE.test(t) || NOT_A_BUTTON.test(t)) return undefined;
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

// Label sanity: the generator renders lexicon labels as ground truth, so a
// label that names something else poisons the dataset and fails the lab for
// nothing. Dropped everywhere: bare punctuation, labels over 40 characters,
// captcha, search, newsletter and chat wording, signup wording on a login
// identifier, password hints. Crawled samples (top 1000, Common Crawl:
// roles guessed by the crawler, often from type or name alone) also need the
// label itself to agree with the field's role: classifyRole on the label
// gives the role, its family, or "unknown" (email labels must name the
// email, password labels a password).
const MAX_LABEL = 40;
const NOT_A_LABEL = /captcha|robot|aufgabe|losen sie|solve|search|recherche|suche|buscar|newsletter|subscribe|abonn|supporter|\bchat/;
const SIGNUP_IDENTIFIER = /creat|regist|sign ?up|confirm|inscri|creer|erstell|crea|repeat|again/;
const PASSWORD_HINT = /at least|characters|caracteres|zeichen|caratteri|minimum|\bmin\b/;
const FAMILY: Partial<Record<Role, Role[]>> = {
  password: ["password", "new_password"], new_password: ["password", "new_password"], email: ["email", "username"],
  username: ["username", "email"], cc_exp: ["cc_exp", "cc_exp_month", "cc_exp_year"],
  address_line1: ["address_line1", "address_line2"], address_line2: ["address_line1", "address_line2"],
};
const STRICT: Role[] = ["email", "password", "new_password"];

export function labelOk(role: Role, label: string, crawled: boolean): boolean {
  const t = plain(label);
  if (!/[\p{L}\p{N}]/u.test(t) || label.trim().length > MAX_LABEL) return false;
  if (NOT_A_LABEL.test(t)) return false;
  if ((role === "username" || role === "email") && SIGNUP_IDENTIFIER.test(t)) return false;
  if ((role === "password" || role === "new_password") && PASSWORD_HINT.test(t)) return false;
  if (!crawled) return true;
  const guess = classifyRole({ label });
  const family = FAMILY[role] ?? [role];
  if (guess === "unknown") return !STRICT.includes(role) && t.replace(/\s/g, "").length > 3;
  return family.includes(guess);
}

// Sanitized placeholders, raw or HTML-escaped by an extractor: no label.
const SKIP = new Set(["<redacted>", "<long>", "&lt;redacted&gt;", "&lt;long&gt;"]);

/** BCP 47 primary subtag, lower case ("en_US" and "pt-BR" count as "en" and "pt"). */
function primaryLang(lang: string | undefined): Lang {
  return (lang ?? "").toLowerCase().split(/[-_]/)[0] || "und";
}

/** The forms of a sample: its single page, or every step of a recorded flow. */
function formsOf(s: Sample): SampleForm[] {
  return s.forms ?? s.steps?.flat() ?? [];
}

const rolesOf = (forms: SampleForm[], keep: (r: Role) => boolean = () => true): Role[] =>
  [...new Set(forms.flatMap((f) => f.fields.map((x) => x.role)).filter((r): r is Role => r !== "unknown" && keep(r)))];

/**
 * Step sequences a sample shows. A recorded flow gives its steps as they were
 * (roles of each step, empty steps dropped). A single page cannot show its
 * next page, so only a page whose form holds one step implies a sequence: an
 * identifier-only form is followed by a password page ([[id], [password]]), a
 * password-only or code-only form is a later step whose earlier pages the
 * generator completes (steps.ts). Forms asking for both, or for anything
 * else, imply no sequence.
 */
function stepSeqs(s: Sample): StepSeq[] {
  if (s.steps && s.steps.length > 0) {
    const seq = s.steps.map((step) => rolesOf(step)).filter((roles) => roles.length > 0);
    return seq.length > 0 ? [seq] : [];
  }
  const out: StepSeq[] = [];
  for (const f of s.forms ?? []) {
    if (f.step === "identifier") {
      const ids = rolesOf([f], (r) => IDENTIFIER.includes(r));
      if (ids.length > 0) out.push([ids, ["password"]]);
    } else if (f.step === "password") out.push([["password"]]);
    else if (f.step === "code") out.push([["otp"]]);
  }
  return out;
}

const FRAMEWORK_NAME: Record<string, string> = { other: "static", react: "react", vue: "vue", angular: "angular" };

/** Traits a sample shows evidence of, read passively (others keep their baseline). */
function traitHits(s: Sample): Set<TraitId> {
  const hits = new Set<TraitId>();
  const forms = formsOf(s);
  // A frame counts only when the page shows no field of its own: the form is in the frame, not an ad or a captcha.
  const ownFields = forms.some((f) => f.fields.some((x) => x.role !== "unknown"));
  if (!ownFields && s.iframes?.some((i) => i.sameSite)) hits.add("iframe_same_origin");
  if (!ownFields && s.iframes?.some((i) => !i.sameSite)) hits.add("iframe_cross_site");
  if ((s.shadowFields ?? 0) > 0) hits.add("shadow_open");
  if (s.framework && s.framework !== "other") hits.add("spa_rerender");
  for (const f of forms) {
    const known = f.fields.filter((x) => x.role !== "unknown");
    if (known.length > 0 && known.every((x) => !x.autocomplete)) hits.add("no_autocomplete");
    // ASP.NET style or numbered names: ctl00$main$user, input_83412.
    if (known.some((x) => /[$:]|(\d.*){4,}/.test(x.name ?? ""))) hits.add("obfuscated_names");
    if (f.fields.some((x) => x.visibility !== "visible" && x.visibility !== "zero_size" && x.tag === "input"
      && x.type !== "hidden" && (x.role === "username" || x.role === "email" || x.role === "password"))) hits.add("honeypot");
  }
  return hits;
}

export interface DistillOptions {
  /** Count recorded (private) samples too. Off by default: the committed patterns.json must not depend on them. */
  withPrivate?: boolean;
}

export function distill(samples: Sample[], baseline: Lexicon, opts: DistillOptions = {}): Patterns {
  const ok = samples.filter((s) => s.status === "ok" && (opts.withPrivate === true || s.source !== "recorded"));
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

  const stepCount = new Map<string, number>();
  for (const [seq, w] of BASELINE_STEPS) stepCount.set(JSON.stringify(seq), w);
  const fwCount: Record<string, number> = {};
  let withForms = 0;
  const traitCount = {} as Record<TraitId, number>;
  for (const t of Object.keys(TRAIT_WEIGHTS) as TraitId[]) traitCount[t] = 0;

  for (const s of ok) {
    const lang: Lang = primaryLang(s.lang);
    langCount[lang] = (langCount[lang] ?? 0) + 1;
    for (const seq of stepSeqs(s)) {
      const k = JSON.stringify(seq);
      stepCount.set(k, (stepCount.get(k) ?? 0) + 1);
    }
    if (formsOf(s).length > 0) {
      withForms++;
      const fw = FRAMEWORK_NAME[s.framework ?? "other"] ?? "static";
      fwCount[fw] = (fwCount[fw] ?? 0) + 1;
    }
    for (const t of traitHits(s)) traitCount[t]++;
    // A static copy (Common Crawl) has no layout: its fields all read zero_size.
    const seen = (v: string) => v === "visible" || (s.source === "commoncrawl" && v === "zero_size");
    const crawled = s.source === "commoncrawl" || (s.extractor === 2 && (s.source ?? "rendered") === "rendered");
    if (s.forms?.some((f) => f.step === "identifier")) identifierFirst++;
    if (s.iframes && s.iframes.length > 0) iframe++;
    if ((s.shadowFields ?? 0) > 0) shadow++;
    if (s.webauthnCalls && s.webauthnCalls.length > 0) webauthn++;
    for (const p of PROVIDERS) if (s.providerButtons?.includes(p)) sso[p]++;
    let sawSplit = false, sawWebauthn = false;
    for (const f of formsOf(s)) {
      if (f.fields.filter((x) => x.role === "otp" && x.maxlength === 1).length >= 4) sawSplit = true;
      for (const b of f.buttons) {
        const kind = classifyButton(b);
        if (kind && !SKIP.has(b)) addTo(buttons[kind], lang, b);
      }
      for (const fld of f.fields) {
        if (fld.autocomplete?.toLowerCase().includes("webauthn")) sawWebauthn = true;
        if (fld.role === "unknown" || !seen(fld.visibility)) continue;
        const r = fld.role;
        acSeen[r]++;
        if (fld.autocomplete && classifyRole({ autocomplete: fld.autocomplete }) === r) acHit[r]++;
        const signupWording = r === "password" && fld.label !== undefined && NEW_PASSWORD.test(plain(fld.label));
        if (fld.label && !SKIP.has(fld.label) && !signupWording && labelOk(r, fld.label, crawled)) addTo(labels[r], lang, fld.label);
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

  const byWeight = <T>(xs: [T, number][]) => xs.sort((x, y) => y[1] - x[1] || (JSON.stringify(x[0]) < JSON.stringify(y[0]) ? -1 : 1));
  const stepTotal = [...stepCount.values()].reduce((a, c) => a + c, 0);
  const steps = byWeight([...stepCount].map(([k, c]): [StepSeq, number] => [JSON.parse(k) as StepSeq, c / stepTotal]));
  const frameworks = withForms === 0 ? [["static", 1] as [string, number]]
    : byWeight(Object.entries(fwCount).map(([f, c]): [string, number] => [f, c / withForms]));
  const traits = {} as Record<TraitId, number>;
  for (const t of Object.keys(TRAIT_WEIGHTS).sort() as TraitId[]) {
    const base = TRAIT_WEIGHTS[t] / 100;
    traits[t] = n > 0 && OBSERVED_TRAITS.includes(t) ? (base + traitCount[t] / n) / 2 : base;
  }

  return {
    version: 2, samples: n, langs, roles: outRoles, buttons: outButtons, steps, frameworks, traits,
    structure: {
      identifierFirst: freq(b.identifierFirst, identifierFirst),
      sso: { google: freq(b.sso.google, sso.google), apple: freq(b.sso.apple, sso.apple), microsoft: freq(b.sso.microsoft, sso.microsoft) },
      iframe: freq(b.iframe, iframe), shadow: freq(b.shadow, shadow),
      splitOtp: freq(b.splitOtp, splitOtp), webauthn: freq(b.webauthn, webauthn),
    },
  };
}

/** Sample files of a samples directory: every `.json` except the crawler's `<host>.done.json` site markers. */
export function sampleFiles(names: string[]): string[] {
  return names.filter((f) => f.endsWith(".json") && !f.endsWith(".done.json")).sort();
}

export interface CorpusDirs { samples: string; private: string }

const here = () => dirname(fileURLToPath(import.meta.url));
/** Inputs of the CLI: tracked samples only (plus the git-ignored private flows on request), never lab/out. */
export function corpusDirs(): CorpusDirs {
  return { samples: join(here(), "samples"), private: join(here(), "private") };
}

function filesIn(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return sampleFiles(readdirSync(dir)).map((f) => join(dir, f));
}

/**
 * Sample files of the sources (Ruling R9): hand-picked samples/, the top
 * 1000 crawl in samples/top1000/, the Common Crawl pages copied (sanitized)
 * into samples/commoncrawl/, and the private recorded flows only when asked.
 * lab/out is never an input: the committed patterns.json rebuilds from a
 * clean checkout.
 */
export function corpusFiles(dirs: CorpusDirs, withPrivate: boolean): string[] {
  return [
    ...filesIn(dirs.samples), ...filesIn(join(dirs.samples, "commoncrawl")), ...filesIn(join(dirs.samples, "top1000")),
    ...(withPrivate ? filesIn(dirs.private) : []),
  ];
}

function isSample(v: unknown): v is Sample {
  const o = v as Partial<Sample> | null;
  return !!o && typeof o.host === "string" && typeof o.status === "string" && typeof o.source_url === "string";
}

/**
 * Everything the distiller reads: the corpus files of every source minus the
 * sites of the real test set (Ruling R13), so patterns.json never holds a label
 * the real test is scored against.
 */
export function distillSamples(dirs: CorpusDirs, withPrivate: boolean, hostsFile?: string): Sample[] {
  const all = corpusFiles(dirs, withPrivate).map((f) => JSON.parse(readFileSync(f, "utf8")) as unknown).filter(isSample);
  return withoutHosts(all, readRealTestHosts(hostsFile).hosts);
}

function main(): void {
  const dir = here();
  const withPrivate = process.argv.includes("--with-private");
  const baseline = JSON.parse(readFileSync(join(dir, "seed-lexicon.json"), "utf8")) as Lexicon;
  const samples = distillSamples(corpusDirs(), withPrivate);
  const out = distill(samples, baseline, { withPrivate });
  writeFileSync(join(dir, "patterns.json"), stableJson(out));
  console.log(`patterns.json written (${out.samples} samples, ${out.steps.length} step sequences)`);
  if (withPrivate) console.log("warning: built with private recorded flows, do not commit this patterns.json");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
