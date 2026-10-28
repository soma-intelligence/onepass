// Second corpus source: forms from pages Common Crawl already archived. Pages
// are read from Common Crawl's public storage (index.commoncrawl.org for the
// CDX index, data.commoncrawl.org for byte ranges of the WARC files), never
// from the sites themselves. HTML goes through jsdom with no scripts and no
// resource loading, then the shared extractor; sanitize.ts runs before writing.
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { JSDOM, VirtualConsole } from "jsdom";
import { extractFeatures } from "../../src/content/detect/features.ts";
import { build } from "./build.ts";
import { writeAtomic } from "./schedule.ts";
import { sanitizeText } from "./sanitize.ts";
import { stableJson } from "./types.ts";
import type { Category, Sample } from "./types.ts";

export const USER_AGENT = "OnePassLabCorpus/2 (+https://github.com/soma-intelligence/onepass)";
const ALLOWED_HOSTS = new Set(["index.commoncrawl.org", "data.commoncrawl.org"]);
const DATA_BASE = "https://data.commoncrawl.org/";
const INDEX_BASE = "https://index.commoncrawl.org/";
const MAX_HTML = 2_000_000;
const MAX_PER_HOST = 6;
const FORM_PATHS = ["login", "signin", "register", "signup", "checkout"];
const PATH_RE = /\/(login|log-in|signin|sign-in|register|signup|sign-up|checkout|connexion|inscription|anmelden|registrieren)\/?$/i;
const EXTRA_TLDS = ["com", "org", "net", "io", "fr", "de", "uk", "es", "it", "nl", "ca", "au"];

export interface CdxEntry { url: string; filename: string; offset: number; length: number; status: number; mime: string; }

/** One line of the CDX index in `output=json` form; null when it is not a usable capture line. */
export function parseCdxLine(line: string): CdxEntry | null {
  let o: Record<string, unknown>;
  try { o = JSON.parse(line) as Record<string, unknown>; } catch { return null; }
  if (!o || typeof o !== "object") return null;
  const { url, filename, mime } = o;
  const offset = Number(o.offset), length = Number(o.length), status = Number(o.status);
  if (typeof url !== "string" || typeof filename !== "string" || typeof mime !== "string") return null;
  if (!url || !filename || !Number.isInteger(offset) || !Number.isInteger(length) || !Number.isInteger(status) || offset < 0 || length <= 0) return null;
  return { url, filename, offset, length, status, mime };
}

function decode(body: Buffer, contentType: string): string {
  const cs = /charset=["']?([\w-]+)/i.exec(contentType)?.[1] ?? "utf-8";
  try { return new TextDecoder(cs).decode(body); } catch { return new TextDecoder("utf-8").decode(body); }
}

/** One gzipped WARC record: WARC headers, then the HTTP response. Only a 200 response with a body yields HTML. */
export function readWarcRecord(gz: Uint8Array): { targetUri: string; html: string } | null {
  let raw: Buffer;
  try { raw = gunzipSync(gz); } catch { return null; }
  const warcEnd = raw.indexOf("\r\n\r\n");
  if (warcEnd < 0) return null;
  const warcHead = raw.subarray(0, warcEnd).toString("latin1");
  if (!warcHead.startsWith("WARC/")) return null;
  const warcField = (n: string): string | undefined => new RegExp(`^${n}:[ \\t]*(.+?)[ \\t]*$`, "im").exec(warcHead)?.[1];
  if (warcField("WARC-Type")?.toLowerCase() !== "response") return null;
  const targetUri = warcField("WARC-Target-URI");
  if (!targetUri) return null;
  const rest = raw.subarray(warcEnd + 4);
  const httpEnd = rest.indexOf("\r\n\r\n");
  if (httpEnd < 0) return null;
  const httpHead = rest.subarray(0, httpEnd).toString("latin1");
  const status = Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(httpHead)?.[1]);
  if (status !== 200) return null;
  const contentType = /^content-type:[ \t]*(.+)$/im.exec(httpHead)?.[1] ?? "";
  let body = rest.subarray(httpEnd + 4);
  const len = Number(/^content-length:[ \t]*(\d+)/im.exec(httpHead)?.[1]);
  if (Number.isInteger(len) && len <= body.length) body = body.subarray(0, len);
  if (body.length > MAX_HTML) body = body.subarray(0, MAX_HTML);
  return { targetUri, html: decode(body, contentType) };
}

const guess = (url: string): Category => {
  const p = new URL(url).pathname.toLowerCase();
  if (/regist|signup|sign-up|inscription|registr/.test(p)) return "signup";
  if (/checkout|kasse|paiement|pago/.test(p)) return "checkout";
  return "login";
};

/** Sample of an archived page, or null when the page has no form. Scripts never run, nothing is loaded. */
export function sampleFromHtml(url: string, html: string, capturedAt: string): Sample | null {
  const u = new URL(url);
  const dom = new JSDOM(html, { virtualConsole: new VirtualConsole() }); // silent: archived pages ship CSS jsdom cannot parse
  try {
    const doc = dom.window.document;
    const page = extractFeatures(doc);
    if (page.forms.length === 0) return null;
    const providerTexts: string[] = [];
    doc.querySelectorAll("button, a, [role=button]").forEach((b) => {
      const t = (b.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
      if (/google|apple|microsoft/i.test(t) && t.length < 80) providerTexts.push(t);
    });
    const base: Sample = { source_url: `${u.origin}${u.pathname}`, host: u.hostname, category: guess(url), captured_at: capturedAt, extractor: 2, source: "commoncrawl", status: "ok" };
    return build(base, page, { lang: doc.documentElement.lang || undefined, providerTexts }, [], "commoncrawl");
  } finally {
    dom.window.close();
  }
}

/** Throws unless the URL is https on one of the two Common Crawl hosts. */
export function assertAllowedUrl(url: string): URL {
  let u: URL;
  try { u = new URL(url); } catch { throw new Error(`blocked: not a URL`); }
  if (u.protocol !== "https:" || u.username || u.password || !ALLOWED_HOSTS.has(u.hostname)) throw new Error(`blocked host: ${u.hostname || url}`);
  return u;
}

export interface CcClientOptions {
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  cdxGapMs?: number;
}

const RETRY_STATUS = new Set([429, 502, 503, 504]); // 502/504 are the index's overload answers
const MAX_RETRIES = 3;
const MAX_RANGE_IN_FLIGHT = 4;
const BACKOFF_MS = 5000; // 5 s, 10 s, 20 s
const MAX_RETRY_AFTER_MS = 600_000;
const BREAKER_FAILS = 5;
const BREAKER_PAUSES_MS = [5 * 60_000, 15 * 60_000];

/** Too many consecutive failures on one host after both pauses: the run stops, its progress is saved. */
export class CircuitOpen extends Error {}

/** Retry-After as milliseconds (seconds or HTTP date), 0 when absent or unreadable. */
function retryAfterMs(value: string | null, now: number): number {
  if (!value) return 0;
  const secs = Number(value);
  const ms = Number.isFinite(secs) ? secs * 1000 : Date.parse(value) - now;
  return Number.isFinite(ms) && ms > 0 ? Math.min(ms, MAX_RETRY_AFTER_MS) : 0;
}

const isRedirectError = (e: unknown): boolean => /redirect/i.test(`${(e as Error)?.message} ${((e as Error)?.cause as Error | undefined)?.message}`);

/** The only network path of this tool: allowlisted hosts, sequential CDX queries 1 s apart, 4 range reads at most, backoff and circuit breaker on overload. */
export class CcClient {
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly gap: number;
  private cdxTail: Promise<unknown> = Promise.resolve();
  private lastCdx = Number.NEGATIVE_INFINITY;
  private active = 0;
  private waiting: (() => void)[] = [];
  private breaker = new Map<string, { fails: number; pauses: number }>();
  requests = 0;

  constructor(opts: CcClientOptions = {}) {
    this.fetchFn = opts.fetch ?? fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = opts.now ?? Date.now;
    this.gap = opts.cdxGapMs ?? 1000;
  }

  /** Counts one failed request of a host: 5 in a row pause the run (5 min, then 15 min), 5 more after that abort it. */
  private async failed(host: string): Promise<void> {
    const b = this.breaker.get(host) ?? { fails: 0, pauses: 0 };
    this.breaker.set(host, b);
    if (++b.fails < BREAKER_FAILS) return;
    const pause = BREAKER_PAUSES_MS[b.pauses];
    if (pause === undefined) throw new CircuitOpen(`${host} failed ${BREAKER_FAILS} requests in a row after two pauses, stopping (progress saved)`);
    b.pauses++;
    b.fails = 0;
    console.error(`${host}: ${BREAKER_FAILS} failed requests in a row, pausing ${pause / 60_000} min`);
    await this.sleep(pause);
  }

  private async send(url: string, headers: Record<string, string>): Promise<Response> {
    const host = assertAllowedUrl(url).hostname; // before any fetch
    for (let attempt = 0; ; attempt++) {
      this.requests++;
      let res: Response | undefined;
      let err: unknown;
      try {
        res = await this.fetchFn(url, { headers: { "User-Agent": USER_AGENT, ...headers }, redirect: "manual", signal: AbortSignal.timeout(90_000) });
      } catch (e) {
        if (isRedirectError(e)) throw e; // never followed, never retried
        err = e;
      }
      if (res && res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        throw new Error(`redirect refused (http ${res.status}) from ${host}`); // the target is never requested
      }
      if (res && !RETRY_STATUS.has(res.status)) {
        this.breaker.delete(host);
        return res;
      }
      const wait = Math.max(BACKOFF_MS * 2 ** attempt, res ? retryAfterMs(res.headers.get("retry-after"), this.now()) : 0);
      await res?.body?.cancel().catch(() => {}); // free the connection before waiting
      await this.failed(host);
      if (attempt >= MAX_RETRIES) throw res ? new Error(`http ${res.status} after ${MAX_RETRIES} retries`) : err;
      await this.sleep(wait);
    }
  }

  /** GET of an allowlisted URL, text body. */
  async get(url: string): Promise<string> {
    const res = await this.send(url, {});
    if (!res.ok) throw new Error(`http ${res.status}`);
    return res.text();
  }

  /** CDX query: one at a time, at least `gap` ms after the previous one started. */
  cdx(url: string): Promise<string> {
    assertAllowedUrl(url);
    const run = async (): Promise<string> => {
      const wait = this.lastCdx + this.gap - this.now();
      if (wait > 0) await this.sleep(wait);
      this.lastCdx = this.now();
      const res = await this.send(url, {});
      const text = await res.text();
      if (!res.ok && res.status !== 404) throw new Error(`http ${res.status}`);
      return text;
    };
    const p = this.cdxTail.then(run, run);
    this.cdxTail = p.catch(() => {});
    return p;
  }

  private async slot(): Promise<void> {
    if (this.active < MAX_RANGE_IN_FLIGHT) { this.active++; return; }
    await new Promise<void>((r) => this.waiting.push(r)); // the releaser hands its slot over
  }
  private release(): void {
    const next = this.waiting.shift();
    if (next) next(); else this.active--;
  }

  /** Byte range of a WARC file on data.commoncrawl.org. */
  async range(filename: string, offset: number, length: number): Promise<Uint8Array> {
    const url = DATA_BASE + filename.replace(/^\/+/, "");
    assertAllowedUrl(url);
    await this.slot();
    try {
      const res = await this.send(url, { Range: `bytes=${offset}-${offset + length - 1}` });
      if (res.status !== 206 && res.status !== 200) throw new Error(`http ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    } finally {
      this.release();
    }
  }
}

export async function newestCrawl(c: CcClient): Promise<string> {
  const list = JSON.parse(await c.get(INDEX_BASE + "collinfo.json")) as { id: string }[];
  const id = list[0]?.id;
  if (!id || !/^CC-MAIN-\d{4}-\d{2}$/.test(id)) throw new Error("no crawl id in collinfo.json");
  return id;
}

function cdxLines(text: string): CdxEntry[] {
  return text.split("\n").map(parseCdxLine).filter((e): e is CdxEntry => e !== null);
}
const wanted = (e: CdxEntry): boolean => e.status === 200 && e.mime === "text/html";

/** Captures of a listed host: its form paths, one prefix query per path. */
async function hostCaptures(c: CcClient, crawl: string, host: string): Promise<CdxEntry[]> {
  const out: CdxEntry[] = [];
  for (const p of FORM_PATHS) {
    if (out.length >= MAX_PER_HOST) break;
    const q = `${INDEX_BASE}${crawl}-index?output=json&limit=2&matchType=prefix&url=${encodeURIComponent(`${host}/${p}`)}&filter=${encodeURIComponent("=status:200")}`;
    try { out.push(...cdxLines(await c.cdx(q)).filter(wanted)); } catch (e) {
      if (e instanceof CircuitOpen) throw e;
      console.error(`cdx ${host}/${p}: ${(e as Error).message}`);
    }
  }
  return out;
}

/** Listing page walked at step k: a low-discrepancy walk over the whole listing, deterministic so a resume can replay it. */
const pageFor = (k: number, n: number): number => Math.floor(((k * 0.6180339887) % 1) * n);

/**
 * Captures outside the top list, from the index's own listing: pages of a few
 * TLD listings spread over the whole crawl, keeping the lines whose path is a
 * common form path (server-side filters time out on the index, so it is done here).
 * Yields one batch per listing page with the cursor to resume from.
 */
export async function* extraPages(c: CcClient, crawl: string, skip: Set<string>, start: number, signal?: AbortSignal): AsyncGenerator<{ entries: CdxEntry[]; cursor: number }> {
  const pages = new Map<string, number>();
  for (const tld of EXTRA_TLDS) {
    if (signal?.aborted) return;
    try {
      const n = (JSON.parse(await c.cdx(`${INDEX_BASE}${crawl}-index?url=${encodeURIComponent(`*.${tld}`)}&showNumPages=true`)) as { pages?: unknown }).pages;
      if (typeof n === "number" && n > 0) pages.set(tld, n);
    } catch (e) {
      if (e instanceof CircuitOpen) throw e; // tld unavailable otherwise
    }
  }
  const tlds = [...pages.keys()];
  const visited = new Set<string>();
  for (let k = 0; k < start && tlds.length > 0; k++) { const t = tlds[k % tlds.length]!; visited.add(`${t}:${pageFor(k, pages.get(t)!)}`); }
  for (let k = start; tlds.length > 0 && k <= EXTRA_TLDS.length * 400; k++) {
    if (signal?.aborted) return;
    const tld = tlds[k % tlds.length]!;
    const page = pageFor(k, pages.get(tld)!);
    if (visited.has(`${tld}:${page}`)) continue;
    visited.add(`${tld}:${page}`);
    let text: string;
    try { text = await c.cdx(`${INDEX_BASE}${crawl}-index?output=json&url=${encodeURIComponent(`*.${tld}`)}&page=${page}`); } catch (e) {
      if (e instanceof CircuitOpen) throw e;
      console.error(`cdx ${tld} page ${page}: ${(e as Error).message}`);
      continue;
    }
    const entries: CdxEntry[] = [];
    for (const line of text.split("\n")) {
      if (!PATH_RE.test(line.slice(0, 400).match(/"url":\s*"([^"]*)"/)?.[1] ?? "")) continue;
      const e = parseCdxLine(line);
      if (!e || !wanted(e)) continue;
      let host: string;
      try { host = new URL(e.url).hostname; } catch { continue; }
      if (!skip.has(host)) entries.push(e);
    }
    console.log(`${tld} page ${page}/${pages.get(tld)}: ${entries.length} form-path captures`);
    yield { entries, cursor: k + 1 };
  }
}

const USAGE = `usage: commoncrawl.ts [--crawl CC-MAIN-YYYY-WW] [--hosts file.json] [--hosts-limit 1000] [--extra 5000] [--out lab/out/commoncrawl] [--manifest file.json]
  --crawl      crawl id, default the newest in collinfo.json (a resumed run keeps its own)
  --hosts      JSON with a "hosts" list: their form pages are read first
  --extra      captures outside that list, from the index's own listing (default 5000, about 1 % of listing lines match)
  --out        one Sample per page, <host>.<n>.json, plus commoncrawl-state.json and commoncrawl-progress.jsonl (resume state)
  Re-running with the same --out resumes: captured records and finished hosts are skipped, nothing is overwritten.`;

interface Args { crawl?: string; hosts?: string; hostsLimit: number; extra: number; out: string; manifest: string; help: boolean; }

function parseArgs(argv: string[]): Args {
  const a: Args = { hostsLimit: 1000, extra: 5000, out: "lab/out/commoncrawl", manifest: new URL("./commoncrawl-manifest.json", import.meta.url).pathname, help: false };
  for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (k === "--help" || k === "-h") { a.help = true; return a; }
    if (v === undefined) throw new Error(`missing value for ${k}\n${USAGE}`);
    if (k === "--crawl") a.crawl = v;
    else if (k === "--hosts") a.hosts = v;
    else if (k === "--hosts-limit") a.hostsLimit = Number(v);
    else if (k === "--extra") a.extra = Number(v);
    else if (k === "--out") a.out = v;
    else if (k === "--manifest") a.manifest = v;
    else throw new Error(`unknown option ${k}\n${USAGE}`);
  }
  if (!Number.isInteger(a.extra) || a.extra < 0 || !Number.isInteger(a.hostsLimit) || a.hostsLimit < 0) throw new Error(`--extra and --hosts-limit take a non-negative integer\n${USAGE}`);
  return a;
}

interface Progress { url: string; host: string; filename: string; offset: number; length: number; kept: boolean; file?: string; }
interface State { crawl: string; hostsDone: string[]; cursor: number; extras: number; }

function readJson<T>(path: string): T | undefined {
  try { return JSON.parse(readFileSync(path, "utf8")) as T; } catch { return undefined; }
}

/** Progress lines that parse (a line cut by a crash is dropped); a kept record whose file never landed is forgotten. */
function readProgress(path: string, out: string): Progress[] {
  let text = "";
  try { text = readFileSync(path, "utf8"); } catch { return []; }
  const rows: Progress[] = [];
  for (const line of text.split("\n")) {
    try {
      const r = JSON.parse(line) as Progress;
      if (typeof r.filename !== "string" || typeof r.host !== "string" || typeof r.url !== "string") continue;
      if (r.kept && !(r.file && existsSync(join(out, r.file)))) continue;
      rows.push(r);
    } catch { /* cut line */ }
  }
  return rows;
}

export async function main(argv = process.argv.slice(2), client = new CcClient(), opts: { signal?: AbortSignal } = {}): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) { console.log(USAGE); return; }
  mkdirSync(args.out, { recursive: true });
  const statePath = join(args.out, "commoncrawl-state.json");
  const progressPath = join(args.out, "commoncrawl-progress.jsonl");
  const saved = readJson<State>(statePath);
  if (saved && args.crawl && saved.crawl !== args.crawl) throw new Error(`${args.out} holds a run of ${saved.crawl}, not ${args.crawl}: use another --out`);
  const crawl = saved?.crawl ?? args.crawl ?? await newestCrawl(client);
  if (!/^CC-MAIN-\d{4}-\d{2}$/.test(crawl)) throw new Error(`bad crawl id ${crawl}`);
  const state: State = { crawl, hostsDone: saved?.hostsDone ?? [], cursor: saved?.cursor ?? 0, extras: saved?.extras ?? 0 };

  const rows = readProgress(progressPath, args.out);
  const seenCaptures = new Set(rows.map((r) => `${r.filename}:${r.offset}`));
  const seenPages = new Set(rows.map((r) => r.url));
  const records = rows.filter((r) => r.kept).map((r) => ({ filename: r.filename, offset: r.offset, length: r.length }));
  const written = new Map<string, number>();
  const nextSlot = (host: string): number => {
    let n = written.get(host) ?? 0;
    while (existsSync(join(args.out, `${host}.${n}.json`))) n++; // never overwrite a page of an earlier run
    written.set(host, n + 1);
    return n;
  };

  const top = args.hosts ? (JSON.parse(readFileSync(args.hosts, "utf8")) as { hosts: string[] }).hosts.slice(0, args.hostsLimit) : [];
  const topSet = new Set(top);
  console.log(`crawl ${crawl}${saved ? " (resumed)" : ""}: ${top.length} listed hosts, up to ${args.extra} extra captures, ${records.length} already kept`);

  let examined = 0, noForm = 0, failed = 0, sinceSave = 0;
  let fatal: Error | undefined;
  const inflight = new Set<Promise<void>>();
  const save = (): void => {
    const sorted = [...records].sort((a, b) => a.filename.localeCompare(b.filename) || a.offset - b.offset);
    writeAtomic(args.manifest, stableJson({ crawl, records: sorted }));
    writeAtomic(statePath, stableJson(state));
  };
  const log = (r: Progress): void => appendFileSync(progressPath, JSON.stringify(r) + "\n");

  const handle = async (e: CdxEntry, u: URL): Promise<void> => {
    const key = `${e.filename}:${e.offset}`;
    examined++;
    const row: Progress = { url: `${u.origin}${u.pathname}`, host: u.hostname, filename: e.filename, offset: e.offset, length: e.length, kept: false };
    try {
      const rec = readWarcRecord(await client.range(e.filename, e.offset, e.length));
      if (!rec) { failed++; log(row); return; } // truncated or not a 200 response: skipped for good
      const s = sampleFromHtml(rec.targetUri, rec.html, new Date().toISOString());
      if (!s) { noForm++; log(row); return; }
      const n = nextSlot(s.host);
      if (n >= MAX_PER_HOST) { log(row); return; }
      const file = `${s.host}.${n}.json`;
      log({ ...row, host: s.host, kept: true, file }); // intent first: a crash before the file lands is forgotten on resume
      writeAtomic(join(args.out, file), stableJson(s));
      records.push({ filename: e.filename, offset: e.offset, length: e.length });
      if (++sinceSave >= 25) { sinceSave = 0; save(); }
    } catch (err) {
      seenCaptures.delete(key); // not recorded: a later run retries it
      if (err instanceof CircuitOpen) { fatal ??= err; return; }
      failed++;
      console.error(`${e.url}: ${sanitizeText((err as Error).message) ?? "error"}`);
    }
  };
  const submit = async (e: CdxEntry): Promise<void> => {
    let u: URL;
    try { u = new URL(e.url); } catch { return; }
    const key = `${e.filename}:${e.offset}`;
    if (seenCaptures.has(key)) return;
    seenCaptures.add(key);
    while (inflight.size >= 8) await Promise.race(inflight); // reads are capped at 4 by the client, this only bounds memory
    const p = handle(e, u).finally(() => inflight.delete(p));
    inflight.add(p);
  };
  const drain = async (): Promise<void> => { await Promise.allSettled(inflight); if (fatal) throw fatal; };
  const stopped = (): boolean => !!opts.signal?.aborted || !!fatal;

  try {
    for (const host of top) {
      if (stopped()) break;
      if (state.hostsDone.includes(host)) continue;
      for (const e of await hostCaptures(client, crawl, host)) await submit(e);
      await drain();
      state.hostsDone.push(host);
      save();
    }
    if (args.extra > 0 && !stopped()) {
      for await (const { entries, cursor } of extraPages(client, crawl, topSet, state.cursor, opts.signal)) {
        for (const e of entries) {
          if (state.extras >= args.extra) break;
          const page = (() => { try { const u = new URL(e.url); return `${u.origin}${u.pathname}`; } catch { return ""; } })();
          if (!page || seenPages.has(page)) continue;
          seenPages.add(page);
          state.extras++;
          await submit(e);
        }
        await drain();
        state.cursor = cursor;
        save();
        if (state.extras >= args.extra || stopped()) break;
      }
    }
    await drain();
  } finally {
    await Promise.allSettled(inflight);
    save(); // progress is kept on every exit: finish, interrupt or breaker
    console.log(`captures read: ${examined}, kept with a form: ${records.length}, no form: ${noForm}, unreadable: ${failed}, requests: ${client.requests}${opts.signal?.aborted ? " (interrupted, re-run to resume)" : ""}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const ctl = new AbortController();
  process.once("SIGINT", () => { console.error("SIGINT: finishing in-flight reads and saving state"); ctl.abort(); });
  main(undefined, undefined, { signal: ctl.signal }).then(() => { if (ctl.signal.aborted) process.exitCode = 130; }).catch((e) => {
    console.error(e instanceof CircuitOpen ? `ABORT: ${e.message}` : e instanceof Error ? e.message : e);
    process.exitCode = 1;
  });
}
