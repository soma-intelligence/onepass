// Second corpus source: forms from pages Common Crawl already archived. Pages
// are read from Common Crawl's public storage (index.commoncrawl.org for the
// CDX index, data.commoncrawl.org for byte ranges of the WARC files), never
// from the sites themselves. HTML goes through jsdom with no scripts and no
// resource loading, then the shared extractor; sanitize.ts runs before writing.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

/** The only network path of this tool: allowlisted hosts, sequential CDX queries 1 s apart, 4 range reads at most, backoff on overload. */
export class CcClient {
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly gap: number;
  private cdxTail: Promise<unknown> = Promise.resolve();
  private lastCdx = Number.NEGATIVE_INFINITY;
  private active = 0;
  private waiting: (() => void)[] = [];
  requests = 0;

  constructor(opts: CcClientOptions = {}) {
    this.fetchFn = opts.fetch ?? fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = opts.now ?? Date.now;
    this.gap = opts.cdxGapMs ?? 1000;
  }

  private async send(url: string, headers: Record<string, string>): Promise<Response> {
    assertAllowedUrl(url); // before any fetch
    for (let attempt = 0; ; attempt++) {
      this.requests++;
      let res: Response | undefined;
      try {
        res = await this.fetchFn(url, { headers: { "User-Agent": USER_AGENT, ...headers }, redirect: "error", signal: AbortSignal.timeout(90_000) });
      } catch (e) {
        if (attempt >= MAX_RETRIES) throw e;
      }
      if (res && !RETRY_STATUS.has(res.status)) return res;
      if (res && attempt >= MAX_RETRIES) throw new Error(`http ${res.status} after ${MAX_RETRIES} retries`);
      await this.sleep(1000 * 2 ** attempt);
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
    try { out.push(...cdxLines(await c.cdx(q)).filter(wanted)); } catch (e) { console.error(`cdx ${host}/${p}: ${(e as Error).message}`); }
  }
  return out;
}

/**
 * Captures outside the top list, from the index's own listing: pages of a few
 * TLD listings spread over the whole crawl, keeping the lines whose path is a
 * common form path (server-side filters time out on the index, so it is done here).
 */
async function* extraCaptures(c: CcClient, crawl: string, skip: Set<string>): AsyncGenerator<CdxEntry> {
  const pages = new Map<string, number>();
  const perHost = new Map<string, number>();
  const seen = new Set<string>();
  for (const tld of EXTRA_TLDS) {
    try { pages.set(tld, (JSON.parse(await c.cdx(`${INDEX_BASE}${crawl}-index?url=${encodeURIComponent(`*.${tld}`)}&showNumPages=true`)) as { pages: number }).pages); } catch { /* tld unavailable */ }
  }
  for (let k = 0; pages.size > 0; k++) {
    const tlds = [...pages.keys()];
    const tld = tlds[k % tlds.length]!;
    const n = pages.get(tld)!;
    const page = Math.floor(((k * 0.6180339887) % 1) * n); // low-discrepancy walk over the listing, deterministic
    let text: string;
    try { text = await c.cdx(`${INDEX_BASE}${crawl}-index?output=json&url=${encodeURIComponent(`*.${tld}`)}&page=${page}`); } catch (e) { console.error(`cdx ${tld} page ${page}: ${(e as Error).message}`); continue; }
    let hits = 0;
    for (const line of text.split("\n")) {
      if (!PATH_RE.test(line.slice(0, 400).match(/"url": "([^"]*)"/)?.[1] ?? "")) continue;
      const e = parseCdxLine(line);
      if (!e || !wanted(e)) continue;
      let u: URL;
      try { u = new URL(e.url); } catch { continue; }
      const key = u.hostname + u.pathname;
      if (seen.has(key) || skip.has(u.hostname) || (perHost.get(u.hostname) ?? 0) >= MAX_PER_HOST) continue;
      seen.add(key);
      perHost.set(u.hostname, (perHost.get(u.hostname) ?? 0) + 1);
      hits++;
      yield e;
    }
    console.log(`${tld} page ${page}/${n}: ${hits} form-path captures`);
    if (k > EXTRA_TLDS.length * 400) return; // hard stop on a pathological index
  }
}

interface Args { crawl?: string; hosts?: string; hostsLimit: number; extra: number; out: string; manifest: string; }

function parseArgs(argv: string[]): Args {
  const a: Args = { hostsLimit: 1000, extra: 0, out: "lab/out/commoncrawl", manifest: new URL("./commoncrawl-manifest.json", import.meta.url).pathname };
  for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (v === undefined) throw new Error(`missing value for ${k}`);
    if (k === "--crawl") a.crawl = v;
    else if (k === "--hosts") a.hosts = v;
    else if (k === "--hosts-limit") a.hostsLimit = Number(v);
    else if (k === "--extra") a.extra = Number(v);
    else if (k === "--out") a.out = v;
    else if (k === "--manifest") a.manifest = v;
    else throw new Error(`unknown option ${k}`);
  }
  if (!Number.isInteger(a.extra) || a.extra < 0 || !Number.isInteger(a.hostsLimit) || a.hostsLimit < 0) throw new Error("--extra and --hosts-limit take a non-negative integer");
  return a;
}

export async function main(argv = process.argv.slice(2), client = new CcClient()): Promise<void> {
  const args = parseArgs(argv);
  const crawl = args.crawl ?? await newestCrawl(client);
  if (!/^CC-MAIN-\d{4}-\d{2}$/.test(crawl)) throw new Error(`bad crawl id ${crawl}`);
  mkdirSync(args.out, { recursive: true });
  const top = args.hosts ? (JSON.parse(readFileSync(args.hosts, "utf8")) as { hosts: string[] }).hosts.slice(0, args.hostsLimit) : [];
  const topSet = new Set(top);
  console.log(`crawl ${crawl}: ${top.length} listed hosts, up to ${args.extra} extra captures`);

  const records: { filename: string; offset: number; length: number }[] = [];
  const written = new Map<string, number>();
  let examined = 0, noForm = 0, failed = 0;
  const inflight = new Set<Promise<void>>();
  const handle = async (e: CdxEntry): Promise<void> => {
    examined++;
    try {
      const rec = readWarcRecord(await client.range(e.filename, e.offset, e.length));
      if (!rec) { failed++; return; }
      const s = sampleFromHtml(rec.targetUri, rec.html, new Date().toISOString());
      if (!s) { noForm++; return; }
      const n = written.get(s.host) ?? 0;
      if (n >= MAX_PER_HOST) return;
      written.set(s.host, n + 1);
      writeAtomic(join(args.out, `${s.host}.${n}.json`), stableJson(s));
      records.push({ filename: e.filename, offset: e.offset, length: e.length });
    } catch (err) {
      failed++;
      console.error(`${e.url}: ${sanitizeText((err as Error).message) ?? "error"}`);
    }
  };
  const submit = async (e: CdxEntry): Promise<void> => {
    while (inflight.size >= 8) await Promise.race(inflight); // reads are capped at 4 by the client, this only bounds memory
    const p = handle(e).finally(() => inflight.delete(p));
    inflight.add(p);
  };

  for (const host of top) for (const e of await hostCaptures(client, crawl, host)) await submit(e);
  let extras = 0;
  if (args.extra > 0) {
    for await (const e of extraCaptures(client, crawl, topSet)) {
      await submit(e);
      if (++extras >= args.extra) break;
    }
  }
  await Promise.all(inflight);
  records.sort((a, b) => a.filename.localeCompare(b.filename) || a.offset - b.offset);
  writeFileSync(args.manifest, stableJson({ crawl, records }));
  console.log(`captures read: ${examined}, kept with a form: ${records.length}, no form: ${noForm}, unreadable: ${failed}, requests: ${client.requests}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
