import { describe, expect, it, vi } from "vitest";
import { gzipSync } from "node:zlib";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CcClient, CircuitOpen, assertAllowedUrl, main, parseCdxLine, readWarcRecord, sampleFromHtml } from "../../lab/corpus/commoncrawl";

const LINE = JSON.stringify({
  urlkey: "com,github)/login", timestamp: "20261005110032", url: "https://github.com/login", mime: "text/html", "mime-detected": "text/html",
  status: "200", digest: "RTJTY3ZEYXJAKVXNOFFYRCB4B222SS5C", length: "117454", offset: "233901358",
  filename: "crawl-data/CC-MAIN-2026-43/segments/1791170053823.21/warc/CC-MAIN-20261005105623-20261005135623-00657.warc.gz", languages: "eng",
});

/** A WARC response record (WARC headers, HTTP headers, body), gzipped as Common Crawl stores it. */
function warc(uri: string, status: number, html: string, type = "response"): Uint8Array {
  const http = `HTTP/1.1 ${status} X\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\n\r\n${html}`;
  const head = `WARC/1.0\r\nWARC-Type: ${type}\r\nWARC-Target-URI: ${uri}\r\nContent-Type: application/http; msgtype=response\r\nContent-Length: ${Buffer.byteLength(http)}\r\n\r\n`;
  return gzipSync(Buffer.from(`${head}${http}\r\n\r\n`));
}

const FORM = `<html lang="fr"><body><form><label>Email <input type="email" name="email"></label><input type="password" name="pw"><button>Sign in</button></form></body></html>`;

describe("parseCdxLine", () => {
  it("reads a real index line", () => {
    expect(parseCdxLine(LINE)).toEqual({
      url: "https://github.com/login", status: 200, mime: "text/html", offset: 233901358, length: 117454,
      filename: "crawl-data/CC-MAIN-2026-43/segments/1791170053823.21/warc/CC-MAIN-20261005105623-20261005135623-00657.warc.gz",
    });
  });
  it("returns null for malformed lines", () => {
    for (const l of ["", "not json", "{}", JSON.stringify({ url: "u", offset: "x", length: "1", filename: "f", status: "200", mime: "text/html" }), '{"message": "No Captures found for: a"}']) {
      expect(parseCdxLine(l)).toBeNull();
    }
  });
});

describe("readWarcRecord", () => {
  it("returns the target URI and the HTML of a 200 response", () => {
    expect(readWarcRecord(warc("https://example.com/login", 200, FORM))).toEqual({ targetUri: "https://example.com/login", html: FORM });
  });
  it("ignores a 404 response, a non-response record and garbage", () => {
    expect(readWarcRecord(warc("https://example.com/x", 404, "<html></html>"))).toBeNull();
    expect(readWarcRecord(warc("https://example.com/x", 200, FORM, "request"))).toBeNull();
    expect(readWarcRecord(new Uint8Array([1, 2, 3]))).toBeNull();
  });
  it("skips a truncated gzip record without throwing", () => {
    const gz = warc("https://example.com/login", 200, FORM);
    expect(readWarcRecord(gz.subarray(0, Math.floor(gz.length / 2)))).toBeNull();
  });
});

describe("sampleFromHtml", () => {
  it("makes a commoncrawl sample from a page with a form and none from a page without", () => {
    const s = sampleFromHtml("https://example.com/login", FORM, "2026-10-27T00:00:00Z")!;
    expect(s).toMatchObject({ source: "commoncrawl", host: "example.com", category: "login", status: "ok", extractor: 2, lang: "fr" });
    expect(s.forms!.length).toBe(1);
    expect(sampleFromHtml("https://example.com/", "<html><body><p>hi</p></body></html>", "t")).toBeNull();
  });
});

describe("host allowlist", () => {
  it("accepts only the two Common Crawl hosts over https", () => {
    expect(() => assertAllowedUrl("https://index.commoncrawl.org/collinfo.json")).not.toThrow();
    expect(() => assertAllowedUrl("https://data.commoncrawl.org/crawl-data/x.warc.gz")).not.toThrow();
    for (const u of ["https://example.com/", "https://commoncrawl.org/", "https://index.commoncrawl.org.evil.com/", "http://index.commoncrawl.org/", "https://user@evil.com@data.commoncrawl.org.evil.com/", "nonsense"]) {
      expect(() => assertAllowedUrl(u)).toThrow();
    }
  });
  it("throws before any fetch for another host", async () => {
    const fetchFn = vi.fn();
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async () => {} });
    await expect(c.get("https://example.com/")).rejects.toThrow(/host/);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe("polite client", () => {
  const res = (status: number, body = "ok") => new Response(body, { status });

  it("retries 503 and 429 with backoff, three times at most", async () => {
    const sleeps: number[] = [];
    const fetchFn = vi.fn().mockResolvedValueOnce(res(503)).mockResolvedValueOnce(res(429)).mockResolvedValueOnce(res(200, "done"));
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async (ms) => { sleeps.push(ms); }, cdxGapMs: 0 });
    expect(await c.cdx("https://index.commoncrawl.org/x")).toBe("done");
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(sleeps.length).toBe(2);
    expect(sleeps).toEqual([5000, 10000]);

    const always = vi.fn().mockImplementation(async () => res(503));
    const d = new CcClient({ fetch: always as unknown as typeof fetch, sleep: async () => {}, cdxGapMs: 0 });
    await expect(d.cdx("https://index.commoncrawl.org/x")).rejects.toThrow(/503/);
    expect(always).toHaveBeenCalledTimes(4); // first try + 3 retries
  });

  it("spaces CDX queries at least 1 s apart and never runs two at once", async () => {
    let t = 0;
    const starts: number[] = [];
    let live = 0, peak = 0;
    const fetchFn = vi.fn().mockImplementation(async () => { starts.push(t); live++; peak = Math.max(peak, live); await Promise.resolve(); live--; return res(200); });
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, now: () => t, sleep: async (ms) => { t += ms; } });
    await Promise.all([c.cdx("https://index.commoncrawl.org/a"), c.cdx("https://index.commoncrawl.org/b"), c.cdx("https://index.commoncrawl.org/c")]);
    expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(1000);
    expect(starts[2]! - starts[1]!).toBeGreaterThanOrEqual(1000);
    expect(peak).toBe(1);
  });

  it("keeps at most 4 range reads in flight and sends a Range header", async () => {
    let live = 0, peak = 0;
    const heads: string[] = [];
    const fetchFn = vi.fn().mockImplementation(async (_u: string, init: RequestInit) => {
      heads.push(new Headers(init.headers).get("range") ?? "");
      live++; peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 5));
      live--; return res(206, "x");
    });
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async () => {} });
    await Promise.all(Array.from({ length: 12 }, (_, i) => c.range("a/b.warc.gz", 100 * i, 50)));
    expect(peak).toBe(4);
    expect(heads[0]).toBe("bytes=0-49");
    expect(heads[1]).toBe("bytes=100-149");
  });
});

describe("redirects, Retry-After and body release", () => {
  const redirect = () => new Response(null, { status: 301, headers: { location: "https://evil.example.com/x" } });

  it("refuses a redirect from an allowlisted host without requesting the target", async () => {
    const fetchFn = vi.fn().mockImplementation(async () => redirect());
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async () => {}, cdxGapMs: 0 });
    await expect(c.cdx("https://index.commoncrawl.org/x")).rejects.toThrow(/redirect refused/);
    await expect(c.range("a.warc.gz", 0, 10)).rejects.toThrow(/redirect refused/);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(fetchFn.mock.calls.map((x) => String(x[0]))).not.toContain("https://evil.example.com/x");
    expect(fetchFn.mock.calls[0]![1].redirect).toBe("manual");
  });

  it("does not retry a redirect TypeError", async () => {
    const fetchFn = vi.fn().mockRejectedValue(new TypeError("fetch failed", { cause: new Error("unexpected redirect") }));
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async () => {}, cdxGapMs: 0 });
    await expect(c.cdx("https://index.commoncrawl.org/x")).rejects.toThrow();
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("honors Retry-After and cancels the body before retrying", async () => {
    const sleeps: number[] = [];
    const cancel = vi.fn();
    const body = new ReadableStream({ cancel });
    const first = new Response(body, { status: 429, headers: { "retry-after": "42" } });
    const fetchFn = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(new Response("ok"));
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async (ms) => { sleeps.push(ms); }, cdxGapMs: 0 });
    expect(await c.cdx("https://index.commoncrawl.org/x")).toBe("ok");
    expect(sleeps).toEqual([42000]);
    expect(cancel).toHaveBeenCalled();
  });
});

describe("circuit breaker", () => {
  it("pauses 5 min then 15 min after 5 failures in a row, then aborts with CircuitOpen", async () => {
    let t = 0;
    const sleeps: number[] = [];
    const fetchFn = vi.fn().mockImplementation(async () => new Response("", { status: 503 }));
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; }, cdxGapMs: 0 });
    let err: unknown;
    for (let i = 0; i < 20 && !(err instanceof CircuitOpen); i++) {
      try { await c.cdx("https://index.commoncrawl.org/x"); } catch (e) { err = e; }
    }
    expect(err).toBeInstanceOf(CircuitOpen);
    expect(sleeps.filter((m) => m >= 300000)).toEqual([300000, 900000]);
    expect(fetchFn).toHaveBeenCalledTimes(15); // 5 + 5 + 5 failed requests
  });

  it("a success resets the count", async () => {
    const answers = [503, 503, 503, 200, 503, 503, 503, 200];
    const sleeps: number[] = [];
    const fetchFn = vi.fn().mockImplementation(async () => new Response("x", { status: answers.shift() ?? 200 }));
    const c = new CcClient({ fetch: fetchFn as unknown as typeof fetch, sleep: async (ms) => { sleeps.push(ms); }, cdxGapMs: 0 });
    await c.cdx("https://index.commoncrawl.org/a");
    await c.cdx("https://index.commoncrawl.org/b");
    expect(sleeps.every((m) => m < 300000)).toBe(true);
  });
});

describe("resumable run on a fake index", () => {
  const CRAWL = "CC-MAIN-2026-43";
  const FILE = "crawl-data/x/warc/f.warc.gz";
  const entries: Record<number, { url: string; offset: number }[]> = {
    0: [{ url: "https://a.fr/login", offset: 1000 }, { url: "https://a.fr/signin", offset: 2000 }],
    2: [{ url: "https://b.fr/login", offset: 3000 }, { url: "https://t.fr/login", offset: 4000 }],
    3: [{ url: "https://a.fr/register", offset: 5000 }],
    1: [{ url: "https://c.fr/login", offset: 6000 }],
  };
  const bytes = new Map<number, Uint8Array>();
  for (const list of Object.values(entries)) for (const e of list) {
    const gz = warc(e.url, 200, FORM);
    bytes.set(e.offset, e.url.includes("t.fr") ? gz.subarray(0, 25) : gz); // t.fr is truncated
  }
  const line = (e: { url: string; offset: number }) => JSON.stringify({ url: e.url, mime: "text/html", status: "200", length: String(bytes.get(e.offset)!.length), offset: String(e.offset), filename: FILE });

  function fakeIndex(reads: number[], onRead?: (offset: number) => void): typeof fetch {
    return (async (input: string, init: RequestInit) => {
      const u = new URL(String(input));
      if (u.hostname === "data.commoncrawl.org") {
        const offset = Number(/bytes=(\d+)-/.exec(new Headers(init.headers).get("range")!)![1]);
        reads.push(offset);
        onRead?.(offset);
        return new Response(Buffer.from(bytes.get(offset)!), { status: 206 });
      }
      const q = u.searchParams;
      if (!q.get("url")?.endsWith(".fr")) return new Response('{"message": "No Captures found"}', { status: 404 });
      if (q.get("showNumPages")) return new Response('{"pages": 4, "pageSize": 5, "blocks": 20}');
      return new Response((entries[Number(q.get("page"))] ?? []).map(line).join("\n"));
    }) as unknown as typeof fetch;
  }

  it("interrupted then resumed: nothing captured twice, nothing overwritten", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cc-test-"));
    try {
      const manifest = join(dir, "manifest.json");
      const argv = ["--crawl", CRAWL, "--extra", "100", "--out", dir, "--manifest", manifest];
      const reads: number[] = [];
      const ctl = new AbortController();
      const first = new CcClient({ fetch: fakeIndex(reads, (o) => { if (o === 3000) ctl.abort(); }), sleep: async () => {}, cdxGapMs: 0 });
      await main(argv, first, { signal: ctl.signal });
      const files1 = readdirSync(dir).filter((f) => /^[a-z]\.fr\.\d+\.json$/.test(f)).sort();
      expect(files1).toEqual(["a.fr.0.json", "a.fr.1.json", "b.fr.0.json"]);
      const a0 = readFileSync(join(dir, "a.fr.0.json"), "utf8");
      expect(JSON.parse(readFileSync(join(dir, "commoncrawl-state.json"), "utf8")).cursor).toBe(2);

      const second = new CcClient({ fetch: fakeIndex(reads), sleep: async () => {}, cdxGapMs: 0 });
      await main(argv, second);
      const files2 = readdirSync(dir).filter((f) => /^[a-z]\.fr\.\d+\.json$/.test(f)).sort();
      expect(files2).toEqual(["a.fr.0.json", "a.fr.1.json", "a.fr.2.json", "b.fr.0.json", "c.fr.0.json"]);
      expect(readFileSync(join(dir, "a.fr.0.json"), "utf8")).toBe(a0); // not overwritten
      expect(JSON.parse(readFileSync(join(dir, "a.fr.2.json"), "utf8")).source_url).toBe("https://a.fr/register");
      expect(new Set(reads).size).toBe(reads.length); // no capture read twice
      const m = JSON.parse(readFileSync(manifest, "utf8")) as { crawl: string; records: { offset: number }[] };
      expect(m.crawl).toBe(CRAWL);
      expect(m.records.map((r) => r.offset).sort((a, b) => a - b)).toEqual([1000, 2000, 3000, 5000, 6000]); // truncated t.fr skipped
      expect(existsSync(join(dir, "t.fr.0.json"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to resume another crawl in the same output directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cc-test-"));
    try {
      const c = new CcClient({ fetch: fakeIndex([]), sleep: async () => {}, cdxGapMs: 0 });
      await main(["--crawl", CRAWL, "--extra", "1", "--out", dir, "--manifest", join(dir, "m.json")], c);
      await expect(main(["--crawl", "CC-MAIN-2026-39", "--out", dir, "--manifest", join(dir, "m.json")], c)).rejects.toThrow(/another --out/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
