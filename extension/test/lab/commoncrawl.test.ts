import { describe, expect, it, vi } from "vitest";
import { gzipSync } from "node:zlib";
import { CcClient, assertAllowedUrl, parseCdxLine, readWarcRecord, sampleFromHtml } from "../../lab/corpus/commoncrawl";

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
    expect(sleeps[1]!).toBeGreaterThan(sleeps[0]!);

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
