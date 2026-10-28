// Committed corpus samples are public: their source URL keeps origin and path only (final review
// I2), and no file carries the em dash character (final review M1).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { sourceUrlOf } from "../../lab/corpus/crawl-top.ts";

const SAMPLES = resolve(__dirname, "../../lab/corpus/samples");

function jsonFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...jsonFiles(p));
    else if (name.endsWith(".json")) out.push(p);
  }
  return out;
}

describe("crawled sample source URL", () => {
  it("keeps origin and path, never a query or a fragment", () => {
    expect(sourceUrlOf("https://accounts.example.com/signin?dsh=S-123&continue=x#frag")).toBe("https://accounts.example.com/signin");
    expect(sourceUrlOf("https://a.example/oauth/authorize?state=abc&code_challenge=def")).toBe("https://a.example/oauth/authorize");
    expect(sourceUrlOf("https://a.example/")).toBe("https://a.example/");
  });

  it("no committed sample keeps a query or a fragment, nor the em dash character", () => {
    const files = jsonFiles(SAMPLES);
    expect(files.length).toBeGreaterThan(100);
    const bad: string[] = [];
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      if (text.includes("\u2014")) bad.push(`${f}: em dash`);
      const o = JSON.parse(text) as { source_url?: unknown };
      if (typeof o.source_url === "string" && /[?#]/.test(o.source_url)) bad.push(`${f}: ${o.source_url.split("?")[0]}`);
    }
    expect(bad).toEqual([]);
  });
});
