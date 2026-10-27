// The crawler's browser guards, against a local server: a popup and a WebSocket
// must not get a POST (or any non-GET) out, and extra pages are closed.
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { guardContext, stats } from "../../lab/corpus/crawl-top.ts";

let server: Server;
let port: number;
const seen: string[] = [];

beforeAll(async () => {
  server = createServer((req: IncomingMessage, res) => {
    if (req.url !== "/robots.txt") seen.push(`${req.method} ${req.url}`);
    res.setHeader("content-type", "text/html");
    if (req.url === "/") res.end("<html><body>main</body></html>");
    else if (req.url === "/popup") res.end("<html><body><script>fetch('/popup-post',{method:'POST',body:'x'}).catch(()=>{});</script>popup</body></html>");
    else res.end("ok");
  });
  server.on("upgrade", (req, socket) => { seen.push(`UPGRADE ${req.url}`); socket.destroy(); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => { server.close(); });

describe("guardContext", () => {
  it("aborts a popup's POST, closes the popup and the WebSocket", async () => {
    const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
    const browser = await (pw.chromium ?? pw.default!.chromium).launch({ channel: "chromium" });
    try {
      const ctx = await browser.newContext({ acceptDownloads: false });
      await guardContext(ctx, async () => true);
      const before = { ...stats };
      const page = await ctx.newPage();
      await page.goto(`http://127.0.0.1:${port}/`);
      await page.evaluate((p: number) => {
        fetch(`http://127.0.0.1:${p}/main-post`, { method: "POST", body: "x" }).catch(() => {});
        window.open(`http://127.0.0.1:${p}/popup`);
        try { new WebSocket(`ws://127.0.0.1:${p}/ws`); } catch { /* ignored */ }
      }, port);
      await page.waitForTimeout(1500);
      expect(ctx.pages().length).toBe(1);
      expect(stats.closedPopups - before.closedPopups).toBe(1);
      expect(stats.abortedNonGet - before.abortedNonGet).toBeGreaterThanOrEqual(1);
      expect(seen.filter((l) => l.startsWith("POST") || l.startsWith("UPGRADE"))).toEqual([]);
      await ctx.close();
    } finally {
      await browser.close();
    }
  }, 30_000);
});
