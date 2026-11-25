// @vitest-environment node
// Replica server: routes per real hostname, GET and HEAD only, certificate
// covering every host and pinned by SPKI.
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildRoutes, replicaCertPath, replicaChromiumArgs, replicaSpki, startReplicaServer } from "../../../../lab/real/replica/server.ts";
import type { ReplicaMeta } from "../../../../lab/real/replica/common.ts";

const meta = (m: Partial<ReplicaMeta> & { host: string }): ReplicaMeta => ({ rank: 1, status: "ok", capturedAt: "", signInForm: false, files: [], tried: [], inlinedCss: 0, ...m });

function req(port: number, host: string, path: string, method = "GET"): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: "127.0.0.1", port, path, method, servername: host, headers: { host, accept: "text/html" }, rejectUnauthorized: false }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on("error", reject);
    r.end(method === "POST" ? "a=b" : undefined);
  });
}

describe("replica routes", () => {
  it("maps home, sign-in and signed-in pages to their hosts", () => {
    const routes = buildRoutes([
      meta({ host: "google.com", homeUrl: "https://www.google.com/", loginUrl: "https://accounts.google.com/v3/signin/", files: ["home.html", "signed-in.html", "login.html"], signInForm: true }),
      meta({ host: "down.com", status: "error: timeout" }),
      meta({ host: "nologin.com", homeUrl: "https://nologin.com/", files: ["home.html", "signed-in.html"] }),
    ]);
    expect([...routes.keys()].sort()).toEqual(["accounts.google.com", "google.com", "nologin.com", "www.google.com"]);
    expect(routes.get("www.google.com")!.get("/login")).toBe("google.com/login.html");
    expect(routes.get("accounts.google.com")!.get("/v3/signin")).toBe("google.com/login.html");
    expect(routes.get("google.com")!.get("/signed-in")).toBe("google.com/signed-in.html");
    expect(routes.get("nologin.com")!.has("/login")).toBe(false);
  });
});

describe("replica server", () => {
  let dir: string;
  let server: Awaited<ReturnType<typeof startReplicaServer>>;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "replica-srv-"));
    mkdirSync(join(dir, "site.com"));
    writeFileSync(join(dir, "site.com", "home.html"), "<p>home</p>");
    writeFileSync(join(dir, "site.com", "login.html"), "<p>login</p>");
    writeFileSync(join(dir, "site.com", "signed-in.html"), "<p>signed</p>");
    writeFileSync(join(dir, "site.com", "meta.json"), JSON.stringify(meta({ host: "site.com", homeUrl: "https://www.site.com/", loginUrl: "https://www.site.com/account/login", files: ["home.html", "login.html", "signed-in.html"], signInForm: true })));
    server = await startReplicaServer({ dir });
  });
  afterAll(async () => { await server?.close(); });

  it("serves the three routes under the real hostnames", async () => {
    expect(server.hosts).toEqual(["site.com", "www.site.com"]);
    expect((await req(server.port, "site.com", "/")).body).toBe("<p>home</p>");
    expect((await req(server.port, "www.site.com", "/login")).body).toBe("<p>login</p>");
    expect((await req(server.port, "www.site.com", "/account/login/")).body).toBe("<p>login</p>");
    expect((await req(server.port, "site.com", "/signed-in")).body).toBe("<p>signed</p>");
    expect((await req(server.port, "site.com", "/nope")).status).toBe(404);
    expect((await req(server.port, "other.com", "/")).status).toBe(404);
  });

  it("refuses every method but GET and HEAD", async () => {
    expect((await req(server.port, "site.com", "/login", "POST")).status).toBe(405);
    expect((await req(server.port, "site.com", "/", "HEAD")).status).toBe(200);
  });

  it("presents a certificate for every host, pinned by SPKI", () => {
    const cert = new X509Certificate(readFileSync(replicaCertPath(dir)));
    expect(cert.subjectAltName).toContain("DNS:www.site.com");
    expect(replicaSpki(dir)).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    const args = replicaChromiumArgs(server, dir);
    expect(args[0]).toBe(`--host-resolver-rules=MAP site.com 127.0.0.1:${server.port}, MAP www.site.com 127.0.0.1:${server.port}`);
    expect(args[1]).toBe(`--ignore-certificate-errors-spki-list=${replicaSpki(dir)}`);
  });
});
