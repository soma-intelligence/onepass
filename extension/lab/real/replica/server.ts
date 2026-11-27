// One local server for every captured replica, under the real hostnames.
// Routes per host: `/` home, `/login` sign-in page, `/signed-in` signed-in
// variant; a sign-in page that lived on its own host (accounts.example.com)
// or path is also served there. GET and HEAD only (anything else: 405), every
// other path 404. HTTPS and plain HTTP share one port (first byte sniffed).
// The certificate covers every host and is made like e2e/cert.ts; Chromium
// trusts it by SPKI pin (`replicaSpki`) and reaches the server through
// `--host-resolver-rules` (`replicaChromiumArgs`).
// CLI: node --experimental-strip-types lab/real/replica/server.ts [--dir lab/out/replicas]
import { readFileSync } from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { generateCert, loadCert } from "../../../e2e/cert.ts";
import { defaultReplicaDir, listReplicas, type ReplicaMeta } from "./common.ts";

/** Folder (inside the replica folder) holding the server certificate. */
export const CERT_SUBDIR = ".cert";

export type ReplicaRoutes = Map<string, Map<string, string>>;

/** Trailing slash dropped except for the root. */
export function normalizePath(path: string): string {
  return path.length > 1 && path.endsWith("/") ? path.replace(/\/+$/, "") || "/" : path;
}

/** Host -> path -> file (relative to the replica folder). Pure, for tests. */
export function buildRoutes(metas: readonly ReplicaMeta[]): ReplicaRoutes {
  const routes: ReplicaRoutes = new Map();
  const set = (host: string, path: string, file: string): void => {
    let m = routes.get(host);
    if (!m) { m = new Map(); routes.set(host, m); }
    const p = normalizePath(path);
    if (!m.has(p)) m.set(p, file);
  };
  for (const meta of metas) {
    if (meta.status !== "ok" || !meta.files.includes("home.html")) continue;
    const homeHosts = [meta.host];
    if (meta.homeUrl) {
      const h = new URL(meta.homeUrl).hostname;
      if (!homeHosts.includes(h)) homeHosts.push(h);
    }
    const hasLogin = meta.files.includes("login.html");
    for (const h of homeHosts) {
      set(h, "/", `${meta.host}/home.html`);
      if (meta.files.includes("signed-in.html")) set(h, "/signed-in", `${meta.host}/signed-in.html`);
      if (hasLogin) set(h, "/login", `${meta.host}/login.html`);
    }
    if (hasLogin && meta.loginUrl) {
      const u = new URL(meta.loginUrl);
      set(u.hostname, u.pathname, `${meta.host}/login.html`);
      if (!homeHosts.includes(u.hostname)) {
        set(u.hostname, "/", `${meta.host}/login.html`);
        set(u.hostname, "/login", `${meta.host}/login.html`);
      }
    }
  }
  return routes;
}

/** The certificate's SPKI hash, for `--ignore-certificate-errors-spki-list`. Valid once the server started. */
export function replicaSpki(dir: string): string {
  return loadCert(join(dir, CERT_SUBDIR)).spki;
}

/** Path of the PEM certificate the server presents. */
export function replicaCertPath(dir: string): string {
  return join(dir, CERT_SUBDIR, "cert.pem");
}

/** Chromium flags that send exactly `hosts` to the server and trust its certificate (pinned key only). */
export function replicaChromiumArgs(server: { port: number; hosts: readonly string[] }, dir: string): string[] {
  return [
    `--host-resolver-rules=${server.hosts.map((h) => `MAP ${h} 127.0.0.1:${server.port}`).join(", ")}`,
    `--ignore-certificate-errors-spki-list=${replicaSpki(dir)}`,
  ];
}

const page404 = (host: string, path: string): string =>
  `<!doctype html><meta charset="utf-8"><title>Not captured</title><meta name="onepass-lab-replica" content="missing"><p>OnePass lab replica: ${esc(host)}${esc(path)} was not captured.</p>`;
const esc = (s: string): string => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);

export async function startReplicaServer(opts: { dir: string }): Promise<{ port: number; hosts: string[]; close(): Promise<void> }> {
  const routes = buildRoutes(listReplicas(opts.dir));
  const hosts = [...routes.keys()].sort();
  if (hosts.length === 0) throw new Error(`replica server: no captured host in ${opts.dir}`);
  const cert = generateCert(join(opts.dir, CERT_SUBDIR), hosts);

  const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    let path = "/";
    try { path = new URL(req.url ?? "/", "https://x").pathname; } catch { /* keep "/" */ }
    path = normalizePath(path);
    const headers = { "cache-control": "no-store", "x-onepass-lab": "replica" };
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { ...headers, allow: "GET, HEAD", "content-type": "text/plain; charset=utf-8" });
      res.end("method not allowed");
      req.resume();
      return;
    }
    const file = routes.get(host)?.get(path);
    let body: Buffer | undefined;
    if (file) { try { body = readFileSync(join(opts.dir, file)); } catch { body = undefined; } }
    if (!body) {
      const accept = String(req.headers.accept ?? "");
      if (accept.includes("text/html")) {
        res.writeHead(404, { ...headers, "content-type": "text/html; charset=utf-8" });
        res.end(req.method === "HEAD" ? undefined : page404(host, path));
      } else {
        res.writeHead(404, headers);
        res.end();
      }
      return;
    }
    res.writeHead(200, { ...headers, "content-type": "text/html; charset=utf-8", "content-length": body.length });
    res.end(req.method === "HEAD" ? undefined : body);
  };

  const tls = https.createServer({ key: cert.key, cert: cert.cert }, handler);
  const plain = http.createServer(handler);
  const sockets = new Set<net.Socket>();
  const front = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
    socket.once("readable", () => {
      const first = socket.read(1) as Buffer | null;
      if (!first) { socket.destroy(); return; }
      socket.unshift(first);
      // 0x16: TLS handshake record.
      (first[0] === 0x16 ? tls : plain).emit("connection", socket);
    });
  });
  await new Promise<void>((resolve) => front.listen(0, "127.0.0.1", resolve));
  const port = (front.address() as net.AddressInfo).port;
  return {
    port,
    hosts,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        front.close(() => resolve());
      }),
  };
}

async function main(): Promise<void> {
  const i = process.argv.indexOf("--dir");
  const dir = i > 0 ? process.argv[i + 1]! : defaultReplicaDir();
  const s = await startReplicaServer({ dir });
  console.log(`replica server on 127.0.0.1:${s.port}, ${s.hosts.length} hosts`);
  console.log(`Chromium flags:\n  ${replicaChromiumArgs(s, dir).map((a) => (a.length > 200 ? a.slice(0, 200) + "..." : a)).join("\n  ")}`);
  process.on("SIGINT", () => { s.close().then(() => process.exit(0)); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
