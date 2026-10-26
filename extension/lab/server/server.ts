// Local server of the autofill lab (spec 5, 6): one 127.0.0.1 port carrying
// HTTPS and plain HTTP (the first byte tells a TLS handshake apart, as in
// e2e/server.ts), routed by the Host header over every host of a world:
// - a site host: its relying party (rp.ts);
// - a cross-site frame host: that site's auth widget (/frame and the steps it
//   leads to), every POST to it recorded;
// - a lookalike host: the trap copy of its site, every POST recorded;
// - the three provider hosts: the mock identity providers (idp.ts);
// - any host: CANARY_PATH answers the server's nonce.
// Every POST goes through the leak ledger first. State is in memory and
// cleared by reset() between scenarios.
import { randomBytes } from "node:crypto";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import type { TestCert } from "../../e2e/cert.ts";
import { CANARY_PATH } from "../../e2e/server.ts";
import type { Account, ProviderId, Site, World } from "../gen/model.ts";
import { IDP_HOST, renderSitePage } from "../gen/render.ts";
import { handleIdp } from "./idp.ts";
import { Ledger } from "./ledger.ts";
import type { LabEvent } from "./ledger.ts";
import { handleSite } from "./rp.ts";

export type { LabEvent } from "./ledger.ts";

export interface Session {
  user?: string;
  /** Login in progress: the account whose next step (password, OTP) is expected. */
  pending?: string;
  /** WebAuthn challenge of the last passkey page. */
  challenge?: string;
  /** Provider sign-in in progress (identity provider hosts only). */
  idp?: { client: string; redirect: string; hint: string; pending?: string };
}

/** One request as the handlers see it. */
export interface Exchange {
  host: string;
  path: string;
  post: boolean;
  query: URLSearchParams;
  body: Record<string, string>;
  /** The session of this host, created (with its cookie) on first use. */
  session(): Session;
  /** The session if the request carried one. */
  peek(): Session | undefined;
  html(markup: string, status?: number): void;
  json(status: number, value: unknown): void;
  redirect(to: string): void;
  notFound(): void;
}

/** Shared state of the handlers. */
export interface LabState {
  world: World;
  ledger: Ledger;
  siteHosts: Set<string>;
  /** Accounts created by signup, by site host. */
  created: Map<string, Account>;
  /** Last accepted WebAuthn counter, by site host. */
  counters: Map<string, number>;
  /** One-time provider codes. */
  codes: Map<string, { email: string; provider: ProviderId; host: string }>;
}

export interface LabServer {
  port: number;
  nonce: string;
  ledger: Ledger;
  events(): LabEvent[];
  reset(): void;
  close(): Promise<void>;
}

const COOKIE = "lab_sid";
const MAX_BODY = 64 * 1024;

async function readBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if ((req.headers["content-type"] ?? "").startsWith("application/json")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {};
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed)) if (typeof v === "string") out[k] = v;
    return out;
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

export async function startLabServer(world: World, cert: TestCert): Promise<LabServer> {
  const nonce = randomBytes(16).toString("hex");
  const ledger = new Ledger(world);
  const sessions = new Map<string, Session>();
  const st: LabState = {
    world, ledger, siteHosts: new Set(world.sites.map((s) => s.host)),
    created: new Map(), counters: new Map(), codes: new Map(),
  };
  const sites = new Map<string, Site>(world.sites.map((s) => [s.host, s]));
  const traps = new Map<string, Site>();
  const frames = new Map<string, Site>();
  for (const s of world.sites) {
    if (s.lookalike) traps.set(s.lookalike.host, s);
    if (s.frameHost) frames.set(s.frameHost, s);
  }
  const providers = new Map<string, ProviderId>(
    (Object.entries(IDP_HOST) as [ProviderId, string][]).map(([p, h]) => [h, p]),
  );

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse, secure: boolean): Promise<void> => {
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const url = new URL(req.url ?? "/", `${secure ? "https" : "http"}://lab.invalid`);
    const post = req.method === "POST";
    const body = post ? await readBody(req) : {};
    const headers: Record<string, string> = { "cache-control": "no-store" };
    const sid = new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`).exec(req.headers.cookie ?? "")?.[1];
    let current = sid ? sessions.get(`${host}|${sid}`) : undefined;
    const x: Exchange = {
      host, path: url.pathname, post, query: url.searchParams, body,
      session() {
        if (current) return current;
        const id = randomBytes(12).toString("base64url");
        current = {};
        sessions.set(`${host}|${id}`, current);
        headers["set-cookie"] = `${COOKIE}=${id}; Path=/; HttpOnly${secure ? "; Secure" : ""}; SameSite=Lax`;
        return current;
      },
      peek: () => current,
      html(markup, status = 200) {
        res.writeHead(status, { ...headers, "content-type": "text/html; charset=utf-8" });
        res.end(markup);
      },
      json(status, value) {
        res.writeHead(status, { ...headers, "content-type": "application/json" });
        res.end(JSON.stringify(value));
      },
      redirect(to) {
        res.writeHead(303, { ...headers, location: to });
        res.end();
      },
      notFound() {
        res.writeHead(404, { ...headers, "content-type": "text/plain; charset=utf-8" });
        res.end("Introuvable");
      },
    };

    // Every POST meets the ledger first, the canary path included.
    if (post) ledger.record(host, x.path, body);
    if (x.path === CANARY_PATH) {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end(nonce);
      return;
    }
    const site = sites.get(host);
    if (site) return handleSite(site, x, st, "site");
    const provider = providers.get(host);
    if (provider) return handleIdp(provider, x, st);
    const framed = frames.get(host);
    // The site's auth widget; its events carry the frame host, and the site's secrets posted here are leaks.
    if (framed) return handleSite(framed, x, st, "frame");
    const trapped = traps.get(host);
    if (trapped) {
      if (post) {
        ledger.note({ at: Date.now(), host, kind: "submit", form: "trap", ok: false,
          fields: Object.keys(body).filter((k) => body[k]), reason: "trap" });
      }
      return x.html(renderSitePage(trapped, "trap", { asHost: host, ...(post ? { error: "Identifiant ou mot de passe incorrect" } : {}) }));
    }
    x.notFound();
  };

  const wrap = (secure: boolean) => (req: http.IncomingMessage, res: http.ServerResponse) => {
    handler(req, res, secure).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  };
  const tls = https.createServer({ key: cert.key, cert: cert.cert }, wrap(true));
  const plain = http.createServer(wrap(false));
  const sockets = new Set<net.Socket>();
  const front = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.once("readable", () => {
      const first = socket.read(1) as Buffer | null;
      if (!first) {
        socket.destroy();
        return;
      }
      socket.unshift(first);
      // 0x16: TLS handshake record.
      (first[0] === 0x16 ? tls : plain).emit("connection", socket);
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((resolve) => front.listen(0, "127.0.0.1", resolve));
  const port = (front.address() as net.AddressInfo).port;

  return {
    port,
    nonce,
    ledger,
    events: () => [...ledger.events],
    reset() {
      sessions.clear();
      st.created.clear();
      st.counters.clear();
      st.codes.clear();
      ledger.reset();
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        front.close(() => resolve());
      }),
  };
}
