// Local test server (spec 11.3): fictional sites served on 127.0.0.1 only,
// routed by the `Host` header. One TCP port carries both HTTPS and plain HTTP
// (the first byte tells a TLS handshake apart), so a single
// `--host-resolver-rules` entry sends every test host here while the URLs
// keep their default ports (`https://atlas-cloud.test/`, `http://atlas-cloud.test/`).
//
// Hosts:
// - atlas-cloud.test (and its subdomains): the fictional "Atlas Cloud" site;
// - accounts.google.com: a neutral, fictional account chooser ("Choisir un
//   compte"), then identifier and password steps (no logo, colors or markup
//   of the real provider);
// - lookalikes and evil.test: trap pages that record anything posted to them.
// Credentials checked here are the fictional ones of
// core/onepass-native-host/fixtures/e2e.json.
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { TestCert } from "./cert";

const PAGES = fileURLToPath(new URL("./pages/", import.meta.url));

/** Fixture values the pages check (fixtures/e2e.json `_comment`). */
export const FX = {
  atlas: { email: "alex@atlas.dev", password: "Atl4s-Pass-0001", totpSecret: "JBSWY3DPEHPK3PXP" },
  ops: { email: "alex.ops@atlas.dev", password: "Atl4s-Ops-0010" },
  googlePerso: { email: "alex.perso@example.com", password: "G-Perso-0005" },
  googlePro: { email: "alex.pro@example.com", password: "G-Pro-0006" },
  card: { holder: "Alex Martin", number: "4242 4242 4242 4242", month: "04", year: "2029", cvv: "123" },
  identity: {
    given: "Alex",
    family: "Martin",
    email: "alex@atlas.dev",
    tel: "+33 6 00 00 00 00",
    org: "Atlas",
    line1: "1 rue de l'Exemple",
    zip: "69000",
    city: "Lyon",
  },
} as const;

// ---- TOTP (RFC 6238, SHA-1, 30 s, 6 digits) ----

function base32(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error("bad base32");
    bits += v.toString(2).padStart(5, "0");
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const off = (mac[mac.length - 1] ?? 0) & 0xf;
  const n = (mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return String(n).padStart(6, "0");
}

function totpOk(secret: string, code: string): boolean {
  const now = Date.now();
  return [-30_000, 0, 30_000].some((d) => totp(secret, now + d) === code.trim());
}

// ---- templates ----

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

const cache = new Map<string, string>();
function file(name: string): string {
  let t = cache.get(name);
  if (t === undefined) {
    t = readFileSync(join(PAGES, name), "utf8");
    cache.set(name, t);
  }
  return t;
}

/** Fills `{{name}}` with escaped values; `raw` values are inserted as is (server-built markup). */
function fill(t: string, vars: Record<string, string>, raw: Record<string, string> = {}): string {
  return t.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => raw[k] ?? esc(vars[k] ?? ""));
}

function page(title: string, name: string, vars: Record<string, string> = {}, raw: Record<string, string> = {}): string {
  return fill(file("layout.html"), { title }, { body: fill(file(name), vars, raw) });
}

// ---- server state ----

interface Session {
  email?: string;
  pending?: string;
  /** accounts.google.com: the account picked in the chooser, and the return URL. */
  chosen?: string;
  continueUrl?: string;
}

export interface Captured {
  host: string;
  path: string;
  body: Record<string, string>;
}

/** Path every host answers on with the server's nonce (fixtures.ts canary). */
export const CANARY_PATH = "/__onepass_e2e_canary";

export interface TestServer {
  port: number;
  /** Random per server: a page showing it was served by this process. */
  nonce: string;
  /** Every POST received by a trap host (lookalikes, evil.test). */
  captured: Captured[];
  /** Accounts that signed in through the fictional provider, in order. */
  providerSignIns: string[];
  /** Users of atlas-cloud.test (email to password). */
  users: Map<string, string>;
  reset(): void;
  close(): Promise<void>;
}

const TRAP_HOSTS = new Set(["atlass-cloud.test", "atlas-cloud.test.evil.test", "evil.test", "sso.evil.test", "accounts.google.com.evil.test"]);

function initialUsers(): Map<string, string> {
  return new Map([
    [FX.atlas.email, FX.atlas.password],
    [FX.ops.email, FX.ops.password],
    // Known to the site only: the "save a new login" flow.
    ["alex.new@atlas.dev", "Nouv-Pass-0042"],
  ]);
}

const GOOGLE_PASSWORDS = new Map<string, string>([
  [FX.googlePerso.email, FX.googlePerso.password],
  [FX.googlePro.email, FX.googlePro.password],
]);

async function readBody(req: http.IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 64 * 1024) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString("utf8")));
}

export async function startServer(cert: TestCert): Promise<TestServer> {
  const nonce = randomBytes(16).toString("hex");
  const sessions = new Map<string, Session>();
  const codes = new Map<string, string>();
  const state: Omit<TestServer, "port" | "close" | "nonce"> = {
    captured: [],
    providerSignIns: [],
    users: initialUsers(),
    reset() {
      sessions.clear();
      codes.clear();
      this.captured.length = 0;
      this.providerSignIns.length = 0;
      this.users = initialUsers();
    },
  };

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse, secure: boolean): Promise<void> => {
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const url = new URL(req.url ?? "/", `${secure ? "https" : "http"}://${host}`);
    const path = url.pathname;
    const post = req.method === "POST";
    const body = post ? await readBody(req) : {};

    const cookieName = "e2e_sid";
    const sid = /(?:^|;\s*)e2e_sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? "")?.[1];
    let s = sid ? sessions.get(`${host}|${sid}`) : undefined;
    const headers: Record<string, string> = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" };
    const session = (): Session => {
      if (s) return s;
      const id = randomBytes(12).toString("base64url");
      s = {};
      sessions.set(`${host}|${id}`, s);
      headers["set-cookie"] = `${cookieName}=${id}; Path=/; HttpOnly${secure ? "; Secure" : ""}; SameSite=Lax`;
      return s;
    };
    const send = (html: string, status = 200) => {
      res.writeHead(status, headers);
      res.end(html);
    };
    const redirect = (to: string) => {
      res.writeHead(303, { ...headers, location: to });
      res.end();
    };

    if (path === CANARY_PATH) {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end(nonce);
      return;
    }
    if (path === "/style.css") {
      res.writeHead(200, { "content-type": "text/css; charset=utf-8" });
      res.end(file("style.css"));
      return;
    }
    if (path === "/favicon.ico") {
      res.writeHead(404);
      res.end();
      return;
    }

    // ---- trap hosts: record and show nothing useful ----
    if (TRAP_HOSTS.has(host)) {
      if (post) {
        state.captured.push({ host, path, body });
        send(page("Merci", "atlas/status.html", { brand: host, status: "Reçu", detail: "" }));
        return;
      }
      if (host === "evil.test" && path === "/frame") return send(page("Autre site", "evil/frame.html"));
      if (host === "accounts.google.com.evil.test") {
        if (path === "/signin/identifier") {
          return send(page("Connexion", "google/identifier.html", { chosen: "", error: "", action: path }));
        }
        const self = (email: string) => `/signin/identifier?hint=${encodeURIComponent(email)}`;
        return send(
          page("Choisir un compte", "google/chooser.html", {
            client: "atlas-cloud.test",
            persoUrl: self(FX.googlePerso.email),
            proUrl: self(FX.googlePro.email),
            otherUrl: "/signin/identifier",
          }),
        );
      }
      const brand = host === "sso.evil.test" ? "Connexion unique" : "Atlas Cloud";
      return send(page("Connexion", "atlas/login.html", { brand, error: "", action: path }));
    }

    // ---- fictional provider ----
    if (host === "accounts.google.com") {
      if (path === "/o/oauth2/auth") {
        const g = session();
        g.continueUrl = url.searchParams.get("redirect_uri") ?? "";
        const pick = (email: string) => `/signin/identifier?hint=${encodeURIComponent(email)}`;
        return send(
          page("Choisir un compte", "google/chooser.html", {
            client: url.searchParams.get("client") ?? "",
            persoUrl: pick(FX.googlePerso.email),
            proUrl: pick(FX.googlePro.email),
            otherUrl: "/signin/identifier",
          }),
        );
      }
      if (path === "/signin/identifier") {
        const g = session();
        if (!post) {
          g.chosen = url.searchParams.get("hint") ?? "";
          return send(page("Connexion", "google/identifier.html", { chosen: g.chosen, error: "", action: "/signin/identifier" }));
        }
        const email = (body.email ?? "").trim().toLowerCase();
        if (!GOOGLE_PASSWORDS.has(email)) {
          return send(page("Connexion", "google/identifier.html", { chosen: g.chosen ?? "", error: "Compte introuvable", action: "/signin/identifier" }));
        }
        g.pending = email;
        return redirect("/signin/password");
      }
      if (path === "/signin/password") {
        const g = session();
        if (!g.pending) return redirect("/signin/identifier");
        if (!post) return send(page("Mot de passe", "google/password.html", { email: g.pending, error: "", action: "/signin/password" }));
        if (GOOGLE_PASSWORDS.get(g.pending) !== body.password) {
          return send(page("Mot de passe", "google/password.html", { email: g.pending, error: "Mot de passe incorrect", action: "/signin/password" }));
        }
        const code = randomBytes(12).toString("base64url");
        codes.set(code, g.pending);
        state.providerSignIns.push(g.pending);
        const back = g.continueUrl && g.continueUrl.startsWith("https://atlas-cloud.test/") ? g.continueUrl : "https://atlas-cloud.test/oauth/callback";
        return redirect(`${back}?code=${code}`);
      }
      return send("Introuvable", 404);
    }

    // ---- Atlas Cloud and its subdomains ----
    if (host === "atlas-cloud.test" || host.endsWith(".atlas-cloud.test")) {
      const brand = host === "docs.atlas-cloud.test" ? "Atlas Docs" : "Atlas Cloud";
      const loginPage = (error = "", extra = "") =>
        page("Atlas Cloud - Connexion", "atlas/login.html", { brand, error, action: path }, { extra });
      const signedIn = (detail: string) => {
        session().email = detail;
        return redirect("/home");
      };
      const google = (client: string, providerHost = "accounts.google.com") =>
        `https://${providerHost}/o/oauth2/auth?client=${encodeURIComponent(client)}&redirect_uri=${encodeURIComponent("https://atlas-cloud.test/oauth/callback")}`;

      switch (path) {
        case "/":
          return redirect("/login");
        case "/home":
          return send(
            page("Atlas Cloud", "atlas/status.html", {
              brand,
              status: s?.email ? "Connecté" : "Non connecté",
              detail: s?.email ?? "",
            }),
          );
        case "/logout":
          if (s) delete s.email;
          return redirect("/login");
        case "/login":
          if (host === "docs.atlas-cloud.test" && !post) {
            return send(page("Atlas Docs - Connexion", "atlas/provider-login.html", { providerUrl: google("atlas-docs") }));
          }
          if (!post) return send(loginPage());
          if (state.users.get((body.email ?? "").trim().toLowerCase()) === body.password) return signedIn(body.email ?? "");
          return send(loginPage("Identifiant ou mot de passe incorrect"));
        case "/login-google": {
          // The site's own form plus "Continuer avec Google" (no link in the vault yet).
          const extra = `<p><a class="button" id="provider" href="${esc(google("atlas-cloud"))}">Continuer avec Google</a></p>`;
          if (!post) return send(loginPage("", extra));
          if (state.users.get((body.email ?? "").trim().toLowerCase()) === body.password) return signedIn(body.email ?? "");
          return send(loginPage("Identifiant ou mot de passe incorrect", extra));
        }
        case "/login-fake-provider":
          return send(
            page("Atlas Docs - Connexion", "atlas/provider-login.html", {
              providerUrl: google("atlas-docs", "accounts.google.com.evil.test"),
            }),
          );
        case "/invisible":
          return send(page("Atlas Cloud - Connexion", "atlas/invisible.html"));
        case "/captcha":
          if (post) return send(loginPage("Validez le CAPTCHA"));
          return send(loginPage("", file("atlas/captcha.html")));
        case "/push":
          if (!post) return send(loginPage());
          return send(page("Atlas Cloud - Validation", "atlas/push.html"));
        case "/multistep":
        case "/captcha-step":
        case "/lookalike-login":
        case "/sso-login": {
          if (!post) return send(page("Atlas Cloud - Connexion", "atlas/identifier.html", { error: "", action: path }));
          const email = (body.email ?? "").trim().toLowerCase();
          if (path === "/sso-login") return redirect("https://sso.evil.test/login");
          if (path === "/lookalike-login") return redirect("https://atlas-cloud.test.evil.test/login");
          if (!state.users.has(email)) {
            return send(page("Atlas Cloud - Connexion", "atlas/identifier.html", { error: "Compte introuvable", action: path }));
          }
          session().pending = email;
          return redirect(`${path}/password`);
        }
        case "/multistep/password":
        case "/captcha-step/password": {
          const flow = path.slice(0, path.indexOf("/", 1));
          if (!s?.pending) return redirect(flow);
          const extra = flow === "/captcha-step" ? file("atlas/captcha.html") : "";
          const show = (error = "") =>
            send(page("Atlas Cloud - Mot de passe", "atlas/password.html", { email: s?.pending ?? "", error, action: path }, { extra }));
          if (!post) return show();
          if (flow === "/captcha-step") return show("Validez le CAPTCHA");
          if (state.users.get(s.pending) !== body.password) return show("Mot de passe incorrect");
          return redirect("/multistep/otp");
        }
        case "/multistep/otp": {
          if (!s?.pending) return redirect("/multistep");
          const show = (error = "") => send(page("Atlas Cloud - Vérification", "atlas/otp.html", { error, action: path }));
          if (!post) return show();
          if (s.pending !== FX.atlas.email || !totpOk(FX.atlas.totpSecret, body.code ?? "")) return show("Code incorrect");
          const email = s.pending;
          delete s.pending;
          return signedIn(email);
        }
        case "/signup": {
          const show = (error = "") => send(page("Atlas Cloud - Inscription", "atlas/signup.html", { error }));
          if (!post) return show();
          const email = (body.email ?? "").trim().toLowerCase();
          if (!email || !body.password || body.password !== body.confirm) return show("Les mots de passe ne correspondent pas");
          if (state.users.has(email)) return show("Ce compte existe déjà");
          state.users.set(email, body.password);
          return signedIn(email);
        }
        case "/change-password": {
          const show = (error = "") =>
            send(page("Atlas Cloud - Sécurité", "atlas/change-password.html", { email: FX.ops.email, error }));
          if (!post) return show();
          const email = (body.email ?? "").trim().toLowerCase();
          if (state.users.get(email) !== body.current) return show("Mot de passe actuel incorrect");
          if (!body.password || body.password !== body.confirm) return show("Les mots de passe ne correspondent pas");
          state.users.set(email, body.password);
          return send(page("Atlas Cloud", "atlas/status.html", { brand, status: "Mot de passe modifié", detail: email }));
        }
        case "/checkout":
          return send(page("Atlas Cloud - Paiement", "atlas/checkout.html"));
        case "/profile":
          return send(page("Atlas Cloud - Profil", "atlas/profile.html"));
        case "/oauth/callback": {
          const email = codes.get(url.searchParams.get("code") ?? "");
          if (!email) return send(page("Atlas Cloud", "atlas/status.html", { brand, status: "Échec", detail: "" }));
          codes.delete(url.searchParams.get("code") ?? "");
          return send(page("Atlas Cloud", "atlas/status.html", { brand, status: "Connecté", detail: `avec Google (${email})` }));
        }
        default:
          return send("Introuvable", 404);
      }
    }
    send("Introuvable", 404);
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
  return Object.assign(state, {
    port,
    nonce,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        front.close(() => resolve());
      }),
  }) as TestServer;
}
