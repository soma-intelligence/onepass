// Hand labelling tool of the real test set (Task 10). `npm run lab:label` serves
// a plain HTML form on 127.0.0.1 (random free port, printed on start): one
// sample per page with the fields of the sample (label, placeholder, aria,
// neighbour text, attributes) and a role menu per field, Précédent / Suivant,
// progress "n / total". Saving writes <labels dir>/<host>.<n>.json atomically
// ({ field index: role | "none" }); a field left blank stays unlabelled.
// Resumable: "/" opens the first sample without a label file.
//
// No script, no stylesheet link, no image, no font: nothing leaves the machine
// (CSP default-src 'none'). The handlers are plain functions of a request
// object so tests need no browser; Host and Origin are checked against DNS
// rebinding and cross-site posts.
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { fileURLToPath } from "node:url";
import { readRealTestHosts } from "../corpus/real-test-hosts.ts";
import type { SampleField } from "../corpus/types.ts";
import { ALL_ROLES, defaultDirs, flatFields, isLabelValue, labelFile, loadPool, loadPrivate, queueOf, readLabels, writeLabels } from "./real.ts";
import type { LabelValue, RealDirs, RealPage } from "./real.ts";
import { existsSync } from "node:fs";

export interface LabelRequest { method: string; url: string; host?: string; origin?: string; body?: string }
export interface LabelResponse { status: number; headers: Record<string, string>; body: string }
export interface LabelApp {
  handle(req: LabelRequest): LabelResponse;
  /** Random per-run secret, embedded in every served form and required on every POST. */
  token: string;
  /** Sets the one Origin a POST may carry (`http://127.0.0.1:<port>`), known once the server listens. */
  setOrigin(origin: string): void;
}
export interface LabelAppOptions { pages: RealPage[]; dirs: RealDirs; /** Allowed POST origin; tests only, the server sets its own. */ origin?: string; /** Fixed token; tests only. */ token?: string }

const MAX_BODY = 1_000_000;
const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const LOCAL_HOST = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/;

const esc = (s: string | number | boolean | undefined): string =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const CSS = `body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#fafaf8;color:#1b1b1a}
main{max-width:860px;margin:0 auto;padding:20px 16px 48px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
h1{font-size:18px;margin:0}.sub{color:#66665f;font-size:13px}
.field{background:#fff;border:1px solid #dcdcd4;border-radius:8px;padding:12px 14px;margin:12px 0}
.field h2{font-size:15px;margin:0 0 6px}dl{display:grid;grid-template-columns:130px 1fr;gap:2px 10px;margin:6px 0 10px;font-size:13px}
dt{color:#66665f}dd{margin:0;word-break:break-word}.dim{color:#9a9a92}select{font-size:15px;padding:6px;min-width:220px}
nav{display:flex;gap:10px;margin-top:18px;position:sticky;bottom:0;background:#fafaf8;padding:10px 0}
button{font-size:15px;padding:8px 16px;border:1px solid #1b1b1a;background:#fff;border-radius:6px;cursor:pointer}
button.main{background:#1b1b1a;color:#fff}`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main></body></html>`;
}

const html = (status: number, body: string, extra: Record<string, string> = {}): LabelResponse =>
  ({ status, headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": CSP, "cache-control": "no-store", ...extra }, body });
const redirect = (to: string): LabelResponse => html(303, "", { location: to });
const fail = (status: number, msg: string): LabelResponse => html(status, page("Erreur", `<h1>${esc(msg)}</h1><p><a href="/">Retour</a></p>`));

function attrs(f: SampleField): [string, string | undefined][] {
  return [
    ["Libellé", f.label], ["Placeholder", f.placeholder], ["aria-label", f.ariaLabel], ["Texte avant", f.before], ["Texte après", f.after],
    ["Balise", f.tag], ["type", f.type], ["name", f.name], ["id", f.id], ["autocomplete", f.autocomplete], ["inputmode", f.inputmode],
    ["maxlength", f.maxlength === undefined ? undefined : String(f.maxlength)], ["Visibilité", f.visibility],
    ["Obligatoire", f.required ? "oui" : "non"], ["pattern", f.hasPattern ? "oui" : "non"],
  ];
}

export function createLabelApp(opts: LabelAppOptions): LabelApp {
  const { pages, dirs } = opts;
  const token = opts.token ?? randomBytes(16).toString("hex");
  let origin = opts.origin;
  const tokenOk = (given: string | null): boolean => {
    if (given === null) return false;
    const a = Buffer.from(given), b = Buffer.from(token);
    return a.length === b.length && timingSafeEqual(a, b);
  };
  const total = pages.length;
  const done = (p: RealPage) => existsSync(labelFile(p, dirs));

  function show(i: number): LabelResponse {
    const p = pages[i]!;
    const saved = readLabels(labelFile(p, dirs));
    const fields = flatFields(p.sample);
    const blocks = fields.map((f, k) => {
      const cur = saved[k];
      const opt = (v: string, text: string) => `<option value="${esc(v)}"${cur === v || (cur === undefined && v === "") ? " selected" : ""}>${esc(text)}</option>`;
      const rows = attrs(f).filter(([, v]) => v !== undefined && v !== "").map(([a, v]) => `<dt>${esc(a)}</dt><dd>${esc(v)}</dd>`).join("");
      return `<section class="field"><h2>Champ ${k + 1} <span class="dim">(${esc(f.label ?? "sans libellé")})</span></h2><dl>${rows}</dl>
<label>Rôle <select name="f${k}">${opt("", "Non étiqueté")}${opt("none", "none (aucun rôle)")}${ALL_ROLES.map((r) => opt(r, r)).join("")}</select></label></section>`;
    }).join("");
    const body = `<header><h1>Étiquetage du jeu de test réel</h1><span class="sub">${i + 1} / ${total}${done(p) ? " · déjà enregistré" : ""}</span></header>
<p class="sub">${esc(p.host)} · page ${p.n} · ${esc(p.category)}${p.private ? " · privé" : ""} · ${fields.length} champ(s)</p>
<form method="post" action="/p/${i}"><input type="hidden" name="token" value="${esc(token)}">${blocks}
<nav><button name="go" value="prev">Précédent</button><button name="go" value="save" class="main">Enregistrer</button><button name="go" value="next">Suivant</button></nav></form>`;
    return html(200, page(`${i + 1} / ${total}`, body));
  }

  function save(i: number, body: string): LabelResponse {
    const p = pages[i]!;
    const form = new URLSearchParams(body);
    if (!tokenOk(form.get("token"))) return fail(403, "Jeton refusé");
    const count = flatFields(p.sample).length;
    const labels: Record<number, LabelValue> = {};
    for (let k = 0; k < count; k++) {
      const v = form.get(`f${k}`);
      if (v === null || v === "") continue;
      if (!isLabelValue(v)) return fail(400, `Rôle inconnu : ${v}`);
      labels[k] = v;
    }
    // A page never saved and left entirely blank leaves no file (it stays to do).
    if (Object.keys(labels).length > 0 || done(p)) writeLabels(labelFile(p, dirs), labels);
    const go = form.get("go");
    const to = go === "next" ? Math.min(i + 1, total - 1) : go === "prev" ? Math.max(i - 1, 0) : i;
    return redirect(`/p/${to}`);
  }

  return {
    token,
    setOrigin(o) { origin = o; },
    handle(req) {
      if (!req.host || !LOCAL_HOST.test(req.host)) return fail(403, "Hôte refusé");
      // A POST must come from this server's own page: Origin present and equal to it ("null" and other ports are refused).
      if (req.method === "POST" && (origin === undefined || req.origin !== origin)) return fail(403, "Origine refusée");
      const path = req.url.split("?")[0]!;
      if (path === "/") {
        if (total === 0) return html(200, page("Aucun échantillon", `<header><h1>Étiquetage</h1><span class="sub">0 / 0</span></header><p>Aucun échantillon à étiqueter.</p>`));
        const first = pages.findIndex((p) => !done(p));
        return redirect(`/p/${first < 0 ? 0 : first}`);
      }
      const m = /^\/p\/(\d+)$/.exec(path);
      if (!m) return fail(404, "Page introuvable");
      const i = Number(m[1]);
      if (!Number.isSafeInteger(i) || i >= total) return fail(404, "Page introuvable");
      if (req.method === "GET") return show(i);
      if (req.method === "POST") return save(i, req.body ?? "");
      return fail(405, "Méthode refusée");
    },
  };
}

export interface LabelServer { host: "127.0.0.1"; port: number; server: Server; close(): Promise<void> }

/** Binds 127.0.0.1 on a free port (0) and serves `createLabelApp`. */
export function startLabelServer(opts: LabelAppOptions): Promise<LabelServer> {
  const app = createLabelApp(opts);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let refused = false;
    req.on("data", (c: Buffer) => {
      if (refused) return;
      size += c.length;
      if (size > MAX_BODY) {
        refused = true;
        if (!res.headersSent) res.writeHead(413).end();
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (refused) return;
      const r = app.handle({ method: req.method ?? "GET", url: req.url ?? "/", host: req.headers.host, origin: req.headers.origin, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(r.status, r.headers).end(r.body);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") return reject(new Error("no address"));
      app.setOrigin(`http://127.0.0.1:${addr.port}`);
      resolve({ host: "127.0.0.1", port: addr.port, server, close: () => new Promise((ok) => { server.close(() => ok()); server.closeAllConnections(); }) });
    });
  });
}

async function main(): Promise<void> {
  const dirs = defaultDirs();
  const { hosts } = readRealTestHosts();
  const pages = queueOf(hosts, loadPool(dirs), loadPrivate(dirs));
  const srv = await startLabelServer({ pages, dirs });
  console.log(`Étiquetage : ${pages.length} pages, ouvrir http://127.0.0.1:${srv.port}/ (Ctrl-C pour arrêter)`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) void main();
