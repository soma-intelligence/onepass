// Prepares the signed-in profile of the real-site bench: opens Playwright's
// Chromium (Chrome for Testing), headed, on the persistent profile folder
// lab/out/real-profile/, with a start page listing suggested sites. The tester
// signs in by hand; this tool never types anything and never touches the
// profile's cookie files. While the browser runs it asks the browser itself
// which hosts hold cookies and, when the window is closed, writes
// real-profile/sites.json with those host names only (never a cookie value).
// Usage: node --experimental-strip-types lab/real/replica/profile.ts [--profile lab/out/real-profile] [--replicas lab/out/replicas]
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { getDomain } from "tldts";
import { defaultProfileDir, defaultReplicaDir, listReplicas, readTranco, type ReplicaMeta } from "./common.ts";

export const SUGGESTED = 30;
/** Infrastructure hosts of the Tranco list: no page a person signs in to. */
const INFRA = /(cdn|akamai|gstatic|googleapis|amazonaws|cloudfront|fbcdn|doubleclick|googlevideo|gtld|domaincontrol|akadns|edgekey|edgesuite|azureedge|trafficmanager|root-servers|apple-dns|icloud-content|ntp|dns|tiktokcdn|whatsapp\.net|msedge|windowsupdate|digicert|sentry|googletagmanager|googlesyndication|app-measurement|ezviz|hicloudcam|cloudflare\.net|static|metric|telemetry|analytics)/i;

export interface Suggestion { host: string; url: string; captured: boolean; }

/** The first `n` sites with a sign-in: captured ones (sign-in form found) first, then plausible Tranco hosts. */
export function suggestSites(metas: readonly ReplicaMeta[], tranco: readonly string[], n = SUGGESTED): Suggestion[] {
  const out: Suggestion[] = [];
  const seen = new Set<string>();
  for (const m of metas) {
    if (out.length >= n) break;
    if (m.status !== "ok" || !m.signInForm || !m.loginUrl) continue;
    seen.add(m.host);
    out.push({ host: m.host, url: m.loginUrl, captured: true });
  }
  const metaHosts = new Set(metas.map((m) => m.host));
  for (const h of tranco) {
    if (out.length >= n) break;
    if (seen.has(h) || metaHosts.has(h) || INFRA.test(h)) continue;
    seen.add(h);
    out.push({ host: h, url: `https://${h}/`, captured: false });
  }
  return out;
}

/** Host names of cookies (leading dot dropped), sorted, unique. Values are never read into the result. */
export function cookieHosts(cookies: readonly { domain: string }[]): string[] {
  return [...new Set(cookies.map((c) => c.domain.replace(/^\./, "").toLowerCase()).filter(Boolean))].sort();
}

export function sitesFile(hosts: readonly string[], now = new Date()): string {
  const sites = [...new Set(hosts.map((h) => getDomain(h) ?? h))].sort();
  return JSON.stringify({ updatedAt: now.toISOString(), note: "Host names with cookies in the bench profile. No cookie value is ever stored here.", sites, hosts }, null, 2) + "\n";
}

const esc = (s: string): string => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);

export function startPage(list: readonly Suggestion[]): string {
  const items = list
    .map((s, i) => `<li><a href="${esc(s.url)}" target="_blank" rel="noopener">${i + 1}. ${esc(s.host)}</a>${s.captured ? "" : ' <span class="muted">(pas encore capturé)</span>'}</li>`)
    .join("\n");
  return `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Profil du banc OnePass</title>
<style>body{font:15px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#1d1d1f}
h1{font-size:22px}ol,ul{padding-left:0;list-style:none;columns:2}li{margin:4px 0}a{color:#3a3ad0}.muted{color:#8e8e93;font-size:13px}
.box{background:#f5f5f7;border-radius:10px;padding:12px 16px}</style>
<h1>Profil connecté du banc sur sites réels</h1>
<div class="box"><p>Connecte-toi à la main aux sites de ton choix (un compte de test si possible). Cet outil ne tape rien et ne lit aucun cookie hors du navigateur.</p>
<p>Ferme la fenêtre quand tu as fini : la liste des sites qui ont des cookies (noms d'hôtes seulement) sera écrite dans <code>real-profile/sites.json</code>.</p></div>
<h2>Sites suggérés</h2>
<ul>
${items}
</ul>
</html>`;
}

async function main(): Promise<void> {
  const arg = (name: string): string | undefined => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; };
  const profile = arg("--profile") ?? defaultProfileDir();
  const replicas = arg("--replicas") ?? defaultReplicaDir();
  mkdirSync(profile, { recursive: true });
  const startPath = join(profile, "onepass-start.html");
  writeFileSync(startPath, startPage(suggestSites(listReplicas(replicas), readTranco())));

  const pw = (await import("playwright-core")) as unknown as { chromium?: any; default?: { chromium: any } };
  const chromium = pw.chromium ?? pw.default!.chromium;
  const ctx = await chromium.launchPersistentContext(profile, { headless: false, channel: "chromium", viewport: null });
  let last: string[] = [];
  let finished = false;
  const snapshot = async (): Promise<void> => {
    try { last = cookieHosts(await ctx.cookies()); } catch { /* browser closing: keep the last list */ }
  };
  const finish = async (): Promise<void> => {
    if (finished) return;
    finished = true;
    clearInterval(timer);
    writeFileSync(join(profile, "sites.json"), sitesFile(last));
    console.log(`sites.json written: ${last.length} hosts with cookies`);
    await ctx.close().catch(() => {});
  };
  const timer = setInterval(() => { void snapshot(); }, 5_000);
  const watch = (p: any): void => {
    p.on("close", async () => {
      if (finished) return;
      await snapshot();
      if (ctx.pages().length === 0) await finish(); // last window closed (macOS keeps the app alive)
    });
  };
  ctx.pages().forEach(watch);
  ctx.on("page", watch);
  ctx.on("close", () => { void finish(); });
  process.on("SIGINT", () => { void snapshot().then(finish).then(() => process.exit(0)); });
  const page = ctx.pages()[0] ?? (await ctx.newPage());
  await page.goto(pathToFileURL(startPath).href);
  console.log("Sign in by hand, then close the window.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; });
}
