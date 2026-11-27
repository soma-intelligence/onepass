// Fetches the official Bitwarden Chrome extension for the real-site bench
// ("Machine polluée" in ../README.md). Only source: the GitHub releases of
// bitwarden/clients, latest non-draft, non-prerelease `browser-v*` release,
// asset `bit-dist-chrome-<version>.zip` (the store build; `dist-chrome-*`
// and `oss-dist-chrome-*` are fallbacks). The zip lands in its own new
// directory, is checked against the digest the API publishes for the asset
// (or its sha256 is recorded when the API gives none), its entry names are
// vetted, and it is extracted with the system `unzip` into a fresh directory
// that then replaces lab/out/managers/bitwarden/ (git-ignored). Nothing from
// the download is ever executed here: Chromium loads it later as an unpacked
// extension.
//
// Run: node --experimental-strip-types lab/real/managers/fetch-bitwarden.ts
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RELEASES_API = "https://api.github.com/repos/bitwarden/clients/releases?per_page=50";
/** Hosts a release asset may be served from (GitHub redirects downloads to its object store). */
const DOWNLOAD_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);
const USER_AGENT = "OnePassLabReal";

/** extension/lab/out/managers/ (git-ignored with the rest of lab/out/). */
export const MANAGERS_OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "out", "managers");
export const BITWARDEN_DIR = join(MANAGERS_OUT, "bitwarden");
/** Provenance of the extracted folder: release, asset, digest, how it was checked. */
export const BITWARDEN_PROVENANCE = join(MANAGERS_OUT, "bitwarden.json");

export interface ReleaseAsset {
  name: string;
  size: number;
  browser_download_url: string;
  /** "sha256:<hex>" when GitHub publishes one (assets uploaded since mid 2025). */
  digest?: string | null;
}

export interface Release {
  tag_name: string;
  draft: boolean;
  prerelease: boolean;
  published_at: string | null;
  assets: ReleaseAsset[];
}

export interface Provenance {
  release: string;
  version: string;
  asset: string;
  url: string;
  size: number;
  sha256: string;
  /** "published-digest": matched the API's digest; "recorded-only": the API gave none, sha256 recorded. */
  check: "published-digest" | "recorded-only";
  fetchedAt: string;
}

const TAG = /^browser-v(\d+)\.(\d+)\.(\d+)$/;

/** Numeric version of a `browser-vX.Y.Z` tag, or null for any other tag. */
export function browserVersion(tag: string): [number, number, number] | null {
  const m = TAG.exec(tag);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** The newest published (non-draft, non-prerelease) `browser-v*` release, by version number. */
export function pickRelease(releases: readonly Release[]): Release {
  let best: { r: Release; v: [number, number, number] } | null = null;
  for (const r of releases) {
    if (r.draft || r.prerelease) continue;
    const v = browserVersion(r.tag_name);
    if (!v) continue;
    if (isNewer(v, best?.v)) best = { r, v };
  }
  if (!best) throw new Error("fetch-bitwarden: no published browser-v* release in the GitHub API answer");
  return best.r;
}

function isNewer(v: [number, number, number], than: [number, number, number] | undefined): boolean {
  if (!than) return true;
  for (let i = 0; i < 3; i++) if (v[i]! !== than[i]!) return v[i]! > than[i]!;
  return false;
}

/** Asset name preference: store build first, then the older plain name, then the OSS build. */
const ASSET_PREFIXES = ["bit-dist-chrome-", "dist-chrome-", "oss-dist-chrome-"];

/** The Chrome build of a release (see ASSET_PREFIXES). */
export function pickAsset(release: Release): ReleaseAsset {
  for (const prefix of ASSET_PREFIXES) {
    const a = release.assets.find((x) => x.name.startsWith(prefix) && x.name.endsWith(".zip"));
    if (a) return a;
  }
  throw new Error(`fetch-bitwarden: release ${release.tag_name} has no dist-chrome-*.zip asset`);
}

/** Lowercase sha256 hex of a "sha256:<hex>" digest, null when absent or of another kind. */
export function parseDigest(digest: string | null | undefined): string | null {
  if (!digest) return null;
  const m = /^sha256:([0-9a-fA-F]{64})$/.exec(digest.trim());
  return m ? m[1]!.toLowerCase() : null;
}

/** A download URL we accept: https on GitHub, path under bitwarden/clients releases. */
export function isOfficialAssetUrl(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === "https:" && u.hostname === "github.com" && u.pathname.startsWith("/bitwarden/clients/releases/download/browser-v");
}

/**
 * Zip entry names safe to extract: relative, no `..` segment, no backslash,
 * no drive letter, no NUL. One bad name rejects the whole archive.
 */
export function unsafeEntries(names: readonly string[]): string[] {
  return names.filter((n) => {
    if (n.length === 0 || n.includes("\0") || n.includes("\\")) return true;
    if (n.startsWith("/") || /^[A-Za-z]:/.test(n)) return true;
    return n.split("/").some((seg) => seg === "..");
  });
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json", "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error(`fetch-bitwarden: GitHub API ${res.status} ${res.statusText}`);
  return res.json();
}

/** Downloads `url`, following redirects by hand so every hop stays on a GitHub host. */
async function download(url: string): Promise<Buffer> {
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const host = new URL(current).hostname;
    if (new URL(current).protocol !== "https:" || !DOWNLOAD_HOSTS.has(host)) {
      throw new Error(`fetch-bitwarden: refusing download from ${host}`);
    }
    const res = await fetch(current, { redirect: "manual", headers: { "User-Agent": USER_AGENT } });
    if (res.status >= 300 && res.status < 400) {
      const next = res.headers.get("location");
      if (!next) throw new Error("fetch-bitwarden: redirect without location");
      current = new URL(next, current).href;
      continue;
    }
    if (!res.ok) throw new Error(`fetch-bitwarden: download ${res.status} ${res.statusText}`);
    return Buffer.from(await res.arrayBuffer());
  }
  throw new Error("fetch-bitwarden: too many redirects");
}

export async function fetchBitwarden(log: (s: string) => void = console.log): Promise<Provenance> {
  const releases = (await getJson(RELEASES_API)) as Release[];
  const release = pickRelease(releases);
  const asset = pickAsset(release);
  if (!isOfficialAssetUrl(asset.browser_download_url)) {
    throw new Error(`fetch-bitwarden: unexpected asset URL ${asset.browser_download_url}`);
  }
  log(`release ${release.tag_name}, asset ${asset.name} (${asset.size} bytes)`);

  mkdirSync(MANAGERS_OUT, { recursive: true });
  // Download and extraction each get their own new, empty directory.
  const dlDir = mkdtempSync(join(MANAGERS_OUT, "download-"));
  const exDir = mkdtempSync(join(MANAGERS_OUT, "extract-"));
  try {
    const bytes = await download(asset.browser_download_url);
    if (bytes.length !== asset.size) throw new Error(`fetch-bitwarden: size ${bytes.length}, release says ${asset.size}`);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const published = parseDigest(asset.digest);
    if (published && published !== sha256) {
      throw new Error(`fetch-bitwarden: sha256 ${sha256} does not match the published digest ${published}`);
    }
    log(published ? `sha256 ${sha256} matches the published digest` : `no published digest; recorded sha256 ${sha256}`);
    const zip = join(dlDir, asset.name);
    writeFileSync(zip, bytes);

    const names = execFileSync("unzip", ["-Z1", zip], { encoding: "utf8", maxBuffer: 64 << 20 }).split("\n").filter(Boolean);
    const bad = unsafeEntries(names);
    if (bad.length) throw new Error(`fetch-bitwarden: unsafe zip entries: ${bad.slice(0, 5).join(", ")}`);
    execFileSync("unzip", ["-q", "-o", zip, "-d", exDir], { stdio: "inherit" });

    // The manifest sits at the root of the zip in current releases; accept one wrapping folder too.
    let root = exDir;
    if (!existsSync(join(root, "manifest.json"))) {
      const tops = [...new Set(names.map((n) => n.split("/")[0]!))];
      if (tops.length === 1 && existsSync(join(exDir, tops[0]!, "manifest.json"))) root = join(exDir, tops[0]!);
      else throw new Error("fetch-bitwarden: no manifest.json in the archive");
    }
    const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as { version?: string; manifest_version?: number };
    rmSync(BITWARDEN_DIR, { recursive: true, force: true });
    renameSync(root, BITWARDEN_DIR);

    const prov: Provenance = {
      release: release.tag_name,
      version: manifest.version ?? "",
      asset: asset.name,
      url: asset.browser_download_url,
      size: asset.size,
      sha256,
      check: published ? "published-digest" : "recorded-only",
      fetchedAt: new Date().toISOString(),
    };
    writeFileSync(BITWARDEN_PROVENANCE, JSON.stringify(prov, null, 2) + "\n");
    log(`extracted manifest v${manifest.manifest_version} version ${prov.version} to ${BITWARDEN_DIR}`);
    return prov;
  } finally {
    rmSync(dlDir, { recursive: true, force: true });
    rmSync(exDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  fetchBitwarden().catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
