// Path guards of the dev-only visual harness (ui-shots.mjs): it writes and
// deletes files, so it only touches a directory it is allowed to own.
import { existsSync, mkdirSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

/** Marker file the harness writes in the `site` folder it creates. */
export const MARKER = ".onepass-ui-shots";

/** True when `child` is strictly below `parent` (no `..`, not the same path). */
export function isInside(parent, child) {
  const rel = relative(resolve(parent), resolve(child));
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/** Roots an output directory may live under: the extension folder or the OS temp dir. */
export function allowedRoots(extRoot) {
  const roots = [resolve(extRoot), resolve(tmpdir())];
  try {
    roots.push(realpathSync(tmpdir()));
  } catch {
    // No temp dir: only the extension folder.
  }
  return roots;
}

/** The resolved output directory, or null when it is outside the allowed roots. */
export function checkOutDir(out, extRoot) {
  const abs = resolve(out);
  return allowedRoots(extRoot).some((r) => isInside(r, abs)) ? abs : null;
}

/**
 * Creates `<out>/site` afresh. An existing `site` folder is deleted only if
 * this harness created it (marker file inside); otherwise an error is thrown.
 */
export function prepareSite(out) {
  const site = join(out, "site");
  if (existsSync(site)) {
    const entries = readdirSync(site);
    if (entries.length > 0 && !entries.includes(MARKER)) {
      throw new Error(`${site} exists and was not created by ui-shots: refusing to delete it`);
    }
    rmSync(site, { recursive: true, force: true });
  }
  mkdirSync(site, { recursive: true });
  writeFileSync(join(site, MARKER), "");
  return site;
}

/** The file served for a URL path, or null when it would leave `site`. */
export function servedPath(site, pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  const f = resolve(join(site, decoded));
  return isInside(site, f) ? f : null;
}
