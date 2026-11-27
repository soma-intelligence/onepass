// Other password managers for the real-site bench ("Machine polluée" in
// ../README.md): the real Bitwarden extension (fetched by fetch-bitwarden.ts)
// and the fake 1Password, LastPass and Dashlane extensions in fake/. The
// caller passes the returned folders to Chromium with --load-extension
// (comma-separated, next to OnePass's own dist folder).
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BITWARDEN_DIR } from "./fetch-bitwarden.ts";

export type FakeManager = "1password" | "lastpass" | "dashlane";

export const FAKE_MANAGERS: readonly FakeManager[] = ["1password", "lastpass", "dashlane"];

/** lab/real/managers/fake/ (one unpacked MV3 extension per fake manager). */
export const FAKE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "fake");

export { BITWARDEN_DIR };

/** Unpacked extension folder of one fake manager. */
export function fakeExtensionDir(fake: FakeManager): string {
  return join(FAKE_ROOT, fake);
}

/**
 * Absolute paths of the unpacked extensions to load next to OnePass:
 * Bitwarden first when asked (throws if it was never fetched), then each
 * requested fake once, in the order given.
 */
export function managerExtensions(opts: { bitwarden: boolean; fakes: ("1password" | "lastpass" | "dashlane")[] }): string[] {
  const out: string[] = [];
  if (opts.bitwarden) {
    if (!existsSync(join(BITWARDEN_DIR, "manifest.json"))) {
      throw new Error(
        `managerExtensions: Bitwarden is not extracted in ${BITWARDEN_DIR}. ` +
          "Run `node --experimental-strip-types lab/real/managers/fetch-bitwarden.ts` in extension/ first.",
      );
    }
    out.push(BITWARDEN_DIR);
  }
  for (const fake of new Set(opts.fakes)) {
    if (!FAKE_MANAGERS.includes(fake)) throw new Error(`managerExtensions: unknown fake manager "${String(fake)}"`);
    out.push(fakeExtensionDir(fake));
  }
  return out;
}
