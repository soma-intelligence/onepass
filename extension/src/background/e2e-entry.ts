// Service worker entry of the end-to-end security build only
// (`node build.mjs --e2e`, dist/<browser>-e2e/): the regular entry
// (index.ts), plus a handle that lets e2e/security.spec.ts call the router
// with a forged sender, as a compromised content script would, and ask the
// host directly. Regular builds never bundle this file.
import { ext } from "../shared/browser";
import { createBackground } from "./app";
import type { BgExt } from "./ext";
import { browserName } from "./pairing";
import { createRouter } from "./router";

const bgExt = ext as unknown as BgExt;
const bg = createBackground(bgExt, { browser: browserName(navigator.userAgent) });
bg.install();

(globalThis as { __onepassE2E?: unknown }).__onepassE2E = {
  router: createRouter(bgExt.runtime, bg.handlers),
  session: bg.session,
  filler: bg.filler,
};
