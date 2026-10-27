// Service worker entry point. Listeners are registered synchronously at top
// level so that the browser can wake the worker for them.
import { ext } from "../shared/browser";
import { createBackground } from "./app";
import type { BgExt } from "./ext";
import { browserName } from "./pairing";

createBackground(ext as unknown as BgExt, { browser: browserName(navigator.userAgent) }).install();
