// Service worker entry point. Listeners are registered synchronously at top
// level so that the browser can wake the worker for them.
import { ext } from "../shared/browser";
import { createBackground } from "./app";
import type { BgExt } from "./ext";
import { browserName } from "./pairing";

createBackground(ext as unknown as BgExt, { browser: browserName(navigator.userAgent) }).install();

// Dev-only form flow recorder: absent from every build that does not define it.
if (__LAB_RECORDER__) {
  void import("../dev/recorder-bg").then((m) => m.default(ext as unknown as BgExt));
}
