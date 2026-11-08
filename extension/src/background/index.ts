// Service worker entry point. Listeners are registered synchronously at top
// level so that the browser can wake the worker for them.
import { BridgeClient } from "../bridge/client";
import { ext } from "../shared/browser";
import { startAgentLoopIfChromium } from "./agent";
import { createBackground } from "./app";
import type { BgExt } from "./ext";
import { NATIVE_HOST, nativeTransport } from "./native";
import { browserName } from "./pairing";
import { IdbPairingStore, Store } from "./store";

const bg = ext as unknown as BgExt;
createBackground(bg, { browser: browserName(navigator.userAgent) }).install();

// The agent channel (agent.ts): Chromium only in v1 (Firefox has no documentId
// and would take Chrome's jobs; Safari has no native port). Its own session on a
// second native port, with the stored pairing; restarted on every wake of the
// worker, and by its alarm.
startAgentLoopIfChromium(bg.runtime, {
  ext: bg,
  store: new Store(bg, new IdbPairingStore()),
  newClient: () => new BridgeClient(nativeTransport(NATIVE_HOST, bg.runtime)),
});

// Dev-only form flow recorder: absent from every build that does not define it.
if (__LAB_RECORDER__) {
  void import("../dev/recorder-bg").then((m) => m.default(ext as unknown as BgExt));
}
