// Service worker side of the dev-only recorder. A second listener beside the
// router (which drops these messages): steps come only from content scripts
// and are stored under the host the browser reports; the export is answered
// only to the popup.
import { contentSender, extensionSender } from "../background/frames";
import type { BgExt } from "../background/ext";
import { MSG_EXPORT, MSG_STEP, appendStep, normalizeStep, readSteps } from "./recorder";

export function installRecorder(ext: Pick<BgExt, "runtime" | "storage">): void {
  const { runtime, storage } = ext;
  runtime.onMessage.addListener((message, sender, sendResponse) => {
    const type = (message as { type?: unknown } | null)?.type;
    if (type === MSG_STEP) {
      const ctx = contentSender(runtime, sender);
      if (!ctx) return undefined;
      let host: string;
      try {
        host = new URL(ctx.origin).hostname;
      } catch {
        return undefined;
      }
      const step = normalizeStep((message as { step?: unknown }).step, host);
      if (!step) return undefined;
      appendStep(storage.local, step).then(
        () => sendResponse({ ok: true }),
        () => sendResponse({ err: "storage" }),
      );
      return true;
    }
    if (type === MSG_EXPORT) {
      if (extensionSender(runtime, sender)?.page !== "popup.html") return undefined;
      readSteps(storage.local).then(
        (steps) => sendResponse({ ok: { steps } }),
        () => sendResponse({ err: "storage" }),
      );
      return true;
    }
    return undefined;
  });
}

export default installRecorder;
