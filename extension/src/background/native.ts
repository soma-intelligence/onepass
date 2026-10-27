// Native messaging transport. The browser frames each message (32-bit
// length + JSON) and parses replies, so envelopes travel as plain objects.
import type { Transport } from "../bridge/client";
import type { Envelope } from "../bridge/wire";
import type { BgExt } from "./ext";

/** Development host name (spec 9); the product host comes with the Mac app. */
export const NATIVE_HOST = "me.somalabs.onepass.dev";

type NativeApi = Pick<BgExt["runtime"], "connectNative" | "lastError">;

/** Open a port to `hostName`. Throws if the browser refuses to connect. */
export function nativeTransport(hostName: string, runtime: NativeApi): Transport {
  const port = runtime.connectNative(hostName);
  let closed = false;
  let closeReason: Error | undefined;
  let onMsg: ((m: unknown) => void) | undefined;
  let onClose: ((reason?: Error) => void) | undefined;
  const early: unknown[] = [];

  port.onMessage.addListener((m) => {
    if (closed) return;
    if (onMsg) onMsg(m);
    else early.push(m);
  });
  port.onDisconnect.addListener(() => {
    if (closed) return;
    closed = true;
    // Chromium sets runtime.lastError, Firefox port.error.
    const msg = port.error?.message ?? runtime.lastError?.message ?? "native host disconnected";
    closeReason = new Error(msg);
    onClose?.(closeReason);
  });

  return {
    send(env: Envelope): void {
      if (closed) throw new Error("native port closed");
      port.postMessage(env);
    },
    onMessage(cb) {
      onMsg = cb;
      for (const m of early.splice(0)) cb(m);
    },
    onClose(cb) {
      onClose = cb;
      if (closed && closeReason) cb(closeReason);
    },
    close() {
      if (closed) return;
      closed = true;
      try {
        port.disconnect();
      } catch {
        // Already gone.
      }
    },
  };
}
