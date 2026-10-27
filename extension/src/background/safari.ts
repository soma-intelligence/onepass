// Safari transport. Safari has no native messaging host: each
// `browser.runtime.sendNativeMessage` reaches the app extension's
// `SafariWebExtensionHandler` as one request with one reply (apple/SafariExtension).
// The handler keeps one bridge host per connection id, so a connection here
// behaves like a Chrome port: `open`, ordered `send`s, and a long `poll`
// that brings back the host's frames in order.
//
// Envelopes travel as JSON text and are relayed byte for byte (spec R-03):
// the same frames, pairing and session as the Chrome and Firefox host.
import type { Transport } from "../bridge/client";
import type { Envelope } from "../bridge/wire";

/** Ignored by Safari (it routes to the containing app's extension); a string is required. */
export const SAFARI_APP = "me.somalabs.onepass";

export interface SafariNativeApi {
  sendNativeMessage(application: string, message: unknown): Promise<unknown>;
}

type Op = "open" | "send" | "poll" | "close";

interface OkReply {
  frames: string[];
  closed: boolean;
}

/** 16 random bytes in lowercase hex, the relay's connection id. */
export function randomConnId(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** The relay's reply, strictly: `{ok: true, frames: string[], closed: bool}` or `{ok: false, error}`. */
function parseReply(raw: unknown): OkReply {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Error("bad relay reply");
  const r = raw as Record<string, unknown>;
  if (r.ok === false) {
    const code = typeof r.error === "string" && /^[a-z_]{1,32}$/.test(r.error) ? r.error : "unknown";
    throw new Error(`relay: ${code}`);
  }
  if (r.ok !== true || typeof r.closed !== "boolean" || !Array.isArray(r.frames)) throw new Error("bad relay reply");
  const frames: string[] = [];
  for (const f of r.frames) {
    if (typeof f !== "string") throw new Error("bad relay reply");
    frames.push(f);
  }
  return { frames, closed: r.closed };
}

/** Open a relay connection. Failures surface through `onClose`, like a Chrome port. */
export function safariTransport(runtime: SafariNativeApi, connId: string = randomConnId()): Transport {
  let closed = false;
  let closeReason: Error | undefined;
  let onMsg: ((m: unknown) => void) | undefined;
  let onClose: ((reason?: Error) => void) | undefined;
  const early: unknown[] = [];

  const request = async (op: Op, frame?: string): Promise<OkReply> => {
    const msg: Record<string, unknown> = { onepass: 1, op, conn: connId };
    if (frame !== undefined) msg.frame = frame;
    return parseReply(await runtime.sendNativeMessage(SAFARI_APP, msg));
  };

  const shutdown = (reason: Error | undefined, tellRelay: boolean): void => {
    if (closed) return;
    closed = true;
    if (tellRelay) request("close").catch(() => undefined);
    if (reason) {
      closeReason = reason;
      onClose?.(reason);
    }
  };
  const fail = (e: unknown): void => shutdown(e instanceof Error ? e : new Error("native host disconnected"), true);

  const deliver = (text: string): void => {
    let m: unknown;
    try {
      m = JSON.parse(text);
    } catch {
      fail(new Error("bad frame from the native host"));
      return;
    }
    if (onMsg) onMsg(m);
    else early.push(m);
  };

  const pollLoop = async (): Promise<void> => {
    while (!closed) {
      let r: OkReply;
      try {
        r = await request("poll");
      } catch (e) {
        fail(e);
        return;
      }
      for (const f of r.frames) {
        if (closed) return;
        deliver(f);
      }
      if (r.closed) {
        fail(new Error("native host disconnected"));
        return;
      }
    }
  };

  // Every request but `poll` goes through this chain, so the host gets the
  // frames in the order they were sent, after `open`.
  let chain: Promise<unknown> = request("open").then(
    () => {
      void pollLoop();
    },
    (e: unknown) => fail(e),
  );

  return {
    send(env: Envelope): void {
      if (closed) throw new Error("native port closed");
      const text = JSON.stringify(env);
      chain = chain.then(async () => {
        if (closed) return;
        try {
          await request("send", text);
        } catch (e) {
          fail(e);
        }
      });
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
      shutdown(undefined, true);
    },
  };
}
