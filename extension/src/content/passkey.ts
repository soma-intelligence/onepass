// Isolated relay of the passkey shim (spec 3.2), injected at document_start
// in every HTTPS frame beside the MAIN-world shim (passkey-shim.ts). It takes
// the one MessagePort the shim offers, checks each request's shape and sizes
// (shared/messages.ts) and sends `passkey_request` to the worker, which takes
// the origin from the browser, with `activated`: whether the page's call came
// under a transient user activation (`navigator.userActivation`, read here in
// the isolated world, never a value of the page). It never holds a secret: the worker answers
// with the final credential, the browser's API, or an error name. Anything
// malformed goes back as "use the browser's API" without reaching the worker.
import { ext as browserExt } from "../shared/browser";
import { PASSKEY_CHANNEL, type PasskeyCsToBg, type PasskeyResult, parsePasskeyRequest, parsePasskeyResult } from "../shared/messages";

declare const __PASSKEY_RELAY__: boolean | undefined;

export type RelaySend = (m: PasskeyCsToBg) => Promise<unknown>;

export interface RelayPort {
  postMessage(m: unknown): void;
  onmessage: ((e: { data: unknown }) => void) | null;
}

const ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
const FALLBACK: PasskeyResult = { kind: "fallback" };
/** Requests of one frame in flight at once (a page looping on get() gets the browser's API). */
export const RELAY_MAX_IN_FLIGHT = 4;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Transient user activation of this document (shared by both worlds, not writable by the page). */
export function userActivated(): boolean {
  const ua = (globalThis.navigator as { userActivation?: { isActive?: unknown } } | undefined)?.userActivation;
  return ua?.isActive === true;
}

/** Serves the shim's requests on `port`. */
export function attachRelay(port: RelayPort, send: RelaySend, activated: () => boolean = userActivated): void {
  let inFlight = 0;
  const reply = (id: string, result: PasskeyResult) => port.postMessage({ type: "result", id, result });
  port.onmessage = (e) => {
    const d = e.data;
    if (!isObj(d) || typeof d.id !== "string" || !ID_RE.test(d.id)) return;
    const id = d.id;
    if (d.type === "abort") {
      void send({ type: "passkey_abort", reqId: id }).catch(() => undefined);
      return;
    }
    if (d.type !== "request") return;
    const request = parsePasskeyRequest(d.request);
    if (!request || inFlight >= RELAY_MAX_IN_FLIGHT) {
      reply(id, FALLBACK);
      return;
    }
    inFlight++;
    send({ type: "passkey_request", reqId: id, request, activated: activated() })
      .then((r) => {
        const result = isObj(r) && "ok" in r ? parsePasskeyResult(r.ok) : null;
        reply(id, result ?? FALLBACK);
      })
      .catch(() => reply(id, FALLBACK))
      .finally(() => {
        inFlight--;
      });
  };
  port.postMessage({ type: "ready" });
}

/** Real start: takes the first port the shim posts to this window, and says hello in case the shim ran first. */
export function startPasskeyRelay(win: Window, send: RelaySend): void {
  let taken = false;
  win.addEventListener("message", (e) => {
    if (taken || e.source !== win || !isObj(e.data) || e.data[PASSKEY_CHANNEL] !== "port") return;
    const port = e.ports[0];
    if (!port) return;
    taken = true;
    attachRelay(port as unknown as RelayPort, send);
  });
  win.postMessage({ [PASSKEY_CHANNEL]: "hello" }, "*");
}

if (typeof __PASSKEY_RELAY__ !== "undefined" && __PASSKEY_RELAY__ && browserExt?.runtime?.id && typeof window !== "undefined") {
  const g = globalThis as { __onepassPasskeyRelay?: boolean };
  if (!g.__onepassPasskeyRelay) {
    g.__onepassPasskeyRelay = true;
    const runtime = browserExt.runtime;
    startPasskeyRelay(window, (m) => runtime.sendMessage(m) as Promise<unknown>);
  }
}
