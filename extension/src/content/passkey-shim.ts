// MAIN-world shim (spec 3.2), injected at document_start in every HTTPS
// frame: wraps `navigator.credentials.get` and `create` for `publicKey`
// requests only, and asks the isolated relay (content/passkey.ts) over a
// MessageChannel. The page shares this world, so nothing here is secret: the
// shim sends the request's public values and gets back the final credential
// (or "use the browser's API", or an error name). Origins are never sent: the
// worker takes them from the browser.
//
// Falls back to the browser's own API when the relay is not there, on a
// non-HTTPS page, for conditional mediation (autofill UI), for a request
// asking for a cross-platform authenticator, and when the worker says so (no
// OnePass passkey, frame of another site, "Autre appareil").

declare const __PASSKEY_SHIM__: boolean | undefined;

/** Marker of the handshake messages with the relay (shared/messages.ts `PASSKEY_CHANNEL`; no import: this bundle stays alone). */
const PASSKEY_CHANNEL = "onepass-passkey";

type Fn = (options?: unknown) => Promise<unknown>;

export interface ShimPort {
  postMessage(m: unknown): void;
  onmessage: ((e: { data: unknown }) => void) | null;
}

export interface ShimEnv {
  /** The relay's port once the handshake is done, else null (the browser's API is used). */
  port: () => ShimPort | null;
  secure: () => boolean;
  /** Prototypes the credential objects take (absent in tests): `instanceof` holds for the page. */
  protos?: {
    credential?: object;
    assertion?: object;
    attestation?: object;
  };
  DOMException: typeof DOMException;
}

// ---- bytes ----

function bytesOf(v: unknown): Uint8Array {
  if (v instanceof ArrayBuffer) return new Uint8Array(v.slice(0));
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer);
  throw new TypeError("not a BufferSource");
}

export function toB64url(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): ArrayBuffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

const b64 = (v: unknown) => toB64url(bytesOf(v));

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null;

/** The wire request of `options.publicKey`, or null when the shim leaves it to the browser. Throws on a malformed BufferSource. */
export function encodeRequest(kind: "get" | "create", options: unknown): Obj | null {
  if (!isObj(options) || !isObj(options.publicKey)) return null;
  if (options.mediation === "conditional") return null;
  const pk = options.publicKey;
  const out: Obj = { kind, challenge: b64(pk.challenge) };
  if (typeof pk.timeout === "number") out.timeout = Math.max(0, Math.min(600_000, Math.floor(pk.timeout)));
  const ids = (list: unknown): string[] => {
    if (list === undefined) return [];
    if (!Array.isArray(list)) throw new TypeError("credential list");
    return list.map((c) => b64(isObj(c) ? c.id : undefined));
  };
  if (kind === "get") {
    if (pk.rpId !== undefined) out.rpId = String(pk.rpId);
    out.allow = ids(pk.allowCredentials);
    return out;
  }
  const sel = pk.authenticatorSelection;
  if (isObj(sel) && sel.authenticatorAttachment === "cross-platform") return null;
  if (!isObj(pk.user) || !isObj(pk.rp)) throw new TypeError("user / rp");
  if (pk.rp.id !== undefined) out.rpId = String(pk.rp.id);
  out.userId = b64(pk.user.id);
  out.userName = String(pk.user.name ?? "");
  out.exclude = ids(pk.excludeCredentials);
  const params = pk.pubKeyCredParams;
  if (!Array.isArray(params)) throw new TypeError("pubKeyCredParams");
  out.algs = params.map((p) => (isObj(p) && typeof p.alg === "number" ? p.alg : 0));
  return out;
}

// ---- credential objects ----

function define(o: object, props: Obj): void {
  for (const [k, v] of Object.entries(props)) Object.defineProperty(o, k, { value: v, enumerable: true, writable: false, configurable: true });
}

/** A `PublicKeyCredential`-shaped object from the worker's result (fields unpadded base64url). */
export function buildCredential(r: Obj, protos: ShimEnv["protos"] = {}): object {
  const s = (k: string) => String(r[k]);
  const credential = Object.create(protos.credential ?? Object.prototype) as object;
  const clientDataJSON = fromB64url(s("clientDataJSON"));
  const authenticatorData = fromB64url(s("authenticatorData"));
  let response: object;
  let responseJSON: Obj;
  if (r.kind === "assertion") {
    response = Object.create(protos.assertion ?? Object.prototype) as object;
    const userHandle = s("userHandle") === "" ? null : fromB64url(s("userHandle"));
    define(response, { clientDataJSON, authenticatorData, signature: fromB64url(s("signature")), userHandle });
    responseJSON = {
      clientDataJSON: s("clientDataJSON"),
      authenticatorData: s("authenticatorData"),
      signature: s("signature"),
      ...(userHandle ? { userHandle: s("userHandle") } : {}),
    };
  } else {
    response = Object.create(protos.attestation ?? Object.prototype) as object;
    const alg = Number(r.publicKeyAlgorithm);
    define(response, {
      clientDataJSON,
      attestationObject: fromB64url(s("attestationObject")),
      getTransports: () => ["internal", "hybrid"],
      getAuthenticatorData: () => fromB64url(s("authenticatorData")),
      getPublicKey: () => fromB64url(s("publicKey")),
      getPublicKeyAlgorithm: () => alg,
    });
    responseJSON = {
      clientDataJSON: s("clientDataJSON"),
      attestationObject: s("attestationObject"),
      authenticatorData: s("authenticatorData"),
      transports: ["internal", "hybrid"],
      publicKey: s("publicKey"),
      publicKeyAlgorithm: alg,
    };
  }
  const id = s("credentialId");
  define(credential, {
    id,
    rawId: fromB64url(id),
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    getClientExtensionResults: () => ({}),
    toJSON: () => ({
      id,
      rawId: id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: responseJSON,
    }),
  });
  return credential;
}

// ---- wrapping ----

/** Replaces `creds.get` / `creds.create`; the originals stay the fallback. */
export function wrapCredentials(creds: { get: Fn; create: Fn }, env: ShimEnv): void {
  const original = { get: creds.get.bind(creds), create: creds.create.bind(creds) };
  const pending = new Map<string, (r: unknown) => void>();
  let seq = 0;
  let wired: ShimPort | null = null;

  const portNow = (): ShimPort | null => {
    const p = env.port();
    if (p && p !== wired) {
      wired = p;
      p.onmessage = (e) => {
        const d = e.data;
        if (!isObj(d) || d.type !== "result" || typeof d.id !== "string") return;
        const cb = pending.get(d.id);
        if (!cb) return;
        pending.delete(d.id);
        cb(d.result);
      };
    }
    return p;
  };

  const call = (kind: "get" | "create", options: unknown): Promise<unknown> => {
    const port = env.secure() ? portNow() : null;
    let req: Obj | null = null;
    if (port) {
      try {
        req = encodeRequest(kind, options);
      } catch {
        // Malformed: the browser's API raises its own TypeError.
        req = null;
      }
    }
    if (!port || !req) return original[kind](options);
    const signal = isObj(options) ? (options.signal as AbortSignal | undefined) : undefined;
    if (signal?.aborted) return Promise.reject(new env.DOMException("The operation was aborted.", "AbortError"));
    const id = `p${++seq}`;
    return new Promise<unknown>((resolve, reject) => {
      const onAbort = () => {
        if (!pending.delete(id)) return;
        port.postMessage({ type: "abort", id });
        reject(new env.DOMException("The operation was aborted.", "AbortError"));
      };
      signal?.addEventListener?.("abort", onAbort, { once: true });
      pending.set(id, (r) => {
        signal?.removeEventListener?.("abort", onAbort);
        const res = isObj(r) ? r : { kind: "fallback" };
        if (res.kind === "assertion" || res.kind === "registration") {
          try {
            resolve(buildCredential(res, env.protos));
          } catch {
            reject(new env.DOMException("The operation failed.", "NotAllowedError"));
          }
        } else if (res.kind === "error") {
          const name = typeof res.name === "string" ? res.name : "NotAllowedError";
          reject(new env.DOMException("The operation either timed out or was not allowed.", name));
        } else {
          original[kind](options).then(resolve, reject);
        }
      });
      port.postMessage({ type: "request", id, request: req });
    });
  };

  const get = function get(options?: unknown) {
    return call("get", options);
  };
  const create = function create(options?: unknown) {
    return call("create", options);
  };
  Object.defineProperty(creds, "get", { value: get, writable: true, configurable: true, enumerable: false });
  Object.defineProperty(creds, "create", { value: create, writable: true, configurable: true, enumerable: false });
}

/** Real start: the handshake with the relay, then the wrap. */
export function installPasskeyShim(win: Window & typeof globalThis): void {
  const creds = win.navigator?.credentials as unknown as { get: Fn; create: Fn } | undefined;
  if (!creds || typeof creds.get !== "function" || typeof creds.create !== "function") return;
  let port: MessagePort | null = null;
  let ready = false;
  const offer = () => {
    const ch = new win.MessageChannel();
    const mine = ch.port1;
    // The relay answers "ready" on the port it took (the first one it saw); until then the API is the browser's.
    mine.onmessage = (e) => {
      if (!ready && isObj(e.data) && e.data.type === "ready") {
        ready = true;
        port = mine;
        mine.onmessage = null;
      }
    };
    win.postMessage({ [PASSKEY_CHANNEL]: "port" }, "*", [ch.port2]);
  };
  // The relay may start after this script: it says hello, and gets a port then.
  win.addEventListener("message", (e) => {
    if (!ready && e.source === win && isObj(e.data) && e.data[PASSKEY_CHANNEL] === "hello") offer();
  });
  offer();
  const g = win as unknown as Record<string, { prototype?: object } | undefined>;
  wrapCredentials(creds, {
    port: () => (ready ? (port as unknown as ShimPort) : null),
    secure: () => win.location.protocol === "https:",
    protos: {
      ...(g.PublicKeyCredential?.prototype ? { credential: g.PublicKeyCredential.prototype } : {}),
      ...(g.AuthenticatorAssertionResponse?.prototype ? { assertion: g.AuthenticatorAssertionResponse.prototype } : {}),
      ...(g.AuthenticatorAttestationResponse?.prototype ? { attestation: g.AuthenticatorAttestationResponse.prototype } : {}),
    },
    DOMException: win.DOMException,
  });
}

if (typeof __PASSKEY_SHIM__ !== "undefined" && __PASSKEY_SHIM__ && typeof window !== "undefined") {
  const g = window as unknown as { __onepassPasskeyShim?: boolean };
  if (!g.__onepassPasskeyShim) {
    g.__onepassPasskeyShim = true;
    installPasskeyShim(window);
  }
}
