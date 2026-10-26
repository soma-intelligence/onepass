// Byte helpers of the bridge client: strict base64, big-endian integers,
// constant-time comparison, and the error type of the protocol.

/** Failure codes of the bridge client. Wire error codes are kept as is. */
export type BridgeErrorCode =
  | "version"
  | "bad_frame"
  | "bad_mac"
  | "replay"
  | "closed"
  | "expired"
  | "crypto"
  | "timeout"
  | "transport"
  | "refused"
  // A handshake is already running on this client.
  | "busy"
  // Error frame of the host (`{"t":"error","code"}`): the code is in `hostCode`.
  | "host";

/** Protocol failure. Messages never carry a secret nor message content. */
export class BridgeError extends Error {
  readonly code: BridgeErrorCode;
  /** Code of the host error frame, when `code` is `"host"`. */
  readonly hostCode: string | undefined;

  constructor(code: BridgeErrorCode, detail?: string, hostCode?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "BridgeError";
    this.code = code;
    this.hostCode = hostCode;
  }
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Standard base64 with padding. */
export function toB64(bytes: Uint8Array): string {
  let s = "";
  // Chunks keep String.fromCharCode under the argument count limit.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

/**
 * Strict standard base64 with padding, as Rust `data_encoding::BASE64`:
 * no whitespace, no URL alphabet, no non-zero trailing bits.
 */
export function fromB64(s: string): Uint8Array {
  if (!B64_RE.test(s)) throw new BridgeError("bad_frame", "invalid base64");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // Canonical form only: re-encoding must give the same text.
  if (toB64(out) !== s) throw new BridgeError("bad_frame", "invalid base64");
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/** `n` must be a safe non-negative integer. */
export function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Equality without early exit on the first differing byte. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Overwrite secrets once they are no longer needed. */
export function wipe(...arrays: (Uint8Array | undefined)[]): void {
  for (const a of arrays) a?.fill(0);
}

/** WebCrypto wants ArrayBuffer-backed views; ours always are. */
export function bs(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return u as Uint8Array<ArrayBuffer>;
}
