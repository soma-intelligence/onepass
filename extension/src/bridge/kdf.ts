// HKDF, HMAC, SHA-256 and the comparison code (spec 6.4, 6.5), through
// WebCrypto: available in extension service workers and in Node 22.
import { BridgeError, bs, concat, utf8 } from "./bytes";

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new BridgeError("crypto", "WebCrypto unavailable");
  return s;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", bs(data)));
}

/** HKDF-SHA256 extract and expand, 32 output bytes, raw `info`. */
export async function hkdf32(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const key = await subtle().importKey("raw", bs(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: bs(salt), info: bs(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/** `HKDF-SHA256(salt, ikm).expand(info = label, 32)`. */
export function expand(salt: Uint8Array, ikm: Uint8Array, label: string): Promise<Uint8Array> {
  return hkdf32(salt, ikm, utf8(label));
}

export type Role = "host" | "ext";

function hmacKey(key: Uint8Array, usage: "sign" | "verify"): Promise<CryptoKey> {
  return subtle().importKey("raw", bs(key), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

/** `HMAC-SHA256(key, role || t)`. */
export async function hmac(key: Uint8Array, role: Role, t: Uint8Array): Promise<Uint8Array> {
  const k = await hmacKey(key, "sign");
  return new Uint8Array(await subtle().sign("HMAC", k, bs(concat(utf8(role), t))));
}

/** Constant-time check of `tag` against `HMAC-SHA256(key, role || t)`. */
export async function verifyHmac(
  key: Uint8Array,
  role: Role,
  t: Uint8Array,
  tag: Uint8Array,
): Promise<boolean> {
  if (tag.length !== 32) return false;
  const k = await hmacKey(key, "verify");
  return subtle().verify("HMAC", k, bs(tag), bs(concat(utf8(role), t)));
}

/** Six digit code: first four bytes big-endian, mod 1 000 000, `"123 456"`. */
export function sas(codeKey: Uint8Array): string {
  if (codeKey.length < 4) throw new BridgeError("crypto", "code key length");
  const n = new DataView(codeKey.buffer, codeKey.byteOffset, 4).getUint32(0, false) % 1_000_000;
  const pad = (x: number) => String(x).padStart(3, "0");
  return `${pad(Math.floor(n / 1000))} ${pad(n % 1000)}`;
}
