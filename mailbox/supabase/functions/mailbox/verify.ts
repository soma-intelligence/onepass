// Signed requests (spec 4.7). The parsing, the skew rule, the digest and the
// signature base are the proto's (WebAssembly); Ed25519 is WebCrypto's.
// Header values are used exactly as `Headers.get()` returns them: never
// trimmed or rewritten here, so any spelling but the canonical one fails.
import * as proto from "./proto.ts";
import { Refusal } from "./errors.ts";

export interface HeaderSource {
  get(name: string): string | null;
}

export interface SignatureParams {
  created: bigint;
  nonce: Uint8Array;
  keyid: Uint8Array;
}

/** A request whose headers, clock and digest checked out; signature not yet verified. */
export interface Checked {
  params: SignatureParams;
  sig: Uint8Array;
  base: Uint8Array;
}

export interface SignedRequest {
  method: string;
  target: string;
  headers: HeaderSource;
  body: Uint8Array;
}

/** An Ed25519 public key that is not a point of the curve (or not 32 bytes). */
export class BadKey extends Error {}

const bad = () => new Refusal("bad_signature");

/** Signature headers that parsed and passed the skew check; body not seen yet. */
export interface CheckedHeaders {
  params: SignatureParams;
  sig: Uint8Array;
  digest: string;
}

/**
 * Steps 1 and 2 of spec 4.7, without the body or any key: strict parse of
 * `Signature-Input` and `Signature`, `|now - created| <= 300`, and the
 * `Content-Digest` header present. Lets a route refuse a request before it
 * reads a large body.
 */
export function checkHeaders(headers: HeaderSource, nowSecs: number): CheckedHeaders {
  const input = headers.get("signature-input");
  const signature = headers.get("signature");
  const digest = headers.get("content-digest");
  if (input === null || signature === null || digest === null) throw bad();
  let parsed: { params: SignatureParams; sig: Uint8Array };
  try {
    parsed = proto.parseSignatureHeaders(input, signature);
  } catch {
    throw bad();
  }
  try {
    proto.checkSkew(parsed.params.created, BigInt(nowSecs));
  } catch {
    throw new Refusal("stale_request");
  }
  return { params: parsed.params, sig: parsed.sig, digest };
}

/**
 * Step 3 of spec 4.7 once the body is read: the `Content-Digest` of the
 * body received, and the signature base (which also refuses a target
 * outside the alphabet the URL parser keeps intact).
 */
export function checkBody(method: string, target: string, head: CheckedHeaders, body: Uint8Array): Checked {
  if (proto.contentDigest(body) !== head.digest) throw bad();
  let base: Uint8Array;
  try {
    base = proto.signatureBase(method, target, head.digest, head.params);
  } catch {
    throw bad();
  }
  return { params: head.params, sig: head.sig, base };
}

/**
 * Steps 1 to 3 of spec 4.7, without any key: `checkHeaders`, then
 * `checkBody`.
 */
export function checkRequest(
  method: string,
  target: string,
  headers: HeaderSource,
  body: Uint8Array,
  nowSecs: number,
): Checked {
  return checkBody(method, target, checkHeaders(headers, nowSecs), body);
}

// ------------------------------------------------------------- Ed25519 keys

const P = (1n << 255n) - 19n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function pow(b: bigint, e: bigint): bigint {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

const D = mod(-121665n * pow(121666n, P - 2n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

/**
 * RFC 8032 section 5.1.3 point decoding: true when the 32 bytes are the
 * canonical encoding of a curve point. WebCrypto in Deno imports any 32
 * bytes as an Ed25519 key, so off-curve keys are refused here.
 */
export function onCurve(raw: Uint8Array): boolean {
  if (raw.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(raw[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  let x = (((u * v3) % P) * pow((u * v7) % P, (P - 5n) / 8n)) % P;
  const vx2 = (((v * x) % P) * x) % P;
  if (vx2 === u) {
    // x is a square root of u / v.
  } else if (vx2 === mod(-u)) {
    x = (x * SQRT_M1) % P;
  } else {
    return false;
  }
  return !(x === 0n && sign === 1n);
}

/** WebCrypto key for a credential's public key; `BadKey` when off the curve. */
export async function importCredentialKey(raw: Uint8Array): Promise<CryptoKey> {
  if (!onCurve(raw)) throw new BadKey("public key is not a curve point");
  try {
    return await crypto.subtle.importKey("raw", raw as BufferSource, "Ed25519", false, ["verify"]);
  } catch {
    throw new BadKey("public key refused by WebCrypto");
  }
}

/** Ed25519 verification; false for a bad key or a bad signature. */
export async function edVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  let key: CryptoKey;
  try {
    key = await importCredentialKey(publicKey);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  return await crypto.subtle.verify("Ed25519", key, sig as BufferSource, msg as BufferSource);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * Step 4: `keyid` must be the fingerprint of the key (spec 4.5: the
 * credential id is SHA-256 of the domain and the key), then Ed25519.
 */
export async function verifySignature(c: Checked, publicKey: Uint8Array): Promise<void> {
  let id: Uint8Array;
  try {
    id = proto.credentialId(publicKey);
  } catch {
    throw bad();
  }
  if (!equal(id, c.params.keyid)) throw bad();
  if (!(await edVerify(publicKey, c.base, c.sig))) throw bad();
}

/** Steps 1 to 4 against a known key. */
export async function verifyRequest(req: SignedRequest, publicKey: Uint8Array, nowSecs: number): Promise<Checked> {
  const c = checkRequest(req.method, req.target, req.headers, req.body, nowSecs);
  await verifySignature(c, publicKey);
  return c;
}
