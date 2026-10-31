// Test helpers: client-side signing with WebCrypto and the proto module,
// exactly as spec 4.7 lays it out. Not imported by the function.
import * as proto from "./proto.ts";

export function fromHex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export interface TestKey {
  priv: CryptoKey;
  pub: Uint8Array;
  id: Uint8Array;
}

export async function newKey(): Promise<TestKey> {
  const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pub, id: proto.credentialId(pub) };
}

export async function edSign(key: TestKey, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key.priv, msg as BufferSource));
}

export interface SignOpts {
  method: string;
  target: string;
  body?: Uint8Array;
  created: number;
  nonce?: Uint8Array;
  keyid?: Uint8Array;
}

function b64(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b));
}

function b64url(b: Uint8Array): string {
  return b64(b).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Content-Digest, Signature-Input and Signature for one request. */
export async function signedHeaders(key: TestKey, o: SignOpts): Promise<Headers> {
  const body = o.body ?? new Uint8Array();
  const nonce = o.nonce ?? crypto.getRandomValues(new Uint8Array(16));
  const keyid = o.keyid ?? key.id;
  const digest = proto.contentDigest(body);
  const params = { created: BigInt(o.created), nonce, keyid };
  const base = proto.signatureBase(o.method, o.target, digest, params);
  const sig = await edSign(key, base);
  return new Headers({
    "content-digest": digest,
    "signature-input": `sig1=("@method" "@onepass-target" "content-digest");created=${o.created};nonce="${
      b64url(nonce)
    }";keyid="${toHex(keyid)}";alg="ed25519";tag="onepass-mailbox/v1"`,
    "signature": `sig1=:${b64(sig)}:`,
  });
}

export function signatureHeaderFor(sig: Uint8Array): string {
  return `sig1=:${b64(sig)}:`;
}
