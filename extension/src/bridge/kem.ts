// Hybrid KEM of the bridge (spec 6.2): ML-KEM-1024 + X25519, combined by
// HKDF-SHA256 under the label `onepass/bridge/kem/v1`.
//
// Public key: `ek_mlkem (1568) || pk_x25519 (32)`. Ciphertext:
// `ct_mlkem (1568) || E_x25519 (32)`. Shared secret:
// `HKDF-SHA256(salt = label, ikm = ss_m || ss_x, info = SHA-256(ct || pk_x))`.
//
// The seeded helpers reproduce the Rust vectors: `mlkemSeed` is `d || z` of
// FIPS 203 `KeyGen_internal` (as libcrux `generate_key_pair`), the
// encapsulation seed is FIPS 203 `m` (as libcrux `encapsulate`).
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { BridgeError, concat, randomBytes, utf8, wipe } from "./bytes";
import { hkdf32, sha256 } from "./kdf";

const MLKEM_PUBLIC_LEN = 1568;
const MLKEM_CT_LEN = 1568;
const X25519_LEN = 32;
/** Hybrid public key length. */
export const PUBLIC_LEN = MLKEM_PUBLIC_LEN + X25519_LEN;
/** Hybrid ciphertext length. */
export const CT_LEN = MLKEM_CT_LEN + X25519_LEN;
const KEM_LABEL = utf8("onepass/bridge/kem/v1");

/** Hybrid secret key: FIPS 203 decapsulation key and X25519 scalar. */
export interface KemSecret {
  mlkem: Uint8Array;
  x25519: Uint8Array;
}

export interface KemKeyPair {
  secret: KemSecret;
  /** 1600 bytes. */
  public: Uint8Array;
}

export interface Encapsulated {
  /** 1600 bytes. */
  ct: Uint8Array;
  /** 32 bytes. */
  ss: Uint8Array;
}

function pair(mlkemSeed: Uint8Array, x25519Secret: Uint8Array): KemKeyPair {
  if (mlkemSeed.length !== 64 || x25519Secret.length !== X25519_LEN) {
    throw new BridgeError("crypto", "kem seed length");
  }
  const { publicKey, secretKey } = ml_kem1024.keygen(mlkemSeed);
  const secret: KemSecret = { mlkem: secretKey, x25519: x25519Secret.slice() };
  try {
    return { secret, public: concat(publicKey, x25519.getPublicKey(x25519Secret)) };
  } catch (e) {
    wipe(secret.mlkem, secret.x25519);
    throw e;
  }
}

/** Fresh ephemeral key pair. */
export function generateKem(): KemKeyPair {
  const seed = randomBytes(64);
  const x = randomBytes(32);
  try {
    return pair(seed, x);
  } finally {
    wipe(seed, x);
  }
}

/** Deterministic key pair, for test vectors. */
export function kemFromSeeds(mlkemSeed: Uint8Array, x25519Secret: Uint8Array): KemKeyPair {
  return pair(mlkemSeed, x25519Secret);
}

/** Overwrite the secret halves. */
export function wipeKem(kp: KemKeyPair): void {
  wipe(kp.secret.mlkem, kp.secret.x25519);
}

/** Spec 6.2 step 4. */
async function combine(ct: Uint8Array, pkX: Uint8Array, ssM: Uint8Array, ssX: Uint8Array): Promise<Uint8Array> {
  const ikm = concat(ssM, ssX);
  try {
    return await hkdf32(KEM_LABEL, ikm, await sha256(concat(ct, pkX)));
  } finally {
    wipe(ikm);
  }
}

function x25519Agree(secret: Uint8Array, peer: Uint8Array): Uint8Array {
  try {
    // noble refuses an all-zero result (low order point), as aws-lc does.
    return x25519.getSharedSecret(secret, peer);
  } catch {
    throw new BridgeError("crypto", "x25519");
  }
}

const MLKEM_Q = 3329;
/** Encoded polynomial vector `t` of the encapsulation key (k = 4). */
const MLKEM_T_LEN = 1536;

/**
 * FIPS 203 section 7.2 modulus check: every 12-bit coefficient of the
 * encapsulation key is below q. Done here because the check of
 * `@noble/post-quantum` 0.5.4 accepts out of range coefficients, while
 * aws-lc (the host) refuses them.
 */
export function mlkemKeyIsValid(ek: Uint8Array): boolean {
  if (ek.length !== MLKEM_PUBLIC_LEN) return false;
  for (let i = 0; i < MLKEM_T_LEN; i += 3) {
    const b0 = ek[i] ?? 0;
    const b1 = ek[i + 1] ?? 0;
    const b2 = ek[i + 2] ?? 0;
    if ((b0 | ((b1 & 0x0f) << 8)) >= MLKEM_Q || ((b1 >> 4) | (b2 << 4)) >= MLKEM_Q) return false;
  }
  return true;
}

async function encaps(pk: Uint8Array, mlkemSeed: Uint8Array, eph: Uint8Array): Promise<Encapsulated> {
  if (pk.length !== PUBLIC_LEN) throw new BridgeError("bad_frame", "kem public key length");
  const ek = pk.subarray(0, MLKEM_PUBLIC_LEN);
  if (!mlkemKeyIsValid(ek)) throw new BridgeError("bad_frame", "kem public key");
  const pkX = pk.subarray(MLKEM_PUBLIC_LEN);
  let ctM: Uint8Array;
  let ssM: Uint8Array;
  try {
    ({ cipherText: ctM, sharedSecret: ssM } = ml_kem1024.encapsulate(ek, mlkemSeed));
  } catch {
    // FIPS 203 modulus check of the encapsulation key.
    throw new BridgeError("bad_frame", "kem public key");
  }
  let ssX: Uint8Array | undefined;
  try {
    ssX = x25519Agree(eph, pkX);
    const ct = concat(ctM, x25519.getPublicKey(eph));
    return { ct, ss: await combine(ct, pkX, ssM, ssX) };
  } finally {
    wipe(ssM, ssX);
  }
}

/** Encapsulate to a 1600 byte hybrid public key. */
export async function encapsulate(pk: Uint8Array): Promise<Encapsulated> {
  const m = randomBytes(32);
  const eph = randomBytes(32);
  try {
    return await encaps(pk, m, eph);
  } finally {
    wipe(m, eph);
  }
}

/** Encapsulation with fixed randomness, for test vectors. */
export function encapsulateDeterministic(
  pk: Uint8Array,
  mlkemSeed: Uint8Array,
  x25519Eph: Uint8Array,
): Promise<Encapsulated> {
  if (mlkemSeed.length !== 32 || x25519Eph.length !== 32) {
    return Promise.reject(new BridgeError("crypto", "kem seed length"));
  }
  return encaps(pk, mlkemSeed, x25519Eph);
}

/**
 * Decapsulate a 1600 byte ciphertext. ML-KEM rejects implicitly: a
 * tampered ciphertext gives an unrelated secret, which then fails the MAC
 * check of the handshake.
 */
export async function decapsulate(sk: KemSecret, ct: Uint8Array): Promise<Uint8Array> {
  if (ct.length !== CT_LEN) throw new BridgeError("bad_frame", "kem ciphertext length");
  const ssM = ml_kem1024.decapsulate(ct.subarray(0, MLKEM_CT_LEN), sk.mlkem);
  let ssX: Uint8Array | undefined;
  try {
    ssX = x25519Agree(sk.x25519, ct.subarray(MLKEM_CT_LEN));
    const pkX = x25519.getPublicKey(sk.x25519);
    return await combine(ct, pkX, ssM, ssX);
  } finally {
    wipe(ssM, ssX);
  }
}
