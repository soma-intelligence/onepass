// Loader of the Rust-generated cross-language vectors
// (core/onepass-bridge/tests/vectors, written by tests/vectors.rs).
import { readFileSync } from "node:fs";
import { fromB64 } from "../../src/bridge/bytes";

const DIR = new URL("../../../core/onepass-bridge/tests/vectors/", import.meta.url);

export function loadVector<T = Record<string, unknown>>(name: "kem" | "pairing" | "session"): T {
  return JSON.parse(readFileSync(new URL(`${name}.json`, DIR), "utf8")) as T;
}

export const b = fromB64;

export interface KemVector {
  mlkem_seed: string;
  x25519_secret: string;
  public: string;
  encaps_mlkem_seed: string;
  encaps_x25519_eph: string;
  ct: string;
  ss: string;
}

export interface PairingVector {
  ext_name: string;
  browser: string;
  ext_mlkem_seed: string;
  ext_x25519_secret: string;
  ext_nonce: string;
  host_mlkem_seed: string;
  host_x25519_secret: string;
  host_nonce: string;
  pairing_id: string;
  encaps_mlkem_seed: string;
  encaps_x25519_eph: string;
  commit: string;
  transcript_hash: string;
  sas: string;
  sas_cases: { code_key: string; sas: string }[];
  pairing_key: string;
  confirm_key: string;
  mac_host: string;
  mac_ext: string;
  pair_hello: Record<string, unknown>;
  pair_offer: Record<string, unknown>;
  pair_reveal: Record<string, unknown>;
  pair_sas: Record<string, unknown>;
  pair_done: Record<string, unknown>;
  pair_confirm: Record<string, unknown>;
  pair_ok: Record<string, unknown>;
}

export interface FrameVector {
  counter: number;
  plaintext: string;
  msg: Record<string, unknown>;
}

export interface SessionVector {
  pairing_id: string;
  pairing_key: string;
  ext_mlkem_seed: string;
  ext_x25519_secret: string;
  ext_nonce: string;
  host_encaps_mlkem_seed: string;
  host_encaps_x25519_eph: string;
  host_nonce: string;
  session_id: string;
  transcript_hash: string;
  key_e2h: string;
  key_h2e: string;
  key_confirm: string;
  hello: Record<string, unknown>;
  welcome: Record<string, unknown>;
  finish: Record<string, unknown>;
  frames_e2h: FrameVector[];
  frames_h2e: FrameVector[];
}
