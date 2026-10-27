// Extension side of the pairing with committed numeric comparison
// (spec 6.4), mirror of `onepass_bridge::pairing::ExtPairing`.
//
// E commits to its ephemeral public key and nonce before seeing the host's,
// both sides derive a six digit code from the transcript, the user compares
// the two screens, then each side proves knowledge of the confirmation key.
// Any failure or the 120 s deadline wipes the state.
import { BridgeError, concat, fromB64, randomBytes, toB64, utf8, wipe } from "./bytes";
import { expand, hmac, sas, sha256, verifyHmac } from "./kdf";
import { type KemKeyPair, encapsulate, encapsulateDeterministic, generateKem, wipeKem } from "./kem";
import type { Encapsulated } from "./kem";
import { TRANSCRIPT_LABEL, Transcript } from "./transcript";
import {
  type PairConfirmEnvelope,
  type PairDone,
  type PairHelloEnvelope,
  type PairOffer,
  type PairRevealEnvelope,
  expectType,
  parseEnvelope,
} from "./wire";

/** Pairing deadline, counted from `start`. */
export const PAIRING_TIMEOUT_MS = 120_000;
/** Longest accepted `ext_name` or `browser`, in UTF-8 bytes. */
export const MAX_NAME_LEN = 128;

const COMMIT_LABEL = utf8("onepass/bridge/commit/v1");
const SAS_LABEL = "onepass/bridge/sas/v1";
const PAIRING_KEY_LABEL = "onepass/bridge/pairing-key/v1";
const CONFIRM_LABEL = "onepass/bridge/pair-confirm/v1";

/** A completed pairing, the only durable secret of the extension. */
export interface PairingRecord {
  /** 16 bytes. */
  pairingId: Uint8Array;
  /** 32 byte pairing key `PK`. */
  key: Uint8Array;
  /** Unix time in milliseconds. */
  createdAt: number;
}

/** Storage form of a record (IndexedDB of the extension origin): base64 fields. */
export interface PairingRecordJson {
  pairing_id: string;
  key: string;
  created_at: number;
}

export function recordToJson(r: PairingRecord): PairingRecordJson {
  return { pairing_id: toB64(r.pairingId), key: toB64(r.key), created_at: r.createdAt };
}

export function recordFromJson(x: unknown): PairingRecord {
  if (typeof x !== "object" || x === null) throw new BridgeError("bad_frame", "pairing record");
  const o = x as Record<string, unknown>;
  if (typeof o.pairing_id !== "string" || typeof o.key !== "string") {
    throw new BridgeError("bad_frame", "pairing record");
  }
  if (typeof o.created_at !== "number" || !Number.isSafeInteger(o.created_at) || o.created_at < 0) {
    throw new BridgeError("bad_frame", "pairing record");
  }
  const pairingId = fromB64(o.pairing_id);
  const key = fromB64(o.key);
  if (pairingId.length !== 16 || key.length !== 32) throw new BridgeError("bad_frame", "pairing record");
  return { pairingId, key, createdAt: o.created_at };
}

/** Rust `char::is_control`: general category Cc. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function checkName(s: string): void {
  const n = utf8(s).length;
  if (n === 0 || n > MAX_NAME_LEN || CONTROL.test(s)) throw new BridgeError("bad_frame", "pairing name");
}

/** Values derived once the transcript is complete. */
interface Keys {
  t: Uint8Array;
  pairingKey: Uint8Array;
  confirm: Uint8Array;
}

/** Intermediate values, for cross-language test vectors. */
export interface PairingVectorKeys {
  transcriptHash: Uint8Array;
  pairingKey: Uint8Array;
  confirmKey: Uint8Array;
}

type State =
  | { s: "await_offer"; kem: KemKeyPair; nonce: Uint8Array }
  | { s: "await_done"; pairingId: Uint8Array; keys: Keys }
  | { s: "verified"; pairingId: Uint8Array; keys: Keys }
  | { s: "closed" };

export interface PairingOptions {
  /** Clock in milliseconds, `Date.now` by default. */
  now?: () => number;
}

type Encaps = (pk: Uint8Array) => Promise<Encapsulated>;

export class ExtPairing {
  private state: State;
  private readonly started: number;
  private readonly now: () => number;

  private constructor(
    private readonly extName: string,
    private readonly browser: string,
    private readonly commit: Uint8Array,
    kem: KemKeyPair,
    nonce: Uint8Array,
    now: () => number,
  ) {
    this.state = { s: "await_offer", kem, nonce };
    this.now = now;
    this.started = now();
  }

  /** Draw an ephemeral key pair and nonce, commit to them: `pair_hello`. */
  static start(
    extName: string,
    browser: string,
    opts: PairingOptions = {},
  ): Promise<{ state: ExtPairing; hello: PairHelloEnvelope }> {
    try {
      checkName(extName);
      checkName(browser);
    } catch (e) {
      return Promise.reject(e);
    }
    return ExtPairing.startDeterministic(extName, browser, generateKem(), randomBytes(32), opts);
  }

  /** `start` with fixed randomness, for test vectors. */
  static async startDeterministic(
    extName: string,
    browser: string,
    kem: KemKeyPair,
    nonce: Uint8Array,
    opts: PairingOptions = {},
  ): Promise<{ state: ExtPairing; hello: PairHelloEnvelope }> {
    checkName(extName);
    checkName(browser);
    if (nonce.length !== 32) throw new BridgeError("crypto", "nonce length");
    const commit = await sha256(concat(COMMIT_LABEL, kem.public, nonce));
    const state = new ExtPairing(extName, browser, commit, kem, nonce, opts.now ?? Date.now);
    const hello: PairHelloEnvelope = {
      v: 1,
      t: "pair_hello",
      commit: toB64(commit),
      ext_name: extName,
      browser,
    };
    return { state, hello };
  }

  /** Derived values once the code is known, for test vectors. */
  vectorKeys(): PairingVectorKeys | undefined {
    const st = this.state;
    if (st.s !== "await_done" && st.s !== "verified") return undefined;
    return {
      transcriptHash: st.keys.t.slice(),
      pairingKey: st.keys.pairingKey.slice(),
      confirmKey: st.keys.confirm.slice(),
    };
  }

  /** Wipe every secret and close. */
  abort(): void {
    const st = this.state;
    this.state = { s: "closed" };
    if (st.s === "await_offer") {
      wipeKem(st.kem);
      wipe(st.nonce);
    } else if (st.s !== "closed") {
      wipe(st.keys.pairingKey, st.keys.confirm);
    }
  }

  /** Take the state, leaving `closed`: any early return wipes it. */
  private take(): State {
    const st = this.state;
    this.state = { s: "closed" };
    if (this.now() - this.started > PAIRING_TIMEOUT_MS) {
      this.state = st;
      this.abort();
      throw new BridgeError("expired");
    }
    return st;
  }

  /** Handle `pair_offer`: encapsulate to the host key, reveal, and the code to show. */
  onOffer(offer: PairOffer): Promise<{ reveal: PairRevealEnvelope; sas: string }> {
    return this.offerWith(offer, encapsulate);
  }

  /** `onOffer` with fixed encapsulation randomness, for test vectors. */
  onOfferDeterministic(
    offer: PairOffer,
    mlkemSeed: Uint8Array,
    x25519Eph: Uint8Array,
  ): Promise<{ reveal: PairRevealEnvelope; sas: string }> {
    return this.offerWith(offer, (pk) => encapsulateDeterministic(pk, mlkemSeed, x25519Eph));
  }

  private async offerWith(
    offerIn: PairOffer,
    encaps: Encaps,
  ): Promise<{ reveal: PairRevealEnvelope; sas: string }> {
    const st = this.take();
    if (st.s !== "await_offer") {
      this.state = st;
      this.abort();
      throw new BridgeError("bad_frame", "unexpected pair_offer");
    }
    const { kem, nonce } = st;
    try {
      const offer = expectType(parseEnvelope(offerIn), "pair_offer");
      const pairingId = fromB64(offer.pairing_id);
      const pkH = fromB64(offer.pk);
      const nH = fromB64(offer.n);
      const { ct, ss } = await encaps(pkH);
      let codeKey: Uint8Array | undefined;
      let pairingKey: Uint8Array | undefined;
      let confirm: Uint8Array | undefined;
      let ok = false;
      try {
        const tr = new Transcript(TRANSCRIPT_LABEL);
        for (const f of [utf8(this.extName), utf8(this.browser), this.commit, pairingId, pkH, nH, kem.public, nonce, ct]) {
          tr.push(f);
        }
        const t = await tr.hash();
        codeKey = await expand(t, ss, SAS_LABEL);
        const code = sas(codeKey);
        pairingKey = await expand(t, ss, PAIRING_KEY_LABEL);
        confirm = await expand(t, ss, CONFIRM_LABEL);
        const keys: Keys = { t, pairingKey, confirm };
        this.state = { s: "await_done", pairingId, keys };
        ok = true;
        const reveal: PairRevealEnvelope = {
          v: 1,
          t: "pair_reveal",
          pk: toB64(kem.public),
          n: toB64(nonce),
          ct: toB64(ct),
        };
        return { reveal, sas: code };
      } finally {
        wipe(ss, codeKey);
        // A half derived set of keys never survives a failure.
        if (!ok) wipe(pairingKey, confirm);
      }
    } finally {
      // The ephemeral secret and the nonce are single use.
      wipeKem(kem);
      wipe(nonce);
    }
  }

  /** Handle `pair_done`: check the host MAC in constant time. */
  async onDone(doneIn: PairDone): Promise<void> {
    const st = this.take();
    if (st.s !== "await_done") {
      this.state = st;
      this.abort();
      throw new BridgeError("bad_frame", "unexpected pair_done");
    }
    let ok = false;
    try {
      const done = expectType(parseEnvelope(doneIn), "pair_done");
      ok = await verifyHmac(st.keys.confirm, "host", st.keys.t, fromB64(done.mac));
    } finally {
      if (!ok) wipe(st.keys.pairingKey, st.keys.confirm);
    }
    if (!ok) throw new BridgeError("bad_mac");
    this.state = { s: "verified", pairingId: st.pairingId, keys: st.keys };
  }

  /** The user confirmed the codes match: `pair_confirm` and the record. */
  async confirm(): Promise<{ confirm: PairConfirmEnvelope; record: PairingRecord }> {
    const st = this.take();
    if (st.s !== "verified") {
      this.state = st;
      this.abort();
      throw new BridgeError("bad_frame", "pairing not verified");
    }
    let ok = false;
    try {
      const mac = await hmac(st.keys.confirm, "ext", st.keys.t);
      const out = {
        confirm: { v: 1 as const, t: "pair_confirm" as const, mac: toB64(mac) },
        record: { pairingId: st.pairingId, key: st.keys.pairingKey, createdAt: this.now() },
      };
      ok = true;
      return out;
    } finally {
      wipe(st.keys.confirm);
      // On failure the pairing key is not handed out: wipe it here.
      if (!ok) wipe(st.keys.pairingKey);
    }
  }
}
