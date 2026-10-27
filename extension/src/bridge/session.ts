// Extension side of the session handshake (spec 6.5), mirror of
// `onepass_bridge::session::{ext_hello, ExtPending}`.
//
// `T = H(pairing_id, pk_e, n_e, ct, n_h, session_id)`; keys are
// `HKDF(salt = T, ikm = ss_e || PK)` expanded with the e2h, h2e and confirm
// labels. The host proves itself in `welcome`, the extension in `finish`.
import { BridgeError, concat, fromB64, randomBytes, toB64, wipe } from "./bytes";
import { Channel } from "./channel";
import { expand, hmac, verifyHmac } from "./kdf";
import { type KemKeyPair, decapsulate, generateKem, wipeKem } from "./kem";
import type { PairingRecord } from "./pairing";
import { TRANSCRIPT_LABEL, Transcript } from "./transcript";
import {
  type FinishEnvelope,
  type HelloEnvelope,
  type WelcomeEnvelope,
  expectType,
  parseEnvelope,
} from "./wire";

const E2H_LABEL = "onepass/bridge/session/e2h/v1";
const H2E_LABEL = "onepass/bridge/session/h2e/v1";
const CONFIRM_LABEL = "onepass/bridge/session/confirm/v1";

/** Session values, for cross-language test vectors. */
export interface SessionVectorKeys {
  transcriptHash: Uint8Array;
  e2h: Uint8Array;
  h2e: Uint8Array;
  confirm: Uint8Array;
}

/** Extension side after `hello`, waiting for `welcome`. Single use. */
export class ExtPending {
  private kem: KemKeyPair | undefined;

  constructor(
    private readonly pairingId: Uint8Array,
    private readonly pairingKey: Uint8Array,
    kem: KemKeyPair,
    private readonly nonce: Uint8Array,
  ) {
    this.kem = kem;
  }

  private async derive(kem: KemKeyPair, welcomeIn: WelcomeEnvelope) {
    const welcome = expectType(parseEnvelope(welcomeIn), "welcome");
    const ct = fromB64(welcome.ct);
    const nH = fromB64(welcome.n);
    const sessionId = fromB64(welcome.session_id);
    const mac = fromB64(welcome.mac);
    const ssE = await decapsulate(kem.secret, ct);
    let ikm: Uint8Array | undefined;
    let e2h: Uint8Array | undefined;
    let h2e: Uint8Array | undefined;
    let ok = false;
    try {
      const tr = new Transcript(TRANSCRIPT_LABEL);
      for (const f of [this.pairingId, kem.public, this.nonce, ct, nH, sessionId]) tr.push(f);
      const t = await tr.hash();
      ikm = concat(ssE, this.pairingKey);
      e2h = await expand(t, ikm, E2H_LABEL);
      h2e = await expand(t, ikm, H2E_LABEL);
      const keys: SessionVectorKeys = { transcriptHash: t, e2h, h2e, confirm: await expand(t, ikm, CONFIRM_LABEL) };
      ok = true;
      return { keys, sessionId, mac };
    } finally {
      wipe(ssE, ikm);
      // A half derived set of keys never survives a failure.
      if (!ok) wipe(e2h, h2e);
    }
  }

  /** Derived values without consuming the state, for test vectors. */
  async vectorKeys(welcome: WelcomeEnvelope): Promise<SessionVectorKeys> {
    if (!this.kem) throw new BridgeError("bad_frame", "session already used");
    return (await this.derive(this.kem, welcome)).keys;
  }

  /** Wipe the ephemeral secret without completing. */
  abort(): void {
    if (this.kem) wipeKem(this.kem);
    this.kem = undefined;
    wipe(this.pairingKey);
  }

  /**
   * Handle `welcome`: decapsulate, derive, verify the host MAC in constant
   * time, answer `finish` with the open channel.
   */
  async onWelcome(welcome: WelcomeEnvelope): Promise<{ channel: Channel; finish: FinishEnvelope }> {
    const kem = this.kem;
    if (!kem) throw new BridgeError("bad_frame", "unexpected welcome");
    this.kem = undefined;
    let keys: SessionVectorKeys | undefined;
    try {
      const d = await this.derive(kem, welcome);
      keys = d.keys;
      if (!(await verifyHmac(keys.confirm, "host", keys.transcriptHash, d.mac))) {
        throw new BridgeError("bad_mac");
      }
      const mac = await hmac(keys.confirm, "ext", keys.transcriptHash);
      const channel = await Channel.create("ext", d.sessionId, keys.e2h, keys.h2e);
      return { channel, finish: { v: 1, t: "finish", mac: toB64(mac) } };
    } finally {
      wipeKem(kem);
      wipe(this.pairingKey);
      // The channel holds non-extractable keys; the raw bytes go.
      if (keys) wipe(keys.e2h, keys.h2e, keys.confirm);
    }
  }
}

/** Open a session for a stored pairing: `hello`. */
export function extHello(record: PairingRecord): { pending: ExtPending; hello: HelloEnvelope } {
  return extHelloDeterministic(record, generateKem(), randomBytes(32));
}

/** `extHello` with fixed randomness, for test vectors. */
export function extHelloDeterministic(
  record: PairingRecord,
  kem: KemKeyPair,
  nonce: Uint8Array,
): { pending: ExtPending; hello: HelloEnvelope } {
  if (record.pairingId.length !== 16 || record.key.length !== 32 || nonce.length !== 32) {
    throw new BridgeError("bad_frame", "pairing record");
  }
  const hello: HelloEnvelope = {
    v: 1,
    t: "hello",
    pairing_id: toB64(record.pairingId),
    pk: toB64(kem.public),
    n: toB64(nonce),
  };
  // Own copies: the caller may wipe or reuse the record.
  const pending = new ExtPending(record.pairingId.slice(), record.key.slice(), kem, nonce);
  return { pending, hello };
}
