// Encrypted channel of an open session (spec 6.6), mirror of
// `onepass_bridge::channel::Channel`.
//
// AES-256-GCM (WebCrypto), one key per direction. Nonce:
// `[0, 0, 0, 0] || counter` (u64 big-endian). AAD:
// `session_id || dir || counter`, `dir` 0 for extension to host, 1 for host
// to extension. Each direction counts from 0 and the receiver requires
// exactly the next counter. Any failure to open closes the channel for good.
//
// Counters are reserved synchronously, before any await: concurrent calls
// get distinct counters in call order. The caller must hand frames to the
// transport, and to `open`, in that order.
import { BridgeError, bs, concat, fromB64, toB64, u64be } from "./bytes";
import { type MsgEnvelope, expectType, parseEnvelope } from "./wire";

/** A counter reaching this value closes the session. */
export const COUNTER_LIMIT = 2 ** 32;

const DIR_E2H = 0;
const DIR_H2E = 1;

export type ChannelRole = "ext" | "host";

interface Half {
  key: CryptoKey | undefined;
  dir: number;
  counter: number;
}

function nonce(counter: number): Uint8Array {
  return concat(new Uint8Array(4), u64be(counter));
}

async function importKey(raw: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  if (raw.length !== 32) throw new BridgeError("crypto", "channel key length");
  return crypto.subtle.importKey("raw", bs(raw), "AES-GCM", false, [usage]);
}

export class Channel {
  private closedFlag = false;

  private constructor(
    readonly role: ChannelRole,
    private readonly sessionId: Uint8Array,
    private readonly send: Half,
    private readonly recv: Half,
  ) {}

  /** Build from the two directional keys of the handshake. */
  static async create(
    role: ChannelRole,
    sessionId: Uint8Array,
    e2h: Uint8Array,
    h2e: Uint8Array,
  ): Promise<Channel> {
    if (sessionId.length !== 16) throw new BridgeError("crypto", "session id length");
    const ext = role === "ext";
    const send: Half = {
      key: await importKey(ext ? e2h : h2e, "encrypt"),
      dir: ext ? DIR_E2H : DIR_H2E,
      counter: 0,
    };
    const recv: Half = {
      key: await importKey(ext ? h2e : e2h, "decrypt"),
      dir: ext ? DIR_H2E : DIR_E2H,
      counter: 0,
    };
    return new Channel(role, sessionId.slice(), send, recv);
  }

  get closed(): boolean {
    return this.closedFlag;
  }

  /** Close for good and drop the keys. */
  close(): void {
    this.closedFlag = true;
    this.send.key = undefined;
    this.recv.key = undefined;
  }

  private fail(e: BridgeError): never {
    this.close();
    throw e;
  }

  private aad(h: Half, counter: number): Uint8Array {
    return concat(this.sessionId, new Uint8Array([h.dir]), u64be(counter));
  }

  /** Encrypt one application message into a `msg` envelope. */
  async seal(plaintext: Uint8Array): Promise<MsgEnvelope> {
    const key = this.send.key;
    if (this.closedFlag || !key) throw new BridgeError("closed");
    if (this.send.counter >= COUNTER_LIMIT) this.fail(new BridgeError("closed", "counter limit"));
    const c = this.send.counter++;
    let out: ArrayBuffer;
    try {
      out = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: bs(nonce(c)), additionalData: bs(this.aad(this.send, c)), tagLength: 128 },
        key,
        bs(plaintext),
      );
    } catch {
      this.fail(new BridgeError("crypto", "seal"));
    }
    return { v: 1, t: "msg", c, d: toB64(new Uint8Array(out)) };
  }

  /**
   * Decrypt the next frame. A wrong counter or a frame that does not
   * authenticate closes the channel; later calls give `closed`.
   */
  async open(msgIn: MsgEnvelope): Promise<Uint8Array> {
    const key = this.recv.key;
    if (this.closedFlag || !key) throw new BridgeError("closed");
    if (this.recv.counter >= COUNTER_LIMIT) this.fail(new BridgeError("closed", "counter limit"));
    let msg: MsgEnvelope;
    let data: Uint8Array;
    try {
      msg = expectType(parseEnvelope(msgIn), "msg");
      data = fromB64(msg.d);
    } catch (e) {
      this.fail(e instanceof BridgeError ? e : new BridgeError("bad_frame"));
    }
    if (msg.c !== this.recv.counter) this.fail(new BridgeError("replay"));
    const c = this.recv.counter++;
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bs(nonce(c)), additionalData: bs(this.aad(this.recv, c)), tagLength: 128 },
        key,
        bs(data),
      );
      return new Uint8Array(plain);
    } catch {
      this.fail(new BridgeError("bad_mac"));
    }
  }
}
