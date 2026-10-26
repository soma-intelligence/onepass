// JSON envelopes of the bridge protocol (spec 6.3 to 6.6).
//
// Envelopes travel as JSON objects with `"v": 1` and a type tag `"t"`;
// binary fields are standard base64 with padding. `parseEnvelope` checks
// the version first (any other or a missing `v` is a `version` error),
// then the shape and every binary length; it never trusts its input.
import { BridgeError, fromB64, utf8 } from "./bytes";
import { CT_LEN, PUBLIC_LEN } from "./kem";

/** Protocol version carried by every envelope. */
export const VERSION = 1;
/** Frame ceiling of the native messaging transport, in bytes. */
export const MAX_FRAME = 1_048_576;

type V = { v: 1 };
export type PairHelloEnvelope = V & { t: "pair_hello"; commit: string; ext_name: string; browser: string };
export type PairOfferEnvelope = V & { t: "pair_offer"; pairing_id: string; pk: string; n: string };
export type PairRevealEnvelope = V & { t: "pair_reveal"; pk: string; n: string; ct: string };
export type PairSasEnvelope = V & { t: "pair_sas" };
export type PairDoneEnvelope = V & { t: "pair_done"; mac: string };
export type PairConfirmEnvelope = V & { t: "pair_confirm"; mac: string };
export type PairOkEnvelope = V & { t: "pair_ok" };
export type HelloEnvelope = V & { t: "hello"; pairing_id: string; pk: string; n: string };
export type WelcomeEnvelope = V & { t: "welcome"; ct: string; n: string; session_id: string; mac: string };
export type FinishEnvelope = V & { t: "finish"; mac: string };
export type MsgEnvelope = V & { t: "msg"; c: number; d: string };
export type ErrorEnvelope = V & { t: "error"; code: string };

// Short aliases used by the state machines.
export type PairOffer = PairOfferEnvelope;
export type PairDone = PairDoneEnvelope;

export type Envelope =
  | PairHelloEnvelope
  | PairOfferEnvelope
  | PairRevealEnvelope
  | PairSasEnvelope
  | PairDoneEnvelope
  | PairConfirmEnvelope
  | PairOkEnvelope
  | HelloEnvelope
  | WelcomeEnvelope
  | FinishEnvelope
  | MsgEnvelope
  | ErrorEnvelope;

export type EnvelopeType = Envelope["t"];

/** Field kinds: a base64 field of a fixed length, any base64, a string. */
type Kind = number | "b64" | "str";

const SHAPES: Record<EnvelopeType, Record<string, Kind>> = {
  pair_hello: { commit: 32, ext_name: "str", browser: "str" },
  pair_offer: { pairing_id: 16, pk: PUBLIC_LEN, n: 32 },
  pair_reveal: { pk: PUBLIC_LEN, n: 32, ct: CT_LEN },
  pair_sas: {},
  pair_done: { mac: 32 },
  pair_confirm: { mac: 32 },
  pair_ok: {},
  hello: { pairing_id: 16, pk: PUBLIC_LEN, n: 32 },
  welcome: { ct: CT_LEN, n: 32, session_id: 16, mac: 32 },
  finish: { mac: 32 },
  msg: { d: "b64" },
  error: { code: "str" },
};

function bad(detail: string): never {
  throw new BridgeError("bad_frame", detail);
}

/** Parse one envelope from JSON text or an already parsed JSON value. */
export function parseEnvelope(input: unknown): Envelope {
  let value = input;
  if (typeof input === "string") {
    if (utf8(input).length > MAX_FRAME) bad("frame too large");
    try {
      value = JSON.parse(input);
    } catch {
      bad("json");
    }
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) bad("not an object");
  const obj = value as Record<string, unknown>;
  if (obj.v !== VERSION) throw new BridgeError("version");
  const t = obj.t;
  if (typeof t !== "string" || !Object.hasOwn(SHAPES, t)) bad("unknown type");
  const shape = SHAPES[t as EnvelopeType];
  const out: Record<string, unknown> = { v: VERSION, t };
  for (const [name, kind] of Object.entries(shape)) {
    const f = obj[name];
    if (typeof f !== "string") bad(`field ${name}`);
    if (kind !== "str") {
      const bytes = fromB64(f);
      if (typeof kind === "number" && bytes.length !== kind) bad(`length of ${name}`);
    }
    out[name] = f;
  }
  if (t === "msg") {
    const c = obj.c;
    if (typeof c !== "number" || !Number.isSafeInteger(c) || c < 0) bad("counter");
    out.c = c;
  }
  return out as Envelope;
}

/** Narrow a parsed envelope to the expected type, or `bad_frame`. */
export function expectType<T extends EnvelopeType>(env: Envelope, t: T): Extract<Envelope, { t: T }> {
  if (env.t !== t) bad(`expected ${t}, got ${env.t}`);
  return env as Extract<Envelope, { t: T }>;
}
