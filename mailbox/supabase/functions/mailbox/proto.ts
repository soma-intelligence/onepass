// The wire format and the signature base come from onepass-mailbox-proto,
// compiled to WebAssembly (mailbox/scripts/build-proto-wasm.sh): the edge
// function never re-implements decoding or canonicalization (spec 4.6).
// The module is embedded as base64 and instantiated synchronously here: the
// edge runtime cannot fetch() a file: URL.
import { initSync } from "../_shared/proto/onepass_mailbox_proto.js";
import { WASM_BASE64 } from "../_shared/proto/onepass_mailbox_proto_bg.wasm.js";

function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

initSync({ module: fromBase64(WASM_BASE64) });

export * from "../_shared/proto/onepass_mailbox_proto.js";

// Values of the proto crate (messages.rs), spec 4.6 and 4.9.
export const CONTENT_TYPE = "application/vnd.onepass.mailbox.v1+postcard";
export const COMMIT_BODY_MAX = 4 << 20;
export const PAGE_MAX_BYTES = 4 << 20;
export const PAGE_MAX_RECORDS = 1000;
/** A rendezvous frame, 1 MiB at most (spec 4.9). */
export const RDV_FRAME_MAX = 1 << 20;
/** Longest rendezvous long poll, seconds (spec 4.6). */
export const RDV_WAIT_MAX = 25;
