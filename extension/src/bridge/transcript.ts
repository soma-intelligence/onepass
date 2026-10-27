// Length-prefixed transcript hashing (spec 6.3).
import { concat, u32be, utf8 } from "./bytes";
import { sha256 } from "./kdf";

/** Domain label hashed ahead of every transcript. */
export const TRANSCRIPT_LABEL = "onepass/bridge/transcript/v1";

/** Accumulates fields as `u32 big-endian length || bytes`, the label first. */
export class Transcript {
  private readonly parts: Uint8Array[] = [];

  constructor(label: string) {
    this.push(utf8(label));
  }

  /** Append one field. Strings are passed as their UTF-8 bytes. */
  push(field: Uint8Array): void {
    this.parts.push(u32be(field.length), field);
  }

  /** SHA-256 of everything pushed so far, label included. */
  hash(): Promise<Uint8Array> {
    return sha256(concat(...this.parts));
  }
}
