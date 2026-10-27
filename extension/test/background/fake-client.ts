// A scripted stand-in for BridgeClient (same interface, no cryptography).
import { BridgeError } from "../../src/bridge/bytes";
import type { Op, RequestFor, ResponseFor } from "../../src/bridge/client";
import type { PairingRecord } from "../../src/bridge/pairing";
import type { BridgeLike } from "../../src/background/session";

export type Answer = (req: Record<string, unknown>) => unknown;

export class FakeClient implements BridgeLike {
  open_ = false;
  closed = false;
  readonly requests: Record<string, unknown>[] = [];
  openCalls = 0;
  /** Opened with this pairing id (hex of the first bytes). */
  openedWith: PairingRecord | undefined;

  constructor(
    private readonly answer: Answer = () => ({}),
    private readonly openImpl: () => Promise<void> = async () => undefined,
    private readonly pairImpl?: (sasCb: (sas: string) => Promise<boolean>) => Promise<PairingRecord>,
  ) {}

  get isOpen(): boolean {
    return this.open_ && !this.closed;
  }

  async open(record: PairingRecord): Promise<void> {
    this.openCalls++;
    if (this.closed) throw new BridgeError("closed");
    this.openedWith = { ...record, key: record.key.slice() };
    await this.openImpl();
    this.open_ = true;
  }

  async pair(_extName: string, _browser: string, confirmCodes: (sas: string) => Promise<boolean>): Promise<PairingRecord> {
    if (!this.pairImpl) throw new BridgeError("transport");
    return this.pairImpl(confirmCodes);
  }

  async request<O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> {
    if (!this.isOpen) throw new BridgeError("closed");
    this.requests.push(req as Record<string, unknown>);
    const r = this.answer(req as Record<string, unknown>);
    if (r instanceof Error) throw r;
    return (await r) as ResponseFor<O>;
  }

  close(): void {
    this.closed = true;
  }

  /** The native port died under an open session. */
  drop(): void {
    this.closed = true;
  }
}

export function record(): PairingRecord {
  return { pairingId: new Uint8Array(16).fill(1), key: new Uint8Array(32).fill(2), createdAt: 1_700_000_000_000 };
}
