// Native messaging transport over a child process, for tests: each frame
// is a 4-byte little-endian length then UTF-8 JSON (Chrome's framing).
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import type { Transport } from "../../src/bridge/client";
import type { Envelope } from "../../src/bridge/wire";
import { MAX_FRAME } from "../../src/bridge/wire";

export class NodeTransport implements Transport {
  private readonly child: ChildProcessWithoutNullStreams;
  private buf = Buffer.alloc(0);
  private msgCb: ((m: unknown) => void) | undefined;
  private closeCbs: ((e?: Error) => void)[] = [];
  private ended = false;
  readonly exited: Promise<number | null>;
  stderr = "";

  constructor(bin: string, args: string[], env: NodeJS.ProcessEnv) {
    this.child = spawn(bin, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stdout.on("data", (d: Buffer) => this.onData(d));
    this.child.stderr.on("data", (d: Buffer) => {
      this.stderr += d.toString();
    });
    this.child.stdin.on("error", () => this.end(new Error("stdin closed")));
    this.exited = new Promise((resolve) => {
      this.child.on("exit", (code) => {
        this.end(new Error(`host exited with ${code}`));
        resolve(code);
      });
    });
  }

  private onData(d: Buffer): void {
    this.buf = Buffer.concat([this.buf, d]);
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32LE(0);
      if (len > MAX_FRAME) {
        this.end(new Error("frame too large"));
        this.close();
        return;
      }
      if (this.buf.length < 4 + len) return;
      const body = this.buf.subarray(4, 4 + len).toString("utf8");
      this.buf = this.buf.subarray(4 + len);
      let value: unknown;
      try {
        value = JSON.parse(body);
      } catch {
        value = body;
      }
      this.msgCb?.(value);
    }
  }

  private end(e: Error): void {
    if (this.ended) return;
    this.ended = true;
    for (const cb of this.closeCbs) cb(e);
  }

  send(env: Envelope): void {
    const body = Buffer.from(JSON.stringify(env), "utf8");
    if (body.length > MAX_FRAME) throw new Error("frame too large");
    const head = Buffer.alloc(4);
    head.writeUInt32LE(body.length, 0);
    this.child.stdin.write(Buffer.concat([head, body]));
  }

  onMessage(cb: (m: unknown) => void): void {
    this.msgCb = cb;
  }

  onClose(cb: (e?: Error) => void): void {
    this.closeCbs.push(cb);
  }

  close(): void {
    this.child.stdin.end();
  }
}
