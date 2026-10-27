import { describe, expect, it } from "vitest";
import { NATIVE_HOST, nativeTransport } from "../../src/background/native";
import { FakeExt } from "./fake-ext";

describe("nativeTransport", () => {
  it("connects to the dev host and passes envelopes as objects", () => {
    const ext = new FakeExt();
    const names: string[] = [];
    const runtime = {
      ...ext.runtime,
      connectNative: (n: string) => {
        names.push(n);
        return ext.runtime.connectNative(n);
      },
    };
    const t = nativeTransport(NATIVE_HOST, runtime);
    expect(names).toEqual(["me.somalabs.onepass.dev"]);
    const port = ext.ports[0]!;
    // A message received before a listener is registered is not lost.
    port.onMessage.emit({ v: 1, t: "pair_sas" });
    const got: unknown[] = [];
    t.onMessage((m) => got.push(m));
    port.onMessage.emit({ v: 1, t: "pair_ok" });
    expect(got).toEqual([{ v: 1, t: "pair_sas" }, { v: 1, t: "pair_ok" }]);
    t.send({ v: 1, t: "finish", mac: "AA==" });
    expect(port.sent).toEqual([{ v: 1, t: "finish", mac: "AA==" }]);
  });

  it("reports a disconnect with the browser's reason, once", () => {
    const ext = new FakeExt();
    const t = nativeTransport(NATIVE_HOST, ext.runtime);
    const reasons: (string | undefined)[] = [];
    t.onClose((e) => reasons.push(e?.message));
    ext.ports[0]!.hostDisconnect("Specified native messaging host not found.");
    ext.ports[0]!.onDisconnect.emit(ext.ports[0]!);
    expect(reasons).toEqual(["Specified native messaging host not found."]);
    expect(() => t.send({ v: 1, t: "pair_ok" })).toThrow();
  });

  it("close disconnects the port and drops later messages", () => {
    const ext = new FakeExt();
    const t = nativeTransport(NATIVE_HOST, ext.runtime);
    const got: unknown[] = [];
    t.onMessage((m) => got.push(m));
    t.close();
    expect(ext.ports[0]!.disconnected).toBe(true);
    ext.ports[0]!.onMessage.emit({ v: 1, t: "pair_ok" });
    expect(got).toEqual([]);
  });
});
