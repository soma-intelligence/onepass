// @vitest-environment node
// Opt-in end-to-end test of the Safari path of the production bridge: the
// TypeScript Safari transport and client, through a team-signed stand-in of
// the Safari extension handler (SafariRelay's RelayHub and AppSocket
// launcher, `apple/scripts/safari-probe/main.swift`, signed as
// me.somalabs.onepass.safari, not sandboxed), to a team-signed stand-in of
// the Mac app (`core/onepass-ffi/examples/bridge_probe.rs`). The sandboxed
// appex's refused listener lookup is covered by SafariRelay's unit tests.
// Runs only when ONEPASS_SAFARI_PROBE names the stand-in's executable and
// the app stand-in is listening.
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { afterAll, describe, expect, it } from "vitest";
import { BridgeClient } from "../../src/bridge/client";
import { safariTransport } from "../../src/background/safari";

const PROBE = process.env.ONEPASS_SAFARI_PROBE ?? "";
const ATLAS = "https://atlas-cloud.test";

describe.skipIf(!PROBE)("Safari handler to the bridge socket", () => {
  let child: ChildProcessWithoutNullStreams | undefined;
  const pending = new Map<number, (r: unknown) => void>();
  let next = 1;

  const sendNativeMessage = (_app: string, msg: unknown): Promise<unknown> => {
    if (!child) {
      child = spawn(PROBE, [], { stdio: ["pipe", "pipe", "pipe"] });
      createInterface({ input: child.stdout }).on("line", (line) => {
        const { id, reply } = JSON.parse(line) as { id: number; reply: unknown };
        pending.get(id)?.(reply);
        pending.delete(id);
      });
    }
    const id = next++;
    return new Promise((resolve) => {
      pending.set(id, resolve);
      child?.stdin.write(`${JSON.stringify({ id, msg })}\n`);
    });
  };

  afterAll(() => child?.stdin.end());

  it(
    "pairs, saves, lists and fills through the Safari handler",
    async () => {
      const client = new BridgeClient(safariTransport({ sendNativeMessage }));
      const record = await client.pair("OnePass", "Safari", async () => true);
      await client.open(record);
      expect((await client.request({ op: "status" })).locked).toBe(false);
      const vaults = await client.request({ op: "vaults" });
      await client.request({
        op: "save_login",
        ctx: "save_prompt",
        origin: ATLAS,
        title: "Atlas Safari",
        username: "alex@atlas.dev",
        password: "Safari-Pass-0042",
        vault_id: vaults.vaults[0]?.id ?? "",
        rule: "domain",
        tags: [],
      });
      const list = await client.request({ op: "list_for_origin", ctx: "menu", origin: ATLAS });
      const item = list.items.find((i) => i.title === "Atlas Safari");
      const fill = await client.request({
        op: "fill_login",
        ctx: "menu",
        item_id: item?.item_id ?? "",
        origin: ATLAS,
        fields: ["password"],
      });
      expect(fill.password).toBe("Safari-Pass-0042");
      client.close();
    },
    120_000,
  );
});
