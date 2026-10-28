// @vitest-environment node
// Opt-in end-to-end test of the production bridge (spec
// docs/specs/2026-10-27-release-bridge-design.md): the
// TypeScript client, through the signed `onepass-relay` of a Release build,
// to a team-signed stand-in of the Mac app (`core/onepass-ffi/examples/bridge_probe.rs`)
// listening on the App Group socket. Runs only when ONEPASS_APP_RELAY names
// the relay binary and the probe is already running (it prints `ready`).
//
//   ONEPASS_APP_RELAY=<OnePass.app>/Contents/Helpers/onepass-relay npx vitest run test/bridge/app-relay.test.ts
import { describe, expect, it } from "vitest";
import { BridgeError } from "../../src/bridge/bytes";
import { BridgeClient } from "../../src/bridge/client";
import { NodeTransport } from "./node-transport";

const RELAY = process.env.ONEPASS_APP_RELAY ?? "";
const EXTENSION = process.env.ONEPASS_APP_RELAY_EXTENSION ?? "abcdefghijklmnopabcdefghijklmnop";
const ATLAS = "https://atlas-cloud.test";

describe.skipIf(!RELAY)("app relay to the bridge socket", () => {
  const connect = (id = EXTENSION) => new NodeTransport(RELAY, [`chrome-extension://${id}/`, "--parent-window=0"], process.env);

  it(
    "pairs, saves a login, lists and fills it, then reopens from the record",
    async () => {
      const t = connect();
      const client = new BridgeClient(t);
      let shown = "";
      const record = await client.pair("OnePass", "Chrome", async (sas) => {
        shown = sas;
        return true;
      });
      expect(shown).toMatch(/^\d{3} \d{3}$/);
      await client.open(record);
      const status = await client.request({ op: "status" });
      expect(status).toMatchObject({ locked: false });
      const vaults = await client.request({ op: "vaults" });
      const saved = await client.request({
        op: "save_login",
        ctx: "save_prompt",
        origin: ATLAS,
        title: "Atlas Cloud",
        username: "alex@atlas.dev",
        password: "Relay-Pass-0042",
        vault_id: vaults.vaults[0]?.id ?? "",
        rule: "domain",
        tags: [],
      });
      expect(typeof saved.item_id).toBe("string");
      const list = await client.request({ op: "list_for_origin", ctx: "menu", origin: ATLAS });
      const item = list.items.find((i) => i.title === "Atlas Cloud");
      expect(JSON.stringify(list)).not.toContain("Relay-Pass-0042");
      const fill = await client.request({
        op: "fill_login",
        ctx: "menu",
        item_id: item?.item_id ?? "",
        origin: ATLAS,
        fields: ["username", "password"],
      });
      expect(fill.password).toBe("Relay-Pass-0042");
      client.close();
      await t.exited;

      const again = new BridgeClient(connect());
      await again.open(record);
      expect((await again.request({ op: "status" })).locked).toBe(false);
      again.close();
    },
    120_000,
  );

  it(
    "an extension id the app does not list is refused",
    async () => {
      const client = new BridgeClient(connect("ponmlkjihgfedcbaponmlkjihgfedcba"));
      const e = (await client
        .open({ pairingId: new Uint8Array(16), key: new Uint8Array(32), createdAt: 0 })
        .catch((x: unknown) => x)) as BridgeError;
      expect(e).toBeInstanceOf(BridgeError);
      expect(e.hostCode).toBe("not_allowed");
    },
    60_000,
  );
});
