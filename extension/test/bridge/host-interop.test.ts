// @vitest-environment node
// Live interoperability: the TypeScript client against the Rust
// development native host (core/onepass-native-host), fixture vault and
// automatic approval, over Chrome's stdio framing.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { BridgeError } from "../../src/bridge/bytes";
import { BridgeAppError, BridgeClient } from "../../src/bridge/client";
import { type PairingRecord, recordFromJson, recordToJson } from "../../src/bridge/pairing";
import { NodeTransport } from "./node-transport";

const CORE = fileURLToPath(new URL("../../../core/", import.meta.url));
const BIN = join(CORE, "target/debug/onepass-native-host");
const FIXTURE = join(CORE, "onepass-native-host/fixtures/e2e.json");
const ATLAS = "https://atlas-cloud.test";
const PATH = `${join(homedir(), ".cargo/bin")}:${process.env.PATH ?? ""}`;

const hasCargo = spawnSync("cargo", ["--version"], { env: { ...process.env, PATH } }).status === 0;
if (!hasCargo) {
  console.warn("host-interop: cargo not found, skipping the native host interoperability test");
}

describe.skipIf(!hasCargo)("interop with onepass-native-host", () => {
  let dir: string;
  let config: string;
  const transports: NodeTransport[] = [];

  beforeAll(() => {
    try {
      execFileSync("cargo", ["build", "-p", "onepass-native-host"], {
        cwd: CORE,
        env: { ...process.env, PATH },
        stdio: "pipe",
        maxBuffer: 64 * 1024 * 1024,
      });
    } catch (e) {
      // The build output only matters when it fails.
      const out = e as { stdout?: Buffer; stderr?: Buffer };
      console.error(`${out.stdout?.toString() ?? ""}${out.stderr?.toString() ?? ""}`);
      throw e;
    }
    dir = mkdtempSync(join(tmpdir(), "onepass-interop-"));
    config = join(dir, "native-host.json");
    writeFileSync(
      config,
      JSON.stringify({
        data_dir: join(dir, "data"),
        allowed_extensions: ["test-extension-id"],
        source: { kind: "fixture", path: FIXTURE },
        approval: "auto",
        unlocked: true,
        reprompt: "deny",
      }),
    );
  }, 600_000);

  afterAll(async () => {
    for (const t of transports) t.close();
    await Promise.all(transports.map((t) => t.exited));
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  function connect(extensionId = "test-extension-id"): NodeTransport {
    const t = new NodeTransport(BIN, [`chrome-extension://${extensionId}/`], {
      ...process.env,
      ONEPASS_NATIVE_HOST_CONFIG: config,
    });
    transports.push(t);
    return t;
  }

  const log = () => readFileSync(join(dir, "data", "native-host.log"), "utf8");
  let stored: unknown;

  it(
    "pairs, opens a session on the same port, lists and fills",
    async () => {
      const client = new BridgeClient(connect());
      let shown = "";
      const record = await client.pair("OnePass", "Chromium", async (sas) => {
        shown = sas;
        return true;
      });
      expect(shown).toMatch(/^\d{3} \d{3}$/);
      const codes = [...log().matchAll(/pairing code: (\d{3} \d{3})/g)].map((m) => m[1]);
      expect(codes).toEqual([shown]);
      expect(record.pairingId.length).toBe(16);
      expect(record.key.length).toBe(32);
      // What chrome.storage.local would keep.
      stored = JSON.parse(JSON.stringify(recordToJson(record)));

      await client.open(record);
      const status = await client.request({ op: "status" });
      expect(status).toMatchObject({ locked: false, account: "alex@atlas.dev" });
      const list = await client.request({ op: "list_for_origin", ctx: "menu", origin: ATLAS });
      const titles = list.items.map((i) => i.title);
      expect(titles).toContain("Atlas Cloud");
      expect(titles).not.toContain("Atlas ancien");
      expect(JSON.stringify(list)).not.toContain("Atl4s-Pass-0001");
      const item = list.items.find((i) => i.title === "Atlas Cloud");
      expect(item?.match).toBe("exact_host");
      const fill = await client.request({
        op: "fill_login",
        ctx: "menu",
        item_id: item?.item_id ?? "",
        origin: ATLAS,
        fields: ["username", "password", "totp"],
      });
      expect(fill.username).toBe("alex@atlas.dev");
      expect(fill.password).toBe("Atl4s-Pass-0001");
      expect(fill.totp).toMatch(/^\d{6}$/);
      // A refused origin is an application error; the session stays open.
      const err = await client
        .request({
          op: "fill_login",
          ctx: "menu",
          item_id: item?.item_id ?? "",
          origin: "https://atlas-cloud.test.evil.test",
          fields: ["password"],
        })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BridgeAppError);
      expect(client.isOpen).toBe(true);
      client.close();
    },
    60_000,
  );

  it(
    "a new connection opens a session from the stored record",
    async () => {
      const record: PairingRecord = recordFromJson(stored);
      const client = new BridgeClient(connect());
      await client.open(record);
      const card = await client.request({ op: "list_fillable", ctx: "menu", origin: ATLAS, kind: "card" });
      expect(Array.isArray(card.items)).toBe(true);
      const status = await client.request({ op: "status" });
      expect(status.locked).toBe(false);
      client.close();
    },
    60_000,
  );

  it(
    "an unknown pairing is refused by the host",
    async () => {
      const client = new BridgeClient(connect());
      const e = (await client
        .open({ pairingId: new Uint8Array(16).fill(7), key: new Uint8Array(32).fill(1), createdAt: 0 })
        .catch((x: unknown) => x)) as BridgeError;
      expect(e).toBeInstanceOf(BridgeError);
      expect(e.hostCode).toBe("unknown_pairing");
    },
    60_000,
  );

  it(
    "an extension outside the allow list is refused",
    async () => {
      const client = new BridgeClient(connect("other-extension"));
      const e = (await client
        .open({ pairingId: new Uint8Array(16), key: new Uint8Array(32), createdAt: 0 })
        .catch((x: unknown) => x)) as BridgeError;
      expect(e.hostCode).toBe("not_allowed");
    },
    60_000,
  );
});
