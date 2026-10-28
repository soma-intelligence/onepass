import { describe, expect, it } from "vitest";
// @ts-expect-error plain JavaScript script without declarations
import { manifestFor } from "../scripts/install-app-host.mjs";

const RELAY = "/Applications/OnePass.app/Contents/Helpers/onepass-relay";

describe("install-app-host manifests", () => {
  it("points Chrome at the app relay for one extension id", () => {
    expect(manifestFor("chrome", RELAY, "abcdefghijklmnopabcdefghijklmnop")).toEqual({
      name: "me.somalabs.onepass",
      description: "OnePass",
      path: RELAY,
      type: "stdio",
      allowed_origins: ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
    });
  });

  it("uses the Firefox add-on id", () => {
    expect(manifestFor("firefox", RELAY).allowed_extensions).toEqual(["onepass@somalabs.me"]);
  });

  it("refuses a missing or malformed Chrome id", () => {
    expect(() => manifestFor("chrome", RELAY)).toThrow();
    expect(() => manifestFor("chromium", RELAY, "xyz")).toThrow();
    expect(() => manifestFor("chrome", RELAY, "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP")).toThrow();
  });
});
