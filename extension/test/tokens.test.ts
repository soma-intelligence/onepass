import { describe, expect, it } from "vitest";
import { newToken } from "../src/shared/tokens";

describe("newToken", () => {
  it("is 16 bytes of base64url without padding", () => {
    const t = newToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const bytes = Uint8Array.from(atob(t.replace(/-/g, "+").replace(/_/g, "/") + "=="), (c) => c.charCodeAt(0));
    expect(bytes).toHaveLength(16);
  });
  it("does not repeat", () => {
    const set = new Set(Array.from({ length: 1000 }, () => newToken()));
    expect(set.size).toBe(1000);
  });
});
