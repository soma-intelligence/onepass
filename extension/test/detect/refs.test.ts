import { describe, expect, it } from "vitest";
import { RefRegistry } from "../../src/content/detect/refs";

describe("RefRegistry", () => {
  it("gives a stable opaque id per element and resolves it back", () => {
    document.body.innerHTML = '<input id="user-field" name="username">';
    const el = document.getElementById("user-field") as HTMLElement;
    const refs = new RefRegistry();
    const r = refs.refFor(el);
    expect(refs.refFor(el)).toBe(r);
    expect(refs.get(r)).toBe(el);
    expect(r).not.toContain("user");
    expect(r).toMatch(/^[A-Za-z0-9_-]{16,}$/);
  });

  it("returns distinct ids for distinct elements and null for unknown ids", () => {
    document.body.innerHTML = "<input><input>";
    const [a, b] = Array.from(document.querySelectorAll("input"));
    const refs = new RefRegistry();
    expect(refs.refFor(a!)).not.toBe(refs.refFor(b!));
    expect(refs.get("nope")).toBeNull();
  });

  it("does not resolve elements removed from the document", () => {
    document.body.innerHTML = "<input id=x>";
    const refs = new RefRegistry();
    const el = document.getElementById("x")!;
    const r = refs.refFor(el);
    el.remove();
    expect(refs.get(r)).toBeNull();
  });
});
