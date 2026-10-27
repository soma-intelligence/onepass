import { describe, expect, it } from "vitest";
import type { BgToCs, CsToBg, FieldRole, FormKind, PageAnalysis, ProviderId, UiToBg } from "../src/shared/messages";
import { isCsToBg } from "../src/shared/messages";

describe("messages types", () => {
  it("accepts a well-formed page analysis", () => {
    const a: PageAnalysis = {
      url: "https://atlas-cloud.test/login",
      forms: [
        {
          ref: "f1",
          kind: "login" satisfies FormKind,
          fields: [{ ref: "e1", role: "username" satisfies FieldRole }],
          submitRef: "e9",
        },
      ],
      captcha: false,
      push: false,
      providerButtons: [{ provider: "google" satisfies ProviderId, ref: "e2" }],
      accountChooser: [{ email: "alex@atlas.dev", ref: "e3" }],
    };
    const m: CsToBg = { type: "page_analysis", analysis: a };
    const ui: UiToBg = { type: "menu_init", token: "t" };
    const bg: BgToCs = { type: "show_frame", kind: "menu", ref: "e1", url: "chrome-extension://x/menu.html#t" };
    expect([m.type, ui.type, bg.type]).toEqual(["page_analysis", "menu_init", "show_frame"]);
  });

  it("isCsToBg validates the discriminant", () => {
    expect(isCsToBg({ type: "close_menu" })).toBe(true);
    expect(isCsToBg({ type: "menu_init", token: "t" })).toBe(false);
    expect(isCsToBg(null)).toBe(false);
    expect(isCsToBg("x")).toBe(false);
  });
});
