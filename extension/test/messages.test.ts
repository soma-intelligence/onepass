import { describe, expect, it } from "vitest";
import type { BgToCs, CsToBg, FieldRole, FormKind, PageAnalysis, ProviderId, UiToBg } from "../src/shared/messages";
import type { RequestFor, ResponseFor } from "../src/bridge/client";
import { type Extra, FORMS_ROLES, type IdentityFill, isCsToBg } from "../src/shared/messages";

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

  it("mirrors the bridge's fill_identity types (forms coverage)", () => {
    const extras: Extra[] = ["passport", "driver_license", "loyalty"];
    const r: IdentityFill = {
      given_name: "Alex",
      sex: "f",
      vat_number: "FR32123456789",
      company_registration: "12345678900011",
      passport: { first_names: "Alex Marie", last_name: "Martin", number: "12AB34567", expiry: "2031-04-01" },
      driver_license: { number: "120175300123", country: "FR" },
      loyalty: { number: "123456789", program: "Atlas Miles" },
    };
    expect(extras).toHaveLength(3);
    expect(r.loyalty?.number).toBe("123456789");
    expect(FORMS_ROLES).toHaveLength(21);
    expect(new Set(FORMS_ROLES).size).toBe(21);
  });

  it("types the bridge's undo_save request and the shared flag of vaults", () => {
    const req: RequestFor<"undo_save"> = { op: "undo_save", ctx: "save_prompt", item_id: "i", origin: "https://atlas-cloud.test" };
    expect(JSON.parse(JSON.stringify(req))).toEqual({ op: "undo_save", ctx: "save_prompt", item_id: "i", origin: "https://atlas-cloud.test" });
    const reply: ResponseFor<"vaults"> = {
      vaults: [
        { id: "v1", name: "Personal", color: null },
        { id: "v2", name: "Family", color: "#5856D6", shared: true },
      ],
    };
    expect(reply.vaults.map((v) => v.shared === true)).toEqual([false, true]);
  });

  it("isCsToBg validates the discriminant", () => {
    expect(isCsToBg({ type: "close_menu" })).toBe(true);
    expect(isCsToBg({ type: "menu_init", token: "t" })).toBe(false);
    expect(isCsToBg(null)).toBe(false);
    expect(isCsToBg("x")).toBe(false);
  });
});
