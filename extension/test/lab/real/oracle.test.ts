// Oracle of the real-site bench: rules R1 to R5 on hand-made snapshots.
import { describe, expect, it } from "vitest";
import { judge, judgeR1, judgeR2, judgeR3, judgeR4, judgeR5, type JudgeContext, type Snapshot } from "../../../lab/real/oracle.ts";

const base = (over: Partial<Snapshot> = {}): Snapshot => ({
  step: "signin-page", host: "example.com", overlayFrames: 0, card: null, cardBoxes: [], cardFrame: null, menuOpen: false, menuBox: null,
  icons: [], fields: [], loginForm: false, signupForm: false, signedInMarks: [], foreignIcons: [], foreignMenus: 0, controls: [], frameProbes: [],
  valuesChanged: [], ...over,
});
const ctx = (over: Partial<JudgeContext> = {}): JudgeContext => ({ vaultLogins: 1, knownSignedIn: false, closedByX: false, arrival: true, ...over });
const card = { overlayFrames: 1, card: "signin" as const, cardFrame: { x: 425, y: 0, width: 430, height: 200 }, cardBoxes: [{ x: 500, y: 20, width: 280, height: 60 }] };
const verdicts = (fs: { verdict: string }[]) => fs.map((f) => f.verdict);

describe("R1", () => {
  it("passes a card on a sign-in page with an account", () => {
    expect(verdicts(judgeR1(base({ ...card, loginForm: true }), ctx()))).toEqual(["pass"]);
  });

  it("flags a card on a page with no sign-in form", () => {
    const f = judgeR1(base({ ...card }), ctx());
    expect(f[0]).toMatchObject({ verdict: "violation", detail: "signin card on a page with no sign-in form" });
  });

  it("flags a card on a signed-in page, by the page or the profile", () => {
    expect(judgeR1(base({ ...card, loginForm: true, signedInMarks: ["avatar"] }), ctx())[0]?.detail).toContain("signed-in page (avatar)");
    expect(judgeR1(base({ ...card, loginForm: true }), ctx({ knownSignedIn: true }))[0]?.verdict).toBe("violation");
  });

  it("flags a card with no account and a card back after ×", () => {
    expect(judgeR1(base({ ...card, loginForm: true }), ctx({ vaultLogins: 0 }))[0]?.detail).toContain("no account");
    expect(judgeR1(base({ ...card, loginForm: true }), ctx({ closedByX: true }))[0]?.detail).toContain("came back after ×");
  });

  it("flags a card for a search field only", () => {
    const f = judgeR1(base({ ...card, fields: [{ index: 0, role: "search", box: { x: 0, y: 0, width: 200, height: 30 } }] }), ctx());
    expect(f.map((x) => x.detail)).toContain("card for a search or newsletter field");
  });

  it("notes a missing card on a sign-in page, only on arrival", () => {
    expect(verdicts(judgeR1(base({ loginForm: true }), ctx()))).toEqual(["info"]);
    expect(verdicts(judgeR1(base({ loginForm: true }), ctx({ arrival: false })))).toEqual(["pass"]);
  });
});

describe("R2", () => {
  it("lets the card cover its own surface and flags an invisible area", () => {
    const own = judgeR2(base({ ...card, controls: [{ tag: "a", x: 600, y: 40, hit: "onepass" }] }));
    expect(verdicts(own)).toEqual(["pass"]);
    const hidden = judgeR2(base({ ...card, controls: [{ tag: "button", x: 440, y: 150, hit: "onepass" }] }));
    expect(hidden[0]).toMatchObject({ verdict: "violation", detail: "invisible OnePass area covers a page <button>" });
  });

  it("flags transparent frame points that take the pointer", () => {
    const f = judgeR2(base({ ...card, frameProbes: [{ x: 440, y: 180, onepass: true }, { x: 600, y: 40, onepass: true }, { x: 840, y: 180, onepass: false }] }));
    expect(f[0]?.detail).toContain("(1 of 3 points)");
  });

  it("flags an icon over a control and a slow or failed ×", () => {
    expect(judgeR2(base({ icons: [{ x: 100, y: 100, width: 22, height: 22 }], controls: [{ tag: "button", x: 110, y: 110, hit: "onepass" }] }))[0]?.detail).toContain("icon covers");
    expect(judgeR2(base({ ...card, closeMs: 2000 }))[0]?.detail).toContain("took 2000 ms");
    expect(judgeR2(base({ ...card, closeMs: null }))[0]?.detail).toBe("× did not remove the card");
    expect(verdicts(judgeR2(base({ ...card, closeMs: 250 })))).toEqual(["pass"]);
  });
});

describe("R3", () => {
  const field = (role: "username" | "search") => ({ index: 3, role, box: { x: 100, y: 300, width: 300, height: 40 } });
  it("flags card and menu together, two cards, two icons, an icon in a search field", () => {
    expect(judgeR3(base({ ...card, menuOpen: true, menuBox: { x: 100, y: 340, width: 380, height: 200 } }))[0]?.detail).toBe("card and field menu open together");
    expect(judgeR3(base({ ...card, overlayFrames: 2 }))[0]?.detail).toBe("2 cards at once");
    const two = judgeR3(base({ fields: [field("username")], icons: [{ x: 370, y: 309, width: 22, height: 22 }, { x: 340, y: 309, width: 22, height: 22 }] }));
    expect(two[0]?.detail).toBe("2 OnePass icons in one username field");
    expect(judgeR3(base({ fields: [field("search")], icons: [{ x: 370, y: 309, width: 22, height: 22 }] }))[0]?.detail).toBe("OnePass icon in a search field");
  });

  it("passes one icon in a sign-in field", () => {
    expect(verdicts(judgeR3(base({ fields: [field("username")], icons: [{ x: 370, y: 309, width: 22, height: 22 }] })))).toEqual(["pass"]);
  });
});

describe("R4", () => {
  it("flags overlapping icons, two dropdowns, a stolen focus, a changed value", () => {
    const f = judgeR4(base({
      icons: [{ x: 370, y: 309, width: 22, height: 22 }], foreignIcons: [{ x: 380, y: 310, width: 20, height: 20 }],
      menuOpen: true, foreignMenus: 1, focus: { expected: "field", on: "onepass" }, valuesChanged: [3],
      fields: [{ index: 3, role: "password", box: { x: 100, y: 300, width: 300, height: 40 } }],
    }), true);
    expect(f.map((x) => x.detail)).toEqual([
      "OnePass icon overlaps another manager's icon",
      "OnePass menu and another manager's dropdown open together",
      "OnePass took the focus from the field",
      "value of a password field changed while nobody typed",
    ]);
  });

  it("skips without another manager and passes icons side by side", () => {
    expect(verdicts(judgeR4(base(), false))).toEqual(["skip"]);
    expect(verdicts(judgeR4(base({ icons: [{ x: 370, y: 309, width: 22, height: 22 }], foreignIcons: [{ x: 330, y: 310, width: 20, height: 20 }] }), true))).toEqual(["pass"]);
  });
});

describe("R5", () => {
  it("passes with nothing cut, notes the page's attempts, flags OnePass's", () => {
    expect(verdicts(judgeR5([]))).toEqual(["pass"]);
    const f = judgeR5([
      { at: 1, kind: "method", host: "a.example", method: "POST", cause: "page" },
      { at: 2, kind: "method", host: "a.example", method: "POST", cause: "onepass" },
      { at: 3, kind: "submit", host: "a.example", cause: "unknown" },
    ]);
    expect(f).toEqual([
      { rule: "R5", verdict: "info", detail: "1 method POST by page cut" },
      { rule: "R5", verdict: "violation", detail: "1 method POST by onepass cut" },
      { rule: "R5", verdict: "warn", detail: "1 submit by unknown cut" },
    ]);
  });
});

it("judge covers the five rules", () => {
  const rules = new Set(judge(base(), ctx(), [], false).map((f) => f.rule));
  expect([...rules]).toEqual(["R1", "R2", "R3", "R4", "R5"]);
});
