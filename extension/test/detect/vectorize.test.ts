// Shared vectorizer: the cases in test/vectors/vectorize.json are asserted by this file and by
// ml/tests/test_vectorize.py, so the model sees the same input in training and in the extension.
// Regenerate the file once from this side with: UPDATE_VECTORS=1 npx vitest run test/detect/vectorize.test.ts
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { FieldFeatures } from "../../src/content/detect/features";
import { cyrb128 } from "../../src/shared/hash";
import { cyrb128 as labCyrb128 } from "../../lab/gen/rng";
import { HASH_DIM, INDICATORS, NUM_INDICATORS, serialize, tokenize, vectorize, VECTOR_DIM } from "../../src/content/detect/vectorize";

const FILE = join(__dirname, "..", "vectors", "vectorize.json");

const base: FieldFeatures = {
  index: 0, tag: "input", hasPattern: false, required: false, depth: 3, siblings: 0,
  visibility: "visible", width: 0, height: 0, formButtons: [], neighbourLabels: [],
};
const f = (o: Partial<FieldFeatures>): FieldFeatures => ({ ...base, ...o });

const HASH_INPUTS = ["", "a", "name:email", "label:メール", "ph:😀", "ac:given-name", "x".repeat(300)];

const CASES: { name: string; features: FieldFeatures }[] = [
  { name: "english_email", features: f({ type: "email", name: "email", id: "user_email", autocomplete: "email", label: "email address", placeholder: "you@example.com", required: true, formButtons: ["sign in"] }) },
  { name: "password_login", features: f({ type: "password", name: "pwd", autocomplete: "current-password", label: "password", index: 1, formButtons: ["sign in", "forgot password?"], neighbourLabels: ["email address"] }) },
  { name: "japanese", features: f({ type: "text", name: "mei", label: "お名前", placeholder: "山田太郎", before: "メールアドレス", after: "必須", formButtons: ["送信"] }) },
  { name: "japanese_katakana_halfwidth", features: f({ type: "text", label: "ｶﾀｶﾅ", placeholder: "カタカナ" }) },
  { name: "arabic", features: f({ type: "email", label: "البريد الإلكتروني", placeholder: "أدخل بريدك", formButtons: ["تسجيل الدخول"] }) },
  { name: "korean", features: f({ type: "text", label: "이메일 주소", placeholder: "이메일주소를 입력", before: "회원가입", formButtons: ["로그인"] }) },
  { name: "chinese_no_spaces", features: f({ type: "text", label: "电子邮件地址", placeholder: "请输入您的电子邮件", after: "必填项", formButtons: ["登录"] }) },
  { name: "chinese_single_char", features: f({ type: "text", label: "姓" }) },
  { name: "turkish_dotted_capital_i", features: f({ type: "text", label: "İSMİNİZ", placeholder: "İstanbul", name: "İsim" }) },
  { name: "turkish_dotless", features: f({ type: "text", label: "Soyadı Iı" }) },
  { name: "german_sharp_s", features: f({ type: "text", label: "Straße und Hausnummer", placeholder: "STRAẞE", name: "Straße" }) },
  { name: "greek_final_sigma", features: f({ type: "text", label: "ΟΔΥΣΣΕΥΣ ΟΝΟΜΑΣ", placeholder: "ΑΣ ΣΣ" }) },
  { name: "emoji", features: f({ type: "text", label: "😀 name 👨‍👩‍👧", placeholder: "📧", formButtons: ["🚀 go"] }) },
  { name: "empty_input", features: f({}) },
  { name: "empty_strings_everywhere", features: f({ type: "", name: "", id: "", autocomplete: "", label: "", placeholder: "", ariaLabel: "", before: "", after: "", inputmode: "", formButtons: ["", " "], neighbourLabels: ["", "  "] }) },
  { name: "whitespace_and_nbsp", features: f({ type: "text", label: "  first  name \t\n last　name﻿", before: "  line sep​" }) },
  { name: "very_long_label", features: f({ type: "text", label: Array.from({ length: 120 }, (_, i) => `word${i}`).join(" "), placeholder: "あ".repeat(500) }) },
  { name: "fullwidth_and_compat", features: f({ type: "text", label: "ＥＭＡＩＬ ﬁnd ① ½", name: "ｎａｍｅ" }) },
  { name: "select_country", features: f({ tag: "select", type: undefined, name: "country", autocomplete: "country-name", label: "country", visibility: "display_none", formButtons: ["continue"] }) },
  { name: "textarea_message", features: f({ tag: "textarea", name: "message", ariaLabel: "your message", maxlength: 500, index: 4, siblings: 2 }) },
  { name: "number_otp", features: f({ type: "tel", inputmode: "numeric", maxlength: 6, hasPattern: true, autocomplete: "one-time-code", label: "verification code", depth: 40, index: 99, siblings: 30, visibility: "offscreen" }) },
  { name: "unknown_autocomplete_section", features: f({ type: "text", autocomplete: "section-billing shipping given-name", name: "fn" }) },
  { name: "autocomplete_off_unknown", features: f({ type: "text", autocomplete: "off", inputmode: "weird", maxlength: 70, visibility: "opacity" }) },
  { name: "neighbours_and_buttons", features: f({ type: "text", before: "card number", after: "hint", neighbourLabels: ["name on card", "expiry", "cvc"], formButtons: ["pay now", "cancel", "back"], visibility: "zero_size" }) },
  { name: "combining_marks_hindi", features: f({ type: "text", label: "नाम ईमेल", placeholder: "émail" }) },
  { name: "ignored_fields_do_not_matter", features: f({ type: "text", label: "x", width: 999, height: 77, pageTitle: "A Page Title", lab: "email" }) },
  { name: "numeric_indicators_absent", features: (({ depth, index, siblings, ...rest }) => rest as unknown as FieldFeatures)(f({ type: "text", label: "x" })) },
  { name: "maxlength_2", features: f({ type: "text", maxlength: 2 }) },
  { name: "maxlength_3", features: f({ type: "text", maxlength: 3 }) },
  { name: "maxlength_4", features: f({ type: "text", maxlength: 4 }) },
  { name: "maxlength_8", features: f({ type: "text", maxlength: 8 }) },
  { name: "maxlength_9", features: f({ type: "text", maxlength: 9 }) },
  { name: "maxlength_16", features: f({ type: "text", maxlength: 16 }) },
  { name: "maxlength_64", features: f({ type: "text", maxlength: 64 }) },
  { name: "maxlength_65", features: f({ type: "text", maxlength: 65 }) },
  { name: "maxlength_1", features: f({ type: "text", maxlength: 1 }) },
  { name: "name_and_id_long_and_cjk", features: f({ type: "text", name: "  First\u00a0NAME  ", id: "\u59d3\u540d".repeat(200) }) },
];

describe("hash", () => {
  it("src hash and lab rng hash are the same implementation", () => {
    for (const s of HASH_INPUTS) expect(cyrb128(s)).toEqual(labCyrb128(s));
    expect(cyrb128).toBe(labCyrb128);
  });
});

describe("vectorize", () => {
  it("layout: 4096 dims, indicators last, positions fixed", () => {
    expect(VECTOR_DIM).toBe(4096);
    expect(HASH_DIM + NUM_INDICATORS).toBe(VECTOR_DIM);
    expect(INDICATORS.at(-1)!.offset + INDICATORS.at(-1)!.size).toBe(VECTOR_DIM);
    expect(vectorize(f({})).length).toBe(VECTOR_DIM);
  });

  it("never reads target, lab, width, height or pageTitle", () => {
    const spy = (o: Record<string, unknown>): FieldFeatures => {
      for (const k of ["target", "lab", "width", "height", "pageTitle", "split", "origin", "seed"]) {
        Object.defineProperty(o, k, { enumerable: true, get() { throw new Error(`read ${k}`); } });
      }
      return o as unknown as FieldFeatures;
    };
    const o = spy({ ...f({ label: "email" }) });
    expect(() => vectorize(o)).not.toThrow();
    expect(() => serialize(o)).not.toThrow();
  });

  it("tokenize: words, CJK bigrams, marks stay with their word", () => {
    expect(tokenize("E-mail address 2")).toEqual(["e", "mail", "address", "2"]);
    expect(tokenize("メールアドレス")).toEqual(["メー", "ール", "ルア", "アド", "ドレ", "レス"]);
    expect(tokenize("姓")).toEqual(["姓"]);
    expect(tokenize("email地址x")).toEqual(["email", "地址", "x"]);
    expect(tokenize("")).toEqual([]);
  });

  const file = (): { cases: { name: string; features: FieldFeatures; nonzero: [number, number][]; serialize: string }[]; hashes: { input: string; words: number[] }[] } =>
    JSON.parse(readFileSync(FILE, "utf8"));

  if (process.env.UPDATE_VECTORS) {
    it("regenerates vectorize.json", () => {
      const cases = CASES.map((c) => {
        const v = vectorize(c.features);
        const nonzero: [number, number][] = [];
        v.forEach((x, i) => { if (x !== 0) nonzero.push([i, x]); });
        return { name: c.name, features: c.features, nonzero, serialize: serialize(c.features) };
      });
      const hashes = HASH_INPUTS.map((input) => ({ input, words: [...cyrb128(input)] }));
      writeFileSync(FILE, JSON.stringify({ cases, hashes }, null, 1) + "\n");
    });
  }

  it("at least 20 shared cases", () => {
    expect(file().cases.length).toBeGreaterThanOrEqual(20);
    expect(file().cases.map((c) => c.name)).toEqual(CASES.map((c) => c.name));
  });

  it("matches the shared vectors", () => {
    for (const c of file().cases) {
      const v = vectorize(c.features);
      const nonzero: [number, number][] = [];
      v.forEach((x, i) => { if (x !== 0) nonzero.push([i, x]); });
      expect(nonzero, c.name).toEqual(c.nonzero);
      expect(serialize(c.features), c.name).toBe(c.serialize);
    }
  });

  it("shared hash words", () => {
    for (const h of file().hashes) expect([...cyrb128(h.input)], h.input).toEqual(h.words);
  });

  it("absent depth, index and siblings count as 0, never NaN", () => {
    const { depth, index, siblings, ...rest } = f({ label: "x" });
    const v = vectorize(rest as unknown as FieldFeatures);
    expect(v.some(Number.isNaN)).toBe(false);
    expect(v).toEqual(vectorize(f({ label: "x", depth: 0, index: 0, siblings: 0 })));
  });

  it("serialize carries name and id", () => {
    expect(serialize(f({ type: "email", name: "Mail", id: "u1" }))).toMatch(/^type=email \| name=mail \| id=u1 \| ac=/);
  });

  it("same features give the same vector, ignored fields change nothing", () => {
    const a = vectorize(f({ label: "x", width: 1, height: 2, pageTitle: "t" }));
    const b = vectorize(f({ label: "x", width: 9, height: 8, pageTitle: "u", lab: "email" }));
    expect(a).toEqual(b);
  });
});
