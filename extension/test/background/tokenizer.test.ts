// @vitest-environment node
// Encoder tokenizer port (Task 15): the TypeScript tokenizer must give the ids the Python reference
// (ml/onepass_ml/tokenizer.py) recorded in test/vectors/tokenizer.json, on the tokenizer JSON
// embedded there. ml/tests/test_tokenizer_vectors.py asserts the same file on the Python side.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { encode, loadTokenizer } from "../../src/background/tokenizer";
import { serialize } from "../../src/content/detect/vectorize";
import type { FieldFeatures } from "../../src/content/detect/features";

const root = join(__dirname, "..", "..");
const DATA = JSON.parse(readFileSync(join(root, "test/vectors/tokenizer.json"), "utf8")) as {
  tokenizer: unknown;
  cases: { name: string; text: string; ids: number[]; features?: FieldFeatures }[];
};
const BENCH = join(root, "..", "ml", "out", "bench-encoder", "tokenizer.json");

describe("encoder tokenizer", () => {
  const tok = loadTokenizer(DATA.tokenizer);

  it("gives the ids of the Python reference on every shared case", () => {
    expect(DATA.cases.length).toBeGreaterThan(50);
    for (const c of DATA.cases) expect(encode(tok, c.text), c.name).toEqual(c.ids);
  });

  it("serializes the shared features to the recorded text", () => {
    for (const c of DATA.cases) if (c.features) expect(serialize(c.features), c.name).toBe(c.text);
  });

  it("counts code points, not UTF-16 units (astral cases are in the file)", () => {
    const astral = DATA.cases.filter((c) => Array.from(c.text).length !== c.text.length);
    expect(astral.length).toBeGreaterThan(2);
  });

  it("refuses a tokenizer JSON outside the restricted format", () => {
    const bad = JSON.parse(JSON.stringify(DATA.tokenizer)) as { normalizer: unknown; model: { type: string } };
    bad.normalizer = { type: "NFC" };
    expect(() => loadTokenizer(bad)).toThrow();
    const bpe = JSON.parse(JSON.stringify(DATA.tokenizer)) as { model: { type: string } };
    bpe.model.type = "BPE";
    expect(() => loadTokenizer(bpe)).toThrow();
  });

  it.skipIf(!existsSync(BENCH))("loads the bench encoder tokenizer and truncates to its max length", () => {
    const bench = loadTokenizer(JSON.parse(readFileSync(BENCH, "utf8")));
    const ids = encode(bench, Array.from({ length: 400 }, (_, i) => `w${i}`).join(" "));
    expect(ids).toHaveLength(bench.maxLength);
    expect(ids[0]).toBe(bench.bosId);
    expect(ids.at(-1)).toBe(bench.eosId);
  });
});
