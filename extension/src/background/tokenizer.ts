// Encoder tokenizer: TypeScript port of ml/onepass_ml/tokenizer.py (the Python reference; read its
// header for the pipeline). It reads the same restricted Hugging Face tokenizer.json. Shared cases:
// test/vectors/tokenizer.json, asserted here and by ml/tests/test_tokenizer_vectors.py.
//
// Every index is a Unicode CODE POINT, as in Python strings: texts are turned into arrays of code
// points (Array.from) before any slicing, never sliced as UTF-16. Scores are float64 sums on both
// sides. NFKC uses the engine's Unicode tables (Node and browsers ICU, Python unicodedata 15.0):
// code points assigned after Unicode 15.0 may normalize differently.

const META = "▁";
const UNK_PENALTY = 10;
/** Unicode White_Space (the set Rust char::is_whitespace and the Python reference use). */
const WHITE_SPACE: ReadonlySet<string> = new Set(
  [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
    0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000].map((c) => String.fromCodePoint(c)),
);

export interface Tokenizer {
  readonly scores: readonly number[];
  readonly index: ReadonlyMap<string, number>;
  readonly unkId: number;
  readonly bosId: number;
  readonly eosId: number;
  readonly padId: number;
  readonly maxLength: number;
  /** Special token texts as code point arrays, longest first, with their ids. */
  readonly specials: readonly { cps: readonly string[]; id: number }[];
  /** Longest piece, in code points. */
  readonly maxPiece: number;
  readonly unkScore: number;
}

type Obj = Record<string, unknown>;
const obj = (v: unknown, what: string): Obj => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`tokenizer: ${what} is not an object`);
  return v as Obj;
};
const int = (v: unknown, what: string): number => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new Error(`tokenizer: bad ${what}`);
  return v;
};
function check(cond: boolean, what: string): asserts cond {
  if (!cond) throw new Error(`tokenizer: unsupported ${what}`);
}

/** Parses a tokenizer.json (already JSON.parse'd) restricted to what the reference implements; throws otherwise. */
export function loadTokenizer(json: unknown): Tokenizer {
  const j = obj(json, "file");
  const norm = obj(j.normalizer, "normalizer");
  check(norm.type === "NFKC" && Object.keys(norm).length === 1, "normalizer");
  const pre = obj(j.pre_tokenizer, "pre_tokenizer");
  const pres = pre.pretokenizers;
  check(pre.type === "Sequence" && Array.isArray(pres) && pres.length === 2, "pre_tokenizer");
  check(obj(pres[0], "pre 0").type === "WhitespaceSplit", "pre_tokenizer 0");
  const ms = obj(pres[1], "pre 1");
  check(ms.type === "Metaspace" && ms.replacement === META && ms.prepend_scheme === "always" && ms.split === true, "Metaspace");
  const m = obj(j.model, "model");
  check(m.type === "Unigram" && !m.byte_fallback, "model");
  const vocab = m.vocab;
  check(Array.isArray(vocab) && vocab.length > 0, "vocab");
  const scores: number[] = [];
  const index = new Map<string, number>();
  let maxPiece = 0;
  let minScore = Infinity;
  vocab.forEach((entry: unknown, i: number) => {
    check(Array.isArray(entry) && typeof entry[0] === "string" && typeof entry[1] === "number", "vocab entry");
    const [piece, score] = entry as [string, number];
    scores.push(score);
    // Python's dict comprehension keeps the last index of a duplicated piece.
    index.set(piece, i);
    maxPiece = Math.max(maxPiece, Array.from(piece).length);
    minScore = Math.min(minScore, score);
  });
  const post = obj(j.post_processor, "post_processor");
  const single = post.single;
  check(Array.isArray(single) && single.length === 3, "post_processor");
  const keys = single.map((s: unknown) => Object.keys(obj(s, "single"))[0]);
  check(keys[0] === "SpecialToken" && keys[1] === "Sequence" && keys[2] === "SpecialToken", "post_processor");
  const added = j.added_tokens;
  check(Array.isArray(added), "added_tokens");
  const byName = new Map<string, number>();
  for (const t of added) {
    const o = obj(t, "added token");
    if (o.special === true && typeof o.content === "string") byName.set(o.content, int(o.id, "added token id"));
  }
  const special = (s: unknown): number => {
    const name = obj(obj(s, "single").SpecialToken, "SpecialToken").id;
    const id = typeof name === "string" ? byName.get(name) : undefined;
    if (id === undefined) throw new Error("tokenizer: unknown special token");
    return id;
  };
  const pad = byName.get("<pad>");
  if (pad === undefined) throw new Error("tokenizer: no <pad>");
  const specials = [...byName]
    .map(([name, id]) => ({ cps: Array.from(name), id }))
    // Python: sorted(specials, key=len, reverse=True), a stable sort on code point length.
    .sort((a, b) => b.cps.length - a.cps.length);
  return {
    scores,
    index,
    unkId: int(m.unk_id, "unk_id"),
    bosId: special(single[0]),
    eosId: special(single[2]),
    padId: pad,
    maxLength: int(obj(j.truncation, "truncation").max_length, "max_length"),
    specials,
    maxPiece,
    unkScore: minScore - UNK_PENALTY,
  };
}

/** Text segments (code point arrays) and special token ids, in order (leftmost match, longest on ties). */
function splitSpecials(tok: Tokenizer, cps: readonly string[]): (string[] | number)[] {
  const out: (string[] | number)[] = [];
  const at = (i: number, s: readonly string[]) => s.every((c, k) => cps[i + k] === c);
  let i = 0;
  let start = 0;
  while (i < cps.length) {
    const hit = tok.specials.find((s) => at(i, s.cps));
    if (hit === undefined) {
      i++;
      continue;
    }
    if (start < i) out.push(cps.slice(start, i));
    out.push(hit.id);
    i = start = i + hit.cps.length;
  }
  if (start < cps.length) out.push(cps.slice(start));
  return out;
}

/** Whitespace split, then Metaspace (prepend "always", split before every U+2581). Pieces as code point arrays. */
function preTokenize(cps: readonly string[]): string[][] {
  const words: string[][] = [];
  let cur: string[] = [];
  for (const c of cps) {
    if (WHITE_SPACE.has(c)) {
      if (cur.length) words.push(cur);
      cur = [];
    } else cur.push(c);
  }
  if (cur.length) words.push(cur);
  const out: string[][] = [];
  for (const word of words) {
    // A word holds no U+0020 after the split, so the reference's replace(" ", META) is a no-op.
    const w = word[0] === META ? word : [META, ...word];
    let cut = 0;
    for (let k = 1; k < w.length; k++) {
      if (w[k] === META) {
        out.push(w.slice(cut, k));
        cut = k;
      }
    }
    out.push(w.slice(cut));
  }
  return out;
}

function viterbi(tok: Tokenizer, s: readonly string[]): number[] {
  const n = s.length;
  const best = new Array<number>(n + 1).fill(-Infinity);
  const back: ([number, number] | null)[] = new Array(n + 1).fill(null);
  best[0] = 0;
  for (let start = 0; start < n; start++) {
    if (back[start] === null && start) continue;
    const here = best[start]!;
    let single = false;
    let piece = "";
    const last = Math.min(n, start + tok.maxPiece);
    for (let end = start + 1; end <= last; end++) {
      piece += s[end - 1];
      const i = tok.index.get(piece);
      if (i === undefined) continue;
      if (end === start + 1) single = true;
      const cand = here + tok.scores[i]!;
      if (back[end] === null || cand > best[end]!) {
        best[end] = cand;
        back[end] = [start, i];
      }
    }
    if (!single) {
      const cand = here + tok.unkScore;
      const end = start + 1;
      if (back[end] === null || cand > best[end]!) {
        best[end] = cand;
        back[end] = [start, tok.unkId];
      }
    }
  }
  const ids: number[] = [];
  for (let end = n; end > 0; ) {
    const [start, i] = back[end]!;
    if (!(i === tok.unkId && ids.length && ids[ids.length - 1] === tok.unkId)) ids.push(i);
    end = start;
  }
  return ids.reverse();
}

/** Token ids with `<s>` / `</s>`, truncated to maxLength (same as the reference's encode). */
export function encode(tok: Tokenizer, text: string): number[] {
  const ids: number[] = [];
  for (const seg of splitSpecials(tok, Array.from(text))) {
    if (typeof seg === "number") {
      ids.push(seg);
      continue;
    }
    for (const piece of preTokenize(Array.from(seg.join("").normalize("NFKC")))) ids.push(...viterbi(tok, piece));
  }
  return [tok.bosId, ...ids.slice(0, Math.max(0, tok.maxLength - 2)), tok.eosId];
}
