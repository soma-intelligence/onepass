// Seeded, deterministic PRNG for the autofill lab generator: cyrb128 string
// hash feeding sfc32. No Math.random and no clock, so a seed always yields
// the same world.

function cyrb128(str: string): [number, number, number, number] {
  let h1 = 1779033703;
  let h2 = 3144134277;
  let h3 = 1013904242;
  let h4 = 2773480762;
  for (let i = 0; i < str.length; i++) {
    const k = str.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  return [(h1 ^ h2 ^ h3 ^ h4) >>> 0, (h2 ^ h1) >>> 0, (h3 ^ h1) >>> 0, (h4 ^ h1) >>> 0];
}

export class Rng {
  private a: number;
  private b: number;
  private c: number;
  private d: number;
  private readonly seed: string;

  // No parameter properties: lab code must run under node --experimental-strip-types.
  constructor(seed: string) {
    this.seed = seed;
    [this.a, this.b, this.c, this.d] = cyrb128(seed);
    for (let i = 0; i < 15; i++) this.step();
  }

  private step(): number {
    const t = (((this.a + this.b) | 0) + this.d) | 0;
    this.d = (this.d + 1) | 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) | 0;
    this.c = (this.c << 21) | (this.c >>> 11);
    this.c = (this.c + t) | 0;
    return t >>> 0;
  }

  /** Uniform float in [0, 1). */
  next(): number {
    return this.step() / 4294967296;
  }

  /** Uniform integer in [min, maxInclusive]. */
  int(min: number, maxInclusive: number): number {
    return min + Math.floor(this.next() * (maxInclusive - min + 1));
  }

  pick<T>(xs: readonly T[]): T {
    if (xs.length === 0) throw new Error("Rng.pick: empty list");
    return xs[this.int(0, xs.length - 1)] as T;
  }

  /** Picks by weight; entries with weight 0 are never returned. */
  weighted<T>(xs: readonly (readonly [T, number])[]): T {
    const total = xs.reduce((s, [, w]) => s + w, 0);
    if (!(total > 0)) throw new Error("Rng.weighted: no positive weight");
    let r = this.next() * total;
    let last: T | undefined;
    for (const [x, w] of xs) {
      if (w <= 0) continue;
      last = x;
      if (r < w) return x;
      r -= w;
    }
    return last as T;
  }

  chance(p: number): boolean {
    return this.next() < p;
  }

  /** Fisher-Yates on a copy. */
  shuffle<T>(xs: readonly T[]): T[] {
    const out = [...xs];
    for (let i = out.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      [out[i], out[j]] = [out[j] as T, out[i] as T];
    }
    return out;
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = this.int(0, 255);
    return out;
  }

  /** Independent child stream: depends only on the seed and `name`, not on draws so far. */
  fork(name: string): Rng {
    return new Rng(`${this.seed}/${name}`);
  }
}
