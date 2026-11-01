// Comparison key of a country or region text: no accents, no case, no
// punctuation (letters and digits of any script kept, runs of anything else
// folded to one space).

export function fold(s: string): string {
  return s
    .slice(0, 200)
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/ß/g, "ss")
    .replace(/œ/g, "oe")
    .replace(/æ/g, "ae")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

/** `fold` without the spaces: "N.Y." and "NY" meet. */
export const squash = (s: string): string => fold(s).replace(/ /g, "");
