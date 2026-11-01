// Region deduced from a postal code, for an item without one: United States
// by ZIP prefix, Canada by the first letter, France by department. Military
// ZIPs (AA, AE, AP) and ambiguous prefixes give nothing.

// "first-last:STATE" over the first three ZIP digits.
const ZIP3 =
  "5:NY 6-7:PR 8:VI 9:PR 10-27:MA 28-29:RI 30-38:NH 39-49:ME 50-54:VT 55:MA 56-59:VT 60-69:CT 70-89:NJ " +
  "100-149:NY 150-196:PA 197-199:DE 200:DC 201:VA 202-205:DC 206-219:MD 220-246:VA 247-268:WV 270-289:NC " +
  "290-299:SC 300-319:GA 320-339:FL 341-349:FL 350-369:AL 370-385:TN 386-397:MS 398-399:GA 400-427:KY " +
  "430-459:OH 460-479:IN 480-499:MI 500-528:IA 530-549:WI 550-567:MN 569:DC 570-577:SD 580-588:ND 590-599:MT " +
  "600-629:IL 630-658:MO 660-679:KS 680-693:NE 700-714:LA 716-729:AR 730-732:OK 733:TX 734-749:OK 750-799:TX " +
  "800-816:CO 820-831:WY 832-838:ID 840-847:UT 850-865:AZ 870-884:NM 885:TX 889-898:NV 900-961:CA 967-968:HI " +
  "970-979:OR 980-994:WA 995-999:AK";

// Five-digit exceptions, checked first (969 is shared by Pacific territories).
const ZIP5 = "96799:AS 96910-96932:GU 96950-96952:MP";

type Range = [lo: number, hi: number, code: string];

const parse = (s: string): Range[] =>
  s.split(" ").map((t) => {
    const [span = "", code = ""] = t.split(":");
    const [lo = "", hi = lo] = span.split("-");
    return [Number(lo), Number(hi), code];
  });

const R3 = parse(ZIP3);
const R5 = parse(ZIP5);
const find = (rs: Range[], n: number) => rs.find(([lo, hi]) => n >= lo && n <= hi)?.[2];

function us(postal: string): string | null {
  const m = /^\s*(\d{5})(?:[-\s]?\d{4})?\s*$/.exec(postal);
  if (!m) return null;
  const zip = Number(m[1]);
  const five = find(R5, zip);
  if (five) return `US-${five}`;
  const prefix = Math.floor(zip / 100);
  if (prefix === 969) return null;
  const st = find(R3, prefix);
  return st ? `US-${st}` : null;
}

const CA_LETTER: Readonly<Record<string, string>> = {
  A: "NL", B: "NS", C: "PE", E: "NB", G: "QC", H: "QC", J: "QC", K: "ON", L: "ON", M: "ON", N: "ON", P: "ON",
  R: "MB", S: "SK", T: "AB", V: "BC", Y: "YT",
};

function ca(postal: string): string | null {
  const m = /^\s*([A-Za-z])\d[A-Za-z]\s?\d[A-Za-z]\d\s*$/.exec(postal);
  const p = m ? CA_LETTER[m[1]!.toUpperCase()] : undefined;
  return p ? `CA-${p}` : null;
}

function fr(postal: string): string | null {
  const m = /^\s*(\d{5})\s*$/.exec(postal);
  if (!m) return null;
  const cp = m[1]!;
  const two = cp.slice(0, 2);
  if (two === "20") {
    const third = Number(cp[2]);
    if (third <= 1) return "FR-2A";
    return third <= 6 ? "FR-2B" : null;
  }
  if (two === "97") {
    const three = cp.slice(0, 3);
    return ["971", "972", "973", "974", "976"].includes(three) ? `FR-${three}` : null;
  }
  const n = Number(two);
  return n >= 1 && n <= 95 ? `FR-${two}` : null;
}

/** ISO 3166-2 region of `postal` in `country` (alpha-2), or null. */
export function regionFromPostal(country: string, postal: string): string | null {
  switch (country) {
    case "US":
      return us(postal);
    case "CA":
      return ca(postal);
    case "FR":
      return fr(postal);
    default:
      return null;
  }
}
