// ISO 3166-1 countries (alpha-2, alpha-3, numeric) and their names through
// Intl.DisplayNames, for matching a vault's country with a page's option.
// The vault's canonical value is the alpha-2 code (spec 2026-10-31, section 2).
import { squash } from "./fold";

// "alpha-2 alpha-3 numeric" triples, alpha-2 order. XK (Kosovo) is
// user-assigned and has no numeric code.
const TABLE =
  "AD AND 020 AE ARE 784 AF AFG 004 AG ATG 028 AI AIA 660 AL ALB 008 AM ARM 051 AO AGO 024 AQ ATA 010 AR ARG 032 " +
  "AS ASM 016 AT AUT 040 AU AUS 036 AW ABW 533 AX ALA 248 AZ AZE 031 BA BIH 070 BB BRB 052 BD BGD 050 BE BEL 056 " +
  "BF BFA 854 BG BGR 100 BH BHR 048 BI BDI 108 BJ BEN 204 BL BLM 652 BM BMU 060 BN BRN 096 BO BOL 068 BQ BES 535 " +
  "BR BRA 076 BS BHS 044 BT BTN 064 BV BVT 074 BW BWA 072 BY BLR 112 BZ BLZ 084 CA CAN 124 CC CCK 166 CD COD 180 " +
  "CF CAF 140 CG COG 178 CH CHE 756 CI CIV 384 CK COK 184 CL CHL 152 CM CMR 120 CN CHN 156 CO COL 170 CR CRI 188 " +
  "CU CUB 192 CV CPV 132 CW CUW 531 CX CXR 162 CY CYP 196 CZ CZE 203 DE DEU 276 DJ DJI 262 DK DNK 208 DM DMA 212 " +
  "DO DOM 214 DZ DZA 012 EC ECU 218 EE EST 233 EG EGY 818 EH ESH 732 ER ERI 232 ES ESP 724 ET ETH 231 FI FIN 246 " +
  "FJ FJI 242 FK FLK 238 FM FSM 583 FO FRO 234 FR FRA 250 GA GAB 266 GB GBR 826 GD GRD 308 GE GEO 268 GF GUF 254 " +
  "GG GGY 831 GH GHA 288 GI GIB 292 GL GRL 304 GM GMB 270 GN GIN 324 GP GLP 312 GQ GNQ 226 GR GRC 300 GS SGS 239 " +
  "GT GTM 320 GU GUM 316 GW GNB 624 GY GUY 328 HK HKG 344 HM HMD 334 HN HND 340 HR HRV 191 HT HTI 332 HU HUN 348 " +
  "ID IDN 360 IE IRL 372 IL ISR 376 IM IMN 833 IN IND 356 IO IOT 086 IQ IRQ 368 IR IRN 364 IS ISL 352 IT ITA 380 " +
  "JE JEY 832 JM JAM 388 JO JOR 400 JP JPN 392 KE KEN 404 KG KGZ 417 KH KHM 116 KI KIR 296 KM COM 174 KN KNA 659 " +
  "KP PRK 408 KR KOR 410 KW KWT 414 KY CYM 136 KZ KAZ 398 LA LAO 418 LB LBN 422 LC LCA 662 LI LIE 438 LK LKA 144 " +
  "LR LBR 430 LS LSO 426 LT LTU 440 LU LUX 442 LV LVA 428 LY LBY 434 MA MAR 504 MC MCO 492 MD MDA 498 ME MNE 499 " +
  "MF MAF 663 MG MDG 450 MH MHL 584 MK MKD 807 ML MLI 466 MM MMR 104 MN MNG 496 MO MAC 446 MP MNP 580 MQ MTQ 474 " +
  "MR MRT 478 MS MSR 500 MT MLT 470 MU MUS 480 MV MDV 462 MW MWI 454 MX MEX 484 MY MYS 458 MZ MOZ 508 NA NAM 516 " +
  "NC NCL 540 NE NER 562 NF NFK 574 NG NGA 566 NI NIC 558 NL NLD 528 NO NOR 578 NP NPL 524 NR NRU 520 NU NIU 570 " +
  "NZ NZL 554 OM OMN 512 PA PAN 591 PE PER 604 PF PYF 258 PG PNG 598 PH PHL 608 PK PAK 586 PL POL 616 PM SPM 666 " +
  "PN PCN 612 PR PRI 630 PS PSE 275 PT PRT 620 PW PLW 585 PY PRY 600 QA QAT 634 RE REU 638 RO ROU 642 RS SRB 688 " +
  "RU RUS 643 RW RWA 646 SA SAU 682 SB SLB 090 SC SYC 690 SD SDN 729 SE SWE 752 SG SGP 702 SH SHN 654 SI SVN 705 " +
  "SJ SJM 744 SK SVK 703 SL SLE 694 SM SMR 674 SN SEN 686 SO SOM 706 SR SUR 740 SS SSD 728 ST STP 678 SV SLV 222 " +
  "SX SXM 534 SY SYR 760 SZ SWZ 748 TC TCA 796 TD TCD 148 TF ATF 260 TG TGO 768 TH THA 764 TJ TJK 762 TK TKL 772 " +
  "TL TLS 626 TM TKM 795 TN TUN 788 TO TON 776 TR TUR 792 TT TTO 780 TV TUV 798 TW TWN 158 TZ TZA 834 UA UKR 804 " +
  "UG UGA 800 UM UMI 581 US USA 840 UY URY 858 UZ UZB 860 VA VAT 336 VC VCT 670 VE VEN 862 VG VGB 092 VI VIR 850 " +
  "VN VNM 704 VU VUT 548 WF WLF 876 WS WSM 882 XK XKX - YE YEM 887 YT MYT 175 ZA ZAF 710 ZM ZMB 894 ZW ZWE 716";

const ALPHA2 = new Set<string>();
const ALPHA3 = new Map<string, string>();
const NUMERIC = new Map<number, string>();
{
  const t = TABLE.split(" ");
  for (let i = 0; i + 2 < t.length; i += 3) {
    const [a2, a3, num] = [t[i]!, t[i + 1]!, t[i + 2]!];
    ALPHA2.add(a2);
    ALPHA3.set(a3, a2);
    if (num !== "-") NUMERIC.set(Number(num), a2);
  }
}

export const COUNTRY_CODES: readonly string[] = [...ALPHA2];

/** Names the display names miss (folded, squashed). */
const ALIASES: Readonly<Record<string, string>> = {
  usa: "US", unitedstatesofamerica: "US", etatsunisdamerique: "US", america: "US", amerique: "US",
  uk: "GB", greatbritain: "GB", grandebretagne: "GB", unitedkingdomofgreatbritainandnorthernireland: "GB",
  england: "GB", angleterre: "GB", scotland: "GB", wales: "GB",
  czechrepublic: "CZ", republiquetcheque: "CZ", holland: "NL", hollande: "NL", southkorea: "KR", northkorea: "KP",
  russianfederation: "RU", vietnam: "VN", ivorycoast: "CI", cotedivoire: "CI", turkey: "TR", turquie: "TR",
  macedonia: "MK", swaziland: "SZ", burma: "MM", vaticancity: "VA", holysee: "VA",
};

const BASE_LANGS = ["fr", "en"] as const;
const namesByLang = new Map<string, Map<string, string>>();

function displayNames(lang: string): Intl.DisplayNames | null {
  try {
    return new Intl.DisplayNames([lang], { type: "region", fallback: "none" });
  } catch {
    return null;
  }
}

/** Squashed name to alpha-2, for one language. */
function names(lang: string): Map<string, string> {
  let m = namesByLang.get(lang);
  if (m) return m;
  m = new Map();
  const dn = displayNames(lang);
  if (dn) {
    for (const code of ALPHA2) {
      let name: string | undefined;
      try {
        name = dn.of(code);
      } catch {
        name = undefined;
      }
      if (!name || name === code) continue;
      m.set(squash(name), code);
      // "Saint-Martin (partie française)": the bare name too, unless taken.
      const bare = squash(name.replace(/\([^)]*\)/g, " "));
      if (bare !== "" && !m.has(bare)) m.set(bare, code);
    }
  }
  namesByLang.set(lang, m);
  return m;
}

/** Languages to read names in: the page's first, then French and English. */
export function nameLangs(pageLang?: string | null): string[] {
  const p = (pageLang ?? "").toLowerCase().split(/[-_]/)[0] ?? "";
  return [...new Set([...(p && /^[a-z]{2,3}$/.test(p) ? [p] : []), ...BASE_LANGS])];
}

function resolveOnce(raw: string, langs: readonly string[]): string | null {
  const t = raw.trim();
  if (t === "") return null;
  if (/^[A-Za-z]{2}$/.test(t)) {
    const c = t.toUpperCase();
    if (ALPHA2.has(c)) return c;
    return ALIASES[c.toLowerCase()] ?? null;
  }
  if (/^[A-Za-z]{3}$/.test(t)) {
    const c = ALPHA3.get(t.toUpperCase());
    if (c) return c;
  }
  if (/^\d{1,3}$/.test(t)) return NUMERIC.get(Number(t)) ?? null;
  const key = squash(t);
  if (key === "") return null;
  for (const lang of langs) {
    const c = names(lang).get(key);
    if (c) return c;
  }
  const alias = ALIASES[key];
  return alias ? alias : null;
}

/**
 * Alpha-2 code of `raw` (a code, a number or a name in `langs`), or null.
 * A parenthesised part ("France (+33)") and leading symbols (a flag) are
 * ignored on a second try.
 */
export function resolveCountry(raw: string, langs: readonly string[] = BASE_LANGS): string | null {
  const ls = langs.length > 0 ? langs : BASE_LANGS;
  const direct = resolveOnce(raw, ls);
  if (direct) return direct;
  const bare = raw.replace(/\([^)]*\)|\[[^\]]*\]/g, " ").replace(/^[^\p{L}\p{N}]+/u, "");
  return bare !== raw ? resolveOnce(bare, ls) : null;
}

/**
 * Alpha-2 code of an option's `value`: as `resolveCountry`, except that a
 * number counts as an ISO numeric code only with exactly 3 digits ("004",
 * "250"); any other number is the site's own id ("4", "36"), not a country.
 */
export function resolveCountryValue(value: string, langs: readonly string[] = BASE_LANGS): string | null {
  const t = value.trim();
  if (/^\d+$/.test(t) && !/^\d{3}$/.test(t)) return null;
  return resolveCountry(t, langs);
}

/** The name of `code` in `lang` (English when the language has none). */
export function countryName(code: string, lang: string): string {
  for (const l of [lang, "en"]) {
    const dn = displayNames(l);
    try {
      const n = dn?.of(code);
      if (n && n !== code) return n;
    } catch {
      // Not a region code this engine knows.
    }
  }
  return code;
}
