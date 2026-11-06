// @vitest-environment node
// Lab relying party checks: TOTP (RFC 6238 appendix B, SHA-1 vectors, one
// period of tolerance) and the comparison of posted card / identity fields
// with the fictional values of the vault fixture; signup passwords must look
// generated; under a site policy (max length, no special) the check adapts.
import { describe, expect, it } from "vitest";
import { totp } from "../../e2e/server.ts";
import patternsJson from "../../lab/corpus/patterns.json";
import type { Patterns } from "../../lab/corpus/types.ts";
import { generate } from "../../lab/gen/generate.ts";
import { CIVILITY_OF, CIVILITY_OPTIONS, DEMONYMS } from "../../lab/gen/forms-lexicon.ts";
import type { FieldSpec, Site } from "../../lab/gen/model.ts";
import { expectedValues, looksGenerated, matches, totpOk, wrongFields } from "../../lab/server/rp.ts";

// base32("12345678901234567890"), the SHA-1 secret of RFC 6238 appendix B.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const world = generate("rp-test", { sites: 10, patterns: patternsJson as unknown as Patterns });
const flow = (f: Site["flow"]) => world.sites.find((s) => s.flow === f)!;

describe("totpOk", () => {
  it("rfc6238_sha1_vectors", () => {
    expect(totpOk(RFC_SECRET, "287082", 59_000)).toBe(true);
    expect(totpOk(RFC_SECRET, "081804", 1_111_111_109_000)).toBe(true);
    expect(totpOk(RFC_SECRET, "081805", 1_111_111_109_000)).toBe(false);
    expect(totpOk(RFC_SECRET, " 287 082 ", 59_000)).toBe(true);
  });
  it("accepts_previous_period", () => {
    const now = 1_700_000_015_000;
    const previous = totp(RFC_SECRET, now - 30_000);
    expect(previous).not.toBe(totp(RFC_SECRET, now));
    expect(totpOk(RFC_SECRET, previous, now)).toBe(true);
    expect(totpOk(RFC_SECRET, totp(RFC_SECRET, now + 30_000), now)).toBe(true);
  });
  it("rejects_two_periods_ago", () => {
    const now = 1_700_000_015_000;
    const old = totp(RFC_SECRET, now - 60_000);
    expect([-30_000, 0, 30_000].map((d) => totp(RFC_SECRET, now + d))).not.toContain(old);
    expect(totpOk(RFC_SECRET, old, now)).toBe(false);
  });
});

describe("wrongFields", () => {
  it("card_values_normalized", () => {
    const site = flow("checkout_card");
    const exp = expectedValues(world, site);
    const body: Record<string, string> = {};
    for (const f of site.fields) {
      if (f.role === "cc_number") body[f.name] = exp.cc_number!.replace(/\s/g, "");
      else if (f.role === "cc_exp") body[f.name] = exp.cc_exp!.replace(/^(\d\d)\/\d\d(\d\d)$/, "$1 / $2");
      else if (f.role === "cc_exp_month") body[f.name] = exp.cc_exp!.slice(0, 2);
      else if (f.role === "cc_exp_year") body[f.name] = exp.cc_exp!.slice(3);
      else body[f.name] = ` ${exp[f.role]} `;
    }
    expect(wrongFields(world, site, body)).toEqual([]);
    const csc = site.fields.find((f) => f.role === "cc_csc")!;
    expect(wrongFields(world, site, { ...body, [csc.name]: "000" })).toEqual([csc.name]);
  });
  it("identity_values_and_missing_field", () => {
    const site = flow("identity");
    const exp = expectedValues(world, site);
    const body: Record<string, string> = {};
    for (const f of site.fields) body[f.name] = f.role === "tel" ? exp.tel!.replace(/\s/g, "") : exp[f.role]!;
    expect(wrongFields(world, site, body)).toEqual([]);
    const email = site.fields.find((f) => f.role === "email")!;
    const { [email.name]: _drop, ...rest } = body;
    expect(wrongFields(world, site, rest)).toEqual([email.name]);
  });
});

describe("looksGenerated", () => {
  it("length_and_classes", () => {
    expect(looksGenerated("Kp4-vX9m!tQz")).toBe(true);
    expect(looksGenerated("abcdefgh1234")).toBe(false); // two classes
    expect(looksGenerated("Ab1-xyz")).toBe(false); // too short
    expect(looksGenerated("ABCDEFGH123!")).toBe(true); // upper, digit, symbol
    expect(looksGenerated("")).toBe(false);
  });

  it("looksGenerated with a policy", () => {
    expect(looksGenerated("Kp4mvXtQzr", { max: 10, via: ["attributes"] })).toBe(true); // 10 chars, the policy's maximum
    expect(looksGenerated("Kp4mvXtQzr")).toBe(false);
    expect(looksGenerated("abcdefgh1234", { noSpecial: true, via: ["hints"] })).toBe(false);
    expect(looksGenerated("Abcdefgh1234", { noSpecial: true, via: ["hints"] })).toBe(true); // lower, upper, digit
    expect(looksGenerated("ABCDEFGH12!?", { noSpecial: true, via: ["hints"] })).toBe(false); // special does not count
  });
});

const CIV = new Map(Object.values(CIVILITY_OPTIONS).flat().map(([l, c]) => [l, c]));

describe("forms flows (generator version 4)", () => {
  const fw = generate("rp-forms", { sites: 400, patterns: patternsJson as unknown as Patterns });
  interface Item { type: string; title: string; fields: Record<string, string> }
  const items = fw.fixture.items as Item[];
  const item = (title: string | undefined) => items.find((i) => i.title === title)!;
  const travel = fw.sites.filter((s) => s.flow === "travel_booking");
  const twoNames = travel.find((s) => item(s.forms!.passportTitle).fields.first_names!.includes(" "))!;
  const withLoyalty = travel.find((s) => s.forms!.loyaltyTitle)!;
  const askedNoLoyalty = travel.find((s) => !s.forms!.loyaltyTitle && s.fields.some((f) => f.role === "loyalty_number"))!;
  const multi = travel.find((s) => s.fields.some((f) => (f.person ?? 0) > 0))!;
  const hiddenShip = fw.sites.find((s) => s.flow === "company_b2b" && s.forms!.shippingSame)!;
  const shownShip = fw.sites.find((s) => s.flow === "company_b2b" && s.forms!.shippingSame === false)!;
  const admin = fw.sites.find((s) => s.flow === "admin_identity" && s.fields.some((f) => f.role === "birth_country"))!;
  const rental = fw.sites.find((s) => s.flow === "car_rental")!;
  const fmt = (iso: string, format: string) => format.replace("YYYY", iso.slice(0, 4)).replace("MM", iso.slice(5, 7)).replace("DD", iso.slice(8, 10));

  /** What a user who knows the vault would post in each field, written the way the field asks (lab-independent formatting). */
  function rightBody(s: Site): Record<string, string> {
    const want = expectedValues(fw, s);
    const body: Record<string, string> = {};
    for (const f of s.fields) {
      if ((f.person ?? 0) > 0) { body[f.name] = "Typed by the user"; continue; }
      if (f.block === "shipping" && s.forms?.shippingSame) { body[f.name] = ""; continue; }
      const v = want[f.role] ?? "";
      const d = f.render?.date;
      const c = f.render?.choice;
      if (v === "") body[f.name] = "";
      else if (d?.kind === "text") body[f.name] = fmt(v, d.format);
      else if (d?.kind === "part") body[f.name] = String(Number(d.part === "day" ? v.slice(8) : d.part === "month" ? v.slice(5, 7) : v.slice(0, 4)));
      else if (c && c.kind !== "text" && f.role === "honorific") body[f.name] = c.options.find((o) => CIV.get(o.label) === CIVILITY_OF[v])!.value;
      else if (c && c.kind !== "text" && f.role === "sex") body[f.name] = c.options[v === "Féminin" ? 1 : 0]!.value;
      else if (c && c.kind === "select") body[f.name] = c.options.find((o) => o.value === v || new Intl.DisplayNames([s.lang], { type: "region" }).of(v) === o.label
        || Object.values(DEMONYMS).some((d) => (d as Record<string, string[]>)[v]?.includes(o.label)))!.value;
      else body[f.name] = v;
    }
    return body;
  }

  it("expected values: passport names over identity names, documents, loyalty, company ids, work phone", () => {
    const want = expectedValues(fw, twoNames);
    const p = item(twoNames.forms!.passportTitle).fields;
    expect(want.given_name).toBe(p.first_names);
    expect(want.family_name).toBe(p.last_name);
    expect(want.passport_number).toBe(p.number);
    expect(want.passport_expiry).toBe(p.expiry);
    expect(want.passport_issuing_country).toBe(p.issuing_country);
    expect(want.birth_country).toBe("");
    expect(expectedValues(fw, withLoyalty).loyalty_number).toBe(item(withLoyalty.forms!.loyaltyTitle).fields.member_number);
    expect(expectedValues(fw, askedNoLoyalty).loyalty_number).toBe("");
    const l = item(rental.forms!.licenseTitle).fields;
    const r = expectedValues(fw, rental);
    expect([r.license_number, r.license_expiry, r.license_issue_date, r.license_issuing_country]).toEqual([l.number, l.expiry, l.issued_on, l.country]);
    const c = expectedValues(fw, hiddenShip);
    const id = item(hiddenShip.identityTitle).fields;
    expect([c.vat_number, c.company_id, c.tel_work, c.job_title]).toEqual([hiddenShip.forms!.vatNumber, hiddenShip.forms!.companyId, id.work_phone, id.job_title]);
    expect(expectedValues(fw, admin).bday_year).toBe(item(admin.identityTitle).fields.birth_date);
  });

  it("a form filled as the vault says passes; passengers 2 and later must be typed", () => {
    for (const s of [twoNames, withLoyalty, askedNoLoyalty, multi, hiddenShip, shownShip, admin, rental]) {
      expect(wrongFields(fw, s, rightBody(s)), `${s.index} ${s.flow}`).toEqual([]);
    }
    const p2 = multi.fields.find((f) => f.person === 1)!;
    expect(wrongFields(fw, multi, { ...rightBody(multi), [p2.name]: "" })).toEqual([p2.name]);
  });

  it("the hidden shipping block, the birth country and a loyalty number the vault lacks must stay empty", () => {
    const ship = hiddenShip.fields.find((f) => f.block === "shipping")!;
    expect(wrongFields(fw, hiddenShip, { ...rightBody(hiddenShip), [ship.name]: "1 rue X" })).toEqual([ship.name]);
    const bc = admin.fields.find((f) => f.role === "birth_country")!;
    expect(wrongFields(fw, admin, { ...rightBody(admin), [bc.name]: "FR" })).toEqual([bc.name]);
    const ln = askedNoLoyalty.fields.find((f) => f.role === "loyalty_number")!;
    expect(wrongFields(fw, askedNoLoyalty, { ...rightBody(askedNoLoyalty), [ln.name]: "123456789" })).toEqual([ln.name]);
    // A shown shipping block gets the billing address.
    const shown = shownShip.fields.find((f) => f.block === "shipping" && f.role === "city")!;
    expect(wrongFields(fw, shownShip, { ...rightBody(shownShip), [shown.name]: "" })).toEqual([shown.name]);
  });

  it("dates match in the rendered format only", () => {
    const at = (render: NonNullable<FieldSpec["render"]>["date"]) => ({ role: "passport_expiry" as const, name: "x", id: "x", label: "x", type: "text", render: { date: render } });
    const iso = "2031-04-07";
    expect(matches("passport_expiry", "2031-04-07", iso, "fr", at({ kind: "input" }))).toBe(true);
    expect(matches("passport_expiry", "07/04/2031", iso, "fr", at({ kind: "input" }))).toBe(false);
    expect(matches("passport_expiry", "07/04/2031", iso, "fr", at({ kind: "text", format: "DD/MM/YYYY", placeholder: true }))).toBe(true);
    expect(matches("passport_expiry", "04/07/2031", iso, "fr", at({ kind: "text", format: "DD/MM/YYYY", placeholder: true }))).toBe(false);
    expect(matches("passport_expiry", "04/07/2031", iso, "en", at({ kind: "text", format: "MM/DD/YYYY", placeholder: false }))).toBe(true);
    expect(matches("passport_expiry", "07.04.2031", iso, "de", at({ kind: "text", format: "DD.MM.YYYY", placeholder: true }))).toBe(true);
    const part = (p: "day" | "month" | "year") => at({ kind: "part", part: p, group: "g", select: true });
    expect(matches("passport_expiry", "7", iso, "fr", part("day"))).toBe(true);
    expect(matches("passport_expiry", "07", iso, "fr", part("day"))).toBe(true);
    expect(matches("passport_expiry", "04", iso, "fr", part("month"))).toBe(true);
    expect(matches("passport_expiry", "2031", iso, "fr", part("year"))).toBe(true);
    expect(matches("passport_expiry", "31", iso, "fr", part("year"))).toBe(false);
    expect(matches("bday_month", "4", "1990-04-12", "fr", { ...part("month"), role: "bday_month" })).toBe(true);
  });

  it("civility and sex by the lab's canonical table, countries by code, names and demonyms, ids without separators", () => {
    const choice = (options: [string, string][]) => ({ role: "honorific" as const, name: "c", id: "c", label: "c", type: "select",
      render: { choice: { kind: "select" as const, options: options.map(([label, value]) => ({ label, value })) } } });
    const civ = choice([["M.", "1"], ["Mme", "2"], ["Mlle", "3"]]);
    expect(matches("honorific", "2", "Mme", "fr", civ)).toBe(true);
    expect(matches("honorific", "3", "Mme", "fr", civ)).toBe(false);
    expect(matches("honorific", "1", "M.", "fr", civ)).toBe(true);
    expect(matches("honorific", "Ms", "Ms", "en")).toBe(true);
    expect(matches("honorific", "Mrs", "Ms", "en")).toBe(false);
    const sex = { ...choice([["Homme", "H"], ["Femme", "F"]]), role: "sex" as const };
    expect(matches("sex", "F", "Féminin", "fr", sex)).toBe(true);
    expect(matches("sex", "H", "Féminin", "fr", sex)).toBe(false);
    expect(matches("sex", "Male", "Masculin", "en")).toBe(true);
    for (const v of ["FR", "France", "Frankreich", "Française", "French", "Francés"]) expect(matches("nationality", v, "FR", "de"), v).toBe(true);
    expect(matches("nationality", "Belgique", "FR", "fr")).toBe(false);
    expect(matches("passport_issuing_country", "Allemagne", "DE", "fr")).toBe(true);
    expect(matches("vat_number", "fr 12.345-678 901", "FR12345678901", "fr")).toBe(true);
    expect(matches("company_id", "123 456 789 00012", "12345678900012", "fr")).toBe(true);
    expect(matches("passport_number", "12AB34567", "12AB34568", "fr")).toBe(false);
  });
});
