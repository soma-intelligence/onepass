// The four forms flows of the autofill lab (generator version 4, spec 11.1 of
// docs/superpowers/specs/2026-11-06-forms-coverage-design.md): travel booking
// (passengers, passport, loyalty), company B2B (work fields, VAT and company
// ids, billing and shipping), car rental (driver license) and admin identity
// (civility, birth name, sex, birth place, nationality). For one site: the
// fields with their persons, blocks and renderings (dates, choices), the
// site's forms data, and the vault items (identity, passport or license,
// loyalty program, decoy passport of another person). Every draw comes from
// forks of the site's Rng; labels from forms-lexicon.ts for the forms roles,
// from the corpus (through `core`) for the roles of version 3.
import { address, person, type Person } from "./data.ts";
import { countryOfLang, formsIdentity, licenseOf, loyaltyNumber, passportOf, type Holder } from "./forms-data.ts";
import {
  blockWord, CIVILITY_OF, CIVILITY_OPTIONS, dateFormatOf, DEMONYMS, formsLabels, isFormsLang, LIST_COUNTRIES, monthNames,
  SEX_OPTIONS, type FormsLang,
} from "./forms-lexicon.ts";
import type {
  Block, ChoiceOption, ChoiceRender, DatePart, DateRender, FieldSpec, FlowId, FormsRole, LabRole, Lang, Role, SiteForms, TraitId,
} from "./model.ts";
import type { Rng } from "./rng.ts";

export const FORMS_FLOWS: readonly FlowId[] = ["travel_booking", "company_b2b", "car_rental", "admin_identity"];
export const isFormsFlow = (f: FlowId): boolean => FORMS_FLOWS.includes(f);

/**
 * Whether the vault template has the Identity work fields `vat_number` and `company_registration` (plan Task 5):
 * until then the fixture leaves them out (the native host refuses unknown fields) and the site keeps them in `forms`.
 */
export const VAULT_COMPANY_IDS = false;

/** Roles of version 3 the forms flows reuse, labelled from the corpus. */
export interface CoreLabel { label: string; token: string; autocompleteRate: number }
export type CoreLabeler = (r: Rng, role: Role) => CoreLabel;

export interface FormsSiteBase { host: string; brand: string; lang: Lang; labelLang: Lang; traits: TraitId[] }
export interface FormsBuild { fields: FieldSpec[]; forms: SiteForms; identityTitle: string; items: unknown[] }

const VAULT = "Lab";
const DATE_ROLES = new Set<LabRole>(["birth_date", "passport_issue_date", "passport_expiry", "license_issue_date", "license_expiry"]);
const PART_ROLE: Record<DatePart, FormsRole> = { day: "bday_day", month: "bday_month", year: "bday_year" };

const FORMS_TOKENS: Record<FormsRole, string[]> = {
  honorific: ["title", "civility", "salutation", "civilite"], additional_name: ["middle_name", "middlename", "second_name"],
  birth_name: ["birth_name", "maiden_name", "nom_naissance"], sex: ["sex", "gender", "sexe"],
  birth_place: ["birth_place", "birthplace", "lieu_naissance"], birth_country: ["birth_country", "country_of_birth", "pays_naissance"],
  nationality: ["nationality", "nationalite", "citizenship"], bday_day: ["dob_day", "birth_day", "jour"],
  bday_month: ["dob_month", "birth_month", "mois"], bday_year: ["dob_year", "birth_year", "annee"],
  passport_number: ["passport", "passport_number", "passportNo", "doc_number"],
  passport_issuing_country: ["passport_country", "issuing_country", "doc_country"],
  passport_issue_date: ["passport_issue", "issue_date", "doc_issued"], passport_expiry: ["passport_expiry", "expiry_date", "doc_expiry"],
  loyalty_number: ["ffp", "frequent_flyer", "loyalty", "membership_no"], license_number: ["license", "licence_number", "dl_number", "permis"],
  license_issuing_country: ["license_country", "dl_country"], license_issue_date: ["license_issued", "dl_issue_date"],
  license_expiry: ["license_expiry", "dl_expiry"], job_title: ["job_title", "position", "jobtitle"],
  department: ["department", "dept", "service"], vat_number: ["vat", "vat_number", "tva", "ustid"],
  company_id: ["siret", "company_number", "registration", "kvk"], website: ["website", "url", "homepage"],
  tel_work: ["work_phone", "office_phone", "tel_pro"],
};
/** HTML autocomplete tokens of the forms roles that have one (spec section 3). */
const FORMS_AUTOCOMPLETE: Partial<Record<LabRole, string>> = {
  honorific: "honorific-prefix", additional_name: "additional-name", sex: "sex", bday_day: "bday-day", bday_month: "bday-month",
  bday_year: "bday-year", job_title: "organization-title", website: "url", tel_work: "work tel",
  given_name: "given-name", family_name: "family-name", email: "email", tel: "tel", birth_date: "bday", organization: "organization",
  address_line1: "address-line1", postal_code: "postal-code", city: "address-level2", country: "country",
};
const CORE_TYPE: Partial<Record<LabRole, string>> = { email: "email", tel: "tel", tel_work: "tel" };
/** Year range of the options of a date's year list, by date role. */
const YEARS: Record<string, [number, number]> = {
  birth_date: [1930, 2010], passport_issue_date: [2005, 2026], license_issue_date: [1990, 2026],
  passport_expiry: [2026, 2045], license_expiry: [2026, 2045],
};

type DateKind = "input" | "text_hint" | "text_bare" | "parts";
type ChoiceKind = "select" | "radio";
type ValueStyle = "label" | "code" | "letter";
type CountryList = "names" | "demonyms" | "text";
type NameStyle = "brackets" | "underscore" | "dash";

interface Shape {
  dateKind: DateKind; months: "number" | "name"; pad: boolean; partsSelect: boolean;
  choice: ChoiceKind; values: ValueStyle; nationality: CountryList; issuing: "names" | "text"; nameStyle: NameStyle;
}

function drawShape(r: Rng): Shape {
  return {
    dateKind: r.weighted<DateKind>([["input", 30], ["text_hint", 25], ["text_bare", 15], ["parts", 30]]),
    months: r.chance(0.5) ? "name" : "number",
    pad: r.chance(0.5),
    partsSelect: r.chance(0.8),
    choice: r.chance(0.6) ? "select" : "radio",
    values: r.weighted<ValueStyle>([["label", 50], ["code", 30], ["letter", 20]]),
    nationality: r.weighted<CountryList>([["names", 60], ["demonyms", 20], ["text", 20]]),
    issuing: r.chance(0.8) ? "names" : "text",
    nameStyle: r.pick<NameStyle>(["brackets", "underscore", "dash"]),
  };
}

interface Slot { role: LabRole; person?: number; block?: Block }

const ADDRESS: LabRole[] = ["address_line1", "postal_code", "city", "country"];

/** The roles of a flow in page order, with their persons and blocks. */
function slotsOf(r: Rng, flow: FlowId, forms: SiteForms): Slot[] {
  const opt = (p: number, role: LabRole): LabRole[] => (r.chance(p) ? [role] : []);
  switch (flow) {
    case "travel_booking": {
      const traveller: LabRole[] = [...opt(0.7, "honorific"), "given_name", "family_name", "birth_date", ...opt(0.6, "nationality"),
        ...opt(0.4, "sex"), "passport_number", ...opt(0.6, "passport_issuing_country"), ...opt(0.3, "passport_issue_date"),
        "passport_expiry", ...opt(0.5, "loyalty_number")];
      const extra = r.chance(0.4) ? r.int(1, 2) : 0;
      const out: Slot[] = [{ role: "email", block: "contact" }, { role: "tel", block: "contact" }];
      for (let p = 0; p <= extra; p++) for (const role of traveller) out.push({ role, person: p, block: "passenger" });
      return out;
    }
    case "company_b2b": {
      const out: Slot[] = (["given_name", "family_name", "email", "tel_work", "organization"] as LabRole[]).map((role) => ({ role }));
      for (const [p, role] of [[0.7, "job_title"], [0.4, "department"], [0.8, "vat_number"], [0.6, "company_id"], [0.3, "website"]] as const) {
        if (r.chance(p)) out.push({ role });
      }
      for (const role of ADDRESS) out.push({ role, block: "billing" });
      if (r.chance(0.5)) {
        forms.shippingSame = r.chance(0.5);
        for (const role of ADDRESS) out.push({ role, block: "shipping" });
      }
      return out;
    }
    case "car_rental":
      return ([...opt(0.5, "honorific"), "given_name", "family_name", "birth_date", "email", "tel", "license_number",
        ...opt(0.6, "license_issuing_country"), ...opt(0.7, "license_issue_date"), ...opt(0.4, "license_expiry")] as LabRole[])
        .map((role) => ({ role }));
    case "admin_identity":
      return ([
        "honorific", "given_name", ...opt(0.3, "additional_name"), "family_name", ...opt(0.6, "birth_name"), ...opt(0.7, "sex"),
        "birth_date", "birth_place", ...opt(0.4, "birth_country"), "nationality", ...(r.chance(0.6) ? ADDRESS : []),
      ] as LabRole[]).map((role) => ({ role }));
    default:
      throw new Error(`forms: ${flow} is not a forms flow`);
  }
}

const isForms = (role: LabRole): role is FormsRole => role in FORMS_TOKENS;
const SAFE = /[^a-zA-Z0-9_-]/g;

function randomToken(r: Rng): string {
  const abc = "abcdefghijklmnopqrstuvwxyz";
  return r.pick([...abc]) + Array.from({ length: 7 }, () => r.pick([...`${abc}0123456789`])).join("");
}

function unique(base: string, taken: Set<string>): string {
  let name = base;
  for (let k = 2; taken.has(name); k++) name = `${base}_${k}`;
  taken.add(name);
  return name;
}

const flang = (lang: Lang): FormsLang => (isFormsLang(lang) ? lang : "en");

function countryName(code: string, lang: Lang): string {
  return new Intl.DisplayNames([lang], { type: "region" }).of(code) ?? code;
}

function valueOf(style: ValueStyle, label: string, k: number, letter: string): string {
  return style === "label" ? label : style === "code" ? String(k + 1) : letter;
}

function civilityChoice(r: Rng, kind: ChoiceKind, values: ValueStyle, lang: Lang, want: string): ChoiceRender {
  const all = CIVILITY_OPTIONS[flang(lang)];
  const shown = all.filter((o, k) => k < 2 || o[1] === want || r.chance(0.5));
  return { kind, options: shown.map(([label, canon], k) => ({ label, value: valueOf(values, label, k, canon.toUpperCase()) })) };
}

function sexChoice(r: Rng, kind: ChoiceKind, values: ValueStyle, lang: Lang): ChoiceRender {
  const all = SEX_OPTIONS[flang(lang)];
  const shown = all.filter((_, k) => k < 2 || r.chance(0.4));
  return { kind, options: shown.map(([label, canon], k) => ({ label, value: valueOf(values, label, k, label.charAt(0).toUpperCase() || canon) })) };
}

function countryChoice(r: Rng, list: CountryList, lang: Lang, feminine: boolean): ChoiceRender {
  if (list === "text") return { kind: "text" };
  const codes = r.chance(0.5);
  const options: ChoiceOption[] = LIST_COUNTRIES.map((code) => {
    const label = list === "demonyms" ? DEMONYMS[flang(lang)][code][feminine ? 1 : 0] : countryName(code, lang);
    return { label, value: codes ? code : label };
  });
  return { kind: "select", options };
}

/** Builds the forms site of `flow`; `holders` (full names of document holders so far) keeps them unique in the world. */
export function buildForms(r: Rng, flow: FlowId, base: FormsSiteBase, core: CoreLabeler, holders: Set<string>): FormsBuild {
  const { lang } = base;
  const rv = r.fork("forms-vault");
  const who = uniquePerson(rv, lang, holders);
  const id = formsIdentity(rv, who, lang, base.brand);
  const forms: SiteForms = {};
  const shape = drawShape(r.fork("forms-shape"));
  const slots = slotsOf(r.fork("forms-slots"), flow, forms);
  const fields = buildFields(r.fork("forms-fields"), slots, shape, base, core, id.sex === "Féminin", CIVILITY_OF[id.honorific] ?? "mr");
  if (shape.dateKind === "text_hint" || shape.dateKind === "text_bare") forms.dateFormat = dateFormatOf(lang);

  const country = countryOfLang(lang);
  const holder: Holder = { given: who.given, family: who.family, birthDate: who.birthDate, sex: id.sex, birthPlace: id.birthPlace, nationality: id.nationality };
  const a = address(rv, lang);
  const identityTitle = `${who.given} ${who.family} (${base.brand})`;
  const identity: Record<string, unknown> = {
    honorific: id.honorific, first_name: who.given, middle_name: id.middleName, last_name: who.family, birth_name: id.birthName,
    sex: id.sex, birth_date: who.birthDate, birth_place: id.birthPlace, nationality: id.nationality,
    address: { line1: a.line1, line2: a.line2, city: a.city, postal_code: a.postalCode, region: a.region, country: a.country },
    mobile_phone: who.phone, work_phone: id.workPhone, email: who.email,
    company: who.company, job_title: id.jobTitle, department: id.department, website: id.website,
    ...(VAULT_COMPANY_IDS ? { vat_number: id.vatNumber, company_registration: id.companyRegistration } : {}),
  };
  forms.vatNumber = id.vatNumber;
  forms.companyId = id.companyRegistration;
  const items: unknown[] = [{ type: "identity", title: identityTitle, vault: VAULT, fields: identity }];
  const rd = r.fork("forms-docs");
  if (flow === "travel_booking") {
    const p = passportOf(rd, holder, country);
    forms.passportTitle = `Passeport ${who.given} ${who.family}`;
    items.push(passportItem(forms.passportTitle, p));
    if (fields.some((f) => f.role === "loyalty_number") && rd.chance(0.7)) {
      forms.loyaltyTitle = `${base.brand} Miles`;
      items.push({
        type: "reward_program", title: forms.loyaltyTitle, vault: VAULT, urls: [{ url: `https://${base.host}`, rule: "domain" }],
        fields: { company: forms.loyaltyTitle, member_number: loyaltyNumber(rd), member_name: `${who.given} ${who.family}` },
      });
    }
    if (rd.chance(0.3)) {
      const other = uniquePerson(rd.fork("decoy"), lang, holders);
      const otherId = formsIdentity(rd.fork("decoy-id"), other, lang, base.brand);
      const decoy = passportOf(rd.fork("decoy-passport"), {
        given: other.given, family: other.family, birthDate: other.birthDate, sex: otherId.sex, birthPlace: otherId.birthPlace,
        nationality: otherId.nationality,
      }, country);
      forms.decoyPassportTitle = `Passeport ${other.given} ${other.family}`;
      items.push(passportItem(forms.decoyPassportTitle, decoy));
    }
  } else if (flow === "car_rental") {
    const l = licenseOf(rd, holder, country);
    forms.licenseTitle = `Permis ${who.given} ${who.family}`;
    items.push({
      type: "driver_license", title: forms.licenseTitle, vault: VAULT,
      fields: { full_name: l.fullName, number: l.number, country: l.country, birth_date: l.birthDate, issued_on: l.issuedOn, expiry: l.expiry },
    });
  }
  return { fields, forms, identityTitle, items };
}

function passportItem(title: string, p: ReturnType<typeof passportOf>): unknown {
  return {
    type: "passport", title, vault: VAULT,
    fields: {
      issuing_country: p.issuingCountry, number: p.number, expiry: p.expiry, last_name: p.lastName, first_names: p.firstNames,
      nationality: p.nationality, birth_date: p.birthDate, birth_place: p.birthPlace, sex: p.sex, issued_on: p.issuedOn,
    },
  };
}

/** A person of `lang` whose full name no document holder of the world has yet (added to `holders`). */
function uniquePerson(r: Rng, lang: Lang, holders: Set<string>): Person {
  for (let k = 0; ; k++) {
    const who = person(k === 0 ? r : r.fork(`retry:${k}`), lang);
    const name = `${who.given} ${who.family}`;
    if (!holders.has(name) || k > 200) {
      holders.add(name);
      return who;
    }
  }
}

function buildFields(r: Rng, slots: Slot[], shape: Shape, base: FormsSiteBase, core: CoreLabeler, feminine: boolean, civility: string): FieldSpec[] {
  const { lang, labelLang, traits } = base;
  const obfuscated = traits.includes("obfuscated_names");
  const noAuto = traits.includes("no_autocomplete");
  const names = new Set<string>();
  const ids = new Set<string>();
  const fields: FieldSpec[] = [];
  // One label per role, the same for every passenger (a page repeats its block).
  const labels = new Map<LabRole, CoreLabel>();
  const labelOf = (role: LabRole): CoreLabel => {
    let l = labels.get(role);
    if (!l) {
      if (isForms(role)) {
        l = { label: r.pick(formsLabels(role, labelLang)), token: r.pick(FORMS_TOKENS[role]), autocompleteRate: 0.5 };
      } else {
        l = core(r, role as Role);
      }
      labels.set(role, l);
    }
    return l;
  };
  // Choices drawn once per role: the passengers' blocks repeat the same lists.
  const choices = new Map<LabRole, ChoiceRender>();
  const choiceOf = (role: LabRole): ChoiceRender | undefined => {
    if (choices.has(role)) return choices.get(role);
    let c: ChoiceRender | undefined;
    if (role === "honorific") c = civilityChoice(r, shape.choice, shape.values, lang, civility);
    else if (role === "sex") c = sexChoice(r, shape.choice, shape.values, lang);
    else if (role === "nationality") c = countryChoice(r, shape.nationality, lang, feminine && r.chance(0.5));
    else if (role === "passport_issuing_country" || role === "license_issuing_country" || role === "birth_country") {
      c = countryChoice(r, shape.issuing, lang, false);
    }
    if (c) choices.set(role, c);
    return c;
  };
  const nameFor = (token: string, person: number | undefined, travel: boolean): string => {
    if (obfuscated) return unique(randomToken(r), names);
    if (!travel) return unique(token, names);
    const k = person ?? 0;
    const n = shape.nameStyle === "brackets" ? `passengers[${k}][${token}]` : shape.nameStyle === "underscore" ? `pax_${k + 1}_${token}` : `adult-${k + 1}-${token}`;
    return unique(n, names);
  };
  const add = (f: Omit<FieldSpec, "name" | "id"> & { token: string }, slot: Slot) => {
    const name = nameFor(f.token, slot.person, slot.block === "passenger");
    const id = unique(obfuscated ? randomToken(r) : name.replace(SAFE, "-"), ids);
    const { token: _t, ...rest } = f;
    const spec: FieldSpec = { ...rest, name, id };
    if (slot.person !== undefined) spec.person = slot.person;
    if (slot.block !== undefined) spec.block = slot.block;
    fields.push(spec);
  };
  for (const slot of slots) {
    const { role } = slot;
    const l = labelOf(role);
    const auto = (token: LabRole) => !noAuto && (slot.person ?? 0) === 0 && FORMS_AUTOCOMPLETE[token] !== undefined && r.chance(l.autocompleteRate)
      ? { autocomplete: FORMS_AUTOCOMPLETE[token] } : {};
    if (DATE_ROLES.has(role)) {
      if (shape.dateKind === "parts") {
        for (const part of ["day", "month", "year"] as DatePart[]) {
          const partRole = PART_ROLE[part];
          const pl = labelOf(partRole);
          const date: DateRender = { kind: "part", part, group: l.label, select: shape.partsSelect,
            ...(part === "month" ? { months: shape.months } : {}), ...(part !== "year" ? { pad: shape.pad } : {}) };
          add({
            role: role === "birth_date" ? partRole : role, label: pl.label, type: shape.partsSelect ? "select" : "text",
            token: `${l.token}_${part}`, render: { date }, ...(role === "birth_date" ? auto(partRole) : {}),
          }, slot);
        }
        continue;
      }
      const date: DateRender = shape.dateKind === "input" ? { kind: "input" }
        : { kind: "text", format: dateFormatOf(lang), placeholder: shape.dateKind === "text_hint" };
      add({ role, label: l.label, type: shape.dateKind === "input" ? "date" : "text", token: l.token, render: { date }, ...auto(role) }, slot);
      continue;
    }
    const choice = choiceOf(role);
    if (choice && choice.kind !== "text") {
      add({ role, label: l.label, type: choice.kind, token: l.token, render: { choice }, ...auto(role) }, slot);
      continue;
    }
    add({ role, label: l.label, type: CORE_TYPE[role] ?? "text", token: l.token, ...(choice ? { render: { choice } } : {}), ...auto(role) }, slot);
  }
  return fields;
}

/** The options of a date part list: days 1-31, months 1-12 (numbers or names in `lang`), years of the date's role. */
export function datePartOptions(role: LabRole, d: Extract<DateRender, { kind: "part" }>, lang: Lang): ChoiceOption[] {
  const two = (n: number) => (d.pad ? String(n).padStart(2, "0") : String(n));
  if (d.part === "day") return Array.from({ length: 31 }, (_, k) => ({ value: two(k + 1), label: two(k + 1) }));
  if (d.part === "month") {
    const names = monthNames(lang).full;
    return Array.from({ length: 12 }, (_, k) => ({ value: two(k + 1), label: d.months === "name" ? names[k]! : two(k + 1) }));
  }
  const [from, to] = YEARS[role.startsWith("bday") ? "birth_date" : role] ?? [1930, 2045];
  return Array.from({ length: to - from + 1 }, (_, k) => ({ value: String(from + k), label: String(from + k) }));
}

/** Legends of the blocks of a forms page, by "<person>|<block>" ("" when a group has none). */
export function blockLegends(fields: FieldSpec[], labelLang: Lang, passenger: (n: number) => string, flow: FlowId): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of fields) {
    const key = `${f.person ?? 0}|${f.block ?? ""}`;
    if (key in out) continue;
    switch (f.block) {
      case "passenger": out[key] = passenger((f.person ?? 0) + 1); break;
      case "contact": out[key] = blockWord(labelLang, "contact"); break;
      case "billing": out[key] = blockWord(labelLang, "billing"); break;
      case "shipping": out[key] = blockWord(labelLang, "shipping"); break;
      default: out[key] = flow === "car_rental" ? blockWord(labelLang, "driver") : flow === "company_b2b" ? blockWord(labelLang, "company") : "";
    }
  }
  return out;
}
