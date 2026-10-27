// Synthetic data of the autofill lab: fictional people, addresses, public
// test cards, passwords, TOTP secrets, P-256 passkeys and .test host names.
// Every value is drawn from the seeded Rng; nothing here is real.
import { domainToASCII } from "node:url";
import { p256 } from "@noble/curves/p256";
import type { Lang, Passkey } from "./model.ts";
import type { Rng } from "./rng.ts";

/** Card numbers published by payment providers for testing; never real cards. */
export const PUBLIC_TEST_CARDS = ["4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222", "378282246310005"];

const GIVEN = ["Alix", "Bastien", "Camille", "Dorian", "Elise", "Fabien", "Gaelle", "Hugo", "Ines", "Jules", "Katell", "Loris",
  "Maelys", "Nolan", "Oriane", "Paco", "Quitterie", "Romane", "Soren", "Tilda", "Ulysse", "Vianney", "Wendel", "Yanis", "Zelie",
  "Ansel", "Brielle", "Corwin", "Delphine", "Emeric"];
const FAMILY = ["Abrial", "Bellanger", "Corvasier", "Dumarest", "Esquerre", "Fontanil", "Guivarch", "Hautecoeur", "Isambert",
  "Jolibois", "Kervella", "Lamarque", "Montclar", "Noirclerc", "Orsenne", "Pellegarde", "Quenard", "Rossignac", "Saintrond",
  "Tavernel", "Ubertin", "Valcourt", "Wassermann", "Ybarnegaray", "Zellweg"];
const MAIL_DOMAINS = ["mail.test", "inbox.test", "example.com", "example.org"];
const COMPANIES = ["Nordlicht Studio", "Atelier Brume", "Cobalt Works", "Lumen Guild", "Verdant Labs", "Quartz Partners"];

const ADJECTIVES = ["amber", "brisk", "calm", "dusky", "eager", "fable", "gentle", "hollow", "ivory", "jolly", "keen", "lunar",
  "mellow", "nimble", "opal", "plush", "quiet", "rustic", "silver", "tidal", "umber", "vivid", "woven", "zesty", "bold", "coral",
  "dapper", "fern", "golden", "hazel", "indigo", "jade", "lofty", "misty", "noble", "olive", "polar", "rapid", "sunny", "tawny"];
const NOUNS = ["anchor", "beacon", "cedar", "delta", "ember", "falcon", "grove", "harbor", "island", "juniper", "kettle", "lantern",
  "meadow", "nectar", "orchard", "pebble", "quill", "river", "summit", "thicket", "upland", "valley", "willow", "yonder", "atlas",
  "badger", "canyon", "dune", "estuary", "fjord", "glade", "heron", "inlet", "lagoon", "marsh", "otter", "prairie", "ridge", "sparrow", "tundra"];

interface Locale { country: string; region: string; streets: string[]; cities: string[]; postal: (r: Rng) => string; phone: (r: Rng) => string }
const digits = (r: Rng, n: number) => Array.from({ length: n }, () => r.int(0, 9)).join("");
const LOCALES: Record<string, Locale> = {
  en: { country: "US", region: "OR", streets: ["Maple Lane", "Cedar Court", "Harbor Road", "Willow Way"], cities: ["Springfield", "Riverton", "Fairview"],
    postal: (r) => `97${digits(r, 3)}`, phone: (r) => `+1 555 01${digits(r, 2)}` },
  fr: { country: "FR", region: "Rhone", streets: ["rue des Tilleuls", "allee des Cerisiers", "chemin du Moulin", "place de la Fontaine"],
    cities: ["Lyon", "Valence", "Annecy"], postal: (r) => `69${digits(r, 3)}`, phone: (r) => `+33 6 00 ${digits(r, 2)} ${digits(r, 2)} ${digits(r, 2)}` },
  de: { country: "DE", region: "Bayern", streets: ["Lindenstrasse", "Ahornweg", "Bergstrasse", "Am Brunnen"], cities: ["Augsburg", "Regensburg", "Passau"],
    postal: (r) => `8${digits(r, 4)}`, phone: (r) => `+49 151 0000 ${digits(r, 3)}` },
  es: { country: "ES", region: "Valencia", streets: ["Calle Mayor", "Avenida del Puerto", "Calle de los Olivos", "Plaza del Sol"],
    cities: ["Valencia", "Alicante", "Castellon"], postal: (r) => `46${digits(r, 3)}`, phone: (r) => `+34 600 00 ${digits(r, 2)} ${digits(r, 2)}` },
};

export interface Person { given: string; family: string; email: string; phone: string; birthDate: string; company: string }
export interface Address { line1: string; line2: string; city: string; postalCode: string; region: string; country: string }
export interface Card { number: string; expMonth: number; expYear: number; cvc: string }

const ascii = (s: string) => s.toLowerCase().replace(/[^a-z]/g, "");

export function person(rng: Rng, lang: Lang = "en"): Person {
  const given = rng.pick(GIVEN);
  const family = rng.pick(FAMILY);
  const loc = LOCALES[lang] ?? LOCALES.en!;
  const month = String(rng.int(1, 12)).padStart(2, "0");
  const day = String(rng.int(1, 28)).padStart(2, "0");
  return {
    given, family,
    email: `${ascii(given)}.${ascii(family)}${rng.int(1, 99)}@${rng.pick(MAIL_DOMAINS)}`,
    phone: loc.phone(rng),
    birthDate: `${rng.int(1960, 2002)}-${month}-${day}`,
    company: rng.pick(COMPANIES),
  };
}

export function address(rng: Rng, lang: Lang): Address {
  const loc = LOCALES[lang] ?? LOCALES.en!;
  const street = rng.pick(loc.streets);
  const no = rng.int(1, 120);
  return {
    line1: lang === "de" || lang === "es" ? `${street} ${no}` : `${no} ${street}`,
    line2: rng.chance(0.3) ? `${rng.int(1, 9)}${rng.pick(["A", "B", "C"])}` : "",
    city: rng.pick(loc.cities), postalCode: loc.postal(rng), region: loc.region, country: loc.country,
  };
}

export function card(rng: Rng): Card {
  const number = rng.pick(PUBLIC_TEST_CARDS);
  const amex = number.length === 15;
  return { number, expMonth: rng.int(1, 12), expYear: rng.int(2028, 2033), cvc: digits(rng, amex ? 4 : 3) };
}

/** Groups a card number the way it is printed: 4-6-5 for 15 digits, else by 4. */
export function formatCardNumber(n: string): string {
  if (n.length === 15) return `${n.slice(0, 4)} ${n.slice(4, 10)} ${n.slice(10)}`;
  return n.replace(/(\d{4})(?=\d)/g, "$1 ");
}

const LOWER = "abcdefghijkmnpqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "-_.!@#%+=";

export function password(rng: Rng): string {
  const len = rng.int(16, 24);
  const classes = [LOWER, UPPER, DIGITS, SYMBOLS];
  const chars = classes.map((c) => rng.pick([...c]));
  const all = [...classes.join("")];
  while (chars.length < len) chars.push(rng.pick(all));
  return rng.shuffle(chars).join("");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function totpSecret(rng: Rng): string {
  return Array.from({ length: 32 }, () => rng.pick([...BASE32])).join("");
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

export function passkey(rng: Rng): Passkey {
  const n = p256.Point.Fn.ORDER;
  let d = BigInt(`0x${Buffer.from(rng.bytes(32)).toString("hex")}`) % n;
  if (d === 0n) d = 1n;
  const hex = d.toString(16).padStart(64, "0");
  const pub = p256.getPublicKey(new Uint8Array(Buffer.from(hex, "hex")), false);
  return { credentialId: b64url(rng.bytes(16)), d: hex, x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33, 65)) };
}

/**
 * A fresh "<word>-<word>-<n>.test" host, added to `used`. The word pair is
 * also reserved ("pair:<a>-<b>") so brands derived from it stay distinct
 * while pairs remain.
 */
export function hostName(rng: Rng, used: Set<string>): string {
  for (let attempt = 0; ; attempt++) {
    const a = rng.pick(ADJECTIVES);
    const b = rng.pick(NOUNS);
    const host = `${a}-${b}-${rng.int(1, 99)}.test`;
    if (used.has(host) || (attempt < 200 && used.has(`pair:${a}-${b}`))) continue;
    used.add(host);
    used.add(`pair:${a}-${b}`);
    return host;
  }
}

/** Invented two-word brand from a generated host: "amber-falcon-3.test" gives "Amber Falcon". */
export function brandOf(host: string): string {
  return host.split("-").slice(0, 2).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

const HOMOGLYPHS: Record<string, string> = { a: "а", e: "е", o: "о", c: "с", p: "р" };

/** One lookalike host of `host` by kind; null when the kind cannot apply (idn without a homoglyph letter). */
export function lookalikeHost(rng: Rng, host: string, kind: "suffix" | "typo" | "hyphen" | "idn"): string | null {
  const label = host.slice(0, -".test".length);
  if (kind === "suffix") return `${host}.evil.test`;
  if (kind === "hyphen") return `${label}-${rng.pick(["secure", "login", "account", "verify"])}.test`;
  if (kind === "typo") {
    const letters = [...label].map((c, i) => [c, i] as const).filter(([c, i]) => /[a-z]/.test(c) && /[a-z]/.test(label[i + 1] ?? ""));
    const [, i] = rng.pick(letters);
    if (label[i] === label[i + 1]) return `${label.slice(0, i)}${label.slice(i + 1)}.test`; // doubled letter: drop one
    return `${label.slice(0, i)}${label[i + 1]}${label[i]}${label.slice(i + 2)}.test`;   // swap two neighbours
  }
  const spots = [...label].map((c, i) => [c, i] as const).filter(([c]) => c in HOMOGLYPHS);
  if (spots.length === 0) return null;
  const [c, i] = rng.pick(spots);
  // domainToASCII returns "" when it cannot convert: no candidate then.
  return domainToASCII(`${label.slice(0, i)}${HOMOGLYPHS[c]}${label.slice(i + 1)}.test`) || null;
}
