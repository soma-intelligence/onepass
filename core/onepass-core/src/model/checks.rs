//! Format checks for sensitive field values: card numbers, IBAN, BIP39
//! recovery phrases, national identifiers and base32 secrets.
//!
//! Every function answers a yes or no question about its input and never
//! echoes it. Inputs that hold secrets are not logged or returned.

use std::sync::OnceLock;

use aws_lc_rs::digest;
use zeroize::Zeroizing;

/// Digits of `s` with spaces and hyphens ignored, or `None` if any other
/// character is present.
fn digits_only(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_digit(10).map(|d| d as u8))
        .collect()
}

fn luhn_digits(digits: &[u8]) -> bool {
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Luhn checksum over a digit string. Spaces and hyphens are ignored, any
/// other character fails. At least two digits are required.
pub fn luhn_valid(digits: &str) -> bool {
    digits_only(digits).is_some_and(|d| luhn_digits(&d))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardBrand {
    Visa,
    Mastercard,
    Amex,
    Discover,
    Jcb,
    DinersClub,
    UnionPay,
    Maestro,
    CartesBancaires,
    Unknown,
}

/// Brand of a card from its leading digits (the BIN ranges). Cartes
/// Bancaires cannot be told apart by BIN alone (co-badged cards start with a
/// Visa or Mastercard range), so it is never returned from here and the
/// variant exists for values chosen explicitly by the user.
pub fn card_brand(number: &str) -> CardBrand {
    let Some(d) = digits_only(number) else {
        return CardBrand::Unknown;
    };
    // Leading `n` digits as a number, or 0 when the number is shorter.
    let p = |n: usize| -> u32 {
        if d.len() < n {
            return 0;
        }
        d[..n].iter().fold(0, |acc, &x| acc * 10 + u32::from(x))
    };
    let has = |n: usize| d.len() >= n;
    if !has(1) {
        return CardBrand::Unknown;
    }
    // Longest and most specific prefixes first.
    if has(6) && matches!(p(6), 676770 | 676774) {
        return CardBrand::Maestro;
    }
    if has(4) && matches!(p(4), 6304 | 6759) {
        return CardBrand::Maestro;
    }
    if has(4) && p(4) == 6011 {
        return CardBrand::Discover;
    }
    if has(4) && (2221..=2720).contains(&p(4)) {
        return CardBrand::Mastercard;
    }
    if has(4) && (3528..=3589).contains(&p(4)) {
        return CardBrand::Jcb;
    }
    if has(3) && (644..=649).contains(&p(3)) {
        return CardBrand::Discover;
    }
    if has(3) && (300..=305).contains(&p(3)) {
        return CardBrand::DinersClub;
    }
    if has(2) {
        match p(2) {
            51..=55 => return CardBrand::Mastercard,
            34 | 37 => return CardBrand::Amex,
            65 => return CardBrand::Discover,
            36 | 38 => return CardBrand::DinersClub,
            62 => return CardBrand::UnionPay,
            50 | 56..=58 => return CardBrand::Maestro,
            _ => {}
        }
    }
    if d[0] == 4 {
        return CardBrand::Visa;
    }
    CardBrand::Unknown
}

/// IBAN total length by country code (SWIFT registry).
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("NO", 15),
    ("BE", 16),
    ("BI", 16),
    ("DK", 18),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("GL", 18),
    ("NL", 18),
    ("SD", 18),
    ("MK", 19),
    ("SI", 19),
    ("AT", 20),
    ("BA", 20),
    ("EE", 20),
    ("KZ", 20),
    ("LT", 20),
    ("LU", 20),
    ("MN", 20),
    ("XK", 20),
    ("CH", 21),
    ("HR", 21),
    ("LI", 21),
    ("LV", 21),
    ("BG", 22),
    ("BH", 22),
    ("CR", 22),
    ("DE", 22),
    ("GB", 22),
    ("GE", 22),
    ("IE", 22),
    ("ME", 22),
    ("RS", 22),
    ("VA", 22),
    ("AE", 23),
    ("GI", 23),
    ("IL", 23),
    ("IQ", 23),
    ("OM", 23),
    ("SO", 23),
    ("TL", 23),
    ("AD", 24),
    ("CZ", 24),
    ("ES", 24),
    ("MD", 24),
    ("PK", 24),
    ("RO", 24),
    ("SA", 24),
    ("SE", 24),
    ("SK", 24),
    ("TN", 24),
    ("VG", 24),
    ("LY", 25),
    ("PT", 25),
    ("ST", 25),
    ("IS", 26),
    ("TR", 26),
    ("DJ", 27),
    ("FR", 27),
    ("GR", 27),
    ("IT", 27),
    ("MC", 27),
    ("MR", 27),
    ("SM", 27),
    ("AL", 28),
    ("AZ", 28),
    ("BY", 28),
    ("CY", 28),
    ("DO", 28),
    ("GT", 28),
    ("HN", 28),
    ("HU", 28),
    ("LB", 28),
    ("NI", 28),
    ("PL", 28),
    ("SV", 28),
    ("BR", 29),
    ("EG", 29),
    ("PS", 29),
    ("QA", 29),
    ("UA", 29),
    ("JO", 30),
    ("KW", 30),
    ("MU", 30),
    ("YE", 30),
    ("MT", 31),
    ("SC", 31),
    ("LC", 32),
    ("RU", 33),
];

fn iban_length(country: &str) -> Option<usize> {
    IBAN_LENGTHS
        .iter()
        .find(|(c, _)| *c == country)
        .map(|(_, n)| *n)
}

/// IBAN check: spaces ignored, case ignored, ISO 7064 mod 97 equal to 1.
/// Countries in the registry table must have their exact length. A country
/// missing from the table is accepted at any length from 15 to 34 so that a
/// real IBAN is never blocked by an outdated table.
pub fn iban_valid(iban: &str) -> bool {
    let s: Vec<u8> = iban
        .bytes()
        .filter(|b| *b != b' ')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if s.len() < 4 || !s.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let (country, rest) = s.split_at(2);
    if !country.iter().all(u8::is_ascii_uppercase) || !rest[..2].iter().all(u8::is_ascii_digit) {
        return false;
    }
    // Country code is ASCII here, so this conversion cannot fail.
    let Ok(country) = std::str::from_utf8(country) else {
        return false;
    };
    let length_ok = match iban_length(country) {
        Some(n) => n == s.len(),
        None => (15..=34).contains(&s.len()),
    };
    if !length_ok {
        return false;
    }
    // Move the first four characters to the end, letters count as 10..=35.
    let mut rem: u32 = 0;
    for &b in s[4..].iter().chain(s[..4].iter()) {
        if b.is_ascii_digit() {
            rem = (rem * 10 + u32::from(b - b'0')) % 97;
        } else {
            rem = (rem * 100 + u32::from(b - b'A') + 10) % 97;
        }
    }
    rem == 1
}

/// The official BIP39 English wordlist, sorted, 2048 words.
fn bip39_words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            include_str!("../../data/bip39_english.txt")
                .lines()
                .collect()
        })
        .as_slice()
}

/// BIP39 check: 12, 15, 18, 21 or 24 words of the English list (case and
/// whitespace insensitive) whose trailing bits equal the SHA-256 checksum of
/// the entropy. Unknown words fail.
pub fn bip39_valid(phrase: &str) -> bool {
    let lower = Zeroizing::new(phrase.to_lowercase());
    let words: Vec<&str> = lower.split_whitespace().collect();
    let n = words.len();
    if !matches!(n, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    let list = bip39_words();
    let mut bits = Zeroizing::new(vec![0u8; (n * 11).div_ceil(8)]);
    for (i, w) in words.iter().enumerate() {
        let Ok(idx) = list.binary_search(w) else {
            return false;
        };
        for b in 0..11 {
            if (idx >> (10 - b)) & 1 == 1 {
                let pos = i * 11 + b;
                bits[pos / 8] |= 0x80 >> (pos % 8);
            }
        }
    }
    let checksum_bits = n / 3;
    let entropy_len = 4 * checksum_bits;
    let hash = digest::digest(&digest::SHA256, &bits[..entropy_len]);
    let expected = hash.as_ref()[0] >> (8 - checksum_bits);
    let actual = bits[entropy_len] >> (8 - checksum_bits);
    expected == actual
}

fn us_ssn_valid(number: &str) -> bool {
    let b = number.as_bytes();
    let d: Vec<u8> = match b.len() {
        9 => b.to_vec(),
        11 if b[3] == b'-' && b[6] == b'-' => b.iter().copied().filter(|c| *c != b'-').collect(),
        _ => return false,
    };
    if d.len() != 9 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> u32 {
        d[r].iter().fold(0, |a, &x| a * 10 + u32::from(x - b'0'))
    };
    let (area, group, serial) = (num(0..3), num(3..5), num(5..9));
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// French NIR with its two-digit key (15 characters, spaces ignored).
fn fr_nir_valid(number: &str) -> bool {
    let s: Vec<u8> = number
        .bytes()
        .filter(|b| *b != b' ')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if s.len() != 15 {
        return false;
    }
    // 13-digit body, with the Corsican department 2A or 2B (characters 6
    // and 7) replaced by 19 or 18.
    let mut body = s[..13].to_vec();
    if body[5] == b'2' && body[6] == b'A' {
        body[5..7].copy_from_slice(b"19");
    } else if body[5] == b'2' && body[6] == b'B' {
        body[5..7].copy_from_slice(b"18");
    }
    if !body.iter().all(u8::is_ascii_digit) || !s[13..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let digits = |bytes: &[u8]| {
        bytes
            .iter()
            .fold(0u64, |a, &x| a * 10 + u64::from(x - b'0'))
    };
    let (n, k) = (digits(&body), digits(&s[13..]));
    k == 97 - (n % 97)
}

fn gb_ni_valid(number: &str) -> bool {
    let s: Vec<u8> = number
        .bytes()
        .filter(|b| *b != b' ')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if s.len() != 9 {
        return false;
    }
    let (p, digits, suffix) = (&s[..2], &s[2..8], s[8]);
    if !p.iter().all(u8::is_ascii_uppercase)
        || !digits.iter().all(u8::is_ascii_digit)
        || !(b'A'..=b'D').contains(&suffix)
    {
        return false;
    }
    if b"DFIQUV".contains(&p[0]) || b"DFIOQUV".contains(&p[1]) {
        return false;
    }
    !matches!(p, b"BG" | b"GB" | b"NK" | b"KN" | b"TN" | b"NT" | b"ZZ")
}

fn ca_sin_valid(number: &str) -> bool {
    let Some(d) = digits_only(number) else {
        return false;
    };
    d.len() == 9 && d[0] != 8 && luhn_digits(&d)
}

/// Checks a national identifier for a country (ISO 3166 alpha-2, case
/// insensitive). `None` when the country is not handled, which is not an
/// error.
pub fn national_id_valid(country: &str, number: &str) -> Option<bool> {
    let number = number.trim();
    match country.trim().to_ascii_uppercase().as_str() {
        "US" => Some(us_ssn_valid(number)),
        "FR" => Some(fr_nir_valid(number)),
        "GB" => Some(gb_ni_valid(number)),
        "CA" => Some(ca_sin_valid(number)),
        _ => None,
    }
}

/// RFC 4648 base32 secret (as used for one-time passwords). Case, spaces
/// and hyphens are ignored; trailing `=` padding is accepted.
pub fn base32_secret_valid(s: &str) -> bool {
    let cleaned: String = s
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    if unpadded.is_empty() || unpadded.contains('=') {
        return false;
    }
    data_encoding::BASE32_NOPAD
        .decode(unpadded.as_bytes())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn luhn_edge_cases() {
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(luhn_valid("4111-1111-1111-1111"));
        assert!(!luhn_valid(""));
        assert!(!luhn_valid("0"));
        assert!(!luhn_valid("4111a11111111111"));
    }

    #[test]
    fn brands() {
        assert_eq!(card_brand("4111111111111111"), CardBrand::Visa);
        assert_eq!(card_brand("5555555555554444"), CardBrand::Mastercard);
        assert_eq!(card_brand("2223003122003222"), CardBrand::Mastercard);
        assert_eq!(card_brand("378282246310005"), CardBrand::Amex);
    }

    #[test]
    fn brand_ranges() {
        let b = card_brand;
        assert_eq!(b("5105105105105100"), CardBrand::Mastercard);
        assert_eq!(b("2221000000000009"), CardBrand::Mastercard);
        assert_eq!(b("2720990000000007"), CardBrand::Mastercard);
        assert_eq!(b("2220990000000000"), CardBrand::Unknown);
        assert_eq!(b("2721000000000000"), CardBrand::Unknown);
        assert_eq!(b("340000000000009"), CardBrand::Amex);
        assert_eq!(b("6011111111111117"), CardBrand::Discover);
        assert_eq!(b("6440000000000000"), CardBrand::Discover);
        assert_eq!(b("6499000000000000"), CardBrand::Discover);
        assert_eq!(b("6500000000000002"), CardBrand::Discover);
        assert_eq!(b("3528000000000007"), CardBrand::Jcb);
        assert_eq!(b("3589000000000003"), CardBrand::Jcb);
        assert_eq!(b("3590000000000000"), CardBrand::Unknown);
        assert_eq!(b("30000000000004"), CardBrand::DinersClub);
        assert_eq!(b("30569309025904"), CardBrand::DinersClub);
        assert_eq!(b("36000000000008"), CardBrand::DinersClub);
        assert_eq!(b("38000000000006"), CardBrand::DinersClub);
        assert_eq!(b("6200000000000005"), CardBrand::UnionPay);
        assert_eq!(b("5018000000000009"), CardBrand::Maestro);
        assert_eq!(b("5612000000000000"), CardBrand::Maestro);
        assert_eq!(b("5800000000000000"), CardBrand::Maestro);
        assert_eq!(b("6304000000000000"), CardBrand::Maestro);
        assert_eq!(b("6759649826438453"), CardBrand::Maestro);
        assert_eq!(b("6767700000000000"), CardBrand::Maestro);
        assert_eq!(b("6767740000000000"), CardBrand::Maestro);
        assert_eq!(b("6767710000000000"), CardBrand::Unknown);
        assert_eq!(b("4111 1111 1111 1111"), CardBrand::Visa);
        assert_eq!(b(""), CardBrand::Unknown);
        assert_eq!(b("abcd"), CardBrand::Unknown);
    }

    #[test]
    fn cartes_bancaires_is_never_detected_from_the_number() {
        // A CB co-badged card starts with a Visa or Mastercard range.
        assert_ne!(card_brand("4970100000000009"), CardBrand::CartesBancaires);
        assert_ne!(card_brand("5131000000000000"), CardBrand::CartesBancaires);
    }

    #[test]
    fn iban() {
        assert!(iban_valid("FR76 3000 6000 0112 3456 7890 189"));
        assert!(!iban_valid("FR76 3000 6000 0112 3456 7890 188"));
    }

    #[test]
    fn iban_other_countries_and_shape() {
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(iban_valid("gb82 west 1234 5698 7654 32"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(iban_valid("NL91ABNA0417164300"));
        // Right checksum would need the right length: too short for FR.
        assert!(!iban_valid("FR7630006000011234567890"));
        assert!(!iban_valid(""));
        assert!(!iban_valid("GB82-WEST-1234-5698-7654-32"));
        assert!(!iban_valid("GB82WEST1234569876543é"));
    }

    /// Synthetic IBAN: country, computed check digits, zero-padded BBAN.
    fn synthetic_iban(country: &str, len: usize) -> String {
        let bban = "0".repeat(len - 4);
        let numeric: String = format!("{bban}{country}00")
            .chars()
            .map(|c| match c.to_digit(36) {
                Some(d) => d.to_string(),
                None => unreachable!(),
            })
            .collect();
        let rem = numeric
            .bytes()
            .fold(0u32, |r, b| (r * 10 + u32::from(b - b'0')) % 97);
        format!("{country}{:02}{bban}", 98 - rem)
    }

    #[test]
    fn iban_costa_rica_is_22() {
        assert!(iban_valid("CR05015202001026284066"));
        assert!(!iban_valid("CR0501520200102628406"));
    }

    #[test]
    fn iban_every_table_entry_accepts_its_length_only() {
        for &(country, len) in super::IBAN_LENGTHS {
            let ok = synthetic_iban(country, len);
            assert_eq!(ok.len(), len, "{country}");
            assert!(iban_valid(&ok), "{country} at {len}");
        }
        for &(country, len) in super::IBAN_LENGTHS.iter().step_by(7) {
            assert!(
                !iban_valid(&synthetic_iban(country, len + 1)),
                "{country} long"
            );
            assert!(
                !iban_valid(&synthetic_iban(country, len - 1)),
                "{country} short"
            );
        }
        for c in [
            "RU", "NI", "HN", "MN", "OM", "SO", "SD", "FK", "BI", "DJ", "YE",
        ] {
            assert!(super::iban_length(c).is_some(), "{c}");
        }
        assert_eq!(super::iban_length("RU"), Some(33));
    }

    #[test]
    fn iban_unlisted_country_is_accepted_by_length_range_and_checksum() {
        assert!(super::iban_length("ZZ").is_none());
        for len in [15, 22, 34] {
            assert!(iban_valid(&synthetic_iban("ZZ", len)), "{len}");
        }
        assert!(!iban_valid(&synthetic_iban("ZZ", 14)));
        assert!(!iban_valid(&synthetic_iban("ZZ", 35)));
        let mut bad = synthetic_iban("ZZ", 22);
        bad.replace_range(2..4, "00");
        assert!(!iban_valid(&bad));
    }

    const ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip39() {
        assert!(bip39_valid(ABOUT));
        assert!(!bip39_valid(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        ));
    }

    #[test]
    fn bip39_normalization_and_lengths() {
        assert!(bip39_valid(&ABOUT.to_uppercase()));
        assert!(bip39_valid(&format!("  {}\n", ABOUT.replace(' ', "  "))));
        // Unknown word: false, no panic.
        assert!(!bip39_valid(&ABOUT.replace("about", "aboot")));
        assert!(!bip39_valid(""));
        assert!(!bip39_valid("abandon abandon abandon"));
        // 24 words (official test vector, all-zero entropy).
        let w24 = format!("{} art", "abandon ".repeat(23).trim_end());
        assert!(bip39_valid(&w24));
        assert!(!bip39_valid(&w24.replace("art", "about")));
        // 15, 18 and 21 words, all-zero entropy.
        assert!(bip39_valid(&format!(
            "{} address",
            "abandon ".repeat(14).trim_end()
        )));
        assert!(bip39_valid(&format!(
            "{} agent",
            "abandon ".repeat(17).trim_end()
        )));
        assert!(bip39_valid(&format!(
            "{} admit",
            "abandon ".repeat(20).trim_end()
        )));
        // 13 words is not a valid length.
        assert!(!bip39_valid(&format!("{ABOUT} about")));
    }

    #[test]
    fn bip39_wordlist_is_the_official_one() {
        assert_eq!(bip39_words().len(), 2048);
        assert_eq!(bip39_words()[0], "abandon");
        assert_eq!(bip39_words()[2047], "zoo");
    }

    #[test]
    fn national_ids() {
        assert_eq!(national_id_valid("US", "078-05-1120"), Some(true));
        assert_eq!(national_id_valid("US", "666-12-3456"), Some(false));
        assert_eq!(national_id_valid("FR", "2 55 08 14 168 025 38"), Some(true));
        assert_eq!(national_id_valid("CA", "046 454 286"), Some(true));
        assert_eq!(national_id_valid("JP", "123"), None);
    }

    #[test]
    fn us_ssn_rules() {
        let us = |n: &str| national_id_valid("US", n);
        assert_eq!(us("078051120"), Some(true));
        assert_eq!(us("000-12-3456"), Some(false));
        assert_eq!(us("899-12-3456"), Some(true));
        assert_eq!(us("900-12-3456"), Some(false));
        assert_eq!(us("999-12-3456"), Some(false));
        assert_eq!(us("123-00-4567"), Some(false));
        assert_eq!(us("123-45-0000"), Some(false));
        assert_eq!(us("123-456-789"), Some(false));
        assert_eq!(us("12345678"), Some(false));
        assert_eq!(us("12a-45-6789"), Some(false));
        assert_eq!(national_id_valid("us", "078-05-1120"), Some(true));
    }

    #[test]
    fn fr_nir_rules() {
        let fr = |n: &str| national_id_valid("FR", n);
        assert_eq!(fr("255081416802538"), Some(true));
        assert_eq!(fr("255081416802537"), Some(false));
        // 13 digits without the key cannot be verified.
        assert_eq!(fr("2550814168025"), Some(false));
        // Corsica: 2A -> 19, 2B -> 18 (key computed on those substitutions).
        assert_eq!(fr("2 55 08 2A 168 025 97"), Some(true));
        assert_eq!(fr("2 55 08 2B 168 025 27"), Some(true));
        assert_eq!(fr("2 55 08 2A 168 025 96"), Some(false));
        assert_eq!(fr("2 55 08 2c 168 025 97"), Some(false));
        assert_eq!(fr("2 55 08 14 168 025 00"), Some(false));
        assert_eq!(fr("abc"), Some(false));
    }

    #[test]
    fn gb_ni_rules() {
        let gb = |n: &str| national_id_valid("GB", n);
        assert_eq!(gb("QQ123456C"), Some(false));
        assert_eq!(gb("AB123456C"), Some(true));
        assert_eq!(gb("ab 12 34 56 c"), Some(true));
        assert_eq!(gb("AB123456D"), Some(true));
        assert_eq!(gb("AB123456E"), Some(false));
        assert_eq!(gb("DA123456A"), Some(false));
        assert_eq!(gb("AO123456A"), Some(false));
        assert_eq!(gb("OA123456A"), Some(true));
        assert_eq!(gb("BG123456A"), Some(false));
        assert_eq!(gb("GB123456A"), Some(false));
        assert_eq!(gb("NK123456A"), Some(false));
        assert_eq!(gb("KN123456A"), Some(false));
        assert_eq!(gb("TN123456A"), Some(false));
        assert_eq!(gb("NT123456A"), Some(false));
        assert_eq!(gb("ZZ123456A"), Some(false));
        assert_eq!(gb("AB12345C"), Some(false));
        assert_eq!(gb("AB1234567"), Some(false));
    }

    #[test]
    fn ca_sin_rules() {
        let ca = |n: &str| national_id_valid("CA", n);
        assert_eq!(ca("046454286"), Some(true));
        assert_eq!(ca("130 692 544"), Some(true));
        assert_eq!(ca("130-692-544"), Some(true));
        assert_eq!(ca("130 692 545"), Some(false));
        assert_eq!(ca("800000002"), Some(false)); // starts with 8
        assert_eq!(ca("13069254"), Some(false));
    }

    #[test]
    fn base32() {
        assert!(base32_secret_valid("JBSWY3DPEHPK3PXP"));
        assert!(base32_secret_valid("jbsw y3dp ehpk 3pxp"));
        assert!(base32_secret_valid("JBSWY3DPEHPK3PXP===="));
        assert!(!base32_secret_valid(""));
        assert!(!base32_secret_valid("JBSWY3DPEHPK3PX1"));
        assert!(!base32_secret_valid("JBSWY3D=PEHPK3PXP"));
        assert!(!base32_secret_valid("JBSWY3DPEHPK3PX"));
    }
}
