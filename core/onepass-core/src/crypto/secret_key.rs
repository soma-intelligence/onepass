//! Account Secret Key: 256 random bits shown as grouped base32 with a check character.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::random::fill_random;
use crate::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BODY_LEN: usize = 52;

/// A 256-bit account Secret Key, wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; 32]);

impl SecretKey {
    pub fn generate() -> Result<SecretKey> {
        let mut k = SecretKey([0u8; 32]);
        fill_random(&mut k.0)?;
        Ok(k)
    }

    /// Base32 (RFC 4648, no padding, upper case) plus one check character,
    /// grouped by 4 with `-`.
    pub fn to_display(&self) -> String {
        // Capacity for body plus check char up front: no reallocation, so no
        // unwiped copy of the key is left behind.
        let mut body: Zeroizing<String> = Zeroizing::new(String::with_capacity(BODY_LEN + 1));
        BASE32_NOPAD.encode_append(&self.0, &mut body);
        let check = checksum_char(body.as_bytes());
        body.push(check as char);
        let mut out = String::with_capacity(body.len() + body.len() / 4);
        for (i, c) in body.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Parse a displayed Secret Key. Ignores whitespace and `-`, accepts lower
    /// case and maps `0`->`O`, `1`->`I`, `8`->`B`.
    ///
    /// Errors: a wrong character count gives `InvalidFormat("secret key length")`.
    /// A character outside the alphabet, a wrong check character, or non-zero
    /// trailing padding bits (a non-canonical encoding) all give
    /// `InvalidFormat("secret key checksum")`.
    pub fn parse(s: &str) -> Result<SecretKey> {
        let mut clean: Zeroizing<String> = Zeroizing::new(String::with_capacity(s.len()));
        for c in s.chars() {
            if c.is_whitespace() || c == '-' {
                continue;
            }
            if !c.is_ascii() {
                return Err(Error::InvalidFormat("secret key checksum"));
            }
            clean.push(match c.to_ascii_uppercase() {
                '0' => 'O',
                '1' => 'I',
                '8' => 'B',
                u => u,
            });
        }
        if clean.len() != BODY_LEN + 1 {
            return Err(Error::InvalidFormat("secret key length"));
        }
        let (body, check) = clean.split_at(BODY_LEN);
        let bad = Error::InvalidFormat("secret key checksum");
        if !body.bytes().all(|b| ALPHABET.contains(&b)) {
            return Err(bad);
        }
        if check.as_bytes()[0] != checksum_char(body.as_bytes()) {
            return Err(bad);
        }
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            BASE32_NOPAD
                .decode(body.as_bytes())
                .map_err(|_| Error::InvalidFormat("secret key checksum"))?,
        );
        let mut key = SecretKey([0u8; 32]);
        if bytes.len() != 32 {
            return Err(Error::InvalidFormat("secret key length"));
        }
        key.0.copy_from_slice(&bytes);
        Ok(key)
    }
}

/// Luhn mod N check character, N = 32, over the base32 symbol values of
/// the body: from the rightmost symbol, every other value is doubled and
/// its two base-32 digits added. It catches every single substitution and
/// every adjacent transposition except `A` (0) with `7` (31), the one blind
/// pair of Luhn mod N.
fn checksum_char(body: &[u8]) -> u8 {
    const N: usize = ALPHABET.len();
    let mut factor = 2;
    let mut sum = 0usize;
    for b in body.iter().rev() {
        let value = ALPHABET.iter().position(|a| a == b).unwrap_or(0);
        let addend = factor * value;
        factor = 3 - factor;
        sum += addend / N + addend % N;
    }
    ALPHABET[(N - sum % N) % N]
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(**)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parses_with_human_noise() {
        let sk = SecretKey::generate().unwrap();
        let shown = sk.to_display();
        assert_eq!(shown.replace('-', "").len(), 53);
        let noisy = shown
            .to_lowercase()
            .replace('-', " ")
            .replace('o', "0")
            .replace('i', "1");
        assert_eq!(SecretKey::parse(&noisy).unwrap().0, sk.0);
    }

    #[test]
    fn single_typo_is_rejected() {
        let shown = SecretKey::generate().unwrap().to_display();
        let mut chars: Vec<char> = shown.chars().collect();
        chars[0] = if chars[0] == 'A' { 'C' } else { 'A' };
        assert!(matches!(
            SecretKey::parse(&chars.into_iter().collect::<String>()),
            Err(Error::InvalidFormat("secret key checksum"))
        ));
    }

    #[test]
    fn missing_character_is_a_length_error() {
        let shown = SecretKey::generate().unwrap().to_display();
        assert!(matches!(
            SecretKey::parse(&shown[1..]),
            Err(Error::InvalidFormat("secret key length"))
        ));
    }

    #[test]
    fn display_shape_and_known_vector() {
        let sk = SecretKey([0u8; 32]);
        let shown = sk.to_display();
        // 52 'A' (value 0): Luhn sum 0, check value 0 = 'A', groups of 4.
        let expected = format!("{}A", "AAAA-".repeat(13));
        assert_eq!(shown, expected);
        assert_eq!(SecretKey::parse(&shown).unwrap().0, [0u8; 32]);
    }

    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        // Last body char carries 4 padding bits. 'B' (value 1) sets one of them.
        let mut body = "A".repeat(51);
        body.push('B');
        let check = checksum_char(body.as_bytes()) as char;
        let forged = format!("{body}{check}");
        assert!(matches!(
            SecretKey::parse(&forged),
            Err(Error::InvalidFormat("secret key checksum"))
        ));
    }

    #[test]
    fn character_outside_alphabet_is_rejected() {
        let shown = SecretKey::generate().unwrap().to_display();
        let bad = format!("9{}", &shown[1..]);
        assert!(matches!(
            SecretKey::parse(&bad),
            Err(Error::InvalidFormat("secret key checksum"))
        ));
    }

    #[test]
    fn non_ascii_input_is_rejected_without_panic() {
        // 51 'A' + 'e acute' is 53 bytes: split_at(52) would not be a boundary.
        let a = format!("{}\u{e9}", "A".repeat(51));
        assert_eq!(a.len(), 53);
        assert!(matches!(
            SecretKey::parse(&a),
            Err(Error::InvalidFormat("secret key checksum"))
        ));
        // 51 'A' + a 3-byte char is 54 bytes.
        let b = format!("{}\u{20ac}", "A".repeat(51));
        assert_eq!(b.len(), 54);
        assert!(matches!(
            SecretKey::parse(&b),
            Err(Error::InvalidFormat("secret key checksum"))
        ));
    }

    /// Key bytes 0..32: no adjacent A/7 pair in its display (see below).
    fn fixed() -> SecretKey {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        SecretKey(b)
    }

    const FIXED_SHOWN: &str = "AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPQ-B";

    fn parse_chars(chars: &[u8]) -> Result<SecretKey> {
        SecretKey::parse(std::str::from_utf8(chars).unwrap())
    }

    #[test]
    fn luhn_mod_32_known_vector() {
        // Check char computed independently (Python, Luhn mod N, N = 32).
        assert_eq!(fixed().to_display(), FIXED_SHOWN);
        assert_eq!(SecretKey::parse(FIXED_SHOWN).unwrap().0, fixed().0);
    }

    #[test]
    fn every_single_substitution_is_rejected() {
        let clean: Vec<u8> = FIXED_SHOWN.bytes().filter(|&b| b != b'-').collect();
        assert_eq!(clean.len(), BODY_LEN + 1);
        for i in 0..clean.len() {
            for &c in ALPHABET {
                if c == clean[i] {
                    continue;
                }
                let mut typo = clean.clone();
                typo[i] = c;
                assert_eq!(
                    parse_chars(&typo).err(),
                    Some(Error::InvalidFormat("secret key checksum")),
                    "position {i}, symbol {}",
                    c as char
                );
            }
        }
    }

    #[test]
    fn every_adjacent_transposition_is_rejected() {
        let clean: Vec<u8> = FIXED_SHOWN.bytes().filter(|&b| b != b'-').collect();
        for i in 0..clean.len() - 1 {
            if clean[i] == clean[i + 1] {
                continue;
            }
            let mut swapped = clean.clone();
            swapped.swap(i, i + 1);
            assert_eq!(
                parse_chars(&swapped).err(),
                Some(Error::InvalidFormat("secret key checksum")),
                "positions {i} and {}",
                i + 1
            );
        }
    }

    #[test]
    fn only_the_a_7_transposition_is_blind() {
        // Luhn mod N misses exactly one transposition: the symbols of value
        // 0 and N - 1 ('A' and '7'), whose doubled forms are themselves.
        let mut blind = Vec::new();
        for &x in ALPHABET {
            for &y in ALPHABET {
                let mut a = [b'A'; BODY_LEN];
                (a[10], a[11]) = (x, y);
                let mut b = a;
                b.swap(10, 11);
                if x < y && checksum_char(&a) == checksum_char(&b) {
                    blind.push((x as char, y as char));
                }
            }
        }
        assert_eq!(blind, vec![('7', 'A')]);
    }

    #[test]
    fn debug_never_prints_bytes() {
        assert_eq!(format!("{:?}", SecretKey([0xAB; 32])), "SecretKey(**)");
    }
}
