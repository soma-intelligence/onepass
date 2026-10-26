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
        let mut body: Zeroizing<String> = Zeroizing::new(BASE32_NOPAD.encode(&self.0));
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

/// Sum of the 5-bit values of the body characters, modulo 32, as a base32 char.
fn checksum_char(body: &[u8]) -> u8 {
    let sum: usize = body
        .iter()
        .map(|b| ALPHABET.iter().position(|a| a == b).unwrap_or(0))
        .sum();
    ALPHABET[sum % 32]
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
        // 52 'A' (value 0), check value 0 = 'A', groups of 4.
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
    fn debug_never_prints_bytes() {
        assert_eq!(format!("{:?}", SecretKey([0xAB; 32])), "SecretKey(**)");
    }
}
