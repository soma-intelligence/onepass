//! Base58 (Bitcoin alphabet, with and without the double SHA-256 checksum)
//! and Bech32 / Bech32m (BIP173, BIP350). Public data only: addresses and
//! extended public keys.

use aws_lc_rs::digest::{SHA256, digest};

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Longest base58 text accepted (an xpub is 111 characters).
const MAX_B58: usize = 128;

pub fn b58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|b| **b == 0).count();
    // Big-endian base conversion, base 256 to base 58.
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| B58[usize::from(*d)] as char));
    out
}

pub fn b58_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() > MAX_B58 {
        return None;
    }
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|a| *a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let once = digest(&SHA256, payload);
    let twice = digest(&SHA256, once.as_ref());
    let mut out = [0u8; 4];
    out.copy_from_slice(&twice.as_ref()[..4]);
    out
}

pub fn b58check_encode(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&checksum(payload));
    b58_encode(&data)
}

/// The payload of a Base58Check text whose checksum holds.
pub fn b58check_decode(text: &str) -> Option<Vec<u8>> {
    let data = b58_decode(text)?;
    if data.len() < 5 {
        return None;
    }
    let (payload, check) = data.split_at(data.len() - 4);
    (checksum(payload) == check).then(|| payload.to_vec())
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Variant {
    Bech32,
    Bech32m,
}

impl Bech32Variant {
    fn constant(self) -> u32 {
        match self {
            Self::Bech32 => BECH32_CONST,
            Self::Bech32m => BECH32M_CONST,
        }
    }
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> impl Iterator<Item = u8> + '_ {
    hrp.iter()
        .map(|c| c >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.iter().map(|c| c & 31))
}

/// Human-readable part (lower case), 5-bit data without the checksum, and
/// the variant whose checksum holds.
pub fn bech32_decode(text: &str) -> Option<(String, Vec<u8>, Bech32Variant)> {
    if text.len() > 90 || !text.is_ascii() {
        return None;
    }
    let has_lower = text.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = text.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let sep = lower.rfind('1')?;
    let (hrp, rest) = (&lower[..sep], &lower[sep + 1..]);
    if hrp.is_empty() || rest.len() < 6 || hrp.bytes().any(|b| !(33..=126).contains(&b)) {
        return None;
    }
    let mut data = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        data.push(CHARSET.iter().position(|a| *a == c)? as u8);
    }
    let check = polymod(hrp_expand(hrp.as_bytes()).chain(data.iter().copied()));
    let variant = match check {
        BECH32_CONST => Bech32Variant::Bech32,
        BECH32M_CONST => Bech32Variant::Bech32m,
        _ => return None,
    };
    data.truncate(data.len() - 6);
    Some((hrp.to_owned(), data, variant))
}

pub fn bech32_encode(hrp: &str, data: &[u8], variant: Bech32Variant) -> String {
    let values: Vec<u8> = hrp_expand(hrp.as_bytes())
        .chain(data.iter().copied())
        .chain([0u8; 6])
        .collect();
    let pm = polymod(values.into_iter()) ^ variant.constant();
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for d in data {
        out.push(CHARSET[usize::from(*d)] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

/// Regroups bits (8 to 5 or 5 to 8). `None` when the padding is invalid.
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &v in data {
        if u32::from(v) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return None;
    }
    Some(out)
}

/// Witness version and program of a segwit address of `hrp` (BIP173 for
/// version 0, BIP350 for 1 to 16).
pub fn segwit_decode(hrp: &str, text: &str) -> Option<(u8, Vec<u8>)> {
    let (got, data, variant) = bech32_decode(text)?;
    if got != hrp || data.is_empty() {
        return None;
    }
    let version = data[0];
    if version > 16 {
        return None;
    }
    let program = convert_bits(&data[1..], 5, 8, false)?;
    if !(2..=40).contains(&program.len()) {
        return None;
    }
    match (version, variant) {
        (0, Bech32Variant::Bech32) if matches!(program.len(), 20 | 32) => {}
        (0, _) => return None,
        (_, Bech32Variant::Bech32m) => {}
        _ => return None,
    }
    Some((version, program))
}

pub fn segwit_encode(hrp: &str, version: u8, program: &[u8]) -> Option<String> {
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true)?);
    let variant = if version == 0 {
        Bech32Variant::Bech32
    } else {
        Bech32Variant::Bech32m
    };
    let out = bech32_encode(hrp, &data, variant);
    segwit_decode(hrp, &out).is_some().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    #[test]
    fn base58_round_trips_with_leading_zeros() {
        // Vectors of the Bitcoin Core base58 test data (base58_encode_decode.json).
        let cases = [
            ("", ""),
            ("61", "2g"),
            ("626262", "a3gV"),
            ("636363", "aPEr"),
            (
                "73696d706c792061206c6f6e6720737472696e67",
                "2cFupjhnEsSn59qHXstmK2ffpLv2",
            ),
            (
                "00eb15231dfceb60925886b67d065299925915aeb172c06647",
                "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
            ),
            ("516b6fcd0f", "ABnLTmg"),
            ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
            ("572e4794", "3EFU7m"),
            ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
            ("10c8511e", "Rt5zm"),
            ("00000000000000000000", "1111111111"),
        ];
        for (h, b) in cases {
            assert_eq!(b58_encode(&hex(h)), b, "{h}");
            if !b.is_empty() {
                assert_eq!(b58_decode(b).unwrap(), hex(h), "{b}");
            }
        }
        assert_eq!(b58_decode("0OIl"), None);
    }

    #[test]
    fn base58check_rejects_a_changed_character() {
        let good = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(b58check_decode(good).unwrap().len(), 21);
        assert_eq!(b58check_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"), None);
    }

    #[test]
    fn bech32_and_bech32m_official_valid_strings() {
        // BIP173 and BIP350 "valid checksum" vectors.
        for s in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ] {
            assert_eq!(bech32_decode(s).unwrap().2, Bech32Variant::Bech32, "{s}");
        }
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            assert_eq!(bech32_decode(s).unwrap().2, Bech32Variant::Bech32m, "{s}");
        }
    }

    #[test]
    fn bech32_official_invalid_strings() {
        for s in [
            "pzry9x0s0muk",  // no separator
            "1pzry9x0s0muk", // empty hrp
            "x1b4n0q5v",     // invalid data char
            "li1dgmt3",      // too short checksum
            "A1G7SGD8",      // checksum from upper hrp
            "10a06t8",       // empty hrp
            "1qzzfhee",      // empty hrp
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", // over 90
        ] {
            assert!(bech32_decode(s).is_none(), "{s}");
        }
    }

    #[test]
    fn segwit_official_addresses() {
        // BIP350 valid segwit addresses (mainnet ones) with their scriptPubKey.
        let cases = [
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            (
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
                "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            ("BC1SW50QGDZ25J", "6002751e"),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
                "5210751e76e8199196d454941c45d1b3a323",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ];
        for (addr, script) in cases {
            let (v, prog) = segwit_decode("bc", addr).unwrap();
            let s = hex(script);
            let op = if v == 0 { 0 } else { 0x50 + v };
            assert_eq!(s[0], op, "{addr}");
            assert_eq!(&s[2..], &prog[..], "{addr}");
            assert_eq!(
                segwit_encode("bc", v, &prog).unwrap(),
                addr.to_ascii_lowercase()
            );
        }
        // BIP350 invalid ones: wrong variant, bad program length, wrong hrp.
        for addr in [
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "bc1gmk9yu",
        ] {
            assert!(segwit_decode("bc", addr).is_none(), "{addr}");
        }
    }
}
