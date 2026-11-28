//! Basic Access Control (ICAO 9303-11, 4.3 and annex D).
//!
//! The caller supplies the randoms (RND.IFD and K.IFD from a CSPRNG in real
//! use, fixed in tests), so the exchange is deterministic and testable.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use super::IcaoError;
use super::sm::{Cipher, Prim, SecureChannel, cbc_decrypt, cbc_encrypt, ct_eq, mac8, pad};
use crate::scan::apdu::{Command, Response};

pub struct BacKeys {
    pub k_enc: Zeroizing<[u8; 16]>,
    pub k_mac: Zeroizing<[u8; 16]>,
}

/// Set the low bit of each byte so it has odd parity (3DES key parity).
fn adjust_parity(key: &mut [u8]) {
    for b in key {
        let ones = (*b >> 1).count_ones();
        *b = (*b & 0xFE) | u8::from(ones % 2 == 0);
    }
}

/// Key derivation (9303-11, 9.7.1): SHA-1(seed || counter), first 16 bytes,
/// with parity adjusted. Counter 1 for encryption, 2 for MAC.
fn kdf(seed: &[u8], counter: u32) -> Zeroizing<[u8; 16]> {
    let mut d = Zeroizing::new(Vec::with_capacity(seed.len() + 4));
    d.extend_from_slice(seed);
    d.extend_from_slice(&counter.to_be_bytes());
    let h = Sha1::digest(&*d);
    let mut k = Zeroizing::new([0u8; 16]);
    k.copy_from_slice(&h[..16]);
    adjust_parity(&mut *k);
    k
}

/// BAC keys from the MRZ seed input (`Mrz::bac_key_seed_input`).
pub fn derive_bac_keys(seed_input: &str) -> BacKeys {
    let h = Sha1::digest(seed_input.as_bytes());
    let mut kseed = Zeroizing::new([0u8; 16]);
    kseed.copy_from_slice(&h[..16]);
    BacKeys {
        k_enc: kdf(&*kseed, 1),
        k_mac: kdf(&*kseed, 2),
    }
}

pub struct BacExchange {
    keys: BacKeys,
    rnd_icc: [u8; 8],
    rnd_ifd: [u8; 8],
    k_ifd: Zeroizing<[u8; 16]>,
}

impl BacExchange {
    pub fn new(keys: BacKeys, rnd_icc: [u8; 8], rnd_ifd: [u8; 8], k_ifd: [u8; 16]) -> Self {
        BacExchange {
            keys,
            rnd_icc,
            rnd_ifd,
            k_ifd: Zeroizing::new(k_ifd),
        }
    }

    /// EXTERNAL AUTHENTICATE (really MUTUAL AUTHENTICATE): E.IFD || M.IFD.
    pub fn external_authenticate(&self) -> Command {
        let mut s = Zeroizing::new([0u8; 32]);
        s[..8].copy_from_slice(&self.rnd_ifd);
        s[8..16].copy_from_slice(&self.rnd_icc);
        s[16..].copy_from_slice(&*self.k_ifd);
        let prim = Prim::new(Cipher::TripleDes, &*self.keys.k_enc).expect("16-byte key");
        cbc_encrypt(&prim, &[0u8; 8], &mut *s);
        let mut m_in = Zeroizing::new(s.to_vec());
        pad(&mut m_in, 8);
        let m = mac8(Cipher::TripleDes, &*self.keys.k_mac, &m_in).expect("16-byte key");
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&*s);
        data.extend_from_slice(&m);
        Command {
            cla: 0x00,
            ins: 0x82,
            p1: 0x00,
            p2: 0x00,
            data,
            le: Some(40),
        }
    }

    /// Check the chip's answer (E.ICC || M.ICC), recover K.ICC and derive
    /// the session keys and SSC.
    pub fn finish(self, resp: &Response) -> Result<SecureChannel, IcaoError> {
        if !resp.ok() {
            return Err(match resp.sw {
                0x6300 | 0x6982 | 0x6985 | 0x6A80 => IcaoError::AccessDenied,
                sw => IcaoError::Chip(sw),
            });
        }
        if resp.data.len() != 40 {
            return Err(IcaoError::Protocol("BAC answer has the wrong length"));
        }
        let (e_icc, m_icc) = resp.data.split_at(32);
        let mut m_in = Zeroizing::new(e_icc.to_vec());
        pad(&mut m_in, 8);
        let expect = mac8(Cipher::TripleDes, &*self.keys.k_mac, &m_in)?;
        if !ct_eq(&expect, m_icc) {
            return Err(IcaoError::BadMac);
        }
        let prim = Prim::new(Cipher::TripleDes, &*self.keys.k_enc)?;
        let mut r = Zeroizing::new(e_icc.to_vec());
        cbc_decrypt(&prim, &[0u8; 8], &mut r);
        // RND.ICC then RND.IFD echo back, then K.ICC.
        if !ct_eq(&r[..8], &self.rnd_icc) || !ct_eq(&r[8..16], &self.rnd_ifd) {
            return Err(IcaoError::Protocol("BAC randoms do not match"));
        }
        let mut seed = Zeroizing::new([0u8; 16]);
        for (i, b) in seed.iter_mut().enumerate() {
            *b = self.k_ifd[i] ^ r[16 + i];
        }
        let ks_enc = kdf(&*seed, 1);
        let ks_mac = kdf(&*seed, 2);
        let mut ssc = [0u8; 8];
        ssc[..4].copy_from_slice(&self.rnd_icc[4..]);
        ssc[4..].copy_from_slice(&self.rnd_ifd[4..]);
        SecureChannel::new(Cipher::TripleDes, &*ks_enc, &*ks_mac, &ssc)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    fn exchange() -> BacExchange {
        let keys = derive_bac_keys(text("text_mrz_info"));
        BacExchange::new(
            keys,
            fx("rnd_icc").try_into().unwrap(),
            fx("rnd_ifd").try_into().unwrap(),
            fx("k_ifd").try_into().unwrap(),
        )
    }

    #[test]
    fn bac_keys_appendix_d() {
        let k = derive_bac_keys(text("text_mrz_info"));
        assert_eq!(hex(&*k.k_enc), hex(&fx("k_enc")));
        assert_eq!(hex(&*k.k_mac), hex(&fx("k_mac")));
        assert_eq!(
            hex(&*k.k_enc).to_lowercase(),
            "ab94fdecf2674fdfb9b391f85d7f76f2"
        );
        assert_eq!(
            hex(&*k.k_mac).to_lowercase(),
            "7962d9ece03d1acd4c76089dce131543"
        );
    }

    #[test]
    fn bac_keys_have_odd_parity() {
        let k = derive_bac_keys(text("text_mrz_info"));
        for b in k.k_enc.iter().chain(k.k_mac.iter()) {
            assert_eq!(b.count_ones() % 2, 1);
        }
    }

    #[test]
    fn bac_external_authenticate_appendix_d() {
        let cmd = exchange().external_authenticate();
        assert_eq!(hex(&cmd.to_bytes()), hex(&fx("ext_auth_apdu")));
        assert_eq!(&cmd.data[..32], &fx("e_ifd")[..]);
        assert_eq!(&cmd.data[32..], &fx("m_ifd")[..]);
    }

    #[test]
    fn bac_mutual_auth_appendix_d() {
        let resp = Response {
            data: fx("ext_auth_resp_data"),
            sw: 0x9000,
        };
        let ch = exchange().finish(&resp).unwrap();
        assert_eq!(hex(ch.ks_enc()), hex(&fx("ks_enc")));
        assert_eq!(hex(ch.ks_mac()), hex(&fx("ks_mac")));
        assert_eq!(hex(ch.ssc()), hex(&fx("ssc0")));
        // K.ICC and KSseed: K.IFD xor K.ICC.
        let seed: Vec<u8> = fx("k_ifd")
            .iter()
            .zip(fx("k_icc"))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(hex(&seed), hex(&fx("ks_seed")));
    }

    #[test]
    fn bac_finish_rejects_tampered_mac() {
        let mut d = fx("ext_auth_resp_data");
        d[39] ^= 1;
        let r = Response {
            data: d,
            sw: 0x9000,
        };
        assert_eq!(exchange().finish(&r).err(), Some(IcaoError::BadMac));
    }

    #[test]
    fn bac_finish_rejects_wrong_rnd_echo() {
        // Valid chip answer, but this exchange used another RND.IFD.
        let keys = derive_bac_keys(text("text_mrz_info"));
        let ex = BacExchange::new(
            keys,
            fx("rnd_icc").try_into().unwrap(),
            [9; 8],
            fx("k_ifd").try_into().unwrap(),
        );
        let r = Response {
            data: fx("ext_auth_resp_data"),
            sw: 0x9000,
        };
        assert!(matches!(ex.finish(&r), Err(IcaoError::Protocol(_))));
    }

    #[test]
    fn bac_finish_maps_status_words() {
        let denied = Response {
            data: vec![],
            sw: 0x6300,
        };
        assert_eq!(
            exchange().finish(&denied).err(),
            Some(IcaoError::AccessDenied)
        );
        let other = Response {
            data: vec![],
            sw: 0x6D00,
        };
        assert_eq!(
            exchange().finish(&other).err(),
            Some(IcaoError::Chip(0x6D00))
        );
        let short = Response {
            data: vec![1; 5],
            sw: 0x9000,
        };
        assert!(matches!(
            exchange().finish(&short),
            Err(IcaoError::Protocol(_))
        ));
    }
}
