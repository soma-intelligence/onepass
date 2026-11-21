//! Secure messaging (ICAO 9303-11, 9.8): 3DES and AES channels.
//!
//! 3DES (BAC): two-key 3DES in CBC with a zero IV, ISO 9797-1 MAC algorithm
//! 3 (retail MAC) over padded input. AES (PACE): AES-CBC with IV =
//! AES(KSenc, SSC), AES-CMAC truncated to 8 bytes. Padding is ISO 9797-1
//! method 2 in both. The MAC input is always SSC || padded header ||
//! protected objects, padded again.
//!
//! Keys, session keys, the send sequence counter and every buffer holding
//! plaintext or MAC input are zeroized on drop.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};
use des::{Des, TdesEde2};
use zeroize::Zeroizing;

use super::IcaoError;
use crate::scan::apdu::{Command, Response};
use crate::scan::tlv;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    TripleDes,
    Aes128,
    Aes192,
    Aes256,
}

impl Cipher {
    pub(super) fn block_size(self) -> usize {
        match self {
            Cipher::TripleDes => 8,
            _ => 16,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Cipher::TripleDes | Cipher::Aes128 => 16,
            Cipher::Aes192 => 24,
            Cipher::Aes256 => 32,
        }
    }
}

/// A block cipher keyed once, used for CBC and the single-block IV.
pub(super) enum Prim {
    Tdes(TdesEde2),
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

macro_rules! each {
    ($self:expr, $c:ident => $body:expr) => {
        match $self {
            Prim::Tdes($c) => $body,
            Prim::A128($c) => $body,
            Prim::A192($c) => $body,
            Prim::A256($c) => $body,
        }
    };
}

impl Prim {
    pub(super) fn new(cipher: Cipher, key: &[u8]) -> Result<Self, IcaoError> {
        if key.len() != cipher.key_len() {
            return Err(IcaoError::Crypto);
        }
        let bad = |_| IcaoError::Crypto;
        Ok(match cipher {
            Cipher::TripleDes => Prim::Tdes(TdesEde2::new_from_slice(key).map_err(bad)?),
            Cipher::Aes128 => Prim::A128(Aes128::new_from_slice(key).map_err(bad)?),
            Cipher::Aes192 => Prim::A192(Aes192::new_from_slice(key).map_err(bad)?),
            Cipher::Aes256 => Prim::A256(Aes256::new_from_slice(key).map_err(bad)?),
        })
    }

    fn enc_block(&self, blk: &mut [u8]) {
        each!(self, c => c.encrypt_block(blk.try_into().expect("block size")))
    }

    fn dec_block(&self, blk: &mut [u8]) {
        each!(self, c => c.decrypt_block(blk.try_into().expect("block size")))
    }
}

/// CBC encryption in place; `buf` is a whole number of blocks.
pub(super) fn cbc_encrypt(p: &Prim, iv: &[u8], buf: &mut [u8]) {
    let bs = iv.len();
    let mut prev = Zeroizing::new(iv.to_vec());
    for blk in buf.chunks_exact_mut(bs) {
        for (b, v) in blk.iter_mut().zip(prev.iter()) {
            *b ^= v;
        }
        p.enc_block(blk);
        prev.copy_from_slice(blk);
    }
}

/// CBC decryption in place; `buf` is a whole number of blocks.
pub(super) fn cbc_decrypt(p: &Prim, iv: &[u8], buf: &mut [u8]) {
    let bs = iv.len();
    let mut prev = Zeroizing::new(iv.to_vec());
    let mut cur = Zeroizing::new(vec![0u8; bs]);
    for blk in buf.chunks_exact_mut(bs) {
        cur.copy_from_slice(blk);
        p.dec_block(blk);
        for (b, v) in blk.iter_mut().zip(prev.iter()) {
            *b ^= v;
        }
        prev.copy_from_slice(&cur);
    }
}

/// ISO 9797-1 padding method 2: `0x80` then zeros up to the block size.
pub(super) fn pad(v: &mut Vec<u8>, bs: usize) {
    v.push(0x80);
    while !v.len().is_multiple_of(bs) {
        v.push(0);
    }
}

/// Undo method 2 padding; `None` when it is malformed.
fn unpad(v: &[u8]) -> Option<&[u8]> {
    let end = v.iter().rposition(|&b| b != 0)?;
    (v[end] == 0x80).then(|| &v[..end])
}

/// 8-byte MAC over `padded` (already padded to the block size).
pub(super) fn mac8(cipher: Cipher, key: &[u8], padded: &[u8]) -> Result<[u8; 8], IcaoError> {
    let mut out = [0u8; 8];
    match cipher {
        Cipher::TripleDes => {
            // ISO 9797-1 algorithm 3: single DES CBC with K1, then decrypt
            // with K2 and encrypt with K1 on the last block.
            if key.len() != 16 {
                return Err(IcaoError::Crypto);
            }
            let k1 = Des::new_from_slice(&key[..8]).map_err(|_| IcaoError::Crypto)?;
            let k2 = Des::new_from_slice(&key[8..]).map_err(|_| IcaoError::Crypto)?;
            let mut h = Zeroizing::new([0u8; 8]);
            for blk in padded.as_chunks::<8>().0 {
                for (a, b) in h.iter_mut().zip(blk) {
                    *a ^= b;
                }
                k1.encrypt_block((&mut *h).into());
            }
            k2.decrypt_block((&mut *h).into());
            k1.encrypt_block((&mut *h).into());
            out = *h;
        }
        _ => {
            macro_rules! cmac8 {
                ($t:ty) => {{
                    let mut m = <Cmac<$t> as KeyInit>::new_from_slice(key)
                        .map_err(|_| IcaoError::Crypto)?;
                    m.update(padded);
                    let t = m.finalize().into_bytes();
                    out.copy_from_slice(&t[..8]);
                }};
            }
            match cipher {
                Cipher::Aes128 if key.len() == 16 => cmac8!(Aes128),
                Cipher::Aes192 if key.len() == 24 => cmac8!(Aes192),
                Cipher::Aes256 if key.len() == 32 => cmac8!(Aes256),
                _ => return Err(IcaoError::Crypto),
            }
        }
    }
    Ok(out)
}

/// Constant-time equality for MACs.
pub(super) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

pub struct SecureChannel {
    cipher: Cipher,
    ks_enc: Zeroizing<Vec<u8>>,
    ks_mac: Zeroizing<Vec<u8>>,
    ssc: Zeroizing<Vec<u8>>,
    /// INS of the last wrapped command: an odd one is answered in DO85,
    /// an even one in DO87.
    odd_ins: bool,
}

impl std::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureChannel({:?})", self.cipher)
    }
}

impl SecureChannel {
    /// `ks_enc` and `ks_mac` have the cipher's key length (16 for 3DES),
    /// `ssc` the block size (8 for 3DES, 16 for AES).
    pub fn new(
        cipher: Cipher,
        ks_enc: &[u8],
        ks_mac: &[u8],
        ssc: &[u8],
    ) -> Result<Self, IcaoError> {
        if ks_enc.len() != cipher.key_len()
            || ks_mac.len() != cipher.key_len()
            || ssc.len() != cipher.block_size()
        {
            return Err(IcaoError::Crypto);
        }
        Ok(SecureChannel {
            cipher,
            ks_enc: Zeroizing::new(ks_enc.to_vec()),
            ks_mac: Zeroizing::new(ks_mac.to_vec()),
            ssc: Zeroizing::new(ssc.to_vec()),
            odd_ins: false,
        })
    }

    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    #[cfg(test)]
    pub(crate) fn ks_enc(&self) -> &[u8] {
        &self.ks_enc
    }

    #[cfg(test)]
    pub(crate) fn ks_mac(&self) -> &[u8] {
        &self.ks_mac
    }

    #[cfg(test)]
    pub(crate) fn ssc(&self) -> &[u8] {
        &self.ssc
    }

    fn increment_ssc(&mut self) {
        for b in self.ssc.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// CBC IV for the current SSC: zero for 3DES, AES(KSenc, SSC) for AES.
    fn iv(&self, prim: &Prim) -> Zeroizing<Vec<u8>> {
        match self.cipher {
            Cipher::TripleDes => Zeroizing::new(vec![0u8; 8]),
            _ => {
                let mut iv = Zeroizing::new(self.ssc.to_vec());
                prim.enc_block(&mut iv);
                iv
            }
        }
    }

    /// MAC over SSC || `body`, padded.
    fn mac(&self, body: &[u8]) -> Result<[u8; 8], IcaoError> {
        let mut input = Zeroizing::new(Vec::with_capacity(self.ssc.len() + body.len() + 16));
        input.extend_from_slice(&self.ssc);
        input.extend_from_slice(body);
        pad(&mut input, self.cipher.block_size());
        mac8(self.cipher, &self.ks_mac, &input)
    }

    /// Protect a command: increments the SSC, encrypts the data into
    /// DO87, encodes Le as DO97 and appends the MAC as DO8E.
    pub fn wrap(&mut self, cmd: &Command) -> Command {
        self.increment_ssc();
        self.odd_ins = cmd.ins & 1 == 1;
        let bs = self.cipher.block_size();
        let prim = Prim::new(self.cipher, &self.ks_enc).expect("lengths checked in new");
        let header = [cmd.cla | 0x0C, cmd.ins, cmd.p1, cmd.p2];

        let mut dos = Zeroizing::new(Vec::new());
        if !cmd.data.is_empty() {
            let mut buf = Zeroizing::new(cmd.data.clone());
            pad(&mut buf, bs);
            cbc_encrypt(&prim, &self.iv(&prim), &mut buf);
            if cmd.ins & 1 == 1 {
                // Odd INS (READ BINARY B1): the data is BER-TLV, so it goes
                // in DO85, without the padding-content indicator.
                dos.extend_from_slice(&tlv::encode(0x85, &buf));
            } else {
                let mut v = Zeroizing::new(Vec::with_capacity(buf.len() + 1));
                v.push(0x01);
                v.extend_from_slice(&buf);
                dos.extend_from_slice(&tlv::encode(0x87, &v));
            }
        }
        if let Some(le) = cmd.le {
            // Le above 256 (extended length) is out of P1 scope.
            let v: Vec<u8> = if le > 256 {
                le.to_be_bytes().to_vec()
            } else {
                vec![if le == 256 { 0 } else { le as u8 }]
            };
            dos.extend_from_slice(&tlv::encode(0x97, &v));
        }

        let mut body = Zeroizing::new(header.to_vec());
        pad(&mut body, bs);
        body.extend_from_slice(&dos);
        let mac = self.mac(&body).expect("lengths checked in new");

        let mut data = std::mem::take(&mut *dos);
        data.extend_from_slice(&[0x8E, 0x08]);
        data.extend_from_slice(&mac);
        Command {
            cla: header[0],
            ins: cmd.ins,
            p1: cmd.p1,
            p2: cmd.p2,
            data,
            le: Some(256),
        }
    }

    /// Verify the MAC (DO8E) of a protected response, then decrypt DO87
    /// (answer to an even INS) or DO85 (answer to an odd INS, without
    /// padding-content indicator; the INS is the last one wrapped) and read
    /// the status from DO99. The MAC is checked before
    /// any decryption.
    ///
    /// A response with no data is an unprotected chip answer: its status is
    /// returned as `Chip(sw)` (a `9000` with nothing in it is a protocol
    /// error, since a protected answer always carries DO99 and DO8E).
    pub fn unwrap(&mut self, resp: &Response) -> Result<Response, IcaoError> {
        if resp.data.is_empty() {
            return Err(if resp.ok() {
                IcaoError::Protocol("response has no secure messaging objects")
            } else {
                IcaoError::Chip(resp.sw)
            });
        }
        self.increment_ssc();

        let data = &resp.data[..];
        let mut rest = data;
        let mut do87: Option<(&[u8], &[u8], bool)> = None; // (raw, value, DO85)
        let mut do99: Option<(&[u8], &[u8])> = None;
        let mut do8e: Option<&[u8]> = None;
        let mut stage = 0u8;
        while !rest.is_empty() {
            let start = data.len() - rest.len();
            let (t, after) =
                tlv::parse_one(rest).map_err(|_| IcaoError::Protocol("malformed response"))?;
            let raw = &data[start..data.len() - after.len()];
            // The only valid order is DO87 or DO85 (optional), DO99, DO8E,
            // each once.
            match t.tag {
                0x87 if stage == 0 && !self.odd_ins => do87 = Some((raw, t.value, false)),
                0x85 if stage == 0 && self.odd_ins => do87 = Some((raw, t.value, true)),
                0x99 if stage <= 1 => do99 = Some((raw, t.value)),
                0x8E if stage == 2 => do8e = Some(t.value),
                _ => return Err(IcaoError::Protocol("unexpected object in response")),
            }
            stage = match t.tag {
                0x85 | 0x87 => 1,
                0x99 => 2,
                _ => 3,
            };
            rest = after;
        }
        let (raw99, v99) = do99.ok_or(IcaoError::Protocol("missing status object"))?;
        let mac = do8e.ok_or(IcaoError::Protocol("missing MAC object"))?;
        if v99.len() != 2 || mac.len() != 8 {
            return Err(IcaoError::Protocol("malformed response"));
        }

        let mut body = Zeroizing::new(Vec::new());
        if let Some((raw87, _, _)) = do87 {
            body.extend_from_slice(raw87);
        }
        body.extend_from_slice(raw99);
        let expect = self.mac(&body)?;
        if !ct_eq(&expect, mac) {
            return Err(IcaoError::BadMac);
        }

        let plain = match do87 {
            None => Vec::new(),
            Some((_, v, is85)) => {
                let bs = self.cipher.block_size();
                let ct = if is85 {
                    v
                } else {
                    if v.first() != Some(&0x01) {
                        return Err(IcaoError::Protocol("malformed encrypted data"));
                    }
                    &v[1..]
                };
                if ct.is_empty() || !ct.len().is_multiple_of(bs) {
                    return Err(IcaoError::Protocol("malformed encrypted data"));
                }
                let prim = Prim::new(self.cipher, &self.ks_enc)?;
                let mut buf = Zeroizing::new(ct.to_vec());
                cbc_decrypt(&prim, &self.iv(&prim), &mut buf);
                unpad(&buf)
                    .ok_or(IcaoError::Protocol("bad padding"))?
                    .to_vec()
            }
        };
        Ok(Response {
            data: plain,
            sw: u16::from_be_bytes([v99[0], v99[1]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    fn channel() -> SecureChannel {
        SecureChannel::new(Cipher::TripleDes, &fx("ks_enc"), &fx("ks_mac"), &fx("ssc0")).unwrap()
    }

    fn plain(name: &str, le: Option<u16>) -> Command {
        let b = fx(name);
        Command {
            cla: b[0],
            ins: b[1],
            p1: b[2],
            p2: b[3],
            data: if b.len() > 5 { b[5..].to_vec() } else { vec![] },
            le,
        }
    }

    #[test]
    fn sm_wrap_select_appendix_d() {
        let mut ch = channel();
        let w = ch.wrap(&plain("select_plain", None));
        assert_eq!(hex(&w.to_bytes()), hex(&fx("select_protected")));
        assert_eq!(hex(ch.ssc()), "887022120C06C227");
    }

    #[test]
    fn sm_appendix_d_chain_select_then_read_binary() {
        // SELECT EF.COM at SSC ...27, the chip's protected answer at ...28,
        // READ BINARY at ...29 and its answer at ...2A, all as printed in D.4.
        let mut ch = channel();
        let w = ch.wrap(&plain("select_plain", None));
        assert_eq!(hex(&w.to_bytes()), hex(&fx("select_protected")));
        let raw = fx("select_resp_protected");
        let ans = ch.unwrap(&Response::parse(&raw).unwrap()).unwrap();
        assert!(ans.data.is_empty());
        assert_eq!(ans.sw, 0x9000);
        assert_eq!(hex(ch.ssc()), "887022120C06C228");
        let w = ch.wrap(&plain("read_plain", Some(4)));
        assert_eq!(hex(&w.to_bytes()), hex(&fx("read_protected")));
        assert_eq!(hex(ch.ssc()), "887022120C06C229");
        let raw = fx("read_resp_protected");
        let out = ch.unwrap(&Response::parse(&raw).unwrap()).unwrap();
        assert_eq!(hex(&out.data), hex(&fx("read_resp_plain")));
        assert_eq!(out.sw, 0x9000);
        assert_eq!(hex(ch.ssc()), "887022120C06C22A");
    }

    fn at_read_answer() -> SecureChannel {
        SecureChannel::new(
            Cipher::TripleDes,
            &fx("ks_enc"),
            &fx("ks_mac"),
            &unhex("887022120C06C229"),
        )
        .unwrap()
    }

    #[test]
    fn sm_unwrap_appendix_d_response() {
        let mut ch = at_read_answer();
        let raw = fx("read_resp_protected");
        let out = ch.unwrap(&Response::parse(&raw).unwrap()).unwrap();
        assert_eq!(hex(&out.data), hex(&fx("read_resp_plain")));
    }

    #[test]
    fn sm_unwrap_rejects_bad_mac() {
        let mut ch = at_read_answer();
        let mut raw = fx("read_resp_protected");
        let n = raw.len();
        raw[n - 3] ^= 0x01; // last MAC byte, before the 9000
        let r = Response::parse(&raw).unwrap();
        assert_eq!(ch.unwrap(&r).err(), Some(IcaoError::BadMac));
    }

    #[test]
    fn sm_unwrap_rejects_tampered_ciphertext_before_decrypting() {
        let mut ch = at_read_answer();
        let mut raw = fx("read_resp_protected");
        raw[5] ^= 0x80;
        let r = Response::parse(&raw).unwrap();
        assert_eq!(ch.unwrap(&r).err(), Some(IcaoError::BadMac));
    }

    #[test]
    fn sm_unwrap_status_only_responses() {
        let mut ch = channel();
        // Bare status word, no data: an unprotected chip error.
        let r = Response {
            data: vec![],
            sw: 0x6982,
        };
        assert_eq!(ch.unwrap(&r).err(), Some(IcaoError::Chip(0x6982)));
        // Bare 9000 with no protection objects is not a valid SM answer.
        let r = Response {
            data: vec![],
            sw: 0x9000,
        };
        assert!(matches!(ch.unwrap(&r), Err(IcaoError::Protocol(_))));
    }

    #[test]
    fn sm_unwrap_rejects_misordered_objects() {
        // DO99 before DO87: the official answer's objects, swapped.
        let mut ch = at_read_answer();
        let raw = fx("read_resp_protected");
        let r = Response::parse(&raw).unwrap();
        let (d87, rest) = crate::scan::tlv::parse_one(&r.data).unwrap();
        let n87 = r.data.len() - rest.len();
        let _ = d87;
        let mut data = rest[..4].to_vec(); // DO99
        data.extend_from_slice(&r.data[..n87]);
        data.extend_from_slice(&rest[4..]);
        let bad = Response { data, sw: 0x9000 };
        assert!(matches!(ch.unwrap(&bad), Err(IcaoError::Protocol(_))));
        // DO8E before DO99.
        let mut ch = at_read_answer();
        let mut data = r.data[..n87].to_vec();
        data.extend_from_slice(&rest[4..]);
        data.extend_from_slice(&rest[..4]);
        let bad = Response { data, sw: 0x9000 };
        assert!(matches!(ch.unwrap(&bad), Err(IcaoError::Protocol(_))));
    }

    #[test]
    fn sm_unwrap_without_do87_is_valid() {
        // Chip answer to SELECT: DO99 + DO8E only. Build it with the
        // channel's own keys through the independent reference below.
        let mut ch = channel();
        let _ = ch.wrap(&plain("select_plain", None)); // SSC -> C227
        let resp =
            reference::chip_response(Cipher::TripleDes, &fx("ks_enc"), &fx("ks_mac"), &ch, None);
        let out = ch.unwrap(&resp).unwrap();
        assert!(out.data.is_empty());
        assert_eq!(out.sw, 0x9000);
    }

    #[test]
    fn sm_ssc_increments_per_message() {
        let mut ch = channel();
        let start = ch.ssc().to_vec();
        for round in 0..2u8 {
            let _ = ch.wrap(&plain("select_plain", None));
            let resp = reference::chip_response(
                Cipher::TripleDes,
                &fx("ks_enc"),
                &fx("ks_mac"),
                &ch,
                Some(&[round, 1, 2]),
            );
            let out = ch.unwrap(&resp).unwrap();
            assert_eq!(out.data, vec![round, 1, 2]);
        }
        // Two wrap/unwrap rounds: SSC + 4.
        let mut expect = u64::from_be_bytes(start.try_into().unwrap());
        expect += 4;
        assert_eq!(ch.ssc(), &expect.to_be_bytes());
    }

    #[test]
    fn sm_rejects_bad_key_lengths() {
        assert_eq!(
            SecureChannel::new(Cipher::TripleDes, &[0; 8], &[0; 16], &[0; 8]).err(),
            Some(IcaoError::Crypto)
        );
        assert_eq!(
            SecureChannel::new(Cipher::Aes128, &[0; 16], &[0; 16], &[0; 8]).err(),
            Some(IcaoError::Crypto)
        );
    }

    /// Independent reference built on the `cbc` and `cmac` crates (the
    /// channel itself uses hand-rolled CBC), standing in for the chip when
    /// no ICAO vector exists (the AES channel).
    mod reference {
        use super::*;
        use aes::{Aes128, Aes192, Aes256};
        use cbc::cipher::block_padding::NoPadding;
        use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
        use cmac::{Cmac, Mac};

        fn pad(mut v: Vec<u8>, bs: usize) -> Vec<u8> {
            v.push(0x80);
            while !v.len().is_multiple_of(bs) {
                v.push(0);
            }
            v
        }

        fn cbc_enc<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8>
        where
            C: cbc::cipher::BlockCipherEncrypt + cbc::cipher::KeyInit,
        {
            let mut buf = data.to_vec();
            let n = buf.len();
            cbc::Encryptor::<C>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded::<NoPadding>(&mut buf, n)
                .unwrap();
            buf
        }

        fn cbc_dec<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8>
        where
            C: cbc::cipher::BlockCipherDecrypt + cbc::cipher::KeyInit,
        {
            let mut buf = data.to_vec();
            cbc::Decryptor::<C>::new_from_slices(key, iv)
                .unwrap()
                .decrypt_padded::<NoPadding>(&mut buf)
                .unwrap();
            buf
        }

        pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
            match key.len() {
                16 => cbc_enc::<Aes128>(key, iv, data),
                24 => cbc_enc::<Aes192>(key, iv, data),
                _ => cbc_enc::<Aes256>(key, iv, data),
            }
        }

        pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
            match key.len() {
                16 => cbc_dec::<Aes128>(key, iv, data),
                24 => cbc_dec::<Aes192>(key, iv, data),
                _ => cbc_dec::<Aes256>(key, iv, data),
            }
        }

        pub fn aes_cmac8(key: &[u8], msg: &[u8]) -> Vec<u8> {
            let t = match key.len() {
                16 => Mac::finalize({
                    let mut m = <Cmac<Aes128> as cmac::KeyInit>::new_from_slice(key).unwrap();
                    m.update(msg);
                    m
                })
                .into_bytes()
                .to_vec(),
                24 => Mac::finalize({
                    let mut m = <Cmac<Aes192> as cmac::KeyInit>::new_from_slice(key).unwrap();
                    m.update(msg);
                    m
                })
                .into_bytes()
                .to_vec(),
                _ => Mac::finalize({
                    let mut m = <Cmac<Aes256> as cmac::KeyInit>::new_from_slice(key).unwrap();
                    m.update(msg);
                    m
                })
                .into_bytes()
                .to_vec(),
            };
            t[..8].to_vec()
        }

        /// What an AES chip would answer, given the channel's current SSC
        /// (already incremented by the wrap of the command).
        pub fn aes_chip_response(
            ks_enc: &[u8],
            ks_mac: &[u8],
            ssc_after_cmd: &[u8],
            data: Option<&[u8]>,
        ) -> Response {
            let mut ssc = u128::from_be_bytes(ssc_after_cmd.try_into().unwrap());
            ssc += 1;
            let ssc = ssc.to_be_bytes();
            let mut body = Vec::new();
            if let Some(d) = data {
                let iv = aes_cbc_encrypt(ks_enc, &[0; 16], &ssc);
                // IV = E(ks_enc, SSC): one ECB block == CBC with zero IV.
                let ct = aes_cbc_encrypt(ks_enc, &iv, &pad(d.to_vec(), 16));
                let mut v = vec![0x01];
                v.extend_from_slice(&ct);
                body.extend_from_slice(&crate::scan::tlv::encode(0x87, &v));
            }
            body.extend_from_slice(&[0x99, 0x02, 0x90, 0x00]);
            let mut mi = ssc.to_vec();
            mi.extend_from_slice(&body);
            let mac = aes_cmac8(ks_mac, &pad(mi, 16));
            body.extend_from_slice(&[0x8E, 0x08]);
            body.extend_from_slice(&mac);
            Response {
                data: body,
                sw: 0x9000,
            }
        }

        pub fn chip_response(
            cipher: Cipher,
            ks_enc: &[u8],
            ks_mac: &[u8],
            ch: &SecureChannel,
            data: Option<&[u8]>,
        ) -> Response {
            match cipher {
                Cipher::TripleDes => tdes_chip_response(ks_enc, ks_mac, ch.ssc(), data),
                _ => aes_chip_response(ks_enc, ks_mac, ch.ssc(), data),
            }
        }

        /// 3DES chip side via the `des` and `cbc` crates plus a textbook
        /// ISO 9797-1 MAC alg 3 written out here.
        fn tdes_chip_response(
            ks_enc: &[u8],
            ks_mac: &[u8],
            ssc_after_cmd: &[u8],
            data: Option<&[u8]>,
        ) -> Response {
            use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt};
            use des::{Des, TdesEde2};
            let ssc = (u64::from_be_bytes(ssc_after_cmd.try_into().unwrap()) + 1).to_be_bytes();
            let mut body = Vec::new();
            if let Some(d) = data {
                let ct = cbc_enc::<TdesEde2>(ks_enc, &[0; 8], &pad(d.to_vec(), 8));
                let mut v = vec![0x01];
                v.extend_from_slice(&ct);
                body.extend_from_slice(&crate::scan::tlv::encode(0x87, &v));
            }
            body.extend_from_slice(&[0x99, 0x02, 0x90, 0x00]);
            let mut mi = ssc.to_vec();
            mi.extend_from_slice(&body);
            let mi = pad(mi, 8);
            let k1 = Des::new_from_slice(&ks_mac[..8]).unwrap();
            let k2 = Des::new_from_slice(&ks_mac[8..]).unwrap();
            let mut h = [0u8; 8];
            for blk in mi.chunks(8) {
                for i in 0..8 {
                    h[i] ^= blk[i];
                }
                k1.encrypt_block((&mut h).into());
            }
            k2.decrypt_block((&mut h).into());
            k1.encrypt_block((&mut h).into());
            body.extend_from_slice(&[0x8E, 0x08]);
            body.extend_from_slice(&h);
            Response {
                data: body,
                sw: 0x9000,
            }
        }
    }

    fn aes_pair(key_len: usize, cipher: Cipher) -> (SecureChannel, Vec<u8>, Vec<u8>) {
        let ke: Vec<u8> = (0..key_len as u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(1))
            .collect();
        let km: Vec<u8> = (0..key_len as u8)
            .map(|i| i.wrapping_mul(11).wrapping_add(3))
            .collect();
        (
            SecureChannel::new(cipher, &ke, &km, &[0u8; 16]).unwrap(),
            ke,
            km,
        )
    }

    #[test]
    fn aes_channel_wrap_matches_reference_for_all_sizes() {
        for (len, c) in [
            (16, Cipher::Aes128),
            (24, Cipher::Aes192),
            (32, Cipher::Aes256),
        ] {
            let (mut ch, ke, km) = aes_pair(len, c);
            let cmd = Command {
                cla: 0x00,
                ins: 0xA4,
                p1: 0x02,
                p2: 0x0C,
                data: vec![0x01, 0x1E],
                le: None,
            };
            let w = ch.wrap(&cmd);
            assert_eq!(w.cla, 0x0C);
            // SSC went 0 -> 1.
            let mut ssc = [0u8; 16];
            ssc[15] = 1;
            assert_eq!(ch.ssc(), &ssc);
            // Parse DOs.
            let (d87, rest) = crate::scan::tlv::parse_one(&w.data).unwrap();
            assert_eq!(d87.tag, 0x87);
            let (d8e, rest) = crate::scan::tlv::parse_one(rest).unwrap();
            assert_eq!(d8e.tag, 0x8E);
            assert!(rest.is_empty());
            // MAC over SSC || padded header || DO87, padded.
            let mut mi = ssc.to_vec();
            mi.extend_from_slice(&[0x0C, 0xA4, 0x02, 0x0C]);
            mi.extend_from_slice(&[0x80; 1]);
            mi.extend_from_slice(&[0; 11]);
            mi.extend_from_slice(&crate::scan::tlv::encode(0x87, d87.value));
            mi = pad_for_test(mi, 16);
            assert_eq!(d8e.value, &reference::aes_cmac8(&km, &mi)[..]);
            // Ciphertext decrypts (IV = E(SSC)) to padded plaintext.
            assert_eq!(d87.value[0], 0x01);
            let iv = reference::aes_cbc_encrypt(&ke, &[0; 16], &ssc);
            let pt = reference::aes_cbc_decrypt(&ke, &iv, &d87.value[1..]);
            assert_eq!(&pt[..2], &[0x01, 0x1E]);
            assert_eq!(pt[2], 0x80);
            assert_eq!(pt.len(), 16);
            // And a chip answer unwraps.
            let resp = reference::aes_chip_response(&ke, &km, ch.ssc(), Some(b"hello passport"));
            let out = ch.unwrap(&resp).unwrap();
            assert_eq!(out.data, b"hello passport");
            // Tamper: bad MAC.
            let _ = ch.wrap(&cmd);
            let mut bad = reference::aes_chip_response(&ke, &km, ch.ssc(), Some(b"x"));
            let n = bad.data.len();
            bad.data[n - 1] ^= 1;
            assert_eq!(ch.unwrap(&bad).err(), Some(IcaoError::BadMac));
        }
    }

    fn pad_for_test(mut v: Vec<u8>, bs: usize) -> Vec<u8> {
        v.push(0x80);
        while !v.len().is_multiple_of(bs) {
            v.push(0);
        }
        v
    }

    #[test]
    fn aes_cmac_rfc4493_sanity() {
        // RFC 4493 example 2 (16-byte message), guards the reference itself.
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = unhex("6bc1bee22e409f96e93d7e117393172a");
        use cmac::{Cmac, Mac};
        let mut m = <Cmac<aes::Aes128> as cmac::KeyInit>::new_from_slice(&key).unwrap();
        m.update(&msg);
        assert_eq!(
            hex(&m.finalize().into_bytes()),
            "070A16B46B4D4144F79BDD9DD04A287C"
        );
    }

    #[test]
    fn odd_ins_uses_do85_both_ways() {
        let (mut ch, ke, km) = aes_pair(16, Cipher::Aes128);
        let cmd = Command {
            cla: 0x00,
            ins: 0xB1,
            p1: 0x00,
            p2: 0x00,
            data: vec![0x54, 0x02, 0x80, 0x00],
            le: Some(0xE3),
        };
        let w = ch.wrap(&cmd);
        let (d85, rest) = crate::scan::tlv::parse_one(&w.data).unwrap();
        assert_eq!(d85.tag, 0x85);
        assert_eq!(d85.value.len(), 16, "no padding-content indicator");
        let mut ssc = [0u8; 16];
        ssc[15] = 1;
        let iv = reference::aes_cbc_encrypt(&ke, &[0; 16], &ssc);
        let pt = reference::aes_cbc_decrypt(&ke, &iv, d85.value);
        assert_eq!(&pt[..5], &[0x54, 0x02, 0x80, 0x00, 0x80]);
        let (d97, rest) = crate::scan::tlv::parse_one(rest).unwrap();
        assert_eq!((d97.tag, d97.value), (0x97, &[0xE3][..]));
        let (d8e, _) = crate::scan::tlv::parse_one(rest).unwrap();
        let mut mi = ssc.to_vec();
        mi.extend_from_slice(&pad_for_test(vec![0x0C, 0xB1, 0x00, 0x00], 16));
        mi.extend_from_slice(&w.data[..w.data.len() - 10]);
        assert_eq!(
            d8e.value,
            &reference::aes_cmac8(&km, &pad_for_test(mi, 16))[..]
        );

        // A DO85 answer (SSC 2): ciphertext without the 01 byte.
        ssc[15] = 2;
        let iv = reference::aes_cbc_encrypt(&ke, &[0; 16], &ssc);
        let plain = [0x53, 0x03, 7, 8, 9];
        let ct = reference::aes_cbc_encrypt(&ke, &iv, &pad_for_test(plain.to_vec(), 16));
        let mut body = crate::scan::tlv::encode(0x85, &ct);
        body.extend_from_slice(&[0x99, 0x02, 0x90, 0x00]);
        let mut mi = ssc.to_vec();
        mi.extend_from_slice(&body);
        let mac = reference::aes_cmac8(&km, &pad_for_test(mi, 16));
        body.extend_from_slice(&[0x8E, 0x08]);
        body.extend_from_slice(&mac);
        let out = ch
            .unwrap(&Response {
                data: body,
                sw: 0x9000,
            })
            .unwrap();
        assert_eq!(out.data, plain);
    }

    #[test]
    fn crypto_object_must_match_the_ins_parity() {
        let (mut ch, ke, km) = aes_pair(16, Cipher::Aes128);
        let even = Command {
            cla: 0x00,
            ins: 0xB0,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(4),
        };
        let odd = Command {
            cla: 0x00,
            ins: 0xB1,
            p1: 0x00,
            p2: 0x00,
            data: vec![0x54, 0x02, 0x80, 0x00],
            le: Some(7),
        };
        // Odd INS answered with DO87: refused.
        let _ = ch.wrap(&odd);
        let r = reference::aes_chip_response(&ke, &km, ch.ssc(), Some(&[0x53, 0x01, 9]));
        assert!(matches!(ch.unwrap(&r), Err(IcaoError::Protocol(_))));
        // Even INS answered with DO85: refused.
        let (mut ch, ke, km) = aes_pair(16, Cipher::Aes128);
        let _ = ch.wrap(&even);
        let mut ssc = [0u8; 16];
        ssc[15] = 2;
        let iv = reference::aes_cbc_encrypt(&ke, &[0; 16], &ssc);
        let ct = reference::aes_cbc_encrypt(&ke, &iv, &pad_for_test(vec![1, 2, 3, 4], 16));
        let mut body = crate::scan::tlv::encode(0x85, &ct);
        body.extend_from_slice(&[0x99, 0x02, 0x90, 0x00]);
        let mut mi = ssc.to_vec();
        mi.extend_from_slice(&body);
        let mac = reference::aes_cmac8(&km, &pad_for_test(mi, 16));
        body.extend_from_slice(&[0x8E, 0x08]);
        body.extend_from_slice(&mac);
        let r = Response {
            data: body,
            sw: 0x9000,
        };
        assert!(matches!(ch.unwrap(&r), Err(IcaoError::Protocol(_))));
        // The even INS with DO87 still unwraps.
        let (mut ch, ke, km) = aes_pair(16, Cipher::Aes128);
        let _ = ch.wrap(&even);
        let r = reference::aes_chip_response(&ke, &km, ch.ssc(), Some(&[1, 2, 3, 4]));
        assert_eq!(ch.unwrap(&r).unwrap().data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn wrap_with_le_adds_do97() {
        let mut ch = channel();
        let w = ch.wrap(&plain("read_plain", Some(4)));
        assert_eq!(&w.data[..3], &[0x97, 0x01, 0x04]);
    }
}
