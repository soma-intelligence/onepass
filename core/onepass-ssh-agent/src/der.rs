//! Minimal DER reader for the private key structures aws-lc-rs exports:
//! PKCS#8 `PrivateKeyInfo` (RFC 5208) and PKCS#1 `RSAPrivateKey` (RFC 8017).
//!
//! Only definite lengths of up to four bytes are accepted, which covers RSA
//! keys far beyond 16384 bits.

use zeroize::Zeroizing;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;

/// Malformed or unsupported DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerError;

pub(crate) struct DerReader<'a> {
    buf: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Reads one element with the given tag and returns its content.
    pub(crate) fn element(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let (&t, rest) = self.buf.split_first().ok_or(DerError)?;
        if t != tag {
            return Err(DerError);
        }
        let (&first, mut rest) = rest.split_first().ok_or(DerError)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(DerError);
            }
            let (len_bytes, tail) = rest.split_at(n);
            rest = tail;
            if len_bytes[0] == 0 {
                return Err(DerError);
            }
            let len = len_bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if len < 0x80 {
                return Err(DerError);
            }
            len
        };
        if rest.len() < len {
            return Err(DerError);
        }
        let (content, tail) = rest.split_at(len);
        self.buf = tail;
        Ok(content)
    }

    /// Reads a non-negative INTEGER and returns its magnitude without
    /// leading zero bytes.
    pub(crate) fn uint(&mut self) -> Result<&'a [u8], DerError> {
        let c = self.element(TAG_INTEGER)?;
        match c {
            [] => Err(DerError),
            [first, ..] if first & 0x80 != 0 => Err(DerError),
            [0, second, ..] if second & 0x80 == 0 => Err(DerError),
            [0, rest @ ..] => Ok(rest),
            _ => Ok(c),
        }
    }

    pub(crate) fn sequence(&mut self) -> Result<DerReader<'a>, DerError> {
        Ok(DerReader::new(self.element(TAG_SEQUENCE)?))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Returns the `privateKey` OCTET STRING content of a PKCS#8 v1 or v2
/// `PrivateKeyInfo`.
pub(crate) fn pkcs8_private_key(der: &[u8]) -> Result<&[u8], DerError> {
    let mut outer = DerReader::new(der);
    let mut info = outer.sequence()?;
    if !outer.is_empty() {
        return Err(DerError);
    }
    let version = info.uint()?;
    if version.len() > 1 || version.first().is_some_and(|&v| v > 1) {
        return Err(DerError);
    }
    info.sequence()?; // AlgorithmIdentifier
    info.element(TAG_OCTET_STRING)
}

/// Components of a two-prime PKCS#1 `RSAPrivateKey`, big-endian magnitudes.
pub(crate) struct RsaParts {
    pub(crate) n: Vec<u8>,
    pub(crate) e: Vec<u8>,
    pub(crate) d: Zeroizing<Vec<u8>>,
    pub(crate) p: Zeroizing<Vec<u8>>,
    pub(crate) q: Zeroizing<Vec<u8>>,
    pub(crate) iqmp: Zeroizing<Vec<u8>>,
}

/// Parses a two-prime PKCS#1 `RSAPrivateKey` (version 0).
pub(crate) fn rsa_private_key(der: &[u8]) -> Result<RsaParts, DerError> {
    let mut outer = DerReader::new(der);
    let mut seq = outer.sequence()?;
    if !outer.is_empty() {
        return Err(DerError);
    }
    if !seq.uint()?.is_empty() {
        return Err(DerError); // multi-prime (version 1) keys are not used by SSH
    }
    let n = seq.uint()?.to_vec();
    let e = seq.uint()?.to_vec();
    let d = Zeroizing::new(seq.uint()?.to_vec());
    let p = Zeroizing::new(seq.uint()?.to_vec());
    let q = Zeroizing::new(seq.uint()?.to_vec());
    seq.uint()?; // dP, recomputed when needed
    seq.uint()?; // dQ
    let iqmp = Zeroizing::new(seq.uint()?.to_vec());
    if !seq.is_empty() {
        return Err(DerError);
    }
    Ok(RsaParts {
        n,
        e,
        d,
        p,
        q,
        iqmp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    fn int(v: &[u8]) -> Vec<u8> {
        if v.first().is_some_and(|b| b & 0x80 != 0) {
            let mut c = vec![0];
            c.extend_from_slice(v);
            tlv(TAG_INTEGER, &c)
        } else {
            tlv(TAG_INTEGER, v)
        }
    }

    fn rsa_der(version: u8, extra: &[u8]) -> Vec<u8> {
        let mut body = int(&[version]);
        if version == 0 {
            body = tlv(TAG_INTEGER, &[0]);
        }
        for v in [
            &[0xC1u8; 200][..],
            &[0x01, 0x00, 0x01],
            &[0x55; 190],
            &[0xE1; 100],
            &[0xD1; 100],
            &[0x11; 99],
            &[0x22; 99],
            &[0x33; 98],
        ] {
            body.extend(int(v));
        }
        body.extend_from_slice(extra);
        tlv(TAG_SEQUENCE, &body)
    }

    #[test]
    fn parses_rsa_private_key() {
        let parts = rsa_private_key(&rsa_der(0, &[])).unwrap();
        assert_eq!(parts.n, vec![0xC1; 200]);
        assert_eq!(parts.e, vec![1, 0, 1]);
        assert_eq!(*parts.d, vec![0x55; 190]);
        assert_eq!(*parts.p, vec![0xE1; 100]);
        assert_eq!(*parts.q, vec![0xD1; 100]);
        assert_eq!(*parts.iqmp, vec![0x33; 98]);
    }

    #[test]
    fn rejects_bad_rsa_private_key() {
        assert!(rsa_private_key(&rsa_der(1, &[])).is_err());
        assert!(rsa_private_key(&rsa_der(0, &int(&[1]))).is_err());
        let good = rsa_der(0, &[]);
        for cut in 0..good.len() {
            assert!(rsa_private_key(&good[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(rsa_private_key(&trailing).is_err());
    }

    #[test]
    fn unwraps_pkcs8() {
        let alg = tlv(TAG_SEQUENCE, &tlv(0x06, &[0x2b, 0x65, 0x70]));
        let mut body = int(&[0]);
        body.extend(alg);
        body.extend(tlv(TAG_OCTET_STRING, b"inner"));
        let der = tlv(TAG_SEQUENCE, &body);
        assert_eq!(pkcs8_private_key(&der).unwrap(), b"inner");
        assert!(pkcs8_private_key(&der[..der.len() - 1]).is_err());
    }

    #[test]
    fn rejects_non_minimal_encodings() {
        // Long-form length for a short element.
        assert!(
            DerReader::new(&[0x02, 0x81, 0x01, 0x05])
                .element(0x02)
                .is_err()
        );
        // Negative and padded integers.
        assert!(DerReader::new(&[0x02, 0x01, 0x80]).uint().is_err());
        assert!(DerReader::new(&[0x02, 0x02, 0x00, 0x05]).uint().is_err());
        assert_eq!(
            DerReader::new(&[0x02, 0x02, 0x00, 0x80]).uint().unwrap(),
            &[0x80]
        );
    }
}
