//! CSCA master list (ICAO 9303 part 12): a CMS SignedData whose content is
//! `CscaMasterList { version, certList SET OF Certificate }`, signed by a
//! master list signer that a CSCA of the list issued.
//!
//! Loading checks that signature and keeps the CSCA certificates, indexed
//! by subject key identifier and by subject name for the DS lookup.

use std::collections::{BTreeSet, HashMap};

use x509_cert::der::oid::ObjectIdentifier as Oid;

use super::IcaoError;
use super::passive_auth::{Cert, check_issuer, check_signer, items, only, parse_signed};

const CSCA_MASTER_LIST: Oid = Oid::new_unwrap("2.23.136.1.1.2");

/// The trusted CSCA certificates of a verified master list.
#[derive(Debug, Clone, Default)]
pub struct MasterList {
    certs: Vec<Vec<u8>>,
    by_key_id: HashMap<Vec<u8>, Vec<usize>>,
    by_subject: HashMap<Vec<u8>, Vec<usize>>,
}

impl MasterList {
    /// Number of CSCA certificates kept.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// The `countryName` values (ISO 3166-1 alpha-2, as printed) of the
    /// CSCA subjects, each once.
    pub fn country_codes(&self) -> BTreeSet<String> {
        self.certs
            .iter()
            .filter_map(|der| Cert::parse(der))
            .filter_map(|c| subject_country(c.subject))
            .collect()
    }

    fn add(&mut self, der: &[u8]) -> bool {
        let Some(c) = Cert::parse(der) else {
            return false;
        };
        let i = self.certs.len();
        if let Some(ski) = c.ski {
            self.by_key_id.entry(ski.to_vec()).or_default().push(i);
        }
        self.by_subject
            .entry(c.subject.to_vec())
            .or_default()
            .push(i);
        self.certs.push(der.to_vec());
        true
    }

    /// The CSCAs that may have issued a certificate with this authority key
    /// identifier and issuer name: those whose key identifier matches, then
    /// those whose subject matches, each once. The flag marks a key
    /// identifier match.
    pub(super) fn candidates(&self, aki: Option<&[u8]>, issuer: &[u8]) -> Vec<(&[u8], bool)> {
        let by_key = aki.and_then(|k| self.by_key_id.get(k));
        let by_name = self.by_subject.get(issuer);
        let mut seen = Vec::new();
        let mut out = Vec::new();
        for (ix, key_match) in [(by_key, true), (by_name, false)] {
            for &i in ix.into_iter().flatten() {
                if seen.contains(&i) {
                    continue;
                }
                if let Some(der) = self.certs.get(i) {
                    seen.push(i);
                    out.push((der.as_slice(), key_match));
                }
            }
        }
        out
    }
}

/// The first `countryName` (2.5.4.6) of a DER `Name`.
fn subject_country(name: &[u8]) -> Option<String> {
    const COUNTRY_NAME: [u8; 3] = [0x55, 0x04, 0x06];
    let rdns = items(only(name)?.value)?;
    rdns.iter()
        .filter_map(|rdn| items(rdn.value))
        .flatten()
        .filter_map(|atv| items(atv.value))
        .find_map(|parts| match parts.as_slice() {
            [oid, value] if oid.tag == 0x06 && oid.value == COUNTRY_NAME => {
                std::str::from_utf8(value.value).ok().map(str::to_owned)
            }
            _ => None,
        })
}

/// Loads a CSCA master list: verifies its CMS signature with the signer
/// certificate it carries, and that a CSCA of the list issued that signer.
/// Certificates of the list that do not parse are skipped.
pub fn load_master_list(cms_bytes: &[u8]) -> Result<MasterList, IcaoError> {
    let signed =
        parse_signed(cms_bytes).ok_or(IcaoError::Protocol("master list is not CMS SignedData"))?;
    if signed.econtent_type != CSCA_MASTER_LIST.as_bytes() {
        return Err(IcaoError::Protocol("not a CSCA master list"));
    }
    let malformed = IcaoError::Protocol("malformed CSCA master list");
    let content = only(signed.econtent)
        .filter(|e| e.tag == 0x30)
        .ok_or(malformed)?;
    let parts = items(content.value).ok_or(malformed)?;
    let cert_list = parts
        .get(1)
        .filter(|e| e.tag == 0x31)
        .and_then(|e| items(e.value))
        .ok_or(malformed)?;
    let mut ml = MasterList::default();
    for c in cert_list {
        ml.add(c.raw);
    }
    if ml.is_empty() {
        return Err(IcaoError::Protocol("master list holds no certificate"));
    }
    let (signer, _) = check_signer(&signed)
        .map_err(|_| IcaoError::Protocol("master list signature does not verify"))?;
    check_issuer(&signer, &ml, |_| true)
        .map_err(|_| IcaoError::Protocol("master list signer not issued by a listed CSCA"))?;
    Ok(ml)
}
