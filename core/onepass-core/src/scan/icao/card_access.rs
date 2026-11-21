//! EF.CardAccess (ICAO 9303-11, 9.2): the SecurityInfos the chip offers
//! before any access control. Only the PACEInfo entries are kept.

use x509_cert::der::oid::ObjectIdentifier;

use super::IcaoError;
use crate::scan::tlv;

/// id-PACE (0.4.0.127.0.7.2.2.4) in DER content octets.
const ID_PACE: [u8; 8] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04];

const MALFORMED: IcaoError = IcaoError::Protocol("card-access-malformed");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaceInfo {
    pub oid: ObjectIdentifier,
    pub parameter_id: u8,
}

/// A small non-negative DER INTEGER, if it fits a byte.
fn small_int(v: &[u8]) -> Option<u8> {
    match v {
        [b] if *b < 0x80 => Some(*b),
        [0x00, b] if *b >= 0x80 => Some(*b),
        _ => None,
    }
}

/// Parse EF.CardAccess (`SecurityInfos ::= SET OF SecurityInfo`) and
/// return its PACEInfo entries: protocol under id-PACE, version 2 and a
/// parameterId. Other SecurityInfos (PACEDomainParameterInfo, Chip
/// Authentication, unknown ones) and PACEInfos without a standardized
/// parameterId are skipped. Bytes after the SET (file padding) are ignored.
pub fn parse_card_access(b: &[u8]) -> Result<Vec<PaceInfo>, IcaoError> {
    let (set, _) = tlv::parse_one(b).map_err(|_| MALFORMED)?;
    if set.tag != 0x31 {
        return Err(MALFORMED);
    }
    let mut out = Vec::new();
    let mut rest = set.value;
    while !rest.is_empty() {
        let (info, after) = tlv::parse_one(rest).map_err(|_| MALFORMED)?;
        rest = after;
        if info.tag != 0x30 {
            return Err(MALFORMED);
        }
        let (oid, fields) = tlv::parse_one(info.value).map_err(|_| MALFORMED)?;
        if oid.tag != 0x06 {
            return Err(MALFORMED);
        }
        if !oid.value.starts_with(&ID_PACE) {
            continue;
        }
        // PACEInfo: version INTEGER (2), then parameterId INTEGER.
        // PACEDomainParameterInfo has a SEQUENCE here and is skipped.
        let Ok((version, fields)) = tlv::parse_one(fields) else {
            return Err(MALFORMED);
        };
        if version.tag != 0x02 || small_int(version.value) != Some(2) {
            continue;
        }
        let Ok((param, _)) = tlv::parse_one(fields) else {
            continue;
        };
        let Some(parameter_id) = (param.tag == 0x02)
            .then(|| small_int(param.value))
            .flatten()
        else {
            continue;
        };
        let oid = ObjectIdentifier::from_bytes(oid.value).map_err(|_| MALFORMED)?;
        out.push(PaceInfo { oid, parameter_id });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::icao::pace::tests::g1;
    use crate::scan::icao::testutil::unhex;
    use crate::scan::tlv;

    /// EF.CardAccess is `SecurityInfos ::= SET OF SecurityInfo` (9.2), so
    /// the appendix G.1 PACEInfo goes inside a SET (tag 31).
    fn card_access_g1() -> Vec<u8> {
        tlv::encode(0x31, &unhex(&g1("pace_info")))
    }

    #[test]
    fn card_access_parses_pace_info() {
        let infos = parse_card_access(&card_access_g1()).unwrap();
        assert_eq!(
            infos,
            vec![PaceInfo {
                oid: ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.2.2"),
                parameter_id: 13,
            }]
        );
    }

    #[test]
    fn card_access_skips_other_security_infos() {
        // A ChipAuthenticationInfo (id-CA-ECDH-AES-CBC-CMAC-128, version 1)
        // next to the PACEInfo: only the PACEInfo comes back.
        let ca = unhex("300F060A04007F00070202030202020101");
        let mut set = ca;
        set.extend_from_slice(&unhex(&g1("pace_info")));
        let infos = parse_card_access(&tlv::encode(0x31, &set)).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].parameter_id, 13);
    }

    #[test]
    fn card_access_rejects_garbage() {
        assert!(matches!(
            parse_card_access(&[0x31, 0x05, 0x30]),
            Err(IcaoError::Protocol(_))
        ));
        assert!(matches!(
            parse_card_access(&unhex(&g1("pace_info"))),
            Err(IcaoError::Protocol(_))
        ));
    }
}
