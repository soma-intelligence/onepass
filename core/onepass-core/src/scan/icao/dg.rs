//! Decoding of EF.COM, DG1 (MRZ) and DG2 (portrait) read from a chip.
//!
//! The portrait is identity data: nothing here logs it, and `Portrait`'s
//! `Debug` prints only the format and the length.

use std::fmt;

use super::IcaoError;
use crate::scan::mrz::{Mrz, parse_td3};
use crate::scan::tlv;

/// Tags of the data groups listed in EF.COM, in file order.
pub fn parse_com(b: &[u8]) -> Result<Vec<u8>, IcaoError> {
    let body = tlv::find(b, &[0x60]).ok_or(IcaoError::Protocol("EF.COM has no tag 60"))?;
    let list = tlv::find(body, &[0x5C]).ok_or(IcaoError::Protocol("EF.COM has no tag list"))?;
    Ok(list.to_vec())
}

/// The MRZ held in DG1 (`61` / `5F1F`), TD3 only.
pub fn parse_dg1(b: &[u8]) -> Result<Mrz, IcaoError> {
    let mrz = tlv::find(b, &[0x61, 0x5F1F]).ok_or(IcaoError::Protocol("DG1 has no MRZ"))?;
    let text = std::str::from_utf8(mrz).map_err(|_| IcaoError::Protocol("DG1 MRZ is not text"))?;
    if text.len() != 88 {
        return Err(IcaoError::Protocol("DG1 MRZ is not TD3"));
    }
    parse_td3(&[&text[..44], &text[44..]]).map_err(|_| IcaoError::Protocol("DG1 MRZ is invalid"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Jpeg,
    Jpeg2000,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Portrait {
    pub format: ImageFormat,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Portrait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Portrait({:?}, {} bytes)", self.format, self.bytes.len())
    }
}

const JPEG_SOI: [u8; 3] = [0xFF, 0xD8, 0xFF];
const JP2_BOX: [u8; 12] = [
    0, 0, 0, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
];
const J2K_CODESTREAM: [u8; 4] = [0xFF, 0x4F, 0xFF, 0x51];

/// First image start in an ISO 19794-5 block, with its format.
fn find_image(block: &[u8]) -> Option<(usize, ImageFormat)> {
    (0..block.len()).find_map(|i| {
        let rest = &block[i..];
        if rest.starts_with(&JPEG_SOI) {
            Some((i, ImageFormat::Jpeg))
        } else if rest.starts_with(&JP2_BOX) || rest.starts_with(&J2K_CODESTREAM) {
            Some((i, ImageFormat::Jpeg2000))
        } else {
            None
        }
    })
}

/// The portrait held in DG2 (`75` / `7F61` / `7F60` / `5F2E` or `7F2E`).
pub fn parse_dg2(b: &[u8]) -> Result<Portrait, IcaoError> {
    let group = tlv::find(b, &[0x75, 0x7F61]).ok_or(IcaoError::Protocol("DG2 has no template"))?;
    let mut cur = group;
    while !cur.is_empty() {
        let (el, after) =
            tlv::parse_one(cur).map_err(|_| IcaoError::Protocol("DG2 is malformed"))?;
        cur = after;
        if el.tag != 0x7F60 {
            continue;
        }
        let block = tlv::find(el.value, &[0x5F2E]).or_else(|| tlv::find(el.value, &[0x7F2E]));
        let Some(block) = block else { continue };
        if let Some((at, format)) = find_image(block) {
            return Ok(Portrait {
                format,
                bytes: block[at..].to_vec(),
            });
        }
    }
    Err(IcaoError::Protocol("DG2 has no image"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MRZ: &str =
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    fn jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00];
        v.extend((0..40u8).map(|i| i.wrapping_mul(7)));
        v.extend([0xFF, 0xD9]);
        v
    }

    fn jp2() -> Vec<u8> {
        let mut v = JP2_BOX.to_vec();
        v.extend([
            0, 0, 0, 0x14, b'f', b't', b'y', b'p', b'j', b'p', b'2', b' ',
        ]);
        v.extend((0..30u8).map(|i| i ^ 0x5A));
        v
    }

    /// ISO 19794-5 block: "FAC\0" header, facial header, one feature-free
    /// image info record, then the image.
    fn face_block(image: &[u8]) -> Vec<u8> {
        let mut v = b"FAC\x00010\x00".to_vec();
        v.extend([0, 0, 0, 0, 0, 0, 0, 1]); // length (ignored) + face count
        v.extend([0u8; 20]); // facial header, image info
        v.extend_from_slice(image);
        v
    }

    fn dg2(block_tag: u32, image: &[u8]) -> Vec<u8> {
        let bit = tlv::encode(
            0x7F60,
            &[
                tlv::encode(0xA1, &[0x80, 0x02, 0x01, 0x01]).as_slice(),
                tlv::encode(block_tag, &face_block(image)).as_slice(),
            ]
            .concat(),
        );
        let group = tlv::encode(0x7F61, &[tlv::encode(0x02, &[1]), bit].concat());
        tlv::encode(0x75, &group)
    }

    #[test]
    fn com_lists_dg1_dg2() {
        let body = [
            tlv::encode(0x5F01, b"0107"),
            tlv::encode(0x5F36, b"040000"),
            tlv::encode(0x5C, &[0x61, 0x75, 0x63]),
        ]
        .concat();
        let com = tlv::encode(0x60, &body);
        assert_eq!(parse_com(&com).unwrap(), vec![0x61, 0x75, 0x63]);
        assert!(parse_com(&tlv::encode(0x60, &[])).is_err());
    }

    #[test]
    fn dg1_gives_specimen_mrz() {
        let dg1 = tlv::encode(0x61, &tlv::encode(0x5F1F, MRZ.as_bytes()));
        let m = parse_dg1(&dg1).unwrap();
        assert_eq!(m.surname, "ERIKSSON");
        assert_eq!(m.given_names, "ANNA MARIA");
        assert_eq!(m.document_number, "L898902C3");
        let short = tlv::encode(0x61, &tlv::encode(0x5F1F, &MRZ.as_bytes()[..72]));
        assert!(parse_dg1(&short).is_err());
    }

    #[test]
    fn dg2_extracts_jpeg() {
        let img = jpeg();
        for tag in [0x5F2E, 0x7F2E] {
            let p = parse_dg2(&dg2(tag, &img)).unwrap();
            assert_eq!(p.format, ImageFormat::Jpeg);
            assert_eq!(p.bytes, img);
            assert_eq!(&p.bytes[..2], &[0xFF, 0xD8]);
            assert_eq!(&p.bytes[p.bytes.len() - 2..], &[0xFF, 0xD9]);
        }
    }

    #[test]
    fn dg2_extracts_jp2() {
        let img = jp2();
        let p = parse_dg2(&dg2(0x5F2E, &img)).unwrap();
        assert_eq!(p.format, ImageFormat::Jpeg2000);
        assert_eq!(p.bytes, img);
        let raw = [J2K_CODESTREAM.to_vec(), vec![1, 2, 3]].concat();
        let p = parse_dg2(&dg2(0x5F2E, &raw)).unwrap();
        assert_eq!(p.format, ImageFormat::Jpeg2000);
        assert_eq!(p.bytes, raw);
    }

    #[test]
    fn dg2_rejects_no_image() {
        assert!(parse_dg2(&dg2(0x5F2E, &[1, 2, 3, 4])).is_err());
        assert!(parse_dg2(&tlv::encode(0x75, &[])).is_err());
    }

    #[test]
    fn portrait_debug_hides_bytes() {
        let p = Portrait {
            format: ImageFormat::Jpeg,
            bytes: vec![0xDE, 0xAD, 0xBE],
        };
        let s = format!("{p:?}");
        assert!(s.contains("3 bytes") && !s.contains("222") && !s.contains("DE"));
    }
}
