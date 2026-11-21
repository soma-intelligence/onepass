//! Decoding of EF.COM, DG1 (MRZ) and DG2 (portrait) read from a chip.
//!
//! The portrait is identity data: nothing here logs it, and `Portrait`'s
//! `Debug` prints only the format and the length.

use std::fmt;

use super::IcaoError;
use crate::scan::mrz::{Mrz, parse_td3};
use crate::scan::tlv;

/// LDS tags of the data groups listed in EF.COM, in file order. These are
/// tags (0x61 = DG1, 0x75 = DG2, 0x63 = DG3), not data group numbers.
pub fn parse_com(b: &[u8]) -> Result<Vec<u8>, IcaoError> {
    let body = tlv::find(b, &[0x60]).ok_or(IcaoError::Protocol("EF.COM has no tag 60"))?;
    let list = tlv::find(body, &[0x5C]).ok_or(IcaoError::Protocol("EF.COM has no tag list"))?;
    Ok(list.to_vec())
}

/// The MRZ held in DG1 (`61` / `5F1F`), TD3 only.
pub fn parse_dg1(b: &[u8]) -> Result<Mrz, IcaoError> {
    let mrz = tlv::find(b, &[0x61, 0x5F1F]).ok_or(IcaoError::Protocol("DG1 has no MRZ"))?;
    if !mrz.is_ascii() || mrz.len() != 88 {
        return Err(IcaoError::Protocol("DG1 MRZ is not TD3"));
    }
    let (l1, l2) = mrz.split_at(44);
    let l1 = std::str::from_utf8(l1).map_err(|_| IcaoError::Protocol("DG1 MRZ is not text"))?;
    let l2 = std::str::from_utf8(l2).map_err(|_| IcaoError::Protocol("DG1 MRZ is not text"))?;
    parse_td3(&[l1, l2]).map_err(|_| IcaoError::Protocol("DG1 MRZ is invalid"))
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

/// Format of an image starting at `rest`, if it begins with a known marker.
fn image_format(rest: &[u8]) -> Option<ImageFormat> {
    if rest.starts_with(&JPEG_SOI) {
        Some(ImageFormat::Jpeg)
    } else if rest.starts_with(&JP2_BOX) || rest.starts_with(&J2K_CODESTREAM) {
        Some(ImageFormat::Jpeg2000)
    } else {
        None
    }
}

/// Image start in an ISO/IEC 19794-5 block, with its format.
///
/// With the `FAC\0` magic the structure is walked: 14-byte general header,
/// 20-byte facial information (feature point count N at offsets 4..6),
/// 8 * N bytes of feature points, 12-byte image information, then the image,
/// which must begin with a known marker. Only when the magic is missing
/// (a non-conforming chip) does it fall back to scanning for the first
/// JPEG, JPEG 2000 or codestream marker.
fn find_image(block: &[u8]) -> Option<(usize, ImageFormat)> {
    if block.starts_with(b"FAC\x00") {
        let count = usize::from(u16::from_be_bytes([*block.get(18)?, *block.get(19)?]));
        let at = 14usize
            .checked_add(20)?
            .checked_add(count.checked_mul(8)?)?
            .checked_add(12)?;
        return image_format(block.get(at..)?).map(|f| (at, f));
    }
    (0..block.len()).find_map(|i| image_format(&block[i..]).map(|f| (i, f)))
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

    /// ISO 19794-5 block: 14-byte general header, 20-byte facial
    /// information with `features` feature points (filled with `fill`),
    /// 12-byte image information, then the image.
    fn face_block_with(image: &[u8], features: usize, fill: &[u8]) -> Vec<u8> {
        let mut v = b"FAC\x00010\x00".to_vec();
        v.extend([0, 0, 0, 0]); // record length (unchecked)
        v.extend([0, 1]); // one face
        let mut info = [0u8; 20];
        info[4..6].copy_from_slice(&(features as u16).to_be_bytes());
        v.extend(info);
        for i in 0..features * 8 {
            v.push(fill[i % fill.len()]);
        }
        v.extend([0u8; 12]);
        v.extend_from_slice(image);
        v
    }

    fn face_block(image: &[u8]) -> Vec<u8> {
        face_block_with(image, 0, &[0])
    }

    fn dg2(block_tag: u32, image: &[u8]) -> Vec<u8> {
        dg2_blocks(&[(block_tag, face_block(image))])
    }

    fn dg2_blocks(blocks: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut inner = tlv::encode(0x02, &[blocks.len() as u8]);
        for (tag, block) in blocks {
            let header = tlv::encode(0xA1, &[0x80, 0x02, 0x01, 0x01]);
            let data = tlv::encode(*tag, block);
            inner.extend(tlv::encode(0x7F60, &[header, data].concat()));
        }
        tlv::encode(0x75, &tlv::encode(0x7F61, &inner))
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

    #[test]
    fn dg1_rejects_non_ascii() {
        // 2-byte char at bytes 43..45, total 88 bytes.
        let mut m = MRZ.as_bytes().to_vec();
        m.splice(43..45, "\u{e9}".bytes());
        assert_eq!(m.len(), 88);
        let dg1 = tlv::encode(0x61, &tlv::encode(0x5F1F, &m));
        assert!(parse_dg1(&dg1).is_err());
    }

    #[test]
    fn dg2_ignores_marker_bytes_inside_header() {
        let img = jpeg();
        let fp = [0xFF, 0xD8, 0xFF, 0xE0, 0x11, 0x22, 0x33, 0x44];
        let block = face_block_with(&img, 2, &fp);
        let p = parse_dg2(&dg2_blocks(&[(0x5F2E, block)])).unwrap();
        assert_eq!(p.bytes, img);
    }

    #[test]
    fn dg2_takes_second_template_when_first_has_no_image() {
        let img = jp2();
        let first = face_block(&[1, 2, 3, 4]);
        let second = face_block(&img);
        let p = parse_dg2(&dg2_blocks(&[(0x5F2E, first), (0x5F2E, second)])).unwrap();
        assert_eq!(p.format, ImageFormat::Jpeg2000);
        assert_eq!(p.bytes, img);
    }

    #[test]
    fn dg2_fac_block_with_bad_marker_is_rejected() {
        // A JPEG marker hidden after a wrong offset must not be found.
        let mut block = face_block(&[0, 0, 0, 0]);
        block.extend(jpeg());
        assert!(parse_dg2(&dg2_blocks(&[(0x5F2E, block)])).is_err());
    }

    #[test]
    fn truncated_inputs_are_errors() {
        let full = dg2(0x5F2E, &jpeg());
        assert!(parse_dg2(&full[..full.len() - 10]).is_err());
        assert!(parse_dg2(&full[..5]).is_err());
        let block = face_block_with(&jpeg(), 0, &[0]);
        assert!(parse_dg2(&dg2_blocks(&[(0x5F2E, block[..20].to_vec())])).is_err());
        let com = tlv::encode(0x60, &tlv::encode(0x5C, &[0x61]));
        assert!(parse_com(&com[..com.len() - 1]).is_err());
        assert!(parse_com(&[]).is_err());
    }
}
