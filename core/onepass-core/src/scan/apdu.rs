//! ISO 7816-4 command and response APDUs for reading a chip.
//!
//! Never log or print the bytes: they carry the holder's data.

use std::fmt;

/// ICAO LDS application.
pub const AID_EMRTD: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

pub const EF_CARD_ACCESS: u16 = 0x011C;
pub const EF_COM: u16 = 0x011E;
pub const EF_SOD: u16 = 0x011D;
pub const EF_DG1: u16 = 0x0101;
pub const EF_DG2: u16 = 0x0102;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// A response shorter than its two status bytes.
    TooShort,
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("response APDU is shorter than its status word")
    }
}

impl std::error::Error for ApduError {}

/// A command APDU.
#[derive(Clone, PartialEq, Eq)]
pub struct Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    /// Expected response length. In the short form `Some(0)` and
    /// `Some(256)` both mean 256 bytes and encode `00`. Values above 256, or
    /// data above 255 bytes, switch the command to the extended form, where
    /// `Some(0)` is invalid (it would encode `0000`, which means 65536) and
    /// is rejected by a `debug_assert!`. Data is limited to 65535 bytes.
    pub le: Option<u16>,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Command(ins {:02X})", self.ins)
    }
}

impl Command {
    /// Short form, or extended form when the data or Le need it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.cla, self.ins, self.p1, self.p2];
        debug_assert!(self.data.len() <= 65535, "APDU data over 65535 bytes");
        let extended = self.data.len() > 255 || self.le.is_some_and(|l| l > 256);
        if extended {
            debug_assert!(self.le != Some(0), "Le 0 is invalid in the extended form");
            if !self.data.is_empty() {
                out.push(0x00);
                out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                if self.data.is_empty() {
                    out.push(0x00);
                }
                out.extend_from_slice(&le.to_be_bytes());
            }
        } else {
            if !self.data.is_empty() {
                out.push(self.data.len() as u8);
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                out.push(if le >= 256 { 0x00 } else { le as u8 });
            }
        }
        out
    }

    /// SELECT an elementary file by id (no response data).
    pub fn select_ef(fid: u16) -> Self {
        Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x02,
            p2: 0x0C,
            data: fid.to_be_bytes().to_vec(),
            le: None,
        }
    }

    /// SELECT an application by AID (no response data).
    pub fn select_applet(aid: &[u8]) -> Self {
        Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: aid.to_vec(),
            le: None,
        }
    }

    /// READ BINARY at `offset` (15 bits), asking for `len` bytes; 0 asks
    /// for 256.
    pub fn read_binary(offset: u16, len: u8) -> Self {
        Command {
            cla: 0x00,
            ins: 0xB0,
            p1: (offset >> 8) as u8 & 0x7F,
            p2: offset as u8,
            data: Vec::new(),
            le: Some(if len == 0 { 256 } else { u16::from(len) }),
        }
    }

    /// GET CHALLENGE: 8 random bytes from the chip.
    pub fn get_challenge() -> Self {
        Command {
            cla: 0x00,
            ins: 0x84,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: Some(8),
        }
    }
}

/// A response APDU: data and the status word.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Response(sw {:04X})", self.sw)
    }
}

impl Response {
    pub fn parse(b: &[u8]) -> Result<Self, ApduError> {
        if b.len() < 2 {
            return Err(ApduError::TooShort);
        }
        let (data, sw) = b.split_at(b.len() - 2);
        Ok(Response {
            data: data.to_vec(),
            sw: u16::from_be_bytes([sw[0], sw[1]]),
        })
    }

    /// `9000`, or `6282` (file ended before Le bytes: the data is valid,
    /// the end of file was reached).
    pub fn ok(&self) -> bool {
        self.sw == 0x9000 || self.sw == 0x6282
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_read_binary_bytes() {
        assert_eq!(
            Command::read_binary(0x0010, 0xE0).to_bytes(),
            vec![0x00, 0xB0, 0x00, 0x10, 0xE0]
        );
        // Offset high bit is dropped, len 0 means 256 (sent as 00).
        assert_eq!(
            Command::read_binary(0x8123, 0).to_bytes(),
            vec![0x00, 0xB0, 0x01, 0x23, 0x00]
        );
    }

    #[test]
    fn apdu_select_applet_bytes() {
        assert_eq!(
            Command::select_applet(&AID_EMRTD).to_bytes(),
            vec![
                0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01
            ]
        );
        assert_eq!(
            Command::select_ef(EF_COM).to_bytes(),
            vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E]
        );
        assert_eq!(
            Command::get_challenge().to_bytes(),
            vec![0x00, 0x84, 0x00, 0x00, 0x08]
        );
    }

    #[test]
    fn apdu_le_256_short_form() {
        let c = Command {
            cla: 0,
            ins: 0xB0,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(256),
        };
        assert_eq!(c.to_bytes(), vec![0x00, 0xB0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn apdu_le_zero_means_256_short_form() {
        let c = Command {
            cla: 0,
            ins: 0xB0,
            p1: 0,
            p2: 0,
            data: Vec::new(),
            le: Some(0),
        };
        assert_eq!(c.to_bytes(), vec![0x00, 0xB0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn apdu_extended_forms() {
        let c = Command {
            cla: 0,
            ins: 0x2A,
            p1: 0,
            p2: 0,
            data: vec![7; 300],
            le: Some(0x200),
        };
        let b = c.to_bytes();
        assert_eq!(&b[..7], &[0, 0x2A, 0, 0, 0x00, 0x01, 0x2C]);
        assert_eq!(&b[b.len() - 2..], &[0x02, 0x00]);
    }

    #[test]
    fn response_parse() {
        let r = Response::parse(&[1, 2, 3, 0x90, 0x00]).unwrap();
        assert_eq!(r.data, vec![1, 2, 3]);
        assert!(r.ok());
        assert_eq!(Response::parse(&[0x90]), Err(ApduError::TooShort));
        assert!(!Response::parse(&[0x69, 0x82]).unwrap().ok());
    }

    #[test]
    fn response_6282_is_ok() {
        assert!(Response::parse(&[0x62, 0x82]).unwrap().ok());
    }

    #[test]
    fn debug_hides_bytes() {
        let r = Response::parse(&[0xDE, 0xAD, 0x90, 0x00]).unwrap();
        assert!(!format!("{r:?}").to_uppercase().contains("DE"));
    }
}
