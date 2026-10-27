//! Native messaging framing (spec section 5): a 32-bit length in native
//! byte order, then that many bytes of JSON.

use std::io::{ErrorKind, Read, Write};

use crate::{BridgeError, Result};

/// OnePass frame ceiling in both directions: 1 MiB.
pub const MAX_FRAME: usize = 1_048_576;

/// Read one frame. `Ok(None)` is a clean end of stream between frames.
/// A longer-than-`MAX_FRAME` header is refused before the body is read.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut got = 0;
    while got < header.len() {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(BridgeError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Native byte order per the native messaging protocol; every supported
    // target (Apple, x86, ARM) is little-endian.
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(BridgeError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            BridgeError::Truncated
        } else {
            e.into()
        }
    })?;
    Ok(Some(body))
}

/// Write one frame (length prefix, payload) and flush.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(BridgeError::FrameTooLarge(payload.len()));
    }
    // MAX_FRAME fits in u32, checked above.
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"v\":1}").unwrap();
        assert_eq!(buf, framed(b"{\"v\":1}"));
        let got = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(got.as_deref(), Some(&b"{\"v\":1}"[..]));
    }

    #[test]
    fn max_len_ok() {
        let payload = vec![b'a'; MAX_FRAME];
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let got = read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
        assert_eq!(got.len(), MAX_FRAME);
    }

    #[test]
    fn write_refuses_over_max() {
        let payload = vec![0u8; MAX_FRAME + 1];
        let mut buf = Vec::new();
        assert_eq!(
            write_frame(&mut buf, &payload),
            Err(BridgeError::FrameTooLarge(MAX_FRAME + 1))
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn too_large_rejected_without_reading_body() {
        let mut data = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 64]);
        let mut c = Cursor::new(data);
        assert_eq!(
            read_frame(&mut c),
            Err(BridgeError::FrameTooLarge(MAX_FRAME + 1))
        );
        assert_eq!(c.position(), 4);
    }

    #[test]
    fn truncated_header() {
        assert_eq!(
            read_frame(&mut Cursor::new(vec![1u8, 0])),
            Err(BridgeError::Truncated)
        );
    }

    #[test]
    fn truncated_body() {
        let mut data = framed(b"hello");
        data.truncate(data.len() - 1);
        assert_eq!(
            read_frame(&mut Cursor::new(data)),
            Err(BridgeError::Truncated)
        );
    }

    #[test]
    fn empty_stream_is_none() {
        assert_eq!(read_frame(&mut Cursor::new(Vec::new())), Ok(None));
    }

    #[test]
    fn two_frames_in_a_row() {
        let mut data = framed(b"one");
        data.extend(framed(b"second"));
        let mut c = Cursor::new(data);
        assert_eq!(read_frame(&mut c).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut c).unwrap().unwrap(), b"second");
        assert_eq!(read_frame(&mut c), Ok(None));
    }

    #[test]
    fn zero_length_frame() {
        let mut c = Cursor::new(framed(b""));
        assert_eq!(read_frame(&mut c).unwrap().unwrap(), b"");
    }
}
