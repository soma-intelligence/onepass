//! The frame of a pairing stream (spec 2b 5.5): a big-endian `u32` length,
//! then that many bytes. The same framing as `LocalNetworkPairingTransport`
//! on the Swift side and as the T-RDV stream of `onepass-mailbox`.

use std::io::{self, Read, Write};

use crate::{MAX_FRAME, PairnetError};

/// What the first read allocates at most, before bytes actually arrive: a
/// peer that announces a large frame and sends nothing costs no memory.
const READ_STEP: usize = 64 << 10;

/// Writes one frame. Above `MAX_FRAME` is `FrameTooLarge`, before anything
/// is written.
pub(crate) fn write_frame<W: Write>(w: &mut W, frame: &[u8]) -> Result<(), PairnetError> {
    if frame.len() > MAX_FRAME {
        return Err(PairnetError::FrameTooLarge);
    }
    let len = (frame.len() as u32).to_be_bytes();
    if frame.len() <= READ_STEP {
        // One write for a small frame: no half-sent header on the wire.
        let mut packet = Vec::with_capacity(4 + frame.len());
        packet.extend_from_slice(&len);
        packet.extend_from_slice(frame);
        w.write_all(&packet).map_err(io_error)?;
    } else {
        w.write_all(&len).map_err(io_error)?;
        w.write_all(frame).map_err(io_error)?;
    }
    w.flush().map_err(io_error)
}

/// Reads one frame of at most `min(max, MAX_FRAME)` bytes. A longer length
/// is `FrameTooLarge` before any of its body is read. The stream ending
/// anywhere (header included) is `Closed`.
pub(crate) fn read_frame<R: Read>(r: &mut R, max: usize) -> Result<Vec<u8>, PairnetError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).map_err(io_error)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > max.min(MAX_FRAME) {
        return Err(PairnetError::FrameTooLarge);
    }
    let mut body = Vec::with_capacity(len.min(READ_STEP));
    let read = r
        .take(len as u64)
        .read_to_end(&mut body)
        .map_err(io_error)?;
    if read != len {
        return Err(PairnetError::Closed);
    }
    Ok(body)
}

/// A socket error as the transport contract names it: the other side gone
/// is `Closed`, a read or write past its timeout `Timeout`.
pub(crate) fn io_error(e: io::Error) -> PairnetError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PairnetError::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected => PairnetError::Closed,
        _ => PairnetError::Io(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_HANDSHAKE_FRAME;

    #[test]
    fn round_trip_and_cut() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"abc").unwrap();
        write_frame(&mut buf, &[9u8; READ_STEP + 1]).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 16).unwrap(), b"abc");
        assert_eq!(
            read_frame(&mut r, MAX_FRAME).unwrap(),
            vec![9u8; READ_STEP + 1]
        );
        assert_eq!(read_frame(&mut r, 16), Err(PairnetError::Closed));
        let mut cut = &buf[..5];
        assert_eq!(read_frame(&mut cut, 16), Err(PairnetError::Closed));
    }

    #[test]
    fn cap_checked_before_the_body() {
        // The header claims 4 GiB; the reader stops at the header.
        let mut r = &[0xff, 0xff, 0xff, 0xff][..];
        assert_eq!(
            read_frame(&mut r, usize::MAX),
            Err(PairnetError::FrameTooLarge)
        );
        let header = ((MAX_HANDSHAKE_FRAME + 1) as u32).to_be_bytes();
        let mut r = &header[..];
        assert_eq!(
            read_frame(&mut r, MAX_HANDSHAKE_FRAME),
            Err(PairnetError::FrameTooLarge)
        );
        let header = (MAX_HANDSHAKE_FRAME as u32).to_be_bytes();
        let mut r = &header[..];
        // At the cap: accepted, then the missing body is a closed stream.
        assert_eq!(
            read_frame(&mut r, MAX_HANDSHAKE_FRAME),
            Err(PairnetError::Closed)
        );
    }
}
