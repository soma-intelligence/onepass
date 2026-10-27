//! ssh-agent wire protocol (draft-miller-ssh-agent).
//!
//! A message is a `u32` big-endian length followed by that many bytes: one
//! type byte and the type-specific contents. Field encodings follow RFC 4251
//! section 5 (`byte`, `uint32`, `string`, `mpint`).

use std::io::{self, Read};

use zeroize::Zeroizing;

/// Largest message body accepted from a client (spec 6.2: 256 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

/// `SSH_AGENT_FAILURE`.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS`.
pub const SSH_AGENT_SUCCESS: u8 = 6;
/// `SSH_AGENTC_REQUEST_IDENTITIES`.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST`.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE`.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENTC_ADD_IDENTITY`.
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
/// `SSH_AGENTC_REMOVE_IDENTITY`.
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
/// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`.
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
/// `SSH_AGENTC_ADD_SMARTCARD_KEY`.
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
/// `SSH_AGENTC_REMOVE_SMARTCARD_KEY`.
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
/// `SSH_AGENTC_LOCK`.
pub const SSH_AGENTC_LOCK: u8 = 22;
/// `SSH_AGENTC_UNLOCK`.
pub const SSH_AGENTC_UNLOCK: u8 = 23;
/// `SSH_AGENTC_ADD_ID_CONSTRAINED`.
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
/// `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`.
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
/// `SSH_AGENTC_EXTENSION`.
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// `SSH_AGENT_RSA_SHA2_256` sign request flag.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
/// `SSH_AGENT_RSA_SHA2_512` sign request flag.
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// A decoded client request.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST`.
    Sign {
        /// Public key blob of the key asked to sign.
        key_blob: Vec<u8>,
        /// Data to sign.
        data: Vec<u8>,
        /// `SSH_AGENT_RSA_SHA2_*` flags.
        flags: u32,
    },
    /// `SSH_AGENTC_LOCK` with its passphrase.
    Lock(Zeroizing<Vec<u8>>),
    /// `SSH_AGENTC_UNLOCK` with its passphrase.
    Unlock(Zeroizing<Vec<u8>>),
    /// `SSH_AGENTC_EXTENSION`: name and the raw bytes that follow it.
    Extension {
        /// Extension name, such as `session-bind@openssh.com`.
        name: String,
        /// Extension-specific contents (not length-prefixed).
        contents: Vec<u8>,
    },
    /// Any other message type (`ADD_*`, `REMOVE_*`, smartcard, unknown).
    /// Its contents are not decoded.
    Unsupported(u8),
}

/// A response to send back to the client.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// `SSH_AGENT_FAILURE`.
    Failure,
    /// `SSH_AGENT_SUCCESS`.
    Success,
    /// `SSH_AGENT_IDENTITIES_ANSWER`: `(public key blob, comment)` pairs.
    Identities(Vec<(Vec<u8>, String)>),
    /// `SSH_AGENT_SIGN_RESPONSE` with the complete SSH signature blob.
    Signature(Vec<u8>),
}

/// A malformed message. Every decoding error closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The message ends before a field is complete.
    Truncated,
    /// A length field exceeds [`MAX_FRAME`].
    TooLong,
    /// Bytes remain after the last field.
    Trailing,
    /// A text field is not UTF-8.
    BadUtf8,
    /// An `mpint` is negative or not minimally encoded.
    BadMpint,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            WireError::Truncated => "truncated agent message",
            WireError::TooLong => "agent message field too long",
            WireError::Trailing => "trailing bytes in agent message",
            WireError::BadUtf8 => "agent message text is not UTF-8",
            WireError::BadMpint => "invalid mpint in agent message",
        })
    }
}

impl std::error::Error for WireError {}

/// Reader over RFC 4251 encoded fields.
pub struct SshReader<'a> {
    buf: &'a [u8],
}

impl<'a> SshReader<'a> {
    /// Reads from `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.buf.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Reads a `byte`.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a `uint32`.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `string` and returns its bytes.
    pub fn string(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        if len > MAX_FRAME {
            return Err(WireError::TooLong);
        }
        self.take(len)
    }

    /// Reads a `string` that must be UTF-8.
    pub fn utf8(&mut self) -> Result<&'a str, WireError> {
        std::str::from_utf8(self.string()?).map_err(|_| WireError::BadUtf8)
    }

    /// Reads a non-negative `mpint` and returns its magnitude, big-endian,
    /// without leading zero bytes (empty for zero).
    pub fn mpint(&mut self) -> Result<&'a [u8], WireError> {
        let raw = self.string()?;
        match raw {
            [] => Ok(raw),
            [first, ..] if first & 0x80 != 0 => Err(WireError::BadMpint),
            [0] => Err(WireError::BadMpint),
            [0, second, ..] if second & 0x80 == 0 => Err(WireError::BadMpint),
            [0, rest @ ..] => Ok(rest),
            _ => Ok(raw),
        }
    }

    /// Returns the unread bytes and consumes them.
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    /// Number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Succeeds only if every byte was read.
    pub fn finish(self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

/// Writer of RFC 4251 encoded fields.
#[derive(Default)]
pub struct SshWriter {
    buf: Vec<u8>,
}

impl SshWriter {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty writer with room for `capacity` bytes. Writers that hold
    /// private key material are sized up front so that the buffer is never
    /// reallocated, which would leave a copy in freed memory.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Bytes the writer can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Writes a `byte`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Writes a `uint32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes a `string`.
    ///
    /// # Panics
    /// If `s` is longer than `u32::MAX` bytes.
    pub fn string(&mut self, s: &[u8]) -> &mut Self {
        let len = u32::try_from(s.len()).expect("SSH string longer than u32::MAX");
        self.u32(len);
        self.buf.extend_from_slice(s);
        self
    }

    /// Writes an `mpint` from a non-negative big-endian magnitude (leading
    /// zero bytes allowed).
    pub fn mpint(&mut self, magnitude: &[u8]) -> &mut Self {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let m = &magnitude[start..];
        if m.first().is_some_and(|b| b & 0x80 != 0) {
            let len = u32::try_from(m.len() + 1).expect("mpint longer than u32::MAX");
            self.u32(len);
            self.buf.push(0);
            self.buf.extend_from_slice(m);
        } else {
            self.string(m);
        }
        self
    }

    /// Appends raw bytes.
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// The written bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Decodes one message body (type byte and contents, without the length
/// prefix). Bytes left after the last field are an error.
pub fn decode_request(frame: &[u8]) -> Result<Request, WireError> {
    let mut r = SshReader::new(frame);
    let request = match r.u8()? {
        SSH_AGENTC_REQUEST_IDENTITIES => Request::RequestIdentities,
        SSH_AGENTC_SIGN_REQUEST => {
            let key_blob = r.string()?.to_vec();
            let data = r.string()?.to_vec();
            let flags = r.u32()?;
            Request::Sign {
                key_blob,
                data,
                flags,
            }
        }
        SSH_AGENTC_LOCK => Request::Lock(Zeroizing::new(r.string()?.to_vec())),
        SSH_AGENTC_UNLOCK => Request::Unlock(Zeroizing::new(r.string()?.to_vec())),
        SSH_AGENTC_EXTENSION => {
            let name = r.utf8()?.to_owned();
            let contents = r.rest().to_vec();
            Request::Extension { name, contents }
        }
        other => {
            r.rest();
            Request::Unsupported(other)
        }
    };
    r.finish()?;
    Ok(request)
}

/// Encodes a response, length prefix included.
pub fn encode_response(response: &Response) -> Vec<u8> {
    let mut body = SshWriter::new();
    match response {
        Response::Failure => {
            body.u8(SSH_AGENT_FAILURE);
        }
        Response::Success => {
            body.u8(SSH_AGENT_SUCCESS);
        }
        Response::Identities(ids) => {
            let count = u32::try_from(ids.len()).expect("too many identities");
            body.u8(SSH_AGENT_IDENTITIES_ANSWER).u32(count);
            for (blob, comment) in ids {
                body.string(blob).string(comment.as_bytes());
            }
        }
        Response::Signature(sig) => {
            body.u8(SSH_AGENT_SIGN_RESPONSE).string(sig);
        }
    }
    let mut out = SshWriter::new();
    out.string(body.as_slice());
    out.into_vec()
}

/// Reads one message body. `Ok(None)` on a clean end of stream (no byte of a
/// new message read); an error for a partial message or a length above
/// [`MAX_FRAME`].
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent message longer than 256 KiB",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, build: impl FnOnce(&mut SshWriter)) -> Vec<u8> {
        let mut w = SshWriter::new();
        w.u8(kind);
        build(&mut w);
        w.into_vec()
    }

    fn sample_frames() -> Vec<Vec<u8>> {
        vec![
            frame(SSH_AGENTC_REQUEST_IDENTITIES, |_| {}),
            frame(SSH_AGENTC_SIGN_REQUEST, |w| {
                w.string(b"blob").string(b"data").u32(4);
            }),
            frame(SSH_AGENTC_LOCK, |w| {
                w.string(b"pw");
            }),
            frame(SSH_AGENTC_UNLOCK, |w| {
                w.string(b"pw");
            }),
            frame(SSH_AGENTC_EXTENSION, |w| {
                w.string(b"session-bind@openssh.com").raw(b"xyz");
            }),
        ]
    }

    #[test]
    fn decode_each_request_kind() {
        let f = sample_frames();
        assert_eq!(decode_request(&f[0]).unwrap(), Request::RequestIdentities);
        assert_eq!(
            decode_request(&f[1]).unwrap(),
            Request::Sign {
                key_blob: b"blob".to_vec(),
                data: b"data".to_vec(),
                flags: 4
            }
        );
        assert_eq!(
            decode_request(&f[2]).unwrap(),
            Request::Lock(Zeroizing::new(b"pw".to_vec()))
        );
        assert_eq!(
            decode_request(&f[3]).unwrap(),
            Request::Unlock(Zeroizing::new(b"pw".to_vec()))
        );
        assert_eq!(
            decode_request(&f[4]).unwrap(),
            Request::Extension {
                name: "session-bind@openssh.com".into(),
                contents: b"xyz".to_vec()
            }
        );
        for code in [17u8, 18, 19, 20, 21, 25, 26, 99] {
            assert_eq!(
                decode_request(&frame(code, |w| {
                    w.string(b"ignored");
                }))
                .unwrap(),
                Request::Unsupported(code)
            );
        }
    }

    #[test]
    fn truncated_frames_are_errors() {
        // The extension's contents run to the end, so only cut inside its
        // name; every other frame is cut at every length.
        for f in sample_frames() {
            let min_valid = if f[0] == SSH_AGENTC_EXTENSION {
                f.len() - 3
            } else {
                f.len()
            };
            for cut in 0..min_valid {
                assert_eq!(
                    decode_request(&f[..cut]),
                    Err(WireError::Truncated),
                    "kind {} cut at {cut}",
                    f[0]
                );
            }
        }
    }

    #[test]
    fn trailing_bytes_are_errors() {
        for f in sample_frames() {
            if f[0] == SSH_AGENTC_EXTENSION {
                continue;
            }
            let mut long = f.clone();
            long.push(0);
            assert_eq!(decode_request(&long), Err(WireError::Trailing));
        }
    }

    #[test]
    fn bad_utf8_extension_name() {
        let f = frame(SSH_AGENTC_EXTENSION, |w| {
            w.string(&[0xff, 0xfe]);
        });
        assert_eq!(decode_request(&f), Err(WireError::BadUtf8));
    }

    #[test]
    fn oversized_string_length_is_too_long() {
        let f = frame(SSH_AGENTC_LOCK, |w| {
            w.u32(MAX_FRAME as u32 + 1);
        });
        assert_eq!(decode_request(&f), Err(WireError::TooLong));
    }

    #[test]
    fn read_frame_rejects_oversized_length() {
        let mut data = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        data.extend_from_slice(&[0; 16]);
        let err = read_frame(&mut data.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut ok = (MAX_FRAME as u32).to_be_bytes().to_vec();
        ok.resize(4 + MAX_FRAME, 7);
        assert_eq!(
            read_frame(&mut ok.as_slice()).unwrap().unwrap().len(),
            MAX_FRAME
        );
    }

    #[test]
    fn read_frame_eof_handling() {
        assert!(read_frame(&mut [].as_slice()).unwrap().is_none());
        let err = read_frame(&mut [0u8, 0].as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let err = read_frame(&mut [0u8, 0, 0, 5, 11].as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let mut two = vec![0u8, 0, 0, 1, 11, 0, 0, 0, 1, 19];
        let mut r = two.as_mut_slice() as &[u8];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), vec![11]);
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), vec![19]);
        assert!(read_frame(&mut r).unwrap().is_none());
    }

    #[test]
    fn encode_identities_layout() {
        let bytes = encode_response(&Response::Identities(vec![(vec![0xAA, 0xBB], "hi".into())]));
        let expected: Vec<u8> = vec![
            0, 0, 0, 17, // length: 1 + 4 + (4 + 2) + (4 + 2)
            12, // SSH_AGENT_IDENTITIES_ANSWER
            0, 0, 0, 1, // nkeys
            0, 0, 0, 2, 0xAA, 0xBB, // key blob
            0, 0, 0, 2, b'h', b'i', // comment
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn encode_simple_responses() {
        assert_eq!(encode_response(&Response::Failure), vec![0, 0, 0, 1, 5]);
        assert_eq!(encode_response(&Response::Success), vec![0, 0, 0, 1, 6]);
        assert_eq!(
            encode_response(&Response::Signature(vec![1, 2, 3])),
            vec![0, 0, 0, 8, 14, 0, 0, 0, 3, 1, 2, 3]
        );
    }

    #[test]
    fn mpint_roundtrip_and_rejections() {
        for (mag, enc) in [
            (&[][..], &[0u8, 0, 0, 0][..]),
            (&[0x7f], &[0, 0, 0, 1, 0x7f]),
            (&[0x80], &[0, 0, 0, 2, 0, 0x80]),
            (&[0, 0, 0x12, 0x34], &[0, 0, 0, 2, 0x12, 0x34]),
        ] {
            let mut w = SshWriter::new();
            w.mpint(mag);
            assert_eq!(w.as_slice(), enc);
            let mut r = SshReader::new(enc);
            let stripped: Vec<u8> = mag.iter().copied().skip_while(|&b| b == 0).collect();
            assert_eq!(r.mpint().unwrap(), stripped.as_slice());
            r.finish().unwrap();
        }
        for bad in [
            &[0u8, 0, 0, 1, 0x80][..],
            &[0, 0, 0, 1, 0],
            &[0, 0, 0, 2, 0, 0x7f],
        ] {
            assert_eq!(SshReader::new(bad).mpint(), Err(WireError::BadMpint));
        }
    }
}
