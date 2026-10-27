//! The sealed channel under the session key K (spec 5.2): one subkey and
//! one counter per direction, fail closed.

use std::fmt;

use crate::crypto::{Aad, BlobKind, SymmetricKey, open, seal};
use crate::{Error, Id, Result};

use super::messages::Message;
use super::{MAX_FRAME_BYTES, now_unix, refused};

const A2N: &[u8] = b"a2n";
const N2A: &[u8] = b"n2a";
const SCHEMA: u16 = 1;

pub struct Channel {
    send: SymmetricKey,
    recv: SymmetricKey,
    session_id: [u8; 16],
    /// Counter of the next frame to send, and to accept.
    sent: u64,
    received: u64,
    /// Set by a public grant: no frame passes after it.
    expires_at: Option<i64>,
    closed: bool,
}

impl Channel {
    /// The newcomer's end: sends under "n2a", reads "a2n".
    pub fn newcomer(k: &SymmetricKey, session_id: [u8; 16]) -> Result<Channel> {
        Self::new(k, session_id, N2A, A2N)
    }

    /// The approver's end: sends under "a2n", reads "n2a".
    pub fn approver(k: &SymmetricKey, session_id: [u8; 16]) -> Result<Channel> {
        Self::new(k, session_id, A2N, N2A)
    }

    fn new(k: &SymmetricKey, session_id: [u8; 16], send: &[u8], recv: &[u8]) -> Result<Channel> {
        Ok(Channel {
            send: k.derive(send)?,
            recv: k.derive(recv)?,
            session_id,
            sent: 0,
            received: 0,
            expires_at: None,
            closed: false,
        })
    }

    pub fn seal(&mut self, msg: &Message) -> Result<Vec<u8>> {
        self.seal_at(msg, now_unix())
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Message> {
        self.open_at(frame, now_unix())
    }

    /// Seal `msg` as the next frame. Sending `End` closes the channel.
    pub fn seal_at(&mut self, msg: &Message, now: i64) -> Result<Vec<u8>> {
        self.check_open(now)?;
        let next = self.sent.checked_add(1).ok_or(refused("counter"))?;
        let plain = msg.encode()?;
        let frame = seal(&self.send, BlobKind::Pairing, &self.aad(self.sent), &plain)?;
        self.sent = next;
        if *msg == Message::End {
            self.closed = true;
        }
        Ok(frame)
    }

    /// Open the next frame from the peer. Any failure closes the channel;
    /// receiving `End` closes it too.
    pub fn open_at(&mut self, frame: &[u8], now: i64) -> Result<Message> {
        self.check_open(now)?;
        let r = self.open_next(frame);
        match &r {
            Ok(Message::End) | Err(_) => self.closed = true,
            Ok(_) => {}
        }
        r
    }

    fn open_next(&mut self, frame: &[u8]) -> Result<Message> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(Error::InvalidFormat("pairing frame too large"));
        }
        let next = self.received.checked_add(1).ok_or(refused("counter"))?;
        let plain = open(
            &self.recv,
            BlobKind::Pairing,
            &self.aad(self.received),
            frame,
        )?;
        let msg = Message::decode(&plain)?;
        self.received = next;
        Ok(msg)
    }

    /// No frame passes after `expires_at`.
    pub fn set_expiry(&mut self, expires_at: i64) {
        self.expires_at = Some(expires_at);
    }

    /// Close the channel: nothing is sealed or opened any more.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Closed by `End`, a failed frame, `close`, or the expiry at `now`.
    pub fn is_closed(&self, now: i64) -> bool {
        self.closed || self.expires_at.is_some_and(|e| now > e)
    }

    fn check_open(&mut self, now: i64) -> Result<()> {
        if self.is_closed(now) {
            self.closed = true;
            return Err(refused("session closed"));
        }
        Ok(())
    }

    /// `session_id` with its last 8 bytes XOR the counter (big-endian).
    fn aad(&self, counter: u64) -> Aad {
        let mut id = self.session_id;
        for (b, c) in id[8..].iter_mut().zip(counter.to_be_bytes()) {
            *b ^= c;
        }
        Aad {
            blob_id: Id(id),
            vault_id: None,
            schema: SCHEMA,
        }
    }
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("sent", &self.sent)
            .field("received", &self.received)
            .field("expires_at", &self.expires_at)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Channel, Channel) {
        let k = SymmetricKey::from_bytes([7; 32]);
        (
            Channel::newcomer(&k, [1; 16]).unwrap(),
            Channel::approver(&k, [1; 16]).unwrap(),
        )
    }

    #[test]
    fn both_directions_flow_in_order() {
        let (mut n, mut a) = pair();
        for _ in 0..3 {
            let f = n.seal_at(&Message::Ack, 0).unwrap();
            assert_eq!(a.open_at(&f, 0).unwrap(), Message::Ack);
            let f = a.seal_at(&Message::Confirmed, 0).unwrap();
            assert_eq!(n.open_at(&f, 0).unwrap(), Message::Confirmed);
        }
    }

    #[test]
    fn frame_layout_binds_kind_and_counter() {
        let (mut n, _) = pair();
        let f = n.seal_at(&Message::Ack, 0).unwrap();
        assert_eq!(&f[..3], b"OPB");
        assert_eq!(f[5], 12);
        // Counter 1 differs from counter 0 in the AAD.
        assert_ne!(n.aad(0), n.aad(1));
        assert_eq!(n.aad(0).blob_id, Id([1; 16]));
        assert_eq!(n.aad(1).blob_id.0[15], 1 ^ 1);
    }

    #[test]
    fn a_tampered_frame_closes_the_channel() {
        let (mut n, mut a) = pair();
        let mut f = n.seal_at(&Message::Ack, 0).unwrap();
        let good = f.clone();
        let last = f.len() - 1;
        f[last] ^= 1;
        assert!(a.open_at(&f, 0).is_err());
        assert!(a.open_at(&good, 0).is_err());
        assert!(a.is_closed(0));
    }

    #[test]
    fn expiry_closes() {
        let (mut n, mut a) = pair();
        n.set_expiry(10);
        a.set_expiry(10);
        let f = n.seal_at(&Message::Ack, 10).unwrap();
        assert!(a.open_at(&f, 11).is_err());
        assert!(n.seal_at(&Message::Ack, 11).is_err());
        assert!(!format!("{n:?}").contains("Symmetric"));
    }
}
