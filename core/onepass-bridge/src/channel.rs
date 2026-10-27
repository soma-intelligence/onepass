//! Encrypted channel of an open session (spec 6.6).
//!
//! AES-256-GCM, one key per direction. Nonce: `[0, 0, 0, 0] || counter`
//! (u64 big-endian). AAD: `session_id || dir || counter`, `dir` 0 for
//! extension to host, 1 for host to extension. Each direction counts from 0
//! and the receiver requires exactly the next counter. Any failure to open
//! closes the channel for good.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::wire::{B64Vec, Envelope, Msg};
use crate::{BridgeError, Result};

/// Idle time after which the host closes a session.
pub const IDLE_TIMEOUT_SECS: u64 = 600;
/// A counter reaching this value closes the session.
pub const COUNTER_LIMIT: u64 = 1 << 32;

const DIR_E2H: u8 = 0;
const DIR_H2E: u8 = 1;
const CLOSED: BridgeError = BridgeError::BadFrame("closed");

/// Which end of the channel this is: picks the keys and directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Ext,
}

/// One direction: key, direction byte and next counter.
struct Half {
    key: LessSafeKey,
    dir: u8,
    counter: u64,
}

impl Half {
    fn new(key: &[u8; 32], dir: u8) -> Result<Half> {
        let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| BridgeError::Crypto)?;
        Ok(Half {
            key: LessSafeKey::new(key),
            dir,
            counter: 0,
        })
    }

    fn nonce(&self) -> Nonce {
        let mut n = [0u8; NONCE_LEN];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }

    fn aad(&self, session_id: &[u8; 16]) -> [u8; 25] {
        let mut a = [0u8; 25];
        a[..16].copy_from_slice(session_id);
        a[16] = self.dir;
        a[17..].copy_from_slice(&self.counter.to_be_bytes());
        a
    }
}

/// An authenticated session's encrypted channel.
pub struct Channel {
    role: Role,
    session_id: [u8; 16],
    send: Half,
    recv: Half,
    last_activity: u64,
    closed: bool,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("send_counter", &self.send.counter)
            .field("recv_counter", &self.recv.counter)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Build from the two directional keys of the handshake.
    pub(crate) fn new(
        role: Role,
        session_id: [u8; 16],
        e2h: &[u8; 32],
        h2e: &[u8; 32],
        now: u64,
    ) -> Result<Channel> {
        let (send, recv) = match role {
            Role::Host => (Half::new(h2e, DIR_H2E)?, Half::new(e2h, DIR_E2H)?),
            Role::Ext => (Half::new(e2h, DIR_E2H)?, Half::new(h2e, DIR_H2E)?),
        };
        Ok(Channel {
            role,
            session_id,
            send,
            recv,
            last_activity: now,
            closed: false,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Record activity at `now` (unix seconds).
    pub fn touch(&mut self, now: u64) {
        self.last_activity = self.last_activity.max(now);
    }

    /// True once more than `IDLE_TIMEOUT_SECS` passed since the last
    /// activity.
    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) > IDLE_TIMEOUT_SECS
    }

    fn fail(&mut self, e: BridgeError) -> BridgeError {
        self.closed = true;
        e
    }

    /// Encrypt one application message into a `msg` envelope.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Envelope> {
        if self.closed {
            return Err(CLOSED);
        }
        if self.send.counter >= COUNTER_LIMIT {
            return Err(self.fail(CLOSED));
        }
        let mut buf = plaintext.to_vec();
        let nonce = self.send.nonce();
        let aad = self.send.aad(&self.session_id);
        if self
            .send
            .key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .is_err()
        {
            return Err(self.fail(BridgeError::Crypto));
        }
        let c = self.send.counter;
        self.send.counter += 1;
        Ok(Envelope::Msg(Msg { c, d: B64Vec(buf) }))
    }

    /// Decrypt the next frame. A wrong counter or a frame that does not
    /// authenticate closes the channel; later calls give `BadFrame("closed")`.
    pub fn open(&mut self, msg: &Msg) -> Result<Zeroizing<Vec<u8>>> {
        if self.closed {
            return Err(CLOSED);
        }
        if self.recv.counter >= COUNTER_LIMIT {
            return Err(self.fail(CLOSED));
        }
        if msg.c != self.recv.counter {
            return Err(self.fail(BridgeError::Replay));
        }
        let mut buf = Zeroizing::new(msg.d.0.clone());
        let nonce = self.recv.nonce();
        let aad = self.recv.aad(&self.session_id);
        let len = match self
            .recv
            .key
            .open_in_place(nonce, Aad::from(aad), buf.as_mut_slice())
        {
            Ok(plain) => plain.len(),
            Err(_) => return Err(self.fail(BridgeError::BadMac)),
        };
        buf.truncate(len);
        self.recv.counter += 1;
        Ok(buf)
    }

    #[cfg(test)]
    fn set_counters(&mut self, send: u64, recv: u64) {
        self.send.counter = send;
        self.recv.counter = recv;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Channel, Channel) {
        let sid = [3u8; 16];
        let host = Channel::new(Role::Host, sid, &[1u8; 32], &[2u8; 32], 0).unwrap();
        let ext = Channel::new(Role::Ext, sid, &[1u8; 32], &[2u8; 32], 0).unwrap();
        (host, ext)
    }

    fn msg(e: Envelope) -> Msg {
        match e {
            Envelope::Msg(m) => m,
            _ => panic!("not a msg"),
        }
    }

    #[test]
    fn counter_limit_closes_sender() {
        let (mut host, mut ext) = pair();
        ext.set_counters(COUNTER_LIMIT - 1, 0);
        host.set_counters(0, COUNTER_LIMIT - 1);
        let m = msg(ext.seal(b"last").unwrap());
        assert_eq!(m.c, COUNTER_LIMIT - 1);
        assert_eq!(&*host.open(&m).unwrap(), b"last");
        assert_eq!(ext.seal(b"over").unwrap_err(), CLOSED);
        assert!(ext.is_closed());
    }

    #[test]
    fn counter_limit_closes_receiver() {
        let (mut host, _) = pair();
        host.set_counters(0, COUNTER_LIMIT);
        let m = Msg {
            c: COUNTER_LIMIT,
            d: B64Vec(vec![0u8; 16]),
        };
        assert_eq!(host.open(&m).unwrap_err(), CLOSED);
        assert!(host.is_closed());
    }

    #[test]
    fn nonce_and_aad_layout() {
        let (mut host, _) = pair();
        host.set_counters(0x0102_0304_0506_0708, 0);
        let mut want = [0u8; 12];
        want[4..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(host.send.nonce().as_ref(), &want);
        let aad = host.send.aad(&[9u8; 16]);
        assert_eq!(&aad[..16], &[9u8; 16]);
        assert_eq!(aad[16], DIR_H2E);
        assert_eq!(&aad[17..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn matches_raw_aes_gcm() {
        // An independent AES-256-GCM open with the documented nonce and AAD.
        let (_, mut ext) = pair();
        let m = msg(ext.seal(b"hello").unwrap());
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[1u8; 32]).unwrap());
        let mut aad = vec![3u8; 16];
        aad.push(0);
        aad.extend_from_slice(&0u64.to_be_bytes());
        let mut buf = m.d.0.clone();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key([0u8; 12]),
                Aad::from(aad),
                &mut buf,
            )
            .unwrap();
        assert_eq!(plain, b"hello");
    }
}
