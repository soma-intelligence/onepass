//! T-RDV: the rendezvous through the mailbox (spec 5.3), as a
//! `FrameTransport`. The stream itself (chunks, retries, the 66 MiB cap) is
//! `onepass_mailbox::Rendezvous`; this only maps its errors and caps.
//!
//! Untrusted like T-LAN: the server sees two addresses and the time, and
//! whatever it substitutes is refused by the sealed pairing channel.

use std::time::{Duration, Instant};

use onepass_mailbox::{ErrorCode, MailboxError, Rendezvous};

use crate::{FrameTransport, MAX_FRAME, PairnetError, TransportKind};

/// How long one `recv` waits for the next frame: a frame stays readable
/// 120 s on the server.
pub const RDV_RECV_TIMEOUT: Duration = Duration::from_secs(120);

/// One side of a rendezvous session. Closing (or dropping) it ends the
/// session for both sides.
#[derive(Debug)]
pub struct RdvTransport(pub Rendezvous);

impl RdvTransport {
    /// The next frame of at most `min(max, MAX_FRAME)` bytes, waiting until
    /// `deadline`. Nothing by then is `Timeout`, and what was read of the
    /// stream stays for the next call.
    pub fn recv_until(&mut self, max: usize, deadline: Instant) -> Result<Vec<u8>, PairnetError> {
        self.0
            .recv_frame(max.min(MAX_FRAME), deadline)
            .map_err(rdv_error)
    }
}

impl FrameTransport for RdvTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), PairnetError> {
        if frame.len() > MAX_FRAME {
            self.0.close();
            return Err(PairnetError::FrameTooLarge);
        }
        self.0.send_frame(frame).map_err(rdv_error)
    }

    fn recv(&mut self, max: usize) -> Result<Vec<u8>, PairnetError> {
        self.recv_until(max, Instant::now() + RDV_RECV_TIMEOUT)
    }

    fn close(&mut self) {
        self.0.close();
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Rendezvous
    }
}

/// `Offline` at the deadline is a timeout; a refused length or the 66 MiB
/// cap is `FrameTooLarge`; a closed or expired session `Closed`.
pub(crate) fn rdv_error(e: MailboxError) -> PairnetError {
    match e {
        MailboxError::Offline => PairnetError::Timeout,
        MailboxError::TooLarge => PairnetError::FrameTooLarge,
        MailboxError::Server(ErrorCode::NotFound) => PairnetError::Closed,
        other => PairnetError::Mailbox(other),
    }
}
