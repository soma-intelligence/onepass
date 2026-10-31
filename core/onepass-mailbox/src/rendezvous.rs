//! T-RDV: the pairing rendezvous through the mailbox (spec 5.3, routes of
//! spec 4.6, limits of spec 4.9).
//!
//! Two parties that share a 128-bit session id (from the QR code) exchange
//! opaque pairing frames. Each direction is a byte stream: every frame is a
//! big-endian `u32` length then the frame, cut into chunks of at most
//! 1 MiB written once each at successive numbers `n` (0 to 4095). A frame
//! starts a new chunk, so a sender never waits to fill one; the reader
//! takes the chunks as one stream either way.
//!
//! The server sees two addresses and the time of the pairing, nothing
//! else: the frames are sealed by the pairing protocol, which also binds
//! them to the QR and the short code. So a frame the server substitutes is
//! refused there; here the stream only keeps its framing and its limits.

use std::time::{Duration, Instant};

use onepass_mailbox_proto::hex;

use crate::client::expect;
use crate::http::{self, Endpoint, Http, Method};
use crate::{ErrorCode, MailboxError};

/// Largest chunk the server stores (`rdv_put`, 1 MiB).
pub(crate) const RDV_CHUNK_MAX: usize = 1 << 20;
/// Chunks per direction: `n` from 0 to 4095.
pub const RDV_FRAMES_MAX: u32 = 4096;
/// Bytes per direction and session (66 MiB, a 50 MiB snapshot in frames).
pub const RDV_SESSION_BYTES_MAX: u64 = 66 << 20;
/// Longest wait of one `GET`, seconds (`RDV_WAIT_MAX` of the edge function).
const WAIT_MAX: u64 = 25;
/// How long a write keeps retrying a busy or unreachable server.
const SEND_PATIENCE: Duration = Duration::from_secs(60);
/// Pause between two reads when the server cannot wait (`wait=0`).
const POLL_GAP: Duration = Duration::from_millis(500);

/// Which side of the pairing this is. The newcomer writes direction 0 and
/// reads direction 1; the approver the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdvRole {
    Newcomer,
    Approver,
}

impl RdvRole {
    fn out_dir(self) -> u8 {
        match self {
            Self::Newcomer => 0,
            Self::Approver => 1,
        }
    }

    fn in_dir(self) -> u8 {
        1 - self.out_dir()
    }
}

/// The three rendezvous routes, as seen by one session. The HTTP one talks
/// to a mailbox; `testing::FakeMailbox` serves another from memory.
pub(crate) trait RdvTransport: Send {
    /// `PUT /v1/rendezvous/{s}/{dir}/{n}`. A chunk already there is
    /// `FrameTaken`; a closed or expired session `Server(NotFound)`.
    fn put(&mut self, dir: u8, n: u32, chunk: &[u8]) -> Result<(), MailboxError>;
    /// `GET /v1/rendezvous/{s}/{dir}/{n}?wait=<wait>`: the chunk, or `None`
    /// when it did not come within `wait` seconds.
    fn get(&mut self, dir: u8, n: u32, wait: u8) -> Result<Option<Vec<u8>>, MailboxError>;
    /// `DELETE /v1/rendezvous/{s}`.
    fn close(&mut self) -> Result<(), MailboxError>;
}

/// One side of a rendezvous session. Blocking, like the rest of the crate.
/// Dropping it closes the session.
pub struct Rendezvous {
    transport: Box<dyn RdvTransport>,
    role: RdvRole,
    next_out: u32,
    next_in: u32,
    sent: u64,
    /// Bytes of the incoming stream read so far (66 MiB at most).
    received: u64,
    /// Bytes of the incoming stream not handed out yet.
    inbox: Vec<u8>,
    closed: bool,
}

impl std::fmt::Debug for Rendezvous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rendezvous")
            .field("role", &self.role)
            .field("next_out", &self.next_out)
            .field("next_in", &self.next_in)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Rendezvous {
    /// A session on the mailbox at `endpoint`. No request is made yet.
    pub fn new(
        endpoint: Endpoint,
        session_id: [u8; 16],
        role: RdvRole,
    ) -> Result<Rendezvous, MailboxError> {
        let base = http::base_url(&endpoint)?;
        let transport = HttpRdv {
            http: Http::new(&endpoint)?,
            url: format!("{base}/v1/rendezvous/{}", hex(&session_id)),
        };
        Ok(Rendezvous::with_transport(Box::new(transport), role))
    }

    pub(crate) fn with_transport(transport: Box<dyn RdvTransport>, role: RdvRole) -> Rendezvous {
        Rendezvous {
            transport,
            role,
            next_out: 0,
            next_in: 0,
            sent: 0,
            received: 0,
            inbox: Vec::new(),
            closed: false,
        }
    }

    pub fn role(&self) -> RdvRole {
        self.role
    }

    /// Writes one frame. A frame that would take this direction past 4 096
    /// chunks or 66 MiB is `TooLarge` before anything is written. A chunk
    /// number someone else wrote first is `FrameTaken`, and the session is
    /// closed. A busy or unreachable server is retried for 60 s, and at
    /// least once past a `Retry { after }` of up to 60 s.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), MailboxError> {
        self.check_open()?;
        let len = u32::try_from(frame.len()).map_err(|_| MailboxError::TooLarge)?;
        let header = len.to_be_bytes();
        let total = frame.len() as u64 + 4;
        let chunks = total.div_ceil(RDV_CHUNK_MAX as u64);
        if u64::from(self.next_out) + chunks > u64::from(RDV_FRAMES_MAX)
            || self.sent + total > RDV_SESSION_BYTES_MAX
        {
            return Err(MailboxError::TooLarge);
        }
        // The header, then the frame, one chunk at a time: the frame is
        // never copied whole.
        let mut chunk = Vec::with_capacity(RDV_CHUNK_MAX.min(frame.len() + 4));
        chunk.extend_from_slice(&header);
        let mut rest = frame;
        loop {
            let take = rest.len().min(RDV_CHUNK_MAX - chunk.len());
            chunk.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if let Err(e) = self.put_chunk(&chunk) {
                return Err(self.fail(e));
            }
            self.next_out += 1;
            self.sent += chunk.len() as u64;
            if rest.is_empty() {
                return Ok(());
            }
            chunk.clear();
        }
    }

    /// Reads the next frame, waiting until `deadline`. A length above `max`
    /// closes the session and is `TooLarge`, before any more of the stream
    /// is read. Nothing by the deadline is `Offline`; what was read so far
    /// stays for the next call. A closed or expired session is
    /// `Server(NotFound)`.
    pub fn recv_frame(&mut self, max: usize, deadline: Instant) -> Result<Vec<u8>, MailboxError> {
        self.check_open()?;
        loop {
            if self.inbox.len() >= 4 {
                let len = u32::from_be_bytes(self.inbox[..4].try_into().expect("4 bytes")) as usize;
                // `len` is a u32: `4 + len` can only overflow a 32-bit usize.
                let end = match len.checked_add(4) {
                    Some(end) if len <= max => end,
                    _ => {
                        self.close();
                        return Err(MailboxError::TooLarge);
                    }
                };
                if self.inbox.len() >= end {
                    let frame = self.inbox[4..end].to_vec();
                    self.inbox.drain(..end);
                    return Ok(frame);
                }
            }
            if self.next_in >= RDV_FRAMES_MAX {
                return Err(self.fail(MailboxError::Malformed("rendezvous stream ended")));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(MailboxError::Offline);
            }
            let left = deadline - now;
            let wait = left.as_secs().min(WAIT_MAX) as u8;
            match self.transport.get(self.role.in_dir(), self.next_in, wait) {
                Ok(Some(chunk)) => {
                    if chunk.is_empty() || chunk.len() > RDV_CHUNK_MAX {
                        return Err(self.fail(MailboxError::Malformed("rendezvous chunk size")));
                    }
                    self.received += chunk.len() as u64;
                    if self.received > RDV_SESSION_BYTES_MAX {
                        return Err(self.fail(MailboxError::Malformed("rendezvous stream size")));
                    }
                    self.inbox.extend_from_slice(&chunk);
                    self.next_in += 1;
                }
                Ok(None) if wait == 0 => std::thread::sleep(left.min(POLL_GAP)),
                Ok(None) => {}
                // Reads change nothing: keep trying until the deadline.
                Err(MailboxError::Offline) => std::thread::sleep(left.min(Duration::from_secs(1))),
                Err(MailboxError::Retry { after }) => {
                    std::thread::sleep(left.min(Duration::from_secs(after.unwrap_or(1).into())));
                }
                Err(e) => return Err(self.fail(e)),
            }
        }
    }

    /// Ends the session for both sides (`DELETE`), once. Best effort: the
    /// server closes it 600 s after its first frame anyway. Blocking, up to
    /// the 30 s request timeout; dropping the `Rendezvous` does the same.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.transport.close();
        }
    }

    fn check_open(&self) -> Result<(), MailboxError> {
        if self.closed {
            return Err(MailboxError::Server(ErrorCode::NotFound));
        }
        Ok(())
    }

    /// Closes the session on an error that spoils it, and hands it on.
    fn fail(&mut self, e: MailboxError) -> MailboxError {
        self.close();
        e
    }

    /// One chunk at `next_out`. A write whose answer was lost may have
    /// landed: after such a try, a `409` (or the `413` the server checks
    /// first, near the 66 MiB cap) is read back and compared.
    fn put_chunk(&mut self, chunk: &[u8]) -> Result<(), MailboxError> {
        let (dir, n) = (self.role.out_dir(), self.next_out);
        let start = Instant::now();
        let mut uncertain = false;
        loop {
            let pause = match self.transport.put(dir, n, chunk) {
                Ok(()) => return Ok(()),
                Err(MailboxError::FrameTaken | MailboxError::TooLarge) if uncertain => {
                    return match self.transport.get(dir, n, 0)? {
                        Some(there) if there == chunk => Ok(()),
                        _ => Err(MailboxError::FrameTaken),
                    };
                }
                Err(MailboxError::Offline) => {
                    uncertain = true;
                    (Duration::from_secs(1), MailboxError::Offline)
                }
                Err(MailboxError::Retry { after }) => (
                    Duration::from_secs(after.unwrap_or(1).into()).min(SEND_PATIENCE),
                    MailboxError::Retry { after },
                ),
                Err(e) => return Err(e),
            };
            // Gives up only once the patience is spent, so one full wait
            // (capped at 60 s) is always tried.
            if start.elapsed() >= SEND_PATIENCE {
                return Err(pause.1);
            }
            std::thread::sleep(pause.0);
        }
    }
}

impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.close();
    }
}

/// The routes over HTTP. No signature: the session id is the only key.
struct HttpRdv {
    http: Http,
    /// `<base>/v1/rendezvous/<hex session>`.
    url: String,
}

impl RdvTransport for HttpRdv {
    fn put(&mut self, dir: u8, n: u32, chunk: &[u8]) -> Result<(), MailboxError> {
        let url = format!("{}/{dir}/{n}", self.url);
        let headers = [("content-type", "application/octet-stream".to_string())];
        let r = self
            .http
            .send(Method::Put, &url, &headers, chunk, 64 * 1024)?;
        if r.status == 409 {
            return Err(MailboxError::FrameTaken);
        }
        let r = expect(r, &[204])?;
        if !r.body.is_empty() {
            return Err(MailboxError::Malformed("body on 204"));
        }
        Ok(())
    }

    fn get(&mut self, dir: u8, n: u32, wait: u8) -> Result<Option<Vec<u8>>, MailboxError> {
        let url = format!("{}/{dir}/{n}?wait={wait}", self.url);
        // One byte of slack: ureq refuses a body that reaches its limit;
        // the reader refuses a chunk above 1 MiB itself.
        let r = self
            .http
            .send(Method::Get, &url, &[], &[], RDV_CHUNK_MAX as u64 + 1)?;
        let r = expect(r, &[200, 204])?;
        if r.status == 204 {
            if !r.body.is_empty() {
                return Err(MailboxError::Malformed("body on 204"));
            }
            return Ok(None);
        }
        let octets = r
            .content_type
            .as_deref()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/octet-stream"));
        if !octets {
            return Err(MailboxError::Malformed("content type"));
        }
        Ok(Some(r.body))
    }

    fn close(&mut self) -> Result<(), MailboxError> {
        let r = self
            .http
            .send(Method::Delete, &self.url, &[], &[], 64 * 1024)?;
        expect(r, &[204]).map(|_| ())
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::testing::FakeMailbox;

    const S: [u8; 16] = [7; 16];

    fn soon(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn rendezvous_round_trip_large_frame() {
        let fake = FakeMailbox::new();
        let mut newcomer = fake.rendezvous(S, RdvRole::Newcomer);
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        // 5 MiB of stream: the length and the frame, in 5 chunks.
        let big = pattern(5 * RDV_CHUNK_MAX - 4);
        newcomer.send_frame(&big).unwrap();
        assert_eq!(fake.rdv_chunks(S, 0), 5);
        newcomer.send_frame(b"").unwrap();
        newcomer.send_frame(b"tail").unwrap();
        assert_eq!(fake.rdv_chunks(S, 0), 7, "every frame starts a chunk");
        assert_eq!(approver.recv_frame(big.len(), soon(5)).unwrap(), big);
        assert_eq!(approver.recv_frame(0, soon(5)).unwrap(), b"");
        assert_eq!(approver.recv_frame(16, soon(5)).unwrap(), b"tail");
        // The other way.
        approver.send_frame(b"back").unwrap();
        assert_eq!(newcomer.recv_frame(16, soon(5)).unwrap(), b"back");
        assert_eq!(fake.rdv_chunks(S, 1), 1);
        newcomer.close();
        assert!(fake.rdv_closed(S));
        assert_eq!(
            approver.recv_frame(16, soon(5)).unwrap_err(),
            MailboxError::Server(ErrorCode::NotFound)
        );
    }

    #[test]
    fn rendezvous_reads_a_stream_cut_anywhere() {
        // Another writer may pack frames into chunks its own way.
        let fake = FakeMailbox::new();
        let mut stream = Vec::new();
        for f in [&b"one"[..], b"", b"three"] {
            stream.extend_from_slice(&(f.len() as u32).to_be_bytes());
            stream.extend_from_slice(f);
        }
        for (n, c) in stream.chunks(3).enumerate() {
            fake.rdv_put_raw(S, 1, n as u32, c).unwrap();
        }
        let mut r = fake.rendezvous(S, RdvRole::Newcomer);
        assert_eq!(r.recv_frame(8, soon(5)).unwrap(), b"one");
        assert_eq!(r.recv_frame(8, soon(5)).unwrap(), b"");
        assert_eq!(r.recv_frame(8, soon(5)).unwrap(), b"three");
    }

    #[test]
    fn rendezvous_oversized_length_refused() {
        let fake = FakeMailbox::new();
        let max = 1000usize;
        let mut chunk = ((max + 1) as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(&[1; 600]);
        fake.rdv_put_raw(S, 0, 0, &chunk).unwrap();
        fake.rdv_put_raw(S, 0, 1, &[2; 401]).unwrap();
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        assert_eq!(
            approver.recv_frame(max, soon(5)).unwrap_err(),
            MailboxError::TooLarge
        );
        assert_eq!(fake.rdv_reads(S, 0), [0], "nothing read past the length");
        assert!(fake.rdv_closed(S));
        // Closed for this side too.
        assert!(approver.recv_frame(max, soon(5)).is_err());
    }

    #[test]
    fn rendezvous_deadline() {
        let fake = FakeMailbox::new();
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        let start = Instant::now();
        let deadline = start + Duration::from_millis(1500);
        assert_eq!(
            approver.recv_frame(64, deadline).unwrap_err(),
            MailboxError::Offline
        );
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        assert!(took < Duration::from_secs(4), "{took:?}");
        assert!(!fake.rdv_closed(S), "a deadline does not close");
        // Half a frame by the deadline stays for the next call.
        let frame = pattern(100);
        let mut stream = (frame.len() as u32).to_be_bytes().to_vec();
        stream.extend_from_slice(&frame);
        fake.rdv_put_raw(S, 0, 0, &stream[..60]).unwrap();
        assert_eq!(
            approver
                .recv_frame(frame.len(), Instant::now() + Duration::from_millis(300))
                .unwrap_err(),
            MailboxError::Offline
        );
        fake.rdv_put_raw(S, 0, 1, &stream[60..]).unwrap();
        assert_eq!(approver.recv_frame(frame.len(), soon(5)).unwrap(), frame);
    }

    #[test]
    fn rendezvous_waits_for_the_other_side() {
        let fake = FakeMailbox::new();
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        let f2 = fake.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut newcomer = f2.rendezvous(S, RdvRole::Newcomer);
            newcomer.send_frame(b"hello").unwrap();
            // Keep the session open until the reader has it.
            std::thread::sleep(Duration::from_millis(500));
            drop(newcomer);
        });
        assert_eq!(approver.recv_frame(16, soon(10)).unwrap(), b"hello");
        writer.join().unwrap();
    }

    #[test]
    fn rendezvous_written_once() {
        let fake = FakeMailbox::new();
        let mut newcomer = fake.rendezvous(S, RdvRole::Newcomer);
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        newcomer.send_frame(b"first").unwrap();
        // Someone else writes the next chunk number first.
        fake.rdv_put_raw(S, 0, 1, b"intruder").unwrap();
        assert_eq!(
            newcomer.send_frame(b"second").unwrap_err(),
            MailboxError::FrameTaken
        );
        assert!(fake.rdv_closed(S), "a taken frame closes the session");
        assert_eq!(
            newcomer.send_frame(b"third").unwrap_err(),
            MailboxError::Server(ErrorCode::NotFound)
        );
        assert_eq!(
            approver.recv_frame(64, soon(5)).unwrap_err(),
            MailboxError::Server(ErrorCode::NotFound)
        );
        // The id is spent: a new session on it cannot start.
        let mut again = fake.rendezvous(S, RdvRole::Newcomer);
        assert_eq!(
            again.send_frame(b"x").unwrap_err(),
            MailboxError::Server(ErrorCode::NotFound)
        );
    }

    #[test]
    fn rendezvous_lost_answer_is_not_a_conflict() {
        // The write landed but its answer was lost: the retry's 409 is our
        // own chunk, read back and compared.
        let fake = FakeMailbox::new();
        let mut newcomer = fake.rendezvous(S, RdvRole::Newcomer);
        fake.rdv_lose_next_answer();
        newcomer.send_frame(b"once").unwrap();
        let mut approver = fake.rendezvous(S, RdvRole::Approver);
        assert_eq!(approver.recv_frame(16, soon(5)).unwrap(), b"once");
        assert_eq!(fake.rdv_chunks(S, 0), 1);
    }

    #[test]
    fn rendezvous_lost_answer_near_the_cap() {
        // The server checks the 66 MiB cap before the written-once rule: a
        // retry of a chunk that landed answers 413, read back as ours.
        let fake = FakeMailbox::new();
        let mut newcomer = fake.rendezvous(S, RdvRole::Newcomer);
        let full = vec![1u8; RDV_CHUNK_MAX - 4];
        for _ in 0..65 {
            newcomer.send_frame(&full).unwrap();
        }
        fake.rdv_lose_next_answer();
        newcomer.send_frame(&full).unwrap();
        assert_eq!(fake.rdv_chunks(S, 0), 66);
    }

    #[test]
    fn rendezvous_limits_before_writing() {
        let fake = FakeMailbox::new();
        let mut newcomer = fake.rendezvous(S, RdvRole::Newcomer);
        let too_big = vec![0u8; RDV_SESSION_BYTES_MAX as usize];
        assert_eq!(
            newcomer.send_frame(&too_big).unwrap_err(),
            MailboxError::TooLarge
        );
        assert_eq!(fake.rdv_chunks(S, 0), 0);
        // 4 096 chunks per direction.
        for _ in 0..RDV_FRAMES_MAX {
            newcomer.send_frame(b"").unwrap();
        }
        assert_eq!(
            newcomer.send_frame(b"").unwrap_err(),
            MailboxError::TooLarge
        );
    }
}
