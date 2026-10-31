//! The rendezvous direction (version 2): the approver shows a short code
//! (as a QR or typed) and the newcomer joins it. See the module docs of
//! `pairing` for the wire formats.

use aws_lc_rs::hmac::{self, HMAC_SHA256};
use data_encoding::BASE32_NOPAD;

use crate::crypto::key::hkdf32;
use crate::crypto::random_array;
use crate::{Error, IntegrityError, Result};

use super::approver::Approver;
use super::messages::{DeviceInfo, JoinHello};
use super::{KEM_LABEL_RV, QR_LIFETIME_SECS, refused};
use crate::devices::DeviceMode;

/// Prefix of the QR text of a rendezvous code.
pub const RV_QR_PREFIX: &str = "OPPAIR2:";
/// A new code is shown this often.
pub const RV_RENEW_SECS: i64 = 30;
/// Bad Hellos tolerated before the host closes: a guess of the 40-bit code
/// gets a handful of tries, not millions.
pub const RV_MAX_FAILURES: u8 = 5;
/// Codes alive at once (valid 120 s, renewed every 30 s).
const MAX_LIVE: usize = (QR_LIFETIME_SECS / RV_RENEW_SECS) as usize + 1;
const SERVICE_INFO: &[u8] = b"onepass/pairing/rv/svc/v2";
const PROOF_INFO: &[u8] = b"onepass/pairing/rv/proof/v2";
const CODE_LEN: usize = 5;

/// The 40-bit secret both devices type or scan: 8 base32 characters.
#[derive(Clone, PartialEq, Eq)]
pub struct RendezvousCode([u8; CODE_LEN]);

impl RendezvousCode {
    pub fn generate() -> Result<Self> {
        Ok(RendezvousCode(random_array()?))
    }

    fn body(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// `"OPPAIR2:" || BASE32(code)`: what the QR holds, and the text the
    /// transcript hashes.
    pub fn qr_text(&self) -> String {
        format!("{RV_QR_PREFIX}{}", self.body())
    }

    /// `XXXX-XXXX`, to read and type.
    pub fn short_text(&self) -> String {
        let b = self.body();
        format!("{}-{}", &b[..4], &b[4..])
    }

    /// Read a scanned QR text or a typed code. Typed input is forgiving:
    /// case, spaces and hyphens are ignored, and `0` and `1` read as `O`
    /// and `I` (the alphabet has neither digit).
    pub fn parse(input: &str) -> Result<Self> {
        const BAD: Error = Error::InvalidFormat("pairing code");
        let trimmed = input.trim();
        let raw = trimmed.strip_prefix(RV_QR_PREFIX).unwrap_or(trimmed);
        let body: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                '0' => 'O',
                '1' => 'I',
                other => other,
            })
            .collect();
        if body.len() != 8 {
            return Err(BAD);
        }
        let bytes = BASE32_NOPAD.decode(body.as_bytes()).map_err(|_| BAD)?;
        let code: [u8; CODE_LEN] = bytes.try_into().map_err(|_| BAD)?;
        Ok(RendezvousCode(code))
    }

    /// The name of the local-network service that hosts this code: the
    /// first 16 bytes of `SHA-256("onepass/pairing/rv/svc/v2" || code)` in
    /// hex. The newcomer derives it from the code it scanned or typed and
    /// connects to that service alone, so a host serves only the device
    /// that holds its code. The name is public on the network: it commits
    /// to the code but is no more than the Hello proof is (the SAS is what
    /// stops someone who learned the code).
    pub fn service_name(&self) -> String {
        let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        ctx.update(SERVICE_INFO);
        ctx.update(&self.0);
        let digest = ctx.finish();
        digest.as_ref()[..16]
            .iter()
            .fold(String::with_capacity(32), |mut out, b| {
                out.push_str(&format!("{b:02x}"));
                out
            })
    }

    /// The proof a newcomer attaches to its Hello.
    pub(crate) fn proof(&self, signed_part: &[u8]) -> Result<[u8; 32]> {
        let key = hkdf32(&[], &self.0, &[PROOF_INFO])?;
        let tag = hmac::sign(&hmac::Key::new(HMAC_SHA256, key.expose()), signed_part);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    fn check_proof(&self, signed_part: &[u8], proof: &[u8; 32]) -> Result<bool> {
        let key = hkdf32(&[], &self.0, &[PROOF_INFO])?;
        Ok(hmac::verify(
            &hmac::Key::new(HMAC_SHA256, key.expose()),
            signed_part,
            proof,
        )
        .is_ok())
    }
}

impl std::fmt::Debug for RendezvousCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RendezvousCode(..)")
    }
}

/// A code as issued: what the screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCode {
    pub qr_text: String,
    pub short_text: String,
    /// The service name to publish for this code (`RendezvousCode::service_name`).
    pub service_name: String,
    pub expires_at: i64,
}

struct Live {
    code: RendezvousCode,
    expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostState {
    Open,
    /// A Hello was accepted: the codes are spent.
    Used,
    Closed,
}

/// The approver's side of the rendezvous: the codes on screen and the one
/// Hello that may use them.
pub struct Host {
    live: Vec<Live>,
    failures: u8,
    state: HostState,
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

impl Host {
    pub fn new() -> Host {
        Host {
            live: Vec::new(),
            failures: 0,
            state: HostState::Open,
        }
    }

    /// A fresh code, valid `QR_LIFETIME_SECS` from `now`. Older codes stay
    /// valid until their own expiry (at most `QR_LIFETIME_SECS /
    /// RV_RENEW_SECS` + 1 live).
    pub fn issue(&mut self, now: i64) -> Result<HostCode> {
        if self.state != HostState::Open {
            return Err(refused("host closed"));
        }
        self.live.retain(|l| l.expires_at >= now);
        while self.live.len() >= MAX_LIVE {
            self.live.remove(0);
        }
        let code = RendezvousCode::generate()?;
        let expires_at = now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?;
        let shown = HostCode {
            qr_text: code.qr_text(),
            short_text: code.short_text(),
            service_name: code.service_name(),
            expires_at,
        };
        self.live.push(Live { code, expires_at });
        Ok(shown)
    }

    /// Check a newcomer's `JoinHello` against the live codes and answer with
    /// the KeyExchange, like `Approver::begin`. The first success spends
    /// every code. A Hello that fails (malformed, no live code proves it)
    /// counts as a failure; `RV_MAX_FAILURES` of them close the host.
    pub fn accept(
        &mut self,
        join_hello: &[u8],
        now: i64,
    ) -> Result<(Approver, Vec<u8>, String, DeviceInfo, DeviceMode)> {
        if self.state != HostState::Open {
            return Err(refused("host closed"));
        }
        match self.try_accept(join_hello, now) {
            Ok(out) => {
                self.state = HostState::Used;
                self.live.clear();
                Ok(out)
            }
            Err(e) => {
                self.failures += 1;
                if self.failures >= RV_MAX_FAILURES {
                    self.close();
                }
                Err(e)
            }
        }
    }

    fn try_accept(
        &self,
        join_hello: &[u8],
        now: i64,
    ) -> Result<(Approver, Vec<u8>, String, DeviceInfo, DeviceMode)> {
        let join = JoinHello::from_bytes(join_hello)?;
        let signed = JoinHello::signed_part(&join.hello)?;
        let mut matched = None;
        // Every live code is tried, none skipped early, so the time taken
        // does not say which one matched.
        for l in &self.live {
            let ok = l.code.check_proof(&signed, &join.proof)?;
            if ok && now <= l.expires_at && matched.is_none() {
                matched = Some(&l.code);
            }
        }
        let code = matched.ok_or(IntegrityError::WrongContext)?;
        Approver::establish(&code.qr_text(), join_hello, join.hello, KEM_LABEL_RV)
    }

    /// Spend the codes: the user left the screen, or refused the SAS.
    pub fn close(&mut self) {
        self.live.clear();
        self.state = HostState::Closed;
    }

    pub fn is_open(&self) -> bool {
        self.state == HostState::Open
    }
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("state", &self.state)
            .field("live", &self.live.len())
            .field("failures", &self.failures)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_texts_round_trip() {
        let c = RendezvousCode([0x95, 0xec, 0x61, 0x2e, 0x40]);
        assert_eq!(c.qr_text().len(), RV_QR_PREFIX.len() + 8);
        assert_eq!(c.short_text().len(), 9);
        assert_eq!(RendezvousCode::parse(&c.qr_text()).unwrap(), c);
        assert_eq!(RendezvousCode::parse(&c.short_text()).unwrap(), c);
        let sloppy = c.short_text().to_lowercase().replace('-', "  ");
        assert_eq!(RendezvousCode::parse(&sloppy).unwrap(), c);
    }

    #[test]
    fn service_name_is_stable_and_code_specific() {
        let a = RendezvousCode([1, 2, 3, 4, 5]);
        let b = RendezvousCode([1, 2, 3, 4, 6]);
        assert_eq!(a.service_name().len(), 32);
        assert_eq!(
            a.service_name(),
            RendezvousCode([1, 2, 3, 4, 5]).service_name()
        );
        assert_ne!(a.service_name(), b.service_name());
        assert!(a.service_name().bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn typed_digits_read_as_letters() {
        let a = RendezvousCode::parse("OIOI-OIOI").unwrap();
        assert_eq!(RendezvousCode::parse("0101-0101").unwrap(), a);
    }

    #[test]
    fn bad_codes_are_refused() {
        for t in [
            "",
            "ABCD",
            "ABCD-EFGH-IJKL",
            "ABCD-EF9H",
            "OPPAIR1:ABCDEFGH",
        ] {
            assert!(RendezvousCode::parse(t).is_err(), "accepted {t:?}");
        }
    }
}
