use std::fmt;
use std::io;

/// Stable application error codes (spec section 10). Never carry a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppErrorCode {
    Version,
    UnknownPairing,
    BadMac,
    BadFrame,
    Locked,
    NotFound,
    OriginMismatch,
    InsecureOrigin,
    CrossSiteFrame,
    NotAllowed,
    RepromptRequired,
    RateLimited,
    Invalid,
    Internal,
}

impl AppErrorCode {
    /// The wire spelling of the code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::UnknownPairing => "unknown_pairing",
            Self::BadMac => "bad_mac",
            Self::BadFrame => "bad_frame",
            Self::Locked => "locked",
            Self::NotFound => "not_found",
            Self::OriginMismatch => "origin_mismatch",
            Self::InsecureOrigin => "insecure_origin",
            Self::CrossSiteFrame => "cross_site_frame",
            Self::NotAllowed => "not_allowed",
            Self::RepromptRequired => "reprompt_required",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for AppErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bridge error. Messages never contain secrets or message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// Transport failure. Only the error kind is kept.
    Io(io::ErrorKind),
    /// A frame header announced more than `MAX_FRAME` bytes.
    FrameTooLarge(usize),
    /// The stream ended in the middle of a frame.
    Truncated,
    /// Unsupported protocol version.
    Version,
    /// Malformed frame or envelope.
    BadFrame(&'static str),
    /// A MAC did not verify.
    BadMac,
    /// The pairing id is not known to the host.
    UnknownPairing,
    /// A cryptographic operation failed.
    Crypto,
    /// A counter was replayed or skipped.
    Replay,
    /// A pairing or session deadline passed.
    Expired,
    /// An application level error code.
    App(AppErrorCode),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("transport error"),
            Self::FrameTooLarge(n) => write!(f, "frame too large: {n} bytes"),
            Self::Truncated => f.write_str("truncated frame"),
            Self::Version => f.write_str("unsupported protocol version"),
            Self::BadFrame(what) => write!(f, "bad frame: {what}"),
            Self::BadMac => f.write_str("message authentication failed"),
            Self::UnknownPairing => f.write_str("unknown pairing"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::Replay => f.write_str("replayed or out of order message"),
            Self::Expired => f.write_str("expired"),
            Self::App(code) => write!(f, "application error: {code}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<io::Error> for BridgeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_spec() {
        assert_eq!(AppErrorCode::UnknownPairing.as_str(), "unknown_pairing");
        assert_eq!(AppErrorCode::CrossSiteFrame.as_str(), "cross_site_frame");
        assert_eq!(AppErrorCode::RepromptRequired.as_str(), "reprompt_required");
    }

    #[test]
    fn io_display_hides_the_detail() {
        let e = BridgeError::from(io::Error::other("secret path"));
        assert!(!e.to_string().contains("secret"));
    }
}
