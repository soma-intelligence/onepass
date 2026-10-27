//! JSON envelopes of the bridge protocol (spec 6.3 to 6.6).
//!
//! Every message is a JSON object with `"v": 1` and a type tag `"t"`.
//! Binary fields are standard base64 with padding. Parsing never panics:
//! any malformed input gives a `BridgeError`.

use data_encoding::BASE64;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::kem::{CT_LEN, PUBLIC_LEN};
use crate::{AppErrorCode, BridgeError, Result};

/// Protocol version carried by every envelope.
pub const VERSION: u64 = 1;

/// Fixed length binary field, base64 on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64<const N: usize>(pub [u8; N]);

/// Variable length binary field, base64 on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64Vec(pub Vec<u8>);

fn decode<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    BASE64
        .decode(s.as_bytes())
        .map_err(|_| de::Error::custom("invalid base64"))
}

impl<const N: usize> Serialize for B64<N> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for B64<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = decode(d)?;
        let arr: [u8; N] = v
            .try_into()
            .map_err(|_| de::Error::custom("wrong binary length"))?;
        Ok(B64(arr))
    }
}

impl Serialize for B64Vec {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64Vec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        decode(d).map(B64Vec)
    }
}

/// Hybrid public key field (1600 bytes).
pub type PublicKeyB64 = B64<PUBLIC_LEN>;
/// Hybrid ciphertext field (1600 bytes).
pub type CiphertextB64 = B64<CT_LEN>;

/// E to H, pairing step 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairHello {
    pub commit: B64<32>,
    pub ext_name: String,
    pub browser: String,
}

/// H to E, pairing step 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairOffer {
    pub pairing_id: B64<16>,
    pub pk: PublicKeyB64,
    pub n: B64<32>,
}

/// E to H, pairing step 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairReveal {
    pub pk: PublicKeyB64,
    pub n: B64<32>,
    pub ct: CiphertextB64,
}

/// H to E, pairing step 6: host confirmation MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairDone {
    pub mac: B64<32>,
}

/// E to H, pairing step 6: extension confirmation MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirm {
    pub mac: B64<32>,
}

/// E to H, session step 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub pairing_id: B64<16>,
    pub pk: PublicKeyB64,
    pub n: B64<32>,
}

/// H to E, session step 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub ct: CiphertextB64,
    pub n: B64<32>,
    pub session_id: B64<16>,
    pub mac: B64<32>,
}

/// E to H, session step 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finish {
    pub mac: B64<32>,
}

/// Encrypted frame, both directions: counter and `ciphertext || tag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Msg {
    pub c: u64,
    pub d: B64Vec,
}

/// H to E error frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub code: String,
}

/// Every envelope of the wire format, tagged by `"t"`.
// Key-carrying variants are large (1600 byte arrays); an envelope lives
// only between parsing and handling, so boxing would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Envelope {
    PairHello(PairHello),
    PairOffer(PairOffer),
    PairReveal(PairReveal),
    /// The host computed the code and waits for the user's approval.
    PairSas,
    PairDone(PairDone),
    PairConfirm(PairConfirm),
    /// The host stored the pairing.
    PairOk,
    Hello(Hello),
    Welcome(Welcome),
    Finish(Finish),
    Msg(Msg),
    Error(ErrorFrame),
}

impl Envelope {
    /// Error frame carrying an application error code.
    pub fn error(code: AppErrorCode) -> Envelope {
        Envelope::Error(ErrorFrame {
            code: code.as_str().to_owned(),
        })
    }
}

/// Parse one envelope. A missing or different `v` gives
/// `BridgeError::Version`, anything else malformed `BridgeError::BadFrame`.
pub fn parse(bytes: &[u8]) -> Result<Envelope> {
    let mut v: Value = serde_json::from_slice(bytes).map_err(|_| BridgeError::BadFrame("json"))?;
    let obj = v
        .as_object_mut()
        .ok_or(BridgeError::BadFrame("not an object"))?;
    match obj.remove("v") {
        Some(Value::Number(n)) if n.as_u64() == Some(VERSION) => {}
        _ => return Err(BridgeError::Version),
    }
    serde_json::from_value(v).map_err(|_| BridgeError::BadFrame("envelope"))
}

#[derive(Serialize)]
struct Versioned<'a> {
    v: u64,
    #[serde(flatten)]
    env: &'a Envelope,
}

/// Serialize one envelope with `"v": 1`.
pub fn to_bytes(env: &Envelope) -> Vec<u8> {
    match serde_json::to_vec(&Versioned { v: VERSION, env }) {
        Ok(b) => b,
        // Unreachable: every field serializes to a JSON string or number.
        // Never emit a partial frame; report an internal error instead.
        Err(_) => br#"{"v":1,"t":"error","code":"internal"}"#.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_frame_shape() {
        let b = to_bytes(&Envelope::error(AppErrorCode::UnknownPairing));
        assert_eq!(
            serde_json::from_slice::<Value>(&b).unwrap(),
            serde_json::json!({"v":1,"t":"error","code":"unknown_pairing"})
        );
    }

    #[test]
    fn msg_round_trip() {
        let env = Envelope::Msg(Msg {
            c: u64::MAX,
            d: B64Vec(vec![1, 2, 3]),
        });
        let b = to_bytes(&env);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["c"], u64::MAX);
        assert_eq!(v["d"], "AQID");
        assert_eq!(parse(&b).unwrap(), env);
    }
}
